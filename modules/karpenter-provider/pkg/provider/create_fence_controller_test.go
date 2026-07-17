package provider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

func TestCreateFenceControllerUsesExactReadBeforeCloudCleanup(t *testing.T) {
	now := metav1.NewTime(time.Now())
	live := createFenceControllerClaim(t, createFenceIssued)
	live.DeletionTimestamp = &now
	live.Status.ProviderID = "inspace://bkk01/22222222-2222-4222-8222-222222222222"
	stale := live.DeepCopy()
	stale.Status.ProviderID = ""

	kubeClient := createFenceControllerClient(t, live)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrNotFound}
	controller, err := NewCreateFenceController(kubeClient, kubeClient, cloud)
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Reconcile(context.Background(), stale)
	if err != nil {
		t.Fatal(err)
	}
	if cloud.calls != 0 || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("stale cache triggered cloud cleanup: calls=%d result=%#v", cloud.calls, result)
	}
}

func TestCreateFenceControllerInitializesRemovalFenceBeforeLiveClaimCanDelete(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	delete(claim.Annotations, AnnotationRemovalMutationFence)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{}
	controller, err := NewCreateFenceController(kubeClient, kubeClient, cloud)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	removal, err := decodeRemovalMutationRecord(stored.Annotations[AnnotationRemovalMutationFence], record.Binding, record.Token)
	if err != nil || removal.Phase != cloudapi.RemovalMutationReady {
		t.Fatalf("migrated removal fence = %#v, %v", removal, err)
	}
	if cloud.calls != 0 {
		t.Fatalf("live migration invoked cleanup cloud %d times", cloud.calls)
	}
}

func TestCreateFenceControllerMissingRemovalFenceAfterDeletionFailsClosed(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	delete(claim.Annotations, AnnotationRemovalMutationFence)
	now := metav1.Now()
	claim.DeletionTimestamp = &now
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	if _, err := controller.Reconcile(context.Background(), claim); err == nil {
		t.Fatal("deleting legacy claim without a pre-removal fence did not fail closed")
	}
	if cloud.calls != 0 {
		t.Fatalf("missing removal fence reached cloud cleanup %d times", cloud.calls)
	}
}

func TestCreateFenceControllerRetainsIssuedUnobservedAttempt(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceIssued)
	claim.DeletionTimestamp = &now
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrCreateAttemptUnresolved}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	_, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if !errors.Is(err, cloudapi.ErrCreateAttemptUnresolved) || cloud.calls != 1 {
		t.Fatalf("Reconcile() error=%v calls=%d, want unresolved issued attempt", err, cloud.calls)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	if !containsString(stored.Finalizers, CreateFenceFinalizer) {
		t.Fatal("controller released an issued-but-unobserved create finalizer")
	}
}

func TestCreateFenceControllerReleasesReservedOnlyAfterCloudAbsence(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceReserved)
	claim.DeletionTimestamp = &now
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrNotFound}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	if containsString(stored.Finalizers, CreateFenceFinalizer) || stored.Annotations[AnnotationCreateFence] != "" || cloud.calls != 1 {
		t.Fatalf("reserved cleanup did not converge: finalizers=%v annotation=%q calls=%d", stored.Finalizers, stored.Annotations[AnnotationCreateFence], cloud.calls)
	}
}

func TestCreateFenceControllerRetriesFinalizerCASAfterUnrelatedNodeClaimUpdate(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceIssued)
	claim.DeletionTimestamp = &now
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	rollbackAt := time.Now().Add(-time.Minute).UTC()
	record.RollbackAt = &rollbackAt
	dependentsResolvedAt := time.Now().Add(-30 * time.Second).UTC()
	record.DependentsResolvedAt = &dependentsResolvedAt
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	baseClient := createFenceControllerClient(t, claim)
	kubeClient := &conflictOnceCreateFenceClient{
		Client: baseClient,
		mutate: func(current *karpv1.NodeClaim) {
			if current.Labels == nil {
				current.Labels = map[string]string{}
			}
			current.Labels["test.inspace.cloud/concurrent-update"] = "preserved"
		},
	}
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrNotFound}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
		t.Fatalf("Reconcile() after one finalizer CAS conflict = %v", err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	if containsString(stored.Finalizers, CreateFenceFinalizer) || stored.Annotations[AnnotationCreateFence] != "" {
		t.Fatalf("finalizer cleanup did not converge: finalizers=%v annotation=%q", stored.Finalizers, stored.Annotations[AnnotationCreateFence])
	}
	if stored.Labels["test.inspace.cloud/concurrent-update"] != "preserved" {
		t.Fatalf("finalizer cleanup lost concurrent NodeClaim update: labels=%v", stored.Labels)
	}
	if kubeClient.patchCalls != 2 || cloud.calls != 1 {
		t.Fatalf("patch calls=%d cloud cleanup calls=%d, want one bounded CAS retry without repeating cloud cleanup", kubeClient.patchCalls, cloud.calls)
	}
}

func TestCreateFenceControllerDoesNotReleaseProviderStateChangedAfterCloudAudit(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceRejected)
	claim.DeletionTimestamp = &now
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	operatorResolution := mustOperatorResolution(t, createFenceOperatorResolution{
		Schema: createFenceResolutionSchema, IssueID: record.IssueID, Result: createFenceResolutionNoResult,
	})
	baseClient := createFenceControllerClient(t, claim)
	kubeClient := &conflictOnceCreateFenceClient{
		Client: baseClient,
		mutate: func(current *karpv1.NodeClaim) {
			current.Annotations[AnnotationCreateFenceResolution] = operatorResolution
		},
	}
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrNotFound}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err == nil {
		t.Fatal("Reconcile() released protection after provider-owned state changed")
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	if !containsString(stored.Finalizers, CreateFenceFinalizer) || stored.Annotations[AnnotationCreateFence] == "" || stored.Annotations[AnnotationCreateFenceResolution] != operatorResolution {
		t.Fatalf("changed provider state lost protection: finalizers=%v fence=%q resolution=%q", stored.Finalizers, stored.Annotations[AnnotationCreateFence], stored.Annotations[AnnotationCreateFenceResolution])
	}
	if kubeClient.patchCalls != 1 || cloud.calls != 1 {
		t.Fatalf("patch calls=%d cloud cleanup calls=%d, want changed fence to stop the in-place retry", kubeClient.patchCalls, cloud.calls)
	}
}

func TestCreateFenceControllerPersistsNormalizedCleanupReceiptBeforeDelete(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	claim.DeletionTimestamp = &now
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), response: cloudapi.FencedCreateCleanupResult{
		Resolution: &cloudapi.FencedCreateCleanupResolution{
			VMUUID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", FloatingIPName: "duplicate-a-public", PublicIPv4: "203.0.113.11",
		},
	}}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if result, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil || !result.Requeue {
		t.Fatalf("first Reconcile() = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	wantFirstHistory := []cloudapi.FencedCreateCleanupResolution{
		{VMUUID: "22222222-2222-4222-8222-222222222222", FloatingIPName: "fenced-public", PublicIPv4: "203.0.113.10"},
		{VMUUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", FloatingIPName: "duplicate-a-public", PublicIPv4: "203.0.113.11"},
	}
	if record.CleanupVMUUID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || !reflect.DeepEqual(record.CleanupResolutions, wantFirstHistory) {
		t.Fatalf("first durable cleanup receipt = %#v, want history %v", record, wantFirstHistory)
	}

	cloud.response = cloudapi.FencedCreateCleanupResult{Resolution: &cloudapi.FencedCreateCleanupResolution{
		VMUUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", FloatingIPName: "duplicate-b-public", PublicIPv4: "203.0.113.12",
	}}
	if result, err := controller.Reconcile(context.Background(), &stored); err != nil || !result.Requeue {
		t.Fatalf("second Reconcile() = %#v, %v", result, err)
	}
	if !reflect.DeepEqual(cloud.request.Resolutions, wantFirstHistory) || cloud.request.ObservedVMUUID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("second cleanup request lost original/current durable receipts: %#v", cloud.request)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	record, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	wantHistory := append(wantFirstHistory, cloudapi.FencedCreateCleanupResolution{
		VMUUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", FloatingIPName: "duplicate-b-public", PublicIPv4: "203.0.113.12",
	})
	if err != nil || record.CleanupVMUUID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" || !reflect.DeepEqual(record.CleanupResolutions, wantHistory) {
		t.Fatalf("advanced durable cleanup receipt = %#v, err=%v, want history %v", record, err, wantHistory)
	}
}

func TestDeletingAnchoredIssuedClaimPersistsDependentPendingBeforeCloudDelete(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceIssued)
	claim.DeletionTimestamp = &now
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrCreateAttemptUnresolved}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || !result.Requeue || cloud.calls != 0 {
		t.Fatalf("first reconcile = %#v err=%v cleanupCalls=%d, want rollback CAS only", result, err, cloud.calls)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt == nil || !storedRecord.DependentUnresolved || storedRecord.DependentsResolvedAt != nil {
		t.Fatalf("durable deletion rollback = %#v err=%v", storedRecord, err)
	}
}

func TestDependentAbsenceProofPersistsValidThirdStateBeforeFinalizerRelease(t *testing.T) {
	now := metav1.NewTime(time.Now())
	claim := createFenceControllerClaim(t, createFenceIssued)
	claim.DeletionTimestamp = &now
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	rollbackAt := time.Now().Add(-time.Minute).UTC()
	record.RollbackAt = &rollbackAt
	record.DependentUnresolved = true
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), response: cloudapi.FencedCreateCleanupResult{DependentsResolved: true}}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if result, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil || !result.Requeue {
		t.Fatalf("dependent proof reconcile = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.DependentUnresolved || storedRecord.DependentsResolvedAt == nil {
		t.Fatalf("persisted dependent absence state = %#v err=%v", storedRecord, err)
	}
	cloud.response = cloudapi.FencedCreateCleanupResult{}
	cloud.result = cloudapi.ErrNotFound
	if _, err := controller.Reconcile(context.Background(), &stored); err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	if containsString(stored.Finalizers, CreateFenceFinalizer) {
		t.Fatal("controller released neither finalizer nor valid dependent terminal proof")
	}
}

func TestLiveAnchoredProtectionFailureChoosesRollback(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: errors.New("base deny did not converge")}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || !result.Requeue || cloud.protectCalls != 1 || cloud.calls != 0 {
		t.Fatalf("live protection reconcile = %#v err=%v protect=%d cleanup=%d", result, err, cloud.protectCalls, cloud.calls)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt == nil || !storedRecord.DependentUnresolved {
		t.Fatalf("live protection rollback = %#v err=%v", storedRecord, err)
	}
}

func TestLiveAnchoredPendingProtectionWaitsForDurableIssueDeadlineThenChoosesRollback(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-createProtectionIssueDeadline + time.Second)
	record.IssuedAt = timePointer(issuedAt)
	record.BaseFirewallAssignment.IssuedAt = timePointer(issuedAt)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrCreateAttemptPending}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("pre-deadline reconcile = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt != nil || cloud.protectCalls != 1 || cloud.calls != 0 {
		t.Fatalf("pre-deadline state = %#v err=%v protect=%d cleanup=%d", storedRecord, err, cloud.protectCalls, cloud.calls)
	}

	now = now.Add(2 * time.Second)
	result, err = controller.Reconcile(context.Background(), &stored)
	if err != nil || !result.Requeue {
		t.Fatalf("post-deadline reconcile = %#v, %v", result, err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt == nil || !storedRecord.RollbackAt.Equal(now) || !storedRecord.DependentUnresolved ||
		cloud.protectCalls != 2 || cloud.calls != 0 {
		t.Fatalf("post-deadline rollback = %#v err=%v protect=%d cleanup=%d", storedRecord, err, cloud.protectCalls, cloud.calls)
	}
}

func TestObservedFirewallProtectionDriftUsesDurableFailureDeadline(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
	observedAt := now.Add(-time.Minute)
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentObserved
	record.BaseFirewallAssignment.ObservedAt = &observedAt
	record.BaseFirewallAssignment.RejectedAt = nil
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrCreateAttemptPending}

	first, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	first.now = func() time.Time { return now }
	result, err := first.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("first observed-firewall drift reconcile = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.ProtectionFailureAt == nil || !storedRecord.ProtectionFailureAt.Equal(now) || storedRecord.RollbackAt != nil {
		t.Fatalf("durable observed-firewall failure marker = %#v err=%v", storedRecord, err)
	}

	beforeDeadline := now.Add(createProtectionIssueDeadline - time.Second)
	restarted, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	restarted.now = func() time.Time { return beforeDeadline }
	result, err = restarted.Reconcile(context.Background(), &stored)
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("restart before observed-firewall deadline = %#v, %v", result, err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.ProtectionFailureAt == nil || !storedRecord.ProtectionFailureAt.Equal(now) || storedRecord.RollbackAt != nil {
		t.Fatalf("restart replaced observed-firewall failure marker = %#v err=%v", storedRecord, err)
	}

	afterDeadline := now.Add(createProtectionIssueDeadline + time.Second)
	restarted.now = func() time.Time { return afterDeadline }
	result, err = restarted.Reconcile(context.Background(), &stored)
	if err != nil || !result.Requeue {
		t.Fatalf("restart after observed-firewall deadline = %#v, %v", result, err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.ProtectionFailureAt != nil || storedRecord.RollbackAt == nil ||
		!storedRecord.RollbackAt.Equal(afterDeadline) || !storedRecord.DependentUnresolved {
		t.Fatalf("observed-firewall bounded rollback = %#v err=%v", storedRecord, err)
	}
}

func TestObservedFloatingIPProtectionDriftUsesDurableFailureDeadlineAndExactCleanup(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
	observedAt := now.Add(-time.Minute)
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentObserved
	record.BaseFirewallAssignment.ObservedAt = &observedAt
	record.BaseFirewallAssignment.RejectedAt = nil
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	update := floatingIPUpdateRecord{
		Schema: floatingIPUpdateFenceSchema, Binding: record.Binding, AttemptToken: record.Token,
		VMUUID: record.CreatedVMUUID, Address: "203.0.113.10", Name: "karpenter-general-a-1234567890",
		BillingAccountID: record.Cleanup.BillingAccountID, Phase: cloudapi.FloatingIPUpdateObserved,
		IssueID: "44444444444444444444444444444444", IssuedAt: now.Add(-2 * time.Minute), ObservedAt: &observedAt,
	}
	encodedUpdate, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	claim.Annotations[AnnotationFloatingIPUpdateFence] = string(encodedUpdate)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrCreateAttemptPending}

	first, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	first.now = func() time.Time { return now }
	result, err := first.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("first observed-FIP drift reconcile = %#v, %v", result, err)
	}
	if cloud.request.FloatingIPUpdate != floatingIPUpdateFenceFromRecord(update) {
		t.Fatalf("observed FIP receipt omitted from protection request: got %#v want %#v", cloud.request.FloatingIPUpdate, floatingIPUpdateFenceFromRecord(update))
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.ProtectionFailureAt == nil || !storedRecord.ProtectionFailureAt.Equal(now) || storedRecord.RollbackAt != nil {
		t.Fatalf("durable observed-FIP failure marker = %#v err=%v", storedRecord, err)
	}

	afterDeadline := now.Add(createProtectionIssueDeadline + time.Second)
	restarted, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	restarted.now = func() time.Time { return afterDeadline }
	result, err = restarted.Reconcile(context.Background(), &stored)
	if err != nil || !result.Requeue {
		t.Fatalf("restart after observed-FIP deadline = %#v, %v", result, err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	wantResolution := cloudapi.FencedCreateCleanupResolution{
		VMUUID: update.VMUUID, FloatingIPName: update.Name, PublicIPv4: update.Address,
	}
	if err != nil || storedRecord.ProtectionFailureAt != nil || storedRecord.RollbackAt == nil ||
		storedRecord.DependentUnresolved || len(storedRecord.CleanupResolutions) != 1 ||
		storedRecord.CleanupResolutions[0] != wantResolution {
		t.Fatalf("observed-FIP bounded exact rollback = %#v err=%v want=%#v", storedRecord, err, wantResolution)
	}
}

func TestSuccessfulProtectionClearsDurableFailureDeadline(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	failureAt := now.Add(-time.Minute)
	record.ProtectionFailureAt = &failureAt
	observedAt := now.Add(-2 * time.Minute)
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentObserved
	record.BaseFirewallAssignment.ObservedAt = &observedAt
	record.BaseFirewallAssignment.RejectedAt = nil
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New()}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || !result.Requeue {
		t.Fatalf("successful protection recovery = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.ProtectionFailureAt != nil || storedRecord.RollbackAt != nil || cloud.protectCalls != 1 {
		t.Fatalf("successful protection retained stale failure deadline: record=%#v err=%v protects=%d", storedRecord, err, cloud.protectCalls)
	}
}

func TestLiveAnchoredPreDeadlineFirewallCommitIsObservedBeforeRollback(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-createProtectionIssueDeadline + time.Second)
	record.IssuedAt = timePointer(issuedAt)
	record.BaseFirewallAssignment.IssuedAt = timePointer(issuedAt)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New()}
	cloud.protect = func(request cloudapi.FencedCreateCleanupRequest) error {
		return request.ObserveBaseFirewall(context.Background(), record.CreatedVMUUID, record.BaseFirewallAssignment.IssueID)
	}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("commit readback reconcile = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt != nil || storedRecord.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentObserved ||
		cloud.protectCalls != 1 || cloud.calls != 0 {
		t.Fatalf("committed protection state = %#v err=%v protect=%d cleanup=%d", storedRecord, err, cloud.protectCalls, cloud.calls)
	}
}

func TestLiveAnchoredProtectionRead5xxDoesNotRollbackBeforeIssueDeadline(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-time.Minute)
	record.IssuedAt = timePointer(issuedAt)
	record.BaseFirewallAssignment.IssuedAt = timePointer(issuedAt)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: errors.New("GET firewall readback: HTTP 503")}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("read 5xx reconcile = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt != nil || cloud.protectCalls != 1 || cloud.calls != 0 {
		t.Fatalf("read 5xx changed durable state = %#v err=%v protect=%d cleanup=%d", storedRecord, err, cloud.protectCalls, cloud.calls)
	}
}

func TestLiveAnchoredIssuedFloatingIPUsesItsOwnDeadline(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	createIssuedAt := now.Add(-time.Hour)
	record.IssuedAt = timePointer(createIssuedAt)
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentObserved
	record.BaseFirewallAssignment.ObservedAt = timePointer(now.Add(-time.Minute))
	record.BaseFirewallAssignment.RejectedAt = nil
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	update := floatingIPUpdateRecord{
		Schema: floatingIPUpdateFenceSchema, Binding: record.Binding, AttemptToken: record.Token,
		VMUUID: record.CreatedVMUUID, Address: "203.0.113.10", Name: "karpenter-general-a-1234567890",
		BillingAccountID: record.Cleanup.BillingAccountID, Phase: cloudapi.FloatingIPUpdateIssued,
		IssueID: "44444444444444444444444444444444", IssuedAt: now.Add(-createProtectionIssueDeadline + time.Second),
	}
	encodedUpdate, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	claim.Annotations[AnnotationFloatingIPUpdateFence] = string(encodedUpdate)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrCreateAttemptPending}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("fresh FIP issue reconcile = %#v, %v", result, err)
	}
	if cloud.request.FloatingIPUpdate != floatingIPUpdateFenceFromRecord(update) {
		t.Fatalf("cloud protection request FIP fence = %#v, want %#v", cloud.request.FloatingIPUpdate, floatingIPUpdateFenceFromRecord(update))
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt != nil {
		t.Fatalf("old create issue overrode fresh FIP issue: record=%#v err=%v", storedRecord, err)
	}

	now = now.Add(2 * time.Second)
	result, err = controller.Reconcile(context.Background(), &stored)
	if err != nil || !result.Requeue {
		t.Fatalf("expired FIP issue reconcile = %#v, %v", result, err)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err = decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt == nil || storedRecord.DependentUnresolved ||
		len(storedRecord.CleanupResolutions) != 1 ||
		storedRecord.CleanupResolutions[0] != (cloudapi.FencedCreateCleanupResolution{
			VMUUID: update.VMUUID, FloatingIPName: update.Name, PublicIPv4: update.Address,
		}) {
		t.Fatalf("expired FIP issue rollback = %#v err=%v", storedRecord, err)
	}
}

func TestRollbackResumesAcrossRestartAndLateFirewallAssignment(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchorCreatedFence(&record)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	issuedAt := now.Add(-createProtectionIssueDeadline - time.Second)
	record.IssuedAt = timePointer(issuedAt)
	record.BaseFirewallAssignment.IssuedAt = timePointer(issuedAt)
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrCreateAttemptPending}
	first, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	first.now = func() time.Time { return now }

	if result, err := first.Reconcile(context.Background(), claim.DeepCopy()); err != nil || !result.Requeue {
		t.Fatalf("rollback selection = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	cloud.protectErr = nil
	cloud.result = cloudapi.ErrCreateAttemptPending
	cloud.cleanup = func(request cloudapi.FencedCreateCleanupRequest) (cloudapi.FencedCreateCleanupResult, error) {
		if !request.RollbackChosen {
			t.Fatal("restart cleanup ran before durable rollback readback")
		}
		if err := request.ObserveBaseFirewall(context.Background(), record.CreatedVMUUID, record.BaseFirewallAssignment.IssueID); err != nil {
			t.Fatalf("persisting late firewall assignment: %v", err)
		}
		return cloudapi.FencedCreateCleanupResult{}, cloudapi.ErrCreateAttemptPending
	}
	restarted, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)
	restarted.now = func() time.Time { return now.Add(time.Second) }

	result, err := restarted.Reconcile(context.Background(), &stored)
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("restart cleanup = %#v, %v", result, err)
	}
	if cloud.protectCalls != 1 || cloud.calls != 1 {
		t.Fatalf("restart replayed protection instead of cleanup: protect=%d cleanup=%d", cloud.protectCalls, cloud.calls)
	}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.RollbackAt == nil || storedRecord.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentObserved {
		t.Fatalf("restart/late-assignment state = %#v err=%v", storedRecord, err)
	}
}

func TestOperatorVMResolutionValidatesProtectsAndAnchorsExactAttempt(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	vmUUID := "33333333-3333-4333-8333-333333333333"
	claim.Annotations[AnnotationCreateFenceResolution] = mustOperatorResolution(t, createFenceOperatorResolution{
		Schema: createFenceResolutionSchema, IssueID: record.IssueID, Result: createFenceResolutionVM, VMUUID: vmUUID,
	})
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New()}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || !result.Requeue || cloud.protectCalls != 1 || cloud.calls != 0 {
		t.Fatalf("operator VM resolution = %#v, %v; protect=%d cleanup=%d", result, err, cloud.protectCalls, cloud.calls)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.Phase != createFenceIssued || storedRecord.CreatedVMUUID != vmUUID || storedRecord.LaunchObservedAt == nil || stored.Annotations[AnnotationCreateFenceResolution] != "" {
		t.Fatalf("persisted operator VM resolution = %#v annotation=%q err=%v", storedRecord, stored.Annotations[AnnotationCreateFenceResolution], err)
	}
}

func TestOperatorNoResultRequiresEmptyAuditThenMarksExactAttemptRejected(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	claim.Annotations[AnnotationCreateFenceResolution] = mustOperatorResolution(t, createFenceOperatorResolution{
		Schema: createFenceResolutionSchema, IssueID: record.IssueID, Result: createFenceResolutionNoResult,
	})
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrCreateAttemptUnresolved}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || !result.Requeue || cloud.calls != 1 || cloud.protectCalls != 0 {
		t.Fatalf("operator no-result = %#v, %v; cleanup=%d protect=%d", result, err, cloud.calls, cloud.protectCalls)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, err := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if err != nil || storedRecord.Phase != createFenceRejected || storedRecord.CreatedVMUUID != "" || stored.Annotations[AnnotationCreateFenceResolution] != "" || !containsString(stored.Finalizers, CreateFenceFinalizer) {
		t.Fatalf("persisted no-result resolution = %#v annotation=%q finalizers=%v err=%v", storedRecord, stored.Annotations[AnnotationCreateFenceResolution], stored.Finalizers, err)
	}
}

func TestOperatorVMResolutionDoesNotAnchorWhenCloudValidationFails(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, _ := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	encoded := mustOperatorResolution(t, createFenceOperatorResolution{
		Schema: createFenceResolutionSchema, IssueID: record.IssueID, Result: createFenceResolutionVM,
		VMUUID: "33333333-3333-4333-8333-333333333333",
	})
	claim.Annotations[AnnotationCreateFenceResolution] = encoded
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), protectErr: cloudapi.ErrOwnershipMismatch}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
		t.Fatalf("foreign operator VM resolution error = %v, want ownership rejection", err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, _ := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if cloud.protectCalls != 1 || storedRecord.CreatedVMUUID != "" || storedRecord.Phase != createFenceIssued || stored.Annotations[AnnotationCreateFenceResolution] != encoded {
		t.Fatalf("failed operator validation changed durable state: protect=%d record=%#v annotation=%q", cloud.protectCalls, storedRecord, stored.Annotations[AnnotationCreateFenceResolution])
	}
}

func TestOperatorNoResultStaysPendingWhileCloudInventoryIsAmbiguous(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, _ := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	encoded := mustOperatorResolution(t, createFenceOperatorResolution{
		Schema: createFenceResolutionSchema, IssueID: record.IssueID, Result: createFenceResolutionNoResult,
	})
	claim.Annotations[AnnotationCreateFenceResolution] = encoded
	kubeClient := createFenceControllerClient(t, claim)
	cloud := &recordingFenceCleanupCloud{Cloud: cloudfake.New(), result: cloudapi.ErrCreateAttemptPending}
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("pending operator no-result = %#v, %v", result, err)
	}
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: claim.Name}, &stored); err != nil {
		t.Fatal(err)
	}
	storedRecord, _ := decodeCreateFence(stored.Annotations[AnnotationCreateFence])
	if storedRecord.Phase != createFenceIssued || stored.Annotations[AnnotationCreateFenceResolution] != encoded {
		t.Fatalf("pending audit changed fence or resolution: phase=%q annotation=%q", storedRecord.Phase, stored.Annotations[AnnotationCreateFenceResolution])
	}
}

func mustOperatorResolution(t *testing.T, resolution createFenceOperatorResolution) string {
	t.Helper()
	encoded, err := json.Marshal(resolution)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type recordingFenceCleanupCloud struct {
	*cloudfake.Cloud
	result       error
	response     cloudapi.FencedCreateCleanupResult
	calls        int
	request      cloudapi.FencedCreateCleanupRequest
	cleanup      func(cloudapi.FencedCreateCleanupRequest) (cloudapi.FencedCreateCleanupResult, error)
	protectErr   error
	protect      func(cloudapi.FencedCreateCleanupRequest) error
	protectCalls int
}

type conflictOnceCreateFenceClient struct {
	client.Client
	mutate     func(*karpv1.NodeClaim)
	patchCalls int
}

func (c *conflictOnceCreateFenceClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	c.patchCalls++
	if c.patchCalls == 1 {
		var current karpv1.NodeClaim
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(object), &current); err != nil {
			return err
		}
		c.mutate(&current)
		if err := c.Client.Update(ctx, &current); err != nil {
			return err
		}
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

func (c *recordingFenceCleanupCloud) ProtectFencedCreate(_ context.Context, request cloudapi.FencedCreateCleanupRequest) error {
	c.protectCalls++
	c.request = request
	if c.protect != nil {
		return c.protect(request)
	}
	return c.protectErr
}

func (c *recordingFenceCleanupCloud) CleanupFencedCreate(_ context.Context, request cloudapi.FencedCreateCleanupRequest) (cloudapi.FencedCreateCleanupResult, error) {
	c.calls++
	c.request = request
	if c.cleanup != nil {
		return c.cleanup(request)
	}
	return c.response, c.result
}

func createFenceControllerClient(t *testing.T, claim *karpv1.NodeClaim) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
}

func createFenceControllerClaim(t *testing.T, phase string) *karpv1.NodeClaim {
	t.Helper()
	claim := createFenceTestNodeClaim()
	binding, cleanup := createFenceTestIdentity(claim)
	record, err := newCreateFenceRecord(binding, cleanup, cloudapi.CreateInventory{}, time.Now().Add(-time.Hour), func() (string, error) {
		return "11111111111111111111111111111111", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record.Phase = phase
	if phase != createFenceReserved {
		record.Intent = cloudapi.CreateAuthorizationPost
		record.IssueID = "22222222222222222222222222222222"
		issuedAt := time.Now().Add(-30 * time.Minute).UTC()
		record.IssuedAt = &issuedAt
		record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentIssued
		record.BaseFirewallAssignment.IssueID = "33333333333333333333333333333333"
		record.BaseFirewallAssignment.IssuedAt = &issuedAt
		if phase == createFenceRejected {
			record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentRejected
			record.BaseFirewallAssignment.RejectedAt = &issuedAt
		}
	}
	if phase == createFenceMaterialized {
		observedAt := time.Now().Add(-20 * time.Minute).UTC()
		record.LaunchObservedAt = &observedAt
		record.CreatedVMUUID = "22222222-2222-4222-8222-222222222222"
		record.BaseFirewallAssignment = &baseFirewallAssignmentRecord{
			VMUUID: record.CreatedVMUUID, FirewallUUID: record.Cleanup.FirewallUUID,
			Phase: cloudapi.FirewallAssignmentObserved, IssueID: "33333333333333333333333333333333",
			IntentAt: observedAt.Add(-2 * time.Minute), IssuedAt: timePointer(observedAt.Add(-time.Minute)), ObservedAt: &observedAt,
		}
		record.ObservedAt = &observedAt
		record.ObservedVMUUID = "22222222-2222-4222-8222-222222222222"
		record.FloatingIPName = "fenced-public"
		record.PublicIPv4 = "203.0.113.10"
	}
	claim.Annotations = map[string]string{
		AnnotationCreateFence:          mustEncodeCreateFence(record),
		AnnotationRemovalMutationFence: mustEncodeRemovalMutation(newRemovalMutationReadyRecord(binding, record.Token, record.StartedAt)),
	}
	claim.Finalizers = append(claim.Finalizers, CreateFenceFinalizer)
	return claim
}

func anchorCreatedFence(record *createFenceRecord) {
	observedAt := time.Now().Add(-20 * time.Minute).UTC()
	record.LaunchObservedAt = &observedAt
	record.CreatedVMUUID = "22222222-2222-4222-8222-222222222222"
	record.BaseFirewallAssignment.VMUUID = record.CreatedVMUUID
}

func timePointer(value time.Time) *time.Time { return &value }
