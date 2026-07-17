package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestTerminationRecoverySurvivesRestartAndRetainsCreateProtectionWithoutNodePool(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 1, 2, 3, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{
		err: cloudprovider.NewNodeClaimNotFoundError(errors.New("VM and dependents are absent")),
	}
	first, err := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return now }

	result, err := first.Reconcile(ctx, claim.DeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != terminationRecoveryConfirmationGap || deleter.calls != 0 {
		t.Fatalf("first absence result=%#v delete calls=%d", result, deleter.calls)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	observation, err := decodeTerminationRecoveryObservation(stored.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		t.Fatal(err)
	}
	if !observation.FirstAbsentAt.Equal(now) || observation.NodeClaimUID != string(claim.UID) || observation.ProviderID != claim.Status.ProviderID {
		t.Fatalf("first durable absence observation = %#v", observation)
	}

	// A new controller instance proves that no in-memory timer or NodePool
	// lookup is required to complete recovery.
	restarted, err := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now.Add(terminationRecoveryConfirmationGap + time.Second) }
	result, err = restarted.Reconcile(ctx, stored)
	if err != nil {
		t.Fatal(err)
	}
	if result != (clientResultZero()) || deleter.calls != 1 {
		t.Fatalf("restarted recovery result=%#v delete calls=%d", result, deleter.calls)
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if containsString(stored.Finalizers, karpv1.TerminationFinalizer) {
		t.Fatalf("Karpenter termination finalizer was retained: %v", stored.Finalizers)
	}
	if !containsString(stored.Finalizers, CreateFenceFinalizer) || !containsString(stored.Finalizers, "example.com/independent") {
		t.Fatalf("recovery removed an independent finalizer: %v", stored.Finalizers)
	}
	if stored.Annotations[AnnotationTerminationRecovery] == "" || stored.Annotations[AnnotationCreateFence] == "" {
		t.Fatalf("recovery removed durable provider audit state: annotations=%v", stored.Annotations)
	}
}

func TestTerminationRecoveryWaitsForSpacedSecondAbsence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}

	controller.now = func() time.Time { return now.Add(11 * time.Second) }
	result, err := controller.Reconcile(ctx, getTerminationRecoveryClaim(t, kubeClient, claim.Name))
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 19*time.Second || deleter.calls != 0 {
		t.Fatalf("early second observation result=%#v delete calls=%d", result, deleter.calls)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) {
		t.Fatal("early observation released Karpenter's finalizer")
	}
}

func TestTerminationRecoveryResetsAndRestartsProofWhenNodeReappears(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(ctx, claim); err != nil {
		t.Fatal(err)
	}

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-reappeared"},
		Spec:       corev1.NodeSpec{ProviderID: claim.Status.ProviderID},
	}
	if err := kubeClient.Create(ctx, node); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := controller.Reconcile(ctx, getTerminationRecoveryClaim(t, kubeClient, claim.Name)); err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if stored.Annotations[AnnotationTerminationRecovery] != "" || deleter.calls != 0 {
		t.Fatalf("reappeared Node did not reset proof: annotation=%q calls=%d", stored.Annotations[AnnotationTerminationRecovery], deleter.calls)
	}

	if err := kubeClient.Delete(ctx, node); err != nil {
		t.Fatal(err)
	}
	restartedAt := now.Add(2 * time.Minute)
	controller.now = func() time.Time { return restartedAt }
	if _, err := controller.Reconcile(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	observation, err := decodeTerminationRecoveryObservation(stored.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		t.Fatal(err)
	}
	if !observation.FirstAbsentAt.Equal(restartedAt) || deleter.calls != 0 {
		t.Fatalf("absence proof did not restart after Node disappearance: %#v calls=%d", observation, deleter.calls)
	}
}

func TestTerminationRecoveryDoesNothingOutsideExactStuckLifecycleState(t *testing.T) {
	tests := map[string]func(*karpv1.NodeClaim){
		"not deleting": func(claim *karpv1.NodeClaim) {
			claim.DeletionTimestamp = nil
		},
		"provider ID empty": func(claim *karpv1.NodeClaim) {
			claim.Status.ProviderID = ""
		},
		"not registered": func(claim *karpv1.NodeClaim) {
			claim.Status.Conditions = nil
		},
		"instance terminating condition present": func(claim *karpv1.NodeClaim) {
			claim.StatusConditions().SetTrue(karpv1.ConditionTypeInstanceTerminating)
		},
		"instance terminating false condition still present": func(claim *karpv1.NodeClaim) {
			claim.StatusConditions().SetFalse(karpv1.ConditionTypeInstanceTerminating, "Pending", "upstream lifecycle owns termination")
		},
		"Karpenter finalizer absent": func(claim *karpv1.NodeClaim) {
			claim.Finalizers = removeString(claim.Finalizers, karpv1.TerminationFinalizer)
		},
		"create protection absent": func(claim *karpv1.NodeClaim) {
			claim.Finalizers = removeString(claim.Finalizers, CreateFenceFinalizer)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claim := terminationRecoveryTestClaim(t)
			mutate(claim)
			kubeClient := terminationRecoveryClient(t, claim)
			deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
			controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
			if result, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil || result != (clientResultZero()) {
				t.Fatalf("Reconcile() result=%#v error=%v", result, err)
			}
			stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
			if stored.Annotations[AnnotationTerminationRecovery] != "" || deleter.calls != 0 {
				t.Fatalf("ineligible claim was mutated: observation=%q calls=%d", stored.Annotations[AnnotationTerminationRecovery], deleter.calls)
			}
		})
	}
}

func TestTerminationRecoveryMatchingNodePreventsFirstProof(t *testing.T) {
	claim := terminationRecoveryTestClaim(t)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "still-present"},
		Spec:       corev1.NodeSpec{ProviderID: claim.Status.ProviderID},
	}
	kubeClient := terminationRecoveryClient(t, claim, node)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	result, err := controller.Reconcile(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if result.RequeueAfter != terminationRecoveryNodePoll || stored.Annotations[AnnotationTerminationRecovery] != "" || deleter.calls != 0 {
		t.Fatalf("matching Node result=%#v observation=%q calls=%d", result, stored.Annotations[AnnotationTerminationRecovery], deleter.calls)
	}
}

func TestTerminationRecoveryPollClosesNodeDeletionMissedWakeup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 3, 30, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-with-missed-event"},
		Spec:       corev1.NodeSpec{ProviderID: claim.Status.ProviderID},
	}
	kubeClient := terminationRecoveryClient(t, claim, node)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }

	result, err := controller.Reconcile(ctx, claim.DeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != terminationRecoveryNodePoll {
		t.Fatalf("present Node result=%#v, want bounded poll", result)
	}
	// Delete only the Node. No NodeClaim field or annotation changes, modeling
	// the exact event/cache race that left RC14 claims stuck.
	if err := kubeClient.Delete(ctx, node); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return now.Add(terminationRecoveryNodePoll) }
	result, err = controller.Reconcile(ctx, claim.DeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != terminationRecoveryConfirmationGap || deleter.calls != 0 {
		t.Fatalf("first polled absence result=%#v calls=%d", result, deleter.calls)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if stored.Annotations[AnnotationTerminationRecovery] == "" {
		t.Fatal("timed Node poll did not persist the first absence proof")
	}

	controller.now = func() time.Time {
		return now.Add(terminationRecoveryNodePoll + terminationRecoveryConfirmationGap + time.Second)
	}
	if _, err := controller.Reconcile(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if containsString(stored.Finalizers, karpv1.TerminationFinalizer) || !containsString(stored.Finalizers, CreateFenceFinalizer) || deleter.calls != 1 {
		t.Fatalf("missed-wakeup recovery did not converge: finalizers=%v calls=%d", stored.Finalizers, deleter.calls)
	}
}

func TestTerminationRecoveryFailsClosedOnMalformedOrDriftedIdentity(t *testing.T) {
	tests := map[string]func(*karpv1.NodeClaim){
		"malformed provider ID": func(claim *karpv1.NodeClaim) {
			claim.Status.ProviderID = "malformed"
		},
		"noncanonical provider ID": func(claim *karpv1.NodeClaim) {
			claim.Status.ProviderID = "inspace://bkk01/22222222-2222-4222-8222-22222222222A"
		},
		"provider ID disagrees with fence": func(claim *karpv1.NodeClaim) {
			claim.Status.ProviderID = "inspace://bkk01/44444444-4444-4444-8444-444444444444"
		},
		"malformed create fence": func(claim *karpv1.NodeClaim) {
			claim.Annotations[AnnotationCreateFence] = "{"
		},
		"malformed removal fence": func(claim *karpv1.NodeClaim) {
			claim.Annotations[AnnotationRemovalMutationFence] = "{}"
		},
		"malformed recovery proof": func(claim *karpv1.NodeClaim) {
			claim.Annotations[AnnotationTerminationRecovery] = `{"schema":"wrong"}`
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claim := terminationRecoveryTestClaim(t)
			mutate(claim)
			kubeClient := terminationRecoveryClient(t, claim)
			deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
			controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
			if _, err := controller.Reconcile(context.Background(), claim); err == nil {
				t.Fatal("Reconcile() accepted malformed or drifted identity")
			}
			stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
			if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || deleter.calls != 0 {
				t.Fatalf("malformed identity reached recovery: finalizers=%v calls=%d", stored.Finalizers, deleter.calls)
			}
		})
	}
}

func TestTerminationRecoveryRejectsDriftedPersistedObservation(t *testing.T) {
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC) }
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	observation, err := decodeTerminationRecoveryObservation(stored.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		t.Fatal(err)
	}
	observation.CreateFenceSHA256 = strings.Repeat("a", 64)
	encoded, _ := jsonMarshal(observation)
	stored.Annotations[AnnotationTerminationRecovery] = encoded
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return time.Date(2026, 7, 18, 4, 1, 0, 0, time.UTC) }
	if _, err := controller.Reconcile(context.Background(), stored); err == nil {
		t.Fatal("Reconcile() accepted a drifted persisted observation")
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || deleter.calls != 0 {
		t.Fatalf("drifted proof reached recovery: finalizers=%v calls=%d", stored.Finalizers, deleter.calls)
	}
}

func TestTerminationRecoveryRejectsFuturePersistedObservation(t *testing.T) {
	now := time.Date(2026, 7, 18, 4, 30, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	observation, err := decodeTerminationRecoveryObservation(stored.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		t.Fatal(err)
	}
	observation.FirstAbsentAt = now.Add(24 * time.Hour)
	encoded, _ := jsonMarshal(observation)
	stored.Annotations[AnnotationTerminationRecovery] = encoded
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Reconcile(context.Background(), stored); err == nil || !strings.Contains(err.Error(), "from the future") {
		t.Fatalf("Reconcile() future-proof error = %v", err)
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || deleter.calls != 0 {
		t.Fatalf("future proof reached recovery: finalizers=%v calls=%d", stored.Finalizers, deleter.calls)
	}
}

func TestTerminationRecoveryRejectsObservationPredatingDeletion(t *testing.T) {
	now := time.Date(2026, 7, 18, 4, 45, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	observation, err := decodeTerminationRecoveryObservation(stored.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		t.Fatal(err)
	}
	observation.FirstAbsentAt = stored.DeletionTimestamp.Time.Add(-time.Second)
	encoded, _ := jsonMarshal(observation)
	stored.Annotations[AnnotationTerminationRecovery] = encoded
	if err := kubeClient.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Reconcile(context.Background(), stored); err == nil || !strings.Contains(err.Error(), "predates deletion") {
		t.Fatalf("Reconcile() pre-deletion proof error = %v", err)
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || deleter.calls != 0 {
		t.Fatalf("pre-deletion proof reached recovery: finalizers=%v calls=%d", stored.Finalizers, deleter.calls)
	}
}

func TestTerminationRecoveryAcceptsOnlyTypedNodeClaimNotFound(t *testing.T) {
	tests := map[string]error{
		"nil":     nil,
		"generic": errors.New("temporary cloud failure"),
		"pending": cloudapi.ErrCreateAttemptPending,
	}
	for name, deleteErr := range tests {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC)
			claim := terminationRecoveryTestClaim(t)
			kubeClient := terminationRecoveryClient(t, claim)
			deleter := &recordingTerminationDeleter{err: deleteErr}
			controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
			controller.now = func() time.Time { return now }
			if _, err := controller.Reconcile(context.Background(), claim); err != nil {
				t.Fatal(err)
			}
			controller.now = func() time.Time { return now.Add(time.Minute) }
			if _, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name)); err == nil {
				t.Fatalf("Reconcile() accepted %s cloud response", name)
			}
			stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
			if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || deleter.calls != 1 {
				t.Fatalf("%s cloud response changed finalizer: %v calls=%d", name, stored.Finalizers, deleter.calls)
			}
		})
	}
}

func TestTerminationRecoveryRechecksNodeAfterTerminalCloudAudit(t *testing.T) {
	now := time.Date(2026, 7, 18, 6, 0, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{}
	deleter.onDelete = func(_ context.Context, deleting *karpv1.NodeClaim) error {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "late-node"},
			Spec:       corev1.NodeSpec{ProviderID: deleting.Status.ProviderID},
		}
		if err := kubeClient.Create(context.Background(), node); err != nil {
			return err
		}
		return cloudprovider.NewNodeClaimNotFoundError(errors.New("cloud absent"))
	}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name)); err != nil {
		t.Fatal(err)
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) || stored.Annotations[AnnotationTerminationRecovery] != "" {
		t.Fatalf("late Node did not abort and reset recovery: finalizers=%v observation=%q", stored.Finalizers, stored.Annotations[AnnotationTerminationRecovery])
	}
}

func TestTerminationRecoveryRechecksClaimIdentityAfterTerminalCloudAudit(t *testing.T) {
	now := time.Date(2026, 7, 18, 7, 0, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{}
	deleter.onDelete = func(_ context.Context, deleting *karpv1.NodeClaim) error {
		current := getTerminationRecoveryClaim(t, kubeClient, deleting.Name)
		current.Status.ProviderID = "inspace://bkk01/44444444-4444-4444-8444-444444444444"
		if err := kubeClient.Update(context.Background(), current); err != nil {
			return err
		}
		return cloudprovider.NewNodeClaimNotFoundError(errors.New("cloud absent"))
	}
	controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name)); err == nil {
		t.Fatal("Reconcile() accepted claim identity drift after cloud audit")
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if !containsString(stored.Finalizers, karpv1.TerminationFinalizer) {
		t.Fatal("claim identity drift released Karpenter's finalizer")
	}
}

func TestTerminationRecoveryAPIReadErrorsNeverReachCloudOrFinalizerMutation(t *testing.T) {
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	reader := &failingNodeListReader{Reader: kubeClient, failOnCall: 1, err: errors.New("API unavailable")}
	deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
	controller, _ := NewTerminationRecoveryController(kubeClient, reader, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), claim); err == nil {
		t.Fatal("Reconcile() ignored uncached Node list error")
	}
	stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if stored.Annotations[AnnotationTerminationRecovery] != "" || deleter.calls != 0 || !containsString(stored.Finalizers, karpv1.TerminationFinalizer) {
		t.Fatalf("API error reached mutation: observation=%q calls=%d finalizers=%v", stored.Annotations[AnnotationTerminationRecovery], deleter.calls, stored.Finalizers)
	}

	reader = &failingNodeListReader{Reader: kubeClient, failOnCall: 3, err: errors.New("API unavailable after cloud audit")}
	controller, _ = NewTerminationRecoveryController(kubeClient, reader, deleter)
	controller.now = func() time.Time { return now }
	if _, err := controller.Reconcile(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	controller.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name)); err == nil {
		t.Fatal("Reconcile() ignored post-cloud uncached Node list error")
	}
	stored = getTerminationRecoveryClaim(t, kubeClient, claim.Name)
	if deleter.calls != 1 || !containsString(stored.Finalizers, karpv1.TerminationFinalizer) {
		t.Fatalf("post-cloud API error released finalizer: calls=%d finalizers=%v", deleter.calls, stored.Finalizers)
	}
}

func TestTerminationRecoveryRequeuesOnOptimisticLockConflicts(t *testing.T) {
	t.Run("persist first absence proof", func(t *testing.T) {
		claim := terminationRecoveryTestClaim(t)
		kubeClient := terminationRecoveryClient(t, claim)
		writer := &conflictingPatchClient{Client: kubeClient, remaining: 1}
		deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
		controller, _ := NewTerminationRecoveryController(writer, kubeClient, deleter)

		result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
		if err != nil {
			t.Fatal(err)
		}
		stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
		if !result.Requeue || result.RequeueAfter != 0 ||
			stored.Annotations[AnnotationTerminationRecovery] != "" ||
			deleter.calls != 0 {
			t.Fatalf("first-proof conflict result=%#v observation=%q calls=%d", result, stored.Annotations[AnnotationTerminationRecovery], deleter.calls)
		}
	})

	t.Run("reset proof after Node reappears", func(t *testing.T) {
		now := time.Date(2026, 7, 18, 8, 30, 0, 0, time.UTC)
		claim := terminationRecoveryTestClaim(t)
		kubeClient := terminationRecoveryClient(t, claim)
		deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
		controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
		controller.now = func() time.Time { return now }
		if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-returned-before-reset"},
			Spec:       corev1.NodeSpec{ProviderID: claim.Status.ProviderID},
		}
		if err := kubeClient.Create(context.Background(), node); err != nil {
			t.Fatal(err)
		}

		writer := &conflictingPatchClient{Client: kubeClient, remaining: 1}
		controller, _ = NewTerminationRecoveryController(writer, kubeClient, deleter)
		controller.now = func() time.Time { return now.Add(time.Second) }
		result, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name))
		if err != nil {
			t.Fatal(err)
		}
		stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
		if !result.Requeue || result.RequeueAfter != 0 ||
			stored.Annotations[AnnotationTerminationRecovery] == "" ||
			deleter.calls != 0 {
			t.Fatalf("proof-reset conflict result=%#v observation=%q calls=%d", result, stored.Annotations[AnnotationTerminationRecovery], deleter.calls)
		}
	})

	t.Run("remove Karpenter finalizer", func(t *testing.T) {
		now := time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)
		claim := terminationRecoveryTestClaim(t)
		kubeClient := terminationRecoveryClient(t, claim)
		deleter := &recordingTerminationDeleter{err: cloudprovider.NewNodeClaimNotFoundError(errors.New("gone"))}
		controller, _ := NewTerminationRecoveryController(kubeClient, kubeClient, deleter)
		controller.now = func() time.Time { return now }
		if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
			t.Fatal(err)
		}

		writer := &conflictingPatchClient{Client: kubeClient, remaining: 1}
		controller, _ = NewTerminationRecoveryController(writer, kubeClient, deleter)
		controller.now = func() time.Time { return now.Add(terminationRecoveryConfirmationGap + time.Second) }
		result, err := controller.Reconcile(context.Background(), getTerminationRecoveryClaim(t, kubeClient, claim.Name))
		if err != nil {
			t.Fatal(err)
		}
		stored := getTerminationRecoveryClaim(t, kubeClient, claim.Name)
		if !result.Requeue || result.RequeueAfter != 0 ||
			!containsString(stored.Finalizers, karpv1.TerminationFinalizer) ||
			!containsString(stored.Finalizers, CreateFenceFinalizer) ||
			deleter.calls != 1 {
			t.Fatalf("finalizer conflict result=%#v finalizers=%v calls=%d", result, stored.Finalizers, deleter.calls)
		}
	})
}

func TestDecodeTerminationRecoveryObservationRejectsNonCanonicalInput(t *testing.T) {
	valid := terminationRecoveryObservation{
		Schema: terminationRecoverySchema, NodeClaimUID: "claim-uid",
		ProviderID:        "inspace://bkk01/22222222-2222-4222-8222-222222222222",
		CreateFenceSHA256: strings.Repeat("a", 64),
		FirstAbsentAt:     time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC),
	}
	encoded, _ := jsonMarshal(valid)
	tests := map[string]string{
		"empty":           "",
		"unknown field":   strings.TrimSuffix(encoded, "}") + `,"unknown":true}`,
		"duplicate field": strings.Replace(encoded, `"schema":"`+terminationRecoverySchema+`"`, `"schema":"`+terminationRecoverySchema+`","schema":"`+terminationRecoverySchema+`"`, 1),
		"trailing JSON":   encoded + `{}`,
		"bad digest":      strings.Replace(encoded, strings.Repeat("a", 64), "not-a-digest", 1),
		"bad provider ID": strings.Replace(encoded, valid.ProviderID, "malformed", 1),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeTerminationRecoveryObservation(value); err == nil {
				t.Fatalf("decodeTerminationRecoveryObservation() accepted %s", name)
			}
		})
	}
	if got, err := decodeTerminationRecoveryObservation(encoded); err != nil || got != valid {
		t.Fatalf("valid observation decoded as %#v, %v", got, err)
	}
}

func TestNewTerminationRecoveryControllerRequiresAllDependencies(t *testing.T) {
	claim := terminationRecoveryTestClaim(t)
	kubeClient := terminationRecoveryClient(t, claim)
	deleter := &recordingTerminationDeleter{}
	tests := []struct {
		writer   client.Client
		reader   client.Reader
		provider nodeClaimDeleter
	}{
		{reader: kubeClient, provider: deleter},
		{writer: kubeClient, provider: deleter},
		{writer: kubeClient, reader: kubeClient},
	}
	for i, test := range tests {
		if _, err := NewTerminationRecoveryController(test.writer, test.reader, test.provider); err == nil {
			t.Fatalf("constructor accepted missing dependency %d", i)
		}
	}
}

type recordingTerminationDeleter struct {
	calls    int
	err      error
	onDelete func(context.Context, *karpv1.NodeClaim) error
}

func (d *recordingTerminationDeleter) Delete(ctx context.Context, nodeClaim *karpv1.NodeClaim) error {
	d.calls++
	if d.onDelete != nil {
		return d.onDelete(ctx, nodeClaim)
	}
	return d.err
}

type failingNodeListReader struct {
	client.Reader
	calls      int
	failOnCall int
	err        error
}

func (r *failingNodeListReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.NodeList); ok {
		r.calls++
		if r.calls == r.failOnCall {
			return r.err
		}
	}
	return r.Reader.List(ctx, list, opts...)
}

type conflictingPatchClient struct {
	client.Client
	remaining int
}

func (c *conflictingPatchClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if c.remaining > 0 {
		c.remaining--
		return apierrors.NewConflict(
			schema.GroupResource{Group: "karpenter.sh", Resource: "nodeclaims"},
			object.GetName(),
			errors.New("injected optimistic-lock conflict"),
		)
	}
	return c.Client.Patch(ctx, object, patch, options...)
}

func terminationRecoveryTestClaim(t *testing.T) *karpv1.NodeClaim {
	t.Helper()
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	now := metav1.NewTime(time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC))
	claim.DeletionTimestamp = &now
	claim.Status.ProviderID = "inspace://bkk01/22222222-2222-4222-8222-222222222222"
	claim.StatusConditions().SetTrue(karpv1.ConditionTypeRegistered)
	claim.Finalizers = append(claim.Finalizers, "example.com/independent")
	return claim
}

func terminationRecoveryClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(kubescheme.Scheme).
		WithObjects(objects...).
		Build()
}

func getTerminationRecoveryClaim(t *testing.T, reader client.Reader, name string) *karpv1.NodeClaim {
	t.Helper()
	var claim karpv1.NodeClaim
	if err := reader.Get(context.Background(), types.NamespacedName{Name: name}, &claim); err != nil {
		t.Fatal(err)
	}
	return &claim
}

func removeString(values []string, remove string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			result = append(result, value)
		}
	}
	return result
}

func jsonMarshal(value any) (string, error) {
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func clientResultZero() reconcile.Result {
	return reconcile.Result{}
}
