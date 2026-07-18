package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestKubernetesCreateFenceTransitionsReservedIssuedMaterializedExactlyOnce(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	baseline := cloudapi.CreateInventory{
		VMs:          []string{"11111111-1111-4111-8111-111111111111"},
		PotentialVMs: []string{"11111111-1111-4111-8111-111111111111"},
		FloatingIPs:  []string{"address:203.0.113.9"},
	}

	fenced, reserved, allowLaunch, err := store.Ensure(ctx, claim, binding, cleanup, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !allowLaunch || reserved.Issued {
		t.Fatalf("initial fence = %#v, allow=%t; want reserved launch authority", reserved, allowLaunch)
	}
	record, err := decodeCreateFence(fenced.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceReserved || !containsString(fenced.Finalizers, CreateFenceFinalizer) {
		t.Fatalf("persisted reserved fence = %#v, err=%v, finalizers=%v", record, err, fenced.Finalizers)
	}
	reservedVM := &cloudapi.VM{
		UUID: "22222222-2222-4222-8222-222222222222", Name: cleanup.VMName,
		ClusterName: cleanup.ClusterName, NodeClaimName: cleanup.NodeClaimName, Location: cleanup.Location,
		BillingAccountID: cleanup.BillingAccountID, FloatingIPName: "fenced-public", PublicIPv4: "203.0.113.10",
	}
	if _, err := store.MarkMaterialized(ctx, fenced, binding, reserved.Token, reservedVM); err == nil {
		t.Fatal("MarkMaterialized() accepted reserved -> materialized without an issued CAS")
	}

	retryClaim, retryFence, exists, err := store.Get(ctx, fenced, binding, cleanup)
	if err != nil || !exists || retryFence.Issued {
		t.Fatalf("Get() = exists=%t fence=%#v err=%v, want reusable reserved preflight", exists, retryFence, err)
	}
	issuedClaim, err := store.Authorize(ctx, retryClaim, binding, retryFence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issuedClaim.Annotations[AnnotationCreateFence])
	if err != nil || issuedRecord.Phase != createFenceIssued || issuedRecord.IssuedAt == nil {
		t.Fatalf("issued readback = %#v, err=%v", issuedRecord, err)
	}
	if _, err := store.Authorize(ctx, issuedClaim, binding, retryFence.Token, cloudapi.CreateAuthorizationPost); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("second Authorize() error = %v, want immutable-attempt pending", err)
	}
	issuedClaim, err = store.RecordCreatedVM(ctx, issuedClaim, binding, retryFence.Token, issuedRecord.IssueID, reservedVM.UUID)
	if err != nil {
		t.Fatal(err)
	}
	issuedClaim, firewallAuthorization, err := store.AuthorizeBaseFirewall(ctx, issuedClaim, binding, retryFence.Token, reservedVM.UUID)
	if err != nil {
		t.Fatal(err)
	}
	issuedClaim, err = store.ObserveBaseFirewall(ctx, issuedClaim, binding, retryFence.Token, reservedVM.UUID, firewallAuthorization.Fence.IssueID)
	if err != nil {
		t.Fatal(err)
	}

	vm := reservedVM
	issuedClaim = observeTestFloatingIPUpdate(t, store, issuedClaim, binding, retryFence.Token, vm)
	materializedClaim, err := store.MarkMaterialized(ctx, issuedClaim, binding, retryFence.Token, vm)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := decodeCreateFence(materializedClaim.Annotations[AnnotationCreateFence])
	if err != nil || materialized.Phase != createFenceMaterialized || materialized.ObservedVMUUID != vm.UUID || materialized.IssuedAt == nil {
		t.Fatalf("materialized readback = %#v, err=%v", materialized, err)
	}
}

func TestRemovalMutationFenceSurvivesStoreRestartAndOnlyBlockedIssueCanReset(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationVMDelete, Location: cleanup.Location,
		VMUUID: "22222222-2222-4222-8222-222222222222",
	}
	issuedClaim, first, err := store.AuthorizeRemovalMutation(ctx, fenced, binding, fence.Token, mutation, true)
	if err != nil || !first.Active || !first.AllowMutation || first.Fence.Phase != cloudapi.RemovalMutationIssued {
		t.Fatalf("first removal authorization = %#v, %v", first, err)
	}

	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	_, replay, err := restarted.AuthorizeRemovalMutation(ctx, issuedClaim, binding, fence.Token, mutation, true)
	if err != nil || !replay.Active || replay.AllowMutation || replay.Fence.IssueID != first.Fence.IssueID {
		t.Fatalf("restarted issued authorization = %#v, %v; want read-only same issue", replay, err)
	}
	rejectedClaim, err := restarted.RejectRemovalMutation(ctx, issuedClaim, binding, fence.Token, first.Fence)
	if err != nil {
		t.Fatal(err)
	}
	resetClaim, reset, err := restarted.AuthorizeRemovalMutation(ctx, rejectedClaim, binding, fence.Token, mutation, true)
	if err != nil || !reset.AllowMutation || reset.Fence.IssueID == first.Fence.IssueID {
		t.Fatalf("blocked issue reset = %#v, %v", reset, err)
	}
	observedClaim, err := restarted.ObserveRemovalMutation(ctx, resetClaim, binding, fence.Token, reset.Fence)
	if err != nil {
		t.Fatal(err)
	}
	fipDelete := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: cleanup.Location,
		VMUUID: mutation.VMUUID, Address: "203.0.113.10", Name: "owned-fip", BillingAccountID: cleanup.BillingAccountID,
	}
	_, next, err := restarted.AuthorizeRemovalMutation(ctx, observedClaim, binding, fence.Token, fipDelete, true)
	if err != nil || !next.AllowMutation {
		t.Fatalf("next serialized removal = %#v, %v", next, err)
	}
}

func TestObservedRemovalMutationAbsentLookupIsReadOnlyAfterStoreRestart(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := cloudapi.RemovalMutation{
		Operation:        cloudapi.RemovalMutationFloatingIPDelete,
		Location:         cleanup.Location,
		VMUUID:           "22222222-2222-4222-8222-222222222222",
		Address:          "203.0.113.10",
		Name:             "owned-fip",
		BillingAccountID: cleanup.BillingAccountID,
	}
	issuedClaim, issued, err := store.AuthorizeRemovalMutation(ctx, fenced, binding, fence.Token, mutation, true)
	if err != nil || !issued.Active || !issued.AllowMutation || issued.Fence.Phase != cloudapi.RemovalMutationIssued {
		t.Fatalf("issued removal authorization = %#v, %v", issued, err)
	}
	forged := issued.Fence
	forged.IssuedAt = forged.IssuedAt.Add(-time.Hour)
	if _, err := store.ObserveRemovalMutation(ctx, issuedClaim, binding, fence.Token, forged); err == nil ||
		!strings.Contains(err.Error(), "issue time changed") {
		t.Fatalf("forged removal issue-time observation error = %v", err)
	}
	observedClaim, err := store.ObserveRemovalMutation(ctx, issuedClaim, binding, fence.Token, issued.Fence)
	if err != nil {
		t.Fatal(err)
	}

	var persisted karpv1.NodeClaim
	if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &persisted); err != nil {
		t.Fatal(err)
	}
	before := persisted.Annotations[AnnotationRemovalMutationFence]
	if before == "" {
		t.Fatal("observed removal mutation was not persisted")
	}
	assertUnchanged := func(phase string) {
		t.Helper()
		var current karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &current); err != nil {
			t.Fatal(err)
		}
		if got := current.Annotations[AnnotationRemovalMutationFence]; got != before {
			t.Fatalf("%s changed observed removal annotation:\nbefore=%s\nafter=%s", phase, before, got)
		}
	}

	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	readClaim, exactAbsent, err := restarted.AuthorizeRemovalMutation(
		ctx,
		observedClaim,
		binding,
		fence.Token,
		mutation,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if readClaim == nil || !exactAbsent.Active || exactAbsent.AllowMutation ||
		exactAbsent.Fence.RemovalMutation != issued.Fence.RemovalMutation ||
		exactAbsent.Fence.IssueID != issued.Fence.IssueID ||
		exactAbsent.Fence.Phase != cloudapi.RemovalMutationObserved {
		t.Fatalf("exact observed absent lookup = %#v claim=%#v", exactAbsent, readClaim)
	}
	assertUnchanged("exact absent lookup")

	different := mutation
	different.Address = "203.0.113.11"
	readClaim, differentAbsent, err := restarted.AuthorizeRemovalMutation(
		ctx,
		readClaim,
		binding,
		fence.Token,
		different,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if readClaim == nil || differentAbsent.Active || differentAbsent.AllowMutation ||
		differentAbsent.Fence != (cloudapi.RemovalMutationFence{}) {
		t.Fatalf("different observed absent lookup = %#v claim=%#v", differentAbsent, readClaim)
	}
	assertUnchanged("different absent lookup")

	if _, _, err := restarted.AuthorizeRemovalMutation(
		ctx,
		readClaim,
		binding,
		fence.Token,
		mutation,
		true,
	); err == nil || !strings.Contains(err.Error(), "observed removal resource reappeared") {
		t.Fatalf("exact observed present lookup error = %v", err)
	}
	assertUnchanged("exact present rejection")
}

func TestRemovalMutationAbsentLookupRequiresExactObservedPhase(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	current, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: cleanup.Location,
		VMUUID: "22222222-2222-4222-8222-222222222222", Address: "203.0.113.10",
		Name: "owned-fip", BillingAccountID: cleanup.BillingAccountID,
	}
	assertLookup := func(label string, expectedPhase cloudapi.RemovalMutationPhase, wantActive bool) {
		t.Helper()
		var beforeClaim karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &beforeClaim); err != nil {
			t.Fatal(err)
		}
		before := beforeClaim.Annotations[AnnotationRemovalMutationFence]
		var authorization cloudapi.RemovalMutationAuthorization
		current, authorization, err = store.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, false)
		if err != nil {
			t.Fatalf("%s absent lookup = %v", label, err)
		}
		if authorization.Active != wantActive || authorization.AllowMutation {
			t.Fatalf("%s absent lookup = %#v, want active=%t and read-only", label, authorization, wantActive)
		}
		if wantActive && (authorization.Fence.Phase != expectedPhase ||
			authorization.Fence.IssuedAt.IsZero() ||
			(expectedPhase == cloudapi.RemovalMutationObserved &&
				authorization.Fence.ObservedAt.Before(authorization.Fence.IssuedAt))) {
			t.Fatalf("%s absent lookup fence = %#v", label, authorization.Fence)
		}
		var afterClaim karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &afterClaim); err != nil {
			t.Fatal(err)
		}
		if after := afterClaim.Annotations[AnnotationRemovalMutationFence]; after != before {
			t.Fatalf("%s absent lookup changed annotation:\nbefore=%s\nafter=%s", label, before, after)
		}
	}

	assertLookup("ready", "", false)
	var issued cloudapi.RemovalMutationAuthorization
	current, issued, err = store.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, true)
	if err != nil || !issued.AllowMutation {
		t.Fatalf("issue = %#v, %v", issued, err)
	}
	assertLookup("issued", cloudapi.RemovalMutationIssued, true)
	current, err = store.RejectRemovalMutation(ctx, current, binding, fence.Token, issued.Fence)
	if err != nil {
		t.Fatal(err)
	}
	assertLookup("rejected", cloudapi.RemovalMutationRejected, true)
	current, issued, err = store.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, true)
	if err != nil || !issued.AllowMutation {
		t.Fatalf("reissue = %#v, %v", issued, err)
	}
	current, err = store.ObserveRemovalMutation(ctx, current, binding, fence.Token, issued.Fence)
	if err != nil {
		t.Fatal(err)
	}
	assertLookup("observed", cloudapi.RemovalMutationObserved, true)
}

func TestObservedFloatingIPDeleteHistorySurvivesLaterRemovalSlots(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	current, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	mutations := []cloudapi.RemovalMutation{
		{
			Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: cleanup.Location,
			VMUUID: "22222222-2222-4222-8222-222222222222", Address: "203.0.113.10",
			Name: "owned-fip-a", BillingAccountID: cleanup.BillingAccountID,
		},
		{
			Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: cleanup.Location,
			VMUUID: "33333333-3333-4333-8333-333333333333", Address: "203.0.113.11",
			Name: "owned-fip-b", BillingAccountID: cleanup.BillingAccountID,
		},
	}
	for index, mutation := range mutations {
		var authorization cloudapi.RemovalMutationAuthorization
		current, authorization, err = store.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, true)
		if err != nil || !authorization.Active || !authorization.AllowMutation {
			t.Fatalf("authorizing %s = %#v, %v", mutation.Address, authorization, err)
		}
		current, err = store.ObserveRemovalMutation(ctx, current, binding, fence.Token, authorization.Fence)
		if err != nil {
			t.Fatalf("observing %s = %v", mutation.Address, err)
		}
		if index == 0 {
			// Model an rc.1 record created before observed-delete history
			// existed. Advancing the slot must archive this current receipt.
			legacy, decodeErr := decodeRemovalMutationRecord(
				current.Annotations[AnnotationRemovalMutationFence],
				binding,
				fence.Token,
			)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			legacy.ObservedFloatingIPDeletes = nil
			current = claimWithRemovalMutation(current, legacy)
			if err := kubeClient.Update(ctx, current); err != nil {
				t.Fatal(err)
			}
		}
	}

	var persisted karpv1.NodeClaim
	if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &persisted); err != nil {
		t.Fatal(err)
	}
	before := persisted.Annotations[AnnotationRemovalMutationFence]
	record, err := decodeRemovalMutationRecord(before, binding, fence.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.ObservedFloatingIPDeletes) != len(mutations) {
		t.Fatalf("observed delete history has %d entries, want %d", len(record.ObservedFloatingIPDeletes), len(mutations))
	}

	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range mutations {
		var authorization cloudapi.RemovalMutationAuthorization
		current, authorization, err = restarted.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, false)
		if err != nil {
			t.Fatalf("reading historical %s = %v", mutation.Address, err)
		}
		if current == nil || !authorization.Active || authorization.AllowMutation ||
			authorization.Fence.Phase != cloudapi.RemovalMutationObserved ||
			authorization.Fence.RemovalMutation != mutation ||
			authorization.Fence.IssuedAt.IsZero() ||
			authorization.Fence.ObservedAt.Before(authorization.Fence.IssuedAt) {
			t.Fatalf("historical authorization for %s = %#v", mutation.Address, authorization)
		}
		if _, _, err := restarted.AuthorizeRemovalMutation(ctx, current, binding, fence.Token, mutation, true); err == nil ||
			!strings.Contains(err.Error(), "observed removal resource reappeared") {
			t.Fatalf("historical present lookup for %s = %v", mutation.Address, err)
		}
	}
	if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &persisted); err != nil {
		t.Fatal(err)
	}
	if after := persisted.Annotations[AnnotationRemovalMutationFence]; after != before {
		t.Fatalf("historical lookups changed removal annotation:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestRemovalMutationHistoryMaximumRoundTripsWithinAnnotationBound(t *testing.T) {
	claim := createFenceTestNodeClaim()
	binding, _ := createFenceTestIdentity(claim)
	token := strings.Repeat("1", 32)
	now := time.Date(2026, time.July, 18, 3, 0, 0, 0, time.UTC)
	record := newRemovalMutationReadyRecord(binding, token, now.Add(-time.Hour))
	record.Operation = cloudapi.RemovalMutationVMDelete
	record.Location = "bkk01"
	record.VMUUID = "99999999-9999-4999-8999-999999999999"
	record.Phase = cloudapi.RemovalMutationObserved
	record.IssueID = strings.Repeat("f", 32)
	issuedAt := now.Add(-time.Minute)
	observedAt := now
	record.IssuedAt = &issuedAt
	record.ObservedAt = &observedAt
	for i := 0; i < cloudapi.MaxCreateCleanupResolutions; i++ {
		record.ObservedFloatingIPDeletes = append(record.ObservedFloatingIPDeletes, observedFloatingIPDeleteRecord{
			Location:   "bkk01",
			VMUUID:     fmt.Sprintf("11111111-1111-4111-8111-%012x", i+1),
			Address:    fmt.Sprintf("203.0.113.%d", i+1),
			Name:       fmt.Sprintf("%03d-%s", i, strings.Repeat("n", 251)),
			BillingID:  1,
			IssueID:    fmt.Sprintf("%032x", i+1),
			IssuedAt:   issuedAt.Add(time.Duration(i) * time.Second),
			ObservedAt: observedAt.Add(time.Duration(i) * time.Second),
		})
	}
	encoded := mustEncodeRemovalMutation(record)
	if len(encoded) > maxRemovalMutationEncodedBytes {
		t.Fatalf("maximum removal history encodes to %d bytes, limit %d", len(encoded), maxRemovalMutationEncodedBytes)
	}
	decoded, err := decodeRemovalMutationRecord(encoded, binding, token)
	if err != nil {
		t.Fatalf("decoding maximum removal history = %v", err)
	}
	if len(decoded.ObservedFloatingIPDeletes) != cloudapi.MaxCreateCleanupResolutions {
		t.Fatalf("decoded %d historical deletes, want %d", len(decoded.ObservedFloatingIPDeletes), cloudapi.MaxCreateCleanupResolutions)
	}
	record.ObservedFloatingIPDeletes = append(record.ObservedFloatingIPDeletes, record.ObservedFloatingIPDeletes[0])
	if _, err := decodeRemovalMutationRecord(mustEncodeRemovalMutation(record), binding, token); err == nil ||
		!strings.Contains(err.Error(), "too many") {
		t.Fatalf("oversized history decode error = %v", err)
	}
}

func TestRemovalMutationFenceConcurrentControllersGrantOneCloudCall(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	initializer, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := initializer.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationVMDelete, Location: cleanup.Location,
		VMUUID: "22222222-2222-4222-8222-222222222222",
	}
	stores := make([]CreateFenceStore, 2)
	for i := range stores {
		stores[i], err = NewKubernetesCreateFenceStore(kubeClient, kubeClient)
		if err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		authorization cloudapi.RemovalMutationAuthorization
		err           error
	}
	results := make(chan result, len(stores))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, candidate := range stores {
		wg.Add(1)
		go func(store CreateFenceStore) {
			defer wg.Done()
			<-start
			_, authorization, authorizeErr := store.AuthorizeRemovalMutation(ctx, fenced, binding, fence.Token, mutation, true)
			results <- result{authorization: authorization, err: authorizeErr}
		}(candidate)
	}
	close(start)
	wg.Wait()
	close(results)
	allowed := 0
	for value := range results {
		if value.err != nil {
			t.Fatalf("concurrent authorization failed: %v", value.err)
		}
		if value.authorization.AllowMutation {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent cloud mutation grants = %d, want exactly one", allowed)
	}
}

func TestRemovalMutationFenceMalformedAndConflictingStateFailsClosed(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	vmDelete := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationVMDelete, Location: cleanup.Location,
		VMUUID: "22222222-2222-4222-8222-222222222222",
	}
	issued, _, err := store.AuthorizeRemovalMutation(ctx, fenced, binding, fence.Token, vmDelete, true)
	if err != nil {
		t.Fatal(err)
	}
	conflict := cloudapi.RemovalMutation{
		Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: cleanup.Location,
		VMUUID: vmDelete.VMUUID, Address: "203.0.113.10", Name: "owned-fip", BillingAccountID: cleanup.BillingAccountID,
	}
	if _, _, err := store.AuthorizeRemovalMutation(ctx, issued, binding, fence.Token, conflict, true); err == nil {
		t.Fatal("different present mutation bypassed unresolved VM DELETE receipt")
	}

	var current karpv1.NodeClaim
	if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &current); err != nil {
		t.Fatal(err)
	}
	current.Annotations[AnnotationRemovalMutationFence] = `{"schema":"broken"}`
	if err := kubeClient.Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthorizeRemovalMutation(ctx, &current, binding, fence.Token, vmDelete, true); err == nil {
		t.Fatal("malformed durable removal annotation did not fail closed")
	}
}

func TestKubernetesCreateFenceCanDurablyRejectOnlyIssuedAttempt(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRejected(ctx, fenced, binding, fence.Token, ""); err == nil {
		t.Fatal("MarkRejected() accepted a reserved attempt")
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.MarkRejected(ctx, issued, binding, fence.Token, issuedRecord.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(rejected.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceRejected || record.IssuedAt == nil || record.ObservedVMUUID != "" || record.CleanupVMUUID != "" {
		t.Fatalf("rejected fence = %#v, err=%v", record, err)
	}
}

func TestBaseFirewallPOSTCannotBeAuthorizedBeforeExactVMAnchor(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	_, authorization, err := store.AuthorizeBaseFirewall(ctx, issued, binding, fence.Token, "22222222-2222-4222-8222-222222222222")
	if err == nil || authorization.AllowPOST {
		t.Fatalf("AuthorizeBaseFirewall() before RecordCreatedVM = %#v, %v; want no POST authority", authorization, err)
	}
}

func TestBaseFirewallIssuedReceiptIsReadOnlyAcrossStoreRestart(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	anchored, first, err := store.AuthorizeBaseFirewall(ctx, anchored, binding, fence.Token, vmUUID)
	if err != nil || !first.AllowPOST {
		t.Fatalf("initial durable firewall-slot acquisition = %#v, %v", first, err)
	}

	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	_, authorization, err := restarted.AuthorizeBaseFirewall(ctx, anchored, binding, fence.Token, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.AllowPOST || authorization.Fence.Phase != cloudapi.FirewallAssignmentIssued ||
		authorization.Fence.IssueID != first.Fence.IssueID {
		t.Fatalf("restarted issued authorization = %#v, want same read-only receipt", authorization)
	}
}

func TestBaseFirewallLocallyProvenRejectionMintsExactlyOneFreshIssue(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.RejectBaseFirewall(ctx, anchored, binding, fence.Token, vmUUID, record.BaseFirewallAssignment.IssueID)
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	issuedAgain, first, err := restarted.AuthorizeBaseFirewall(ctx, rejected, binding, fence.Token, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.AllowPOST || first.Fence.Phase != cloudapi.FirewallAssignmentIssued || first.Fence.IssueID == record.BaseFirewallAssignment.IssueID {
		t.Fatalf("reauthorized rejection = %#v, want one fresh POST issue", first)
	}
	_, second, err := restarted.AuthorizeBaseFirewall(ctx, issuedAgain, binding, fence.Token, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	if second.AllowPOST || second.Fence != first.Fence {
		t.Fatalf("second authorization = %#v, want same read-only receipt %#v", second, first.Fence)
	}
}

func TestFloatingIPIssuedReceiptIsReadOnlyAcrossStoreRestart(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	anchored, first, err := store.AuthorizeFloatingIPUpdate(ctx, anchored, binding, fence.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.AllowPOST || first.Fence.Phase != cloudapi.FloatingIPUpdateIssued || anchored.Annotations[AnnotationFloatingIPUpdateFence] == "" {
		t.Fatalf("initial floating-IP authorization = %#v annotation=%q", first, anchored.Annotations[AnnotationFloatingIPUpdateFence])
	}
	restarted, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := restarted.AuthorizeFloatingIPUpdate(ctx, anchored, binding, fence.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if second.AllowPOST || second.Fence != first.Fence {
		t.Fatalf("restarted floating-IP authorization = %#v, want same read-only receipt %#v", second, first.Fence)
	}
}

func TestFloatingIPLocallyRejectedReceiptMintsOneFreshIssue(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	anchored, first, err := store.AuthorizeFloatingIPUpdate(ctx, anchored, binding, fence.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.RejectFloatingIPUpdate(ctx, anchored, binding, fence.Token, first.Fence)
	if err != nil {
		t.Fatal(err)
	}
	reissued, second, err := store.AuthorizeFloatingIPUpdate(ctx, rejected, binding, fence.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.AllowPOST || second.Fence.IssueID == first.Fence.IssueID || second.Fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("reauthorized floating-IP rejection = %#v, first=%#v", second, first)
	}
	_, third, err := store.AuthorizeFloatingIPUpdate(ctx, reissued, binding, fence.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if third.AllowPOST || third.Fence != second.Fence {
		t.Fatalf("third floating-IP authorization = %#v, want read-only %#v", third, second.Fence)
	}
}

const legacyV2MaterializedFenceJSON = `{"schema":"karpenter.inspace.cloud/create-fence-v2","binding":{"nodeClaimUID":"claim-uid","idempotencyKeyHash":"c6678a5678c3a1ae820cb07badff385f65cbbf782e536f519d4a2835e7c3daae","requestHash":"1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047","specHash":"spec","bootstrapHash":"bootstrap"},"cleanup":{"clusterName":"cluster-a","location":"bkk01","networkUUID":"11111111-1111-4111-8111-111111111111","controlPlaneVIP":"10.0.0.10","privateLoadBalancerPoolStart":"10.0.0.200","privateLoadBalancerPoolStop":"10.0.0.219","firewallUUID":"33333333-3333-4333-8333-333333333333","firewallProfile":"private-worker","nodeClaimName":"general-abc12","vmName":"cluster-a-karp-general-abc12","billingAccountID":1,"ownershipKeyHash":"c6678a5678c3a1ae820cb07badff385f"},"token":"11111111111111111111111111111111","phase":"materialized","intent":"post","issueID":"22222222222222222222222222222222","startedAt":"2026-01-01T00:00:00Z","issuedAt":"2026-01-01T00:01:00Z","launchObservedAt":"2026-01-01T00:02:00Z","createdVMUUID":"22222222-2222-4222-8222-222222222222","observedAt":"2026-01-01T00:03:00Z","observedVMUUID":"22222222-2222-4222-8222-222222222222","floatingIPName":"fenced-public","publicIPv4":"203.0.113.10"}`

const legacyV2IssuedUnanchoredFenceJSON = `{"schema":"karpenter.inspace.cloud/create-fence-v2","binding":{"nodeClaimUID":"claim-uid","idempotencyKeyHash":"c6678a5678c3a1ae820cb07badff385f65cbbf782e536f519d4a2835e7c3daae","requestHash":"1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047","specHash":"spec","bootstrapHash":"bootstrap"},"cleanup":{"clusterName":"cluster-a","location":"bkk01","networkUUID":"11111111-1111-4111-8111-111111111111","controlPlaneVIP":"10.0.0.10","privateLoadBalancerPoolStart":"10.0.0.200","privateLoadBalancerPoolStop":"10.0.0.219","firewallUUID":"33333333-3333-4333-8333-333333333333","firewallProfile":"private-worker","nodeClaimName":"general-abc12","vmName":"cluster-a-karp-general-abc12","billingAccountID":1,"ownershipKeyHash":"c6678a5678c3a1ae820cb07badff385f"},"token":"11111111111111111111111111111111","phase":"issued","intent":"post","issueID":"22222222222222222222222222222222","startedAt":"2026-01-01T00:00:00Z","issuedAt":"2026-01-01T00:01:00Z"}`

const legacyV2ReservedFenceJSON = `{"schema":"karpenter.inspace.cloud/create-fence-v2","binding":{"nodeClaimUID":"claim-uid","idempotencyKeyHash":"c6678a5678c3a1ae820cb07badff385f65cbbf782e536f519d4a2835e7c3daae","requestHash":"1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047","specHash":"spec","bootstrapHash":"bootstrap"},"cleanup":{"clusterName":"cluster-a","location":"bkk01","networkUUID":"11111111-1111-4111-8111-111111111111","controlPlaneVIP":"10.0.0.10","privateLoadBalancerPoolStart":"10.0.0.200","privateLoadBalancerPoolStop":"10.0.0.219","firewallUUID":"33333333-3333-4333-8333-333333333333","firewallProfile":"private-worker","nodeClaimName":"general-abc12","vmName":"cluster-a-karp-general-abc12","billingAccountID":1,"ownershipKeyHash":"c6678a5678c3a1ae820cb07badff385f"},"token":"11111111111111111111111111111111","phase":"reserved","startedAt":"2026-01-01T00:00:00Z"}`

func TestLegacyV2ReservedFenceCanAuthorizeNewFloatingIPPATCHAfterUpgrade(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	claim.Annotations = map[string]string{AnnotationCreateFence: legacyV2ReservedFenceJSON}
	claim.Finalizers = append(claim.Finalizers, CreateFenceFinalizer)
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	binding, cleanup := createFenceTestIdentity(claim)
	record, err := decodeCreateFence(legacyV2ReservedFenceJSON)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, claim, binding, record.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	if !stored.LegacyV2 || stored.LegacyV2FloatingIPMayBeIssued {
		t.Fatalf("reserved migration marker = legacy=%t mayBeIssued=%t", stored.LegacyV2, stored.LegacyV2FloatingIPMayBeIssued)
	}
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	anchored, err := store.RecordCreatedVM(ctx, issued, binding, stored.Token, stored.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	_, authorization, err := store.AuthorizeFloatingIPUpdate(ctx, anchored, binding, stored.Token, vmUUID, "203.0.113.10", "fenced-public", cleanup.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if !authorization.AllowPOST || authorization.Fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("reserved v2 post-upgrade FIP authorization = %#v, want fresh PATCH authority", authorization)
	}
}

func TestLegacyV2MaterializedFenceMigratesToObservedBaseFirewall(t *testing.T) {
	record, err := decodeCreateFence(legacyV2MaterializedFenceJSON)
	if err != nil {
		t.Fatal(err)
	}
	assignment := record.BaseFirewallAssignment
	if record.Schema != createFenceSchema || !record.LegacyV2 || assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentObserved ||
		assignment.VMUUID != record.CreatedVMUUID || assignment.FirewallUUID != record.Cleanup.FirewallUUID || !createFenceKeyHashPattern.MatchString(assignment.IssueID) {
		t.Fatalf("legacy materialized migration = %#v", record)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), legacyCreateFenceSchema) || !strings.Contains(string(encoded), createFenceSchema) {
		t.Fatalf("migrated fence was not written as v3: %s", encoded)
	}
	if _, err := decodeCreateFence(string(encoded)); err != nil {
		t.Fatalf("persisted v3 migration is invalid: %v", err)
	}
}

func TestLegacyV2IssuedUnanchoredFenceCanBeRejectedWithoutAssignmentPOST(t *testing.T) {
	ctx := context.Background()
	record, err := decodeCreateFence(legacyV2IssuedUnanchoredFenceJSON)
	if err != nil {
		t.Fatal(err)
	}
	if record.BaseFirewallAssignment == nil || record.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentIssued || record.BaseFirewallAssignment.VMUUID != "" {
		t.Fatalf("legacy unanchored issue did not synthesize a read-only assignment receipt: %#v", record.BaseFirewallAssignment)
	}
	claim := createFenceTestNodeClaim()
	claim.Annotations = map[string]string{AnnotationCreateFence: legacyV2IssuedUnanchoredFenceJSON}
	claim.Finalizers = append(claim.Finalizers, CreateFenceFinalizer)
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.MarkRejected(ctx, claim, record.Binding, record.Token, record.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := decodeCreateFence(rejected.Annotations[AnnotationCreateFence])
	if err != nil || stored.Schema != createFenceSchema || stored.Phase != createFenceRejected || stored.BaseFirewallAssignment == nil || stored.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentRejected {
		t.Fatalf("legacy no-result rejection = %#v err=%v", stored, err)
	}
}

func TestLegacyV2IssuedAnchoredFirewallAssignmentMaterializesReadOnlyLease(t *testing.T) {
	var legacy createFenceRecord
	if err := json.Unmarshal([]byte(legacyV2IssuedUnanchoredFenceJSON), &legacy); err != nil {
		t.Fatal(err)
	}
	const vmUUID = "22222222-2222-4222-8222-222222222222"
	observedAt := time.Now().Add(-time.Minute).UTC()
	legacy.CreatedVMUUID = vmUUID
	legacy.LaunchObservedAt = &observedAt
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	claim := createFenceTestNodeClaim()
	claim.Annotations = map[string]string{AnnotationCreateFence: string(encoded)}
	claim.Finalizers = append(claim.Finalizers, CreateFenceFinalizer)
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeCreateFence(string(encoded))
	if err != nil || !migrated.LegacyV2BaseFirewallMayBeIssued {
		t.Fatalf("legacy issued migration = %#v, %v", migrated, err)
	}
	_, authorization, err := store.AuthorizeBaseFirewall(context.Background(), claim, migrated.Binding, migrated.Token, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.AllowPOST || authorization.Fence.Phase != cloudapi.FirewallAssignmentIssued {
		t.Fatalf("hidden committed v2 assignment gained post-upgrade POST authority: %#v", authorization)
	}
	var leases coordinationv1.LeaseList
	if err := kubeClient.List(context.Background(), &leases); err != nil {
		t.Fatal(err)
	}
	if len(leases.Items) != 1 || leases.Items[0].Name != firewallMutationCoordinatorLeaseName {
		t.Fatalf("legacy ambiguous assignment coordinator Leases = %#v, want one fixed-name read-only slot", leases.Items)
	}
	ledger, err := decodeFirewallMutationLedger(&leases.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := ledger.Slots[firewallMutationSlotName(migrated.Cleanup.Location, migrated.Cleanup.FirewallUUID)]
	if !ok || stored.Operation != firewallMutationAssign || stored.Phase != cloudapi.FirewallAssignmentIssued ||
		stored.NodeClaimUID != string(claim.UID) || stored.VMUUID != vmUUID || stored.IssueID != authorization.Fence.IssueID {
		t.Fatalf("legacy read-only migration slot = %#v, found=%t", stored, ok)
	}
}

func TestKubernetesCreateFenceRejectsIssuedAttemptAfterDeletionBegins(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Delete(ctx, issued); err != nil {
		t.Fatal(err)
	}
	rejected, err := store.MarkRejected(ctx, issued, binding, fence.Token, issuedRecord.IssueID)
	if err != nil {
		t.Fatalf("MarkRejected() after deletion began = %v", err)
	}
	record, err := decodeCreateFence(rejected.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceRejected || rejected.DeletionTimestamp == nil {
		t.Fatalf("deleting rejected fence = %#v claim=%#v err=%v", record, rejected, err)
	}
}

func TestRollbackAndMaterializationAreMutuallyExclusiveForAnchoredVM(t *testing.T) {
	ctx := context.Background()
	for _, rollbackFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "rollback wins", false: "materialization wins"}[rollbackFirst], func(t *testing.T) {
			claim := createFenceTestNodeClaim()
			store := NewMemoryCreateFenceStore()
			binding, cleanup := createFenceTestIdentity(claim)
			fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
			if err != nil {
				t.Fatal(err)
			}
			record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
			if err != nil {
				t.Fatal(err)
			}
			vm := &cloudapi.VM{
				UUID: "22222222-2222-4222-8222-222222222222", Name: cleanup.VMName,
				ClusterName: cleanup.ClusterName, NodeClaimName: cleanup.NodeClaimName, Location: cleanup.Location,
				BillingAccountID: cleanup.BillingAccountID, FloatingIPName: "fenced-public", PublicIPv4: "203.0.113.10",
			}
			anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vm.UUID)
			if err != nil {
				t.Fatal(err)
			}
			if rollbackFirst {
				rolledBack, err := store.ChooseRollback(ctx, anchored, binding, fence.Token, record.IssueID, vm.UUID, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.MarkMaterialized(ctx, rolledBack, binding, fence.Token, vm); err == nil {
					t.Fatal("MarkMaterialized() overwrote an irreversible rollback decision")
				}
				stored, err := decodeCreateFence(rolledBack.Annotations[AnnotationCreateFence])
				if err != nil || stored.RollbackAt == nil || !stored.DependentUnresolved {
					t.Fatalf("rollback state = %#v err=%v", stored, err)
				}
				return
			}
			anchored, firewallAuthorization, err := store.AuthorizeBaseFirewall(ctx, anchored, binding, fence.Token, vm.UUID)
			if err != nil {
				t.Fatal(err)
			}
			anchored, err = store.ObserveBaseFirewall(ctx, anchored, binding, fence.Token, vm.UUID, firewallAuthorization.Fence.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			anchored = observeTestFloatingIPUpdate(t, store, anchored, binding, fence.Token, vm)
			materialized, err := store.MarkMaterialized(ctx, anchored, binding, fence.Token, vm)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ChooseRollback(ctx, materialized, binding, fence.Token, record.IssueID, vm.UUID, nil); err == nil {
				t.Fatal("ChooseRollback() overwrote a materialized VM")
			}
		})
	}
}

func TestCreateInventoryRejectsPotentialVMOutsideBoundedBaseline(t *testing.T) {
	err := validateCreateInventory(cloudapi.CreateInventory{
		VMs:          []string{"11111111-1111-4111-8111-111111111111"},
		PotentialVMs: []string{"22222222-2222-4222-8222-222222222222"},
	})
	if err == nil {
		t.Fatal("validateCreateInventory() accepted a potential VM absent from the complete baseline")
	}
}

func TestCreateInventoryEncodedBoundLeavesKubernetesAnnotationHeadroom(t *testing.T) {
	identities := make([]string, 800)
	for i := range identities {
		identities[i] = fmt.Sprintf("%04d-%s", i, strings.Repeat("x", 118))
	}
	if err := validateCreateInventory(cloudapi.CreateInventory{FloatingIPs: identities}); err == nil {
		t.Fatalf("validateCreateInventory() accepted an inventory larger than %d encoded bytes", cloudapi.MaxCreateInventoryEncodedBytes)
	}

	safe := cloudapi.CreateInventory{FloatingIPs: identities[:600]}
	if err := validateCreateInventory(safe); err != nil {
		t.Fatalf("safe inventory was rejected: %v", err)
	}
	claim := createFenceTestNodeClaim()
	binding, cleanup := createFenceTestIdentity(claim)
	record, err := newCreateFenceRecord(binding, cleanup, safe, time.Now(), func() (string, error) {
		return "11111111111111111111111111111111", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 128*1024 {
		t.Fatalf("maximum accepted fixture encoded fence is %d bytes, want at least 128 KiB of Kubernetes annotation headroom", len(encoded))
	}
}

func createFenceTestNodeClaim() *karpv1.NodeClaim {
	return &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "general-abc12", UID: types.UID("claim-uid"), Generation: 1,
			Labels:     map[string]string{karpv1.NodePoolLabelKey: "general"},
			Finalizers: []string{karpv1.TerminationFinalizer},
		},
		Spec: karpv1.NodeClaimSpec{NodeClassRef: &karpv1.NodeClassReference{Name: "workers"}},
	}
}

func createFenceTestIdentity(claim *karpv1.NodeClaim) (createFenceBinding, createFenceCleanupIdentity) {
	return createFenceBinding{
			NodeClaimUID: string(claim.UID), IdempotencyKeyHash: createFenceHash(string(claim.UID)),
			RequestHash: createFenceHash("request"), SpecHash: "spec", BootstrapHash: "bootstrap",
		}, createFenceCleanupIdentity{
			ClusterName: "cluster-a", Location: "bkk01", NetworkUUID: "11111111-1111-4111-8111-111111111111",
			ControlPlaneVIP: "10.0.0.10", PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.219",
			FirewallUUID: "33333333-3333-4333-8333-333333333333", FirewallProfile: inspacev1.FirewallProfilePrivateWorker,
			NodeClaimName: claim.Name,
			VMName:        "cluster-a-karp-general-abc12", BillingAccountID: 1, OwnershipKeyHash: cloudapi.OwnershipKeyHash(string(claim.UID)),
		}
}

func observeTestFloatingIPUpdate(
	t *testing.T,
	store CreateFenceStore,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	vm *cloudapi.VM,
) *karpv1.NodeClaim {
	t.Helper()
	authorized, authorization, err := store.AuthorizeFloatingIPUpdate(context.Background(), claim, binding, token, vm.UUID, vm.PublicIPv4, vm.FloatingIPName, vm.BillingAccountID)
	if err != nil {
		t.Fatalf("AuthorizeFloatingIPUpdate() error = %v", err)
	}
	observed, err := store.ObserveFloatingIPUpdate(context.Background(), authorized, binding, token, authorization.Fence)
	if err != nil {
		t.Fatalf("ObserveFloatingIPUpdate() error = %v", err)
	}
	return observed
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
