package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

type issuedFirewallClaim struct {
	claim   *karpv1.NodeClaim
	binding createFenceBinding
	cleanup createFenceCleanupIdentity
	fence   createFence
	vmUUID  string
}

func prepareIssuedFirewallClaim(t *testing.T, store CreateFenceStore, name, uid, vmUUID, firewallUUID string) issuedFirewallClaim {
	t.Helper()
	claim := createFenceTestNodeClaim()
	claim.Name = name
	claim.UID = types.UID(uid)
	binding, cleanup := createFenceTestIdentity(claim)
	cleanup.NodeClaimName = name
	cleanup.VMName = "cluster-a-karp-" + name
	cleanup.FirewallUUID = firewallUUID
	fenced, fence, _, err := store.Ensure(context.Background(), claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(context.Background(), fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := store.RecordCreatedVM(context.Background(), issued, binding, fence.Token, record.IssueID, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	return issuedFirewallClaim{claim: anchored, binding: binding, cleanup: cleanup, fence: fence, vmUUID: vmUUID}
}

func newFirewallSlotTestClient(t *testing.T, claims ...*karpv1.NodeClaim) client.Client {
	t.Helper()
	objects := make([]client.Object, 0, len(claims))
	for _, claim := range claims {
		objects = append(objects, claim)
	}
	return fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(objects...).Build()
}

func TestDurableFirewallSlotBlocksSecondClaimAfterAmbiguousAssignmentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	claimA := createFenceTestNodeClaim()
	claimA.Name, claimA.UID = "general-a", types.UID("claim-a")
	claimB := createFenceTestNodeClaim()
	claimB.Name, claimB.UID = "general-b", types.UID("claim-b")
	claimC := createFenceTestNodeClaim()
	claimC.Name, claimC.UID = "general-c", types.UID("claim-c")
	kubeClient := newFirewallSlotTestClient(t, claimA, claimB, claimC)
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")

	a := prepareIssuedFirewallClaim(t, store, claimA.Name, string(claimA.UID), "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333")
	b := prepareIssuedFirewallClaim(t, store, claimB.Name, string(claimB.UID), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")
	c := prepareIssuedFirewallClaim(t, store, claimC.Name, string(claimC.UID), "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555")

	updatedA, authA, err := store.AuthorizeBaseFirewall(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID)
	a.claim = updatedA
	if err != nil || !authA.AllowPOST {
		t.Fatalf("claim A initial slot = %#v, %v", authA, err)
	}
	// Model an HTTP 500 followed by a readback timeout: no terminal callback is
	// made. Reconstructing the store also drops every process-local mutex.
	restarted, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	_, recoveredA, err := restarted.AuthorizeBaseFirewall(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID)
	if err != nil || recoveredA.AllowPOST || recoveredA.Fence.IssueID != authA.Fence.IssueID {
		t.Fatalf("restarted ambiguous owner = %#v, %v; want same read-only issue", recoveredA, err)
	}
	if _, authB, err := restarted.AuthorizeBaseFirewall(ctx, b.claim, b.binding, b.fence.Token, b.vmUUID); !errors.Is(err, cloudapi.ErrCreateAttemptPending) || authB.AllowPOST {
		t.Fatalf("same-firewall claim B = %#v, %v; want blocked without POST", authB, err)
	}
	if _, authC, err := restarted.AuthorizeBaseFirewall(ctx, c.claim, c.binding, c.fence.Token, c.vmUUID); err != nil || !authC.AllowPOST {
		t.Fatalf("different-firewall claim C = %#v, %v; want independent POST", authC, err)
	}
	if _, err := restarted.ObserveBaseFirewall(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID, authA.Fence.IssueID); err != nil {
		t.Fatal(err)
	}
	if _, authB, err := restarted.AuthorizeBaseFirewall(ctx, b.claim, b.binding, b.fence.Token, b.vmUUID); err != nil || !authB.AllowPOST {
		t.Fatalf("claim B after A terminal readback = %#v, %v; want slot takeover", authB, err)
	}
}

func TestDurableFirewallSlotCASAllowsExactlyOneSameFirewallAssignment(t *testing.T) {
	ctx := context.Background()
	claims := make([]*karpv1.NodeClaim, 2)
	for i := range claims {
		claims[i] = createFenceTestNodeClaim()
		claims[i].Name = fmt.Sprintf("general-race-%d", i)
		claims[i].UID = types.UID(fmt.Sprintf("claim-race-%d", i))
	}
	kubeClient := newFirewallSlotTestClient(t, claims...)
	stores := make([]CreateFenceStore, 2)
	prepared := make([]issuedFirewallClaim, 2)
	for i := range stores {
		stores[i], _ = NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
		prepared[i] = prepareIssuedFirewallClaim(t, stores[i], claims[i].Name, string(claims[i].UID),
			fmt.Sprintf("%08d-1111-4111-8111-111111111111", i+1), "33333333-3333-4333-8333-333333333333")
	}
	type result struct {
		authorization cloudapi.FirewallAssignmentAuthorization
		err           error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range stores {
		go func(i int) {
			start.Wait()
			_, authorization, err := stores[i].AuthorizeBaseFirewall(ctx, prepared[i].claim, prepared[i].binding, prepared[i].fence.Token, prepared[i].vmUUID)
			results <- result{authorization: authorization, err: err}
		}(i)
	}
	start.Done()
	allowed := 0
	blocked := 0
	for range stores {
		result := <-results
		if result.err == nil && result.authorization.AllowPOST {
			allowed++
		} else if errors.Is(result.err, cloudapi.ErrCreateAttemptPending) && !result.authorization.AllowPOST {
			blocked++
		} else {
			t.Fatalf("unexpected concurrent authorization = %#v, %v", result.authorization, result.err)
		}
	}
	if allowed != 1 || blocked != 1 {
		t.Fatalf("concurrent same-firewall results allowed=%d blocked=%d, want 1/1", allowed, blocked)
	}
}

func TestDurableFirewallSlotCASPreservesConcurrentDifferentFirewallsInFixedLease(t *testing.T) {
	ctx := context.Background()
	claims := make([]*karpv1.NodeClaim, 2)
	stores := make([]CreateFenceStore, 2)
	prepared := make([]issuedFirewallClaim, 2)
	kubeClient := newFirewallSlotTestClient(t)
	for i := range claims {
		claims[i] = createFenceTestNodeClaim()
		claims[i].Name = fmt.Sprintf("different-firewall-%d", i)
		claims[i].UID = types.UID(fmt.Sprintf("different-firewall-claim-%d", i))
		if err := kubeClient.Create(ctx, claims[i]); err != nil {
			t.Fatal(err)
		}
		stores[i], _ = NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
		prepared[i] = prepareIssuedFirewallClaim(t, stores[i], claims[i].Name, string(claims[i].UID),
			fmt.Sprintf("%08d-1111-4111-8111-111111111111", i+1),
			fmt.Sprintf("%08d-3333-4333-8333-333333333333", i+1))
	}
	type result struct {
		authorization cloudapi.FirewallAssignmentAuthorization
		err           error
	}
	results := make(chan result, len(stores))
	var start sync.WaitGroup
	start.Add(1)
	for i := range stores {
		go func(i int) {
			start.Wait()
			_, authorization, err := stores[i].AuthorizeBaseFirewall(ctx, prepared[i].claim, prepared[i].binding, prepared[i].fence.Token, prepared[i].vmUUID)
			results <- result{authorization: authorization, err: err}
		}(i)
	}
	start.Done()
	for range stores {
		result := <-results
		if result.err != nil || !result.authorization.AllowPOST {
			t.Fatalf("different-firewall authorization = %#v, %v; want independent POST", result.authorization, result.err)
		}
	}
	var leases coordinationv1.LeaseList
	if err := kubeClient.List(ctx, &leases, client.InNamespace("karpenter")); err != nil {
		t.Fatal(err)
	}
	if len(leases.Items) != 1 || leases.Items[0].Name != firewallMutationCoordinatorLeaseName {
		t.Fatalf("firewall coordinator Leases = %#v; want one fixed-name Lease", leases.Items)
	}
	ledger, err := decodeFirewallMutationLedger(&leases.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Slots) != len(stores) {
		t.Fatalf("firewall coordinator slots = %d, want %d", len(ledger.Slots), len(stores))
	}
}

func TestDurableFirewallSlotSerializesAssignmentAndDetachmentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	claimA := createFenceTestNodeClaim()
	claimA.Name, claimA.UID = "general-delete", types.UID("claim-delete")
	claimB := createFenceTestNodeClaim()
	claimB.Name, claimB.UID = "general-create", types.UID("claim-create")
	kubeClient := newFirewallSlotTestClient(t, claimA, claimB)
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	a := prepareIssuedFirewallClaim(t, store, claimA.Name, string(claimA.UID), "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333")
	b := prepareIssuedFirewallClaim(t, store, claimB.Name, string(claimB.UID), "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")

	updatedA, assignA, err := store.AuthorizeBaseFirewall(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID)
	a.claim = updatedA
	if err != nil || !assignA.AllowPOST {
		t.Fatalf("initial assignment = %#v, %v", assignA, err)
	}
	a.claim, err = store.ObserveBaseFirewall(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID, assignA.Fence.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	detachA, err := store.AuthorizeBaseFirewallDetach(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID)
	if err != nil || !detachA.AllowDELETE {
		t.Fatalf("initial detachment = %#v, %v", detachA, err)
	}
	restarted, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	if retry, err := restarted.AuthorizeBaseFirewallDetach(ctx, a.claim, a.binding, a.fence.Token, a.vmUUID); err != nil || retry.AllowDELETE || retry.Fence != detachA.Fence {
		t.Fatalf("restart ambiguous removal = %#v, %v; want same read-only durable issue", retry, err)
	}
	if _, assignmentB, err := restarted.AuthorizeBaseFirewall(ctx, b.claim, b.binding, b.fence.Token, b.vmUUID); !errors.Is(err, cloudapi.ErrCreateAttemptPending) || assignmentB.AllowPOST {
		t.Fatalf("assignment crossed active detachment = %#v, %v", assignmentB, err)
	}
	if err := restarted.ObserveBaseFirewallDetach(ctx, a.claim, a.binding, a.fence.Token, detachA.Fence); err != nil {
		t.Fatal(err)
	}
	if _, assignmentB, err := restarted.AuthorizeBaseFirewall(ctx, b.claim, b.binding, b.fence.Token, b.vmUUID); err != nil || !assignmentB.AllowPOST {
		t.Fatalf("assignment after detachment absence = %#v, %v", assignmentB, err)
	}
}

func TestDurableFirewallSlotCASAllowsOnlyOneDetachmentDispatcherAcrossStores(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	claim.Name, claim.UID = "general-detach-race", types.UID("claim-detach-race")
	kubeClient := newFirewallSlotTestClient(t, claim)
	initial, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	prepared := prepareIssuedFirewallClaim(t, initial, claim.Name, string(claim.UID),
		"11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333")
	updated, assignment, err := initial.AuthorizeBaseFirewall(ctx, prepared.claim, prepared.binding, prepared.fence.Token, prepared.vmUUID)
	prepared.claim = updated
	if err != nil || !assignment.AllowPOST {
		t.Fatalf("assignment setup = %#v, %v", assignment, err)
	}
	prepared.claim, err = initial.ObserveBaseFirewall(ctx, prepared.claim, prepared.binding, prepared.fence.Token, prepared.vmUUID, assignment.Fence.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	stores := make([]CreateFenceStore, 2)
	for i := range stores {
		stores[i], _ = NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	}
	type result struct {
		authorization cloudapi.FirewallDetachmentAuthorization
		err           error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range stores {
		go func(i int) {
			start.Wait()
			authorization, err := stores[i].AuthorizeBaseFirewallDetach(ctx, prepared.claim, prepared.binding, prepared.fence.Token, prepared.vmUUID)
			results <- result{authorization: authorization, err: err}
		}(i)
	}
	start.Done()
	allowed := 0
	blocked := 0
	for range stores {
		result := <-results
		if result.err == nil && result.authorization.AllowDELETE {
			allowed++
		} else if (result.err == nil || errors.Is(result.err, cloudapi.ErrCreateAttemptPending)) && !result.authorization.AllowDELETE {
			blocked++
		} else {
			t.Fatalf("unexpected concurrent detachment authorization = %#v, %v", result.authorization, result.err)
		}
	}
	if allowed != 1 || blocked != 1 {
		t.Fatalf("concurrent detach dispatchers allowed=%d blocked=%d, want 1/1", allowed, blocked)
	}
	// A third store represents a restarted controller. Its new acquisition ID
	// cannot match the winning in-flight slot and must remain read-only.
	restarted, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	retry, err := restarted.AuthorizeBaseFirewallDetach(ctx, prepared.claim, prepared.binding, prepared.fence.Token, prepared.vmUUID)
	if err != nil || retry.AllowDELETE || retry.Fence.IssueID == "" {
		t.Fatalf("restart detachment authorization = %#v, %v; want read-only issued receipt", retry, err)
	}
}

func TestLegacyV2IssuedAssignmentBlocksNewV3ClaimBeforeLegacyOwnerReconciles(t *testing.T) {
	ctx := context.Background()
	const vmUUID = "22222222-2222-4222-8222-222222222222"

	var rawLegacy createFenceRecord
	if err := json.Unmarshal([]byte(legacyV2IssuedUnanchoredFenceJSON), &rawLegacy); err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().Add(-time.Minute).UTC()
	rawLegacy.CreatedVMUUID = vmUUID
	rawLegacy.LaunchObservedAt = &observedAt
	encodedLegacy, err := json.Marshal(rawLegacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyClaim := createFenceTestNodeClaim()
	legacyClaim.Annotations = map[string]string{AnnotationCreateFence: string(encodedLegacy)}
	legacyClaim.Finalizers = append(legacyClaim.Finalizers, CreateFenceFinalizer)
	legacyRecord, err := decodeCreateFence(string(encodedLegacy))
	if err != nil {
		t.Fatal(err)
	}

	newClaim := createFenceTestNodeClaim()
	newClaim.Name, newClaim.UID = "general-v3", types.UID("claim-v3")
	kubeClient := newFirewallSlotTestClient(t, legacyClaim, newClaim)
	store, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	newAttempt := prepareIssuedFirewallClaim(t, store, newClaim.Name, string(newClaim.UID),
		"44444444-4444-4444-8444-444444444444", legacyRecord.Cleanup.FirewallUUID)

	// Upgrade order must not matter: a new v3 claim reaching an empty ledger
	// first still sees the uncached legacy receipt and cannot dispatch.
	if _, authorization, err := store.AuthorizeBaseFirewall(ctx, newAttempt.claim, newAttempt.binding, newAttempt.fence.Token, newAttempt.vmUUID); !errors.Is(err, cloudapi.ErrCreateAttemptPending) || authorization.AllowPOST {
		t.Fatalf("new v3 claim before legacy migration = %#v, %v; want blocked", authorization, err)
	}
	var absent coordinationv1.Lease
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "karpenter", Name: firewallMutationCoordinatorLeaseName}, &absent); err == nil {
		t.Fatal("blocked v3 claim unexpectedly created the coordinator Lease")
	} else if !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	otherClaim := createFenceTestNodeClaim()
	otherClaim.Name, otherClaim.UID = "general-other-firewall", types.UID("claim-other-firewall")
	if err := kubeClient.Create(ctx, otherClaim); err != nil {
		t.Fatal(err)
	}
	otherAttempt := prepareIssuedFirewallClaim(t, store, otherClaim.Name, string(otherClaim.UID),
		"55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666")
	if _, authorization, err := store.AuthorizeBaseFirewall(ctx, otherAttempt.claim, otherAttempt.binding, otherAttempt.fence.Token, otherAttempt.vmUUID); err != nil || !authorization.AllowPOST {
		t.Fatalf("different-firewall v3 claim during legacy migration = %#v, %v; want independent POST authority", authorization, err)
	}

	// The legacy owner installs an issued slot but never receives POST authority,
	// including after reconstructing the controller store.
	legacyCurrent, legacyAuthorization, err := store.AuthorizeBaseFirewall(ctx, legacyClaim, legacyRecord.Binding, legacyRecord.Token, vmUUID)
	if err != nil || legacyAuthorization.AllowPOST || legacyAuthorization.Fence.Phase != cloudapi.FirewallAssignmentIssued {
		t.Fatalf("legacy migration authorization = %#v, %v", legacyAuthorization, err)
	}
	restarted, _ := NewKubernetesCreateFenceStore(kubeClient, kubeClient, "karpenter")
	if _, retry, err := restarted.AuthorizeBaseFirewall(ctx, legacyCurrent, legacyRecord.Binding, legacyRecord.Token, vmUUID); err != nil || retry.AllowPOST || retry.Fence != legacyAuthorization.Fence {
		t.Fatalf("legacy restart authorization = %#v, %v; want same read-only issue", retry, err)
	}
	if _, authorization, err := restarted.AuthorizeBaseFirewall(ctx, newAttempt.claim, newAttempt.binding, newAttempt.fence.Token, newAttempt.vmUUID); !errors.Is(err, cloudapi.ErrCreateAttemptPending) || authorization.AllowPOST {
		t.Fatalf("new v3 claim crossed legacy slot = %#v, %v", authorization, err)
	}

	legacyCurrent, err = restarted.ObserveBaseFirewall(ctx, legacyCurrent, legacyRecord.Binding, legacyRecord.Token, vmUUID, legacyAuthorization.Fence.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	if _, authorization, err := restarted.AuthorizeBaseFirewall(ctx, newAttempt.claim, newAttempt.binding, newAttempt.fence.Token, newAttempt.vmUUID); err != nil || !authorization.AllowPOST {
		t.Fatalf("new v3 claim after legacy terminal readback = %#v, %v; want POST authority", authorization, err)
	}
}
