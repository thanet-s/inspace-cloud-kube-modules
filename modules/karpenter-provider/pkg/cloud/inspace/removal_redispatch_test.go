package inspace

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	redispatchFirewallUUID = "33333333-3333-4333-8333-333333333333"
	redispatchVMUUID       = "11111111-1111-4111-8111-111111111111"
	redispatchIssueID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// detachProbeAPI records when relation mutations happen relative to relation
// reads and whether the adapter's in-process firewall gate is held while it
// reads.
type detachProbeAPI struct {
	*fakeAPI
	adapter           *Adapter
	listsAtUnassign   []int
	gateHeldOnLists   []bool
	listsAfterRelease int
}

func (f *detachProbeAPI) gateHeld() bool {
	value, ok := f.adapter.firewallAssignmentGates.Load("bkk01/" + redispatchFirewallUUID)
	if !ok {
		return false
	}
	gate := value.(*sync.Mutex)
	if gate.TryLock() {
		gate.Unlock()
		return false
	}
	return true
}

func (f *detachProbeAPI) ListFirewalls(ctx context.Context, location string) ([]sdk.Firewall, error) {
	f.gateHeldOnLists = append(f.gateHeldOnLists, f.gateHeld())
	return f.fakeAPI.ListFirewalls(ctx, location)
}

func (f *detachProbeAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	f.listsAtUnassign = append(f.listsAtUnassign, f.firewallListCalls)
	return f.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

func newDetachProbe(t *testing.T, relationPresent bool, unassignErrors ...error) (*detachProbeAPI, *Adapter, sdk.Firewall) {
	t.Helper()
	firewall := secureFirewall()
	firewall.UUID = redispatchFirewallUUID
	if relationPresent {
		firewall.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: redispatchVMUUID}}
	}
	api := &detachProbeAPI{fakeAPI: &fakeAPI{firewalls: []sdk.Firewall{firewall}, unassignFirewallErrors: unassignErrors}}
	adapter, err := New(api)
	if err != nil {
		t.Fatal(err)
	}
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	api.adapter = adapter
	return api, adapter, firewall
}

type recordingDetachAuthority struct {
	allowFirst  bool
	authorizes  int
	listsAtAuth []int
	observed    []cloudapi.FirewallDetachmentFence
	rejected    int
	api         *detachProbeAPI
}

func (r *recordingDetachAuthority) authority() baseFirewallDetachmentAuthority {
	fence := cloudapi.FirewallDetachmentFence{
		VMUUID: redispatchVMUUID, FirewallUUID: redispatchFirewallUUID, Phase: cloudapi.FirewallAssignmentIssued, IssueID: redispatchIssueID,
	}
	return baseFirewallDetachmentAuthority{
		fenced: true,
		authorize: func(context.Context, string) (cloudapi.FirewallDetachmentAuthorization, error) {
			r.authorizes++
			r.listsAtAuth = append(r.listsAtAuth, r.api.firewallListCalls)
			return cloudapi.FirewallDetachmentAuthorization{Fence: fence, AllowDELETE: r.allowFirst && r.authorizes == 1}, nil
		},
		observe: func(_ context.Context, observed cloudapi.FirewallDetachmentFence) error {
			r.observed = append(r.observed, observed)
			return nil
		},
		reject: func(context.Context, cloudapi.FirewallDetachmentFence) error {
			r.rejected++
			return errors.New("dispatched detachment was unexpectedly rejected")
		},
	}
}

func TestDurableFirewallDetachResendsUncommittedDeleteOnlyAfterSpacedPresence(t *testing.T) {
	api, adapter, firewall := newDetachProbe(t, true, &sdk.APIError{StatusCode: 500, Message: "failed before commit"})
	recorder := &recordingDetachAuthority{allowFirst: true, api: api}
	err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewall.UUID, redispatchVMUUID, firewall.BillingAccountID, recorder.authority())
	if err != nil {
		t.Fatalf("uncommitted detachment did not recover through an exact re-send: %v", err)
	}
	if len(api.listsAtUnassign) != 2 {
		t.Fatalf("unassign attempts = %d, want the failed dispatch plus one re-send; operations=%v", len(api.listsAtUnassign), api.operations)
	}
	if spaced := api.listsAtUnassign[1] - api.listsAtUnassign[0]; spaced < destructiveAbsenceConfirmations {
		t.Fatalf("re-send followed only %d relation reads, want at least %d spaced presence reads", spaced, destructiveAbsenceConfirmations)
	}
	if recorder.authorizes < 2 || recorder.listsAtAuth[len(recorder.listsAtAuth)-1] <= api.listsAtUnassign[0] {
		t.Fatalf("re-send did not re-check durable ownership after the failed dispatch: authorizes=%d at=%v unassigns=%v",
			recorder.authorizes, recorder.listsAtAuth, api.listsAtUnassign)
	}
	if len(recorder.observed) != 1 || recorder.rejected != 0 || firewallHasVM(api.firewalls[0], redispatchVMUUID) {
		t.Fatalf("re-sent detachment did not converge exactly: observed=%v rejected=%d firewall=%#v", recorder.observed, recorder.rejected, api.firewalls[0])
	}
}

func TestDurableFirewallDetachRestartResendsIssuedDeleteAfterSpacedPresence(t *testing.T) {
	api, adapter, firewall := newDetachProbe(t, true)
	// A previous controller already issued, and maybe dispatched, this exact
	// detachment. The relation is still visible, so it never committed.
	recorder := &recordingDetachAuthority{api: api}
	err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewall.UUID, redispatchVMUUID, firewall.BillingAccountID, recorder.authority())
	if err != nil {
		t.Fatalf("restarted issued detachment stayed wedged: %v", err)
	}
	if len(api.listsAtUnassign) != 1 || api.listsAtUnassign[0] < destructiveAbsenceConfirmations {
		t.Fatalf("restart unassigns=%v, want one re-send after at least %d spaced presence reads", api.listsAtUnassign, destructiveAbsenceConfirmations)
	}
	if len(recorder.observed) != 1 || firewallHasVM(api.firewalls[0], redispatchVMUUID) {
		t.Fatalf("restart detachment did not converge: observed=%v firewall=%#v", recorder.observed, api.firewalls[0])
	}
}

func TestDurableFirewallDetachObservedReceiptStaysReadOnly(t *testing.T) {
	api, adapter, firewall := newDetachProbe(t, true)
	authority := baseFirewallDetachmentAuthority{
		fenced: true,
		authorize: func(context.Context, string) (cloudapi.FirewallDetachmentAuthorization, error) {
			return cloudapi.FirewallDetachmentAuthorization{Fence: cloudapi.FirewallDetachmentFence{
				VMUUID: redispatchVMUUID, FirewallUUID: redispatchFirewallUUID, Phase: cloudapi.FirewallAssignmentObserved, IssueID: redispatchIssueID,
			}}, nil
		},
		observe: func(context.Context, cloudapi.FirewallDetachmentFence) error { return nil },
		reject:  func(context.Context, cloudapi.FirewallDetachmentFence) error { return nil },
	}
	err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewall.UUID, redispatchVMUUID, firewall.BillingAccountID, authority)
	if !errors.Is(err, errFirewallCleanupUncertain) {
		t.Fatalf("reappeared relation after an observed receipt = %v, want uncertainty", err)
	}
	if len(api.listsAtUnassign) != 0 {
		t.Fatalf("observed receipt dispatched an unassign: operations=%v", api.operations)
	}
}

func TestFirewallDetachHoldsNeitherGateNorSlotWhileRelationIsAlreadyAbsent(t *testing.T) {
	api, adapter, firewall := newDetachProbe(t, false)
	recorder := &recordingDetachAuthority{allowFirst: true, api: api}
	if err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewall.UUID, redispatchVMUUID, firewall.BillingAccountID, recorder.authority()); err != nil {
		t.Fatal(err)
	}
	for i, held := range api.gateHeldOnLists {
		if held {
			t.Fatalf("relation read %d held the in-process firewall gate although nothing was mutated", i+1)
		}
	}
	if recorder.authorizes != 1 || recorder.listsAtAuth[0] < destructiveAbsenceConfirmations {
		t.Fatalf("durable slot authorized at relation reads %v, want once after %d absence confirmations", recorder.listsAtAuth, destructiveAbsenceConfirmations)
	}
	if len(recorder.observed) != 1 || len(api.listsAtUnassign) != 0 {
		t.Fatalf("absent relation: observed=%v unassigns=%v, want one observation and no mutation", recorder.observed, api.listsAtUnassign)
	}
}

func TestFirewallDetachReleasesGateAfterItsDeleteReadback(t *testing.T) {
	api, adapter, firewall := newDetachProbe(t, true)
	recorder := &recordingDetachAuthority{allowFirst: true, api: api}
	if err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewall.UUID, redispatchVMUUID, firewall.BillingAccountID, recorder.authority()); err != nil {
		t.Fatal(err)
	}
	if len(api.listsAtUnassign) != 1 {
		t.Fatalf("unassigns=%v, want one", api.listsAtUnassign)
	}
	dispatchedAfter := api.listsAtUnassign[0]
	if len(api.gateHeldOnLists) < dispatchedAfter+destructiveAbsenceConfirmations {
		t.Fatalf("relation reads=%d after dispatch at %d, want absence confirmations", len(api.gateHeldOnLists), dispatchedAfter)
	}
	// The exact pre-DELETE read and the first post-DELETE readback stay
	// serialized with other same-firewall mutations.
	if !api.gateHeldOnLists[dispatchedAfter-1] || !api.gateHeldOnLists[dispatchedAfter] {
		t.Fatalf("gate was not held around the mutation: held=%v dispatchAfterRead=%d", api.gateHeldOnLists, dispatchedAfter)
	}
	// Later read-only absence confirmations must not block same-firewall launches.
	for i := dispatchedAfter + 1; i < len(api.gateHeldOnLists); i++ {
		if api.gateHeldOnLists[i] {
			t.Fatalf("read-only confirmation %d still held the firewall gate: held=%v", i+1, api.gateHeldOnLists)
		}
	}
}

// deleteVMProbeAPI records how many canonical VM reads preceded each DELETE.
type deleteVMProbeAPI struct {
	*fakeAPI
	getsAtDelete []int
}

func (f *deleteVMProbeAPI) DeleteVM(ctx context.Context, location, uuid string) error {
	f.getsAtDelete = append(f.getsAtDelete, f.vmGetCalls)
	return f.fakeAPI.DeleteVM(ctx, location, uuid)
}

func TestDurableVMDeleteUncommittedFailureIsResentAfterSpacedPresence(t *testing.T) {
	api := &deleteVMProbeAPI{fakeAPI: &fakeAPI{}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteVMErrors = []error{&sdk.APIError{StatusCode: 500, Message: "failed before commit"}}
	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if !errors.Is(err, errVMAbsenceUncertain) {
		t.Fatalf("first DeleteVM() error = %v, want the uncommitted VM to remain present", err)
	}
	if api.deleteVMCalls != 1 || len(api.vms) != 1 || harness.current.Phase != cloudapi.RemovalMutationIssued {
		t.Fatalf("uncommitted delete state: calls=%d VMs=%d receipt=%#v", api.deleteVMCalls, len(api.vms), harness.current)
	}
	issued := harness.current
	var observed []cloudapi.RemovalMutationFence
	identity.ObserveRemovalMutation = func(ctx context.Context, fence cloudapi.RemovalMutationFence) error {
		observed = append(observed, fence)
		return harness.observe(ctx, fence)
	}

	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	getsBefore := api.vmGetCalls
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("restarted DeleteVM() stayed wedged on an issued but uncommitted receipt: %v", err)
	}
	if api.deleteVMCalls != 2 || len(api.vms) != 0 {
		t.Fatalf("issued VM DELETE was not re-sent exactly once: calls=%d VMs=%#v", api.deleteVMCalls, api.vms)
	}
	if spaced := api.getsAtDelete[1] - getsBefore; spaced < destructiveAbsenceConfirmations+1 {
		t.Fatalf("re-send followed %d canonical reads, want the pre-delete read plus %d spaced presence proofs", spaced, destructiveAbsenceConfirmations)
	}
	if len(observed) == 0 || observed[0] != issued {
		t.Fatalf("re-send did not observe the original VM DELETE receipt: issued=%#v observed=%#v", issued, observed)
	}
	for _, fence := range observed[1:] {
		if fence.Operation == cloudapi.RemovalMutationVMDelete {
			t.Fatalf("re-send minted a second VM DELETE receipt: %#v", observed)
		}
	}
}

func TestDurableVMDeleteDoesNotResendWhenOwnershipChangesDuringPresenceProof(t *testing.T) {
	api := &deleteVMProbeAPI{fakeAPI: &fakeAPI{}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteVMErrors = []error{&sdk.APIError{StatusCode: 500, Message: "failed before commit"}}
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("first DeleteVM() unexpectedly converged")
	}
	getsBefore := api.vmGetCalls
	api.getVMHook = func(uuid string) {
		// After the pre-delete ownership audit, the VM stops carrying this
		// NodeClaim's exact ownership record.
		if uuid != created.UUID || api.vmGetCalls < getsBefore+2 {
			return
		}
		api.mu.Lock()
		for i := range api.vms {
			if api.vms[i].UUID == created.UUID && !strings.Contains(api.vms[i].Description, "changed-owner") {
				api.vms[i].Description = strings.Replace(api.vms[i].Description, `"nodeClaim":"nodeclaim-a"`, `"nodeClaim":"changed-owner"`, 1)
			}
		}
		api.mu.Unlock()
	}
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("DeleteVM() converged although the VM ownership changed")
	}
	if api.deleteVMCalls != 1 || len(api.vms) != 1 {
		t.Fatalf("VM DELETE was re-sent after ownership changed: calls=%d VMs=%d", api.deleteVMCalls, len(api.vms))
	}
}

func TestDeleteConfirmsDependentAbsenceWithOneReadAfterFloatingIPCleanup(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.getVMHook = func(uuid string) {
		if uuid == created.UUID {
			api.operations = append(api.operations, "get-vm")
		}
	}
	api.operations = nil
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a", cloudapi.DeleteVMIdentity{}); err != nil {
		t.Fatal(err)
	}
	lastFloatingIPDelete, firstDetach := -1, -1
	for i, operation := range api.operations {
		switch operation {
		case "delete-floating-ip":
			lastFloatingIPDelete = i
		case "unassign-firewall":
			if firstDetach < 0 {
				firstDetach = i
			}
		}
	}
	if lastFloatingIPDelete < 0 || firstDetach < lastFloatingIPDelete {
		t.Fatalf("delete staging changed: operations=%v", api.operations)
	}
	reads := countOperation(api.operations[lastFloatingIPDelete:firstDetach], "get-vm")
	// Core absence was already proven with spaced reads and persisted before the
	// floating IP was removed, and the firewall DELETE re-confirms core absence
	// with one read immediately before dispatch (it no longer repeats the spaced
	// proof). One dependent read closes the gap between.
	if want := 1 + 1; reads != want {
		t.Fatalf("canonical VM reads between floating-IP cleanup and firewall DELETE = %d, want %d; operations=%v", reads, want, api.operations)
	}
}
