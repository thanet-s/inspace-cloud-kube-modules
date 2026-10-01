package inspace

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestDeleteLiveVMReusesPostDeleteAbsenceProofForFloatingIPAndFirewallStages(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
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
	clock := installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	api.operations = nil
	getBefore := api.vmGetCalls

	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("DeleteVM() = %v", err)
	}
	t.Logf("live-VM delete simulated wait: %v over %d spaced waits, %d VM GETs", clock.total(), clock.spaced(), api.vmGetCalls-getBefore)
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("delete left VMs=%d floating IPs=%d firewall=%#v", len(api.vms), len(api.floatingIPs), api.firewalls[0])
	}
	// The three-read proof after the VM DELETE is the real safety proof and
	// stays (2 gaps). The floating-IP removal CAS and the firewall DELETE reuse
	// it with one confirming read each; the floating IP's own absence proof
	// (2 gaps) and the firewall relation's absence readback (2 gaps) remain.
	if got := clock.spaced(); got != 6 {
		t.Fatalf("spaced waits = %d (%v), want 6", got, clock.waits)
	}
	// Before this change the same delete took 14 VM GETs: each re-proof added
	// two further spaced reads.
	if got := api.vmGetCalls - getBefore; got > 10 {
		t.Fatalf("VM GET reads = %d, want at most 10", got)
	}
}

func TestDeleteLiveVMKeepsFullPostDeleteVMAbsenceProof(t *testing.T) {
	api := &fakeAPI{deleteVMKeepCount: 1, firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	vanishedAtGet := 0
	getBefore := api.vmGetCalls
	api.getVMHook = func(uuid string) {
		if uuid != created.UUID || api.deleteVMCalls == 0 || api.vmGetCalls < getBefore+3 {
			return
		}
		api.mu.Lock()
		if len(api.vms) != 0 {
			api.vms = nil
			vanishedAtGet = api.vmGetCalls
		}
		api.mu.Unlock()
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	clock := installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	api.operations = nil

	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("DeleteVM() = %v", err)
	}
	if api.firewallDetachedWhileVMVisible {
		t.Fatal("firewall detached while the VM was still visible")
	}
	// The VM stays visible for the first reads after DELETE. Once it vanishes
	// the post-DELETE proof still needs three clean reads (the final one is the
	// last read before any dependent cleanup), so at least two further reads
	// were taken after the VM vanished.
	if vanishedAtGet == 0 {
		t.Fatal("the VM never vanished in the fake")
	}
	if got := clock.spaced(); got < 6 {
		t.Fatalf("spaced waits = %d (%v), want the full proof plus dependent absence", got, clock.waits)
	}
}

func TestFloatingIPRemovalWithPriorProofStillRejectsVMReappearingAfterCAS(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	address := sdk.FloatingIP{
		Address: "203.0.113.10", Name: "karpenter-nodeclaim-a-b4d89a8fa6", BillingAccountID: 1, Enabled: true, Type: "public",
	}
	api := &fakeAPI{floatingIPs: []sdk.FloatingIP{address}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	var issued cloudapi.RemovalMutationFence
	rejects := 0
	authority := removalMutationAuthority{
		fenced: true,
		authorize: func(_ context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
			if !present {
				return cloudapi.RemovalMutationAuthorization{}, nil
			}
			issued = cloudapi.RemovalMutationFence{
				RemovalMutation: mutation, Phase: cloudapi.RemovalMutationIssued,
				IssueID: strings.Repeat("b", 32), IssuedAt: time.Now().UTC(),
			}
			// The UUID is reused by a live VM after the CAS.
			api.vms = append(api.vms, sdk.VM{UUID: vmUUID, Name: "uuid-reused-after-cas", Description: "foreign"})
			return cloudapi.RemovalMutationAuthorization{Fence: issued, Active: true, AllowMutation: true}, nil
		},
		observe: func(context.Context, cloudapi.RemovalMutationFence) error { return nil },
		reject: func(_ context.Context, rejected cloudapi.RemovalMutationFence) error {
			if rejected != issued {
				return errors.New("floating-IP removal rejection identity changed")
			}
			rejects++
			issued.Phase = cloudapi.RemovalMutationRejected
			return nil
		},
	}

	err := adapter.deleteOwnedFloatingIPWithProof(context.Background(), "bkk01", "network-1", address, vmUUID, authority, true, nil)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("removal error = %v, want post-CAS proof failure", err)
	}
	if countOperation(api.operations, "delete-floating-ip") != 0 || countOperation(api.operations, "unassign-floating-ip") != 0 ||
		issued.Phase != cloudapi.RemovalMutationRejected || rejects != 1 {
		t.Fatalf("a reappeared VM was not blocked: operations=%v fence=%#v rejects=%d", api.operations, issued, rejects)
	}
}

func TestFirewallDetachmentWithPriorProofStillRejectsVMReappearingAfterCAS(t *testing.T) {
	const (
		vmUUID       = "11111111-1111-4111-8111-111111111111"
		firewallUUID = "33333333-3333-4333-8333-333333333333"
	)
	firewall := secureFirewall()
	firewall.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}}
	api := &fakeAPI{firewalls: []sdk.Firewall{firewall}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	var fence cloudapi.FirewallDetachmentFence
	rejects := 0
	authority := baseFirewallDetachmentAuthority{
		fenced: true,
		authorize: func(_ context.Context, uuid string) (cloudapi.FirewallDetachmentAuthorization, error) {
			fence = cloudapi.FirewallDetachmentFence{
				VMUUID: uuid, FirewallUUID: firewallUUID, Phase: cloudapi.FirewallAssignmentIssued, IssueID: strings.Repeat("c", 32),
			}
			api.vms = append(api.vms, sdk.VM{UUID: vmUUID, Name: "uuid-reused-after-cas", Description: "foreign"})
			return cloudapi.FirewallDetachmentAuthorization{Fence: fence, AllowDELETE: true}, nil
		},
		observe: func(context.Context, cloudapi.FirewallDetachmentFence) error { return nil },
		reject: func(_ context.Context, rejected cloudapi.FirewallDetachmentFence) error {
			if rejected != fence {
				return errors.New("firewall detachment rejection identity changed")
			}
			rejects++
			fence.Phase = cloudapi.FirewallAssignmentRejected
			return nil
		},
	}

	err := adapter.detachFirewallAfterVMDeletionWithProof(context.Background(), "bkk01", "network-1", firewallUUID, vmUUID, firewall.BillingAccountID, authority, true, nil)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("detachment error = %v, want post-CAS VM absence failure", err)
	}
	if countOperation(api.operations, "unassign-firewall") != 0 || fence.Phase != cloudapi.FirewallAssignmentRejected || rejects != 1 {
		t.Fatalf("a reappeared VM was not blocked: operations=%v fence=%#v rejects=%d", api.operations, fence, rejects)
	}
}
