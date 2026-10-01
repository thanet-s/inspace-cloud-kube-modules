package inspace

import (
	"context"
	"errors"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const flapVMUUID = "11111111-1111-4111-8111-111111111111"

// flapGetVM scripts the exact VM GET: the first read shows the VM (or fails
// with a retryable 500), every later read is a clean 404. Each call is logged
// in api.operations as get-vm-contrary or get-vm-absent.
func flapGetVM(api *fakeAPI, contrary string) {
	if contrary == "transport error" {
		api.vms = nil
		api.getVMErrorByUUID = map[string]error{flapVMUUID: errors.New("connection reset by peer")}
	}
	calls := 0
	// The fake reads the VM and any injected error before it calls the hook, so
	// the first read still sees the scripted contrary state and the hook only
	// makes every later read clean.
	api.getVMHook = func(uuid string) {
		if uuid != flapVMUUID {
			return
		}
		calls++
		if calls == 1 {
			api.mu.Lock()
			api.vms = nil
			api.getVMErrorByUUID = nil
			api.mu.Unlock()
			api.operations = append(api.operations, "get-vm-contrary")
			return
		}
		api.operations = append(api.operations, "get-vm-absent")
	}
}

func flapVM() sdk.VM {
	return sdk.VM{UUID: flapVMUUID, Name: "flapping", Description: "foreign"}
}

// trailingAbsentReadsBefore counts the consecutive clean reads immediately
// before the first occurrence of mutation in operations.
func trailingAbsentReadsBefore(operations []string, mutation string) int {
	index := -1
	for i, operation := range operations {
		if operation == mutation {
			index = i
			break
		}
	}
	if index < 0 {
		return -1
	}
	count := 0
	for i := index - 1; i >= 0 && operations[i] == "get-vm-absent"; i-- {
		count++
	}
	return count
}

func TestReducedAbsenceConfirmationEscalatesToFullProofAfterAContraryRead(t *testing.T) {
	confirmers := map[string]func(*Adapter) error{
		"core": func(a *Adapter) error {
			return a.confirmAuthorizedVMCoreAbsence(context.Background(), "bkk01", "network-1", flapVMUUID, "flap test", nil)
		},
		"core and floating IP": func(a *Adapter) error {
			return a.confirmAuthorizedVMAbsence(context.Background(), "bkk01", "network-1", flapVMUUID, "flap test", nil)
		},
	}
	for name, confirm := range confirmers {
		for _, contrary := range []string{"VM visible", "transport error"} {
			t.Run(name+"/"+contrary, func(t *testing.T) {
				api := &fakeAPI{vms: []sdk.VM{flapVM()}}
				adapter, _ := New(api)
				configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
				clock := installVirtualReadbackClock(t)
				useProductionConfirmationIntervals(adapter)
				flapGetVM(api, contrary)

				if err := confirm(adapter); err != nil {
					t.Fatalf("confirmation = %v", err)
				}
				absent := 0
				for _, operation := range api.operations {
					if operation == "get-vm-absent" {
						absent++
					}
				}
				// present (or error) -> 404 must not be enough: three spaced clean
				// reads are required once anything contrary was seen.
				if absent < destructiveAbsenceConfirmations || clock.spaced() < destructiveAbsenceConfirmations-1 {
					t.Fatalf("clean reads=%d spaced waits=%d (%v); a flapping VM must need %d spaced absent reads", absent, clock.spaced(), clock.waits, destructiveAbsenceConfirmations)
				}
			})
		}
	}
}

func TestReducedAbsenceConfirmationStaysOneReadWhenNothingContradicts(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	clock := installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)

	if err := adapter.confirmAuthorizedVMCoreAbsence(context.Background(), "bkk01", "network-1", flapVMUUID, "clean", nil); err != nil {
		t.Fatal(err)
	}
	if api.vmGetCalls != 1 || clock.spaced() != 0 {
		t.Fatalf("clean confirmation used %d GETs and %d spaced waits, want one read", api.vmGetCalls, clock.spaced())
	}
}

func TestFlappingVMNeedsThreeSpacedAbsentReadsBeforeFirewallDelete(t *testing.T) {
	const firewallUUID = "33333333-3333-4333-8333-333333333333"
	firewall := secureFirewall()
	firewall.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: flapVMUUID}}
	api := &fakeAPI{vms: []sdk.VM{flapVM()}, firewalls: []sdk.Firewall{firewall}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	flapGetVM(api, "VM visible")

	err := adapter.detachFirewallAfterVMDeletionWithProof(context.Background(), "bkk01", "network-1", firewallUUID, flapVMUUID, firewall.BillingAccountID, baseFirewallDetachmentAuthority{}, true, nil)
	if err != nil {
		t.Fatalf("detachment = %v", err)
	}
	if got := trailingAbsentReadsBefore(api.operations, "unassign-firewall"); got < destructiveAbsenceConfirmations {
		t.Fatalf("firewall DELETE followed %d clean VM reads (%v), want at least %d after the VM was seen", got, api.operations, destructiveAbsenceConfirmations)
	}
}

func TestFlappingVMNeedsThreeSpacedAbsentReadsBeforeFloatingIPRemoval(t *testing.T) {
	address := sdk.FloatingIP{
		Address: "203.0.113.10", Name: "karpenter-nodeclaim-a-b4d89a8fa6", BillingAccountID: 1, Enabled: true, Type: "public",
	}
	api := &fakeAPI{vms: []sdk.VM{flapVM()}, floatingIPs: []sdk.FloatingIP{address}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	flapGetVM(api, "VM visible")
	harness := &testRemovalMutationHarness{}
	authority := removalMutationAuthority{fenced: true, authorize: harness.authorize, observe: harness.observe, reject: harness.reject}

	err := adapter.deleteOwnedFloatingIPWithProof(context.Background(), "bkk01", "network-1", address, flapVMUUID, authority, true, nil)
	if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("floating-IP removal = %v", err)
	}
	if got := trailingAbsentReadsBefore(api.operations, "delete-floating-ip"); got < destructiveAbsenceConfirmations {
		t.Fatalf("floating-IP DELETE followed %d clean VM reads (%v), want at least %d after the VM was seen", got, api.operations, destructiveAbsenceConfirmations)
	}
}

func TestFlappingVMNeedsThreeSpacedAbsentReadsInMissingVMAfterDeleteStep(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil
	api.operations = nil
	installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	// The delete preflight proves absence with GETs 1-3; the after-delete
	// confirmation is GET 4 and fails with a retryable server error, after
	// which reads are clean again.
	calls := 0
	api.getVMHook = func(uuid string) {
		if uuid != created.UUID {
			return
		}
		calls++
		api.mu.Lock()
		switch calls {
		case 3:
			api.getVMErrorByUUID = map[string]error{created.UUID: errors.New("connection reset by peer")}
		case 4:
			api.getVMErrorByUUID = nil
		}
		api.mu.Unlock()
		switch {
		case calls == 4:
			api.operations = append(api.operations, "get-vm-contrary")
		case calls > 4:
			api.operations = append(api.operations, "get-vm-absent")
		}
	}

	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a", durableDeleteIdentity(created)); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("DeleteVM() = %v", err)
	}
	// Reads after the contrary one, before the first mutation of the
	// dependent cleanup that follows the after-delete step.
	if got := trailingAbsentReadsBefore(api.operations, "unassign-floating-ip"); got < destructiveAbsenceConfirmations {
		t.Fatalf("dependent cleanup started after %d clean VM reads (%v), want at least %d once a read was contrary", got, api.operations, destructiveAbsenceConfirmations)
	}
}
