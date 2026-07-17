package inspace

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestPostLaunchCASAppearanceIsAdoptedWithoutDuplicateVMPost(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := fencedAdapterRequest(true)
	authorizeCalls := 0
	anchored := ""
	request.AuthorizeLaunch = func(_ context.Context, kind cloudapi.CreateAuthorizationKind) error {
		if kind != cloudapi.CreateAuthorizationPost {
			t.Fatalf("authorization kind = %q, want POST", kind)
		}
		authorizeCalls++
		api.vms = append(api.vms, canonicalVMForRequest(t, request, vmUUID))
		api.floatingIPs = append(api.floatingIPs, sdk.FloatingIP{
			Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
		})
		return nil
	}
	request.RecordCreatedVM = func(_ context.Context, uuid string) error {
		anchored = uuid
		return nil
	}

	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID != vmUUID || anchored != vmUUID || authorizeCalls != 1 || api.createCalls != 0 {
		t.Fatalf("post-CAS adoption = created=%#v anchor=%q auth=%d POSTs=%d", created, anchored, authorizeCalls, api.createCalls)
	}
	if api.firewallAssignCalls != 1 || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("post-CAS adoption was not protected exactly once: firewall=%d FIP PATCH=%d", api.firewallAssignCalls, api.floatingIPUpdateCalls)
	}
}

func TestPostLaunchCASNetworkAuthorityDriftRejectsUndispatchedAttempt(t *testing.T) {
	readErr := errors.New("network read failed after launch CAS")
	tests := []struct {
		name   string
		mutate func(*fakeAPI)
		want   string
	}{
		{
			name: "subnet drift",
			mutate: func(api *fakeAPI) {
				api.network = &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/23"}
			},
			want: "configured network prefix changed from preflight",
		},
		{
			name: "control-plane VIP outside drifted subnet",
			mutate: func(api *fakeAPI) {
				api.network = &sdk.Network{UUID: "network-1", Subnet: "10.0.0.128/25"}
			},
			want: "private RKE2 supervisor VIP 10.0.0.10 must be inside subnet 10.0.0.128/25",
		},
		{
			name: "private load-balancer pool outside drifted subnet",
			mutate: func(api *fakeAPI) {
				api.network = &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/25"}
			},
			want: "private load-balancer pool start 10.0.0.200 must be inside subnet 10.0.0.0/25",
		},
		{
			name: "wrong UUID",
			mutate: func(api *fakeAPI) {
				api.network = &sdk.Network{UUID: "network-2", Subnet: "10.0.0.0/24"}
			},
			want: `network read-back UUID "network-2" does not match "network-1"`,
		},
		{
			name: "malformed subnet",
			mutate: func(api *fakeAPI) {
				api.network = &sdk.Network{UUID: "network-1", Subnet: "not-a-prefix"}
			},
			want: `network network-1 subnet "not-a-prefix" must be an RFC1918 IPv4 prefix`,
		},
		{
			name: "read error",
			mutate: func(api *fakeAPI) {
				api.networkErrors = map[int]error{2: readErr}
			},
			want: "getting InSpace network network-1 immediately before worker VM create",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			request := fencedAdapterRequest(true)
			receiptPhase := "intent"
			authorizeCalls := 0
			request.AuthorizeLaunch = func(_ context.Context, kind cloudapi.CreateAuthorizationKind) error {
				if kind != cloudapi.CreateAuthorizationPost {
					t.Fatalf("authorization kind = %q, want POST", kind)
				}
				authorizeCalls++
				receiptPhase = "issued"
				test.mutate(api)
				return nil
			}
			request.RecordCreatedVM = func(context.Context, string) error {
				receiptPhase = "anchored"
				return nil
			}

			_, err := adapter.CreateVM(context.Background(), request)
			if !errors.Is(err, cloudapi.ErrCreateAttemptRejected) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("CreateVM() error = %v, want rejected post-CAS network failure containing %q", err, test.want)
			}
			if api.createCalls != 0 {
				t.Fatalf("post-CAS network failure dispatched %d VM POSTs, want zero", api.createCalls)
			}
			if authorizeCalls != 1 || receiptPhase != "issued" {
				t.Fatalf("launch authorization = phase %q after %d calls; provider must consume ErrCreateAttemptRejected for this exact issue", receiptPhase, authorizeCalls)
			}
			if api.networkGetCalls != 2 || api.firewallListCalls != 2 {
				t.Fatalf("post-CAS authority ordering = network reads %d, firewall reads %d; want fresh network read before a third firewall read", api.networkGetCalls, api.firewallListCalls)
			}
		})
	}
}

func TestBaseFirewallAssignmentDriftAfterCASRejectsUndispatchedReceipt(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	api := &fakeAPI{vms: []sdk.VM{canonicalVMForRequest(t, request, vmUUID)}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.vmUUID = vmUUID
	harness.anchorAttempt = vmUUID
	harness.attachAssignmentCallbacks(&request)
	originalAuthorize := request.AuthorizeBaseFirewall
	request.AuthorizeBaseFirewall = func(ctx context.Context, uuid string) (cloudapi.FirewallAssignmentAuthorization, error) {
		authorization, err := originalAuthorize(ctx, uuid)
		api.vms[0].Name = "foreign-after-cas"
		return authorization, err
	}

	err := adapter.ensureCreateBaseFirewall(context.Background(), request, vmUUID, netip.MustParsePrefix("10.0.0.0/24"), true)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("assignment error = %v, want post-CAS proof failure", err)
	}
	if api.firewallAssignCalls != 0 || harness.fence.Phase != cloudapi.FirewallAssignmentRejected || harness.rejectCalls != 1 {
		t.Fatalf("post-CAS drift failed to reject undispatched receipt: assigns=%d fence=%#v rejects=%d", api.firewallAssignCalls, harness.fence, harness.rejectCalls)
	}
}

func TestAutoFloatingIPDriftAfterCASRejectsUndispatchedReceipt(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	address := sdk.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
	}
	api := &fakeAPI{vms: []sdk.VM{canonicalVMForRequest(t, request, vmUUID)}, floatingIPs: []sdk.FloatingIP{address}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	originalAuthorize := request.AuthorizeFloatingIPUpdate
	request.AuthorizeFloatingIPUpdate = func(ctx context.Context, uuid, publicIP, name string, account int64) (cloudapi.FloatingIPUpdateAuthorization, error) {
		authorization, err := originalAuthorize(ctx, uuid, publicIP, name, account)
		api.vms[0].Name = "foreign-after-cas"
		return authorization, err
	}

	_, err := adapter.ensureAutoFloatingIP(
		context.Background(), request.Location, vmUUID, floatingIPName(request.ClusterName, request.NodeClaimName), request.BillingAccountID,
		createFloatingIPUpdateAuthority(request),
		func(ctx context.Context) error {
			return adapter.proveFreshCreateMutationTarget(ctx, request, vmUUID, netip.MustParsePrefix("10.0.0.0/24"))
		},
	)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("floating-IP error = %v, want post-CAS proof failure", err)
	}
	if api.floatingIPUpdateCalls != 0 || harness.fence.Phase != cloudapi.FloatingIPUpdateRejected || harness.rejectCalls != 1 {
		t.Fatalf("post-CAS drift failed to reject undispatched FIP receipt: PATCHes=%d fence=%#v rejects=%d", api.floatingIPUpdateCalls, harness.fence, harness.rejectCalls)
	}
}

func TestCleanupFloatingIPDeletedVMTombstoneRejectsUndispatchedReceipt(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedCleanupRequest(true)
	request.CreatedVMUUID = vmUUID
	vm := canonicalVMForRequest(t, testRequest(), vmUUID)
	vm.Status = "Deleted"
	address := sdk.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
	}
	api := &fakeAPI{vms: []sdk.VM{vm}, floatingIPs: []sdk.FloatingIP{address}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCleanup(&request)

	_, err := adapter.ensureAutoFloatingIP(
		context.Background(), request.Location, vmUUID, floatingIPName(request.ClusterName, request.NodeClaimName), request.BillingAccountID,
		cleanupFloatingIPUpdateAuthority(request),
		func(ctx context.Context) error {
			return adapter.ensureFencedCreateAnchorOwnership(ctx, request)
		},
	)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("deleted cleanup VM authority error = %v, want pre-dispatch proof rejection", err)
	}
	if api.floatingIPUpdateCalls != 0 || api.firewallAssignCalls != 0 || api.deleteVMCalls != 0 ||
		harness.fence.Phase != cloudapi.FloatingIPUpdateRejected || harness.rejectCalls != 1 || len(api.operations) != 0 {
		t.Fatalf("deleted cleanup VM crossed mutation boundary: FIP PATCHes=%d firewall=%d VM deletes=%d fence=%#v rejects=%d operations=%v",
			api.floatingIPUpdateCalls, api.firewallAssignCalls, api.deleteVMCalls, harness.fence, harness.rejectCalls, api.operations)
	}
}

func TestBaselineFloatingIPDriftAfterCASRejectsUndispatchedReceipt(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedCleanupRequest(true)
	current := sdk.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
	}
	identity, err := floatingIPInventoryIdentity(current)
	if err != nil {
		t.Fatal(err)
	}
	assignment := cloudapi.CreateFloatingIPAssignment{
		Identity: identity, VMUUID: vmUUID, Address: current.Address, BillingAccountID: current.BillingAccountID,
	}
	api := &fakeAPI{floatingIPs: []sdk.FloatingIP{current}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCleanup(&request)
	originalAuthorize := request.AuthorizeFloatingIPUpdate
	request.AuthorizeFloatingIPUpdate = func(ctx context.Context, uuid, publicIP, name string, account int64) (cloudapi.FloatingIPUpdateAuthorization, error) {
		authorization, authorizeErr := originalAuthorize(ctx, uuid, publicIP, name, account)
		api.floatingIPs[0].AssignedTo = "99999999-9999-4999-8999-999999999999"
		return authorization, authorizeErr
	}

	_, err = adapter.ensureBaselineTargetFloatingIPName(
		context.Background(), request.Location, assignment, vmUUID,
		floatingIPName(request.ClusterName, request.NodeClaimName), cleanupFloatingIPUpdateAuthority(request),
		func(context.Context) error { return nil },
	)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("baseline floating-IP error = %v, want post-CAS proof failure", err)
	}
	if api.floatingIPUpdateCalls != 0 || harness.fence.Phase != cloudapi.FloatingIPUpdateRejected || harness.rejectCalls != 1 {
		t.Fatalf("post-CAS baseline drift failed to reject undispatched receipt: PATCHes=%d fence=%#v rejects=%d", api.floatingIPUpdateCalls, harness.fence, harness.rejectCalls)
	}
}

func TestVMDeleteDriftAfterCASRejectsUndispatchedReceipt(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	identity := durableDeleteIdentity(created)
	var fence cloudapi.RemovalMutationFence
	rejects := 0
	identity.AuthorizeRemovalMutation = func(_ context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
		if mutation.Operation != cloudapi.RemovalMutationVMDelete || !present {
			t.Fatalf("removal authorization = %#v present=%t", mutation, present)
		}
		fence = cloudapi.RemovalMutationFence{RemovalMutation: mutation, Phase: cloudapi.RemovalMutationIssued, IssueID: strings.Repeat("a", 32)}
		api.vms[0].Name = "foreign-after-cas"
		return cloudapi.RemovalMutationAuthorization{Fence: fence, Active: true, AllowMutation: true}, nil
	}
	identity.ObserveRemovalMutation = func(context.Context, cloudapi.RemovalMutationFence) error { return nil }
	identity.RejectRemovalMutation = func(_ context.Context, rejected cloudapi.RemovalMutationFence) error {
		if rejected != fence {
			return errors.New("removal rejection identity changed")
		}
		rejects++
		fence.Phase = cloudapi.RemovalMutationRejected
		return nil
	}
	api.operations = nil

	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("DeleteVM() error = %v, want post-CAS proof failure", err)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || fence.Phase != cloudapi.RemovalMutationRejected || rejects != 1 {
		t.Fatalf("post-CAS VM drift failed to reject undispatched DELETE: calls=%d operations=%v fence=%#v rejects=%d", api.deleteVMCalls, api.operations, fence, rejects)
	}
}

func TestFloatingIPRemovalDriftAfterCASRejectsUndispatchedReceipt(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	for _, test := range []struct {
		name      string
		assigned  bool
		operation cloudapi.RemovalMutationOperation
		wantOp    string
	}{
		{name: "unassign", assigned: true, operation: cloudapi.RemovalMutationFloatingIPUnassign, wantOp: "unassign-floating-ip"},
		{name: "delete", assigned: false, operation: cloudapi.RemovalMutationFloatingIPDelete, wantOp: "delete-floating-ip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := sdk.FloatingIP{
				Address: "203.0.113.10", Name: "karpenter-nodeclaim-a-b4d89a8fa6", BillingAccountID: 1, Enabled: true, Type: "public",
			}
			if test.assigned {
				address.AssignedTo = vmUUID
				address.AssignedToResourceType = "virtual_machine"
			}
			api := &fakeAPI{floatingIPs: []sdk.FloatingIP{address}}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			var issued cloudapi.RemovalMutationFence
			rejects := 0
			authority := removalMutationAuthority{
				fenced: true,
				authorize: func(_ context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
					if !test.assigned && mutation.Operation == cloudapi.RemovalMutationFloatingIPUnassign && !present {
						return cloudapi.RemovalMutationAuthorization{}, nil
					}
					if mutation.Operation != test.operation || !present {
						t.Fatalf("authorization = %#v present=%t, want %s/present", mutation, present, test.operation)
					}
					issued = cloudapi.RemovalMutationFence{RemovalMutation: mutation, Phase: cloudapi.RemovalMutationIssued, IssueID: strings.Repeat("b", 32)}
					if test.assigned {
						api.floatingIPs[0].AssignedTo = "99999999-9999-4999-8999-999999999999"
					} else {
						api.floatingIPs[0].Name = "foreign-after-cas"
					}
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

			err := adapter.deleteOwnedFloatingIP(context.Background(), "bkk01", "network-1", address, vmUUID, authority)
			if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
				t.Fatalf("removal error = %v, want post-CAS proof failure", err)
			}
			if countOperation(api.operations, test.wantOp) != 0 || issued.Phase != cloudapi.RemovalMutationRejected || rejects != 1 {
				t.Fatalf("post-CAS FIP drift failed to reject undispatched receipt: operations=%v fence=%#v rejects=%d", api.operations, issued, rejects)
			}
		})
	}
}

func TestFirewallDetachmentVMReappearanceAfterCASRejectsUndispatchedReceipt(t *testing.T) {
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

	err := adapter.detachFirewallAfterVMDeletion(context.Background(), "bkk01", "network-1", firewallUUID, vmUUID, firewall.BillingAccountID, authority)
	if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "fresh mutation-target proof") {
		t.Fatalf("detachment error = %v, want post-CAS VM absence failure", err)
	}
	if countOperation(api.operations, "unassign-firewall") != 0 || fence.Phase != cloudapi.FirewallAssignmentRejected || rejects != 1 {
		t.Fatalf("post-CAS VM reappearance failed to reject undispatched detachment: operations=%v fence=%#v rejects=%d", api.operations, fence, rejects)
	}
}
