package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	reallocatedFIPOldVM = "11111111-1111-4111-8111-111111111111"
	reallocatedFIPNewVM = "22222222-2222-4222-8222-222222222222"
	reallocatedFIPName  = "karpenter-edge-old-0123456789"
	reallocatedFIPAddr  = "203.0.113.10"
)

var (
	reallocatedFIPCreatedAt = time.Date(2026, time.July, 18, 10, 50, 45, 0, time.UTC)
	oldFIPDeleteIssuedAt    = reallocatedFIPCreatedAt.Add(-time.Minute)
	oldFIPDeleteObservedAt  = reallocatedFIPCreatedAt.Add(time.Minute)
)

func reallocatedFloatingIP() sdk.FloatingIP {
	var address sdk.FloatingIP
	if err := json.Unmarshal([]byte(`{
		"uuid":"55555555-5555-4555-8555-555555555555",
		"id":155566,
		"address":"203.0.113.10",
		"user_id":7,
		"billing_account_id":1,
		"type":"public",
		"name":"karpenter-edge-new-9876543210",
		"enabled":true,
		"is_deleted":false,
		"is_ipv6":false,
		"assigned_to":"22222222-2222-4222-8222-222222222222",
		"assigned_to_resource_type":"virtual_machine",
		"assigned_to_private_ip":"10.0.0.22",
		"created_at":"2026-07-18 10:50:45",
		"updated_at":"2026-07-18 10:50:47"
	}`), &address); err != nil {
		panic(err)
	}
	return address
}

func reallocatedFloatingIPWithIsVirtual(value bool) sdk.FloatingIP {
	address := reallocatedFloatingIP()
	address.IsVirtual = value
	encoded, err := json.Marshal(address)
	if err != nil {
		panic(err)
	}
	var result sdk.FloatingIP
	if err := json.Unmarshal(encoded, &result); err != nil {
		panic(err)
	}
	return result
}

func observedFloatingIPDeleteHarness() *testRemovalMutationHarness {
	return observedFloatingIPDeleteHarnessFor(reallocatedFIPName)
}

func observedFloatingIPDeleteHarnessFor(oldName string) *testRemovalMutationHarness {
	return &testRemovalMutationHarness{current: cloudapi.RemovalMutationFence{
		RemovalMutation: cloudapi.RemovalMutation{
			Operation:        cloudapi.RemovalMutationFloatingIPDelete,
			Location:         "bkk01",
			VMUUID:           reallocatedFIPOldVM,
			Address:          reallocatedFIPAddr,
			Name:             oldName,
			BillingAccountID: 1,
		},
		Phase:      cloudapi.RemovalMutationObserved,
		IssueID:    strings.Repeat("a", 32),
		IssuedAt:   oldFIPDeleteIssuedAt,
		ObservedAt: oldFIPDeleteObservedAt,
	}}
}

func reallocationRemovalAuthority(harness *testRemovalMutationHarness) removalMutationAuthority {
	identity := cloudapi.DeleteVMIdentity{}
	harness.attachDelete(&identity)
	return deleteRemovalMutationAuthority(identity)
}

func TestObservedFloatingIPAddressReallocationProofIsReadOnly(t *testing.T) {
	tests := map[string]struct {
		mutateAddress func(*sdk.FloatingIP)
		mutateAPI     func(*fakeAPI)
		mutateFence   func(*testRemovalMutationHarness)
		wantAccepted  bool
	}{
		"observed exact deletion accepts a complete later allocation": {
			wantAccepted: true,
		},
		"RFC3339 allocation timestamp remains accepted": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = reallocatedFIPCreatedAt.Format(time.RFC3339Nano)
				address.UpdatedAt = reallocatedFIPCreatedAt.Format(time.RFC3339Nano)
			},
			wantAccepted: true,
		},
		"optional is_virtual present and equal remains accepted": {
			mutateAPI: func(api *fakeAPI) {
				address := reallocatedFloatingIPWithIsVirtual(false)
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &address}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {address}}
			},
			wantAccepted: true,
		},
		"explicit virtual allocation fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				virtual := reallocatedFloatingIPWithIsVirtual(true)
				*address = virtual
			},
		},
		"ready fence is insufficient": {
			mutateFence: func(h *testRemovalMutationHarness) {
				h.current = cloudapi.RemovalMutationFence{}
			},
		},
		"issued receipt is insufficient": {
			mutateFence: func(h *testRemovalMutationHarness) {
				h.current.Phase = cloudapi.RemovalMutationIssued
				h.current.ObservedAt = time.Time{}
			},
		},
		"rejected receipt is insufficient": {
			mutateFence: func(h *testRemovalMutationHarness) {
				h.current.Phase = cloudapi.RemovalMutationRejected
				h.current.ObservedAt = time.Time{}
			},
		},
		"different observed receipt is insufficient": {
			mutateFence: func(h *testRemovalMutationHarness) {
				h.current.RemovalMutation.Operation = cloudapi.RemovalMutationVMDelete
				h.current.Address = ""
				h.current.Name = ""
				h.current.BillingAccountID = 0
			},
		},
		"same issue second is accepted at API timestamp precision": {
			mutateFence: func(h *testRemovalMutationHarness) {
				h.current.IssuedAt = reallocatedFIPCreatedAt.Add(500 * time.Millisecond)
			},
			wantAccepted: true,
		},
		"old deterministic name is not a later allocation": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.Name = reallocatedFIPName
			},
		},
		"old VM assignment is not a later allocation": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.AssignedTo = reallocatedFIPOldVM
			},
		},
		"empty allocation UUID fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.UUID = ""
			},
		},
		"malformed allocation UUID fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.UUID = "not-a-uuid"
			},
		},
		"unassigned allocation fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.AssignedTo = ""
				address.AssignedToResourceType = ""
			},
		},
		"allocation created before deletion issue fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = oldFIPDeleteIssuedAt.Add(-time.Second).Format(time.RFC3339Nano)
			},
		},
		"timezone-less allocation created before deletion issue fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = oldFIPDeleteIssuedAt.Add(-time.Second).UTC().Format("2006-01-02 15:04:05")
			},
		},
		"allocation with invalid creation time fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = "not-a-time"
			},
		},
		"allocation with unsupported timezone-less suffix fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = "2026-07-18 10:50:45Z"
			},
		},
		"allocation with unsupported timezone-less fraction fails closed": {
			mutateAddress: func(address *sdk.FloatingIP) {
				address.CreatedAt = "2026-07-18 10:50:45.1"
			},
		},
		"duplicate active address fails closed": {
			mutateAPI: func(api *fakeAPI) {
				duplicate := api.floatingIPs[0]
				duplicate.UUID = "66666666-6666-4666-8666-666666666666"
				api.floatingIPs = append(api.floatingIPs, duplicate)
			},
		},
		"late old name at another address fails closed": {
			mutateAPI: func(api *fakeAPI) {
				old := api.floatingIPs[0]
				old.UUID = "66666666-6666-4666-8666-666666666666"
				old.ID++
				old.Address = "203.0.113.11"
				old.Name = reallocatedFIPName
				api.floatingIPs = append(api.floatingIPs, old)
			},
		},
		"late old VM assignment at another address fails closed": {
			mutateAPI: func(api *fakeAPI) {
				old := api.floatingIPs[0]
				old.UUID = "66666666-6666-4666-8666-666666666666"
				old.ID++
				old.Address = "203.0.113.11"
				old.AssignedTo = reallocatedFIPOldVM
				api.floatingIPs = append(api.floatingIPs, old)
			},
		},
		"exact and list identities disagree": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				listed := exact
				listed.UUID = "66666666-6666-4666-8666-666666666666"
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"exact and list numeric IDs disagree": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				listed := exact
				listed.ID++
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"exact and list user IDs disagree": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				listed := exact
				listed.UserID++
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"exact and list timestamps disagree": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				listed := exact
				listed.UpdatedAt = reallocatedFIPCreatedAt.Add(time.Minute).Format(time.RFC3339Nano)
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"exact and list optional is_virtual presence disagrees": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				listed := reallocatedFloatingIPWithIsVirtual(false)
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"exact and list optional is_virtual values disagree": {
			mutateAPI: func(api *fakeAPI) {
				exact := reallocatedFloatingIPWithIsVirtual(false)
				listed := reallocatedFloatingIPWithIsVirtual(true)
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
		"listed stable identity fields are omitted": {
			mutateAPI: func(api *fakeAPI) {
				exact := api.floatingIPs[0]
				encoded, err := json.Marshal(exact)
				if err != nil {
					panic(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &fields); err != nil {
					panic(err)
				}
				delete(fields, "user_id")
				encoded, err = json.Marshal(fields)
				if err != nil {
					panic(err)
				}
				var listed sdk.FloatingIP
				if err := json.Unmarshal(encoded, &listed); err != nil {
					panic(err)
				}
				api.floatingIPGetSnapshots = map[int]*sdk.FloatingIP{1: &exact}
				api.floatingIPListSnapshots = map[int][]sdk.FloatingIP{1: {listed}}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			address := reallocatedFloatingIP()
			if test.mutateAddress != nil {
				test.mutateAddress(&address)
			}
			api := &fakeAPI{floatingIPs: []sdk.FloatingIP{address}}
			if test.mutateAPI != nil {
				test.mutateAPI(api)
			}
			harness := observedFloatingIPDeleteHarness()
			if test.mutateFence != nil {
				test.mutateFence(harness)
			}
			adapter, err := New(api)
			if err != nil {
				t.Fatal(err)
			}

			accepted, _ := adapter.proveObservedFloatingIPAddressReallocation(
				context.Background(),
				"bkk01",
				reallocatedFIPOldVM,
				reallocatedFIPName,
				reallocatedFIPAddr,
				1,
				reallocationRemovalAuthority(harness),
			)
			if accepted != test.wantAccepted {
				t.Fatalf("reallocation proof accepted=%t, want %t", accepted, test.wantAccepted)
			}
			if len(api.operations) != 0 {
				t.Fatalf("read-only reallocation proof mutated cloud: %v", api.operations)
			}
		})
	}
}

func TestDeleteMissingVMDoesNotTrustReallocatedAddressWithoutObservedReceipt(t *testing.T) {
	const (
		clusterName   = "cluster-a"
		nodeClaimName = "nodeclaim-a"
	)
	oldName := floatingIPName(clusterName, nodeClaimName)
	api := &fakeAPI{
		vms:         []sdk.VM{{UUID: reallocatedFIPNewVM, Name: "foreign-replacement"}},
		floatingIPs: []sdk.FloatingIP{reallocatedFloatingIP()},
		firewalls:   []sdk.Firewall{secureFirewall()},
	}
	adapter, err := New(api)
	if err != nil {
		t.Fatal(err)
	}
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := &testRemovalMutationHarness{}
	identity := cloudapi.DeleteVMIdentity{
		FloatingIPName:   oldName,
		PublicIPv4:       reallocatedFIPAddr,
		BillingAccountID: 1,
		NetworkUUID:      "network-1",
		FirewallUUID:     secureFirewall().UUID,
	}
	harness.attachDelete(&identity)

	err = adapter.DeleteVM(
		context.Background(),
		"bkk01",
		reallocatedFIPOldVM,
		clusterName,
		nodeClaimName,
		identity,
	)
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
		t.Fatalf("DeleteVM() = %v, want fail-closed ownership mismatch", err)
	}
	if len(api.operations) != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("missing observed receipt reached mutation: operations=%v VMs=%#v FIPs=%#v", api.operations, api.vms, api.floatingIPs)
	}
}

func TestFencedCleanupConvergesAcrossObservedFloatingIPAddressReallocation(t *testing.T) {
	api := &fakeAPI{
		vms: []sdk.VM{{
			UUID: reallocatedFIPNewVM,
			Name: "foreign-replacement",
		}},
		floatingIPs: []sdk.FloatingIP{reallocatedFloatingIP()},
		firewalls:   []sdk.Firewall{secureFirewall()},
	}
	adapter, err := New(api)
	if err != nil {
		t.Fatal(err)
	}
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.createAbsenceReadInterval = time.Millisecond

	cleanup := fencedCleanupRequest(true)
	oldName := floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName)
	cleanup.AttemptResolved = true
	cleanup.ObservedVMUUID = reallocatedFIPOldVM
	cleanup.FloatingIPName = oldName
	cleanup.PublicIPv4 = reallocatedFIPAddr
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{{
		VMUUID:         reallocatedFIPOldVM,
		FloatingIPName: oldName,
		PublicIPv4:     reallocatedFIPAddr,
	}}
	harness := observedFloatingIPDeleteHarnessFor(oldName)
	cleanup.AuthorizeRemovalMutation = harness.authorize
	cleanup.ObserveRemovalMutation = harness.observe
	cleanup.RejectRemovalMutation = harness.reject

	deleteCallsBefore := api.deleteVMCalls
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil {
		t.Fatalf("CleanupFencedCreate() = %v", err)
	}
	if result.Resolution != nil || result.DependentsResolved {
		t.Fatalf("CleanupFencedCreate() result = %#v, want terminal empty result", result)
	}
	if api.deleteVMCalls != deleteCallsBefore || len(api.operations) != 0 {
		t.Fatalf("cleanup replayed a mutation after observed deletion: VM deletes=%d operations=%v", api.deleteVMCalls-deleteCallsBefore, api.operations)
	}
	if len(api.vms) != 1 || api.vms[0].UUID != reallocatedFIPNewVM ||
		len(api.floatingIPs) != 1 || api.floatingIPs[0].UUID != reallocatedFloatingIP().UUID {
		t.Fatalf("cleanup changed replacement resources: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
}

func TestFencedCleanupConvergesForMultipleReallocatedHistoricalAddresses(t *testing.T) {
	const (
		secondOldVM = "33333333-3333-4333-8333-333333333333"
		secondNewVM = "44444444-4444-4444-8444-444444444444"
		secondAddr  = "203.0.113.11"
	)
	first := reallocatedFloatingIP()
	second := reallocatedFloatingIP()
	second.UUID = "66666666-6666-4666-8666-666666666666"
	second.ID++
	second.Address = secondAddr
	second.Name = "karpenter-edge-new-2222222222"
	second.AssignedTo = secondNewVM
	second.AssignedToPrivateIP = "10.0.0.44"
	api := &fakeAPI{
		vms: []sdk.VM{
			{UUID: reallocatedFIPNewVM, Name: "foreign-replacement-a"},
			{UUID: secondNewVM, Name: "foreign-replacement-b"},
		},
		floatingIPs: []sdk.FloatingIP{first, second},
		firewalls:   []sdk.Firewall{secureFirewall()},
	}
	adapter, err := New(api)
	if err != nil {
		t.Fatal(err)
	}
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.createAbsenceReadInterval = time.Millisecond

	cleanup := fencedCleanupRequest(true)
	oldName := floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName)
	cleanup.AttemptResolved = true
	cleanup.ObservedVMUUID = reallocatedFIPOldVM
	cleanup.FloatingIPName = oldName
	cleanup.PublicIPv4 = reallocatedFIPAddr
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{
		{VMUUID: reallocatedFIPOldVM, FloatingIPName: oldName, PublicIPv4: reallocatedFIPAddr},
		{VMUUID: secondOldVM, FloatingIPName: oldName, PublicIPv4: secondAddr},
	}
	receipts := make(map[cloudapi.RemovalMutation]cloudapi.RemovalMutationFence, len(cleanup.Resolutions))
	for index, resolution := range cleanup.Resolutions {
		mutation := cloudapi.RemovalMutation{
			Operation:        cloudapi.RemovalMutationFloatingIPDelete,
			Location:         cleanup.Location,
			VMUUID:           resolution.VMUUID,
			Address:          resolution.PublicIPv4,
			Name:             resolution.FloatingIPName,
			BillingAccountID: cleanup.BillingAccountID,
		}
		receipts[mutation] = cloudapi.RemovalMutationFence{
			RemovalMutation: mutation,
			Phase:           cloudapi.RemovalMutationObserved,
			IssueID:         fmt.Sprintf("%032x", index+1),
			IssuedAt:        oldFIPDeleteIssuedAt,
			ObservedAt:      oldFIPDeleteObservedAt,
		}
	}
	cleanup.AuthorizeRemovalMutation = func(_ context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
		receipt, found := receipts[mutation]
		if !found {
			if present {
				return cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("unexpected present mutation %#v", mutation)
			}
			return cloudapi.RemovalMutationAuthorization{}, nil
		}
		if present {
			return cloudapi.RemovalMutationAuthorization{}, errors.New("observed removal resource reappeared")
		}
		return cloudapi.RemovalMutationAuthorization{Fence: receipt, Active: true}, nil
	}
	cleanup.ObserveRemovalMutation = func(context.Context, cloudapi.RemovalMutationFence) error { return nil }
	cleanup.RejectRemovalMutation = func(context.Context, cloudapi.RemovalMutationFence) error { return nil }

	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil {
		t.Fatalf("CleanupFencedCreate() = %v", err)
	}
	if result.Resolution != nil || result.DependentsResolved || len(api.operations) != 0 {
		t.Fatalf("multi-resolution cleanup result=%#v operations=%v", result, api.operations)
	}
	if len(api.vms) != 2 || len(api.floatingIPs) != 2 {
		t.Fatalf("multi-resolution cleanup changed replacements: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
}
