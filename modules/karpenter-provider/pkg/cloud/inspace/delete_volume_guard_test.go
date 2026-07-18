package inspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestValidateVMDeleteVolumeSafety(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	primary := sdk.VMStorage{
		UUID:    "22222222-2222-4222-8222-222222222222",
		Name:    "root",
		SizeGiB: 100,
		Primary: true,
	}
	additionalA := sdk.VMStorage{
		UUID:    "33333333-3333-4333-8333-333333333333",
		Name:    "data-a",
		SizeGiB: 20,
	}
	additionalB := sdk.VMStorage{
		UUID:    "44444444-4444-4444-8444-444444444444",
		Name:    "data-b",
		SizeGiB: 40,
	}

	tests := []struct {
		name       string
		storage    []sdk.VMStorage
		want       error
		wantDetail string
	}{
		{
			name:    "one primary root disk",
			storage: []sdk.VMStorage{primary},
		},
		{
			name:       "one attached non-primary volume",
			storage:    []sdk.VMStorage{primary, additionalA},
			want:       cloudapi.ErrAttachedNonPrimaryVolumes,
			wantDetail: "reports 1 attached non-primary block volume(s)",
		},
		{
			name:       "many attached non-primary volumes",
			storage:    []sdk.VMStorage{primary, additionalA, additionalB},
			want:       cloudapi.ErrAttachedNonPrimaryVolumes,
			wantDetail: "reports 2 attached non-primary block volume(s)",
		},
		{
			name:       "non-primary volume with sparse identity",
			storage:    []sdk.VMStorage{primary, {SizeGiB: 20}},
			want:       cloudapi.ErrAttachedNonPrimaryVolumes,
			wantDetail: "reports 1 attached non-primary block volume(s)",
		},
		{
			name:       "omitted storage inventory",
			want:       cloudapi.ErrVMStorageInventoryUncertain,
			wantDetail: "reports 0 storage entries and 0 primary root disks",
		},
		{
			name:       "no primary root disk",
			storage:    []sdk.VMStorage{},
			want:       cloudapi.ErrVMStorageInventoryUncertain,
			wantDetail: "reports 0 storage entries and 0 primary root disks",
		},
		{
			name:       "multiple primary root disks",
			storage:    []sdk.VMStorage{primary, primary},
			want:       cloudapi.ErrVMStorageInventoryUncertain,
			wantDetail: "reports 2 storage entries and 2 primary root disks",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateVMDeleteVolumeSafety(sdk.VM{UUID: vmUUID, Storage: test.storage})
			if test.want == nil {
				if err != nil {
					t.Fatalf("validateVMDeleteVolumeSafety() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), test.wantDetail) {
				t.Fatalf("validateVMDeleteVolumeSafety() error = %v, want %v containing %q", err, test.want, test.wantDetail)
			}
		})
	}
}

func TestDeleteVMBlocksEveryAttachedNonPrimaryVolumeBeforeMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Storage = append(api.vms[0].Storage,
		sdk.VMStorage{UUID: "33333333-3333-4333-8333-333333333333", Name: "data-a", SizeGiB: 20},
		sdk.VMStorage{UUID: "44444444-4444-4444-8444-444444444444", Name: "data-b", SizeGiB: 40},
	)
	api.operations = nil
	api.deleteVMCalls = 0
	authorizeCalls := 0
	identity := durableDeleteIdentity(created)
	identity.AuthorizeRemovalMutation = func(context.Context, cloudapi.RemovalMutation, bool) (cloudapi.RemovalMutationAuthorization, error) {
		authorizeCalls++
		return cloudapi.RemovalMutationAuthorization{}, nil
	}
	identity.ObserveRemovalMutation = func(context.Context, cloudapi.RemovalMutationFence) error { return nil }
	identity.RejectRemovalMutation = func(context.Context, cloudapi.RemovalMutationFence) error { return nil }

	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if !errors.Is(err, cloudapi.ErrAttachedNonPrimaryVolumes) || !strings.Contains(err.Error(), "reports 2 attached non-primary block volume(s)") {
		t.Fatalf("DeleteVM() error = %v, want attached-volume guard", err)
	}
	if authorizeCalls != 0 {
		t.Fatalf("attached-volume guard authorized %d removal mutations, want zero", authorizeCalls)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 ||
		!firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("attached-volume guard mutated cloud state: deletes=%d operations=%v VMs=%#v FIPs=%#v firewall=%#v",
			api.deleteVMCalls, api.operations, api.vms, api.floatingIPs, api.firewalls[0])
	}
}

func TestDeleteVMFailsClosedWhenStorageInventoryIsOmitted(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Storage = nil
	api.operations = nil
	api.deleteVMCalls = 0

	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, durableDeleteIdentity(created))
	if err == nil || (!errors.Is(err, cloudapi.ErrVMStorageInventoryUncertain) && !errors.Is(err, cloudapi.ErrOwnershipMismatch)) {
		t.Fatalf("DeleteVM() error = %v, want fail-closed storage inventory rejection", err)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 ||
		!firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("uncertain storage inventory mutated cloud state: deletes=%d operations=%v VMs=%#v FIPs=%#v firewall=%#v",
			api.deleteVMCalls, api.operations, api.vms, api.floatingIPs, api.firewalls[0])
	}
}

func TestDeleteVMContinuesAfterEveryNonPrimaryVolumeDetaches(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Storage = append(api.vms[0].Storage,
		sdk.VMStorage{UUID: "33333333-3333-4333-8333-333333333333", Name: "data-a", SizeGiB: 20},
		sdk.VMStorage{UUID: "44444444-4444-4444-8444-444444444444", Name: "data-b", SizeGiB: 40},
	)
	api.operations = nil

	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, cloudapi.DeleteVMIdentity{})
	if !errors.Is(err, cloudapi.ErrAttachedNonPrimaryVolumes) {
		t.Fatalf("first DeleteVM() error = %v, want attached-volume guard", err)
	}
	api.vms[0].Storage = api.vms[0].Storage[:1]

	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, cloudapi.DeleteVMIdentity{}); err != nil {
		t.Fatalf("DeleteVM() after detachment error = %v", err)
	}
	if api.deleteVMCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("delete after detachment did not converge: deletes=%d VMs=%#v FIPs=%#v firewall=%#v operations=%v",
			api.deleteVMCalls, api.vms, api.floatingIPs, api.firewalls[0], api.operations)
	}
}

func TestLaunchRollbackPreservesVMAndDependentsWhileNonPrimaryVolumeIsAttached(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Storage = append(api.vms[0].Storage, sdk.VMStorage{
		UUID:    "33333333-3333-4333-8333-333333333333",
		Name:    "data",
		SizeGiB: 20,
	})
	anchor := api.floatingIPs[0]
	api.operations = nil
	api.deleteVMCalls = 0

	err = adapter.cleanupLaunch(
		context.Background(),
		created.Location,
		testRequest().NetworkUUID,
		testRequest().FirewallUUID,
		created.UUID,
		testRequest().BillingAccountID,
		anchor,
		errors.New("launch failed"),
		baseFirewallDetachmentAuthority{},
		removalMutationAuthority{},
		nil,
	)
	if !errors.Is(err, cloudapi.ErrAttachedNonPrimaryVolumes) {
		t.Fatalf("cleanupLaunch() error = %v, want attached-volume guard", err)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 ||
		!firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("guarded rollback mutated cloud state: deletes=%d operations=%v VMs=%#v FIPs=%#v firewall=%#v",
			api.deleteVMCalls, api.operations, api.vms, api.floatingIPs, api.firewalls[0])
	}
}
