package inspace

import (
	"context"
	"errors"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

func attachedExpansionFixture(sizeGiB int) *fakeAPI {
	return &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: sizeGiB, Status: "Active"}},
		vms: []sdk.VM{
			{UUID: testVM1, Storage: []sdk.VMStorage{{UUID: testDiskID, SizeGiB: sizeGiB}}},
			{UUID: testVM2, Storage: []sdk.VMStorage{}},
		},
	}
}

func TestExpandVolumeResizesAttachedDiskToRoundedGiB(t *testing.T) {
	api := attachedExpansionFixture(1)
	adapter := newAdapter(t, api, nil)

	capacity, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib+1)
	if err != nil {
		t.Fatal(err)
	}
	if capacity != 3*gib {
		t.Fatalf("capacity = %d, want %d", capacity, 3*gib)
	}
	if api.resizeCalls != 1 || api.lastResizeVM != testVM1 || api.lastResizeGiB != 3 {
		t.Fatalf("resize calls=%d vm=%q size=%d, want one 3 GiB resize on %s",
			api.resizeCalls, api.lastResizeVM, api.lastResizeGiB, testVM1)
	}
}

func TestExpandVolumeIsNoOpWhenDiskIsAlreadyLargeEnough(t *testing.T) {
	api := attachedExpansionFixture(5)
	api.vms[0].Storage = []sdk.VMStorage{}
	adapter := newAdapter(t, api, nil)

	capacity, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 3*gib)
	if err != nil {
		t.Fatal(err)
	}
	if capacity != 5*gib {
		t.Fatalf("capacity = %d, want current %d", capacity, 5*gib)
	}
	if api.resizeCalls != 0 {
		t.Fatalf("already-large disk issued %d resize call(s)", api.resizeCalls)
	}
}

func TestExpandVolumeRequiresAttachedDisk(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.vms[0].Storage = []sdk.VMStorage{}
	adapter := newAdapter(t, api, nil)

	_, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if !errors.Is(err, cloud.ErrVolumeNotAttached) {
		t.Fatalf("detached expand error = %v, want ErrVolumeNotAttached", err)
	}
	if api.resizeCalls != 0 {
		t.Fatalf("detached disk issued %d resize call(s)", api.resizeCalls)
	}
}

func TestExpandVolumeRefusesUnownedDiskBeforeResize(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.disks[0].BillingAccountID = 7
	adapter := newAdapter(t, api, nil)

	_, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if !errors.Is(err, cloud.ErrPermissionDenied) {
		t.Fatalf("unowned expand error = %v, want ErrPermissionDenied", err)
	}
	if api.resizeCalls != 0 {
		t.Fatalf("unowned disk issued %d resize call(s)", api.resizeCalls)
	}
}

func TestExpandVolumeRefusesPrimaryBootDisk(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.vms[0].Storage[0].Primary = true
	adapter := newAdapter(t, api, nil)

	_, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if !errors.Is(err, cloud.ErrPermissionDenied) {
		t.Fatalf("boot disk expand error = %v, want ErrPermissionDenied", err)
	}
	if api.resizeCalls != 0 {
		t.Fatalf("boot disk issued %d resize call(s)", api.resizeCalls)
	}
}

func TestExpandVolumeAcceptsCommittedResizeAfterAmbiguousResponse(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.resizeMutationError = &sdk.APIError{StatusCode: 504, Retryable: true, Message: "gateway timeout"}
	adapter := newAdapter(t, api, nil)

	capacity, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if err != nil {
		t.Fatalf("committed resize after ambiguous response failed: %v", err)
	}
	if capacity != 2*gib {
		t.Fatalf("capacity = %d, want %d", capacity, 2*gib)
	}
}

func TestExpandVolumeRetriesUncommittedResizeWithSameAbsoluteSize(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.suppressResizeCommit = true
	api.resizeMutationError = &sdk.APIError{StatusCode: 503, Retryable: true, Message: "unavailable"}
	adapter := newAdapter(t, api, nil)

	if _, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("uncommitted resize error = %v, want retryable ErrUnavailable", err)
	}
	api.suppressResizeCommit = false
	api.resizeMutationError = nil
	capacity, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if err != nil {
		t.Fatal(err)
	}
	if capacity != 2*gib || api.resizeCalls != 2 || api.lastResizeGiB != 2 {
		t.Fatalf("retry capacity=%d calls=%d size=%d, want 2 GiB after two absolute resizes",
			capacity, api.resizeCalls, api.lastResizeGiB)
	}
}

func TestExpandVolumeRejectsNonPositiveCapacity(t *testing.T) {
	api := attachedExpansionFixture(1)
	adapter := newAdapter(t, api, nil)

	if _, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 0); err == nil {
		t.Fatal("zero-byte expansion was accepted")
	}
	if api.resizeCalls != 0 {
		t.Fatalf("invalid capacity issued %d resize call(s)", api.resizeCalls)
	}
}
