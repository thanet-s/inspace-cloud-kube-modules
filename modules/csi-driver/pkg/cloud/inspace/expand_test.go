package inspace

import (
	"context"
	"errors"
	"strings"
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

// A complete, non-retryable rejection is final for this request: return its
// cause after one confirming read instead of polling out the readback window
// and reporting a transient outage the resizer would retry forever.
func TestExpandVolumeReturnsDefinitiveRejectionWithoutReadbackWait(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{name: "quota", status: 422, want: cloud.ErrRejected},
		{name: "bad request", status: 400, want: cloud.ErrRejected},
		{name: "unauthenticated", status: 401, want: cloud.ErrUnauthenticated},
		{name: "forbidden", status: 403, want: cloud.ErrPermissionDenied},
		{name: "conflict", status: 409, want: cloud.ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := attachedExpansionFixture(1)
			api.suppressResizeCommit = true
			api.resizeMutationError = &sdk.APIError{StatusCode: tc.status, Message: "disk size exceeds account quota"}
			adapter := newAdapter(t, api, nil)
			getsBefore := api.exactDiskReads

			_, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
			if !errors.Is(err, tc.want) || errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("rejected resize error = %v, want %v and not ErrUnavailable", err, tc.want)
			}
			if !strings.Contains(err.Error(), "disk size exceeds account quota") {
				t.Fatalf("rejected resize error %q lost the InSpace cause", err)
			}
			// Two exact reads precede the PATCH; the rejection adds one.
			if reads := api.exactDiskReads - getsBefore; reads != 3 {
				t.Fatalf("rejected resize read the disk %d times, want 3 (no readback polling)", reads)
			}
		})
	}
}

func TestExpandVolumeAcceptsRejectionThatRaceCommitted(t *testing.T) {
	api := attachedExpansionFixture(1)
	api.resizeMutationError = &sdk.APIError{StatusCode: 409, Message: "resize already in progress"}
	adapter := newAdapter(t, api, nil)

	capacity, err := adapter.ExpandVolume(context.Background(), testLocation, testDiskID, 2*gib)
	if err != nil {
		t.Fatalf("committed resize behind a 409 failed: %v", err)
	}
	if capacity != 2*gib {
		t.Fatalf("capacity = %d, want %d", capacity, 2*gib)
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
