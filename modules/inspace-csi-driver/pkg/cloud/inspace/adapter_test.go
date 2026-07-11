package inspace

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/cloud"
)

const (
	testLocation = "bkk01"
	testDiskID   = "11111111-1111-4111-8111-111111111111"
	testVM1      = "22222222-2222-4222-8222-222222222222"
	testVM2      = "33333333-3333-4333-8333-333333333333"
)

type fakeAPI struct {
	disks                 []sdk.Disk
	vms                   []sdk.VM
	lastCreate            sdk.CreateDiskRequest
	createCommittedError  error
	listError             error
	deleteCalls           int
	attachCalls           int
	detachCalls           int
	attachVisibilityDelay int
	detachVisibilityDelay int
	pendingAttachVM       string
	pendingAttachDisk     string
	pendingDetachVM       string
	pendingDetachDisk     string
}

func (f *fakeAPI) CreateDisk(_ context.Context, _ string, req sdk.CreateDiskRequest) (*sdk.Disk, error) {
	f.lastCreate = req
	disk := sdk.Disk{UUID: testDiskID, DisplayName: req.DisplayName, SizeGiB: req.SizeGiB, Status: "Active"}
	f.disks = append(f.disks, disk)
	return &disk, f.createCommittedError
}

func (f *fakeAPI) GetDisk(_ context.Context, _ string, id string) (*sdk.Disk, error) {
	for i := range f.disks {
		if f.disks[i].UUID == id {
			copy := f.disks[i]
			return &copy, nil
		}
	}
	return nil, apiNotFound("disk")
}

func (f *fakeAPI) ListDisks(context.Context, string) ([]sdk.Disk, error) {
	return append([]sdk.Disk(nil), f.disks...), f.listError
}

func (f *fakeAPI) DeleteDisk(_ context.Context, _ string, id string) error {
	for i := range f.disks {
		if f.disks[i].UUID == id {
			f.disks = append(f.disks[:i], f.disks[i+1:]...)
			f.deleteCalls++
			return nil
		}
	}
	return apiNotFound("disk")
}

func (f *fakeAPI) ListVMs(context.Context, string) ([]sdk.VM, error) {
	if f.pendingAttachVM != "" {
		if f.attachVisibilityDelay > 0 {
			f.attachVisibilityDelay--
		} else {
			f.addStorage(f.pendingAttachVM, f.pendingAttachDisk)
			f.pendingAttachVM, f.pendingAttachDisk = "", ""
		}
	}
	if f.pendingDetachVM != "" {
		if f.detachVisibilityDelay > 0 {
			f.detachVisibilityDelay--
		} else {
			f.removeStorage(f.pendingDetachVM, f.pendingDetachDisk)
			f.pendingDetachVM, f.pendingDetachDisk = "", ""
		}
	}
	return append([]sdk.VM(nil), f.vms...), nil
}

func (f *fakeAPI) GetVM(_ context.Context, _ string, id string) (*sdk.VM, error) {
	for i := range f.vms {
		if f.vms[i].UUID == id {
			copy := f.vms[i]
			return &copy, nil
		}
	}
	return nil, apiNotFound("VM")
}

func (f *fakeAPI) AttachDisk(_ context.Context, _ string, vmID, diskID string) (*sdk.VMStorage, error) {
	for i := range f.vms {
		if f.vms[i].UUID == vmID {
			storage := sdk.VMStorage{UUID: diskID, SizeGiB: 2}
			if f.attachVisibilityDelay > 0 {
				f.pendingAttachVM, f.pendingAttachDisk = vmID, diskID
			} else {
				f.vms[i].Storage = append(f.vms[i].Storage, storage)
			}
			f.attachCalls++
			return &storage, nil
		}
	}
	return nil, apiNotFound("VM")
}

func (f *fakeAPI) DetachDisk(_ context.Context, _ string, vmID, diskID string) error {
	for i := range f.vms {
		if f.vms[i].UUID != vmID {
			continue
		}
		for j := range f.vms[i].Storage {
			if f.vms[i].Storage[j].UUID == diskID {
				if f.detachVisibilityDelay > 0 {
					f.pendingDetachVM, f.pendingDetachDisk = vmID, diskID
				} else {
					f.vms[i].Storage = append(f.vms[i].Storage[:j], f.vms[i].Storage[j+1:]...)
				}
				f.detachCalls++
				return nil
			}
		}
		return nil
	}
	return apiNotFound("VM")
}

func (f *fakeAPI) addStorage(vmID, diskID string) {
	for i := range f.vms {
		if f.vms[i].UUID == vmID {
			f.vms[i].Storage = append(f.vms[i].Storage, sdk.VMStorage{UUID: diskID, SizeGiB: 2})
			return
		}
	}
}

func (f *fakeAPI) removeStorage(vmID, diskID string) {
	for i := range f.vms {
		if f.vms[i].UUID != vmID {
			continue
		}
		for j := range f.vms[i].Storage {
			if f.vms[i].Storage[j].UUID == diskID {
				f.vms[i].Storage = append(f.vms[i].Storage[:j], f.vms[i].Storage[j+1:]...)
				return
			}
		}
	}
}

type nodeResolver map[string]string

func (r nodeResolver) ProviderIDForNode(_ context.Context, name string) (string, error) {
	value, ok := r[name]
	if !ok {
		return "", errors.New("node not found")
	}
	return value, nil
}

func newAdapter(t *testing.T, api *fakeAPI, resolver NodeResolver) *Adapter {
	t.Helper()
	adapter, err := New(api, resolver, Config{Location: testLocation, BillingAccountID: 42})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestEnsureVolumeRoundsGiBAndReconcilesByName(t *testing.T) {
	api := &fakeAPI{}
	adapter := newAdapter(t, api, nil)
	spec := cloud.VolumeSpec{Name: "pvc-a", Location: testLocation, CapacityBytes: gib + 1}
	first, err := adapter.EnsureVolume(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.EnsureVolume(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || len(api.disks) != 1 {
		t.Fatalf("idempotent ensure returned %#v then %#v with %d disks", first, second, len(api.disks))
	}
	if api.lastCreate.SizeGiB != 2 || api.lastCreate.BillingAccountID != 42 || first.CapacityBytes != 2*gib {
		t.Fatalf("create request=%#v, volume=%#v", api.lastCreate, first)
	}
}

func TestEnsureVolumeReconcilesAmbiguousCreate(t *testing.T) {
	api := &fakeAPI{createCommittedError: context.DeadlineExceeded}
	adapter := newAdapter(t, api, nil)
	volume, err := adapter.EnsureVolume(context.Background(), cloud.VolumeSpec{
		Name: "pvc-timeout", Location: testLocation, CapacityBytes: gib,
	})
	if err != nil || volume.ID != testDiskID || len(api.disks) != 1 {
		t.Fatalf("volume=%#v err=%v disks=%d", volume, err, len(api.disks))
	}
}

func TestDeleteRefusesSnapshotsAndAttachedDisks(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Snapshots: []sdk.DiskSnapshot{{UUID: "snapshot"}}}},
		vms:   []sdk.VM{{UUID: testVM1}},
	}
	adapter := newAdapter(t, api, nil)
	if err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrSnapshotsPresent) {
		t.Fatalf("snapshot delete error=%v", err)
	}
	api.disks[0].Snapshots = nil
	api.vms[0].Storage = []sdk.VMStorage{{UUID: testDiskID}}
	if err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
		t.Fatalf("attached delete error=%v", err)
	}
	if api.deleteCalls != 0 {
		t.Fatalf("DeleteDisk called %d times", api.deleteCalls)
	}
}

func TestAttachAndDetachResolveStableProviderIDs(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1}},
		vms:   []sdk.VM{{UUID: testVM1}, {UUID: testVM2}},
	}
	resolver := nodeResolver{
		"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		"worker-2": fmt.Sprintf("inspace://%s/%s", testLocation, testVM2),
	}
	adapter := newAdapter(t, api, resolver)
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if api.attachCalls != 1 {
		t.Fatalf("AttachDisk called %d times", api.attachCalls)
	}
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-2"); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
		t.Fatalf("second-node attach error=%v", err)
	}
	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-2"); err != nil {
		t.Fatal(err)
	}
	if api.detachCalls != 0 {
		t.Fatalf("wrong-node detach called API %d times", api.detachCalls)
	}
	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if api.detachCalls != 1 {
		t.Fatalf("correct detach called API %d times", api.detachCalls)
	}
}

func TestAttachAndDetachWaitForStorageStateConvergence(t *testing.T) {
	api := &fakeAPI{
		disks:                 []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1}},
		vms:                   []sdk.VM{{UUID: testVM1}},
		attachVisibilityDelay: 2,
	}
	adapter, err := New(api, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)}, Config{
		Location: testLocation, BillingAccountID: 42, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := adapter.AttachVolume(ctx, testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	api.detachVisibilityDelay = 2
	if err := adapter.DetachVolume(ctx, testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if api.attachCalls != 1 || api.detachCalls != 1 {
		t.Fatalf("attach calls=%d detach calls=%d", api.attachCalls, api.detachCalls)
	}
}

func TestProviderIDLocationAndKubernetesErrors(t *testing.T) {
	api := &fakeAPI{disks: []sdk.Disk{{UUID: testDiskID, SizeGiB: 1}}, vms: []sdk.VM{{UUID: testVM1}}}
	adapter := newAdapter(t, api, nodeResolver{})
	for _, nodeID := range []string{
		"inspace://sin01/" + testVM1,
		"not-a-node",
		"inspace://bkk01/not-a-uuid",
		testVM1,
	} {
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, nodeID); !errors.Is(err, cloud.ErrInvalidNode) {
			t.Errorf("node %q error=%v", nodeID, err)
		}
	}
}

func TestNodeNameNeverFallsBackToAccountVMHostname(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, SizeGiB: 1}},
		vms:   []sdk.VM{{UUID: testVM1, Hostname: "worker-stale"}},
	}
	adapter := newAdapter(t, api, nodeResolver{})
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-stale"); !errors.Is(err, cloud.ErrInvalidNode) {
		t.Fatalf("AttachVolume error=%v, want ErrInvalidNode", err)
	}
	if api.attachCalls != 0 {
		t.Fatalf("AttachDisk called %d times", api.attachCalls)
	}
}

func TestProbeMapsRetryableAPIError(t *testing.T) {
	api := &fakeAPI{listError: &sdk.APIError{StatusCode: 503, Retryable: true}}
	adapter := newAdapter(t, api, nil)
	if err := adapter.Probe(context.Background()); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("Probe error=%v", err)
	}
}

func apiNotFound(resource string) error {
	return &sdk.APIError{StatusCode: 404, Method: "GET", Path: resource, Message: "not found"}
}

var _ API = (*fakeAPI)(nil)
