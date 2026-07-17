package inspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	testLocation = "bkk01"
	testDiskID   = "11111111-1111-4111-8111-111111111111"
	testVM1      = "22222222-2222-4222-8222-222222222222"
	testVM2      = "33333333-3333-4333-8333-333333333333"
	testNetwork  = "44444444-4444-4444-8444-444444444444"
)

type fakeAPI struct {
	disks                  []sdk.Disk
	vms                    []sdk.VM
	lastCreate             sdk.CreateDiskRequest
	createCommittedError   error
	createCalls            int
	suppressCreateCommit   bool
	hideCreateResponse     bool
	createResponseUUID     string
	blockCreatedVisibility bool
	pendingCreatedDisk     *sdk.Disk
	listError              error
	listCalls              int
	diskAppearsOnListCall  int
	appearingDisks         []sdk.Disk
	readbackError          error
	deleteCalls            int
	deleteMutationError    error
	suppressDeleteCommit   bool
	deleteVisibilityDelay  int
	pendingDeleteDisk      string
	attachCalls            int
	detachCalls            int
	attachVisibilityDelay  int
	detachVisibilityDelay  int
	pendingAttachVM        string
	pendingAttachDisk      string
	pendingDetachVM        string
	pendingDetachDisk      string
	attachMutationError    error
	detachMutationError    error
	suppressAttachCommit   bool
	suppressDetachCommit   bool
	preserveDiskBilling    bool
	preserveVMBilling      bool
	preserveVMNetwork      bool
	networkVMUUIDs         []string
	omitNetworkMembership  bool
	networkError           error
}

// detailSequenceAPI can replace a specific canonical detail read while all
// other behavior comes from fakeAPI. It models ownership fields changing or
// being omitted between discovery and the final pre-mutation read.
type detailSequenceAPI struct {
	*fakeAPI
	diskGets         int
	vmGets           int
	diskOverride     map[int]sdk.Disk
	vmOverride       map[int]sdk.VM
	stripListStorage bool
	forceListStorage bool
}

// staleAttachmentListAPI keeps VM identities visible but strips list-side
// storage. Canonical GetVM remains authoritative and models the InSpace list
// endpoint lagging detail after attach/detach state changes.
type staleAttachmentListAPI struct {
	*fakeAPI
	omitVMs bool
}

type transientDiskOmissionAPI struct {
	*fakeAPI
	hiddenRounds int
	round        int
}

// deletedDiskTombstoneAPI models the live InSpace delete contract: after the
// DELETE commits, ListDisks omits the disk while exact GetDisk keeps returning
// its canonical identity and billing account with status Deleted.
type deletedDiskTombstoneAPI struct {
	*fakeAPI
	tombstone *sdk.Disk
}

func (a *deletedDiskTombstoneAPI) GetDisk(ctx context.Context, location, id string) (*sdk.Disk, error) {
	if a.tombstone != nil {
		copy := *a.tombstone
		return &copy, nil
	}
	return a.fakeAPI.GetDisk(ctx, location, id)
}

func (a *deletedDiskTombstoneAPI) DeleteDisk(ctx context.Context, location, id string) error {
	var deleted sdk.Disk
	for _, disk := range a.disks {
		if strings.EqualFold(disk.UUID, id) {
			deleted = disk
			break
		}
	}
	before := a.deleteCalls
	err := a.fakeAPI.DeleteDisk(ctx, location, id)
	if a.deleteCalls == before+1 && !a.suppressDeleteCommit && a.pendingDeleteDisk == "" {
		deleted.Status = "Deleted"
		a.tombstone = &deleted
	}
	return err
}

func (a *transientDiskOmissionAPI) GetDisk(ctx context.Context, location, id string) (*sdk.Disk, error) {
	if a.round < a.hiddenRounds {
		return nil, apiNotFound("disk")
	}
	return a.fakeAPI.GetDisk(ctx, location, id)
}

func (a *transientDiskOmissionAPI) ListDisks(ctx context.Context, location string) ([]sdk.Disk, error) {
	if a.round < a.hiddenRounds {
		a.round++
		return []sdk.Disk{}, nil
	}
	return a.fakeAPI.ListDisks(ctx, location)
}

func (a *staleAttachmentListAPI) ListVMs(ctx context.Context, location string) ([]sdk.VM, error) {
	vms, err := a.fakeAPI.ListVMs(ctx, location)
	if a.omitVMs {
		return []sdk.VM{}, err
	}
	for i := range vms {
		vms[i].Storage = nil
	}
	return vms, err
}

func (a *detailSequenceAPI) GetDisk(ctx context.Context, location, id string) (*sdk.Disk, error) {
	a.diskGets++
	if disk, ok := a.diskOverride[a.diskGets]; ok {
		copy := disk
		return &copy, nil
	}
	return a.fakeAPI.GetDisk(ctx, location, id)
}

func (a *detailSequenceAPI) GetVM(ctx context.Context, location, id string) (*sdk.VM, error) {
	a.vmGets++
	if vm, ok := a.vmOverride[a.vmGets]; ok {
		copy := vm
		return &copy, nil
	}
	return a.fakeAPI.GetVM(ctx, location, id)
}

func (a *detailSequenceAPI) ListVMs(ctx context.Context, location string) ([]sdk.VM, error) {
	vms, err := a.fakeAPI.ListVMs(ctx, location)
	if a.stripListStorage {
		for i := range vms {
			vms[i].Storage = nil
		}
	}
	if a.forceListStorage {
		for i := range vms {
			vms[i].Storage = []sdk.VMStorage{{UUID: testDiskID}}
		}
	}
	return vms, err
}

func (f *fakeAPI) CreateDisk(_ context.Context, _ string, req sdk.CreateDiskRequest) (*sdk.Disk, error) {
	f.lastCreate = req
	f.createCalls++
	disk := sdk.Disk{
		UUID: testDiskID, DisplayName: req.DisplayName, SizeGiB: req.SizeGiB,
		Status: "Active", BillingAccountID: req.BillingAccountID, SourceImageType: req.SourceImageType,
	}
	if f.suppressCreateCommit {
		return nil, f.createCommittedError
	}
	if f.blockCreatedVisibility {
		copy := disk
		f.pendingCreatedDisk = &copy
	} else {
		f.disks = append(f.disks, disk)
	}
	if f.hideCreateResponse {
		return nil, f.createCommittedError
	}
	response := disk
	if f.createResponseUUID != "" {
		response.UUID = f.createResponseUUID
	}
	return &response, f.createCommittedError
}

func (f *fakeAPI) GetDisk(_ context.Context, _ string, id string) (*sdk.Disk, error) {
	if f.mutationCalls() != 0 && f.readbackError != nil {
		return nil, f.readbackError
	}
	f.revealCreatedDisk()
	f.advancePendingDelete()
	for i := range f.disks {
		if f.disks[i].UUID == id {
			copy := f.disks[i]
			if copy.BillingAccountID == 0 && !f.preserveDiskBilling {
				copy.BillingAccountID = 42
			}
			return &copy, nil
		}
	}
	return nil, apiNotFound("disk")
}

func (f *fakeAPI) ListDisks(context.Context, string) ([]sdk.Disk, error) {
	f.listCalls++
	if f.diskAppearsOnListCall > 0 && f.listCalls == f.diskAppearsOnListCall {
		f.disks = append(f.disks, f.appearingDisks...)
	}
	if f.mutationCalls() != 0 && f.readbackError != nil {
		return nil, f.readbackError
	}
	f.revealCreatedDisk()
	f.advancePendingDelete()
	result := append([]sdk.Disk(nil), f.disks...)
	for i := range result {
		if result[i].BillingAccountID == 0 && !f.preserveDiskBilling {
			result[i].BillingAccountID = 42
		}
	}
	return result, f.listError
}

func (f *fakeAPI) DeleteDisk(_ context.Context, _ string, id string) error {
	for i := range f.disks {
		if f.disks[i].UUID == id {
			f.deleteCalls++
			if !f.suppressDeleteCommit {
				if f.deleteVisibilityDelay > 0 {
					f.pendingDeleteDisk = id
				} else {
					f.disks = append(f.disks[:i], f.disks[i+1:]...)
				}
			}
			return f.deleteMutationError
		}
	}
	return apiNotFound("disk")
}

func (f *fakeAPI) ListVMs(context.Context, string) ([]sdk.VM, error) {
	if f.mutationCalls() != 0 && f.readbackError != nil {
		return nil, f.readbackError
	}
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
	result := append([]sdk.VM(nil), f.vms...)
	for i := range result {
		if result[i].BillingAccountID == 0 && !f.preserveVMBilling {
			result[i].BillingAccountID = 42
		}
		if result[i].NetworkUUID == "" && !f.preserveVMNetwork {
			result[i].NetworkUUID = testNetwork
		}
	}
	return result, nil
}

func (f *fakeAPI) mutationCalls() int {
	return f.createCalls + f.deleteCalls + f.attachCalls + f.detachCalls
}

func (f *fakeAPI) GetVM(_ context.Context, _ string, id string) (*sdk.VM, error) {
	for i := range f.vms {
		if f.vms[i].UUID == id {
			copy := f.vms[i]
			if copy.BillingAccountID == 0 && !f.preserveVMBilling {
				copy.BillingAccountID = 42
			}
			if copy.NetworkUUID == "" && !f.preserveVMNetwork {
				copy.NetworkUUID = testNetwork
			}
			return &copy, nil
		}
	}
	return nil, apiNotFound("VM")
}

func (f *fakeAPI) GetNetwork(_ context.Context, _ string, id string) (*sdk.Network, error) {
	if f.networkError != nil {
		return nil, f.networkError
	}
	var members []string
	switch {
	case f.omitNetworkMembership:
		members = nil
	case f.networkVMUUIDs != nil:
		members = append([]string(nil), f.networkVMUUIDs...)
	default:
		members = make([]string, 0, len(f.vms))
		for _, vm := range f.vms {
			members = append(members, vm.UUID)
		}
	}
	return &sdk.Network{UUID: id, VMUUIDs: members}, nil
}

func (f *fakeAPI) AttachDisk(_ context.Context, _ string, vmID, diskID string) (*sdk.VMStorage, error) {
	for i := range f.vms {
		if f.vms[i].UUID == vmID {
			storage := sdk.VMStorage{UUID: diskID, SizeGiB: 2}
			if !f.suppressAttachCommit {
				if f.attachVisibilityDelay > 0 {
					f.pendingAttachVM, f.pendingAttachDisk = vmID, diskID
				} else {
					f.vms[i].Storage = append(f.vms[i].Storage, storage)
				}
			}
			f.attachCalls++
			return &storage, f.attachMutationError
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
				if !f.suppressDetachCommit {
					if f.detachVisibilityDelay > 0 {
						f.pendingDetachVM, f.pendingDetachDisk = vmID, diskID
					} else {
						f.vms[i].Storage = append(f.vms[i].Storage[:j], f.vms[i].Storage[j+1:]...)
					}
				}
				f.detachCalls++
				return f.detachMutationError
			}
		}
		return nil
	}
	return apiNotFound("VM")
}

func (f *fakeAPI) revealCreatedDisk() {
	if f.blockCreatedVisibility || f.pendingCreatedDisk == nil {
		return
	}
	f.disks = append(f.disks, *f.pendingCreatedDisk)
	f.pendingCreatedDisk = nil
}

func (f *fakeAPI) advancePendingDelete() {
	if f.pendingDeleteDisk == "" {
		return
	}
	if f.deleteVisibilityDelay > 0 {
		f.deleteVisibilityDelay--
		return
	}
	for i := range f.disks {
		if f.disks[i].UUID == f.pendingDeleteDisk {
			f.disks = append(f.disks[:i], f.disks[i+1:]...)
			break
		}
	}
	f.pendingDeleteDisk = ""
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

type fencedNodeResolver struct {
	nodeResolver
	*memoryMutationFenceStore
}

func newAdapter(t *testing.T, api *fakeAPI, resolver NodeResolver) *Adapter {
	t.Helper()
	adapter, err := New(api, resolver, Config{
		Location: testLocation, NetworkUUID: testNetwork, BillingAccountID: 42,
		PollInterval: time.Millisecond, MutationReadbackTimeout: time.Second,
		DestructiveAbsenceInterval: time.Millisecond, DestructiveReadbackTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func newFencedAdapter(t *testing.T, api API, resolver NodeResolver, timeout time.Duration) *Adapter {
	t.Helper()
	adapter, err := New(api, resolver, Config{
		Location: testLocation, NetworkUUID: testNetwork, BillingAccountID: 42,
		PollInterval: time.Millisecond, MutationReadbackTimeout: timeout,
		DestructiveAbsenceInterval: time.Millisecond, DestructiveReadbackTimeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func newFencedNetworkAdapter(t *testing.T, api API, resolver NodeResolver, timeout time.Duration) *Adapter {
	t.Helper()
	adapter, err := New(api, resolver, Config{
		Location: testLocation, NetworkUUID: testNetwork, BillingAccountID: 42,
		PollInterval: time.Millisecond, MutationReadbackTimeout: timeout,
		DestructiveAbsenceInterval: time.Millisecond, DestructiveReadbackTimeout: timeout,
	})
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

func TestEnsureVolumeRechecksDeterministicNameAfterFenceCAS(t *testing.T) {
	spec := cloud.VolumeSpec{Name: "pvc-post-cas", Location: testLocation, CapacityBytes: gib}
	owned := sdk.Disk{
		UUID: testDiskID, DisplayName: spec.Name, SizeGiB: 1,
		Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
	}
	t.Run("adopts exact disk without POST", func(t *testing.T) {
		api := &fakeAPI{diskAppearsOnListCall: 2, appearingDisks: []sdk.Disk{owned}}
		volume, err := newAdapter(t, api, nil).EnsureVolume(context.Background(), spec)
		if err != nil || volume.ID != testDiskID {
			t.Fatalf("post-CAS adoption volume=%#v err=%v", volume, err)
		}
		if api.createCalls != 0 {
			t.Fatalf("post-CAS exact appearance caused %d CreateDisk call(s)", api.createCalls)
		}
	})
	t.Run("foreign disk blocks POST and clears undispatched fence", func(t *testing.T) {
		foreign := owned
		foreign.BillingAccountID = 99
		api := &fakeAPI{
			diskAppearsOnListCall: 2, appearingDisks: []sdk.Disk{foreign}, preserveDiskBilling: true,
		}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
		if _, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec); err == nil {
			t.Fatal("post-CAS foreign disk was accepted")
		}
		if api.createCalls != 0 {
			t.Fatalf("post-CAS foreign appearance caused %d CreateDisk call(s)", api.createCalls)
		}
		if fence, err := store.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name)); err != nil || fence != nil {
			t.Fatalf("post-CAS foreign appearance left fence=%#v err=%v", fence, err)
		}
	})
	t.Run("duplicate disks block POST and clear undispatched fence", func(t *testing.T) {
		duplicate := owned
		duplicate.UUID = testVM2
		api := &fakeAPI{diskAppearsOnListCall: 2, appearingDisks: []sdk.Disk{owned, duplicate}}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
		if _, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec); err == nil {
			t.Fatal("post-CAS duplicate disks were accepted")
		}
		if api.createCalls != 0 {
			t.Fatalf("post-CAS duplicates caused %d CreateDisk call(s)", api.createCalls)
		}
		if fence, err := store.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name)); err != nil || fence != nil {
			t.Fatalf("post-CAS duplicates left fence=%#v err=%v", fence, err)
		}
	})
	t.Run("terminal disk blocks POST and clears undispatched fence", func(t *testing.T) {
		failed := owned
		failed.Status = "Failed"
		api := &fakeAPI{diskAppearsOnListCall: 2, appearingDisks: []sdk.Disk{failed}}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
		if _, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec); err == nil {
			t.Fatal("post-CAS terminal disk was accepted")
		}
		if api.createCalls != 0 {
			t.Fatalf("post-CAS terminal disk caused %d CreateDisk call(s)", api.createCalls)
		}
		if fence, err := store.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name)); err != nil || fence != nil {
			t.Fatalf("post-CAS terminal disk left fence=%#v err=%v", fence, err)
		}
	})
}

type secondDiskListErrorAPI struct {
	*fakeAPI
	calls int
	err   error
}

func (a *secondDiskListErrorAPI) ListDisks(ctx context.Context, location string) ([]sdk.Disk, error) {
	a.calls++
	if a.calls == 2 {
		return nil, a.err
	}
	return a.fakeAPI.ListDisks(ctx, location)
}

type deadlineCheckingMutationFenceStore struct {
	mutationFenceStore
	sawDeadline bool
}

func (s *deadlineCheckingMutationFenceStore) Delete(ctx context.Context, fence mutationFence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 {
		return errors.New("CSI fence delete lacks a live bounded context")
	}
	s.sawDeadline = true
	return s.mutationFenceStore.Delete(ctx, fence)
}

type advanceReceiptBeforeFenceDeleteStore struct {
	mutationFenceStore
	receipt     string
	advanced    bool
	sawDeadline bool
}

func (s *advanceReceiptBeforeFenceDeleteStore) Delete(ctx context.Context, fence mutationFence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 {
		return errors.New("CSI fence delete lacks a live bounded context")
	}
	s.sawDeadline = true
	if !s.advanced {
		current, err := s.mutationFenceStore.Get(ctx, fence.Key)
		if err != nil {
			return err
		}
		if current == nil {
			return errors.New("CSI mutation fence disappeared before replacement receipt")
		}
		if _, err := s.mutationFenceStore.SetReceipt(ctx, *current, s.receipt); err != nil {
			return err
		}
		s.advanced = true
	}
	return s.mutationFenceStore.Delete(ctx, fence)
}

func TestDetachedFenceDeleteSurvivesCancellationWithReadbackBound(t *testing.T) {
	base := newMemoryMutationFenceStore()
	candidate, err := newMutationFence("disk-create/bkk01/canceled-delete", diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "canceled-delete", SizeGiB: 1, BillingAccountID: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := base.Create(context.Background(), candidate)
	if err != nil || !acquired || stored == nil {
		t.Fatalf("seed fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	checking := &deadlineCheckingMutationFenceStore{mutationFenceStore: base}
	adapter := newAdapter(t, &fakeAPI{}, nil)
	adapter.readback = 50 * time.Millisecond
	adapter.fences = checking
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := adapter.deleteMutationFenceDetached(canceled, *stored); err != nil {
		t.Fatalf("detached fence delete: %v", err)
	}
	if !checking.sawDeadline {
		t.Fatal("detached fence delete did not expose a finite deadline")
	}
	if current, err := base.Get(context.Background(), candidate.Key); err != nil || current != nil {
		t.Fatalf("detached fence delete result=%#v err=%v", current, err)
	}
}

func TestAttachmentPredispatchCleanupSurvivesCancellationAndPreservesAdvancedReceipt(t *testing.T) {
	vm := func(uuid string, attached bool) sdk.VM {
		result := sdk.VM{
			UUID: uuid, Status: "Active", BillingAccountID: 42, NetworkUUID: testNetwork,
		}
		if attached {
			result.Storage = []sdk.VMStorage{{UUID: testDiskID}}
		}
		return result
	}
	type cleanupCase struct {
		name          string
		attach        bool
		vms           []sdk.VM
		vmReads       map[int]sdk.VM
		wantElsewhere bool
	}
	tests := []cleanupCase{
		{
			name: "attach first discovery already desired", attach: true,
			vms: []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, false),
				2: vm(testVM1, true),
			},
		},
		{
			name: "attach first discovery on another VM", attach: true,
			vms: []sdk.VM{{UUID: testVM1}, {UUID: testVM2}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, false),
				2: vm(testVM1, false),
				3: vm(testVM2, true),
			},
			wantElsewhere: true,
		},
		{
			name: "attach canonical detail already desired", attach: true,
			vms: []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, false),
				2: vm(testVM1, false),
				3: vm(testVM1, true),
			},
		},
		{
			name: "attach final discovery already desired", attach: true,
			vms: []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, false),
				2: vm(testVM1, false),
				3: vm(testVM1, false),
				4: vm(testVM1, true),
			},
		},
		{
			name: "detach first recheck already empty",
			vms:  []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, true),
				2: vm(testVM1, false),
			},
		},
		{
			name: "detach first recheck moved to another VM",
			vms:  []sdk.VM{{UUID: testVM1}, {UUID: testVM2}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, true),
				2: vm(testVM2, false),
				3: vm(testVM1, false),
				4: vm(testVM2, true),
			},
			wantElsewhere: true,
		},
		{
			name: "detach canonical detail already empty",
			vms:  []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, true),
				2: vm(testVM1, true),
				3: vm(testVM1, false),
			},
		},
		{
			name: "detach final discovery already empty",
			vms:  []sdk.VM{{UUID: testVM1}},
			vmReads: map[int]sdk.VM{
				1: vm(testVM1, true),
				2: vm(testVM1, true),
				3: vm(testVM1, true),
				4: vm(testVM1, false),
			},
		},
	}

	for _, test := range tests {
		for _, advanceReceipt := range []bool{false, true} {
			mode := "clear"
			if advanceReceipt {
				mode = "receipt advanced before delete"
			}
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				baseAPI := &fakeAPI{
					disks: []sdk.Disk{{
						UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1,
						Status: "Active", BillingAccountID: 42,
					}},
					vms: test.vms,
				}
				api := &detailSequenceAPI{fakeAPI: baseAPI, vmOverride: test.vmReads}
				baseStore := newMemoryMutationFenceStore()
				resolver := &fencedNodeResolver{
					nodeResolver: nodeResolver{
						"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
					},
					memoryMutationFenceStore: baseStore,
				}
				adapter := newFencedAdapter(t, api, resolver, 50*time.Millisecond)

				var sawDeadline func() bool
				if advanceReceipt {
					store := &advanceReceiptBeforeFenceDeleteStore{
						mutationFenceStore: baseStore,
						receipt:            testVM2,
					}
					adapter.fences = store
					sawDeadline = func() bool { return store.sawDeadline && store.advanced }
				} else {
					store := &deadlineCheckingMutationFenceStore{mutationFenceStore: baseStore}
					adapter.fences = store
					sawDeadline = func() bool { return store.sawDeadline }
				}

				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				var err error
				if test.attach {
					err = adapter.AttachVolume(canceled, testLocation, testDiskID, "worker-1")
				} else {
					err = adapter.DetachVolume(canceled, testLocation, testDiskID, "")
				}
				if test.wantElsewhere && !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
					t.Fatalf("operation error = %v, want ErrVolumeAttachedElsewhere", err)
				}
				if !test.wantElsewhere && !advanceReceipt && err != nil {
					t.Fatalf("operation error = %v", err)
				}
				if advanceReceipt && err == nil {
					t.Fatal("advanced receipt was cleared")
				}
				if !sawDeadline() {
					t.Fatal("cleanup did not use a live bounded context")
				}
				if baseAPI.mutationCalls() != 0 {
					t.Fatalf("pre-dispatch cleanup issued %d cloud mutation(s)", baseAPI.mutationCalls())
				}
				fence, getErr := baseStore.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID))
				if getErr != nil {
					t.Fatal(getErr)
				}
				if advanceReceipt {
					if fence == nil || fence.Receipt != testVM2 {
						t.Fatalf("advanced receipt fence = %#v, want retained receipt %s", fence, testVM2)
					}
				} else if fence != nil {
					t.Fatalf("proven-undispatched fence = %#v, want cleared", fence)
				}
			})
		}
	}
}

func TestEnsureVolumePredispatchCleanupPreservesAdvancedReceipt(t *testing.T) {
	spec := cloud.VolumeSpec{Name: "pvc-post-cas-receipt-race", Location: testLocation, CapacityBytes: gib}
	owned := sdk.Disk{
		UUID: testDiskID, DisplayName: spec.Name, SizeGiB: 1,
		Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
	}
	tests := map[string][]sdk.Disk{
		"duplicate": {
			owned,
			{
				UUID: testVM2, DisplayName: spec.Name, SizeGiB: 1,
				Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
			},
		},
		"validation": {
			{
				UUID: testDiskID, DisplayName: spec.Name, SizeGiB: 1,
				Status: "Active", BillingAccountID: 99, SourceImageType: "EMPTY",
			},
		},
		"readiness": {
			{
				UUID: testDiskID, DisplayName: spec.Name, SizeGiB: 1,
				Status: "Failed", BillingAccountID: 42, SourceImageType: "EMPTY",
			},
		},
	}
	for name, appearing := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{diskAppearsOnListCall: 2, appearingDisks: appearing, preserveDiskBilling: true}
			base := newMemoryMutationFenceStore()
			store := &advanceReceiptBeforeFenceDeleteStore{
				mutationFenceStore: base,
				receipt:            testVM1,
			}
			adapter := newFencedAdapter(t, api, nil, time.Second)
			adapter.fences = store

			if _, err := adapter.EnsureVolume(context.Background(), spec); err == nil {
				t.Fatal("post-CAS authority failure was accepted")
			}
			if api.createCalls != 0 {
				t.Fatalf("post-CAS authority failure caused %d CreateDisk call(s)", api.createCalls)
			}
			if !store.advanced || !store.sawDeadline {
				t.Fatalf("cleanup advanced=%t saw bounded context=%t", store.advanced, store.sawDeadline)
			}
			fence, err := base.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name))
			if err != nil || fence == nil || fence.Receipt != testVM1 {
				t.Fatalf("advanced receipt fence=%#v err=%v", fence, err)
			}
		})
	}
}

func TestEnsureVolumeClearsUndispatchedFenceAfterPostCASHTTPReadError(t *testing.T) {
	spec := cloud.VolumeSpec{Name: "pvc-post-cas-http-error", Location: testLocation, CapacityBytes: gib}
	base := &fakeAPI{}
	api := &secondDiskListErrorAPI{
		fakeAPI: base,
		err: &sdk.APIError{
			StatusCode: 500, Method: "GET", Path: "/storage/disks", Message: "temporary read failure", Retryable: true,
		},
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	adapter := newFencedAdapter(t, api, resolver, time.Second)

	if _, err := adapter.EnsureVolume(context.Background(), spec); err == nil {
		t.Fatal("post-CAS HTTP read failure was accepted")
	}
	if base.createCalls != 0 {
		t.Fatalf("post-CAS HTTP read failure dispatched %d CreateDisk call(s)", base.createCalls)
	}
	if fence, err := store.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name)); err != nil || fence != nil {
		t.Fatalf("proven-undispatched fence = %#v, err = %v; want cleared", fence, err)
	}

	volume, err := adapter.EnsureVolume(context.Background(), spec)
	if err != nil {
		t.Fatalf("retry after proven-undispatched read failure: %v", err)
	}
	if volume.ID == "" || base.createCalls != 1 {
		t.Fatalf("retry volume = %#v, CreateDisk calls = %d", volume, base.createCalls)
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

func TestEnsureVolumeDurableFenceRecoversDelayedCommittedAmbiguousCreateAcrossRestart(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/disks", Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/disks", Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{createCommittedError: mutationErr, blockCreatedVisibility: true}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			spec := cloud.VolumeSpec{Name: "pvc-delayed", Location: testLocation, CapacityBytes: gib}
			first := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
			if _, err := first.EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("first ambiguous create error = %v, want ErrUnavailable", err)
			}
			if api.createCalls != 1 {
				t.Fatalf("first create calls = %d, want 1", api.createCalls)
			}

			// Simulate a controller Pod restart: in-memory adapter state is gone,
			// while the production-equivalent durable fence store survives.
			api.blockCreatedVisibility = false
			second := newFencedAdapter(t, api, resolver, time.Second)
			volume, err := second.EnsureVolume(context.Background(), spec)
			if err != nil || volume.ID != testDiskID {
				t.Fatalf("restarted recovery volume=%#v err=%v", volume, err)
			}
			if api.createCalls != 1 || len(api.disks) != 1 {
				t.Fatalf("ambiguous committed create was replayed: calls=%d disks=%d", api.createCalls, len(api.disks))
			}
			if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence != nil {
				t.Fatalf("converged disk-create fence = %#v, err=%v", fence, err)
			}
		})
	}
}

func TestEnsureVolumeNeverAnchorsForeignCreateResponseUUID(t *testing.T) {
	const foreignDiskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	foreign := sdk.Disk{
		UUID: foreignDiskID, DisplayName: "operator-disk", SizeGiB: 9,
		Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
	}
	api := &fakeAPI{
		disks: []sdk.Disk{foreign}, createResponseUUID: foreignDiskID,
		blockCreatedVisibility: true,
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	spec := cloud.VolumeSpec{Name: "pvc-foreign-response", Location: testLocation, CapacityBytes: gib}

	if _, err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("hidden canonical create error = %v, want ErrUnavailable", err)
	}
	if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence == nil || fence.Receipt != "" {
		t.Fatalf("foreign response UUID became authoritative: fence=%#v err=%v", fence, err)
	}

	api.blockCreatedVisibility = false
	volume, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec)
	if err != nil || volume.ID != testDiskID {
		t.Fatalf("canonical restart recovery volume=%#v err=%v", volume, err)
	}
	if api.createCalls != 1 || len(api.disks) != 2 || api.disks[0].UUID != foreign.UUID || api.disks[0].DisplayName != foreign.DisplayName {
		t.Fatalf("foreign disk changed or create replayed: calls=%d disks=%#v", api.createCalls, api.disks)
	}
	if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence != nil {
		t.Fatalf("canonical create fence = %#v, err=%v", fence, err)
	}
}

func TestEnsureVolumeReplacesLegacyForeignReceiptOnlyFromCanonicalNameReadback(t *testing.T) {
	const foreignDiskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	foreign := sdk.Disk{
		UUID: foreignDiskID, DisplayName: "operator-disk", SizeGiB: 9,
		Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
	}
	actual := sdk.Disk{
		UUID: testDiskID, DisplayName: "pvc-legacy-receipt", SizeGiB: 1,
		Status: "Active", BillingAccountID: 42, SourceImageType: "EMPTY",
	}
	api := &fakeAPI{disks: []sdk.Disk{foreign, actual}}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: actual.DisplayName,
		SizeGiB: actual.SizeGiB, BillingAccountID: 42,
	}
	candidate, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := store.Create(context.Background(), candidate)
	if err != nil || !acquired || stored == nil {
		t.Fatalf("seed legacy fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	if stored, err = store.SetReceipt(context.Background(), *stored, foreignDiskID); err != nil {
		t.Fatal(err)
	}

	volume, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), cloud.VolumeSpec{
		Name: actual.DisplayName, Location: testLocation, CapacityBytes: gib,
	})
	if err != nil || volume.ID != testDiskID {
		t.Fatalf("legacy canonical recovery volume=%#v err=%v", volume, err)
	}
	if api.createCalls != 0 || api.disks[0].UUID != foreign.UUID || api.disks[0].DisplayName != foreign.DisplayName {
		t.Fatalf("legacy recovery mutated cloud state: calls=%d disks=%#v", api.createCalls, api.disks)
	}
	if fence, err := store.Get(context.Background(), candidate.Key); err != nil || fence != nil {
		t.Fatalf("legacy fence = %#v, err=%v", fence, err)
	}
}

func TestEnsureVolumeDurableFenceNeverReplaysUncommittedAmbiguousCreate(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/disks", Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/disks", Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{createCommittedError: mutationErr, suppressCreateCommit: true}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			spec := cloud.VolumeSpec{Name: "pvc-unresolved", Location: testLocation, CapacityBytes: gib}
			for attempt := range 2 {
				adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
				if _, err := adapter.EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
					t.Fatalf("attempt %d error = %v, want ErrUnavailable", attempt+1, err)
				}
			}
			if api.createCalls != 1 || len(api.disks) != 0 {
				t.Fatalf("unresolved paid POST was replayed: calls=%d disks=%d", api.createCalls, len(api.disks))
			}
			if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence == nil {
				t.Fatalf("unresolved disk-create fence = %#v, err=%v", fence, err)
			}
		})
	}
}

func TestEnsureVolumeHTTP400WithoutCommitRetainsFenceAndNeverReplays(t *testing.T) {
	api := &fakeAPI{
		createCommittedError: &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/disks", Message: "invalid"},
		suppressCreateCommit: true,
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	spec := cloud.VolumeSpec{Name: "pvc-definitive", Location: testLocation, CapacityBytes: gib}
	for attempt := range 2 {
		adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
		if _, err := adapter.EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("attempt %d error = %v, want ErrUnavailable", attempt+1, err)
		}
	}
	if api.createCalls != 1 {
		t.Fatalf("HTTP 400 disk create was replayed %d times", api.createCalls)
	}
	if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence == nil {
		t.Fatalf("HTTP 400 disk-create fence = %#v, err=%v", fence, err)
	}
}

func TestLocallyBlockedDiskCreateClearsOnlyItsUndispatchedFence(t *testing.T) {
	api := &fakeAPI{createCommittedError: sdk.ErrMutationBlocked, suppressCreateCommit: true}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	spec := cloud.VolumeSpec{Name: "pvc-blocked", Location: testLocation, CapacityBytes: gib}
	if _, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec); !errors.Is(err, sdk.ErrMutationBlocked) {
		t.Fatalf("locally blocked create error = %v", err)
	}
	if api.createCalls != 1 || len(api.disks) != 0 {
		t.Fatalf("locally blocked create changed cloud state: calls=%d disks=%#v", api.createCalls, api.disks)
	}
	if fence, err := store.Get(context.Background(), diskCreateFenceKey(spec.Location, spec.Name)); err != nil || fence != nil {
		t.Fatalf("locally blocked create fence=%#v err=%v", fence, err)
	}
}

func TestEnsureVolumeRecoversHTTP400HiddenCommitWithoutReceipt(t *testing.T) {
	api := &fakeAPI{
		createCommittedError:   &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/disks", Message: "invalid"},
		hideCreateResponse:     true,
		blockCreatedVisibility: true,
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	spec := cloud.VolumeSpec{Name: "pvc-hidden-400", Location: testLocation, CapacityBytes: gib}
	for attempt := range 2 {
		adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
		if _, err := adapter.EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("hidden attempt %d error = %v, want ErrUnavailable", attempt+1, err)
		}
	}
	if api.createCalls != 1 {
		t.Fatalf("hidden HTTP 400 disk create calls = %d, want 1", api.createCalls)
	}
	api.blockCreatedVisibility = false
	volume, err := newFencedAdapter(t, api, resolver, time.Second).EnsureVolume(context.Background(), spec)
	if err != nil || volume.ID != testDiskID || api.createCalls != 1 || len(api.disks) != 1 {
		t.Fatalf("hidden HTTP 400 recovery volume=%#v err=%v calls=%d disks=%d", volume, err, api.createCalls, len(api.disks))
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

func TestDeleteVolumeDurableFenceRecoversDelayedCommittedAmbiguousDeleteAcrossRestart(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "DELETE", Path: "/storage/disks/" + testDiskID, Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "DELETE", Path: "/storage/disks/" + testDiskID, Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				disks:               []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1, Status: "Active"}},
				deleteMutationError: mutationErr, deleteVisibilityDelay: 80,
			}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			first := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
			if err := first.DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("first ambiguous delete error = %v, want ErrUnavailable", err)
			}
			second := newFencedAdapter(t, api, resolver, time.Second)
			if err := second.DeleteVolume(context.Background(), testLocation, testDiskID); err != nil && !errors.Is(err, cloud.ErrNotFound) {
				t.Fatal(err)
			}
			if api.deleteCalls != 1 || len(api.disks) != 0 {
				t.Fatalf("ambiguous delete was replayed: calls=%d disks=%#v", api.deleteCalls, api.disks)
			}
			if fences, err := store.List(context.Background(), ""); err != nil || len(fences) != 0 {
				t.Fatalf("converged deletion fences=%#v err=%v", fences, err)
			}
		})
	}
}

func TestDeleteVolumeConvergesCanonicalDeletedTombstoneAcrossRestart(t *testing.T) {
	base := &fakeAPI{disks: []sdk.Disk{{
		UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1,
		Status: "Active", BillingAccountID: 42,
	}}}
	api := &deletedDiskTombstoneAPI{fakeAPI: base}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}

	// The live API returns HTTP 204, omits the disk from ListDisks, and retains
	// an exact status=Deleted tombstone. Stop after the first durable observation
	// to prove a restarted controller resumes the same fence without replaying
	// DELETE.
	first := newFencedAdapter(t, api, resolver, 20*time.Millisecond)
	first.absencePoll = 100 * time.Millisecond
	if err := first.DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("first tombstone delete error=%v, want ErrUnavailable", err)
	}
	if base.deleteCalls != 1 || len(base.disks) != 0 || api.tombstone == nil || !strings.EqualFold(api.tombstone.Status, "deleted") {
		t.Fatalf("committed tombstone delete calls=%d disks=%#v tombstone=%#v", base.deleteCalls, base.disks, api.tombstone)
	}
	fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID))
	if err != nil || fence == nil {
		t.Fatalf("retained tombstone delete fence=%#v err=%v", fence, err)
	}
	observation, err := decodeMutationObservation(fence.Observation)
	if err != nil || observation.Kind != diskDeleteAbsenceObservationKind || observation.Count != 1 {
		t.Fatalf("retained tombstone observation=%#v err=%v", observation, err)
	}

	restarted := newFencedAdapter(t, api, resolver, time.Second)
	if err := restarted.DeleteVolume(context.Background(), testLocation, testDiskID); err != nil {
		t.Fatal(err)
	}
	if base.deleteCalls != 1 {
		t.Fatalf("restart replayed tombstone DELETE %d times", base.deleteCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("completed tombstone delete fence=%#v err=%v", fence, err)
	}
}

func TestCanonicalDeletedDiskTombstoneIsAbsentForReadAndNeverAttached(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{
			UUID: testDiskID, DisplayName: "pvc-deleted", SizeGiB: 1,
			Status: "Deleted", BillingAccountID: 42,
		}},
		vms: []sdk.VM{{
			UUID: testVM1, Status: "Active", BillingAccountID: 42,
			NetworkUUID: testNetwork,
		}},
		networkVMUUIDs: []string{testVM1},
	}
	adapter := newAdapter(t, api, nodeResolver{
		"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
	})

	if _, err := adapter.GetVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("GetVolume deleted tombstone error = %v, want ErrNotFound", err)
	}
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("AttachVolume deleted tombstone error = %v, want ErrNotFound", err)
	}
	if api.attachCalls != 0 {
		t.Fatalf("deleted tombstone issued %d AttachDisk call(s)", api.attachCalls)
	}
}

func TestDeleteVolumeAdoptsCanonicalDeletedTombstoneWithoutReplayingDelete(t *testing.T) {
	base := &fakeAPI{}
	api := &deletedDiskTombstoneAPI{
		fakeAPI: base,
		tombstone: &sdk.Disk{
			UUID: testDiskID, DisplayName: "pvc-deleted", SizeGiB: 1,
			Status: "Deleted", BillingAccountID: 42,
		},
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	adapter := newFencedAdapter(t, api, resolver, time.Second)

	if err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID); err != nil {
		t.Fatal(err)
	}
	if base.deleteCalls != 0 {
		t.Fatalf("pre-existing deleted tombstone replayed DELETE %d time(s)", base.deleteCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("completed pre-existing tombstone fence=%#v err=%v", fence, err)
	}
}

func TestLocallyBlockedDiskDeleteClearsOnlyItsUndispatchedFence(t *testing.T) {
	api := &fakeAPI{
		disks:               []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
		deleteMutationError: sdk.ErrMutationBlocked, suppressDeleteCommit: true,
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	if err := newFencedAdapter(t, api, resolver, time.Second).DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, sdk.ErrMutationBlocked) {
		t.Fatalf("locally blocked delete error = %v", err)
	}
	if api.deleteCalls != 1 || len(api.disks) != 1 {
		t.Fatalf("locally blocked delete changed cloud state: calls=%d disks=%#v", api.deleteCalls, api.disks)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("locally blocked delete fence=%#v err=%v", fence, err)
	}
}

func TestDiskDeleteAbsenceProofPersistsAcrossRestart(t *testing.T) {
	api := &fakeAPI{}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	intent := diskAttachmentIntent{
		Operation: "disk-delete", Location: testLocation,
		DiskUUID: testDiskID, BillingAccountID: 42,
	}
	candidate, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := store.Create(context.Background(), candidate)
	if err != nil || !acquired || stored == nil {
		t.Fatalf("seed disk-delete fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	first := newFencedAdapter(t, api, resolver, time.Second)
	first.absencePoll = 50 * time.Millisecond
	firstCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	_, firstErr := first.waitForDiskAbsent(firstCtx, testLocation, testDiskID, *stored)
	cancel()
	if firstErr == nil {
		t.Fatal("one absence observation unexpectedly completed disk deletion")
	}
	retained, err := store.Get(context.Background(), candidate.Key)
	if err != nil || retained == nil {
		t.Fatalf("first absence observation was not retained: fence=%#v err=%v", retained, err)
	}
	observation, err := decodeMutationObservation(retained.Observation)
	if err != nil || observation.Kind != diskDeleteAbsenceObservationKind || observation.Count != 1 {
		t.Fatalf("retained disk-delete observation=%#v err=%v", observation, err)
	}

	restarted := newFencedAdapter(t, api, resolver, time.Second)
	resolved, err := restarted.waitForDiskAbsent(context.Background(), testLocation, testDiskID, *retained)
	if err != nil {
		t.Fatal(err)
	}
	observation, err = decodeMutationObservation(resolved.Observation)
	if err != nil || observation.Count != 3 {
		t.Fatalf("resolved disk-delete observation=%#v err=%v", observation, err)
	}
	if api.mutationCalls() != 0 {
		t.Fatalf("absence recovery issued %d cloud mutation(s)", api.mutationCalls())
	}
}

func TestDiskDeleteTombstoneAbsenceRemainsFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		tombstone  sdk.Disk
		listedDisk *sdk.Disk
	}{
		{name: "active", tombstone: sdk.Disk{UUID: testDiskID, Status: "Active", BillingAccountID: 42}},
		{name: "error", tombstone: sdk.Disk{UUID: testDiskID, Status: "Error", BillingAccountID: 42}},
		{name: "failed", tombstone: sdk.Disk{UUID: testDiskID, Status: "Failed", BillingAccountID: 42}},
		{name: "deleting", tombstone: sdk.Disk{UUID: testDiskID, Status: "Deleting", BillingAccountID: 42}},
		{name: "empty status", tombstone: sdk.Disk{UUID: testDiskID, BillingAccountID: 42}},
		{name: "unknown status", tombstone: sdk.Disk{UUID: testDiskID, Status: "Archived", BillingAccountID: 42}},
		{
			name: "deleted but still listed",
			tombstone: sdk.Disk{
				UUID: testDiskID, Status: "Deleted", BillingAccountID: 42,
			},
			listedDisk: &sdk.Disk{UUID: testDiskID, Status: "Deleted", BillingAccountID: 42},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := &fakeAPI{}
			if test.listedDisk != nil {
				base.disks = []sdk.Disk{*test.listedDisk}
			}
			tombstone := test.tombstone
			api := &deletedDiskTombstoneAPI{fakeAPI: base, tombstone: &tombstone}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			intent := diskAttachmentIntent{
				Operation: "disk-delete", Location: testLocation,
				DiskUUID: testDiskID, BillingAccountID: 42,
			}
			candidate, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
			if err != nil {
				t.Fatal(err)
			}
			stored, acquired, err := store.Create(context.Background(), candidate)
			if err != nil || !acquired || stored == nil {
				t.Fatalf("seed disk-delete fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
			}
			encoded, err := encodeMutationObservation(mutationObservation{
				Kind: diskDeleteAbsenceObservationKind, Count: 1,
				FirstObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
			if err != nil {
				t.Fatal(err)
			}
			stored, err = store.SetObservation(context.Background(), *stored, encoded)
			if err != nil {
				t.Fatal(err)
			}

			adapter := newFencedAdapter(t, api, resolver, time.Second)
			readCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			_, readErr := adapter.waitForDiskAbsent(readCtx, testLocation, testDiskID, *stored)
			cancel()
			if readErr == nil {
				t.Fatal("visible tombstone state completed destructive absence proof")
			}
			retained, err := store.Get(context.Background(), candidate.Key)
			if err != nil || retained == nil || retained.Observation != "" {
				t.Fatalf("visible tombstone state did not reset absence proof: fence=%#v err=%v", retained, err)
			}
			if base.mutationCalls() != 0 {
				t.Fatalf("visible tombstone state caused %d mutation(s)", base.mutationCalls())
			}
		})
	}
}

func TestDiskDeleteTombstoneRequiresExactIdentityAndBilling(t *testing.T) {
	for name, tombstone := range map[string]sdk.Disk{
		"wrong UUID":      {UUID: testVM1, Status: "Deleted", BillingAccountID: 42},
		"omitted billing": {UUID: testDiskID, Status: "Deleted"},
		"wrong billing":   {UUID: testDiskID, Status: "Deleted", BillingAccountID: 43},
	} {
		t.Run(name, func(t *testing.T) {
			api := &deletedDiskTombstoneAPI{fakeAPI: &fakeAPI{}, tombstone: &tombstone}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			intent := diskAttachmentIntent{
				Operation: "disk-delete", Location: testLocation,
				DiskUUID: testDiskID, BillingAccountID: 42,
			}
			candidate, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
			if err != nil {
				t.Fatal(err)
			}
			stored, acquired, err := store.Create(context.Background(), candidate)
			if err != nil || !acquired || stored == nil {
				t.Fatalf("seed disk-delete fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
			}
			adapter := newFencedAdapter(t, api, resolver, time.Second)
			if _, err := adapter.waitForDiskAbsent(context.Background(), testLocation, testDiskID, *stored); err == nil {
				t.Fatal("non-canonical Deleted tombstone completed absence proof")
			}
			if api.mutationCalls() != 0 {
				t.Fatalf("non-canonical tombstone caused %d mutation(s)", api.mutationCalls())
			}
		})
	}
}

func TestTransientDiskOmissionResetsDurableAbsenceProof(t *testing.T) {
	base := &fakeAPI{disks: []sdk.Disk{{
		UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1,
		Status: "Active", BillingAccountID: 42,
	}}}
	api := &transientDiskOmissionAPI{fakeAPI: base, hiddenRounds: 1}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	intent := diskAttachmentIntent{
		Operation: "disk-delete", Location: testLocation,
		DiskUUID: testDiskID, BillingAccountID: 42,
	}
	candidate, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := store.Create(context.Background(), candidate)
	if err != nil || !acquired || stored == nil {
		t.Fatalf("seed disk-delete fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	adapter := newFencedAdapter(t, api, resolver, time.Second)
	readCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, readErr := adapter.waitForDiskAbsent(readCtx, testLocation, testDiskID, *stored)
	cancel()
	if readErr == nil {
		t.Fatal("transient disk omission completed a destructive absence proof")
	}
	retained, err := store.Get(context.Background(), candidate.Key)
	if err != nil || retained == nil || retained.Observation != "" {
		t.Fatalf("visible disk did not reset absence proof: fence=%#v err=%v", retained, err)
	}
	if len(base.disks) != 1 || base.mutationCalls() != 0 {
		t.Fatalf("transient omission changed cloud state: disks=%#v mutations=%d", base.disks, base.mutationCalls())
	}
}

func TestDeleteVolumeDurableFenceNeverReplaysUncommittedAmbiguousDelete(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "DELETE", Path: "/storage/disks/" + testDiskID, Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "DELETE", Path: "/storage/disks/" + testDiskID, Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				disks:               []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1, Status: "Active"}},
				deleteMutationError: mutationErr, suppressDeleteCommit: true,
			}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
			for attempt := range 2 {
				adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
				err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
				if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "inspace-csi-") {
					t.Fatalf("attempt %d error = %v, want fail-closed Lease name", attempt+1, err)
				}
			}
			if api.deleteCalls != 1 || len(api.disks) != 1 {
				t.Fatalf("unresolved delete was replayed: calls=%d disks=%#v", api.deleteCalls, api.disks)
			}
		})
	}
}

func TestDeleteVolumeBlocksUnresolvedAttachFenceBeforeCloudDelete(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1, Status: "Active"}},
		vms:   []sdk.VM{{UUID: testVM1}},
	}
	store := newMemoryMutationFenceStore()
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: testLocation,
		DiskUUID: testDiskID, BillingAccountID: 42, DesiredVMUUID: testVM1,
	}
	fence, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, acquired, err := store.Create(context.Background(), fence); err != nil || !acquired {
		t.Fatalf("seed attachment fence acquired=%t err=%v", acquired, err)
	}
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
	err = adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
	if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), mutationFenceLeaseName(fence.Key)) {
		t.Fatalf("delete with pending attach fence error = %v", err)
	}
	if api.deleteCalls != 0 || len(api.disks) != 1 {
		t.Fatalf("delete crossed unresolved attach: calls=%d disks=%#v", api.deleteCalls, api.disks)
	}
}

func TestDeleteVolumeBlocksUnreceiptedCreateFenceAndNamesOperatorLease(t *testing.T) {
	api := &fakeAPI{disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1, Status: "Active"}}}
	store := newMemoryMutationFenceStore()
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "pvc-delete",
		SizeGiB: 1, BillingAccountID: 42,
	}
	fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, acquired, err := store.Create(context.Background(), fence); err != nil || !acquired {
		t.Fatalf("seed create fence acquired=%t err=%v", acquired, err)
	}
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	adapter := newFencedAdapter(t, api, resolver, 20*time.Millisecond)
	err = adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
	if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), mutationFenceLeaseName(fence.Key)) || !strings.Contains(err.Error(), "operator") {
		t.Fatalf("delete with unreceipted create fence error = %v", err)
	}
	if api.deleteCalls != 0 || len(api.disks) != 1 {
		t.Fatalf("delete crossed unresolved create: calls=%d disks=%#v", api.deleteCalls, api.disks)
	}
}

func TestDeleteVolumeCleansExactCreateReceiptAfterGetListAbsenceProof(t *testing.T) {
	api := &fakeAPI{disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-delete", SizeGiB: 1, Status: "Active"}}}
	store := newMemoryMutationFenceStore()
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "pvc-delete",
		SizeGiB: 1, BillingAccountID: 42,
	}
	fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := store.Create(context.Background(), fence)
	if err != nil || !acquired {
		t.Fatalf("seed create fence acquired=%t err=%v", acquired, err)
	}
	if stored, err = store.SetReceipt(context.Background(), *stored, testDiskID); err != nil {
		t.Fatal(err)
	}
	resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
	adapter := newFencedAdapter(t, api, resolver, time.Second)
	if err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID); err != nil {
		t.Fatal(err)
	}
	if api.deleteCalls != 1 || len(api.disks) != 0 {
		t.Fatalf("protected delete calls=%d disks=%#v", api.deleteCalls, api.disks)
	}
	if fences, err := store.List(context.Background(), ""); err != nil || len(fences) != 0 {
		t.Fatalf("residual protected-delete fences=%#v err=%v", fences, err)
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
		Location: testLocation, NetworkUUID: testNetwork, BillingAccountID: 42,
		PollInterval: time.Millisecond, MutationReadbackTimeout: time.Second,
		DestructiveAbsenceInterval: time.Millisecond, DestructiveReadbackTimeout: time.Second,
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

func TestAttachDurableFenceRecoversCommittedAmbiguousMutationAcrossRestart(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/attach", Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
				vms:   []sdk.VM{{UUID: testVM1}}, attachVisibilityDelay: 80,
				attachMutationError: mutationErr,
			}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{
				nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
				memoryMutationFenceStore: store,
			}
			first := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
			if err := first.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("first attach error = %v, want ErrUnavailable", err)
			}
			second := newFencedAdapter(t, api, resolver, time.Second)
			if err := second.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
				t.Fatal(err)
			}
			if api.attachCalls != 1 {
				t.Fatalf("ambiguous attach POST calls = %d, want 1", api.attachCalls)
			}
		})
	}
}

func TestAttachDurableFenceNeverReplaysUncommittedAmbiguousMutation(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
		vms:   []sdk.VM{{UUID: testVM1}}, suppressAttachCommit: true,
		attachMutationError: &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "internal error", Retryable: true},
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
	for attempt := range 2 {
		adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("attempt %d attach error = %v, want ErrUnavailable", attempt+1, err)
		}
	}
	if api.attachCalls != 1 {
		t.Fatalf("unresolved attach POST calls = %d, want 1", api.attachCalls)
	}
}

func TestDetachDurableFenceRecoversCommittedAmbiguousMutationAcrossRestart(t *testing.T) {
	for name, mutationErr := range map[string]error{
		"http 400": &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/detach", Message: "invalid"},
		"http 500": &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/detach", Message: "internal error", Retryable: true},
		"timeout":  context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				disks:                 []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
				vms:                   []sdk.VM{{UUID: testVM1, Storage: []sdk.VMStorage{{UUID: testDiskID}}}},
				detachVisibilityDelay: 80, detachMutationError: mutationErr,
			}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{
				nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
				memoryMutationFenceStore: store,
			}
			first := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
			if err := first.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("first detach error = %v, want ErrUnavailable", err)
			}
			second := newFencedAdapter(t, api, resolver, time.Second)
			if err := second.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
				t.Fatal(err)
			}
			if api.detachCalls != 1 {
				t.Fatalf("ambiguous detach POST calls = %d, want 1", api.detachCalls)
			}
		})
	}
}

func TestDetachDurableFenceNeverReplaysUncommittedAmbiguousMutation(t *testing.T) {
	api := &fakeAPI{
		disks:                []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
		vms:                  []sdk.VM{{UUID: testVM1, Storage: []sdk.VMStorage{{UUID: testDiskID}}}},
		suppressDetachCommit: true,
		detachMutationError:  &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/detach", Message: "internal error", Retryable: true},
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
	for attempt := range 2 {
		adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
		if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("attempt %d detach error = %v, want ErrUnavailable", attempt+1, err)
		}
	}
	if api.detachCalls != 1 {
		t.Fatalf("unresolved detach POST calls = %d, want 1", api.detachCalls)
	}
}

func TestMutationErrorsRetainDurableFenceWhenAuthoritativeReadbackFails(t *testing.T) {
	readbackErr := errors.New("authoritative readback unavailable")

	t.Run("create", func(t *testing.T) {
		api := &fakeAPI{
			createCommittedError: &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/disks", Message: "invalid"},
			suppressCreateCommit: true,
			readbackError:        readbackErr,
		}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
		spec := cloud.VolumeSpec{Name: "pvc-readback-failure", Location: testLocation, CapacityBytes: gib}
		if _, err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).EnsureVolume(context.Background(), spec); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("create readback failure error = %v, want ErrUnavailable", err)
		}
		if fence, err := store.Get(context.Background(), diskCreateFenceKey(testLocation, spec.Name)); err != nil || fence == nil {
			t.Fatalf("create readback failure fence = %#v, err=%v", fence, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		api := &fakeAPI{
			disks:                []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
			deleteMutationError:  &sdk.APIError{StatusCode: 400, Method: "DELETE", Path: "/storage/disks/" + testDiskID, Message: "invalid"},
			suppressDeleteCommit: true,
			readbackError:        readbackErr,
		}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{nodeResolver: nodeResolver{}, memoryMutationFenceStore: store}
		if err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("delete readback failure error = %v, want ErrUnavailable", err)
		}
		if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence == nil {
			t.Fatalf("delete readback failure fence = %#v, err=%v", fence, err)
		}
	})

	t.Run("attach", func(t *testing.T) {
		api := &fakeAPI{
			disks:                []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
			vms:                  []sdk.VM{{UUID: testVM1}},
			attachMutationError:  &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/attach", Message: "invalid"},
			suppressAttachCommit: true,
			readbackError:        readbackErr,
		}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{
			nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
			memoryMutationFenceStore: store,
		}
		if err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("attach readback failure error = %v, want ErrUnavailable", err)
		}
		if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence == nil {
			t.Fatalf("attach readback failure fence = %#v, err=%v", fence, err)
		}
	})

	t.Run("detach", func(t *testing.T) {
		api := &fakeAPI{
			disks:                []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"}},
			vms:                  []sdk.VM{{UUID: testVM1, Storage: []sdk.VMStorage{{UUID: testDiskID}}}},
			detachMutationError:  &sdk.APIError{StatusCode: 400, Method: "POST", Path: "/storage/detach", Message: "invalid"},
			suppressDetachCommit: true,
			readbackError:        readbackErr,
		}
		store := newMemoryMutationFenceStore()
		resolver := &fencedNodeResolver{
			nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
			memoryMutationFenceStore: store,
		}
		if err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
			t.Fatalf("detach readback failure error = %v, want ErrUnavailable", err)
		}
		if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence == nil {
			t.Fatalf("detach readback failure fence = %#v, err=%v", fence, err)
		}
	})
}

func TestAttachmentReadbackRejectsDuplicateDiskRowsOnOneVM(t *testing.T) {
	api := &fakeAPI{vms: []sdk.VM{{
		UUID:    testVM1,
		Storage: []sdk.VMStorage{{UUID: testDiskID}, {UUID: testDiskID}},
	}}}
	adapter := newAdapter(t, api, nil)
	if _, err := adapter.attachedVM(context.Background(), testLocation, testDiskID); err == nil || !strings.Contains(err.Error(), "2 attachment rows") {
		t.Fatalf("duplicate attachment rows error = %v", err)
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

func TestAdapterRequiresPositiveBillingAccount(t *testing.T) {
	for _, billing := range []int64{0, -1} {
		api := &fakeAPI{}
		if _, err := New(api, nil, Config{Location: testLocation, BillingAccountID: billing}); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("New() billing %d error = %v", billing, err)
		}
		if api.mutationCalls() != 0 {
			t.Fatalf("invalid config issued %d cloud mutation(s)", api.mutationCalls())
		}
	}
}

func TestDiskBillingOmissionOrMismatchNeverMutates(t *testing.T) {
	for name, billing := range map[string]int64{"omitted": 0, "wrong": 43} {
		t.Run(name, func(t *testing.T) {
			newAPI := func(attached bool) *fakeAPI {
				api := &fakeAPI{
					disks:               []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: billing}},
					vms:                 []sdk.VM{{UUID: testVM1, BillingAccountID: 42}},
					preserveDiskBilling: true,
				}
				if attached {
					api.vms[0].Storage = []sdk.VMStorage{{UUID: testDiskID}}
				}
				return api
			}

			createAPI := newAPI(false)
			if _, err := newAdapter(t, createAPI, nil).EnsureVolume(context.Background(), cloud.VolumeSpec{
				Name: "pvc", Location: testLocation, CapacityBytes: gib,
			}); err == nil {
				t.Fatal("create recovery accepted unowned same-named disk")
			}
			if createAPI.createCalls != 0 {
				t.Fatalf("create recovery issued %d CreateDisk call(s)", createAPI.createCalls)
			}

			getAPI := newAPI(false)
			if _, err := newAdapter(t, getAPI, nil).GetVolume(context.Background(), testLocation, testDiskID); err == nil {
				t.Fatal("GetVolume accepted unowned disk")
			}

			deleteAPI := newAPI(false)
			if err := newAdapter(t, deleteAPI, nil).DeleteVolume(context.Background(), testLocation, testDiskID); err == nil {
				t.Fatal("DeleteVolume accepted unowned disk")
			}
			if deleteAPI.deleteCalls != 0 {
				t.Fatalf("unowned disk caused %d DeleteDisk call(s)", deleteAPI.deleteCalls)
			}

			attachAPI := newAPI(false)
			if err := newAdapter(t, attachAPI, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)}).AttachVolume(
				context.Background(), testLocation, testDiskID, "worker-1",
			); err == nil {
				t.Fatal("AttachVolume accepted unowned disk")
			}
			if attachAPI.attachCalls != 0 {
				t.Fatalf("unowned disk caused %d AttachDisk call(s)", attachAPI.attachCalls)
			}

			detachAPI := newAPI(true)
			if err := newAdapter(t, detachAPI, nil).DetachVolume(context.Background(), testLocation, testDiskID, ""); err == nil {
				t.Fatal("DetachVolume accepted unowned disk")
			}
			if detachAPI.detachCalls != 0 {
				t.Fatalf("unowned disk caused %d DetachDisk call(s)", detachAPI.detachCalls)
			}
		})
	}
}

func TestVMBillingOmissionOrMismatchNeverMutates(t *testing.T) {
	for name, billing := range map[string]int64{"omitted": 0, "wrong": 43} {
		t.Run(name, func(t *testing.T) {
			attachAPI := &fakeAPI{
				disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
				vms:   []sdk.VM{{UUID: testVM1, BillingAccountID: billing}}, preserveVMBilling: true,
			}
			adapter := newAdapter(t, attachAPI, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)})
			if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err == nil {
				t.Fatal("AttachVolume accepted unowned target VM")
			}
			if attachAPI.attachCalls != 0 {
				t.Fatalf("unowned VM caused %d AttachDisk call(s)", attachAPI.attachCalls)
			}

			detachAPI := &fakeAPI{
				disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
				vms:   []sdk.VM{{UUID: testVM1, BillingAccountID: billing, Storage: []sdk.VMStorage{{UUID: testDiskID}}}}, preserveVMBilling: true,
			}
			if err := newAdapter(t, detachAPI, nil).DetachVolume(context.Background(), testLocation, testDiskID, ""); err == nil {
				t.Fatal("DetachVolume accepted unowned attached VM")
			}
			if detachAPI.detachCalls != 0 {
				t.Fatalf("unowned VM caused %d DetachDisk call(s)", detachAPI.detachCalls)
			}
		})
	}
}

func TestFinalExactDiskReadRejectsOwnershipDriftBeforeMutation(t *testing.T) {
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	variants := map[string]sdk.Disk{
		"omitted billing": {UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"},
		"wrong billing":   {UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 43},
		"wrong UUID":      {UUID: testVM2, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42},
	}
	for name, foreign := range variants {
		t.Run(name, func(t *testing.T) {

			deleteBase := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{{UUID: testVM1, BillingAccountID: 42}}}
			deleteAPI := &detailSequenceAPI{fakeAPI: deleteBase, diskOverride: map[int]sdk.Disk{2: foreign}}
			if err := newFencedAdapter(t, deleteAPI, nil, time.Second).DeleteVolume(context.Background(), testLocation, testDiskID); err == nil {
				t.Fatal("DeleteVolume accepted final disk ownership drift")
			}
			if deleteBase.deleteCalls != 0 {
				t.Fatalf("ownership drift caused %d DeleteDisk call(s)", deleteBase.deleteCalls)
			}

			attachBase := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{{UUID: testVM1, BillingAccountID: 42}}}
			attachAPI := &detailSequenceAPI{fakeAPI: attachBase, diskOverride: map[int]sdk.Disk{2: foreign}}
			if err := newFencedAdapter(t, attachAPI, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)}, time.Second).AttachVolume(
				context.Background(), testLocation, testDiskID, "worker-1",
			); err == nil {
				t.Fatal("AttachVolume accepted final disk ownership drift")
			}
			if attachBase.attachCalls != 0 {
				t.Fatalf("ownership drift caused %d AttachDisk call(s)", attachBase.attachCalls)
			}

			detachBase := &fakeAPI{
				disks: []sdk.Disk{ownedDisk},
				vms:   []sdk.VM{{UUID: testVM1, BillingAccountID: 42, Storage: []sdk.VMStorage{{UUID: testDiskID}}}},
			}
			detachAPI := &detailSequenceAPI{fakeAPI: detachBase, diskOverride: map[int]sdk.Disk{2: foreign}}
			if err := newFencedAdapter(t, detachAPI, nil, time.Second).DetachVolume(context.Background(), testLocation, testDiskID, ""); err == nil {
				t.Fatal("DetachVolume accepted final disk ownership drift")
			}
			if detachBase.detachCalls != 0 {
				t.Fatalf("ownership drift caused %d DetachDisk call(s)", detachBase.detachCalls)
			}
		})
	}
}

func TestCreateReceiptRecoveryRequiresCanonicalNameUUIDAndBilling(t *testing.T) {
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "pvc",
		SizeGiB: 1, BillingAccountID: 42,
	}
	variants := map[string]sdk.Disk{
		"omitted billing": {UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active"},
		"wrong billing":   {UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 43},
		"invalid UUID":    {UUID: "not-a-uuid", DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42},
	}
	for name, disk := range variants {
		t.Run(name, func(t *testing.T) {
			base := &fakeAPI{disks: []sdk.Disk{disk}, preserveDiskBilling: true}
			adapter := newFencedAdapter(t, base, nil, time.Second)
			fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
			if err != nil {
				t.Fatal(err)
			}
			fence.Receipt = testDiskID
			if _, err := adapter.reconcileDiskCreateFence(context.Background(), intent, fence, errors.New("ambiguous create")); err == nil {
				t.Fatal("create receipt recovery accepted non-exact disk ownership")
			}
			if base.mutationCalls() != 0 {
				t.Fatalf("create receipt recovery issued %d cloud mutation(s)", base.mutationCalls())
			}
		})
	}
}

func TestTargetVMRequiresExactUUIDBillingAndConfiguredNetwork(t *testing.T) {
	const networkUUID = "44444444-4444-4444-8444-444444444444"
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	for name, vm := range map[string]sdk.VM{
		"wrong UUID":    {UUID: testVM2, BillingAccountID: 42, NetworkUUID: networkUUID},
		"zero billing":  {UUID: testVM1, BillingAccountID: 0, NetworkUUID: networkUUID},
		"wrong billing": {UUID: testVM1, BillingAccountID: 43, NetworkUUID: networkUUID},
		"wrong network": {UUID: testVM1, BillingAccountID: 42, NetworkUUID: testVM2},
		"deleted":       {UUID: testVM1, Status: "Deleted", BillingAccountID: 42, NetworkUUID: networkUUID},
	} {
		t.Run(name, func(t *testing.T) {
			base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: networkUUID}}}
			api := &detailSequenceAPI{fakeAPI: base, vmOverride: map[int]sdk.VM{1: vm}}
			adapter, err := New(api, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)}, Config{
				Location: testLocation, NetworkUUID: networkUUID, BillingAccountID: 42,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err == nil {
				t.Fatal("AttachVolume accepted invalid target VM detail")
			}
			if base.attachCalls != 0 {
				t.Fatalf("invalid target VM caused %d AttachDisk call(s)", base.attachCalls)
			}
		})
	}
}

func TestTargetVMAllowsSparseNetworkOnlyWithExactConfiguredVPCMembership(t *testing.T) {
	ownedDisk := sdk.Disk{
		UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42,
	}
	// This matches the live InSpace VM detail/list contract: identity and
	// billing_account are present, while network_uuid is omitted.
	sparseVM := sdk.VM{UUID: testVM1, BillingAccountID: 42}

	t.Run("exact membership authorizes attach", func(t *testing.T) {
		api := &fakeAPI{
			disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{sparseVM},
			networkVMUUIDs: []string{testVM1}, preserveVMNetwork: true,
		}
		adapter := newFencedNetworkAdapter(t, api, nodeResolver{
			"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		}, time.Second)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
			t.Fatal(err)
		}
		if api.attachCalls != 1 || vmDiskRows(api.vms[0], testDiskID) != 1 {
			t.Fatalf("sparse-detail attach calls=%d storage=%#v", api.attachCalls, api.vms[0].Storage)
		}
	})

	t.Run("missing membership remains fail closed", func(t *testing.T) {
		api := &fakeAPI{
			disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{sparseVM},
			networkVMUUIDs: []string{testVM2}, preserveVMNetwork: true,
		}
		adapter := newFencedNetworkAdapter(t, api, nodeResolver{
			"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		}, time.Second)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrInvalidNode) {
			t.Fatalf("missing-membership attach error=%v, want ErrInvalidNode", err)
		}
		if api.mutationCalls() != 0 {
			t.Fatalf("missing membership caused %d cloud mutation(s)", api.mutationCalls())
		}
	})
}

func TestFinalExactVMReadRejectsOwnershipDriftBeforeMutation(t *testing.T) {
	const networkUUID = "44444444-4444-4444-8444-444444444444"
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	ownedVM := sdk.VM{UUID: testVM1, BillingAccountID: 42, NetworkUUID: networkUUID}
	variants := map[string]sdk.VM{
		"omitted billing": {UUID: testVM1, NetworkUUID: networkUUID},
		"wrong billing":   {UUID: testVM1, BillingAccountID: 43, NetworkUUID: networkUUID},
		"wrong UUID":      {UUID: testVM2, BillingAccountID: 42, NetworkUUID: networkUUID},
		"wrong network":   {UUID: testVM1, BillingAccountID: 42, NetworkUUID: testVM2},
	}
	for name, foreign := range variants {
		t.Run(name, func(t *testing.T) {
			attachBase := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{ownedVM}}
			attachAPI := &detailSequenceAPI{fakeAPI: attachBase, vmOverride: map[int]sdk.VM{3: foreign}}
			attachAdapter, err := New(attachAPI, nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)}, Config{
				Location: testLocation, NetworkUUID: networkUUID, BillingAccountID: 42,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := attachAdapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err == nil {
				t.Fatal("AttachVolume accepted final VM ownership drift")
			}
			if attachBase.attachCalls != 0 {
				t.Fatalf("VM ownership drift caused %d AttachDisk call(s)", attachBase.attachCalls)
			}

			detachOwnedVM := ownedVM
			detachOwnedVM.Storage = []sdk.VMStorage{{UUID: testDiskID}}
			detachBase := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{detachOwnedVM}}
			detachForeign := foreign
			detachForeign.Storage = []sdk.VMStorage{{UUID: testDiskID}}
			detachAPI := &detailSequenceAPI{fakeAPI: detachBase, vmOverride: map[int]sdk.VM{3: detachForeign}}
			detachAdapter, err := New(detachAPI, nil, Config{
				Location: testLocation, NetworkUUID: networkUUID, BillingAccountID: 42,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := detachAdapter.DetachVolume(context.Background(), testLocation, testDiskID, ""); err == nil {
				t.Fatal("DetachVolume accepted final VM ownership drift")
			}
			if detachBase.detachCalls != 0 {
				t.Fatalf("VM ownership drift caused %d DetachDisk call(s)", detachBase.detachCalls)
			}
		})
	}
}

func TestAttachStaleListCannotCompleteFenceWithoutExactVMStorage(t *testing.T) {
	base := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
		vms:   []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}},
		attachMutationError: &sdk.APIError{
			StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "committed response lost", Retryable: true,
		},
	}
	staleVMDetails := make(map[int]sdk.VM)
	for read := 4; read < 64; read++ {
		staleVMDetails[read] = sdk.VM{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}
	}
	api := &detailSequenceAPI{
		fakeAPI: base, stripListStorage: true,
		// Resolve and the final pre-dispatch VM read are canonical. After the
		// POST, ListVMs exposes the attachment but exact GetVM remains stale.
		vmOverride: staleVMDetails,
	}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
	adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("stale exact attach readback error = %v, want ErrUnavailable", err)
	}
	if base.attachCalls != 1 {
		t.Fatalf("AttachDisk calls = %d, want 1", base.attachCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence == nil {
		t.Fatalf("stale exact readback completed durable fence: fence=%#v err=%v", fence, err)
	}

	// On restart, exact detail has converged while the list storage remains
	// stale-negative. The retained fence completes without another POST.
	restarted := newFencedAdapter(t, &staleAttachmentListAPI{fakeAPI: base}, resolver, time.Second)
	if err := restarted.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if base.attachCalls != 1 {
		t.Fatalf("restarted split-view attach calls = %d, want 1", base.attachCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("restarted split-view fence = %#v, err=%v", fence, err)
	}
}

func TestAttachFalsePositiveVMListCannotCompleteFence(t *testing.T) {
	base := &fakeAPI{
		disks:                []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
		vms:                  []sdk.VM{{UUID: testVM1, BillingAccountID: 42}},
		suppressAttachCommit: true,
		attachMutationError: &sdk.APIError{
			StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "uncommitted error", Retryable: true,
		},
	}
	api := &detailSequenceAPI{fakeAPI: base, forceListStorage: true}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
	if err := newFencedAdapter(t, api, resolver, 8*time.Millisecond).AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("false-positive list attach error = %v, want ErrUnavailable", err)
	}
	if base.attachCalls != 1 {
		t.Fatalf("AttachDisk calls = %d, want 1", base.attachCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence == nil {
		t.Fatalf("false-positive list completed durable fence: fence=%#v err=%v", fence, err)
	}
}

func TestStaleNegativeVMListUsesExactDetailsForDeleteAttachAndDetach(t *testing.T) {
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	attachedVM := sdk.VM{
		UUID: testVM1, BillingAccountID: 42,
		Storage: []sdk.VMStorage{{UUID: testDiskID}},
	}

	t.Run("delete", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base}
		if err := newFencedAdapter(t, api, nil, time.Second).DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
			t.Fatalf("DeleteVolume stale-negative error = %v, want ErrVolumeAttachedElsewhere", err)
		}
		if base.deleteCalls != 0 {
			t.Fatalf("stale-negative list caused %d DeleteDisk call(s)", base.deleteCalls)
		}
	})

	t.Run("attach", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base}
		adapter := newFencedAdapter(t, api, nodeResolver{
			"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		}, time.Second)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
			t.Fatal(err)
		}
		if base.attachCalls != 0 {
			t.Fatalf("stale-negative list caused %d duplicate AttachDisk call(s)", base.attachCalls)
		}
	})

	t.Run("detach", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base}
		if err := newFencedAdapter(t, api, nil, time.Second).DetachVolume(context.Background(), testLocation, testDiskID, ""); err != nil {
			t.Fatal(err)
		}
		if base.detachCalls != 1 || len(base.vms[0].Storage) != 0 {
			t.Fatalf("stale-negative detach calls=%d storage=%#v", base.detachCalls, base.vms[0].Storage)
		}
	})
}

func TestNetworkMembershipCannotReplaceMissingUnfilteredVMIdentity(t *testing.T) {
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	attachedVM := sdk.VM{
		UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork,
		Storage: []sdk.VMStorage{{UUID: testDiskID}},
	}

	t.Run("delete", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base, omitVMs: true}
		if err := newFencedNetworkAdapter(t, api, nil, time.Second).DeleteVolume(context.Background(), testLocation, testDiskID); err == nil {
			t.Fatal("DeleteVolume accepted VPC membership without an unfiltered VM identity row")
		}
		if base.deleteCalls != 0 {
			t.Fatalf("omitted VM caused %d DeleteDisk call(s)", base.deleteCalls)
		}
	})

	t.Run("attach", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base, omitVMs: true}
		adapter := newFencedNetworkAdapter(t, api, nodeResolver{
			"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		}, time.Second)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
			t.Fatalf("already-attached read-only convergence failed: %v", err)
		}
		if base.attachCalls != 0 {
			t.Fatalf("omitted VM caused %d duplicate AttachDisk call(s)", base.attachCalls)
		}
	})

	t.Run("detach", func(t *testing.T) {
		base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{attachedVM}}
		api := &staleAttachmentListAPI{fakeAPI: base, omitVMs: true}
		if err := newFencedNetworkAdapter(t, api, nil, time.Second).DetachVolume(context.Background(), testLocation, testDiskID, ""); err == nil {
			t.Fatal("DetachVolume accepted VPC membership without an unfiltered VM identity row")
		}
		if base.detachCalls != 0 || len(base.vms[0].Storage) != 1 {
			t.Fatalf("omitted VM changed detach state: calls=%d storage=%#v", base.detachCalls, base.vms[0].Storage)
		}
	})
}

func TestAttachmentOutsideConfiguredVPCBlocksEveryMutation(t *testing.T) {
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	target := sdk.VM{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}
	external := sdk.VM{
		UUID: testVM2, BillingAccountID: 42, NetworkUUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Storage: []sdk.VMStorage{{UUID: testDiskID}},
	}
	newAPI := func() *fakeAPI {
		return &fakeAPI{
			disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{target, external},
			networkVMUUIDs: []string{testVM1}, preserveVMNetwork: true,
		}
	}
	t.Run("delete", func(t *testing.T) {
		api := newAPI()
		if err := newFencedNetworkAdapter(t, api, nil, time.Second).DeleteVolume(context.Background(), testLocation, testDiskID); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
			t.Fatalf("outside-VPC delete error = %v, want ErrVolumeAttachedElsewhere", err)
		}
		if api.deleteCalls != 0 {
			t.Fatalf("outside-VPC attachment caused %d DeleteDisk call(s)", api.deleteCalls)
		}
	})
	t.Run("attach", func(t *testing.T) {
		api := newAPI()
		adapter := newFencedNetworkAdapter(t, api, nodeResolver{
			"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		}, time.Second)
		if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
			t.Fatalf("outside-VPC attach error = %v, want ErrVolumeAttachedElsewhere", err)
		}
		if api.attachCalls != 0 {
			t.Fatalf("outside-VPC attachment caused %d AttachDisk call(s)", api.attachCalls)
		}
	})
	t.Run("detach", func(t *testing.T) {
		api := newAPI()
		if err := newFencedNetworkAdapter(t, api, nil, time.Second).DetachVolume(context.Background(), testLocation, testDiskID, ""); !errors.Is(err, cloud.ErrVolumeAttachedElsewhere) {
			t.Fatalf("outside-VPC detach error = %v, want ErrVolumeAttachedElsewhere", err)
		}
		if api.detachCalls != 0 {
			t.Fatalf("outside-VPC attachment caused %d DetachDisk call(s)", api.detachCalls)
		}
	})
}

func TestNetworkInventoryHTTPErrorNeverMutates(t *testing.T) {
	networkErr := &sdk.APIError{StatusCode: 500, Method: "GET", Path: "/network/network/" + testNetwork, Message: "transient", Retryable: true}
	ownedDisk := sdk.Disk{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}
	for _, operation := range []string{"delete", "attach", "detach"} {
		t.Run(operation, func(t *testing.T) {
			vm := sdk.VM{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}
			if operation == "detach" {
				vm.Storage = []sdk.VMStorage{{UUID: testDiskID}}
			}
			base := &fakeAPI{disks: []sdk.Disk{ownedDisk}, vms: []sdk.VM{vm}, networkError: networkErr}
			adapter := newFencedNetworkAdapter(t, base, nodeResolver{
				"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
			}, 10*time.Millisecond)
			var err error
			switch operation {
			case "delete":
				err = adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
			case "attach":
				err = adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
			case "detach":
				err = adapter.DetachVolume(context.Background(), testLocation, testDiskID, "")
			}
			if !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("%s network inventory error = %v, want ErrUnavailable", operation, err)
			}
			if base.deleteCalls != 0 || base.attachCalls != 0 || base.detachCalls != 0 {
				t.Fatalf("%s network error caused mutations delete=%d attach=%d detach=%d", operation, base.deleteCalls, base.attachCalls, base.detachCalls)
			}
		})
	}
}

func TestAttachCommittedHTTP500ConvergesThroughExactVMWhenListStorageIsStale(t *testing.T) {
	base := &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}},
		vms:   []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}},
		attachMutationError: &sdk.APIError{
			StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "committed response lost", Retryable: true,
		},
	}
	api := &staleAttachmentListAPI{fakeAPI: base}
	store := newMemoryMutationFenceStore()
	resolver := &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
	if err := newFencedNetworkAdapter(t, api, resolver, time.Second).AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the adapter to prove the converged fence cannot cause a replay.
	if err := newFencedNetworkAdapter(t, api, resolver, time.Second).AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if base.attachCalls != 1 {
		t.Fatalf("committed HTTP 500 attach calls = %d, want 1", base.attachCalls)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("converged attach fence = %#v, err=%v", fence, err)
	}
}

func apiNotFound(resource string) error {
	return &sdk.APIError{StatusCode: 404, Method: "GET", Path: resource, Message: "not found"}
}

var _ API = (*fakeAPI)(nil)
var _ API = (*detailSequenceAPI)(nil)
var _ API = (*staleAttachmentListAPI)(nil)
