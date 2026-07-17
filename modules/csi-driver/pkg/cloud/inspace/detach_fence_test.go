package inspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

type detachReadStep struct {
	list string
	get  string
}

// detachFenceAPI is a synchronized cloud double whose post-DetachDisk
// ListVMs/GetVM pairs can model independent eventual-consistency failures.
// Pre-dispatch reads always expose its actual attachment state.
type detachFenceAPI struct {
	mu           sync.Mutex
	attached     bool
	detachCommit bool
	detachErr    error
	detachCalls  int
	issued       bool
	steps        []detachReadStep
	step         int
}

func (a *detachFenceAPI) CreateDisk(context.Context, string, sdk.CreateDiskRequest) (*sdk.Disk, error) {
	return nil, errors.New("unexpected CreateDisk")
}

func (a *detachFenceAPI) GetDisk(context.Context, string, string) (*sdk.Disk, error) {
	return &sdk.Disk{
		UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42,
		Snapshots: []sdk.DiskSnapshot{},
	}, nil
}

func (a *detachFenceAPI) ListDisks(context.Context, string) ([]sdk.Disk, error) {
	return []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc", SizeGiB: 1, Status: "Active", BillingAccountID: 42}}, nil
}

func (a *detachFenceAPI) DeleteDisk(context.Context, string, string) error {
	return errors.New("unexpected DeleteDisk")
}

func (a *detachFenceAPI) ListVMs(context.Context, string) ([]sdk.VM, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	mode := a.actualModeLocked()
	if a.issued && a.step < len(a.steps) {
		mode = a.steps[a.step].list
	}
	return detachVMList(mode)
}

func (a *detachFenceAPI) GetVM(_ context.Context, _ string, id string) (*sdk.VM, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id != testVM1 {
		return &sdk.VM{UUID: id, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{}}, nil
	}
	mode := a.actualModeLocked()
	if a.issued && a.step < len(a.steps) {
		mode = a.steps[a.step].get
		a.step++
	}
	return detachExactVM(mode, id)
}

func (a *detachFenceAPI) GetNetwork(context.Context, string, string) (*sdk.Network, error) {
	return &sdk.Network{UUID: testNetwork, VMUUIDs: []string{testVM1, testVM2}}, nil
}

func (a *detachFenceAPI) AttachDisk(context.Context, string, string, string) (*sdk.VMStorage, error) {
	return nil, errors.New("unexpected AttachDisk")
}

func (a *detachFenceAPI) DetachDisk(_ context.Context, _ string, vmID, diskID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vmID != testVM1 || diskID != testDiskID {
		return fmt.Errorf("unexpected detach identity %s/%s", vmID, diskID)
	}
	a.detachCalls++
	a.issued = true
	if a.detachCommit {
		a.attached = false
	}
	return a.detachErr
}

func (a *detachFenceAPI) actualModeLocked() string {
	if a.attached {
		return "present"
	}
	return "absent"
}

func (a *detachFenceAPI) setSteps(steps ...detachReadStep) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.steps = append([]detachReadStep(nil), steps...)
	a.step = 0
}

func (a *detachFenceAPI) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.detachCalls
}

func detachVMList(mode string) ([]sdk.VM, error) {
	switch mode {
	case "present":
		return []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{{UUID: testDiskID}}}}, nil
	case "absent", "not-found", "empty":
		return []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}}, nil
	case "other":
		return []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork}, {UUID: testVM2, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{{UUID: testDiskID}}}}, nil
	case "duplicate":
		return []sdk.VM{{UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{{UUID: testDiskID}, {UUID: testDiskID}}}}, nil
	case "error":
		return nil, errors.New("injected ListVMs failure")
	default:
		return nil, fmt.Errorf("unknown ListVMs mode %q", mode)
	}
}

func detachExactVM(mode, id string) (*sdk.VM, error) {
	switch mode {
	case "present":
		return &sdk.VM{UUID: id, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{{UUID: testDiskID}}}, nil
	case "absent":
		return &sdk.VM{UUID: id, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{}}, nil
	case "omitted":
		return &sdk.VM{UUID: id, BillingAccountID: 42, NetworkUUID: testNetwork}, nil
	case "not-found":
		return nil, exactAPINotFound("VM", id)
	case "empty":
		return nil, nil
	case "mismatch":
		return &sdk.VM{UUID: testVM2, BillingAccountID: 42, NetworkUUID: testNetwork}, nil
	case "duplicate":
		return &sdk.VM{UUID: id, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{{UUID: testDiskID}, {UUID: testDiskID}}}, nil
	case "error":
		return nil, errors.New("injected GetVM failure")
	default:
		return nil, fmt.Errorf("unknown GetVM mode %q", mode)
	}
}

func detachFenceResolver(store *memoryMutationFenceStore) *fencedNodeResolver {
	return &fencedNodeResolver{
		nodeResolver:             nodeResolver{"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1)},
		memoryMutationFenceStore: store,
	}
}

func TestDetachAbsenceNeedsListAndExactGetAndReappearanceClearsOnlyObservation(t *testing.T) {
	api := &detachFenceAPI{
		attached: true, detachCommit: false,
		detachErr: &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/detach", Message: "ambiguous", Retryable: true},
		steps: []detachReadStep{
			// A transient ListVMs omission is rejected by exact GetVM.
			{list: "absent", get: "present"},
			// One corroborated absence becomes durable but is insufficient.
			{list: "absent", get: "absent"},
			// Visibility again invalidates only the absence evidence.
			{list: "present", get: "present"},
		},
	}
	store := newMemoryMutationFenceStore()
	adapter := newFencedAdapter(t, api, detachFenceResolver(store), 12*time.Millisecond)
	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
	if !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("ambiguous detach error = %v, want ErrUnavailable", err)
	}
	if api.calls() != 1 {
		t.Fatalf("DetachDisk calls = %d, want 1", api.calls())
	}
	fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID))
	if err != nil || fence == nil {
		t.Fatalf("retained detach fence = %#v, err=%v", fence, err)
	}
	if fence.Observation != "" {
		t.Fatalf("reappearing attachment did not clear only absence observation: %#v", fence)
	}
	if fence.Attempt == "" {
		t.Fatal("reappearing attachment cleared immutable issue authority")
	}
}

func TestDetachCommittedHTTP500EmptyReadbackAndRestartNeverReplay(t *testing.T) {
	api := &detachFenceAPI{
		attached: true, detachCommit: true,
		detachErr: &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/detach", Message: "committed response lost", Retryable: true},
		steps: []detachReadStep{
			{list: "present", get: "present"},
			{list: "absent", get: "empty"},
		},
	}
	store := newMemoryMutationFenceStore()
	resolver := detachFenceResolver(store)
	first := newFencedAdapter(t, api, resolver, 25*time.Millisecond)
	if err := first.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "empty VM") {
		t.Fatalf("first ambiguous detach error = %v", err)
	}
	if api.calls() != 1 {
		t.Fatalf("first DetachDisk calls = %d, want 1", api.calls())
	}

	// Reconstruct the adapter while retaining the production-equivalent Lease.
	// A short readback can persist only observation one; it must not complete.
	api.setSteps(detachReadStep{list: "absent", get: "not-found"})
	second := newFencedAdapter(t, api, resolver, 4*time.Millisecond)
	second.poll = 20 * time.Millisecond
	if err := second.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("single durable absence error = %v, want ErrUnavailable", err)
	}
	fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID))
	if err != nil || fence == nil {
		t.Fatalf("single-observation fence = %#v, err=%v", fence, err)
	}
	observation, err := decodeMutationObservation(fence.Observation)
	if err != nil || observation.Count != 1 {
		t.Fatalf("durable first observation = %#v, err=%v", observation, err)
	}

	api.setSteps(
		detachReadStep{list: "absent", get: "absent"},
		detachReadStep{list: "absent", get: "not-found"},
	)
	third := newFencedAdapter(t, api, resolver, time.Second)
	third.poll = 20 * time.Millisecond
	if err := third.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatal(err)
	}
	if api.calls() != 1 {
		t.Fatalf("ambiguous committed DetachDisk replayed: calls=%d", api.calls())
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("completed detach fence = %#v, err=%v", fence, err)
	}
}

func TestDetachCommittedHTTP500OmittedStorageRetainsDurableFence(t *testing.T) {
	steps := make([]detachReadStep, 128)
	for index := range steps {
		steps[index] = detachReadStep{list: "absent", get: "omitted"}
	}
	api := &detachFenceAPI{
		attached: true, detachCommit: true,
		detachErr: &sdk.APIError{
			StatusCode: 500, Method: "POST", Path: "/storage/detach",
			Message: "committed response lost", Retryable: true,
		},
		steps: steps,
	}
	store := newMemoryMutationFenceStore()
	resolver := detachFenceResolver(store)
	adapter := newFencedAdapter(t, api, resolver, 8*time.Millisecond)

	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
	if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "omitted storage") {
		t.Fatalf("omitted-storage detach error = %v", err)
	}
	if api.calls() != 1 {
		t.Fatalf("DetachDisk calls = %d, want 1", api.calls())
	}
	fence, getErr := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID))
	if getErr != nil || fence == nil {
		t.Fatalf("omitted-storage durable fence = %#v, err=%v", fence, getErr)
	}
	if fence.Attempt == "" {
		t.Fatal("omitted-storage readback cleared immutable issue authority")
	}
}

func TestDetachConcurrentControllersShareOneIssueAuthority(t *testing.T) {
	api := &detachFenceAPI{attached: true, detachCommit: true}
	store := newMemoryMutationFenceStore()
	resolver := detachFenceResolver(store)
	first := newFencedAdapter(t, api, resolver, time.Second)
	second := newFencedAdapter(t, api, resolver, time.Second)

	start := make(chan struct{})
	errorsByController := make(chan error, 2)
	for _, adapter := range []*Adapter{first, second} {
		go func(adapter *Adapter) {
			<-start
			errorsByController <- adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		}(adapter)
	}
	close(start)
	for range 2 {
		if err := <-errorsByController; err != nil {
			t.Fatalf("concurrent detach error = %v", err)
		}
	}
	if api.calls() != 1 {
		t.Fatalf("concurrent DetachDisk calls = %d, want 1", api.calls())
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("concurrent completed fence = %#v, err=%v", fence, err)
	}
}

func TestDetachMalformedObservationFailsClosed(t *testing.T) {
	api := &detachFenceAPI{attached: false, detachCommit: true, issued: true}
	store := newMemoryMutationFenceStore()
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: testLocation, DiskUUID: testDiskID, BillingAccountID: 42, PreviousVMUUID: testVM1,
	}
	fence, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
	if err != nil {
		t.Fatal(err)
	}
	fence.Observation = `{"kind":"disk-detach-absence","count":2,"firstObservedAt":"2026-07-17T00:00:00Z"}`
	store.fences[fence.Key] = fence
	adapter := newFencedAdapter(t, api, detachFenceResolver(store), 20*time.Millisecond)
	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err == nil || !strings.Contains(err.Error(), "last-observation timestamp") {
		t.Fatalf("malformed observation error = %v", err)
	}
	if api.calls() != 0 {
		t.Fatalf("malformed observation authorized %d DetachDisk call(s)", api.calls())
	}
	retained, getErr := store.Get(context.Background(), fence.Key)
	if getErr != nil || retained == nil || retained.Attempt != fence.Attempt {
		t.Fatalf("malformed observation fence was not retained: %#v, err=%v", retained, getErr)
	}
}

func TestDetachErrMutationBlockedIsOnlyPostDispatchErrorThatClearsFence(t *testing.T) {
	api := &detachFenceAPI{attached: true, detachErr: sdk.ErrMutationBlocked}
	store := newMemoryMutationFenceStore()
	adapter := newFencedAdapter(t, api, detachFenceResolver(store), 20*time.Millisecond)
	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
	if !errors.Is(err, sdk.ErrMutationBlocked) {
		t.Fatalf("locally blocked detach error = %v", err)
	}
	if fence, err := store.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); err != nil || fence != nil {
		t.Fatalf("locally blocked unissued fence = %#v, err=%v", fence, err)
	}
}

var _ API = (*detachFenceAPI)(nil)
