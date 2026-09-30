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

// busyVMAPI models the live InSpace contract that only one storage mutation
// per VM is accepted at a time: while an attach or detach POST for a VM is in
// flight, another POST for the same VM fails. Each mutation takes hold to
// complete so overlapping callers are guaranteed to collide. All state is
// guarded by mu; the fake behind it is not goroutine-safe on its own.
type busyVMAPI struct {
	mu    sync.Mutex
	inner *fakeAPI
	hold  time.Duration

	inFlight      map[string]int
	peakPerVM     map[string]int
	inFlightAll   int
	peakAll       int
	rejected      int
	attachPosts   int
	detachPosts   int
	resizePatches int
	mutationSeen  map[string]int
}

func newBusyVMAPI(inner *fakeAPI, hold time.Duration) *busyVMAPI {
	return &busyVMAPI{
		inner: inner, hold: hold,
		inFlight: map[string]int{}, peakPerVM: map[string]int{}, mutationSeen: map[string]int{},
	}
}

func (b *busyVMAPI) CreateDisk(ctx context.Context, loc string, req sdk.CreateDiskRequest) (*sdk.Disk, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.CreateDisk(ctx, loc, req)
}

func (b *busyVMAPI) GetDisk(ctx context.Context, loc, id string) (*sdk.Disk, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.GetDisk(ctx, loc, id)
}

func (b *busyVMAPI) ListDisks(ctx context.Context, loc string) ([]sdk.Disk, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.ListDisks(ctx, loc)
}

func (b *busyVMAPI) DeleteDisk(ctx context.Context, loc, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.DeleteDisk(ctx, loc, id)
}

func (b *busyVMAPI) ListVMs(ctx context.Context, loc string) ([]sdk.VM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.ListVMs(ctx, loc)
}

func (b *busyVMAPI) GetVM(ctx context.Context, loc, id string) (*sdk.VM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.GetVM(ctx, loc, id)
}

func (b *busyVMAPI) GetNetwork(ctx context.Context, loc, id string) (*sdk.Network, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inner.GetNetwork(ctx, loc, id)
}

func (b *busyVMAPI) ResizeAttachedDisk(ctx context.Context, loc, vm, disk string, size int) (*sdk.VMStorage, error) {
	busy := b.enter(vm)
	defer b.leave(vm)
	time.Sleep(b.hold)
	if busy {
		return nil, &sdk.APIError{StatusCode: 500, Method: "PATCH", Path: "/storage/resize", Message: "VM is busy", Retryable: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resizePatches++
	return b.inner.ResizeAttachedDisk(ctx, loc, vm, disk, size)
}

// enter registers one in-flight mutation POST and reports whether the VM was
// already busy.
func (b *busyVMAPI) enter(vm string) (busy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inFlight[vm]++
	b.inFlightAll++
	if b.inFlight[vm] > b.peakPerVM[vm] {
		b.peakPerVM[vm] = b.inFlight[vm]
	}
	if b.inFlightAll > b.peakAll {
		b.peakAll = b.inFlightAll
	}
	if b.inFlight[vm] > 1 {
		b.rejected++
		return true
	}
	return false
}

func (b *busyVMAPI) leave(vm string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inFlight[vm]--
	b.inFlightAll--
}

func (b *busyVMAPI) AttachDisk(ctx context.Context, loc, vm, disk string) (*sdk.VMStorage, error) {
	busy := b.enter(vm)
	defer b.leave(vm)
	time.Sleep(b.hold)
	if busy {
		return nil, &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/attach", Message: "VM is busy", Retryable: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attachPosts++
	return b.inner.AttachDisk(ctx, loc, vm, disk)
}

func (b *busyVMAPI) DetachDisk(ctx context.Context, loc, vm, disk string) error {
	busy := b.enter(vm)
	defer b.leave(vm)
	time.Sleep(b.hold)
	if busy {
		return &sdk.APIError{StatusCode: 500, Method: "POST", Path: "/storage/detach", Message: "VM is busy", Retryable: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.detachPosts++
	return b.inner.DetachDisk(ctx, loc, vm, disk)
}

func (b *busyVMAPI) stats() (peakVM1, peakVM2, peakAll, rejected int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peakPerVM[testVM1], b.peakPerVM[testVM2], b.peakAll, b.rejected
}

func serializationDiskID(n int) string {
	return fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", n)
}

func newSerializationFixture(t *testing.T, disksPerVM int) (*busyVMAPI, *Adapter, []string) {
	t.Helper()
	inner := &fakeAPI{vms: []sdk.VM{{UUID: testVM1}, {UUID: testVM2}}}
	var ids []string
	for i := 0; i < disksPerVM*2; i++ {
		id := serializationDiskID(i)
		ids = append(ids, id)
		inner.disks = append(inner.disks, sdk.Disk{UUID: id, DisplayName: fmt.Sprintf("pvc-%d", i), SizeGiB: 1})
	}
	api := newBusyVMAPI(inner, 25*time.Millisecond)
	resolver := nodeResolver{
		"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
		"worker-2": fmt.Sprintf("inspace://%s/%s", testLocation, testVM2),
	}
	adapter, err := New(api, resolver, Config{
		Location: testLocation, NetworkUUID: testNetwork, BillingAccountID: 42,
		PollInterval: time.Millisecond, MutationReadbackTimeout: 5 * time.Second,
		DestructiveAbsenceInterval: time.Millisecond, DestructiveReadbackTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api, adapter, ids
}

func runConcurrently(n int, fn func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func TestConcurrentAttachesToOneVMAreSerialized(t *testing.T) {
	api, adapter, ids := newSerializationFixture(t, 5)
	// Five disks all target worker-1 at once, as when several PVCs of pods on
	// one node are published together.
	errs := runConcurrently(5, func(i int) error {
		return adapter.AttachVolume(context.Background(), testLocation, ids[i], "worker-1")
	})
	for i, err := range errs {
		if err != nil {
			t.Errorf("attach of disk %d: %v", i, err)
		}
	}
	peak1, _, _, rejected := api.stats()
	if peak1 != 1 || rejected != 0 {
		t.Fatalf("attach POSTs in flight for one VM: peak=%d rejected=%d, want 1 and 0", peak1, rejected)
	}
	if api.attachPosts != 5 {
		t.Fatalf("attach POSTs = %d, want 5", api.attachPosts)
	}
	if fences, err := adapter.fences.List(context.Background(), ""); err != nil || len(fences) != 0 {
		t.Fatalf("residual fences after serialized attaches: %#v err=%v", fences, err)
	}
	if n := adapter.vmLocks.size(); n != 0 {
		t.Fatalf("VM lock entries left behind = %d", n)
	}
}

func TestConcurrentAttachesToDifferentVMsOverlap(t *testing.T) {
	api, adapter, ids := newSerializationFixture(t, 3)
	errs := runConcurrently(6, func(i int) error {
		node := "worker-1"
		if i%2 == 1 {
			node = "worker-2"
		}
		return adapter.AttachVolume(context.Background(), testLocation, ids[i], node)
	})
	for i, err := range errs {
		if err != nil {
			t.Errorf("attach of disk %d: %v", i, err)
		}
	}
	peak1, peak2, peakAll, rejected := api.stats()
	if peak1 != 1 || peak2 != 1 || rejected != 0 {
		t.Fatalf("per-VM peaks = %d/%d rejected=%d, want 1/1 and 0", peak1, peak2, rejected)
	}
	if peakAll < 2 {
		t.Fatalf("attach POSTs for different VMs never overlapped (peak total %d)", peakAll)
	}
}

func TestConcurrentDetachesFromOneVMAreSerialized(t *testing.T) {
	api, adapter, ids := newSerializationFixture(t, 4)
	for i := 0; i < 4; i++ {
		if err := adapter.AttachVolume(context.Background(), testLocation, ids[i], "worker-1"); err != nil {
			t.Fatal(err)
		}
	}
	errs := runConcurrently(4, func(i int) error {
		return adapter.DetachVolume(context.Background(), testLocation, ids[i], "worker-1")
	})
	for i, err := range errs {
		if err != nil {
			t.Errorf("detach of disk %d: %v", i, err)
		}
	}
	peak1, _, _, rejected := api.stats()
	if peak1 != 1 || rejected != 0 {
		t.Fatalf("detach POSTs in flight for one VM: peak=%d rejected=%d, want 1 and 0", peak1, rejected)
	}
	if api.detachPosts != 4 {
		t.Fatalf("detach POSTs = %d, want 4", api.detachPosts)
	}
	if fences, err := adapter.fences.List(context.Background(), ""); err != nil || len(fences) != 0 {
		t.Fatalf("residual fences after serialized detaches: %#v err=%v", fences, err)
	}
	if n := adapter.vmLocks.size(); n != 0 {
		t.Fatalf("VM lock entries left behind = %d", n)
	}
}

func TestVMLockWaitHonorsContextCancellation(t *testing.T) {
	api, adapter, ids := newSerializationFixture(t, 1)
	// Hold the VM lock as an in-flight mutation would.
	unlock, err := adapter.vmLocks.Lock(context.Background(), strings.ToLower(testVM1))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(30*time.Millisecond, cancel)
	err = adapter.AttachVolume(ctx, testLocation, ids[0], "worker-1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("attach waiting on a held VM lock = %v, want context.Canceled", err)
	}
	if errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("context error must not be remapped: %v", err)
	}
	unlock()
	if api.attachPosts != 0 {
		t.Fatalf("attach POST issued while the VM lock was held: %d", api.attachPosts)
	}
	// The abandoned waiter must leave no fence and no lock behind.
	if err := adapter.AttachVolume(context.Background(), testLocation, ids[0], "worker-1"); err != nil {
		t.Fatalf("attach after canceled waiter: %v", err)
	}
}

// countingFenceStore records how many fences a call created.
type countingFenceStore struct {
	mutationFenceStore
	mu      sync.Mutex
	creates int
}

func (s *countingFenceStore) Create(ctx context.Context, fence mutationFence) (*mutationFence, bool, error) {
	s.mu.Lock()
	s.creates++
	s.mu.Unlock()
	return s.mutationFenceStore.Create(ctx, fence)
}

func (s *countingFenceStore) created() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creates
}

// A queued caller may wait only for the part of its deadline that exceeds the
// dispatch reserve. Past that it must fail retryably, at once, with no fence.
func TestVMLockWaitIsCappedByDispatchReserve(t *testing.T) {
	for _, operation := range []string{"attach", "detach"} {
		t.Run(operation, func(t *testing.T) {
			api, adapter, ids := newSerializationFixture(t, 1)
			if operation == "detach" {
				if err := adapter.AttachVolume(context.Background(), testLocation, ids[0], "worker-1"); err != nil {
					t.Fatal(err)
				}
			}
			store := &countingFenceStore{mutationFenceStore: adapter.fences}
			adapter.fences = store
			attachPosts, detachPosts := api.attachPosts, api.detachPosts

			unlock, err := adapter.vmLocks.Lock(context.Background(), strings.ToLower(testVM1))
			if err != nil {
				t.Fatal(err)
			}
			// 100ms of waiting budget remain above the reserve.
			ctx, cancel := context.WithTimeout(context.Background(), minimumMutationDispatchReserve+100*time.Millisecond)
			defer cancel()
			started := time.Now()
			if operation == "attach" {
				err = adapter.AttachVolume(ctx, testLocation, ids[0], "worker-1")
			} else {
				err = adapter.DetachVolume(ctx, testLocation, ids[0], "worker-1")
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("queued caller waited %s; wait must stop at the dispatch reserve", elapsed)
			}
			if !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("error = %v, want retryable ErrUnavailable", err)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				t.Fatalf("lock wait must not surface the parent context: err=%v ctx=%v", err, ctx.Err())
			}
			if store.created() != 0 {
				t.Fatalf("queued caller created %d fence(s) before holding the VM lock", store.created())
			}
			if api.attachPosts != attachPosts || api.detachPosts != detachPosts {
				t.Fatal("queued caller issued a cloud mutation")
			}
			unlock()
			if n := adapter.vmLocks.size(); n != 0 {
				t.Fatalf("VM lock entries left behind = %d", n)
			}
			if fences, err := adapter.fences.List(context.Background(), ""); err != nil || len(fences) != 0 {
				t.Fatalf("residual fences: %#v err=%v", fences, err)
			}
		})
	}
}

// A caller whose deadline already lacks the reserve fails before creating a
// fence even when the VM lock is free.
func TestVMLockedMutationChecksReserveBeforeFence(t *testing.T) {
	for _, operation := range []string{"attach", "detach"} {
		t.Run(operation, func(t *testing.T) {
			api, adapter, ids := newSerializationFixture(t, 1)
			if operation == "detach" {
				if err := adapter.AttachVolume(context.Background(), testLocation, ids[0], "worker-1"); err != nil {
					t.Fatal(err)
				}
			}
			store := &countingFenceStore{mutationFenceStore: adapter.fences}
			adapter.fences = store
			attachPosts, detachPosts := api.attachPosts, api.detachPosts
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var err error
			if operation == "attach" {
				err = adapter.AttachVolume(ctx, testLocation, ids[0], "worker-1")
			} else {
				err = adapter.DetachVolume(ctx, testLocation, ids[0], "worker-1")
			}
			if !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
			if store.created() != 0 {
				t.Fatalf("created %d fence(s) without the dispatch reserve", store.created())
			}
			if api.attachPosts != attachPosts || api.detachPosts != detachPosts {
				t.Fatal("cloud mutation issued without the dispatch reserve")
			}
			if n := adapter.vmLocks.size(); n != 0 {
				t.Fatalf("VM lock entries left behind = %d", n)
			}
		})
	}
}

func TestExpandAndAttachToOneVMNeverOverlap(t *testing.T) {
	api, adapter, ids := newSerializationFixture(t, 2)
	if err := adapter.AttachVolume(context.Background(), testLocation, ids[0], "worker-1"); err != nil {
		t.Fatal(err)
	}
	errs := runConcurrently(3, func(i int) error {
		if i == 0 {
			_, err := adapter.ExpandVolume(context.Background(), testLocation, ids[0], 2*gib)
			return err
		}
		return adapter.AttachVolume(context.Background(), testLocation, ids[i], "worker-1")
	})
	for i, err := range errs {
		if err != nil {
			t.Errorf("operation %d: %v", i, err)
		}
	}
	peak1, _, _, rejected := api.stats()
	if peak1 != 1 || rejected != 0 {
		t.Fatalf("mutations in flight for one VM: peak=%d rejected=%d, want 1 and 0", peak1, rejected)
	}
	if api.resizePatches != 1 {
		t.Fatalf("resize PATCHes = %d, want 1", api.resizePatches)
	}
	if n := adapter.vmLocks.size(); n != 0 {
		t.Fatalf("VM lock entries left behind = %d", n)
	}
}
