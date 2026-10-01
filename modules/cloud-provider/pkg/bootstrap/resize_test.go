package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const resizeTestUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"

// resizeAPI is a one-VM double of the InSpace compute routes. Stop and start
// settle after a few status reads, like the real asynchronous transitions.
type resizeAPI struct {
	mu           sync.Mutex
	vm           inspace.VM
	calls        []string
	stopErr      error
	startErr     error
	neverStop    bool
	ignoreUpdate bool
	settleReads  int
	pending      string
	pendingLeft  int

	// dropStops accepts that many stop requests without any state change.
	dropStops int
	// resendErr is what every stop request after the first returns.
	resendErr error
	// updateErr fails the PATCH; updateCommits applies the resize anyway.
	updateErr     error
	updateCommits bool
	// hideIPReads blanks the private address of that many running VM reads.
	hideIPReads int
}

func resizeDescription(owner string, slot int) string {
	return fmt.Sprintf("inspace-rke2-cp/v9 owner=%s slot=%d spec=%s", owner, slot, strings.Repeat("ab", 32))
}

func newResizeAPI(cluster string, slot int, owner, status string, vcpu, memoryMiB int) *resizeAPI {
	return &resizeAPI{vm: inspace.VM{
		UUID: resizeTestUUID, Name: controlPlaneName(cluster, slot), Status: status,
		VCPU: vcpu, MemoryMiB: memoryMiB, PrivateIPv4: "10.20.30.21", BillingAccountID: 42,
		Description: resizeDescription(owner, slot),
	}, settleReads: 2}
}

func (f *resizeAPI) ListVMs(context.Context, string) ([]inspace.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []inspace.VM{f.vm}, nil
}

func (f *resizeAPI) GetVM(_ context.Context, _, uuid string) (*inspace.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if uuid != f.vm.UUID {
		return nil, errors.New("unknown VM")
	}
	if f.pendingLeft > 0 {
		f.pendingLeft--
		if f.pendingLeft == 0 {
			f.vm.Status = f.pending
		}
	}
	copy := f.vm
	if f.hideIPReads > 0 && f.vm.Status == "running" {
		f.hideIPReads--
		copy.PrivateIPv4 = ""
	}
	return &copy, nil
}

func (f *resizeAPI) count(call string) int {
	n := 0
	for _, item := range f.calls {
		if item == call {
			n++
		}
	}
	return n
}

func (f *resizeAPI) StopVM(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stop")
	if n := f.count("stop"); n > 1 && f.resendErr != nil {
		return f.resendErr
	} else if n <= f.dropStops {
		return nil
	}
	f.vm.Status = "stopping"
	if !f.neverStop {
		f.pending, f.pendingLeft = "stopped", f.settleReads
	}
	return f.stopErr
}

func (f *resizeAPI) StartVM(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "start")
	f.vm.Status = "starting"
	f.pending, f.pendingLeft = "running", f.settleReads
	return f.startErr
}

func (f *resizeAPI) UpdateVMCompute(_ context.Context, _, _ string, vcpu, memoryMiB int) (*inspace.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "update")
	if resizeStatus(&f.vm) != "stopped" {
		return nil, &inspace.APIError{StatusCode: http.StatusUnprocessableEntity, Message: "VM must be stopped"}
	}
	if f.updateErr != nil {
		if f.updateCommits {
			f.vm.VCPU, f.vm.MemoryMiB = vcpu, memoryMiB
		}
		return nil, f.updateErr
	}
	copy := f.vm
	copy.VCPU, copy.MemoryMiB = vcpu, memoryMiB
	if !f.ignoreUpdate {
		f.vm = copy
	}
	return &copy, nil
}

func (f *resizeAPI) callList() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func testResizer(api ControlPlaneResizeAPI) *ControlPlaneResizer {
	return &ControlPlaneResizer{
		API: api, PollInterval: time.Millisecond, StopTimeout: 2 * time.Second, StartTimeout: 2 * time.Second,
		ResendInterval: time.Hour, IPTimeout: 50 * time.Millisecond,
	}
}

func resizeRequest() ControlPlaneResizeRequest {
	return ControlPlaneResizeRequest{Slot: 1, VCPU: 4, MemoryMiB: 6144, ExpectedPrivateIPv4: "10.20.30.21", ExpectedUUID: resizeTestUUID}
}

func TestResizeControlPlaneStopsResizesAndStartsARunningVM(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	// A graceful stop can block past the client timeout; status polling decides.
	api.stopErr = &url.Error{Op: "Post", URL: "https://api.invalid", Err: context.DeadlineExceeded}
	result, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callList(); got != "stop,update,start" {
		t.Fatalf("calls = %s, want stop,update,start", got)
	}
	if result.Action != ResizeActionResized || result.VCPU != 4 || result.MemoryMiB != 6144 || result.VMUUID != resizeTestUUID {
		t.Fatalf("result = %#v", result)
	}
	if api.vm.Status != "running" || api.vm.MemoryMiB != 6144 {
		t.Fatalf("VM after resize = %#v", api.vm)
	}
}

func TestResizeControlPlaneIsNoOpWhenRunningAtTarget(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 6144)
	result, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callList(); got != "" || result.Action != ResizeActionUnchanged {
		t.Fatalf("calls = %q result = %#v, want no mutation", got, result)
	}
}

func TestResizeControlPlaneResumesFromEveryInterruptedStage(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    string
		memoryMiB int
		want      string
	}{
		{name: "stopped at old size", status: "stopped", memoryMiB: 4096, want: "update,start"},
		{name: "stopped at target", status: "stopped", memoryMiB: 6144, want: "start"},
		{name: "starting at target", status: "starting", memoryMiB: 6144, want: ""},
		{name: "stopping at old size", status: "stopping", memoryMiB: 4096, want: "update,start"},
		{name: "shutoff at old size", status: "shutoff", memoryMiB: 4096, want: "update,start"},
		{name: "off at target", status: "off", memoryMiB: 6144, want: "start"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := testCluster()
			api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), test.status, 4, test.memoryMiB)
			switch test.status {
			case "starting":
				api.pending, api.pendingLeft = "running", 2
			case "stopping":
				api.pending, api.pendingLeft = "stopped", 2
			}
			result, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
			if err != nil {
				t.Fatal(err)
			}
			if got := api.callList(); got != test.want {
				t.Fatalf("calls = %q, want %q", got, test.want)
			}
			if api.vm.Status != "running" || api.vm.MemoryMiB != 6144 || result.MemoryMiB != 6144 {
				t.Fatalf("VM = %#v result = %#v", api.vm, result)
			}
		})
	}
}

func TestResizeControlPlaneCheckNeverMutates(t *testing.T) {
	cluster := testCluster()
	for _, test := range []struct {
		memoryMiB int
		want      string
	}{{4096, ResizeActionNeeded}, {6144, ResizeActionUnchanged}} {
		api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, test.memoryMiB)
		result, err := testResizer(api).Check(context.Background(), cluster, resizeRequest())
		if err != nil || result.Action != test.want || api.callList() != "" {
			t.Fatalf("Check(%d MiB) = %#v, %v calls=%q, want %s and no mutation", test.memoryMiB, result, err, api.callList(), test.want)
		}
	}
}

func TestResizeControlPlaneRefusesBeforeAnyMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*resizeAPI)
		request func(*ControlPlaneResizeRequest)
		want    string
	}{
		{name: "private IPv4 drift", mutate: func(a *resizeAPI) { a.vm.PrivateIPv4 = "10.20.30.99" }, want: "private IPv4"},
		{name: "running without a private IPv4", mutate: func(a *resizeAPI) { a.vm.PrivateIPv4 = "" }, want: "private IPv4"},
		{name: "stopped with another private IPv4", mutate: func(a *resizeAPI) { a.vm.Status, a.vm.PrivateIPv4 = "stopped", "10.20.30.99" }, want: "private IPv4"},
		{name: "foreign owner", mutate: func(a *resizeAPI) { a.vm.Description = resizeDescription("0123456789abcdef", 1) }, want: "ownership"},
		{name: "wrong slot record", mutate: func(a *resizeAPI) { a.vm.Description = resizeDescription(ownerKey(testCluster()), 2) }, want: "ownership"},
		{name: "missing record", mutate: func(a *resizeAPI) { a.vm.Description = "" }, want: "ownership"},
		{name: "wrong billing account", mutate: func(a *resizeAPI) { a.vm.BillingAccountID = 7 }, want: "billing"},
		{name: "memory shrink", mutate: func(a *resizeAPI) { a.vm.MemoryMiB = 8192 }, want: "shrink"},
		{name: "vcpu shrink", mutate: func(a *resizeAPI) { a.vm.VCPU = 8 }, want: "shrink"},
		{name: "deleted tombstone", mutate: func(a *resizeAPI) { a.vm.Status = "deleted" }, want: "deleted"},
		{name: "different VM UUID", request: func(r *ControlPlaneResizeRequest) { r.ExpectedUUID = "cccccccc-1111-4222-8333-bbbbbbbbbbbb" }, want: "UUID"},
		{name: "missing journaled UUID", request: func(r *ControlPlaneResizeRequest) { r.ExpectedUUID = "" }, want: "UUID"},
		{name: "slot out of range", request: func(r *ControlPlaneResizeRequest) { r.Slot = 3 }, want: "slot"},
		{name: "zero memory", request: func(r *ControlPlaneResizeRequest) { r.MemoryMiB = 0 }, want: "positive"},
		{name: "empty expected IPv4", request: func(r *ControlPlaneResizeRequest) { r.ExpectedPrivateIPv4 = "" }, want: "private IPv4"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := testCluster()
			api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
			if test.mutate != nil {
				test.mutate(api)
			}
			request := resizeRequest()
			if test.request != nil {
				test.request(&request)
			}
			_, err := testResizer(api).Resize(context.Background(), cluster, request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Resize() error = %v, want %q", err, test.want)
			}
			if got := api.callList(); got != "" {
				t.Fatalf("refused resize still mutated: %s", got)
			}
		})
	}
}

func TestResizeControlPlaneAcceptsAStoppedVMWithoutAPrivateIPv4ButRequiresItAfterStart(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.vm.PrivateIPv4 = ""
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err == nil {
		// The address returns once started; here the double never restores it.
		t.Fatal("Resize() accepted a started VM that never regained its private IPv4")
	}
	if got := api.callList(); got != "update,start" {
		t.Fatalf("calls = %q, want update,start", got)
	}
}

func TestResizeControlPlaneWaitsForThePrivateIPv4AfterStart(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.hideIPReads = 3
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err != nil {
		t.Fatalf("Resize() = %v, want the address to be awaited", err)
	}
	api = newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.hideIPReads = 1 << 20
	_, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "private IPv4") {
		t.Fatalf("Resize() error = %v, want a bounded wait for the private IPv4", err)
	}
}

func TestResizeControlPlaneNeverUpdatesAVMThatDoesNotStop(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.neverStop = true
	resizer := testResizer(api)
	resizer.StopTimeout = 30 * time.Millisecond
	_, err := resizer.Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("Resize() error = %v, want a stop timeout", err)
	}
	if got := api.callList(); strings.Contains(got, "update") || strings.Contains(got, "start") {
		t.Fatalf("calls = %s, want no update or start after a stop timeout", got)
	}
}

func TestResizeControlPlaneSendsStopOncePerTransition(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.settleReads = 8
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err != nil {
		t.Fatal(err)
	}
	if got := api.callList(); got != "stop,update,start" {
		t.Fatalf("calls = %s, want one stop and one start while the status settles", got)
	}
}

func TestResizeControlPlaneResendsAfterTheGracePeriodAndToleratesConflicts(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.dropStops = 1
	resizer := testResizer(api)
	resizer.ResendInterval = 10 * time.Millisecond
	if _, err := resizer.Resize(context.Background(), cluster, resizeRequest()); err != nil {
		t.Fatal(err)
	}
	if api.count("stop") < 2 {
		t.Fatalf("calls = %s, want a stop resent after the grace period", api.callList())
	}

	// A resend that meets a conflict is not fatal: the stop already took.
	api = newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.dropStops = 1
	api.resendErr = &inspace.APIError{StatusCode: http.StatusConflict, Message: "VM is stopping"}
	api.settleReads = 1
	resizer = testResizer(api)
	resizer.ResendInterval = 5 * time.Millisecond
	resizer.StopTimeout = 200 * time.Millisecond
	_, err := resizer.Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("Resize() error = %v, want polling to continue until the stop timeout", err)
	}
	if api.count("stop") < 3 {
		t.Fatalf("calls = %s, want repeated resends despite 409", api.callList())
	}
}

func TestResizeControlPlaneStartsTheVMAgainWhenThePatchIsRejected(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.updateErr = &inspace.APIError{StatusCode: http.StatusUnprocessableEntity, Message: "unsupported size"}
	_, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "unsupported size") {
		t.Fatalf("Resize() error = %v, want the PATCH rejection", err)
	}
	if got := api.callList(); got != "stop,update,start" {
		t.Fatalf("calls = %s, want the VM started again at its current size", got)
	}
	if api.vm.Status != "running" || api.vm.MemoryMiB != 4096 {
		t.Fatalf("VM = %#v, want running at the old size", api.vm)
	}
}

func TestResizeControlPlaneTrustsTheReadbackAfterAnAmbiguousPatchError(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.updateErr = &url.Error{Op: "Patch", URL: "https://api.invalid", Err: context.DeadlineExceeded}
	api.updateCommits = true
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err != nil {
		t.Fatalf("Resize() = %v, want the committed resize accepted by readback", err)
	}
	if got := api.callList(); got != "update,start" || api.vm.MemoryMiB != 6144 {
		t.Fatalf("calls = %s VM = %#v", got, api.vm)
	}

	api = newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.updateErr = &url.Error{Op: "Patch", URL: "https://api.invalid", Err: context.DeadlineExceeded}
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err == nil {
		t.Fatal("Resize() accepted an ambiguous PATCH error whose readback shows the old size")
	}
	if got := api.callList(); got != "update,start" {
		t.Fatalf("calls = %s, want the VM started again after the failed resize", got)
	}
}

func TestResizeControlPlaneRejectsAnIgnoredUpdate(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.ignoreUpdate = true
	_, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "read back") {
		t.Fatalf("Resize() error = %v, want a readback failure", err)
	}
	if got := api.callList(); got != "update,start" {
		t.Fatalf("calls = %s, want the VM started again at its current size", got)
	}
}

func TestResizeControlPlaneStopsOnPermanentStopFailure(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.stopErr = &inspace.APIError{StatusCode: http.StatusForbidden, Message: "denied"}
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err == nil {
		t.Fatal("Resize() accepted a permanent stop failure")
	}
	if got := api.callList(); got != "stop" {
		t.Fatalf("calls = %s, want a single stop", got)
	}
}

func TestResizeControlPlaneToleratesAConflictOnTheFirstPowerRequest(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	// The request landed (the VM is already changing state) but answered 409.
	api.stopErr = &inspace.APIError{StatusCode: http.StatusConflict, Message: "VM is stopping"}
	api.startErr = &inspace.APIError{StatusCode: http.StatusUnprocessableEntity, Message: "VM is starting"}
	if _, err := testResizer(api).Resize(context.Background(), cluster, resizeRequest()); err != nil {
		t.Fatalf("Resize() = %v, want status polling to settle a 409/422 first request", err)
	}
	if got := api.callList(); got != "stop,update,start" {
		t.Fatalf("calls = %s, want stop,update,start", got)
	}

	// A 409 whose VM never moves is not fatal either; the stop timeout decides.
	api = newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "running", 4, 4096)
	api.dropStops = 1 << 20
	api.stopErr = &inspace.APIError{StatusCode: http.StatusConflict, Message: "busy"}
	resizer := testResizer(api)
	resizer.StopTimeout = 30 * time.Millisecond
	_, err := resizer.Resize(context.Background(), cluster, resizeRequest())
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("Resize() error = %v, want a stop timeout", err)
	}
}

func TestStartOnlyNeverStopsOrResizesAVM(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    string
		memoryMiB int
		want      string
		action    string
	}{
		{name: "running at old size", status: "running", memoryMiB: 4096, want: "", action: ResizeActionUnchanged},
		{name: "running at target", status: "running", memoryMiB: 6144, want: "", action: ResizeActionUnchanged},
		{name: "stopped at old size", status: "stopped", memoryMiB: 4096, want: "start", action: ResizeActionStarted},
		{name: "stopped at target", status: "stopped", memoryMiB: 6144, want: "start", action: ResizeActionStarted},
		{name: "starting", status: "starting", memoryMiB: 4096, want: "", action: ResizeActionStarted},
		{name: "stopping", status: "stopping", memoryMiB: 4096, want: "start", action: ResizeActionStarted},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := testCluster()
			api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), test.status, 4, test.memoryMiB)
			switch test.status {
			case "starting":
				api.pending, api.pendingLeft = "running", 2
			case "stopping":
				api.pending, api.pendingLeft = "stopped", 2
			}
			result, err := testResizer(api).StartOnly(context.Background(), cluster, resizeRequest())
			if err != nil {
				t.Fatal(err)
			}
			if got := api.callList(); got != test.want || result.Action != test.action {
				t.Fatalf("calls = %q action = %s, want %q and %s", got, result.Action, test.want, test.action)
			}
			if api.vm.Status != "running" || api.vm.MemoryMiB != test.memoryMiB {
				t.Fatalf("VM = %#v, want running at its unchanged size", api.vm)
			}
		})
	}
}

func TestStartOnlyKeepsEveryOwnershipRefusal(t *testing.T) {
	cluster := testCluster()
	api := newResizeAPI(cluster.Metadata.Name, 1, ownerKey(cluster), "stopped", 4, 4096)
	api.vm.Description = resizeDescription("0123456789abcdef", 1)
	if _, err := testResizer(api).StartOnly(context.Background(), cluster, resizeRequest()); err == nil || api.callList() != "" {
		t.Fatalf("StartOnly() = %v calls = %q, want an ownership refusal and no mutation", err, api.callList())
	}
}
