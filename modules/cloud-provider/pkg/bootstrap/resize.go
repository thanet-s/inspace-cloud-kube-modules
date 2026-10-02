package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const (
	// ResizeActionUnchanged means the VM already runs at the target size.
	ResizeActionUnchanged = "unchanged"
	// ResizeActionNeeded is what a read-only check reports for any other state.
	ResizeActionNeeded = "resize-needed"
	// ResizeActionResized means this run finished the resize.
	ResizeActionResized = "resized"
	// ResizeActionStarted means StartOnly powered the VM on without resizing it.
	ResizeActionStarted = "started"

	defaultResizePollInterval = 5 * time.Second
	// A graceful ACPI stop takes about a minute; allow a slow guest far longer
	// before giving up. The stop is never forced.
	defaultResizeStopTimeout  = 15 * time.Minute
	defaultResizeStartTimeout = 15 * time.Minute
	// A power request is sent once per transition and only repeated after this
	// grace period, so a slow guest is never nudged twice mid-shutdown.
	defaultResizeResendInterval = 3 * time.Minute
	// The private address can lag a start by a few reads.
	defaultResizeIPTimeout = 2 * time.Minute
)

// ControlPlaneResizeAPI is the subset of the InSpace client a resize needs.
type ControlPlaneResizeAPI interface {
	ListVMs(context.Context, string) ([]inspace.VM, error)
	GetVM(context.Context, string, string) (*inspace.VM, error)
	StopVM(context.Context, string, string) error
	StartVM(context.Context, string, string) error
	UpdateVMCompute(context.Context, string, string, int, int) (*inspace.VM, error)
}

// ControlPlaneResizer grows one deterministic control-plane VM. Every step
// derives from the live VM, so a run interrupted anywhere resumes by re-running.
type ControlPlaneResizer struct {
	API            ControlPlaneResizeAPI
	PollInterval   time.Duration
	StopTimeout    time.Duration
	StartTimeout   time.Duration
	ResendInterval time.Duration
	IPTimeout      time.Duration
}

type ControlPlaneResizeRequest struct {
	Slot      int
	VCPU      int
	MemoryMiB int
	// ExpectedUUID and ExpectedPrivateIPv4 are the identity journaled at init.
	// A stop/start keeps both, so any difference means this is not the
	// journaled VM. A stopped VM may not report an address, so that one is only
	// compared when present.
	ExpectedUUID        string
	ExpectedPrivateIPv4 string
}

type ControlPlaneResizeResult struct {
	Slot      int    `json:"slot"`
	Name      string `json:"name"`
	VMUUID    string `json:"vmUUID"`
	VCPU      int    `json:"vcpu"`
	MemoryMiB int    `json:"memoryMiB"`
	Status    string `json:"status"`
	Action    string `json:"action"`
	Message   string `json:"message"`
}

// Check reads the VM and reports whether Resize would change anything. It never
// mutates, so the caller can decide to drain the node first.
func (r *ControlPlaneResizer) Check(ctx context.Context, cluster *v1alpha1.InSpaceCluster, request ControlPlaneResizeRequest) (ControlPlaneResizeResult, error) {
	vm, err := r.inspect(ctx, cluster, request)
	if err != nil {
		return ControlPlaneResizeResult{}, err
	}
	result := resizeResult(request, vm, ResizeActionNeeded, "the VM must be resized or restarted")
	if resizeAtTarget(vm, request) && resizeStatus(vm) == "running" {
		result.Action, result.Message = ResizeActionUnchanged, "the VM already runs at the target size"
	}
	return result, nil
}

// StartOnly powers on a VM a resize left stopped, and nothing else. It never
// stops the VM and never changes its size, so it is safe to run before any
// quorum check: a running VM is left alone, and a stopping or starting one is
// waited for. The ownership, UUID, and address proofs of Resize still apply.
func (r *ControlPlaneResizer) StartOnly(ctx context.Context, cluster *v1alpha1.InSpaceCluster, request ControlPlaneResizeRequest) (ControlPlaneResizeResult, error) {
	vm, err := r.inspect(ctx, cluster, request)
	if err != nil {
		return ControlPlaneResizeResult{}, err
	}
	location := cluster.Spec.Location
	switch resizeStatus(vm) {
	case "running":
		return resizeResult(request, vm, ResizeActionUnchanged, "the VM is already running; nothing was started"), nil
	case "starting":
		vm, err = r.waitStatus(ctx, location, vm.UUID, "running", r.startTimeout(), "start")
	case "stopping":
		if vm, err = r.waitStatus(ctx, location, vm.UUID, "stopped", r.stopTimeout(), "stop"); err == nil {
			vm, err = r.startAndWait(ctx, location, vm.UUID)
		}
	case "stopped":
		vm, err = r.startAndWait(ctx, location, vm.UUID)
	default:
		err = fmt.Errorf("bootstrap: control-plane VM %q is %q; refusing to start it", vm.Name, vm.Status)
	}
	if err != nil {
		return ControlPlaneResizeResult{}, err
	}
	if vm, err = r.waitForAddress(ctx, location, vm); err != nil {
		return ControlPlaneResizeResult{}, err
	}
	if err := r.checkAddress(vm, request); err != nil {
		return ControlPlaneResizeResult{}, err
	}
	return resizeResult(request, vm, ResizeActionStarted, "the VM was started without changing its size"), nil
}

// Resize drives one control-plane VM to the target size and running state:
// graceful stop, PATCH while stopped, read back, start. A failure after the
// stop starts the VM again at its current size before the error is returned.
func (r *ControlPlaneResizer) Resize(ctx context.Context, cluster *v1alpha1.InSpaceCluster, request ControlPlaneResizeRequest) (ControlPlaneResizeResult, error) {
	vm, err := r.inspect(ctx, cluster, request)
	if err != nil {
		return ControlPlaneResizeResult{}, err
	}
	location := cluster.Spec.Location
	changed := false
	if resizeStatus(vm) == "starting" {
		if vm, err = r.waitStatus(ctx, location, vm.UUID, "running", r.startTimeout(), "start"); err != nil {
			return ControlPlaneResizeResult{}, err
		}
	}
	if resizeAtTarget(vm, request) && resizeStatus(vm) == "running" {
		if err := r.checkAddress(vm, request); err != nil {
			return ControlPlaneResizeResult{}, err
		}
		return resizeResult(request, vm, ResizeActionUnchanged, "the VM already runs at the target size"), nil
	}
	if (!resizeAtTarget(vm, request) && resizeStatus(vm) == "running") || resizeStatus(vm) == "stopping" {
		if vm, err = r.stopAndWait(ctx, location, vm.UUID); err != nil {
			return ControlPlaneResizeResult{}, err
		}
		changed = true
	}
	if resizeStatus(vm) != "stopped" {
		return ControlPlaneResizeResult{}, fmt.Errorf("bootstrap: control-plane VM %q is %q; refusing to resize it", vm.Name, vm.Status)
	}
	if !resizeAtTarget(vm, request) {
		if vm, err = r.applyCompute(ctx, location, vm, request); err != nil {
			// The VM is stopped and nothing else will start it, so bring it
			// back at its current size before reporting the failure.
			return ControlPlaneResizeResult{}, errors.Join(err, r.restart(ctx, location, vm.UUID))
		}
		changed = true
	}
	if vm, err = r.startAndWait(ctx, location, vm.UUID); err != nil {
		return ControlPlaneResizeResult{}, err
	}
	if vm, err = r.waitForAddress(ctx, location, vm); err != nil {
		return ControlPlaneResizeResult{}, err
	}
	if err := r.checkAddress(vm, request); err != nil {
		return ControlPlaneResizeResult{}, err
	}
	if !resizeAtTarget(vm, request) {
		return ControlPlaneResizeResult{}, fmt.Errorf(
			"bootstrap: control-plane VM %q came back with %d vCPU and %d MiB, want %d vCPU and %d MiB",
			vm.Name, vm.VCPU, vm.MemoryMiB, request.VCPU, request.MemoryMiB,
		)
	}
	action, message := ResizeActionUnchanged, "the VM already runs at the target size"
	if changed {
		action, message = ResizeActionResized, "the VM was stopped gracefully, resized, and started"
	}
	return resizeResult(request, vm, action, message), nil
}

// applyCompute PATCHes the stopped VM. The read-back is the authority: after
// an error that may have committed, matching values still count as success. It
// returns the last observed VM, which is always the stopped one on failure.
func (r *ControlPlaneResizer) applyCompute(ctx context.Context, location string, vm *inspace.VM, request ControlPlaneResizeRequest) (*inspace.VM, error) {
	echo, patchErr := r.API.UpdateVMCompute(ctx, location, vm.UUID, request.VCPU, request.MemoryMiB)
	readback, readErr := r.API.GetVM(ctx, location, vm.UUID)
	switch {
	case readErr == nil && resizeAtTarget(readback, request):
		return readback, nil
	case readErr == nil:
		if patchErr != nil {
			return vm, fmt.Errorf("bootstrap: resize control-plane VM %q: %w", vm.Name, patchErr)
		}
		return vm, fmt.Errorf(
			"bootstrap: control-plane VM %q read back %d vCPU and %d MiB after the resize, want %d vCPU and %d MiB",
			vm.Name, readback.VCPU, readback.MemoryMiB, request.VCPU, request.MemoryMiB,
		)
	case patchErr == nil && echo != nil && resizeAtTarget(echo, request):
		// The 200 echo shows the new size; only the confirming read failed.
		return echo, nil
	case patchErr != nil:
		return vm, fmt.Errorf("bootstrap: resize control-plane VM %q: %w", vm.Name, errors.Join(patchErr, readErr))
	default:
		return vm, fmt.Errorf("bootstrap: read back resized control-plane VM %q: %w", vm.Name, readErr)
	}
}

// restart brings a VM that this run stopped back up after a failed resize. It
// outlives a cancelled context so an operator interrupt cannot strand it down.
func (r *ControlPlaneResizer) restart(ctx context.Context, location, uuid string) error {
	if _, err := r.startAndWait(context.WithoutCancel(ctx), location, uuid); err != nil {
		return fmt.Errorf("bootstrap: starting control-plane VM %s again after the failed resize: %w", uuid, err)
	}
	return nil
}

// inspect validates the request and returns the exact owned VM. Nothing is
// mutated before every ownership and address proof passes.
func (r *ControlPlaneResizer) inspect(ctx context.Context, cluster *v1alpha1.InSpaceCluster, request ControlPlaneResizeRequest) (*inspace.VM, error) {
	if r.API == nil {
		return nil, errors.New("bootstrap: API is required")
	}
	if cluster == nil {
		return nil, errors.New("bootstrap: cluster is required")
	}
	// The spec is the cluster's persisted init-time spec, which may name a
	// released release candidate.
	if errs := cluster.Spec.ValidatePersisted(); len(errs) != 0 {
		return nil, fmt.Errorf("bootstrap: invalid cluster: %v", errs)
	}
	replicas := controlPlaneReplicaCount(cluster)
	if request.Slot < 0 || request.Slot >= replicas {
		return nil, fmt.Errorf("bootstrap: control-plane slot %d is outside this cluster's %d slots", request.Slot, replicas)
	}
	if request.VCPU <= 0 || request.MemoryMiB <= 0 {
		return nil, errors.New("bootstrap: target vCPU and memory must be positive")
	}
	if net.ParseIP(request.ExpectedPrivateIPv4) == nil {
		return nil, errors.New("bootstrap: the journaled private IPv4 of the control-plane VM is required")
	}
	if !vmUUIDPattern.MatchString(request.ExpectedUUID) {
		return nil, errors.New("bootstrap: the journaled UUID of the control-plane VM is required")
	}
	owner := ownerKey(cluster)
	name := controlPlaneName(cluster.Metadata.Name, request.Slot)
	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	var listed *inspace.VM
	for i := range vms {
		if vms[i].Name != name {
			continue
		}
		if listed != nil {
			return nil, fmt.Errorf("bootstrap: duplicate VM name %q", name)
		}
		listed = &vms[i]
	}
	if listed == nil || !vmUUIDPattern.MatchString(listed.UUID) {
		return nil, fmt.Errorf("bootstrap: control-plane VM %q was not found", name)
	}
	if !strings.EqualFold(listed.UUID, request.ExpectedUUID) {
		return nil, fmt.Errorf("bootstrap: control-plane VM %q has UUID %s, journaled %s", name, listed.UUID, request.ExpectedUUID)
	}
	vm, err := r.API.GetVM(ctx, cluster.Spec.Location, listed.UUID)
	if err != nil {
		return nil, err
	}
	if vm == nil || !strings.EqualFold(vm.UUID, listed.UUID) || vm.Name != name {
		return nil, fmt.Errorf("bootstrap: control-plane VM %q detail does not match its inventory row", name)
	}
	if resizeStatus(vm) == "deleted" {
		return nil, fmt.Errorf("bootstrap: control-plane VM %q is a deleted tombstone", name)
	}
	if !hasControlPlaneOwnershipRecord(vm.Description, owner, request.Slot) {
		return nil, fmt.Errorf("bootstrap: refusing to resize VM %q without this cluster's slot %d ownership record", name, request.Slot)
	}
	if cluster.Spec.BillingAccountID <= 0 || vm.BillingAccountID != cluster.Spec.BillingAccountID {
		return nil, fmt.Errorf("bootstrap: refusing to resize VM %q without exact billing-account ownership", name)
	}
	if err := r.checkAddress(vm, request); err != nil {
		return nil, err
	}
	if vm.VCPU > request.VCPU || vm.MemoryMiB > request.MemoryMiB {
		return nil, fmt.Errorf(
			"bootstrap: refusing to shrink control-plane VM %q from %d vCPU and %d MiB to %d vCPU and %d MiB",
			name, vm.VCPU, vm.MemoryMiB, request.VCPU, request.MemoryMiB,
		)
	}
	return vm, nil
}

// checkAddress compares the private address with the journal. Only a stopped
// VM may omit it; every other state must report exactly the journaled one.
func (r *ControlPlaneResizer) checkAddress(vm *inspace.VM, request ControlPlaneResizeRequest) error {
	if vm.PrivateIPv4 == request.ExpectedPrivateIPv4 || (vm.PrivateIPv4 == "" && resizeStatus(vm) == "stopped") {
		return nil
	}
	return fmt.Errorf("bootstrap: control-plane VM %q private IPv4 is %q, journaled %q", vm.Name, vm.PrivateIPv4, request.ExpectedPrivateIPv4)
}

// waitForAddress polls until a started VM reports its private address.
func (r *ControlPlaneResizer) waitForAddress(ctx context.Context, location string, vm *inspace.VM) (*inspace.VM, error) {
	if vm.PrivateIPv4 != "" {
		return vm, nil
	}
	timeout := r.IPTimeout
	if timeout <= 0 {
		timeout = defaultResizeIPTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for r.sleep(waitCtx) {
		current, err := r.API.GetVM(waitCtx, location, vm.UUID)
		if err != nil && !transientResizeError(err) {
			return nil, err
		}
		if err == nil && current.PrivateIPv4 != "" {
			return current, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("bootstrap: control-plane VM %q reported no private IPv4 within %s of starting", vm.Name, timeout)
}

// hasControlPlaneOwnershipRecord accepts every control-plane ownership schema
// that Destroy still recognizes for the current display-name topology.
func hasControlPlaneOwnershipRecord(description, owner string, slot int) bool {
	for version := 9; version >= 2; version-- {
		hash, found := strings.CutPrefix(description, fmt.Sprintf("inspace-rke2-cp/v%d owner=%s slot=%d spec=", version, owner, slot))
		if !found || len(hash) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(hash); err == nil {
			return true
		}
	}
	return false
}

func (r *ControlPlaneResizer) stopAndWait(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	return r.powerAndWait(ctx, location, uuid, "running", "stopped", r.stopTimeout(), r.API.StopVM, "stop")
}

func (r *ControlPlaneResizer) startAndWait(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	return r.powerAndWait(ctx, location, uuid, "stopped", "running", r.startTimeout(), r.API.StartVM, "start")
}

// powerAndWait sends the power request once when the VM sits in the source
// state and then only polls. It resends after the grace period if the VM is
// still in the source state. A 409/422 means the VM is already changing state,
// on the first request or a resend, so it keeps polling. The
// API call can block past a minute, so a timeout or retryable failure is
// ambiguous and status decides.
func (r *ControlPlaneResizer) powerAndWait(
	ctx context.Context, location, uuid, from, want string, timeout time.Duration,
	request func(context.Context, string, string) error, verb string,
) (*inspace.VM, error) {
	resend := r.ResendInterval
	if resend <= 0 {
		resend = defaultResizeResendInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var sentAt time.Time
	for {
		vm, err := r.API.GetVM(waitCtx, location, uuid)
		switch {
		case err != nil && !transientResizeError(err):
			return nil, err
		case err == nil && resizeStatus(vm) == want:
			return vm, nil
		case err == nil && resizeStatus(vm) == from && (sentAt.IsZero() || time.Since(sentAt) >= resend):
			sentAt = time.Now()
			if err := request(waitCtx, location, uuid); err != nil && !transientResizeError(err) && !resizeConflict(err) {
				return nil, fmt.Errorf("bootstrap: %s control-plane VM %s: %w", verb, uuid, err)
			}
		}
		if !r.sleep(waitCtx) {
			return nil, resizeWaitError(ctx, verb, uuid, want, timeout)
		}
	}
}

// waitStatus only polls; it never issues a request.
func (r *ControlPlaneResizer) waitStatus(ctx context.Context, location, uuid, want string, timeout time.Duration, verb string) (*inspace.VM, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		vm, err := r.API.GetVM(waitCtx, location, uuid)
		if err != nil && !transientResizeError(err) {
			return nil, err
		}
		if err == nil && resizeStatus(vm) == want {
			return vm, nil
		}
		if !r.sleep(waitCtx) {
			return nil, resizeWaitError(ctx, verb, uuid, want, timeout)
		}
	}
}

func resizeWaitError(ctx context.Context, verb, uuid, want string, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if verb == "stop" {
		return fmt.Errorf("bootstrap: control-plane VM %s did not stop within %s; it was not forced, so resize nothing and retry once the guest is down", uuid, timeout)
	}
	return fmt.Errorf("bootstrap: control-plane VM %s did not reach %q within %s", uuid, want, timeout)
}

func (r *ControlPlaneResizer) sleep(ctx context.Context) bool {
	interval := r.PollInterval
	if interval <= 0 {
		interval = defaultResizePollInterval
	}
	return waitForContext(ctx, interval)
}

func waitForContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (r *ControlPlaneResizer) stopTimeout() time.Duration {
	if r.StopTimeout > 0 {
		return r.StopTimeout
	}
	return defaultResizeStopTimeout
}

func (r *ControlPlaneResizer) startTimeout() time.Duration {
	if r.StartTimeout > 0 {
		return r.StartTimeout
	}
	return defaultResizeStartTimeout
}

// transientResizeError reports a failure whose outcome is unknown or that a
// later status read can resolve: a client timeout or a retryable HTTP status.
func transientResizeError(err error) bool {
	if errors.Is(err, inspace.ErrMutationNotDispatched) {
		return false
	}
	var apiErr *inspace.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable
	}
	var networkErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout())
}

// resizeConflict reports the 409/422 a power request gets while the VM is
// already changing state.
func resizeConflict(err error) bool {
	var apiErr *inspace.APIError
	return errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusConflict || apiErr.StatusCode == http.StatusUnprocessableEntity)
}

// resizeStatus lowercases the API status and folds every stopped-like value
// (the set Provider.InstanceShutdown treats as shut down) into "stopped". The
// live API reports running, stopping and stopped.
func resizeStatus(vm *inspace.VM) string {
	switch status := strings.ToLower(strings.TrimSpace(vm.Status)); status {
	case "stopped", "shutoff", "shutdown", "off":
		return "stopped"
	default:
		return status
	}
}

func resizeAtTarget(vm *inspace.VM, request ControlPlaneResizeRequest) bool {
	return vm.VCPU == request.VCPU && vm.MemoryMiB == request.MemoryMiB
}

func resizeResult(request ControlPlaneResizeRequest, vm *inspace.VM, action, message string) ControlPlaneResizeResult {
	return ControlPlaneResizeResult{
		Slot: request.Slot, Name: vm.Name, VMUUID: vm.UUID, VCPU: vm.VCPU, MemoryMiB: vm.MemoryMiB,
		Status: vm.Status, Action: action, Message: message,
	}
}
