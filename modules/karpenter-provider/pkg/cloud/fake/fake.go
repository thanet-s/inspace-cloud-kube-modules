package fake

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

type Cloud struct {
	mu       sync.RWMutex
	byID     map[string]*cloud.VM
	byKey    map[string]string
	requests map[string]cloud.CreateVMRequest
}

func New() *Cloud {
	return &Cloud{
		byID:     map[string]*cloud.VM{},
		byKey:    map[string]string{},
		requests: map[string]cloud.CreateVMRequest{},
	}
}

func (f *Cloud) PrepareCreate(_ context.Context, _ cloud.CreateVMRequest) (cloud.CreateInventory, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	inventory := cloud.CreateInventory{VMs: make([]string, 0, len(f.byID))}
	for id := range f.byID {
		inventory.VMs = append(inventory.VMs, id)
	}
	sort.Strings(inventory.VMs)
	return inventory, nil
}

func (f *Cloud) CreateVM(ctx context.Context, request cloud.CreateVMRequest) (*cloud.VM, error) {
	f.mu.Lock()
	if request.IdempotencyKey == "" {
		f.mu.Unlock()
		return nil, fmt.Errorf("idempotency key is required")
	}
	if id, ok := f.byKey[request.IdempotencyKey]; ok {
		if vm, exists := f.byID[id]; exists {
			existing := cloneVM(vm)
			f.mu.Unlock()
			if request.CreateAttemptToken != "" && request.CreateAttemptAllowPOST {
				if request.AuthorizeLaunch == nil {
					return nil, cloud.ErrCreateAttemptPending
				}
				if err := request.AuthorizeLaunch(ctx, cloud.CreateAuthorizationAdoption); err != nil {
					return nil, err
				}
			}
			if request.CreateAttemptToken != "" {
				if request.RecordCreatedVM == nil {
					return nil, fmt.Errorf("missing durable created-VM anchor writer")
				}
				if err := request.RecordCreatedVM(ctx, existing.UUID); err != nil {
					return nil, err
				}
			}
			return existing, nil
		}
	}
	f.mu.Unlock()
	if request.CreateAttemptToken != "" {
		if !request.CreateAttemptAllowPOST || request.AuthorizeLaunch == nil {
			return nil, cloud.ErrCreateAttemptPending
		}
		if err := request.AuthorizeLaunch(ctx, cloud.CreateAuthorizationPost); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	if id, ok := f.byKey[request.IdempotencyKey]; ok {
		if vm, exists := f.byID[id]; exists {
			existing := cloneVM(vm)
			f.mu.Unlock()
			if request.CreateAttemptToken != "" {
				if request.RecordCreatedVM == nil {
					return nil, fmt.Errorf("missing durable created-VM anchor writer")
				}
				if err := request.RecordCreatedVM(ctx, existing.UUID); err != nil {
					return nil, err
				}
			}
			return existing, nil
		}
	}
	id := deterministicUUID(request.IdempotencyKey)
	vm := &cloud.VM{
		UUID:                         id,
		Name:                         request.Name,
		ClusterName:                  request.ClusterName,
		BillingAccountID:             request.BillingAccountID,
		NodePoolName:                 request.NodePoolName,
		NodeClaimName:                request.NodeClaimName,
		Location:                     request.Location,
		OSName:                       request.OSName,
		OSVersion:                    request.OSVersion,
		HostClass:                    request.HostClass,
		InstanceType:                 request.InstanceType,
		VCPU:                         request.VCPU,
		MemoryGiB:                    request.MemoryGiB,
		RootDiskGiB:                  request.RootDiskGiB,
		FirewallUUID:                 request.FirewallUUID,
		FirewallProfile:              inspacev1.EffectiveFirewallProfile(request.FirewallProfile),
		NetworkUUID:                  request.NetworkUUID,
		ControlPlaneVIP:              request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart,
		PrivateLoadBalancerPoolStop:  request.PrivateLoadBalancerPoolStop,
		SpecHash:                     request.SpecHash,
		BootstrapHash:                request.BootstrapHash,
		PrivateIPv4:                  "10.0.0.20",
		PublicIPv4:                   "203.0.113.10",
		FloatingIPName:               request.Name + "-public",
		State:                        cloud.LifecycleRunning,
		RawState:                     "running",
	}
	f.byID[id] = vm
	f.byKey[request.IdempotencyKey] = id
	f.requests[id] = cloneRequest(request)
	f.mu.Unlock()
	if request.CreateAttemptToken != "" {
		if request.RecordCreatedVM == nil {
			return nil, fmt.Errorf("missing durable created-VM anchor writer")
		}
		if err := request.RecordCreatedVM(ctx, id); err != nil {
			return nil, err
		}
	}
	return cloneVM(vm), nil
}

func (f *Cloud) ProtectFencedCreate(_ context.Context, request cloud.FencedCreateCleanupRequest) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	vm, ok := f.byID[request.CreatedVMUUID]
	if !ok {
		return cloud.ErrNotFound
	}
	if vm.Location != request.Location || vm.ClusterName != request.ClusterName || vm.NodeClaimName != request.NodeClaimName {
		return cloud.ErrOwnershipMismatch
	}
	return nil
}

func (f *Cloud) CleanupFencedCreate(_ context.Context, request cloud.FencedCreateCleanupRequest) (cloud.FencedCreateCleanupResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, resolution := range request.Resolutions {
		delete(f.byID, resolution.VMUUID)
	}
	for id, vm := range f.byID {
		if vm.Location == request.Location && vm.ClusterName == request.ClusterName && vm.NodeClaimName == request.NodeClaimName && vm.Name == request.VMName {
			return cloud.FencedCreateCleanupResult{Resolution: &cloud.FencedCreateCleanupResolution{
				VMUUID: id, FloatingIPName: vm.FloatingIPName, PublicIPv4: vm.PublicIPv4,
			}}, nil
		}
	}
	if len(request.Resolutions) != 0 {
		return cloud.FencedCreateCleanupResult{}, nil
	}
	if request.POSTRejected {
		return cloud.FencedCreateCleanupResult{}, cloud.ErrNotFound
	}
	if request.POSTIssued {
		return cloud.FencedCreateCleanupResult{}, cloud.ErrCreateAttemptUnresolved
	}
	return cloud.FencedCreateCleanupResult{}, cloud.ErrNotFound
}

func (f *Cloud) DeleteVM(_ context.Context, location, id, clusterName, nodeClaimName string, _ cloud.DeleteVMIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	vm, ok := f.byID[id]
	if !ok {
		return cloud.ErrNotFound
	}
	if vm.Location != location || vm.ClusterName != clusterName || vm.NodeClaimName != nodeClaimName {
		return cloud.ErrOwnershipMismatch
	}
	delete(f.byID, id)
	return nil
}

func (f *Cloud) GetVM(_ context.Context, location, id, clusterName string) (*cloud.VM, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	vm, ok := f.byID[id]
	if !ok {
		return nil, cloud.ErrNotFound
	}
	if vm.Location != location || vm.ClusterName != clusterName {
		return nil, cloud.ErrOwnershipMismatch
	}
	return cloneVM(vm), nil
}

func (f *Cloud) ListVMs(_ context.Context, location, clusterName string) ([]*cloud.VM, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]*cloud.VM, 0, len(f.byID))
	for _, vm := range f.byID {
		if vm.Location == location && vm.ClusterName == clusterName {
			result = append(result, cloneVM(vm))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	return result, nil
}

func (f *Cloud) ValidateNodeClass(_ context.Context, location, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID string) error {
	vip, err := netip.ParseAddr(controlPlaneVIP)
	pool := inspacev1.PrivateLoadBalancerPool{Start: privateLoadBalancerPoolStart, Stop: privateLoadBalancerPoolStop}
	reservedVIP := err == nil && (netip.MustParsePrefix(inspacev1.CiliumNativeRoutingPodCIDR).Contains(vip) || netip.MustParsePrefix(inspacev1.KubernetesServiceCIDR).Contains(vip))
	if location == "" || networkUUID == "" || hostPoolUUID == "" || firewallUUID == "" || err != nil || !vip.Is4() || !vip.IsPrivate() || reservedVIP || pool.ValidateForSupervisor(vip) != nil {
		return fmt.Errorf("location, network UUID, private control-plane VIP and Service pool, host pool UUID, and firewall UUID are required")
	}
	return nil
}

func (f *Cloud) Request(id string) (cloud.CreateVMRequest, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	request, ok := f.requests[id]
	return cloneRequest(request), ok
}

func deterministicUUID(key string) string {
	sum := sha256.Sum256([]byte(key))
	// Mark the deterministic test identifier as UUIDv4/RFC 4122.
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func cloneVM(vm *cloud.VM) *cloud.VM {
	if vm == nil {
		return nil
	}
	copy := *vm
	return &copy
}

func cloneRequest(request cloud.CreateVMRequest) cloud.CreateVMRequest {
	request.CreateBaseline = cloud.CreateInventory{
		VMs:               append([]string(nil), request.CreateBaseline.VMs...),
		PotentialVMs:      append([]string(nil), request.CreateBaseline.PotentialVMs...),
		TargetVMs:         append([]string(nil), request.CreateBaseline.TargetVMs...),
		FloatingIPs:       append([]string(nil), request.CreateBaseline.FloatingIPs...),
		TargetFloatingIPs: append([]cloud.CreateFloatingIPAssignment(nil), request.CreateBaseline.TargetFloatingIPs...),
	}
	request.AuthorizeLaunch = nil
	request.RecordCreatedVM = nil
	request.ChooseRollback = nil
	return request
}
