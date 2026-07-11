package fake

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/cloud"
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

func (f *Cloud) CreateVM(_ context.Context, request cloud.CreateVMRequest) (*cloud.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if request.IdempotencyKey == "" {
		return nil, fmt.Errorf("idempotency key is required")
	}
	if id, ok := f.byKey[request.IdempotencyKey]; ok {
		if vm, exists := f.byID[id]; exists {
			return cloneVM(vm), nil
		}
	}
	id := deterministicUUID(request.IdempotencyKey)
	vm := &cloud.VM{
		UUID:             id,
		Name:             request.Name,
		ClusterName:      request.ClusterName,
		BillingAccountID: request.BillingAccountID,
		NodeClaimName:    request.NodeClaimName,
		Location:         request.Location,
		OSName:           request.OSName,
		OSVersion:        request.OSVersion,
		HostClass:        request.HostClass,
		InstanceType:     request.InstanceType,
		VCPU:             request.VCPU,
		MemoryGiB:        request.MemoryGiB,
		RootDiskGiB:      request.RootDiskGiB,
		FirewallUUID:     request.FirewallUUID,
		SpecHash:         request.SpecHash,
		BootstrapHash:    request.BootstrapHash,
		PublicIPv4:       "203.0.113.10",
		FloatingIPName:   request.Name + "-public",
		State:            cloud.LifecycleRunning,
		RawState:         "running",
	}
	f.byID[id] = vm
	f.byKey[request.IdempotencyKey] = id
	f.requests[id] = cloneRequest(request)
	return cloneVM(vm), nil
}

func (f *Cloud) DeleteVM(_ context.Context, location, id, clusterName, nodeClaimName string) error {
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

func (f *Cloud) ValidateNodeClass(_ context.Context, location, networkUUID, hostPoolUUID, firewallUUID string) error {
	if location == "" || networkUUID == "" || hostPoolUUID == "" || firewallUUID == "" {
		return fmt.Errorf("location, network UUID, host pool UUID, and firewall UUID are required")
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
	return request
}
