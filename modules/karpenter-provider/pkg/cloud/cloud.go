package cloud

import (
	"context"
	"errors"
)

var (
	ErrNotFound          = errors.New("cloud resource not found")
	ErrOwnershipMismatch = errors.New("cloud resource ownership does not match")
)

// LifecycleState is the provider's stable interpretation of the API's VM
// status strings. RawState is retained on VM for diagnostics and forward
// compatibility.
type LifecycleState string

const (
	LifecyclePending  LifecycleState = "pending"
	LifecycleRunning  LifecycleState = "running"
	LifecycleStopping LifecycleState = "stopping"
	LifecycleStopped  LifecycleState = "stopped"
	LifecycleDeleting LifecycleState = "deleting"
	LifecycleFailed   LifecycleState = "failed"
	LifecycleUnknown  LifecycleState = "unknown"
)

type CreateVMRequest struct {
	// IdempotencyKey is a controller identity used for read-before-create
	// reconciliation. It is not sent as an unsupported InSpace API header.
	IdempotencyKey   string
	Name             string
	ClusterName      string
	BillingAccountID int64
	NodeClaimName    string
	Location         string
	NetworkUUID      string
	FirewallUUID     string
	OSName           string
	OSVersion        string
	HostPoolUUID     string
	HostClass        string
	InstanceType     string
	VCPU             int
	MemoryGiB        int
	RootDiskGiB      int32
	PublicIPv4       bool
	// CloudInitJSON is an API-compatible JSON object, not raw #cloud-config.
	CloudInitJSON string
	SpecHash      string
	BootstrapHash string
}

type VM struct {
	UUID             string
	Name             string
	ClusterName      string
	BillingAccountID int64
	NodeClaimName    string
	Location         string
	OSName           string
	OSVersion        string
	HostClass        string
	InstanceType     string
	VCPU             int
	MemoryGiB        int
	RootDiskGiB      int32
	FirewallUUID     string
	SpecHash         string
	BootstrapHash    string
	PublicIPv4       string
	FloatingIPName   string
	State            LifecycleState
	RawState         string
}

func (v *VM) ImageID() string { return v.OSName + "@" + v.OSVersion }

// Cloud is the complete location-aware cloud boundary used by the provider.
// Ownership arguments are mandatory so Get/List/Delete cannot adopt or mutate
// VMs that merely happen to share a name.
type Cloud interface {
	CreateVM(context.Context, CreateVMRequest) (*VM, error)
	DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string) error
	GetVM(ctx context.Context, location, uuid, clusterName string) (*VM, error)
	ListVMs(ctx context.Context, location, clusterName string) ([]*VM, error)
}

// NodeClassValidator is implemented by production and fake clouds for the
// readiness reconciler's read-only host-pool check.
type NodeClassValidator interface {
	ValidateNodeClass(ctx context.Context, location, networkUUID, hostPoolUUID, firewallUUID string) error
}
