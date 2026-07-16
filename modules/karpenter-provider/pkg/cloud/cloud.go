package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

var (
	ErrNotFound          = errors.New("cloud resource not found")
	ErrOwnershipMismatch = errors.New("cloud resource ownership does not match")
	// ErrCreateAttemptPending means a durable pre-POST fence exists but the
	// previous attempt is still inside the cloud visibility ambiguity window.
	ErrCreateAttemptPending = errors.New("durable VM create attempt remains ambiguous")
	// ErrCreateAttemptUnresolved is an issued POST that never produced an
	// attributable resource. No finite list-absence window can prove that a
	// timed-out server operation will not commit later, so automatic finalizer
	// release is unsafe and operator resolution is required.
	ErrCreateAttemptUnresolved = errors.New("issued VM create attempt requires operator resolution")
	// ErrCreateAttemptRejected proves that this invocation did not obtain an
	// accepted VM create: either the immediate Kubernetes authorization failed
	// before the SDK call, or the API returned a definitive non-retryable
	// rejection. The provider may durably mark the issued fence rejected; a
	// crash before that mark remains safely unresolved.
	ErrCreateAttemptRejected = errors.New("VM create attempt was definitively rejected")
)

const (
	MaxCreateInventoryEntries            = 1024
	MaxCreateTargetFloatingIPAssignments = 64
	MaxCreateInventoryEncodedBytes       = 96 * 1024
	MaxCreateCleanupResolutions          = 64
)

// CreateInventory is the bounded authoritative resource inventory observed
// before a NodeClaim is granted its one and only VM POST. Entries are opaque,
// stable cloud identities sorted by the adapter. A later resource absent from
// this baseline is treated as a possible result of an ambiguous create until
// its ownership is proven.
type CreateInventory struct {
	VMs               []string                     `json:"vms,omitempty"`
	PotentialVMs      []string                     `json:"potentialVMs,omitempty"`
	TargetVMs         []string                     `json:"targetVMs,omitempty"`
	FloatingIPs       []string                     `json:"floatingIPs,omitempty"`
	TargetFloatingIPs []CreateFloatingIPAssignment `json:"targetFloatingIPs,omitempty"`
}

// CreateFloatingIPAssignment retains the exact pre-authorization association
// between an adoption target and its public dependent. The VM delete API can
// auto-unassign an address, so a global floating-IP baseline alone is not
// enough to correlate that address after a security rollback.
type CreateFloatingIPAssignment struct {
	Identity         string `json:"identity"`
	VMUUID           string `json:"vmUUID"`
	Address          string `json:"address"`
	Name             string `json:"name,omitempty"`
	BillingAccountID int64  `json:"billingAccountID"`
}

// FencedCreateCleanupRequest is persisted on the NodeClaim before the paid
// mutation. It is intentionally limited to non-secret launch ownership and
// the pre-POST resource baseline required for safe orphan cleanup.
type FencedCreateCleanupRequest struct {
	ClusterName                  string
	Location                     string
	NetworkUUID                  string
	NodePoolName                 string
	ControlPlaneVIP              string
	PrivateLoadBalancerPoolStart string
	PrivateLoadBalancerPoolStop  string
	FirewallUUID                 string
	FirewallProfile              inspacev1.FirewallProfile
	SpecHash                     string
	BootstrapHash                string
	NodeClaimName                string
	VMName                       string
	BillingAccountID             int64
	OwnershipKeyHash             string
	AttemptToken                 string
	AttemptIssuedAt              time.Time
	POSTIssued                   bool
	POSTRejected                 bool
	AttemptResolved              bool
	// CreatedVMUUID is the exact UUID returned by this fence's authorized
	// create/adoption operation and persisted before any post-create cloud
	// mutation. RollbackChosen is a separate irreversible CAS decision: the
	// UUID anchor alone may only be protected/read, never cleaned up.
	CreatedVMUUID       string
	RollbackChosen      bool
	DependentUnresolved bool
	DependentsResolved  bool
	ObservedVMUUID      string
	FloatingIPName      string
	PublicIPv4          string
	// Resolutions is the bounded durable history of exact ownership receipts
	// persisted before cleanup deleted each target. Full dependent identity is
	// retained so every historical target can be exact-read and idempotently
	// deleted again during each final absence pass.
	Resolutions []FencedCreateCleanupResolution
	Baseline    CreateInventory
}

// FencedCreateCleanupResolution is exact cloud identity discovered during a
// deletion audit. The controller must persist this receipt on the NodeClaim
// and read it back before invoking cleanup again; only the later invocation is
// allowed to perform the destructive delete. This two-step handshake closes
// the crash window between discovering an orphan and remembering what was
// deleted.
type FencedCreateCleanupResolution struct {
	VMUUID         string `json:"vmUUID"`
	FloatingIPName string `json:"floatingIPName"`
	PublicIPv4     string `json:"publicIPv4"`
}

// FencedCreateCleanupResult is empty when cleanup is complete. Resolution is
// populated when an exact owned VM was found but has intentionally not yet
// been deleted because its cleanup identity is not Kubernetes-durable.
type FencedCreateCleanupResult struct {
	Resolution         *FencedCreateCleanupResolution
	DependentsResolved bool
}

// OwnershipKeyHash is the non-secret, compact launch key persisted in the VM
// ownership description. It is distinct from the full fence binding hash.
func OwnershipKeyHash(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return hex.EncodeToString(sum[:16])
}

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
	NodePoolName     string
	NodeClaimName    string
	Location         string
	NetworkUUID      string
	// ControlPlaneVIP is the literal RFC1918 address of the private RKE2
	// supervisor endpoint. Production creation rejects any worker whose private
	// address collides with it.
	ControlPlaneVIP string
	// PrivateLoadBalancerPoolStart/Stop are the exact inclusive 16-to-256
	// address range reserved from worker private-IP assignment.
	PrivateLoadBalancerPoolStart string
	PrivateLoadBalancerPoolStop  string
	FirewallUUID                 string
	FirewallProfile              inspacev1.FirewallProfile
	OSName                       string
	OSVersion                    string
	HostPoolUUID                 string
	HostClass                    string
	InstanceType                 string
	VCPU                         int
	MemoryGiB                    int
	RootDiskGiB                  int32
	PublicIPv4                   bool
	// SSHUsername and SSHPublicKey are optional, public operator-access data.
	// The production adapter always adds a separate ephemeral random password
	// at the API boundary; password material never enters this request model.
	SSHUsername  string
	SSHPublicKey string
	// CloudInitJSON is an API-compatible JSON object, not raw #cloud-config.
	CloudInitJSON string
	SpecHash      string
	BootstrapHash string
	// CreateAttempt* is a Kubernetes-durable pre-POST fence. AllowPOST is true
	// only for the invocation that created the immutable attempt. Once an SDK
	// POST may have been dispatched, this NodeClaim can only adopt or clean up
	// that launch; it never receives a second POST token.
	CreateAttemptToken     string
	CreateAttemptStartedAt time.Time
	CreateAttemptAllowPOST bool
	CreateAttemptIntent    CreateAuthorizationKind
	CreatedVMUUID          string
	CreateBaseline         CreateInventory `json:"-"`
	// AuthorizeLaunch performs an uncached exact NodeClaim/finalizer/fence CAS
	// immediately before either adopting an existing exact VM or dispatching
	// the SDK POST. It is process-local and excluded from request identity.
	AuthorizeLaunch func(context.Context, CreateAuthorizationKind) error `json:"-"`
	// RecordCreatedVM persists and exactly reads back the UUID returned by the
	// authorized launch before protection, FIP, or materialization work. The
	// sparse SDK response is sufficient authority to protect or roll back that
	// exact VM, but never to delete an uncorrelated floating IP.
	RecordCreatedVM func(context.Context, string) error `json:"-"`
	// ChooseRollback irreversibly races materialization for the same anchored
	// UUID. An optional resolution atomically adds an exact VM/FIP receipt; a
	// nil resolution still authorizes security-priority deletion of the exact
	// VM while dependent FIP discovery continues under the finalizer.
	ChooseRollback func(context.Context, string, *FencedCreateCleanupResolution) error `json:"-"`
}

type CreateAuthorizationKind string

const (
	CreateAuthorizationPost     CreateAuthorizationKind = "post"
	CreateAuthorizationAdoption CreateAuthorizationKind = "adoption"
)

type VM struct {
	UUID                         string
	Name                         string
	ClusterName                  string
	BillingAccountID             int64
	NodePoolName                 string
	NodeClaimName                string
	Location                     string
	OSName                       string
	OSVersion                    string
	HostClass                    string
	InstanceType                 string
	VCPU                         int
	MemoryGiB                    int
	RootDiskGiB                  int32
	FirewallUUID                 string
	FirewallProfile              inspacev1.FirewallProfile
	NetworkUUID                  string
	ControlPlaneVIP              string
	PrivateLoadBalancerPoolStart string
	PrivateLoadBalancerPoolStop  string
	SpecHash                     string
	BootstrapHash                string
	PrivateIPv4                  string
	PublicIPv4                   string
	FloatingIPName               string
	State                        LifecycleState
	RawState                     string
}

// DeleteVMIdentity is the NodeClaim-persisted identity of the worker's
// provider-owned floating IP. It is required to clean an orphan after the VM
// has already disappeared, because a deterministic name alone is not durable
// authority to mutate an account resource.
type DeleteVMIdentity struct {
	FloatingIPName   string
	PublicIPv4       string
	BillingAccountID int64
	NetworkUUID      string
}

func (v *VM) ImageID() string { return v.OSName + "@" + v.OSVersion }

// Cloud is the complete location-aware cloud boundary used by the provider.
// Ownership arguments are mandatory so Get/List/Delete cannot adopt or mutate
// VMs that merely happen to share a name.
type Cloud interface {
	PrepareCreate(context.Context, CreateVMRequest) (CreateInventory, error)
	CreateVM(context.Context, CreateVMRequest) (*VM, error)
	ProtectFencedCreate(context.Context, FencedCreateCleanupRequest) error
	CleanupFencedCreate(context.Context, FencedCreateCleanupRequest) (FencedCreateCleanupResult, error)
	DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string, identity DeleteVMIdentity) error
	GetVM(ctx context.Context, location, uuid, clusterName string) (*VM, error)
	ListVMs(ctx context.Context, location, clusterName string) ([]*VM, error)
}

// NodeClassValidator is implemented by production and fake clouds for the
// readiness reconciler's read-only host-pool check.
type NodeClassValidator interface {
	ValidateNodeClass(ctx context.Context, location, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID string) error
}
