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
	ErrNotFound                    = errors.New("cloud resource not found")
	ErrOwnershipMismatch           = errors.New("cloud resource ownership does not match")
	ErrAttachedNonPrimaryVolumes   = errors.New("VM has attached non-primary block volumes")
	ErrVMStorageInventoryUncertain = errors.New("VM storage inventory is not authoritative")
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
	// before the SDK call, or the SDK supplied positive local proof that no
	// request was dispatched. HTTP responses, including every 4xx, are never
	// rejection proof. A crash before the durable mark remains safely unresolved.
	ErrCreateAttemptRejected = errors.New("VM create attempt was locally blocked before dispatch")
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
	// CreatedVMUUID is the canonically verified launch UUID persisted only after
	// exact v3 launch, billing-account, and configured-VPC proofs. A UUID from an
	// SDK response is provisional and never grants mutation authority by itself.
	// RollbackChosen is a separate irreversible CAS decision.
	CreatedVMUUID       string
	RollbackChosen      bool
	DependentUnresolved bool
	DependentsResolved  bool
	ObservedVMUUID      string
	FloatingIPName      string
	PublicIPv4          string
	// Resolutions is the bounded durable history of exact ownership receipts
	// persisted before cleanup deleted each target. Full dependent identity is
	// retained so every historical target can be exact-read during each final
	// absence pass without replaying a DELETE after canonical absence.
	Resolutions []FencedCreateCleanupResolution
	Baseline    CreateInventory
	// BaseFirewallAssignment is the Kubernetes-durable authority for the one
	// base-firewall assignment POST associated with CreatedVMUUID. An issued
	// assignment may only be recovered with authoritative reads; it must never
	// be replayed after a timeout, process restart, or controller failover.
	BaseFirewallAssignment FirewallAssignmentFence
	// FloatingIPUpdate is the Kubernetes-durable authority for the deterministic
	// metadata PATCH of the created VM's auto-reserved public address. Protection
	// reconciliation uses issued and observed receipts only for readback; it
	// never grants a second PATCH.
	FloatingIPUpdate            FloatingIPUpdateFence
	AuthorizeBaseFirewall       func(context.Context, string) (FirewallAssignmentAuthorization, error)                      `json:"-"`
	ObserveBaseFirewall         func(context.Context, string, string) error                                                 `json:"-"`
	RejectBaseFirewall          func(context.Context, string, string) error                                                 `json:"-"`
	AuthorizeBaseFirewallDetach func(context.Context, string) (FirewallDetachmentAuthorization, error)                      `json:"-"`
	ObserveBaseFirewallDetach   func(context.Context, FirewallDetachmentFence) error                                        `json:"-"`
	RejectBaseFirewallDetach    func(context.Context, FirewallDetachmentFence) error                                        `json:"-"`
	AuthorizeFloatingIPUpdate   func(context.Context, string, string, string, int64) (FloatingIPUpdateAuthorization, error) `json:"-"`
	ObserveFloatingIPUpdate     func(context.Context, FloatingIPUpdateFence) error                                          `json:"-"`
	RejectFloatingIPUpdate      func(context.Context, FloatingIPUpdateFence) error                                          `json:"-"`
	AuthorizeRemovalMutation    func(context.Context, RemovalMutation, bool) (RemovalMutationAuthorization, error)          `json:"-"`
	ObserveRemovalMutation      func(context.Context, RemovalMutationFence) error                                           `json:"-"`
	RejectRemovalMutation       func(context.Context, RemovalMutationFence) error                                           `json:"-"`
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
	// RecordCreatedVM persists and exactly reads back a UUID only after the cloud
	// adapter independently proves the complete v3 launch identity, billing
	// account, and configured-VPC membership. Sparse SDK responses are discovery
	// hints only and never authorize protection, rollback, or dependent mutation.
	RecordCreatedVM func(context.Context, string) error `json:"-"`
	// ChooseRollback irreversibly races materialization for the same anchored
	// UUID. An optional resolution atomically adds an exact VM/FIP receipt; a
	// nil resolution still authorizes security-priority deletion of the exact
	// VM while dependent FIP discovery continues under the finalizer.
	ChooseRollback func(context.Context, string, *FencedCreateCleanupResolution) error `json:"-"`
	// BaseFirewallAssignment and its callbacks are a second durable mutation
	// fence, scoped to the exact anchored VM. AuthorizeBaseFirewall persists and
	// reads back an issued receipt before the adapter may POST. Observe and
	// Reject transition that same exact issue after authoritative cloud evidence.
	BaseFirewallAssignment      FirewallAssignmentFence                                                                     `json:"-"`
	AuthorizeBaseFirewall       func(context.Context, string) (FirewallAssignmentAuthorization, error)                      `json:"-"`
	ObserveBaseFirewall         func(context.Context, string, string) error                                                 `json:"-"`
	RejectBaseFirewall          func(context.Context, string, string) error                                                 `json:"-"`
	AuthorizeBaseFirewallDetach func(context.Context, string) (FirewallDetachmentAuthorization, error)                      `json:"-"`
	ObserveBaseFirewallDetach   func(context.Context, FirewallDetachmentFence) error                                        `json:"-"`
	RejectBaseFirewallDetach    func(context.Context, FirewallDetachmentFence) error                                        `json:"-"`
	AuthorizeFloatingIPUpdate   func(context.Context, string, string, string, int64) (FloatingIPUpdateAuthorization, error) `json:"-"`
	ObserveFloatingIPUpdate     func(context.Context, FloatingIPUpdateFence) error                                          `json:"-"`
	RejectFloatingIPUpdate      func(context.Context, FloatingIPUpdateFence) error                                          `json:"-"`
	AuthorizeRemovalMutation    func(context.Context, RemovalMutation, bool) (RemovalMutationAuthorization, error)          `json:"-"`
	ObserveRemovalMutation      func(context.Context, RemovalMutationFence) error                                           `json:"-"`
	RejectRemovalMutation       func(context.Context, RemovalMutationFence) error                                           `json:"-"`
}

type FirewallAssignmentPhase string

const (
	FirewallAssignmentIntent   FirewallAssignmentPhase = "intent"
	FirewallAssignmentIssued   FirewallAssignmentPhase = "issued"
	FirewallAssignmentRejected FirewallAssignmentPhase = "rejected"
	FirewallAssignmentObserved FirewallAssignmentPhase = "observed"
)

// FirewallAssignmentFence is the non-secret, durable state needed by the
// cloud adapter to distinguish a never-issued assignment from an ambiguous
// issued one. The timestamps remain in the provider-owned annotation record;
// the adapter needs only exact identity and phase.
type FirewallAssignmentFence struct {
	VMUUID       string
	FirewallUUID string
	Phase        FirewallAssignmentPhase
	IssueID      string
}

// FirewallAssignmentAuthorization distinguishes the invocation that won new
// POST authority from a retry that merely read an issued or observed receipt.
// AssignFirewallToVM is permitted only when AllowPOST is true.
type FirewallAssignmentAuthorization struct {
	Fence     FirewallAssignmentFence
	AllowPOST bool
}

// FirewallDetachmentFence is the durable, firewall-scoped receipt for one
// exact base-firewall relationship DELETE. An issued receipt is read-only
// after its owning invocation ends; authoritative relationship absence is the
// only automatic success proof after an ambiguous cloud response.
type FirewallDetachmentFence struct {
	VMUUID       string
	FirewallUUID string
	Phase        FirewallAssignmentPhase
	IssueID      string
}

type FirewallDetachmentAuthorization struct {
	Fence       FirewallDetachmentFence
	AllowDELETE bool
}

type FloatingIPUpdatePhase string

const (
	FloatingIPUpdateIssued   FloatingIPUpdatePhase = "issued"
	FloatingIPUpdateRejected FloatingIPUpdatePhase = "rejected"
	FloatingIPUpdateObserved FloatingIPUpdatePhase = "observed"
)

// FloatingIPUpdateFence is the exact durable receipt for the deterministic
// metadata PATCH of one auto-reserved floating IP. HTTP status is never
// terminal proof that the PATCH did not commit; an issued receipt is read-only
// after its owning invocation ends.
type FloatingIPUpdateFence struct {
	VMUUID           string
	Address          string
	Name             string
	BillingAccountID int64
	Phase            FloatingIPUpdatePhase
	IssueID          string
}

type FloatingIPUpdateAuthorization struct {
	Fence     FloatingIPUpdateFence
	AllowPOST bool
}

type RemovalMutationOperation string

const (
	RemovalMutationVMDelete           RemovalMutationOperation = "vm-delete"
	RemovalMutationFloatingIPUnassign RemovalMutationOperation = "floating-ip-unassign"
	RemovalMutationFloatingIPDelete   RemovalMutationOperation = "floating-ip-delete"
)

type RemovalMutationPhase string

const (
	RemovalMutationReady    RemovalMutationPhase = "ready"
	RemovalMutationIssued   RemovalMutationPhase = "issued"
	RemovalMutationRejected RemovalMutationPhase = "rejected"
	RemovalMutationObserved RemovalMutationPhase = "observed"
)

// RemovalMutation is the exact non-secret identity of one destructive cloud
// operation. Floating-IP fields are empty for a VM DELETE. The VM UUID remains
// part of dependent identities after unassignment so an address can never be
// reused as authority for another NodeClaim.
type RemovalMutation struct {
	Operation        RemovalMutationOperation
	Location         string
	VMUUID           string
	Address          string
	Name             string
	BillingAccountID int64
}

// RemovalMutationFence is a Kubernetes-durable one-shot mutation receipt.
// Issued remains read-only after any request may have reached InSpace. Only a
// locally blocked request may transition to Rejected and obtain a later issue.
type RemovalMutationFence struct {
	RemovalMutation
	Phase   RemovalMutationPhase
	IssueID string
}

type RemovalMutationAuthorization struct {
	Fence         RemovalMutationFence
	Active        bool
	AllowMutation bool
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
	FirewallUUID     string
	// FloatingIPUpdate is populated only by fenced rollback with an exact issued
	// or observed metadata-PATCH receipt. It lets cleanup accept either coherent
	// pre-PATCH blank/zero metadata or the complete desired metadata without
	// replaying the PATCH; partial and foreign states remain rejected.
	FloatingIPUpdate            FloatingIPUpdateFence
	AuthorizeBaseFirewallDetach func(context.Context, string) (FirewallDetachmentAuthorization, error)             `json:"-"`
	ObserveBaseFirewallDetach   func(context.Context, FirewallDetachmentFence) error                               `json:"-"`
	RejectBaseFirewallDetach    func(context.Context, FirewallDetachmentFence) error                               `json:"-"`
	AuthorizeRemovalMutation    func(context.Context, RemovalMutation, bool) (RemovalMutationAuthorization, error) `json:"-"`
	ObserveRemovalMutation      func(context.Context, RemovalMutationFence) error                                  `json:"-"`
	RejectRemovalMutation       func(context.Context, RemovalMutationFence) error                                  `json:"-"`
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
	ValidateNodeClass(ctx context.Context, location string, billingAccountID int64, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID string) error
}
