package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const (
	ControlPlaneReplicas  = 3
	BastionVCPU           = 1
	BastionMemoryMiB      = 2048
	BastionRootDiskGiB    = 30
	DefaultManagementCIDR = "0.0.0.0/0"

	defaultProtectionAuditTimeout            = 15 * time.Second
	defaultProtectionRequestTimeout          = 10 * time.Second
	defaultProtectionReadbackMinInterval     = 500 * time.Millisecond
	defaultProtectionReadbackMaxInterval     = 2 * time.Second
	defaultCreatedVMRecoveryTimeout          = 15 * time.Second
	defaultCreatedVMFloatingIPCleanupTimeout = 10 * time.Second
	defaultCreatedVMDeleteTimeout            = 10 * time.Second
)

var (
	sshUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,29}$`)
	vmUUIDPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// ErrRetryableAmbiguousVMDelete marks a VM DELETE whose commit status is
	// uncertain and whose exact in-memory deletion intent must survive a retry.
	ErrRetryableAmbiguousVMDelete  = errors.New("bootstrap: retryable ambiguous VM deletion outcome")
	errManagedFirewallNotVisible   = errors.New("bootstrap: managed firewall row is not yet visible during assignment readback")
	errOwnedVMMutationTargetAbsent = errors.New("bootstrap: owned VM mutation target is absent")
)

type API interface {
	ListHostPools(context.Context, string) ([]inspace.HostPool, error)
	GetNetwork(context.Context, string, string) (*inspace.Network, error)
	ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error)
	ListVMs(context.Context, string) ([]inspace.VM, error)
	GetVM(context.Context, string, string) (*inspace.VM, error)
	CreateVM(context.Context, string, inspace.CreateVMRequest) (*inspace.VM, error)
	DeleteVM(context.Context, string, string) error
	ListFirewalls(context.Context, string) ([]inspace.Firewall, error)
	CreateFirewall(context.Context, string, inspace.CreateFirewallRequest) (*inspace.Firewall, error)
	AssignFirewallToVM(context.Context, string, string, string) error
	DeleteFirewall(context.Context, string, string) error
	ListFloatingIPs(context.Context, string, *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error)
	UpdateFloatingIP(context.Context, string, string, inspace.UpdateFloatingIPRequest) (*inspace.FloatingIP, error)
	UnassignFloatingIP(context.Context, string, string) (*inspace.FloatingIP, error)
	DeleteFloatingIP(context.Context, string, string) error
}

type Reconciler struct {
	API API
	// StatusCompareAndSwap durably persists create/assignment intent, issue,
	// and materialization receipts before cloud mutations can advance.
	StatusCompareAndSwap StatusCompareAndSwapFunc
	// BootstrapCacheKey deterministically derives the private cache's P-256
	// CA and server key. Cached mode requires exactly 32 bytes. The raw key is
	// never sent to a VM or exposed in Result.
	BootstrapCacheKey []byte
	// BootstrapCacheNotBefore is minted once at cluster initialization and
	// persisted by the caller. Reusing it keeps the 15-year certificate and VM
	// ownership hashes stable across controller restarts.
	BootstrapCacheNotBefore time.Time
	// ModuleVersion selects the exact released InSpace controller images that
	// the bastion pre-seeds. Development builds must use directDownload.
	ModuleVersion string

	// SSHUsername and SSHPublicKey are optional and must be set together. The
	// public key is sent to InSpace's VM-create API; private key material is
	// never accepted by this package.
	SSHUsername  string
	SSHPublicKey string

	// ManagementCIDR permits either Any (the default 0.0.0.0/0) or one explicit
	// public IPv4 /32 to reach the exact TCP ports listed here and the bastion's
	// portless ICMP rule.
	ManagementCIDR     string
	ManagementTCPPorts []int

	// Fixed-node VM boot may overlap, but paid control-plane creates and InSpace
	// firewall relationship writes to one shared firewall are sequenced through
	// authoritative protection readback. Different firewall pairs remain independent.
	firewallAssignmentGates sync.Map
	statusMu                sync.Mutex

	protectionAuditTimeout            time.Duration
	protectionRequestTimeout          time.Duration
	protectionReadbackMinInterval     time.Duration
	protectionReadbackMaxInterval     time.Duration
	createdVMRecoveryTimeout          time.Duration
	createdVMFloatingIPCleanupTimeout time.Duration
	createdVMDeleteTimeout            time.Duration
	vmAbsenceObservationMinInterval   time.Duration
}

type privateIPv4Range struct {
	Start        netip.Addr
	Stop         netip.Addr
	AddressCount uint64
}

type bootstrapResourceNames struct {
	NodeFirewall      string
	BastionFirewall   string
	BastionFloatingIP string
	ControlPlaneFIP   [ControlPlaneReplicas]string
}

type Result struct {
	Ready                          bool          `json:"ready"`
	RequeueAfter                   time.Duration `json:"requeueAfter"`
	MaxParallelControlPlaneCreates int           `json:"maxParallelControlPlaneCreates,omitempty"`
	Owner                          string        `json:"owner"`
	FirewallUUID                   string        `json:"firewallUUID,omitempty"`
	BastionFirewallUUID            string        `json:"bastionFirewallUUID,omitempty"`
	BastionVMUUID                  string        `json:"bastionVMUUID,omitempty"`
	BastionPublicIPv4              string        `json:"bastionPublicIPv4,omitempty"`
	BastionPrivateIPv4             string        `json:"bastionPrivateIPv4,omitempty"`
	BootstrapCacheEndpoint         string        `json:"bootstrapCacheEndpoint,omitempty"`
	BootstrapCacheRegistry         string        `json:"bootstrapCacheRegistry,omitempty"`
	BootstrapCacheAddress          string        `json:"bootstrapCacheAddress,omitempty"`
	BootstrapCacheCABundle         string        `json:"bootstrapCacheCABundle,omitempty"`
	ControlPlaneEndpoint           string        `json:"controlPlaneEndpoint,omitempty"`
	PrivateControlPlaneEndpoint    string        `json:"privateControlPlaneEndpoint,omitempty"`
	PrivateRegistrationEndpoint    string        `json:"privateRegistrationEndpoint,omitempty"`
	ControlPlaneVMs                []string      `json:"controlPlaneVMs,omitempty"`
	Message                        string        `json:"message,omitempty"`
}

type DestroyResult struct {
	Done      bool     `json:"done"`
	Owner     string   `json:"owner"`
	Remaining []string `json:"remaining,omitempty"`
	Message   string   `json:"message,omitempty"`
}

func (r *Reconciler) Reconcile(ctx context.Context, cluster *v1alpha1.InSpaceCluster, rke2Token string) (Result, error) {
	if r.API == nil {
		return Result{}, errors.New("bootstrap: API is required")
	}
	if cluster == nil {
		return Result{}, errors.New("bootstrap: cluster is required")
	}
	r.ManagementCIDR = effectiveBastionManagementCIDR(r.ManagementCIDR)
	if errs := cluster.Validate(); len(errs) != 0 {
		return Result{}, fmt.Errorf("bootstrap: invalid cluster: %v", errs)
	}
	if cluster.Spec.BillingAccountID < 1 {
		return Result{}, errors.New("bootstrap: billingAccountID is required for managed floating IPv4")
	}
	if rke2Token == "" {
		return Result{}, errors.New("bootstrap: RKE2 token is required")
	}
	if err := r.validateBastionAccess(); err != nil {
		return Result{}, err
	}
	rollbackPending, err := r.resumeRollbackDeletes(ctx, cluster)
	if err != nil {
		return Result{}, err
	}
	if rollbackPending {
		return Result{}, fmt.Errorf("%w: malformed-create rollback is awaiting exact floating-IP/VM absence", ErrCreateAttemptPending)
	}
	owner := ownerKey(cluster)
	cacheTLS, err := r.bootstrapCacheTLS(cluster, owner)
	if err != nil {
		return Result{}, err
	}
	network, err := r.API.GetNetwork(ctx, cluster.Spec.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return Result{}, err
	}
	if network == nil || network.UUID != cluster.Spec.Network.UUID {
		return Result{}, errors.New("bootstrap: configured network readback UUID does not match spec.network.uuid")
	}
	if err := validatePrivateSubnet(network.Subnet); err != nil {
		return Result{}, err
	}
	if err := validateNetworkCIDRs(network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR); err != nil {
		return Result{}, err
	}
	if err := validateVirtualIPv4(network.Subnet, cluster.Spec.Endpoint.VirtualIPv4); err != nil {
		return Result{}, err
	}
	privatePool, err := validatePrivateLoadBalancerPool(
		network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR, cluster.Spec.Endpoint.VirtualIPv4,
		cluster.Spec.Network.PrivateLoadBalancerPool.Start, cluster.Spec.Network.PrivateLoadBalancerPool.Stop,
	)
	if err != nil {
		return Result{}, err
	}
	loadBalancers, err := r.API.ListLoadBalancers(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	if err := validateNoLoadBalancerVirtualIPCollision(loadBalancers, network.UUID, cluster.Spec.Endpoint.VirtualIPv4); err != nil {
		return Result{}, err
	}
	if err := validateNoLoadBalancerPoolCollision(loadBalancers, network.UUID, privatePool); err != nil {
		return Result{}, err
	}
	bastionVMName := currentBastionName(cluster.Metadata.Name)
	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	configuredNetworkVMs, err := vmsOnConfiguredNetwork(vms, network)
	if err != nil {
		if r.hasUnresolvedVMCreate(cluster) {
			return Result{}, fmt.Errorf("%w: VPC and VM inventory have not converged after an issued create: %v", ErrCreateAttemptPending, err)
		}
		return Result{}, err
	}
	byName, err := uniqueOwnedVMs(vms, owner, cluster.Metadata.Name)
	if err != nil {
		return Result{}, err
	}
	if err := validateControlPlaneBootstrapTopology(byName, cluster.Metadata.Name); err != nil {
		return Result{}, err
	}
	if err := validateNoVirtualIPCollision(configuredNetworkVMs, cluster.Spec.Endpoint.VirtualIPv4); err != nil {
		return Result{}, err
	}
	if err := validateNoVMPoolCollision(configuredNetworkVMs, privatePool); err != nil {
		return Result{}, err
	}
	byName, pendingVMDetail, err := r.canonicalOwnedVMDetails(ctx, cluster.Spec.Location, byName)
	if err != nil {
		return Result{}, err
	}
	if pendingVMDetail != "" {
		result := progressResult(nil, fmt.Sprintf("waiting for stale VM list entry %q to converge with authoritative detail", pendingVMDetail))
		result.Owner = owner
		return result, nil
	}
	floatingIPSnapshot, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return Result{}, err
	}
	firewalls, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	if err := validateCurrentBootstrapResourceTopology(floatingIPSnapshot, firewalls, legacyBootstrapResourceNames(owner)); err != nil {
		return Result{}, err
	}
	floatingByName, err := validateOwnedFloatingIPs(floatingIPSnapshot, cluster, resourceNames, byName)
	if err != nil {
		return Result{}, err
	}
	nodeFirewall, err := uniqueFirewallByName(firewalls, resourceNames.NodeFirewall)
	if err != nil {
		return Result{}, err
	}
	bastionFirewall, err := uniqueFirewallByName(firewalls, resourceNames.BastionFirewall)
	if err != nil {
		return Result{}, err
	}
	if err := validateManagedNodeFirewall(nodeFirewall, cluster, network, owner, resourceNames.NodeFirewall); err != nil {
		return Result{}, err
	}
	if err := validateManagedBastionFirewall(bastionFirewall, cluster, network.Subnet, owner, resourceNames.BastionFirewall, r.ManagementCIDR); err != nil {
		return Result{}, err
	}
	if err := validateOwnedFirewallAssignments(nodeFirewall, controlPlaneUUIDSet(byName, currentControlPlaneNames(cluster.Metadata.Name))); err != nil {
		return Result{}, fmt.Errorf("bootstrap: node firewall assignment drift: %w", err)
	}
	if err := validateOwnedFirewallAssignments(bastionFirewall, bastionUUIDSet(byName, bastionVMName)); err != nil {
		return Result{}, fmt.Errorf("bootstrap: bastion firewall assignment drift: %w", err)
	}
	if err := validateReverseFirewallAssignments(firewalls, nodeFirewall, bastionFirewall, byName, bastionVMName, currentControlPlaneNames(cluster.Metadata.Name)); err != nil {
		return Result{}, err
	}
	if err := r.validateExistingVMs(cluster, network, privatePool, owner, byName, rke2Token, cacheTLS); err != nil {
		return Result{}, err
	}
	if byName[bastionVMName] == nil && floatingByName[resourceNames.BastionFloatingIP] != nil {
		return Result{}, fmt.Errorf("bootstrap: refusing to create bastion VM while residual floating IP %q already exists", resourceNames.BastionFloatingIP)
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if byName[controlPlaneName(cluster.Metadata.Name, slot)] == nil && floatingByName[resourceNames.ControlPlaneFIP[slot]] != nil {
			return Result{}, fmt.Errorf("bootstrap: refusing to create control-plane slot %d while residual floating IP %q already exists", slot, resourceNames.ControlPlaneFIP[slot])
		}
	}

	bastion := byName[bastionVMName]
	var bastionIP *inspace.FloatingIP
	baseResult := func(vms []*inspace.VM, message string) Result {
		result := progressResult(vms, message)
		result.Owner = owner
		result.ControlPlaneEndpoint = fmt.Sprintf("https://%s:6443", cluster.Spec.Endpoint.VirtualIPv4)
		result.PrivateControlPlaneEndpoint = result.ControlPlaneEndpoint
		result.PrivateRegistrationEndpoint = fmt.Sprintf("https://%s:9345", cluster.Spec.Endpoint.VirtualIPv4)
		if nodeFirewall != nil {
			result.FirewallUUID = nodeFirewall.UUID
		}
		if bastionFirewall != nil {
			result.BastionFirewallUUID = bastionFirewall.UUID
		}
		if bastionIP != nil {
			result.BastionPublicIPv4 = bastionIP.Address
		}
		if bastion != nil {
			result.BastionVMUUID = bastion.UUID
			result.BastionPrivateIPv4 = bastion.PrivateIPv4
		}
		if !cluster.Spec.BootstrapCache.DirectDownload {
			hostname := bootstrapCacheHostname(cluster.Metadata.Name)
			result.BootstrapCacheEndpoint = fmt.Sprintf("https://%s:%d", hostname, BootstrapCachePort)
			result.BootstrapCacheRegistry = fmt.Sprintf("%s:%d", hostname, BootstrapCachePort)
			result.BootstrapCacheCABundle = cacheTLS.CACertificate
			if bastion != nil {
				result.BootstrapCacheAddress = bastion.PrivateIPv4
			}
		}
		return result
	}
	bastionRequest, err := r.desiredBastionVMRequest(cluster, network, owner, cacheTLS)
	if err != nil {
		return Result{}, err
	}
	if bastion == nil {
		bastionFirewall, err = r.ensureManagedBastionFirewall(ctx, cluster, network.Subnet, owner, bastionFirewall)
		if err != nil {
			return Result{}, err
		}
		if err := r.rejectResidualFloatingIPNames(ctx, cluster.Spec.Location, resourceNames.BastionFloatingIP); err != nil {
			return Result{}, err
		}
		secured, created, createErr := r.ensureManagedVMCreate(
			ctx, cluster, createAttemptBastionVM, bastionFirewall, nil, bastionRequest,
			resourceNames.BastionFloatingIP, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool,
		)
		if createErr != nil {
			return Result{}, createErr
		}
		bastion = secured
		if created {
			return baseResult(nil, "created and firewalled the private bastion; waiting for authoritative VM readback"), nil
		}
	} else {
		if _, _, err := r.ensureManagedVMCreate(
			ctx, cluster, createAttemptBastionVM, bastionFirewall, bastion, bastionRequest,
			resourceNames.BastionFloatingIP, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool,
		); err != nil {
			return Result{}, err
		}
	}
	bastionFirewall, err = r.ensureManagedBastionFirewall(ctx, cluster, network.Subnet, owner, bastionFirewall)
	if err != nil {
		return Result{}, err
	}
	protected, err := r.ensureVMProtection(ctx, cluster, createAttemptBastionFirewallAssignment, bastionFirewall, bastion)
	if err != nil {
		return Result{}, err
	}
	if !protected {
		return baseResult(nil, "waiting for bastion firewall assignment readback"), nil
	}
	if !isVMReady(bastion) {
		return baseResult(nil, "waiting for bastion private networking"), nil
	}
	if err := validateVMPrivateIPv4(bastion, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
		return Result{}, err
	}
	bastionIP, ready, err := r.ensureOwnedAutoFloatingIP(ctx, cluster, resourceNames.BastionFloatingIP, bastion, floatingByName[resourceNames.BastionFloatingIP])
	if err != nil {
		return Result{}, err
	}
	if !ready {
		return baseResult(nil, "waiting for the bastion auto floating IP assignment"), nil
	}
	nodeCache, err := nodeCacheConfig(cluster, bastion.PrivateIPv4, cacheTLS)
	if err != nil {
		return Result{}, err
	}
	controlled := make([]*inspace.VM, ControlPlaneReplicas)
	desiredRequests := make([]inspace.CreateVMRequest, ControlPlaneReplicas)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := controlPlaneName(cluster.Metadata.Name, slot)
		vm := byName[name]
		controlled[slot] = vm
		desired, desiredErr := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, cluster.Spec.Endpoint.VirtualIPv4, rke2Token, nodeCache)
		if desiredErr != nil {
			return Result{}, desiredErr
		}
		desiredRequests[slot] = desired
	}

	missing := 0
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if controlled[slot] == nil {
			missing++
		}
	}
	if missing != 0 {
		nodeFirewall, err = r.ensureManagedNodeFirewall(ctx, cluster, network, owner, nodeFirewall)
		if err != nil {
			return Result{}, err
		}
		missingFloatingIPNames := make([]string, 0, missing)
		for slot := 0; slot < ControlPlaneReplicas; slot++ {
			if controlled[slot] == nil {
				missingFloatingIPNames = append(missingFloatingIPNames, resourceNames.ControlPlaneFIP[slot])
			}
		}
		if err := r.rejectResidualFloatingIPNames(ctx, cluster.Spec.Location, missingFloatingIPNames...); err != nil {
			return Result{}, err
		}
		for slot := 0; slot < ControlPlaneReplicas; slot++ {
			if controlled[slot] != nil {
				if _, _, err := r.ensureManagedVMCreate(
					ctx, cluster, controlPlaneCreateAttemptKey(slot), nodeFirewall, controlled[slot], desiredRequests[slot],
					resourceNames.ControlPlaneFIP[slot], network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool,
				); err != nil {
					return baseResult(controlled, "stopped ordered control-plane creation while validating an existing slot"), fmt.Errorf("bootstrap: control-plane slot %d: %w", slot, err)
				}
				if _, err := r.ensureVMProtection(ctx, cluster, controlPlaneFirewallAssignmentAttemptKey(slot), nodeFirewall, controlled[slot]); err != nil {
					return baseResult(controlled, "stopped ordered control-plane creation until an existing slot is authoritatively firewalled"), fmt.Errorf("bootstrap: control-plane slot %d: %w", slot, err)
				}
				continue
			}
			// Re-check the exact slot immediately before its VM POST. More
			// importantly, do not advance to the next slot until this create has
			// completed its durable, authoritative restrictive-firewall proof.
			if err := r.rejectResidualFloatingIPNames(ctx, cluster.Spec.Location, resourceNames.ControlPlaneFIP[slot]); err != nil {
				return baseResult(controlled, "stopped ordered control-plane creation before a residual floating-IP collision"), fmt.Errorf("bootstrap: control-plane slot %d: %w", slot, err)
			}
			secured, _, err := r.ensureManagedVMCreate(
				ctx, cluster, controlPlaneCreateAttemptKey(slot), nodeFirewall, nil, desiredRequests[slot],
				resourceNames.ControlPlaneFIP[slot], network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool,
			)
			if err != nil {
				return baseResult(controlled, "stopped ordered control-plane creation until the current slot is authoritatively firewalled"), fmt.Errorf("bootstrap: control-plane slot %d: %w", slot, err)
			}
			controlled[slot] = secured
		}
		return baseResult(controlled, "created and firewalled missing private RKE2 control-plane VMs in deterministic slot order; VM boot may continue concurrently"), nil
	}
	nodeFirewall, err = r.ensureManagedNodeFirewall(ctx, cluster, network, owner, nodeFirewall)
	if err != nil {
		return Result{}, err
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if _, _, err := r.ensureManagedVMCreate(
			ctx, cluster, controlPlaneCreateAttemptKey(slot), nodeFirewall, controlled[slot], desiredRequests[slot],
			resourceNames.ControlPlaneFIP[slot], network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool,
		); err != nil {
			return Result{}, err
		}
	}
	allProtected := true
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		protected, protectErr := r.ensureVMProtection(ctx, cluster, controlPlaneFirewallAssignmentAttemptKey(slot), nodeFirewall, controlled[slot])
		if protectErr != nil {
			return Result{}, protectErr
		}
		allProtected = allProtected && protected
	}
	if !allProtected {
		return baseResult(controlled, "waiting for control-plane firewall assignment readback"), nil
	}

	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := controlled[slot]
		if err := validateOwnedVM(vm, desiredRequests[slot], network); err != nil {
			return Result{}, err
		}
		if vm.PrivateIPv4 == cluster.Spec.Endpoint.VirtualIPv4 {
			return Result{}, fmt.Errorf("bootstrap: control-plane VM %q private IPv4 collides with the virtual IPv4", vm.Name)
		}
		if !isVMReady(vm) {
			result := baseResult(controlled, "waiting for control-plane VM private networking")
			return result, nil
		}
		if err := validateVMPrivateIPv4(vm, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
			return Result{}, err
		}
		_, ready, err := r.ensureOwnedAutoFloatingIP(ctx, cluster, resourceNames.ControlPlaneFIP[slot], vm, floatingByName[resourceNames.ControlPlaneFIP[slot]])
		if err != nil {
			return Result{}, err
		}
		if !ready {
			result := baseResult(controlled, "waiting for control-plane auto floating IP assignments")
			return result, nil
		}
	}
	result := baseResult(controlled, "infrastructure reconciled; RKE2 API health is not yet probed")
	result.Ready = true
	result.RequeueAfter = 0
	return result, nil
}

// Destroy removes only infrastructure with the cluster's deterministic
// ownership names. It performs one fail-closed step per call so callers can
// persist progress and retry safely. Firewalls remain attached until every VM
// is confirmed absent.
func (r *Reconciler) Destroy(ctx context.Context, cluster *v1alpha1.InSpaceCluster) (DestroyResult, error) {
	if r.API == nil {
		return DestroyResult{}, errors.New("bootstrap: API is required")
	}
	if cluster == nil {
		return DestroyResult{}, errors.New("bootstrap: cluster is required")
	}
	r.ManagementCIDR = effectiveBastionManagementCIDR(r.ManagementCIDR)
	// Teardown validates the infrastructure spec but deliberately does not
	// apply create-time metadata.name constraints. Older clusters may have a
	// name that cannot form the current guest-hostname convention and must
	// still remain safely deletable through their owner records.
	if errs := cluster.Spec.Validate(); len(errs) != 0 {
		return DestroyResult{}, fmt.Errorf("bootstrap: invalid cluster: %v", errs)
	}
	if err := validateBastionFirewallAccess(r.ManagementCIDR, r.ManagementTCPPorts); err != nil {
		return DestroyResult{}, err
	}
	rollbackPending, err := r.resumeRollbackDeletes(ctx, cluster)
	if err != nil {
		return DestroyResult{}, err
	}
	if rollbackPending {
		return DestroyResult{Owner: ownerKey(cluster), Message: "waiting for durable malformed-create rollback"}, nil
	}
	owner := ownerKey(cluster)
	result := DestroyResult{Owner: owner}
	network, err := r.API.GetNetwork(ctx, cluster.Spec.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return result, err
	}
	if network == nil || network.UUID != cluster.Spec.Network.UUID {
		return result, errors.New("bootstrap: configured network readback UUID does not match spec.network.uuid")
	}
	if err := validatePrivateSubnet(network.Subnet); err != nil {
		return result, err
	}
	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return result, err
	}
	ownedVMs, controlPlaneNames, bastionVMName, err := uniqueDestroyVMs(vms, owner, cluster.Metadata.Name)
	if err != nil {
		return result, err
	}
	ownedVMs, pendingVMDetail, err := r.canonicalOwnedVMDetails(ctx, cluster.Spec.Location, ownedVMs)
	if err != nil {
		return result, err
	}
	if pendingVMDetail != "" {
		result.Remaining = []string{"vm/" + pendingVMDetail}
		result.Message = fmt.Sprintf("waiting for stale VM list entry %q to disappear after authoritative detail was not found", pendingVMDetail)
		return result, nil
	}
	if err := validateDestroyVMOwnership(ownedVMs, owner, cluster.Metadata.Name, bastionVMName, controlPlaneNames); err != nil {
		return result, err
	}
	floatingIPSnapshot, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return result, err
	}
	firewalls, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return result, err
	}
	resourceNames, err := selectDestroyBootstrapResourceNames(
		floatingIPSnapshot, firewalls,
		currentBootstrapResourceNames(cluster.Metadata.Name, owner),
		legacyBootstrapResourceNames(owner),
	)
	if err != nil {
		return result, err
	}
	floatingByName, err := validateOwnedFloatingIPsForControlPlanes(floatingIPSnapshot, cluster, resourceNames, ownedVMs, bastionVMName, controlPlaneNames)
	if err != nil {
		return result, err
	}
	bastionIPName := resourceNames.BastionFloatingIP
	floatingNames := []string{bastionIPName}
	floatingDeleteKeys := map[string]string{bastionIPName: destroyFIPBastionKey}
	floatingVMByName := map[string]*inspace.VM{bastionIPName: ownedVMs[bastionVMName]}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := resourceNames.ControlPlaneFIP[slot]
		floatingNames = append(floatingNames, name)
		floatingDeleteKeys[name] = destroyFIPControlPlaneKey(slot)
		floatingVMByName[name] = ownedVMs[controlPlaneNames[slot]]
	}
	for _, name := range floatingNames {
		item := floatingByName[name]
		if item != nil {
			result.Remaining = append(result.Remaining, "floating-ip/"+name)
		}
	}
	nodeFirewall, err := uniqueFirewallByName(firewalls, resourceNames.NodeFirewall)
	if err != nil {
		return result, err
	}
	bastionFirewall, err := uniqueFirewallByName(firewalls, resourceNames.BastionFirewall)
	if err != nil {
		return result, err
	}
	if err := validateManagedNodeFirewall(nodeFirewall, cluster, network, owner, resourceNames.NodeFirewall); err != nil {
		return result, err
	}
	if err := validateManagedBastionFirewallForDestroy(bastionFirewall, cluster, network.Subnet, owner, resourceNames.BastionFirewall, r.ManagementCIDR); err != nil {
		return result, err
	}
	durableDeletions, err := durableVMDeleteAssignments(cluster, firewalls)
	if err != nil {
		return result, err
	}
	for key, deletion := range durableDeletions {
		if deletion.Phase != deletePhaseVMIssued {
			continue
		}
		absent, observeErr := r.observeExactVMDeletion(ctx, cluster, key)
		if observeErr != nil {
			return result, errors.Join(ErrRetryableAmbiguousVMDelete, observeErr)
		}
		if absent {
			result.Message = "confirmed absent " + deletion.ResourceName
		} else {
			result.Message = "VM remains visible after exact deletion readback: " + deletion.ResourceName
		}
		return result, nil
	}
	for key, deletion := range durableDeletions {
		if deletion.Phase != deletePhaseVMIntent || ownedVMs[deletion.ResourceName] != nil {
			continue
		}
		absent, observeErr := r.observeExactVMDeletion(ctx, cluster, key)
		if observeErr != nil {
			return result, observeErr
		}
		if absent {
			result.Message = "confirmed externally absent " + deletion.ResourceName
		} else {
			result.Message = "waiting for VM inventory to include exact deletion target " + deletion.ResourceName
		}
		return result, nil
	}
	nodeAllowed := controlPlaneUUIDSet(ownedVMs, controlPlaneNames)
	bastionAllowed := bastionUUIDSet(ownedVMs, bastionVMName)
	for _, deletion := range durableDeletions {
		switch {
		case nodeFirewall != nil && deletion.FirewallUUID == nodeFirewall.UUID:
			nodeAllowed[deletion.ResourceUUID] = true
		case bastionFirewall != nil && deletion.FirewallUUID == bastionFirewall.UUID:
			bastionAllowed[deletion.ResourceUUID] = true
		default:
			visible := false
			for i := range firewalls {
				visible = visible || strings.EqualFold(firewalls[i].UUID, deletion.FirewallUUID)
			}
			if visible {
				return result, fmt.Errorf("bootstrap: durable deletion for VM %q references an unexpected managed firewall", deletion.ResourceName)
			}
		}
	}
	if err := validateOwnedFirewallAssignments(nodeFirewall, nodeAllowed); err != nil {
		return result, fmt.Errorf("bootstrap: refusing node firewall assignment drift: %w", err)
	}
	if err := validateOwnedFirewallAssignments(bastionFirewall, bastionAllowed); err != nil {
		return result, fmt.Errorf("bootstrap: refusing bastion firewall assignment drift: %w", err)
	}
	if err := validateReverseFirewallAssignments(firewalls, nodeFirewall, bastionFirewall, ownedVMs, bastionVMName, controlPlaneNames); err != nil {
		return result, err
	}
	vmNames := []string{bastionVMName}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vmNames = append(vmNames, controlPlaneNames[slot])
	}
	for _, name := range vmNames {
		if ownedVMs[name] != nil {
			result.Remaining = append(result.Remaining, "vm/"+name)
		}
	}
	for _, firewall := range []*inspace.Firewall{bastionFirewall, nodeFirewall} {
		if firewall != nil {
			result.Remaining = append(result.Remaining, "firewall/"+firewall.EffectiveName())
		}
	}
	sort.Strings(result.Remaining)

	for _, name := range floatingNames {
		item := floatingByName[name]
		deleteKey := floatingDeleteKeys[name]
		if item == nil {
			if attempt, exists := r.deleteAttempt(cluster, deleteKey); exists {
				if attempt.ResourceKind != deleteAttemptKindFloatingIP {
					return result, fmt.Errorf("bootstrap: floating-IP removal slot %q contains resource kind %q", deleteKey, attempt.ResourceKind)
				}
				if attempt.Phase == deletePhaseAbsent {
					continue
				}
				terminal, observeErr := r.observeDestroyRemovalTwice(ctx, cluster, deleteKey, func() (bool, error) {
					return r.observeDestroyFloatingIPRemoval(ctx, cluster, deleteKey)
				})
				if observeErr != nil {
					return result, observeErr
				}
				if terminal {
					continue
				}
			}
			continue
		}
		if attempt, exists := r.deleteAttempt(cluster, deleteKey); exists && attempt.Phase == deletePhaseAbsent {
			return result, fmt.Errorf("bootstrap: floating IP %q reappeared after durable authoritative absence", name)
		}
		if item.Name == "" {
			_, ready, renameErr := r.ensureOwnedAutoFloatingIP(ctx, cluster, name, floatingVMByName[name], item)
			if renameErr != nil {
				return result, renameErr
			}
			if !ready {
				result.Message = "waiting to name " + name + " before cleanup"
				return result, nil
			}
			result.Message = "named " + name + " before cleanup"
			return result, nil
		}
		if _, exists := r.deleteAttempt(cluster, deleteKey); !exists {
			if err := r.ensureDestroyFloatingIPRemoval(ctx, cluster, deleteKey, item); err != nil {
				return result, err
			}
		}
		terminal, removalErr := r.reconcileDestroyFloatingIPRemoval(ctx, cluster, deleteKey)
		if removalErr != nil {
			return result, removalErr
		}
		if terminal {
			result.Message = "deleted " + name
		} else {
			updated, _ := r.deleteAttempt(cluster, deleteKey)
			if updated.Phase == deletePhaseFIPDeleteIntent && item.AssignedTo != "" {
				result.Message = "unassigned " + name
			} else {
				result.Message = "advanced durable removal for " + name
			}
		}
		return result, nil
	}

	for _, name := range vmNames {
		vm := ownedVMs[name]
		if vm == nil {
			continue
		}
		firewallUUID := ""
		if name == bastionVMName {
			if bastionFirewall != nil {
				firewallUUID = bastionFirewall.UUID
			}
		} else if nodeFirewall != nil {
			firewallUUID = nodeFirewall.UUID
		}
		deleteKey, keyErr := deleteKeyForVMName(cluster, name)
		if keyErr != nil {
			return result, keyErr
		}
		if deletion, exists := durableDeletions[deleteKey]; exists && deletion.Phase == deletePhaseAbsent {
			return result, fmt.Errorf("bootstrap: VM %q reappeared after durable authoritative absence", name)
		}
		if err := r.ensureVMDeleteAttempt(ctx, cluster, deleteKey, deletePurposeDestroy, vm, firewallUUID, ""); err != nil {
			return result, err
		}
		absent, deleteErr := r.reconcileVMDelete(ctx, cluster, deleteKey)
		if deleteErr != nil {
			return result, deleteErr
		}
		if absent {
			result.Message = "confirmed absent " + vm.Name
		} else {
			result.Message = "issued exact deletion for " + vm.Name
		}
		return result, nil
	}
	deleteKeys := []string{deleteAttemptBastion}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		deleteKeys = append(deleteKeys, controlPlaneDeleteAttemptKey(slot))
	}
	for _, deleteKey := range deleteKeys {
		deletion, exists := durableDeletions[deleteKey]
		if !exists || deletion.Phase == deletePhaseAbsent {
			continue
		}
		absent, deleteErr := r.reconcileVMDelete(ctx, cluster, deleteKey)
		if deleteErr != nil {
			return result, deleteErr
		}
		if absent {
			result.Message = "confirmed absent " + deletion.ResourceName
		} else {
			result.Message = "waiting for authoritative VM absence before firewall teardown"
		}
		return result, nil
	}
	for _, removal := range []struct {
		firewall *inspace.Firewall
		key      string
		name     string
	}{
		{firewall: bastionFirewall, key: destroyFirewallBastionKey, name: resourceNames.BastionFirewall},
		{firewall: nodeFirewall, key: destroyFirewallNodesKey, name: resourceNames.NodeFirewall},
	} {
		firewall := removal.firewall
		if firewall == nil {
			if attempt, exists := r.deleteAttempt(cluster, removal.key); exists {
				if attempt.ResourceKind != deleteAttemptKindFirewall {
					return result, fmt.Errorf("bootstrap: firewall removal slot %q contains resource kind %q", removal.key, attempt.ResourceKind)
				}
				if attempt.Phase == deletePhaseAbsent {
					continue
				}
				terminal, observeErr := r.observeDestroyRemovalTwice(ctx, cluster, removal.key, func() (bool, error) {
					return r.observeDestroyFirewallRemoval(ctx, cluster, removal.key)
				})
				if observeErr != nil {
					return result, observeErr
				}
				if terminal {
					continue
				}
			}
			continue
		}
		if attempt, exists := r.deleteAttempt(cluster, removal.key); exists && attempt.Phase == deletePhaseAbsent {
			return result, fmt.Errorf("bootstrap: firewall %q reappeared after durable authoritative absence", removal.name)
		}
		if firewall != nil {
			if len(firewall.ResourcesAssigned) != 0 {
				result.Message = "waiting for firewall assignments to clear after VM deletion"
				return result, nil
			}
			if _, exists := r.deleteAttempt(cluster, removal.key); !exists {
				if err := r.ensureDestroyFirewallRemoval(ctx, cluster, removal.key, firewall); err != nil {
					return result, err
				}
			}
			terminal, removalErr := r.reconcileDestroyFirewallRemoval(ctx, cluster, removal.key)
			if removalErr != nil {
				return result, removalErr
			}
			if terminal {
				result.Message = "confirmed absent " + firewall.EffectiveName()
			} else {
				result.Message = "issued exact deletion for " + firewall.EffectiveName()
			}
			return result, nil
		}
	}

	if err := r.clearAllMutationAttempts(ctx, cluster); err != nil {
		return result, err
	}
	result.Done = true
	result.Message = "owned bastion and control-plane infrastructure is absent"
	return result, nil
}

// validateDestroyVMOwnership prevents deterministic-name collisions from
// becoming deletion authority. Destroy cannot recompute the full spec hash
// without the original RKE2 token, but it can require the versioned ownership
// record written by this controller and an exact control-plane slot name.
func validateDestroyVMOwnership(vms map[string]*inspace.VM, owner, clusterName, bastionVMName string, controlPlaneNames [ControlPlaneReplicas]string) error {
	hasControlPlaneV2 := false
	hasControlPlaneV3 := false
	hasControlPlaneV4 := false
	hasControlPlaneV5 := false
	hasControlPlaneV6 := false
	hasControlPlaneV7 := false
	hasControlPlaneV8 := false
	bastionSchema := 0
	for name, vm := range vms {
		if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
			return fmt.Errorf("bootstrap: refusing to delete VM %q with an invalid UUID", name)
		}
		var prefixes []string
		if name == bastionVMName {
			if name == legacyBastionName(owner) {
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=", owner))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v6 owner=%s spec=", owner))
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v5 owner=%s spec=", owner))
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v4 owner=%s spec=", owner))
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v3 owner=%s spec=", owner))
			}
		}
		slot := -1
		for candidate := 0; candidate < ControlPlaneReplicas; candidate++ {
			if name == controlPlaneNames[candidate] {
				slot = candidate
				if name == controlPlaneName(clusterName, candidate) {
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v8 owner=%s slot=%d spec=", owner, slot))
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v7 owner=%s slot=%d spec=", owner, slot))
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v6 owner=%s slot=%d spec=", owner, slot))
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v5 owner=%s slot=%d spec=", owner, slot))
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v4 owner=%s slot=%d spec=", owner, slot))
					prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v3 owner=%s slot=%d spec=", owner, slot))
				}
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=", owner, slot))
				break
			}
		}
		if len(prefixes) == 0 {
			return fmt.Errorf("bootstrap: refusing to delete VM %q outside the owned bastion/control-plane slots", name)
		}
		hash := ""
		matchedPrefix := ""
		for _, prefix := range prefixes {
			candidate := strings.TrimPrefix(vm.Description, prefix)
			if candidate != vm.Description {
				hash = candidate
				matchedPrefix = prefix
				break
			}
		}
		if len(hash) != sha256.Size*2 {
			return fmt.Errorf("bootstrap: refusing to delete VM %q without the expected ownership record", name)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("bootstrap: refusing to delete VM %q with an invalid ownership hash", name)
		}
		if slot >= 0 {
			hasControlPlaneV2 = hasControlPlaneV2 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v2 ")
			hasControlPlaneV3 = hasControlPlaneV3 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v3 ")
			hasControlPlaneV4 = hasControlPlaneV4 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v4 ")
			hasControlPlaneV5 = hasControlPlaneV5 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v5 ")
			hasControlPlaneV6 = hasControlPlaneV6 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v6 ")
			hasControlPlaneV7 = hasControlPlaneV7 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v7 ")
			hasControlPlaneV8 = hasControlPlaneV8 || strings.HasPrefix(matchedPrefix, "inspace-rke2-cp/v8 ")
		} else {
			switch {
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v1 "):
				bastionSchema = 1
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v3 "):
				bastionSchema = 3
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v4 "):
				bastionSchema = 4
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v5 "):
				bastionSchema = 5
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v6 "):
				bastionSchema = 6
			}
		}
	}
	schemaCount := 0
	for _, present := range []bool{hasControlPlaneV2, hasControlPlaneV3, hasControlPlaneV4, hasControlPlaneV5, hasControlPlaneV6, hasControlPlaneV7, hasControlPlaneV8} {
		if present {
			schemaCount++
		}
	}
	if schemaCount > 1 {
		return errors.New("bootstrap: refusing incoherent teardown ownership schema with mixed control-plane records")
	}
	if vms[bastionVMName] != nil && schemaCount == 1 {
		controlPlaneSchema := 2
		if hasControlPlaneV3 {
			controlPlaneSchema = 3
		} else if hasControlPlaneV4 {
			controlPlaneSchema = 4
		} else if hasControlPlaneV5 {
			controlPlaneSchema = 5
		} else if hasControlPlaneV6 {
			controlPlaneSchema = 6
		} else if hasControlPlaneV7 {
			controlPlaneSchema = 7
		} else if hasControlPlaneV8 {
			controlPlaneSchema = 8
		}
		expectedControlPlaneSchema := bastionSchema
		if bastionSchema == 1 {
			expectedControlPlaneSchema = 2
		}
		compatible := expectedControlPlaneSchema == controlPlaneSchema ||
			(bastionSchema == 6 && (controlPlaneSchema == 7 || controlPlaneSchema == 8))
		if !compatible {
			return errors.New("bootstrap: refusing incoherent teardown ownership schema: bastion and control planes use incompatible schemas")
		}
	}
	return nil
}

// canonicalOwnedVMDetails replaces the intentionally sparse ListVMs records
// for deterministic owned names with authoritative per-VM detail responses.
// The list remains the source for location-wide name/address collision checks;
// a detail response may only enrich an already identified list record, never
// introduce a new deletion or adoption candidate.
func (r *Reconciler) canonicalOwnedVMDetails(ctx context.Context, location string, listed map[string]*inspace.VM) (map[string]*inspace.VM, string, error) {
	names := make([]string, 0, len(listed))
	for name := range listed {
		names = append(names, name)
	}
	sort.Strings(names)

	details := make(map[string]*inspace.VM, len(listed))
	for _, name := range names {
		summary := listed[name]
		if summary == nil || !vmUUIDPattern.MatchString(summary.UUID) {
			return nil, "", fmt.Errorf("bootstrap: refusing authoritative detail lookup for VM %q with an invalid list UUID", name)
		}
		detail, err := r.API.GetVM(ctx, location, summary.UUID)
		if err != nil {
			if inspace.IsNotFound(err) {
				// A location-wide list can lag the per-VM endpoint after create or
				// delete. The stale row is neither adoption nor deletion authority;
				// stop this pass and wait for the two read models to converge.
				return nil, name, nil
			}
			return nil, "", fmt.Errorf("bootstrap: get authoritative detail for VM %q: %w", name, err)
		}
		if detail == nil {
			return nil, "", fmt.Errorf("bootstrap: authoritative detail for VM %q is missing", name)
		}
		if detail.UUID != summary.UUID || detail.Name != name {
			return nil, "", fmt.Errorf("bootstrap: authoritative detail identity for VM %q does not match list UUID/name", name)
		}
		details[name] = detail
	}
	return details, "", nil
}

func configuredDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

// deleteVMFailureProvesNoDispatch recognizes only the explicit local mutation
// guard, which rejects the request before it can reach the network. HTTP/API
// retry metadata is not commit evidence: every such failure, plus transport
// errors and cancellations, must retain the exact deletion transition.
func deleteVMFailureProvesNoDispatch(err error) bool {
	return errors.Is(err, inspace.ErrMutationBlocked)
}

// validateCreatedVMResponse only trusts fields that the create response
// actually supplied. Its exact UUID/name pair is enough to attach the already
// validated managed firewall immediately; canonical ownership and machine
// state are still required from authoritative readback before any later
// adoption or floating-IP mutation.
func validateCreatedVMResponse(vm *inspace.VM, desired inspace.CreateVMRequest, subnet, virtualIPv4 string, privatePool privateIPv4Range) error {
	if vm == nil {
		return errors.New("bootstrap: create VM returned an empty response")
	}
	if !vmUUIDPattern.MatchString(vm.UUID) {
		return errors.New("bootstrap: create VM response has an invalid UUID")
	}
	if vm.Name != desired.Name {
		return fmt.Errorf("bootstrap: create VM response name %q does not match %q", vm.Name, desired.Name)
	}
	if vm.Hostname != "" && vm.Hostname != desired.Name {
		return fmt.Errorf("bootstrap: create VM response hostname %q does not match %q", vm.Hostname, desired.Name)
	}
	if vm.Description != "" && vm.Description != desired.Description {
		return fmt.Errorf("bootstrap: create VM response for %q has ownership description drift", desired.Name)
	}
	if vm.VCPU != 0 && vm.VCPU != desired.VCPU || vm.MemoryMiB != 0 && vm.MemoryMiB != desired.MemoryMiB ||
		vm.OSName != "" && vm.OSName != desired.OSName || vm.OSVersion != "" && vm.OSVersion != desired.OSVersion ||
		vm.DesignatedPoolUUID != "" && vm.DesignatedPoolUUID != desired.DesignatedPoolUUID {
		return fmt.Errorf("bootstrap: create VM response for %q has compute, image, or pool drift", desired.Name)
	}
	if vm.BillingAccountID != 0 && vm.BillingAccountID != desired.BillingAccountID {
		return fmt.Errorf("bootstrap: create VM response for %q belongs to another billing account", desired.Name)
	}
	if vm.NetworkUUID != "" && vm.NetworkUUID != desired.NetworkUUID {
		return fmt.Errorf("bootstrap: create VM response for %q belongs to another private network", desired.Name)
	}
	if vm.PublicIPv4 != "" {
		return fmt.Errorf("bootstrap: create VM response for %q unexpectedly contains an implicit public IPv4", desired.Name)
	}
	if vm.PrivateIPv4 != "" {
		if err := validateVMPrivateIPv4(vm, subnet, virtualIPv4, privatePool); err != nil {
			return err
		}
	}
	if len(vm.Storage) != 0 {
		rootDiskMatches := false
		for _, disk := range vm.Storage {
			if disk.Primary && disk.SizeGiB == desired.DiskGiB {
				rootDiskMatches = true
				break
			}
		}
		if !rootDiskMatches {
			return fmt.Errorf("bootstrap: create VM response for %q has root disk drift", desired.Name)
		}
	}
	return nil
}

func (r *Reconciler) rollbackMalformedCreatedVM(ctx context.Context, cluster *v1alpha1.InSpaceCluster, attemptKey string, firewall *inspace.Firewall, vm *inspace.VM, desired inspace.CreateVMRequest, floatingIPName string, responseErr error) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) || vm.Name != desired.Name {
		return responseErr
	}
	deleteKey, keyErr := vmDeleteAttemptKeyForCreateKey(attemptKey)
	if keyErr != nil {
		return errors.Join(responseErr, keyErr)
	}
	firewallUUID := ""
	if firewall != nil {
		firewallUUID = firewall.UUID
	}
	rollbackCtx := context.WithoutCancel(ctx)
	if err := r.ensureVMDeleteAttempt(rollbackCtx, cluster, deleteKey, deletePurposeRollback, vm, firewallUUID, floatingIPName); err != nil {
		return errors.Join(responseErr, err)
	}
	done, rollbackErr := r.reconcileRollbackDelete(rollbackCtx, cluster, deleteKey)
	// Containment of a newly created but unprotected public VM is the one path
	// that deliberately waits for the second observation in the initiating
	// call. Each observation still performs independent exact-detail, location
	// inventory, and configured-VPC reads. Ordinary destroy never blocks here;
	// its second observation occurs in a later reconciliation.
	if !done && rollbackErr == nil {
		attempt, exists := r.deleteAttempt(cluster, deleteKey)
		if exists && attempt.Phase == deletePhaseVMIssued && attempt.AbsenceObservedAt != "" {
			firstObserved, parseErr := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
			if parseErr != nil || firstObserved.Location() != time.UTC {
				return errors.Join(responseErr, fmt.Errorf("bootstrap: rollback VM absence timestamp is invalid"))
			}
			remaining := time.Until(firstObserved.Add(configuredDuration(r.vmAbsenceObservationMinInterval, defaultVMAbsenceObservationMinInterval)))
			if remaining > 0 {
				timer := time.NewTimer(remaining)
				<-timer.C
			}
			done, rollbackErr = r.reconcileRollbackDelete(rollbackCtx, cluster, deleteKey)
		}
	}
	if !done && rollbackErr == nil {
		rollbackErr = fmt.Errorf("%w: malformed VM %s rollback is durably pending", ErrCreateAttemptPending, vm.UUID)
	}
	return errors.Join(responseErr, rollbackErr)
}

func (r *Reconciler) ensureManagedVMCreate(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	attemptKey string,
	firewall *inspace.Firewall,
	found *inspace.VM,
	desired inspace.CreateVMRequest,
	floatingIPName, subnet, virtualIPv4 string,
	privatePool privateIPv4Range,
) (*inspace.VM, bool, error) {
	location := cluster.Spec.Location
	billingAccountID := cluster.Spec.BillingAccountID
	networkUUID := cluster.Spec.Network.UUID
	hostPoolUUID := cluster.Spec.ControlPlane.Machine.HostPoolUUID
	clusterName := cluster.Metadata.Name
	intentHash, err := createIntentHash(createAttemptKindVM, desired.Name, desired)
	if err != nil {
		return nil, false, err
	}
	assignmentAttemptKey, err := firewallAssignmentAttemptKey(attemptKey)
	if err != nil {
		return nil, false, err
	}
	if found != nil {
		network, networkErr := r.API.GetNetwork(ctx, cluster.Spec.Location, desired.NetworkUUID)
		if networkErr != nil || network == nil {
			return nil, false, errors.Join(errors.New("bootstrap: get VPC before adopting existing VM"), networkErr)
		}
		if err := validateOwnedVM(found, desired, network); err != nil {
			return nil, false, err
		}
		attempt, exists := r.createAttempt(cluster, attemptKey)
		if !exists || attempt.Phase == createAttemptPhaseIntent {
			if err := r.recordAdoptedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, found.UUID); err != nil {
				return nil, false, err
			}
			return found, false, nil
		}
		if err := validateCreateAttempt(attempt, createAttemptKindVM, desired.Name, intentHash); err != nil {
			return nil, false, err
		}
		if attempt.Phase == createAttemptPhaseIssued || attempt.Phase == createAttemptPhaseRejected {
			if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, found.UUID); err != nil {
				return nil, false, err
			}
			return found, false, nil
		}
		if !strings.EqualFold(attempt.ResourceUUID, found.UUID) {
			return nil, false, fmt.Errorf("bootstrap: durable VM receipt for %q names UUID %s, authoritative readback returned %s", desired.Name, attempt.ResourceUUID, found.UUID)
		}
		return found, false, nil
	}

	attempt, exists := r.createAttempt(cluster, attemptKey)
	if exists {
		if err := validateCreateAttempt(attempt, createAttemptKindVM, desired.Name, intentHash); err != nil {
			return nil, false, err
		}
		if attempt.Phase == createAttemptPhaseRejected {
			if err := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash); err != nil {
				return nil, false, err
			}
			return nil, false, fmt.Errorf("%w: VM %q rejection is now authoritatively absent and may be retried", ErrCreateAttemptPending, desired.Name)
		}
		if attempt.Phase != createAttemptPhaseIntent {
			identityUUID := attempt.ResourceUUID
			var ownedIdentity *inspace.VM
			if identityUUID == "" {
				identity, discoveryErr := r.discoverCreatedVMIdentity(ctx, cluster, desired)
				if discoveryErr != nil {
					return nil, false, fmt.Errorf("%w: VM %q has no authoritative identity yet: %v", ErrCreateAttemptPending, desired.Name, discoveryErr)
				}
				ownedIdentity, discoveryErr = r.recoverCreatedVMOwnership(ctx, cluster, desired, identity.UUID)
				if discoveryErr != nil {
					return nil, false, fmt.Errorf("%w: VM %q exact recovery did not prove ownership: %v", ErrCreateAttemptPending, desired.Name, discoveryErr)
				}
				identityUUID = ownedIdentity.UUID
				if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, identityUUID); err != nil {
					return nil, false, err
				}
			}
			if ownedIdentity == nil {
				ownedIdentity, err = r.recoverCreatedVMOwnership(ctx, cluster, desired, identityUUID)
				if err != nil {
					return nil, false, fmt.Errorf("%w: VM %q exact recovery did not prove ownership: %v", ErrCreateAttemptPending, desired.Name, err)
				}
			}
			// A valid UUID, even one durably returned by CreateVM, is only a
			// readback anchor. Canonical VM fields and exact configured-VPC
			// membership must prove ownership before any second cloud mutation.
			if err := r.protectReturnedVMUUID(ctx, cluster, assignmentAttemptKey, firewall, ownedIdentity.UUID); err != nil {
				return nil, false, err
			}
			canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, identityUUID, subnet, virtualIPv4, privatePool)
			if recoveryErr != nil {
				return nil, false, r.rollbackMalformedCreatedVM(ctx, cluster, attemptKey, firewall, ownedIdentity, desired, floatingIPName,
					fmt.Errorf("bootstrap: canonically owned VM %q did not match its requested shape/address: %w", desired.Name, recoveryErr))
			}
			return canonical, false, nil
		}
	}

	allowed, err := r.authorizeCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash)
	if err != nil {
		return nil, false, err
	}
	if !allowed {
		return nil, false, fmt.Errorf("%w: VM %q cannot replay its issued create", ErrCreateAttemptPending, desired.Name)
	}
	// The issued receipt is necessary but not sufficient dispatch authority.
	// Re-read every mutable cloud input after the CAS. This includes the exact
	// VPC/subnet, host-pool catalog identity, managed firewall policy and
	// assignment topology, and finally the unfiltered deterministic-name VM
	// inventory. A stale pre-CAS snapshot can never authorize this paid POST.
	preDispatchCandidate, preDispatchAbsent, preDispatchErr := r.readVMCreateDispatchAuthority(
		ctx, cluster, location, billingAccountID, networkUUID, hostPoolUUID, clusterName,
		firewall, desired, subnet,
	)
	if preDispatchErr != nil {
		return nil, false, errors.Join(preDispatchErr,
			fmt.Errorf("%w: VM %q create is issued without fresh absence authority", ErrCreateAttemptPending, desired.Name))
	}
	if !preDispatchAbsent {
		ownedIdentity, ownershipErr := r.recoverCreatedVMOwnership(ctx, cluster, desired, preDispatchCandidate.UUID)
		if ownershipErr != nil {
			return nil, false, errors.Join(ownershipErr,
				fmt.Errorf("%w: VM %q appeared after create authorization but ownership is unproven", ErrCreateAttemptPending, desired.Name))
		}
		if anchorErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, ownedIdentity.UUID); anchorErr != nil {
			return nil, false, errors.Join(anchorErr,
				fmt.Errorf("%w: VM %q pre-dispatch adoption was not durably anchored", ErrCreateAttemptPending, desired.Name))
		}
		if protectionErr := r.protectReturnedVMUUID(ctx, cluster, assignmentAttemptKey, firewall, ownedIdentity.UUID); protectionErr != nil {
			return nil, false, protectionErr
		}
		canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, ownedIdentity.UUID, subnet, virtualIPv4, privatePool)
		if recoveryErr != nil {
			return nil, false, r.rollbackMalformedCreatedVM(ctx, cluster, attemptKey, firewall, ownedIdentity, desired, floatingIPName,
				fmt.Errorf("bootstrap: pre-dispatch adopted VM %q did not match its requested shape/address: %w", desired.Name, recoveryErr))
		}
		return canonical, false, nil
	}
	created, createErr := r.API.CreateVM(ctx, location, desired)
	exactResponseUUID := created != nil && vmUUIDPattern.MatchString(created.UUID)
	var anchorErr error
	if createErr != nil && !exactResponseUUID && bootstrapMutationFailureProvesNoDispatch(createErr) {
		if rejectionErr := r.recordPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash); rejectionErr != nil {
			return nil, true, errors.Join(createErr, rejectionErr,
				fmt.Errorf("%w: VM %q rejection receipt was not persisted", ErrCreateAttemptPending, desired.Name))
		}
		candidate, absent, readbackErr := r.readVMCreatePostError(ctx, cluster.Spec.Location, desired.Name)
		if readbackErr != nil {
			return nil, true, errors.Join(createErr, readbackErr,
				fmt.Errorf("%w: VM %q rejection lacks authoritative non-commit proof", ErrCreateAttemptPending, desired.Name))
		}
		if absent {
			clearErr := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash)
			return nil, true, errors.Join(createErr, clearErr)
		}
		canonical, recoveryErr := r.recoverCreatedVMOwnership(ctx, cluster, desired, candidate.UUID)
		if recoveryErr != nil {
			return nil, true, errors.Join(createErr, recoveryErr,
				fmt.Errorf("%w: VM %q appeared after local rejection but ownership is unproven", ErrCreateAttemptPending, desired.Name))
		}
		anchorErr = r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, canonical.UUID)
		var protectionErr error
		if anchorErr == nil {
			protectionErr = r.protectReturnedVMUUID(ctx, cluster, assignmentAttemptKey, firewall, canonical.UUID)
		}
		return nil, true, errors.Join(createErr, anchorErr, protectionErr,
			fmt.Errorf("%w: VM %q became visible after its rejection response", ErrCreateAttemptPending, desired.Name))
	}
	secured, secureErr := r.secureCreatedVMResponse(ctx, cluster, created, desired, subnet, virtualIPv4, privatePool)
	if secured != nil {
		// A CreateVM response UUID is provisional. Only the UUID returned by
		// canonical ownership/billing/VPC recovery may become the durable
		// materialized identity and authorize follow-up mutations.
		anchorErr = r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindVM, desired.Name, intentHash, secured.UUID)
	}
	if secured == nil || anchorErr != nil {
		return nil, true, errors.Join(createErr, secureErr, anchorErr,
			fmt.Errorf("%w: VM %q POST outcome requires authoritative recovery", ErrCreateAttemptPending, desired.Name))
	}
	protectionErr := r.protectReturnedVMUUID(ctx, cluster, assignmentAttemptKey, firewall, secured.UUID)
	if protectionErr != nil || secureErr != nil {
		return nil, true, r.rollbackMalformedCreatedVM(ctx, cluster, attemptKey, firewall, secured, desired, floatingIPName,
			errors.Join(createErr, secureErr, protectionErr))
	}
	if createErr != nil {
		return nil, true, errors.Join(createErr,
			fmt.Errorf("%w: VM %q POST returned an error after canonical ownership and protection converged", ErrCreateAttemptPending, desired.Name))
	}
	return secured, true, nil
}

// readVMCreatePostError is the mandatory fresh authority after the SDK proves
// locally that the VM POST was blocked before dispatch. A pre-POST snapshot is
// not enough: an independently submitted matching VM may already be becoming
// visible. One exact deterministic-name row therefore wins over the local
// block, while only a successful fresh list with no such row permits the
// pre-dispatch rejection receipt to be cleared. HTTP responses never enter
// this path and can never be cleared by absence.
func (r *Reconciler) readVMCreatePostError(ctx context.Context, location, name string) (*inspace.VM, bool, error) {
	items, err := r.API.ListVMs(ctx, location)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: list VMs after rejected create of %q: %w", name, err)
	}
	var found *inspace.VM
	for i := range items {
		if items[i].Name != name {
			continue
		}
		if found != nil {
			return nil, false, fmt.Errorf("bootstrap: multiple VMs named %q appeared after its create error", name)
		}
		copy := items[i]
		found = &copy
	}
	if found == nil {
		return nil, true, nil
	}
	if !vmUUIDPattern.MatchString(found.UUID) {
		return nil, false, fmt.Errorf("bootstrap: VM %q appeared after its create error with invalid UUID %q", name, found.UUID)
	}
	return found, false, nil
}

// readVMCreateDispatchAuthority is the final post-CAS gate for a paid VM
// create. Every value supplied by the earlier reconciliation snapshot is only
// a candidate until independent cloud reads prove it again. The host-pool API
// has no exact-detail endpoint, so its unfiltered catalog is treated as a set:
// exactly one visible row must carry the configured UUID.
func (r *Reconciler) readVMCreateDispatchAuthority(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	location string,
	billingAccountID int64,
	networkUUID string,
	hostPoolUUID string,
	clusterName string,
	capturedFirewall *inspace.Firewall,
	desired inspace.CreateVMRequest,
	capturedSubnet string,
) (*inspace.VM, bool, error) {
	if cluster == nil || location == "" || billingAccountID <= 0 || clusterName == "" ||
		!vmUUIDPattern.MatchString(networkUUID) || !vmUUIDPattern.MatchString(hostPoolUUID) {
		return nil, false, errors.New("bootstrap: VM create authority has invalid captured cluster identity")
	}
	if cluster.Metadata.Name != clusterName || cluster.Spec.Location != location ||
		cluster.Spec.BillingAccountID != billingAccountID ||
		!strings.EqualFold(cluster.Spec.Network.UUID, networkUUID) ||
		!strings.EqualFold(cluster.Spec.ControlPlane.Machine.HostPoolUUID, hostPoolUUID) {
		return nil, false, errors.New("bootstrap: cluster identity changed after VM create issue CAS")
	}
	if desired.BillingAccountID != billingAccountID || desired.BillingAccountID <= 0 ||
		!strings.EqualFold(desired.NetworkUUID, networkUUID) ||
		!strings.EqualFold(desired.DesignatedPoolUUID, hostPoolUUID) {
		return nil, false, errors.New("bootstrap: VM request billing, VPC, or host-pool identity changed before dispatch")
	}

	network, err := r.API.GetNetwork(ctx, location, networkUUID)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: fresh configured VPC read before VM create: %w", err)
	}
	if network == nil || !strings.EqualFold(network.UUID, networkUUID) || network.Subnet != capturedSubnet {
		return nil, false, errors.New("bootstrap: configured VPC UUID/subnet changed before VM create")
	}
	if err := validatePrivateSubnet(network.Subnet); err != nil {
		return nil, false, err
	}
	if err := validateNetworkCIDRs(network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR); err != nil {
		return nil, false, err
	}
	if err := validateVirtualIPv4(network.Subnet, cluster.Spec.Endpoint.VirtualIPv4); err != nil {
		return nil, false, err
	}
	if _, err := validatePrivateLoadBalancerPool(
		network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR,
		cluster.Spec.Endpoint.VirtualIPv4, cluster.Spec.Network.PrivateLoadBalancerPool.Start,
		cluster.Spec.Network.PrivateLoadBalancerPool.Stop,
	); err != nil {
		return nil, false, err
	}

	hostPools, err := r.API.ListHostPools(ctx, location)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: fresh host-pool catalog before VM create: %w", err)
	}
	matchingHostPools := 0
	for i := range hostPools {
		if !strings.EqualFold(hostPools[i].UUID, hostPoolUUID) {
			continue
		}
		matchingHostPools++
		if !hostPools[i].IsVisible || hostPools[i].Name == "" {
			return nil, false, fmt.Errorf("bootstrap: configured host pool %s is not a visible catalog identity", hostPoolUUID)
		}
	}
	if matchingHostPools != 1 {
		return nil, false, fmt.Errorf("bootstrap: host-pool catalog contains %d rows for %s, want one", matchingHostPools, hostPoolUUID)
	}

	if capturedFirewall == nil || !vmUUIDPattern.MatchString(capturedFirewall.UUID) {
		return nil, false, errors.New("bootstrap: VM create lacks a captured managed firewall UUID")
	}
	firewalls, err := r.API.ListFirewalls(ctx, location)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: fresh firewall inventory before VM create: %w", err)
	}
	resourceNames := currentBootstrapResourceNames(clusterName, ownerKey(cluster))
	nodeFirewall, err := uniqueFirewallByName(firewalls, resourceNames.NodeFirewall)
	if err != nil {
		return nil, false, err
	}
	bastionFirewall, err := uniqueFirewallByName(firewalls, resourceNames.BastionFirewall)
	if err != nil {
		return nil, false, err
	}
	var targetFirewall *inspace.Firewall
	switch {
	case desired.Name == currentBastionName(clusterName):
		targetFirewall = bastionFirewall
		if err := validateManagedBastionFirewall(targetFirewall, cluster, network.Subnet, ownerKey(cluster), resourceNames.BastionFirewall, r.ManagementCIDR); err != nil {
			return nil, false, err
		}
	case isCurrentControlPlaneName(clusterName, desired.Name):
		targetFirewall = nodeFirewall
		if err := validateManagedNodeFirewall(targetFirewall, cluster, network, ownerKey(cluster), resourceNames.NodeFirewall); err != nil {
			return nil, false, err
		}
	default:
		return nil, false, fmt.Errorf("bootstrap: VM create name %q is outside the managed bootstrap topology", desired.Name)
	}
	if targetFirewall == nil || !strings.EqualFold(targetFirewall.UUID, capturedFirewall.UUID) {
		return nil, false, errors.New("bootstrap: managed firewall UUID changed before VM create")
	}
	exactFirewallRows := 0
	for i := range firewalls {
		if strings.EqualFold(firewalls[i].UUID, capturedFirewall.UUID) {
			exactFirewallRows++
		}
	}
	if exactFirewallRows != 1 {
		return nil, false, fmt.Errorf("bootstrap: managed firewall UUID has %d exact inventory rows, want one", exactFirewallRows)
	}

	listedVMs, err := r.API.ListVMs(ctx, location)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: fresh VM inventory for firewall assignment authority: %w", err)
	}
	if _, err := vmsOnConfiguredNetwork(listedVMs, network); err != nil {
		return nil, false, fmt.Errorf("bootstrap: configured VPC membership changed before VM create: %w", err)
	}
	ownedVMs, err := uniqueOwnedVMs(listedVMs, ownerKey(cluster), clusterName)
	if err != nil {
		return nil, false, err
	}
	canonicalOwnedVMs := make(map[string]*inspace.VM, len(ownedVMs))
	for name, listed := range ownedVMs {
		if listed == nil {
			return nil, false, fmt.Errorf("bootstrap: owned VM %q has an empty inventory row", name)
		}
		detail, detailErr := r.readExactOwnedVMMutationAuthority(ctx, cluster, listed.UUID, name)
		if detailErr != nil {
			return nil, false, fmt.Errorf("bootstrap: owned VM %q lacks post-CAS assignment authority: %w", name, detailErr)
		}
		canonicalOwnedVMs[name] = detail
	}
	ownedVMs = canonicalOwnedVMs
	controlPlaneNames := currentControlPlaneNames(clusterName)
	if err := validateOwnedFirewallAssignments(nodeFirewall, controlPlaneUUIDSet(ownedVMs, controlPlaneNames)); err != nil {
		return nil, false, fmt.Errorf("bootstrap: node firewall assignment drift before VM create: %w", err)
	}
	if err := validateOwnedFirewallAssignments(bastionFirewall, bastionUUIDSet(ownedVMs, currentBastionName(clusterName))); err != nil {
		return nil, false, fmt.Errorf("bootstrap: bastion firewall assignment drift before VM create: %w", err)
	}
	if err := validateReverseFirewallAssignments(
		firewalls, nodeFirewall, bastionFirewall, ownedVMs,
		currentBastionName(clusterName), controlPlaneNames,
	); err != nil {
		return nil, false, err
	}

	// Keep deterministic-name absence as the final cloud read immediately
	// before POST. If a concurrent exact object appeared, the caller switches
	// to canonical Get/List/VPC adoption and dispatches nothing.
	return r.readVMCreatePostError(ctx, location, desired.Name)
}

func isCurrentControlPlaneName(clusterName, name string) bool {
	for _, candidate := range currentControlPlaneNames(clusterName) {
		if name == candidate {
			return true
		}
	}
	return false
}

// secureCreatedVMResponse resolves a CreateVM response to canonical owned VM
// state. Despite its historical name, this helper deliberately performs no
// mutation: a syntactically valid response UUID or one exact-name list row is
// only a lookup anchor. The caller must durably persist that identity before
// attaching a firewall, updating a floating IP, or authorizing rollback.
func (r *Reconciler) secureCreatedVMResponse(ctx context.Context, cluster *v1alpha1.InSpaceCluster, vm *inspace.VM, desired inspace.CreateVMRequest, subnet, virtualIPv4 string, privatePool privateIPv4Range) (*inspace.VM, error) {
	responseErr := validateCreatedVMResponse(vm, desired, subnet, virtualIPv4, privatePool)
	var provisionalErr error
	if vm != nil && vmUUIDPattern.MatchString(vm.UUID) {
		canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, vm.UUID, subnet, virtualIPv4, privatePool)
		if recoveryErr == nil {
			return canonical, nil
		}
		ownedIdentity, ownershipErr := r.recoverCreatedVMOwnership(ctx, cluster, desired, vm.UUID)
		if ownershipErr == nil {
			return ownedIdentity, errors.Join(responseErr, fmt.Errorf("bootstrap: canonical created VM shape/address recovery: %w", recoveryErr))
		}
		// A stale or malformed response UUID is diagnostic only. The issued
		// create fence prevents replay while deterministic-name discovery finds
		// the actual canonically owned VM produced by this POST.
		provisionalErr = errors.Join(recoveryErr, ownershipErr)
	}

	identity, discoveryErr := r.discoverCreatedVMIdentity(ctx, cluster, desired)
	if discoveryErr != nil {
		return nil, errors.Join(responseErr, provisionalErr,
			fmt.Errorf("bootstrap: created VM ownership is uncertain because exact-name discovery did not converge: %w", discoveryErr))
	}
	canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, identity.UUID, subnet, virtualIPv4, privatePool)
	if recoveryErr == nil {
		return canonical, nil
	}
	ownedIdentity, ownershipErr := r.recoverCreatedVMOwnership(ctx, cluster, desired, identity.UUID)
	if ownershipErr != nil {
		return nil, errors.Join(responseErr, provisionalErr,
			fmt.Errorf("bootstrap: discovered created VM ownership recovery: %w", ownershipErr))
	}
	return ownedIdentity, errors.Join(responseErr,
		fmt.Errorf("bootstrap: canonical discovered VM shape/address recovery: %w", recoveryErr))
}

func (r *Reconciler) protectReturnedVMUUID(ctx context.Context, cluster *v1alpha1.InSpaceCluster, assignmentAttemptKey string, firewall *inspace.Firewall, vmUUID string) error {
	if firewall == nil || !vmUUIDPattern.MatchString(firewall.UUID) {
		return errors.New("bootstrap: cannot protect a created VM without its validated managed firewall")
	}
	if !vmUUIDPattern.MatchString(vmUUID) {
		return errors.New("bootstrap: cannot protect a created VM without its returned or recovered UUID")
	}
	return r.ensureExactFirewallAssignment(context.WithoutCancel(ctx), cluster, assignmentAttemptKey, firewall, vmUUID)
}

// discoverCreatedVMIdentity obtains the minimum authoritative identity needed
// to protect a create whose response omitted a usable UUID. Only one exact
// deterministic-name row is acceptable; malformed or duplicate exact rows are
// ambiguity, not a reason to issue a second create.
func (r *Reconciler) discoverCreatedVMIdentity(ctx context.Context, cluster *v1alpha1.InSpaceCluster, desired inspace.CreateVMRequest) (*inspace.VM, error) {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMRecoveryTimeout, defaultCreatedVMRecoveryTimeout))
	defer cancel()
	requestTimeout := configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout)
	delay := configuredDuration(r.protectionReadbackMinInterval, defaultProtectionReadbackMinInterval)
	maxDelay := configuredDuration(r.protectionReadbackMaxInterval, defaultProtectionReadbackMaxInterval)
	if maxDelay < delay {
		maxDelay = delay
	}
	var lastErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(recoveryCtx, requestTimeout)
		items, err := r.API.ListVMs(requestCtx, cluster.Spec.Location)
		requestCancel()
		if err != nil {
			lastErr = fmt.Errorf("list VMs during create recovery: %w", err)
		} else {
			var candidate *inspace.VM
			for i := range items {
				if items[i].Name != desired.Name {
					continue
				}
				if candidate != nil {
					return nil, fmt.Errorf("multiple VMs named %q appeared during create recovery", desired.Name)
				}
				copy := items[i]
				candidate = &copy
			}
			if candidate == nil {
				lastErr = fmt.Errorf("VM %q is not yet visible during create recovery", desired.Name)
			} else if !vmUUIDPattern.MatchString(candidate.UUID) {
				return nil, fmt.Errorf("VM %q has an invalid UUID during create recovery", desired.Name)
			} else {
				return &inspace.VM{UUID: candidate.UUID, Name: desired.Name}, nil
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-recoveryCtx.Done():
			timer.Stop()
			return nil, errors.Join(lastErr, recoveryCtx.Err())
		case <-timer.C:
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

// recoverCreatedVMOwnership proves only the fields that can safely authorize a
// follow-up mutation or rollback. It intentionally does not require the
// requested compute shape, disk, or private address: if InSpace materialized
// those incorrectly, the exact controller description, positive billing ID,
// deterministic name, UUID, and configured-VPC membership still prove which
// malformed VM this controller owns and may contain/delete.
func (r *Reconciler) recoverCreatedVMOwnership(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	desired inspace.CreateVMRequest,
	returnedUUID string,
) (*inspace.VM, error) {
	if !vmUUIDPattern.MatchString(returnedUUID) {
		return nil, errors.New("bootstrap: created VM ownership recovery requires an exact UUID")
	}
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMRecoveryTimeout, defaultCreatedVMRecoveryTimeout))
	defer cancel()
	requestTimeout := configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout)
	delay := configuredDuration(r.protectionReadbackMinInterval, defaultProtectionReadbackMinInterval)
	maxDelay := configuredDuration(r.protectionReadbackMaxInterval, defaultProtectionReadbackMaxInterval)
	if maxDelay < delay {
		maxDelay = delay
	}
	var lastErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(recoveryCtx, requestTimeout)
		detail, detailErr := r.API.GetVM(requestCtx, cluster.Spec.Location, returnedUUID)
		requestCancel()
		if detailErr != nil || detail == nil {
			lastErr = errors.Join(fmt.Errorf("get exact VM %q during ownership recovery", desired.Name), detailErr)
		} else if !strings.EqualFold(detail.UUID, returnedUUID) || detail.Name != desired.Name {
			lastErr = fmt.Errorf("bootstrap: exact VM readback for %q changed UUID/name identity", desired.Name)
		} else if detail.Description != desired.Description {
			lastErr = fmt.Errorf("bootstrap: exact VM %q lacks the requested ownership/spec description", desired.Name)
		} else if detail.BillingAccountID != desired.BillingAccountID || desired.BillingAccountID <= 0 {
			lastErr = fmt.Errorf("bootstrap: exact VM %q lacks positive requested billing ownership", desired.Name)
		} else if detail.NetworkUUID != "" && !strings.EqualFold(detail.NetworkUUID, desired.NetworkUUID) {
			lastErr = fmt.Errorf("bootstrap: exact VM %q reports another private network", desired.Name)
		} else {
			requestCtx, requestCancel = context.WithTimeout(recoveryCtx, requestTimeout)
			listed, listErr := r.API.ListVMs(requestCtx, cluster.Spec.Location)
			requestCancel()
			if listErr != nil {
				lastErr = fmt.Errorf("list VMs during ownership recovery for %q: %w", desired.Name, listErr)
				goto retry
			}
			if listErr = validateUniqueVMInventoryIdentity(listed, detail, desired.BillingAccountID, desired.NetworkUUID); listErr != nil {
				lastErr = fmt.Errorf("bootstrap: location inventory during ownership recovery for %q: %w", desired.Name, listErr)
				goto retry
			}
			requestCtx, requestCancel = context.WithTimeout(recoveryCtx, requestTimeout)
			network, networkErr := r.API.GetNetwork(requestCtx, cluster.Spec.Location, desired.NetworkUUID)
			requestCancel()
			if networkErr != nil || network == nil {
				lastErr = errors.Join(errors.New("get configured VPC during VM ownership recovery"), networkErr)
			} else if !strings.EqualFold(network.UUID, desired.NetworkUUID) {
				lastErr = errors.New("bootstrap: configured VPC identity changed during VM ownership recovery")
			} else {
				memberships := 0
				for _, vmUUID := range network.VMUUIDs {
					if strings.EqualFold(vmUUID, returnedUUID) {
						memberships++
					}
				}
				if memberships == 1 {
					return detail, nil
				}
				lastErr = fmt.Errorf("bootstrap: exact VM %q has %d configured-VPC memberships, want one", desired.Name, memberships)
			}
		}

	retry:
		timer := time.NewTimer(delay)
		select {
		case <-recoveryCtx.Done():
			timer.Stop()
			return nil, errors.Join(lastErr, recoveryCtx.Err())
		case <-timer.C:
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (r *Reconciler) recoverCreatedVM(ctx context.Context, cluster *v1alpha1.InSpaceCluster, desired inspace.CreateVMRequest, returnedUUID, subnet, virtualIPv4 string, privatePool privateIPv4Range) (*inspace.VM, error) {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMRecoveryTimeout, defaultCreatedVMRecoveryTimeout))
	defer cancel()
	requestTimeout := configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout)
	delay := configuredDuration(r.protectionReadbackMinInterval, defaultProtectionReadbackMinInterval)
	maxDelay := configuredDuration(r.protectionReadbackMaxInterval, defaultProtectionReadbackMaxInterval)
	if maxDelay < delay {
		maxDelay = delay
	}
	var lastErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(recoveryCtx, requestTimeout)
		detail, detailErr := r.API.GetVM(requestCtx, cluster.Spec.Location, returnedUUID)
		requestCancel()
		if detailErr != nil || detail == nil {
			lastErr = errors.Join(fmt.Errorf("get VM %q during create recovery", desired.Name), detailErr)
		} else {
			requestCtx, requestCancel = context.WithTimeout(recoveryCtx, requestTimeout)
			network, networkErr := r.API.GetNetwork(requestCtx, cluster.Spec.Location, desired.NetworkUUID)
			requestCancel()
			if networkErr != nil || network == nil {
				lastErr = errors.Join(errors.New("get VPC during create recovery"), networkErr)
			} else if validationErr := validateOwnedVM(detail, desired, network); validationErr != nil {
				lastErr = validationErr
			} else if detail.PrivateIPv4 != "" {
				if validationErr := validateVMPrivateIPv4(detail, subnet, virtualIPv4, privatePool); validationErr != nil {
					lastErr = validationErr
				} else {
					return detail, nil
				}
			} else {
				return detail, nil
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-recoveryCtx.Done():
			timer.Stop()
			return nil, errors.Join(lastErr, recoveryCtx.Err())
		case <-timer.C:
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (r *Reconciler) ensureManagedNodeFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	expectedName := currentBootstrapResourceNames(cluster.Metadata.Name, owner).NodeFirewall
	request := inspace.CreateFirewallRequest{
		DisplayName: expectedName, Description: "Managed RKE2 node firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedFirewallRules(network.Subnet, cluster.Spec.Network.PodCIDR, "", nil),
	}
	return r.ensureManagedFirewallCreate(ctx, cluster, createAttemptNodeFirewall, "node", request, found, network.Subnet, func(firewall *inspace.Firewall) error {
		return validateManagedNodeFirewall(firewall, cluster, network, owner, expectedName)
	})
}

func (r *Reconciler) ensureManagedBastionFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, privateSubnet, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	expectedName := currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFirewall
	request := inspace.CreateFirewallRequest{
		DisplayName: expectedName, Description: "Managed RKE2 bastion firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedBastionFirewallRules(r.ManagementCIDR, privateSubnet, !cluster.Spec.BootstrapCache.DirectDownload),
	}
	return r.ensureManagedFirewallCreate(ctx, cluster, createAttemptBastionFirewall, "bastion", request, found, privateSubnet, func(firewall *inspace.Firewall) error {
		return validateManagedBastionFirewall(firewall, cluster, privateSubnet, owner, expectedName, r.ManagementCIDR)
	})
}

func (r *Reconciler) ensureManagedFirewallCreate(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	attemptKey string,
	role string,
	request inspace.CreateFirewallRequest,
	found *inspace.Firewall,
	capturedSubnet string,
	validate func(*inspace.Firewall) error,
) (*inspace.Firewall, error) {
	location := cluster.Spec.Location
	billingAccountID := cluster.Spec.BillingAccountID
	networkUUID := cluster.Spec.Network.UUID
	intentHash, err := createIntentHash(createAttemptKindFirewall, request.DisplayName, request)
	if err != nil {
		return nil, err
	}
	if found != nil {
		if err := validate(found); err != nil {
			return nil, err
		}
		attempt, exists := r.createAttempt(cluster, attemptKey)
		if !exists || attempt.Phase == createAttemptPhaseIntent {
			if err := r.recordAdoptedCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash, found.UUID); err != nil {
				return nil, err
			}
			return found, nil
		}
		if err := validateCreateAttempt(attempt, createAttemptKindFirewall, request.DisplayName, intentHash); err != nil {
			return nil, err
		}
		if attempt.Phase == createAttemptPhaseIssued || attempt.Phase == createAttemptPhaseRejected {
			if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash, found.UUID); err != nil {
				return nil, err
			}
			return found, nil
		}
		if !strings.EqualFold(attempt.ResourceUUID, found.UUID) {
			return nil, fmt.Errorf("bootstrap: durable firewall receipt for %q names UUID %s, authoritative readback returned %s", request.DisplayName, attempt.ResourceUUID, found.UUID)
		}
		return found, nil
	}
	attempt, exists := r.createAttempt(cluster, attemptKey)
	if exists {
		if err := validateCreateAttempt(attempt, createAttemptKindFirewall, request.DisplayName, intentHash); err != nil {
			return nil, err
		}
		if attempt.Phase == createAttemptPhaseRejected {
			if err := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: firewall %q rejection is now authoritatively absent and may be retried", ErrCreateAttemptPending, request.DisplayName)
		}
	}

	allowed, err := r.authorizeCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("%w: firewall %q is not yet visible", ErrCreateAttemptPending, request.DisplayName)
	}
	if err := r.validateFirewallCreateDispatchAuthority(
		ctx, cluster, location, billingAccountID, networkUUID, capturedSubnet, role, request,
	); err != nil {
		return nil, errors.Join(err,
			fmt.Errorf("%w: firewall %q create is issued without fresh VPC/policy authority", ErrCreateAttemptPending, request.DisplayName))
	}
	// Re-list after the durable issue CAS. Only a successful unique-name
	// absence authorizes POST; an exact owned object is adopted, while read
	// failure, duplicate identity, or policy/billing drift leaves the issue
	// receipt unresolved and prevents replay.
	preDispatchItems, preDispatchErr := r.API.ListFirewalls(ctx, location)
	if preDispatchErr != nil {
		return nil, errors.Join(preDispatchErr,
			fmt.Errorf("%w: firewall %q create is issued without fresh absence authority", ErrCreateAttemptPending, request.DisplayName))
	}
	preDispatchFirewall, preDispatchErr := uniqueFirewallByName(preDispatchItems, request.DisplayName)
	if preDispatchErr != nil {
		return nil, errors.Join(preDispatchErr,
			fmt.Errorf("%w: firewall %q create has ambiguous post-CAS identity", ErrCreateAttemptPending, request.DisplayName))
	}
	if preDispatchFirewall != nil {
		if validationErr := validate(preDispatchFirewall); validationErr != nil {
			return nil, errors.Join(validationErr,
				fmt.Errorf("%w: firewall %q appeared after create authorization with foreign ownership", ErrCreateAttemptPending, request.DisplayName))
		}
		if materializeErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash, preDispatchFirewall.UUID); materializeErr != nil {
			return nil, errors.Join(materializeErr,
				fmt.Errorf("%w: firewall %q pre-dispatch adoption was not durably anchored", ErrCreateAttemptPending, request.DisplayName))
		}
		return preDispatchFirewall, nil
	}
	created, createErr := r.API.CreateFirewall(ctx, location, request)
	exactResponseUUID := created != nil && vmUUIDPattern.MatchString(created.UUID)
	if createErr != nil && !exactResponseUUID && bootstrapMutationFailureProvesNoDispatch(createErr) {
		if rejectionErr := r.recordPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash); rejectionErr != nil {
			return nil, errors.Join(createErr, rejectionErr,
				fmt.Errorf("%w: firewall %q rejection receipt was not persisted", ErrCreateAttemptPending, request.DisplayName))
		}
		items, readbackErr := r.API.ListFirewalls(ctx, location)
		if readbackErr != nil {
			return nil, errors.Join(createErr, readbackErr,
				fmt.Errorf("%w: firewall %q rejection lacks authoritative non-commit proof", ErrCreateAttemptPending, request.DisplayName))
		}
		readback, identityErr := uniqueFirewallByName(items, request.DisplayName)
		if identityErr != nil {
			return nil, errors.Join(createErr, identityErr,
				fmt.Errorf("%w: firewall %q rejection readback is ambiguous", ErrCreateAttemptPending, request.DisplayName))
		}
		if readback == nil {
			clearErr := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash)
			return nil, errors.Join(createErr, clearErr)
		}
		if !vmUUIDPattern.MatchString(readback.UUID) {
			return nil, errors.Join(createErr, fmt.Errorf("%w: firewall %q appeared after its create error with invalid UUID %q", ErrCreateAttemptPending, request.DisplayName, readback.UUID))
		}
		if validationErr := validate(readback); validationErr != nil {
			return nil, errors.Join(createErr, validationErr,
				fmt.Errorf("%w: firewall %q appeared after its create error with invalid ownership", ErrCreateAttemptPending, request.DisplayName))
		}
		if materializeErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash, readback.UUID); materializeErr != nil {
			return nil, errors.Join(createErr, materializeErr,
				fmt.Errorf("%w: firewall %q committed but its receipt was not anchored", ErrCreateAttemptPending, request.DisplayName))
		}
		return readback, nil
	}
	responseErr := validateCreatedFirewallResponse(created, request.DisplayName, request.Description, request.BillingAccountID)
	items, listErr := r.API.ListFirewalls(ctx, location)
	if listErr != nil {
		return nil, errors.Join(createErr, responseErr, listErr,
			fmt.Errorf("%w: firewall %q readback failed after POST", ErrCreateAttemptPending, request.DisplayName))
	}
	readback, readbackErr := uniqueFirewallByName(items, request.DisplayName)
	if readbackErr != nil {
		return nil, readbackErr
	}
	if readback == nil {
		return nil, errors.Join(createErr, responseErr,
			fmt.Errorf("%w: created firewall %q is not yet visible", ErrCreateAttemptPending, request.DisplayName))
	}
	if err := validate(readback); err != nil {
		return nil, errors.Join(createErr, responseErr, err)
	}
	// The POST response UUID is provisional. Only the unique deterministic-name
	// readback with exact billing and policy can become mutation authority.
	if anchorErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewall, request.DisplayName, intentHash, readback.UUID); anchorErr != nil {
		return nil, errors.Join(createErr, responseErr, anchorErr,
			fmt.Errorf("%w: firewall %q canonical UUID receipt was not persisted", ErrCreateAttemptPending, request.DisplayName))
	}
	if createErr != nil {
		return readback, errors.Join(createErr,
			fmt.Errorf("%w: firewall %q POST returned an error after canonical materialization", ErrCreateAttemptPending, request.DisplayName))
	}
	return readback, nil
}

// validateFirewallCreateDispatchAuthority recomputes the complete desired
// policy from a fresh exact VPC read after the durable issue CAS. This matters
// even when the firewall name is absent: a moved/re-addressed VPC would make a
// previously rendered private-prefix policy unsafe to create.
func (r *Reconciler) validateFirewallCreateDispatchAuthority(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	location string,
	billingAccountID int64,
	networkUUID string,
	capturedSubnet string,
	role string,
	request inspace.CreateFirewallRequest,
) error {
	if cluster == nil || location == "" || billingAccountID <= 0 ||
		!vmUUIDPattern.MatchString(networkUUID) || capturedSubnet == "" {
		return errors.New("bootstrap: firewall create authority has invalid captured cluster/VPC identity")
	}
	if cluster.Spec.Location != location || cluster.Spec.BillingAccountID != billingAccountID ||
		!strings.EqualFold(cluster.Spec.Network.UUID, networkUUID) {
		return errors.New("bootstrap: cluster billing/location/VPC identity changed after firewall create issue CAS")
	}
	if request.BillingAccountID != billingAccountID || request.BillingAccountID <= 0 {
		return errors.New("bootstrap: firewall request lacks exact positive billing-account authority")
	}
	network, err := r.API.GetNetwork(ctx, location, networkUUID)
	if err != nil {
		return fmt.Errorf("bootstrap: fresh configured VPC read before firewall create: %w", err)
	}
	if network == nil || !strings.EqualFold(network.UUID, networkUUID) || network.Subnet != capturedSubnet {
		return errors.New("bootstrap: configured VPC UUID/subnet changed before firewall create")
	}
	if err := validatePrivateSubnet(network.Subnet); err != nil {
		return err
	}
	if err := validateNetworkCIDRs(network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR); err != nil {
		return err
	}
	if err := validateVirtualIPv4(network.Subnet, cluster.Spec.Endpoint.VirtualIPv4); err != nil {
		return err
	}

	owner := ownerKey(cluster)
	names := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	var expectedName, expectedDescription string
	var expectedRules []inspace.FirewallRule
	switch role {
	case "node":
		expectedName = names.NodeFirewall
		expectedDescription = "Managed RKE2 node firewall for " + owner
		expectedRules = managedFirewallRules(network.Subnet, cluster.Spec.Network.PodCIDR, "", nil)
	case "bastion":
		expectedName = names.BastionFirewall
		expectedDescription = "Managed RKE2 bastion firewall for " + owner
		expectedRules = managedBastionFirewallRules(r.ManagementCIDR, network.Subnet, !cluster.Spec.BootstrapCache.DirectDownload)
	default:
		return fmt.Errorf("bootstrap: unsupported managed firewall role %q", role)
	}
	if request.DisplayName != expectedName || request.Description != expectedDescription {
		return errors.New("bootstrap: firewall deterministic identity changed before dispatch")
	}
	if !sameFirewallPolicy(request.Rules, expectedRules) {
		return errors.New("bootstrap: desired firewall policy no longer matches the fresh VPC prefix")
	}
	return nil
}

func bootstrapMutationFailureProvesNoDispatch(err error) bool {
	// Only the shared client's typed local mutation guard proves that no request
	// reached the network. Every HTTP response, including an ordinary 4xx, is a
	// post-dispatch outcome: the provider may have committed the mutation before
	// returning it, and an immediate old/empty read can still be eventual
	// consistency. Such outcomes must therefore keep their issued receipt.
	return errors.Is(err, inspace.ErrMutationBlocked)
}

// validateCreatedFirewallResponse treats a firewall POST response as only a
// provisional resource handle. InSpace may omit identity fields and return an
// empty rules array even though the authoritative list readback is complete.
// Any identity evidence it does return must agree with the request; policy and
// assignment authority always comes from the subsequent ListFirewalls call.
func validateCreatedFirewallResponse(firewall *inspace.Firewall, expectedName, expectedDescription string, billingAccountID int64) error {
	if firewall == nil {
		return errors.New("returned an empty response")
	}
	if !vmUUIDPattern.MatchString(firewall.UUID) {
		return errors.New("has an invalid UUID")
	}
	if firewall.Name != "" && firewall.Name != expectedName {
		return fmt.Errorf("name %q does not match %q", firewall.Name, expectedName)
	}
	if firewall.DisplayName != "" && firewall.DisplayName != expectedName {
		return fmt.Errorf("display name %q does not match %q", firewall.DisplayName, expectedName)
	}
	if firewall.Description != "" && firewall.Description != expectedDescription {
		return errors.New("has an unexpected description")
	}
	if firewall.BillingAccountID != 0 && firewall.BillingAccountID != billingAccountID {
		return errors.New("belongs to another billing account")
	}
	return nil
}

func validateManagedNodeFirewall(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner, expectedName string) error {
	if firewall == nil {
		return nil
	}
	expectedDescription := "Managed RKE2 node firewall for " + owner
	if firewall.EffectiveName() != expectedName || firewall.BillingAccountID != cluster.Spec.BillingAccountID {
		return errors.New("bootstrap: node firewall lacks the expected deterministic name or billing-account identity")
	}
	// InSpace accepts a description on create but currently omits it from both
	// create and list responses. Treat a returned mismatch as drift, but never
	// require this unreadable field as deletion authority.
	if firewall.Description != "" && firewall.Description != expectedDescription {
		return errors.New("bootstrap: node firewall has an unexpected description")
	}
	if err := validateFirewallPolicy(firewall, network.Subnet, cluster.Spec.Network.PodCIDR, "", nil); err != nil {
		return fmt.Errorf("bootstrap: node firewall policy: %w", err)
	}
	return nil
}

func validateManagedBastionFirewall(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, privateSubnet, owner, expectedName, managementCIDR string) error {
	if err := validateManagedBastionFirewallIdentity(firewall, cluster, owner, expectedName); err != nil {
		return err
	}
	if firewall == nil {
		return nil
	}
	if err := validateBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, !cluster.Spec.BootstrapCache.DirectDownload); err != nil {
		return fmt.Errorf("bootstrap: bastion firewall policy: %w", err)
	}
	return nil
}

func validateManagedBastionFirewallForDestroy(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, privateSubnet, owner, expectedName, managementCIDR string) error {
	if err := validateManagedBastionFirewallIdentity(firewall, cluster, owner, expectedName); err != nil {
		return err
	}
	if firewall == nil {
		return nil
	}
	cacheEnabled := !cluster.Spec.BootstrapCache.DirectDownload
	currentErr := validateBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, cacheEnabled)
	if currentErr == nil {
		return nil
	}
	legacyErr := validateLegacyBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, cacheEnabled)
	if legacyErr == nil {
		return nil
	}
	return fmt.Errorf("bootstrap: bastion firewall policy is neither current nor exact legacy policy: %w", errors.Join(currentErr, legacyErr))
}

func validateManagedBastionFirewallIdentity(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, owner, expectedName string) error {
	if firewall == nil {
		return nil
	}
	expectedDescription := "Managed RKE2 bastion firewall for " + owner
	if firewall.EffectiveName() != expectedName || firewall.BillingAccountID != cluster.Spec.BillingAccountID {
		return errors.New("bootstrap: bastion firewall lacks the expected deterministic name or billing-account identity")
	}
	if firewall.Description != "" && firewall.Description != expectedDescription {
		return errors.New("bootstrap: bastion firewall has an unexpected description")
	}
	return nil
}

type floatingIPUpdateIntent struct {
	Location         string `json:"location"`
	Address          string `json:"address"`
	DesiredName      string `json:"desiredName"`
	BillingAccountID int64  `json:"billingAccountID"`
	VMUUID           string `json:"vmUUID"`
}

func (r *Reconciler) ensureOwnedAutoFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM, item *inspace.FloatingIP) (*inspace.FloatingIP, bool, error) {
	if vm == nil {
		return nil, false, errors.New("bootstrap: cannot discover an auto floating IP without its owned VM")
	}
	if item == nil {
		return nil, false, nil
	}
	attemptKey, err := floatingIPUpdateAttemptKey(cluster, name)
	if err != nil {
		return nil, false, err
	}
	resourceName := item.Address + "/" + name
	intentHash, err := createIntentHash(createAttemptKindFloatingIPUpdate, resourceName, floatingIPUpdateIntent{
		Location: cluster.Spec.Location, Address: item.Address, DesiredName: name,
		BillingAccountID: cluster.Spec.BillingAccountID, VMUUID: vm.UUID,
	})
	if err != nil {
		return nil, false, err
	}
	attempt, exists := r.createAttempt(cluster, attemptKey)
	if exists {
		if err := validateCreateAttempt(attempt, createAttemptKindFloatingIPUpdate, resourceName, intentHash); err != nil {
			return nil, false, err
		}
	}
	if item.Name == name {
		if err := validateOwnedFloatingIP(item, cluster, name, vm); err != nil {
			return nil, false, err
		}
		if item.AssignedTo != vm.UUID {
			return nil, false, fmt.Errorf("bootstrap: floating IP %q is not assigned to owned VM %q", name, vm.Name)
		}
		switch {
		case !exists || attempt.Phase == createAttemptPhaseIntent:
			if err := r.recordAdoptedCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash, vm.UUID); err != nil {
				return nil, false, err
			}
		case attempt.Phase == createAttemptPhaseIssued || attempt.Phase == createAttemptPhaseRejected:
			if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash, vm.UUID); err != nil {
				return nil, false, err
			}
		case !strings.EqualFold(attempt.ResourceUUID, vm.UUID):
			return nil, false, fmt.Errorf("bootstrap: durable floating-IP update receipt %q names VM %s, expected %s", attemptKey, attempt.ResourceUUID, vm.UUID)
		}
		return item, true, nil
	}
	if err := validateAutoAssignedFloatingIP(item, cluster, vm); err != nil {
		return nil, false, err
	}
	if exists && attempt.Phase == createAttemptPhaseRejected {
		if err := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if exists && attempt.Phase != createAttemptPhaseIntent {
		if attempt.Phase != createAttemptPhaseIssued {
			return nil, false, fmt.Errorf("bootstrap: floating IP %q reverted after its durable update receipt reached phase %q", name, attempt.Phase)
		}
		readback, committed, readErr := r.readFloatingIPUpdateState(ctx, cluster, name, vm, item.Address)
		if readErr != nil {
			return nil, false, errors.Join(readErr,
				fmt.Errorf("%w: floating-IP update %q cannot replay its issued PATCH", ErrCreateAttemptPending, attemptKey))
		}
		if !committed {
			return nil, false, fmt.Errorf("%w: floating-IP update %q remains issued with the original state visible", ErrCreateAttemptPending, attemptKey)
		}
		if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash, vm.UUID); err != nil {
			return nil, false, errors.Join(err,
				fmt.Errorf("%w: floating-IP update %q committed but its receipt was not anchored", ErrCreateAttemptPending, attemptKey))
		}
		return readback, true, nil
	}
	allowed, err := r.authorizeCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash)
	if err != nil {
		return nil, false, err
	}
	if !allowed {
		return nil, false, fmt.Errorf("%w: floating-IP update %q cannot replay its issued PATCH", ErrCreateAttemptPending, attemptKey)
	}
	// Re-prove both sides of the relationship after the issue CAS. The caller's
	// VM and floating-IP snapshots are lookup hints only; a stale address/name,
	// billing account, assignment, VM identity, or VPC membership must retain the
	// issued receipt and prevent PATCH.
	freshVM, authorityErr := r.readExactOwnedVMMutationAuthority(ctx, cluster, vm.UUID, vm.Name)
	if authorityErr != nil {
		return nil, false, errors.Join(authorityErr,
			fmt.Errorf("%w: floating-IP update %q lacks fresh VM authority", ErrCreateAttemptPending, attemptKey))
	}
	freshItem, alreadyCommitted, authorityErr := r.readFloatingIPUpdateState(ctx, cluster, name, freshVM, item.Address)
	if authorityErr != nil {
		return nil, false, errors.Join(authorityErr,
			fmt.Errorf("%w: floating-IP update %q lacks fresh address/assignment authority", ErrCreateAttemptPending, attemptKey))
	}
	if alreadyCommitted {
		if materializeErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash, freshVM.UUID); materializeErr != nil {
			return nil, false, errors.Join(materializeErr,
				fmt.Errorf("%w: floating-IP update %q pre-dispatch adoption was not anchored", ErrCreateAttemptPending, attemptKey))
		}
		return freshItem, true, nil
	}
	updated, updateErr := r.API.UpdateFloatingIP(ctx, cluster.Spec.Location, freshItem.Address, inspace.UpdateFloatingIPRequest{
		Name: name, BillingAccountID: cluster.Spec.BillingAccountID,
	})
	var responseErr error
	if updateErr == nil {
		if err := validateOwnedFloatingIP(updated, cluster, name, freshVM); err != nil {
			responseErr = fmt.Errorf("bootstrap: update floating IP %q response: %w", name, err)
		}
	}
	if updateErr != nil && bootstrapMutationFailureProvesNoDispatch(updateErr) {
		if rejectionErr := r.recordPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash); rejectionErr != nil {
			return nil, false, errors.Join(updateErr, responseErr, rejectionErr,
				fmt.Errorf("%w: floating-IP update %q rejection receipt was not persisted", ErrCreateAttemptPending, attemptKey))
		}
	}
	readback, committed, readErr := r.readFloatingIPUpdateState(ctx, cluster, name, freshVM, freshItem.Address)
	if readErr == nil && committed {
		if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash, freshVM.UUID); err != nil {
			return nil, false, errors.Join(updateErr, responseErr, err,
				fmt.Errorf("%w: floating-IP update %q committed but its receipt was not anchored", ErrCreateAttemptPending, attemptKey))
		}
		if responseErr != nil {
			return nil, false, responseErr
		}
		return readback, true, nil
	}
	if updateErr != nil && bootstrapMutationFailureProvesNoDispatch(updateErr) && readErr == nil && !committed {
		clearErr := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFloatingIPUpdate, resourceName, intentHash)
		return nil, false, errors.Join(updateErr, responseErr, clearErr)
	}
	if updateErr == nil {
		updateErr = errors.New("floating-IP PATCH returned success without authoritative commit evidence")
	}
	return nil, false, errors.Join(updateErr, responseErr, readErr,
		fmt.Errorf("%w: floating-IP update %q outcome is unresolved", ErrCreateAttemptPending, attemptKey))
}

// readFloatingIPUpdateState exact-reads the one address/name/VM ownership
// tuple after PATCH. It reports committed only for the desired name and
// reports false only when the exact original unnamed auto-assignment remains;
// every missing, duplicate, foreign, or partially changed row is ambiguity.
func (r *Reconciler) readFloatingIPUpdateState(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM, address string) (*inspace.FloatingIP, bool, error) {
	items, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: list floating IPs after update of %q: %w", name, err)
	}
	var found *inspace.FloatingIP
	for i := range items {
		item := &items[i]
		if item.IsDeleted || (item.Address != address && item.Name != name && item.AssignedTo != vm.UUID) {
			continue
		}
		if found != nil {
			return nil, false, fmt.Errorf("bootstrap: multiple floating IP rows overlap update identity %q/%s/VM-%s", name, address, vm.UUID)
		}
		found = item
	}
	if found == nil {
		return nil, false, fmt.Errorf("bootstrap: floating IP %s disappeared after update of %q", address, name)
	}
	if found.Address != address || found.AssignedTo != vm.UUID {
		return nil, false, fmt.Errorf("bootstrap: floating IP %q update changed its exact address or VM assignment", name)
	}
	switch found.Name {
	case name:
		if err := validateOwnedFloatingIP(found, cluster, name, vm); err != nil {
			return nil, false, err
		}
		return found, true, nil
	case "":
		if err := validateAutoAssignedFloatingIP(found, cluster, vm); err != nil {
			return nil, false, err
		}
		return found, false, nil
	default:
		return nil, false, fmt.Errorf("bootstrap: floating IP %s changed to foreign name %q while updating %q", address, found.Name, name)
	}
}

func (r *Reconciler) ensureVMProtection(ctx context.Context, cluster *v1alpha1.InSpaceCluster, attemptKey string, firewall *inspace.Firewall, vm *inspace.VM) (bool, error) {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
		return false, errors.New("bootstrap: cannot ensure firewall protection without an exact VM UUID")
	}
	if err := r.ensureExactFirewallAssignment(ctx, cluster, attemptKey, firewall, vm.UUID); err != nil {
		return false, err
	}
	return true, nil
}

type firewallAssignmentIntent struct {
	Location     string `json:"location"`
	FirewallUUID string `json:"firewallUUID"`
	VMUUID       string `json:"vmUUID"`
}

// ensureExactFirewallAssignment serializes one per-slot assignment POST behind
// a durable issued receipt. Once issued, reconciliation is read-only until an
// authoritative firewall list proves the exact firewall/VM/type tuple. This
// prevents a committed-but-500 response from producing duplicate rows after a
// process restart.
func (r *Reconciler) ensureExactFirewallAssignment(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	attemptKey string,
	firewall *inspace.Firewall,
	vmUUID string,
) error {
	if cluster == nil || firewall == nil || !vmUUIDPattern.MatchString(firewall.UUID) || !vmUUIDPattern.MatchString(vmUUID) {
		return errors.New("bootstrap: exact firewall assignment requires a cluster and valid firewall/VM UUIDs")
	}
	resourceName := firewall.UUID + "/" + vmUUID
	intentHash, err := createIntentHash(createAttemptKindFirewallAssignment, resourceName, firewallAssignmentIntent{
		Location: cluster.Spec.Location, FirewallUUID: firewall.UUID, VMUUID: vmUUID,
	})
	if err != nil {
		return err
	}
	attempt, exists := r.createAttempt(cluster, attemptKey)
	if exists {
		if err := validateCreateAttempt(attempt, createAttemptKindFirewallAssignment, resourceName, intentHash); err != nil {
			return err
		}
	}
	if firewallHasVM(firewall, vmUUID) {
		switch {
		case !exists || attempt.Phase == createAttemptPhaseIntent:
			return r.recordAdoptedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID)
		case attempt.Phase == createAttemptPhaseIssued || attempt.Phase == createAttemptPhaseRejected:
			return r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID)
		case !strings.EqualFold(attempt.ResourceUUID, vmUUID):
			return fmt.Errorf("bootstrap: durable firewall-assignment receipt %q names VM %s, expected %s", attemptKey, attempt.ResourceUUID, vmUUID)
		default:
			return nil
		}
	}
	if exists && attempt.Phase == createAttemptPhaseRejected {
		if err := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash); err != nil {
			return err
		}
		return fmt.Errorf("%w: firewall assignment %q rejection is now authoritatively absent and may be retried", ErrCreateAttemptPending, attemptKey)
	}
	if exists && attempt.Phase != createAttemptPhaseIntent {
		if readbackErr := r.waitForExactFirewallAssignment(ctx, cluster.Spec.Location, firewall, vmUUID); readbackErr != nil {
			return errors.Join(
				fmt.Errorf("%w: firewall assignment %q cannot replay its issued POST", ErrCreateAttemptPending, attemptKey),
				readbackErr,
			)
		}
		if attempt.Phase == createAttemptPhaseIssued {
			if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID); err != nil {
				return errors.Join(err, fmt.Errorf("%w: firewall assignment %q read back but its receipt was not anchored", ErrCreateAttemptPending, attemptKey))
			}
		}
		return nil
	}
	release := r.acquireFirewallAssignmentGate(cluster.Spec.Location, firewall.UUID)
	defer release()
	// The caller's firewall snapshot can predate another slot that completed
	// while this goroutine waited. Re-read inside the per-firewall gate before
	// minting the durable one-shot assignment issue.
	readCtx, readCancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout))
	present, readErr := r.readExactFirewallAssignment(readCtx, cluster.Spec.Location, firewall, vmUUID)
	readCancel()
	if readErr != nil {
		return fmt.Errorf("bootstrap: fresh in-gate firewall assignment read for %s: %w", resourceName, readErr)
	}
	if present {
		return r.recordAdoptedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID)
	}

	allowed, err := r.authorizeCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: firewall assignment %q cannot replay its issued POST", ErrCreateAttemptPending, attemptKey)
	}
	// The snapshots above predate the durable issue transition. Re-read the
	// exact firewall policy/relation and the VM's canonical Get/List/VPC tuple
	// after CAS before allowing a relationship POST.
	present, authorityErr := r.readExactFirewallAssignment(ctx, cluster.Spec.Location, firewall, vmUUID)
	if authorityErr != nil {
		return errors.Join(authorityErr,
			fmt.Errorf("%w: firewall assignment %q lacks fresh firewall authority", ErrCreateAttemptPending, attemptKey))
	}
	if present {
		if materializeErr := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID); materializeErr != nil {
			return errors.Join(materializeErr,
				fmt.Errorf("%w: firewall assignment %q pre-dispatch adoption was not anchored", ErrCreateAttemptPending, attemptKey))
		}
		return nil
	}
	if _, authorityErr = r.readExactOwnedVMMutationAuthority(ctx, cluster, vmUUID, ""); authorityErr != nil {
		return errors.Join(authorityErr,
			fmt.Errorf("%w: firewall assignment %q lacks fresh VM authority", ErrCreateAttemptPending, attemptKey))
	}
	requestCtx, cancel := context.WithTimeout(ctx, configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout))
	assignErr := r.API.AssignFirewallToVM(requestCtx, cluster.Spec.Location, firewall.UUID, vmUUID)
	cancel()
	readbackErr := r.waitForExactFirewallAssignment(ctx, cluster.Spec.Location, firewall, vmUUID)
	if readbackErr == nil {
		if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID); err != nil {
			return errors.Join(err, fmt.Errorf("%w: firewall assignment %q committed but its receipt was not anchored", ErrCreateAttemptPending, attemptKey))
		}
		return nil
	}
	if bootstrapMutationFailureProvesNoDispatch(assignErr) {
		if rejectionErr := r.recordPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash); rejectionErr != nil {
			return errors.Join(fmt.Errorf("bootstrap: assign firewall: %w", assignErr), readbackErr, rejectionErr,
				fmt.Errorf("%w: firewall assignment %q rejection receipt was not persisted", ErrCreateAttemptPending, attemptKey))
		}
		present, proofErr := r.readExactFirewallAssignment(ctx, cluster.Spec.Location, firewall, vmUUID)
		if proofErr != nil {
			return errors.Join(fmt.Errorf("bootstrap: assign firewall: %w", assignErr), readbackErr, proofErr,
				fmt.Errorf("%w: firewall assignment %q rejection lacks authoritative outcome proof", ErrCreateAttemptPending, attemptKey))
		}
		if present {
			if err := r.recordMaterializedCreate(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash, vmUUID); err != nil {
				return errors.Join(err, fmt.Errorf("%w: firewall assignment %q committed but its receipt was not anchored", ErrCreateAttemptPending, attemptKey))
			}
			return nil
		}
		clearErr := r.clearPreDispatchCreateRejection(ctx, cluster, attemptKey, createAttemptKindFirewallAssignment, resourceName, intentHash)
		return errors.Join(fmt.Errorf("bootstrap: assign firewall: %w", assignErr), readbackErr, clearErr)
	}
	if assignErr == nil {
		assignErr = errors.New("assignment call returned success without authoritative commit evidence")
	}
	return errors.Join(
		fmt.Errorf("bootstrap: assign firewall: %w", assignErr),
		readbackErr,
		fmt.Errorf("%w: firewall assignment %q POST outcome is unresolved", ErrCreateAttemptPending, attemptKey),
	)
}

func (r *Reconciler) acquireFirewallAssignmentGate(location, firewallUUID string) func() {
	key := strings.ToLower(location) + "/" + strings.ToLower(firewallUUID)
	gateValue, _ := r.firewallAssignmentGates.LoadOrStore(key, &sync.Mutex{})
	gate := gateValue.(*sync.Mutex)
	gate.Lock()
	return gate.Unlock
}

func (r *Reconciler) waitForExactFirewallAssignment(ctx context.Context, location string, expectedFirewall *inspace.Firewall, vmUUID string) error {
	if expectedFirewall == nil || !vmUUIDPattern.MatchString(expectedFirewall.UUID) || !vmUUIDPattern.MatchString(vmUUID) {
		return errors.New("bootstrap: exact firewall assignment readback requires valid firewall and VM UUIDs")
	}
	auditCtx, cancel := context.WithTimeout(ctx, configuredDuration(r.protectionAuditTimeout, defaultProtectionAuditTimeout))
	defer cancel()
	requestTimeout := configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout)
	delay := configuredDuration(r.protectionReadbackMinInterval, defaultProtectionReadbackMinInterval)
	maxDelay := configuredDuration(r.protectionReadbackMaxInterval, defaultProtectionReadbackMaxInterval)
	if maxDelay < delay {
		maxDelay = delay
	}
	var lastErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(auditCtx, requestTimeout)
		items, err := r.API.ListFirewalls(requestCtx, location)
		requestCancel()
		if err != nil {
			lastErr = fmt.Errorf("bootstrap: list firewalls for assignment readback: %w", err)
		} else {
			present, stateErr := exactFirewallAssignmentState(items, expectedFirewall, vmUUID)
			if errors.Is(stateErr, errManagedFirewallNotVisible) {
				lastErr = stateErr
			} else if stateErr != nil {
				return stateErr
			} else if present {
				return nil
			} else {
				lastErr = fmt.Errorf("bootstrap: VM %s firewall assignment is not yet visible", vmUUID)
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-auditCtx.Done():
			timer.Stop()
			return errors.Join(lastErr, auditCtx.Err())
		case <-timer.C:
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (r *Reconciler) readExactFirewallAssignment(ctx context.Context, location string, expectedFirewall *inspace.Firewall, vmUUID string) (bool, error) {
	items, err := r.API.ListFirewalls(ctx, location)
	if err != nil {
		return false, fmt.Errorf("bootstrap: list firewalls for post-error assignment proof: %w", err)
	}
	return exactFirewallAssignmentState(items, expectedFirewall, vmUUID)
}

func exactFirewallAssignmentState(items []inspace.Firewall, expectedFirewall *inspace.Firewall, vmUUID string) (bool, error) {
	if expectedFirewall == nil || !vmUUIDPattern.MatchString(expectedFirewall.UUID) || !vmUUIDPattern.MatchString(vmUUID) {
		return false, errors.New("bootstrap: exact firewall assignment state requires valid firewall and VM UUIDs")
	}
	expectedRows := 0
	assignmentRows := 0
	for i := range items {
		firewall := &items[i]
		if firewall.UUID == expectedFirewall.UUID {
			expectedRows++
			if firewall.EffectiveName() != expectedFirewall.EffectiveName() || firewall.BillingAccountID != expectedFirewall.BillingAccountID {
				return false, errors.New("bootstrap: managed firewall identity drifted during assignment readback")
			}
			if !sameFirewallPolicy(firewall.Rules, expectedFirewall.Rules) {
				return false, errors.New("bootstrap: managed firewall policy drifted during assignment readback")
			}
		}
		for _, resource := range firewall.ResourcesAssigned {
			if resource.ResourceUUID != vmUUID {
				continue
			}
			assignmentRows++
			if resource.ResourceType != "vm" || firewall.UUID != expectedFirewall.UUID {
				return false, fmt.Errorf("bootstrap: VM %s appeared on the wrong firewall or resource type during assignment readback", vmUUID)
			}
		}
	}
	if expectedRows == 0 {
		return false, errManagedFirewallNotVisible
	}
	if expectedRows != 1 {
		return false, fmt.Errorf("bootstrap: expected one managed firewall row during assignment readback, got %d", expectedRows)
	}
	// ResourcesAssigned is a set-valued relation. Exact duplicate VM/firewall
	// rows are equivalent to one attachment; the loop above still rejects every
	// wrong firewall and non-VM resource type.
	return assignmentRows > 0, nil
}

func sameFirewallPolicy(actual, expected []inspace.FirewallRule) bool {
	if len(actual) != len(expected) {
		return false
	}
	normalize := func(rules []inspace.FirewallRule) []string {
		result := make([]string, 0, len(rules))
		for _, rule := range rules {
			endpoints := append([]string(nil), rule.EndpointSpec...)
			sort.Strings(endpoints)
			portStart, portEnd := "", ""
			if rule.PortStart != nil {
				portStart = fmt.Sprint(*rule.PortStart)
			}
			if rule.PortEnd != nil {
				portEnd = fmt.Sprint(*rule.PortEnd)
			}
			result = append(result, strings.Join([]string{
				rule.Protocol, rule.Direction, portStart, portEnd, rule.EndpointSpecType, strings.Join(endpoints, ","),
			}, "\x00"))
		}
		sort.Strings(result)
		return result
	}
	actualNormalized := normalize(actual)
	expectedNormalized := normalize(expected)
	for i := range actualNormalized {
		if actualNormalized[i] != expectedNormalized[i] {
			return false
		}
	}
	return true
}

func (r *Reconciler) bootstrapCacheTLS(cluster *v1alpha1.InSpaceCluster, owner string) (cacheTLSMaterial, error) {
	if cluster.Spec.BootstrapCache.DirectDownload {
		return cacheTLSMaterial{}, nil
	}
	if len(r.BootstrapCacheKey) != 32 {
		return cacheTLSMaterial{}, errors.New("bootstrap: cached mode requires a persisted 32-byte INSPACE_BOOTSTRAP_CACHE_KEY")
	}
	if _, err := renderCacheImageManifest(cluster.Spec.RKE2.Version, r.ModuleVersion, cluster.Spec.RKE2.Disable); err != nil {
		return cacheTLSMaterial{}, err
	}
	return deriveCacheTLS(r.BootstrapCacheKey, owner, bootstrapCacheHostname(cluster.Metadata.Name), r.BootstrapCacheNotBefore)
}

func nodeCacheConfig(cluster *v1alpha1.InSpaceCluster, address string, material cacheTLSMaterial) (*NodeCacheConfig, error) {
	if cluster.Spec.BootstrapCache.DirectDownload {
		return nil, nil
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is4() || !parsed.IsPrivate() || parsed.String() != address {
		return nil, errors.New("bootstrap: cached mode requires the bastion's canonical RFC1918 address")
	}
	if material.CACertificate == "" {
		return nil, errors.New("bootstrap: cached mode requires a derived CA certificate")
	}
	return &NodeCacheConfig{
		Address: address, Hostname: bootstrapCacheHostname(cluster.Metadata.Name), CABundle: material.CACertificate,
	}, nil
}

func (r *Reconciler) desiredControlPlaneVMRequest(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, slot int, joinAddress, token string, cache *NodeCacheConfig) (inspace.CreateVMRequest, error) {
	tlsNames := append([]string{cluster.Spec.Endpoint.VirtualIPv4}, cluster.Spec.RKE2.TLSSubjectAltNames...)
	cloudInit, err := RenderCloudInitJSON(CloudInitInput{
		NodeName: controlPlaneName(cluster.Metadata.Name, slot), PrivateSubnet: network.Subnet, VirtualIPv4: cluster.Spec.Endpoint.VirtualIPv4,
		RKE2Version: cluster.Spec.RKE2.Version, RKE2Token: token, Initialize: slot == 0, ServerAddress: joinAddress,
		PodCIDR: cluster.Spec.Network.PodCIDR, ServiceCIDR: cluster.Spec.Network.ServiceCIDR,
		PrivateLoadBalancerPoolStart: cluster.Spec.Network.PrivateLoadBalancerPool.Start,
		PrivateLoadBalancerPoolStop:  cluster.Spec.Network.PrivateLoadBalancerPool.Stop,
		TLSSubjectAltNames:           tlsNames, Disable: cluster.Spec.RKE2.Disable,
		BootstrapCache: cache, SkipOSUpgrade: cluster.Spec.RKE2.SkipOSUpgrade,
	})
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	reserve := true
	machine := cluster.Spec.ControlPlane.Machine
	request := inspace.CreateVMRequest{
		Name:   controlPlaneName(cluster.Metadata.Name, slot),
		OSName: machine.Image.OSName, OSVersion: machine.Image.OSVersion, DiskGiB: int(machine.RootDiskGiB),
		VCPU: int(machine.VCPU), MemoryMiB: int(machine.MemoryMiB), DesignatedPoolUUID: machine.HostPoolUUID,
		BillingAccountID: cluster.Spec.BillingAccountID, NetworkUUID: cluster.Spec.Network.UUID,
		Username: r.SSHUsername, PublicKey: r.SSHPublicKey,
		CloudInit: cloudInit, ReservePublicIP: &reserve,
	}
	hashInput := request
	hashInput.Description = ""
	data, err := json.Marshal(hashInput)
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	sum := sha256.Sum256(data)
	request.Description = fmt.Sprintf("inspace-rke2-cp/v8 owner=%s slot=%d spec=%s", owner, slot, hex.EncodeToString(sum[:]))
	return request, nil
}

func (r *Reconciler) desiredBastionVMRequest(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, material cacheTLSMaterial) (inspace.CreateVMRequest, error) {
	name := currentBastionName(cluster.Metadata.Name)
	cloudInit := ""
	var err error
	if cluster.Spec.BootstrapCache.DirectDownload {
		cloudInit, err = renderBastionCloudInitJSON(name, cluster.Spec.RKE2.SkipOSUpgrade)
	} else {
		cloudInit, err = RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
			NodeName: name, PrivateSubnet: network.Subnet, CacheHostname: bootstrapCacheHostname(cluster.Metadata.Name),
			RKE2Version: cluster.Spec.RKE2.Version, ModuleVersion: r.ModuleVersion,
			Disable:       cluster.Spec.RKE2.Disable,
			CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
			SkipOSUpgrade: cluster.Spec.RKE2.SkipOSUpgrade,
		})
	}
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	reserve := true
	request := inspace.CreateVMRequest{
		Name: name, OSName: "ubuntu", OSVersion: "24.04", DiskGiB: BastionRootDiskGiB,
		VCPU: BastionVCPU, MemoryMiB: BastionMemoryMiB, DesignatedPoolUUID: cluster.Spec.ControlPlane.Machine.HostPoolUUID,
		BillingAccountID: cluster.Spec.BillingAccountID, NetworkUUID: cluster.Spec.Network.UUID,
		Username: r.SSHUsername, PublicKey: r.SSHPublicKey, CloudInit: cloudInit, ReservePublicIP: &reserve,
	}
	hashInput := request
	hashInput.Description = ""
	data, err := json.Marshal(hashInput)
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	sum := sha256.Sum256(data)
	request.Description = fmt.Sprintf("inspace-rke2-bastion/v6 owner=%s spec=%s", owner, hex.EncodeToString(sum[:]))
	return request, nil
}

func (r *Reconciler) validateExistingVMs(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, privatePool privateIPv4Range, owner string, byName map[string]*inspace.VM, token string, material cacheTLSMaterial) error {
	var cache *NodeCacheConfig
	if bastion := byName[currentBastionName(cluster.Metadata.Name)]; bastion != nil {
		if bastion.PrivateIPv4 != "" {
			if err := validateVMPrivateIPv4(bastion, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
				return err
			}
		}
		desired, err := r.desiredBastionVMRequest(cluster, network, owner, material)
		if err != nil {
			return err
		}
		if err := validateOwnedVM(bastion, desired, network); err != nil {
			return err
		}
		if bastion.Hostname != "" && bastion.Hostname != desired.Name {
			return fmt.Errorf("bootstrap: refusing to adopt bastion VM %q whose authoritative hostname is %q", bastion.Name, bastion.Hostname)
		}
		if bastion.PrivateIPv4 != "" {
			cache, err = nodeCacheConfig(cluster, bastion.PrivateIPv4, material)
			if err != nil {
				return err
			}
		}
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := byName[controlPlaneName(cluster.Metadata.Name, slot)]
		if vm == nil {
			continue
		}
		if vm.PrivateIPv4 != "" {
			if err := validateVMPrivateIPv4(vm, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
				return err
			}
		}
		if !cluster.Spec.BootstrapCache.DirectDownload && cache == nil {
			return errors.New("bootstrap: refusing to validate cached control-plane VMs before the bastion private address is authoritative")
		}
		desired, err := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, cluster.Spec.Endpoint.VirtualIPv4, token, cache)
		if err != nil {
			return err
		}
		if err := validateOwnedVM(vm, desired, network); err != nil {
			return err
		}
		if vm.Hostname != "" && vm.Hostname != desired.Name {
			return fmt.Errorf("bootstrap: refusing to adopt control-plane VM %q whose authoritative hostname is %q", vm.Name, vm.Hostname)
		}
	}
	return nil
}

func validateOwnedFloatingIPs(items []inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, names bootstrapResourceNames, ownedVMs map[string]*inspace.VM) (map[string]*inspace.FloatingIP, error) {
	return validateOwnedFloatingIPsForControlPlanes(items, cluster, names, ownedVMs, currentBastionName(cluster.Metadata.Name), currentControlPlaneNames(cluster.Metadata.Name))
}

func (r *Reconciler) rejectResidualFloatingIPNames(ctx context.Context, location string, names ...string) error {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	items, err := r.API.ListFloatingIPs(ctx, location, nil)
	if err != nil {
		return fmt.Errorf("bootstrap: audit floating IP names immediately before VM create: %w", err)
	}
	for i := range items {
		if items[i].IsDeleted || !wanted[items[i].Name] {
			continue
		}
		return fmt.Errorf("bootstrap: refusing VM create while active residual floating IP %q already exists", items[i].Name)
	}
	return nil
}

func validateOwnedFloatingIPsForControlPlanes(items []inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, names bootstrapResourceNames, ownedVMs map[string]*inspace.VM, bastionVMName string, controlPlaneNames [ControlPlaneReplicas]string) (map[string]*inspace.FloatingIP, error) {
	expected := map[string]*inspace.VM{names.BastionFloatingIP: ownedVMs[bastionVMName]}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expected[names.ControlPlaneFIP[slot]] = ownedVMs[controlPlaneNames[slot]]
	}
	expectedByVMUUID := make(map[string]string, len(expected))
	for name, vm := range expected {
		if vm != nil && vm.UUID != "" {
			expectedByVMUUID[vm.UUID] = name
		}
	}
	result := make(map[string]*inspace.FloatingIP, len(expected))
	for i := range items {
		item := &items[i]
		if item.IsDeleted {
			continue
		}
		vm, isOwnedName := expected[item.Name]
		expectedNameByAssignment, assignedToOwnedVM := expectedByVMUUID[item.AssignedTo]
		if !isOwnedName && !assignedToOwnedVM {
			continue
		}
		expectedName := item.Name
		if !isOwnedName {
			if item.Name != "" {
				return nil, fmt.Errorf("bootstrap: floating IP %s with foreign name %q is assigned to owned VM %s", item.Address, item.Name, item.AssignedTo)
			}
			expectedName = expectedNameByAssignment
			vm = expected[expectedName]
		} else if assignedToOwnedVM && expectedNameByAssignment != expectedName {
			return nil, fmt.Errorf("bootstrap: floating IP %q is assigned to the wrong owned VM", expectedName)
		}
		if result[expectedName] != nil {
			return nil, fmt.Errorf("bootstrap: multiple floating IPs resolve to owned slot %q", expectedName)
		}
		if item.Name == "" {
			if err := validateAutoAssignedFloatingIP(item, cluster, vm); err != nil {
				return nil, err
			}
		} else if err := validateOwnedFloatingIP(item, cluster, expectedName, vm); err != nil {
			return nil, err
		}
		result[expectedName] = item
	}
	return result, nil
}

// validateOwnedFloatingIP is the single ownership and safety contract used
// for create responses, authoritative adoption lists, assignment readbacks,
// and destroy preflight/readback.
func validateOwnedFloatingIP(item *inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, expectedName string, vm *inspace.VM) error {
	if item == nil {
		return fmt.Errorf("bootstrap: floating IP %q returned an empty response", expectedName)
	}
	if item.Name != expectedName || item.BillingAccountID != cluster.Spec.BillingAccountID {
		return fmt.Errorf("bootstrap: floating IP %q lacks the expected name or billing-account ownership", expectedName)
	}
	if !item.Enabled || item.IsDeleted || item.IsVirtual || item.Type != "public" {
		return fmt.Errorf("bootstrap: floating IP %q must be enabled, active, non-virtual, and type public", expectedName)
	}
	address, err := netip.ParseAddr(item.Address)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != item.Address {
		return fmt.Errorf("bootstrap: floating IP %q has an invalid public IPv4", expectedName)
	}
	if item.AssignedTo == "" {
		if item.AssignedToResourceType != "" || item.AssignedToPrivateIP != "" {
			return fmt.Errorf("bootstrap: floating IP %q has residual assignment metadata", expectedName)
		}
		return nil
	}
	if vm == nil || vm.UUID == "" || item.AssignedTo != vm.UUID || item.AssignedToResourceType != "virtual_machine" {
		return fmt.Errorf("bootstrap: floating IP %q has an unexpected assignment", expectedName)
	}
	if vm.PrivateIPv4 != "" && item.AssignedToPrivateIP != vm.PrivateIPv4 {
		return fmt.Errorf("bootstrap: floating IP %q assignment private IPv4 does not match VM %q", expectedName, vm.Name)
	}
	return nil
}

func validateAutoAssignedFloatingIP(item *inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, vm *inspace.VM) error {
	if item == nil || vm == nil || vm.UUID == "" {
		return errors.New("bootstrap: auto floating IP lacks an owned VM")
	}
	if item.Name != "" {
		return fmt.Errorf("bootstrap: auto floating IP %s has unexpected name %q", item.Address, item.Name)
	}
	copy := *item
	copy.Name = "auto"
	if err := validateOwnedFloatingIP(&copy, cluster, "auto", vm); err != nil {
		return fmt.Errorf("bootstrap: auto floating IP for VM %q: %w", vm.Name, err)
	}
	if item.AssignedTo == "" {
		return fmt.Errorf("bootstrap: auto floating IP %s is not assigned to VM %q", item.Address, vm.Name)
	}
	return nil
}

func validateOwnedVM(vm *inspace.VM, desired inspace.CreateVMRequest, network *inspace.Network) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with an invalid UUID", desired.Name)
	}
	if vm.Name != desired.Name {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q under unexpected name %q", desired.Name, vm.Name)
	}
	if vm.Description != desired.Description {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with missing or mismatched ownership/spec hash", vm.Name)
	}
	if vm.VCPU != desired.VCPU || vm.MemoryMiB != desired.MemoryMiB || vm.OSName != desired.OSName || vm.OSVersion != desired.OSVersion || vm.DesignatedPoolUUID != desired.DesignatedPoolUUID {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with immutable compute/image drift", vm.Name)
	}
	if desired.BillingAccountID <= 0 || vm.BillingAccountID != desired.BillingAccountID {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q without exact positive billing-account ownership", vm.Name)
	}
	if vm.NetworkUUID != "" && !strings.EqualFold(vm.NetworkUUID, desired.NetworkUUID) {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q from another private network", vm.Name)
	}
	if network == nil || !strings.EqualFold(network.UUID, desired.NetworkUUID) {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q without the exact configured private network", vm.Name)
	}
	memberships := 0
	for _, uuid := range network.VMUUIDs {
		if strings.EqualFold(uuid, vm.UUID) {
			memberships++
		}
	}
	if memberships != 1 {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with %d configured-network memberships, want one", vm.Name, memberships)
	}
	rootDiskMatches := false
	for _, disk := range vm.Storage {
		if disk.Primary && disk.SizeGiB == desired.DiskGiB {
			rootDiskMatches = true
			break
		}
	}
	if !rootDiskMatches {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with root disk drift", vm.Name)
	}
	return nil
}

// validateUniqueVMInventoryIdentity makes an exact detail response usable as
// mutation authority only when the unfiltered location inventory contains one
// matching UUID/name row and no deterministic-name collision. List responses
// may omit billing or network fields, but any value they do return must agree
// with the authoritative detail and configured ownership tuple.
func validateUniqueVMInventoryIdentity(items []inspace.VM, detail *inspace.VM, billingAccountID int64, networkUUID string) error {
	if detail == nil || !vmUUIDPattern.MatchString(detail.UUID) || detail.Name == "" {
		return errors.New("exact VM detail has an invalid UUID/name identity")
	}
	matches := 0
	for i := range items {
		candidate := &items[i]
		if strings.EqualFold(candidate.UUID, detail.UUID) {
			matches++
			if candidate.Name != detail.Name ||
				(candidate.BillingAccountID != 0 && candidate.BillingAccountID != billingAccountID) ||
				(candidate.NetworkUUID != "" && !strings.EqualFold(candidate.NetworkUUID, networkUUID)) {
				return fmt.Errorf("VM %s location inventory changed exact ownership", detail.UUID)
			}
			continue
		}
		if candidate.Name == detail.Name {
			return fmt.Errorf("VM name %q is also held by UUID %q", detail.Name, candidate.UUID)
		}
	}
	if matches != 1 {
		return fmt.Errorf("location inventory contains %d exact rows for VM %s, want one", matches, detail.UUID)
	}
	return nil
}

// readExactOwnedVMMutationAuthority re-proves a bootstrap VM immediately after
// a durable mutation issue CAS. A UUID saved before that transition is only a
// lookup key: exact detail, unfiltered inventory uniqueness, positive billing,
// controller ownership metadata, and one configured-VPC membership must all
// agree before the VM may authorize a related cloud mutation.
func (r *Reconciler) readExactOwnedVMMutationAuthority(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	vmUUID, expectedName string,
) (*inspace.VM, error) {
	if cluster == nil || !vmUUIDPattern.MatchString(vmUUID) || cluster.Spec.BillingAccountID <= 0 ||
		!vmUUIDPattern.MatchString(cluster.Spec.Network.UUID) {
		return nil, errors.New("bootstrap: exact VM mutation authority requires a valid cluster, billing account, VPC, and VM UUID")
	}
	detail, err := r.API.GetVM(ctx, cluster.Spec.Location, vmUUID)
	if err != nil {
		if inspace.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", errOwnedVMMutationTargetAbsent, vmUUID)
		}
		return nil, fmt.Errorf("bootstrap: exact VM mutation-authority read for %s: %w", vmUUID, err)
	}
	if detail == nil || !strings.EqualFold(detail.UUID, vmUUID) || detail.Name == "" ||
		(expectedName != "" && detail.Name != expectedName) {
		return nil, fmt.Errorf("bootstrap: exact VM mutation-authority identity for %s changed", vmUUID)
	}
	if detail.BillingAccountID != cluster.Spec.BillingAccountID {
		return nil, fmt.Errorf("bootstrap: VM %q lacks exact billing-account mutation authority", detail.Name)
	}
	if detail.NetworkUUID != "" && !strings.EqualFold(detail.NetworkUUID, cluster.Spec.Network.UUID) {
		return nil, fmt.Errorf("bootstrap: VM %q reports another private network", detail.Name)
	}

	listed, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: unfiltered VM inventory for mutation target %s: %w", vmUUID, err)
	}
	if err := validateUniqueVMInventoryIdentity(listed, detail, cluster.Spec.BillingAccountID, cluster.Spec.Network.UUID); err != nil {
		return nil, fmt.Errorf("bootstrap: VM %q lacks unique location mutation authority: %w", detail.Name, err)
	}

	network, err := r.API.GetNetwork(ctx, cluster.Spec.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: configured VPC read for mutation target %s: %w", vmUUID, err)
	}
	if network == nil || !strings.EqualFold(network.UUID, cluster.Spec.Network.UUID) {
		return nil, fmt.Errorf("bootstrap: configured VPC identity changed for mutation target %s", vmUUID)
	}
	memberships := 0
	for _, candidateUUID := range network.VMUUIDs {
		if strings.EqualFold(candidateUUID, vmUUID) {
			memberships++
		}
	}
	if memberships != 1 {
		return nil, fmt.Errorf("bootstrap: VM %q has %d configured-VPC memberships, want one", detail.Name, memberships)
	}

	owned, controlPlaneNames, bastionName, err := uniqueDestroyVMs([]inspace.VM{*detail}, ownerKey(cluster), cluster.Metadata.Name)
	if err != nil {
		return nil, err
	}
	if owned[detail.Name] == nil || !strings.EqualFold(owned[detail.Name].UUID, vmUUID) {
		return nil, fmt.Errorf("bootstrap: VM %q is outside an owned bootstrap slot", detail.Name)
	}
	if err := validateDestroyVMOwnership(owned, ownerKey(cluster), cluster.Metadata.Name, bastionName, controlPlaneNames); err != nil {
		return nil, err
	}
	return detail, nil
}

func (r *Reconciler) findFloatingIPByAddress(ctx context.Context, location, address string) (*inspace.FloatingIP, error) {
	items, err := r.API.ListFloatingIPs(ctx, location, nil)
	if err != nil {
		return nil, err
	}
	var found *inspace.FloatingIP
	for i := range items {
		if items[i].IsDeleted || items[i].Address != address {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: duplicate active floating IP address %s", address)
		}
		found = &items[i]
	}
	return found, nil
}

func validateFloatingIPCleanupReadback(item *inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, expectedName, expectedAddress string) error {
	if item == nil {
		return fmt.Errorf("bootstrap: floating IP %q cleanup returned an empty response", expectedName)
	}
	if item.Name != "" && item.Name != expectedName {
		return fmt.Errorf("bootstrap: floating IP %q cleanup returned foreign name %q", expectedName, item.Name)
	}
	copy := *item
	copy.Name = expectedName
	if err := validateOwnedFloatingIP(&copy, cluster, expectedName, nil); err != nil {
		return err
	}
	if item.Address != expectedAddress {
		return fmt.Errorf("bootstrap: floating IP %q cleanup changed address from %s to %s", expectedName, expectedAddress, item.Address)
	}
	if item.AssignedTo != "" {
		return fmt.Errorf("bootstrap: floating IP %q remained assigned after unassign", expectedName)
	}
	return nil
}

func managedFirewallRules(subnet, podCIDR, managementCIDR string, managementTCPPorts []int) []inspace.FirewallRule {
	result := make([]inspace.FirewallRule, 0, 6+len(managementTCPPorts))
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		result = append(result, inspace.FirewallRule{Protocol: protocol, Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{subnet, podCIDR}})
		result = append(result, inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"})
	}
	for _, port := range sortedUniquePorts(managementTCPPorts) {
		value := int32(port)
		result = append(result, inspace.FirewallRule{
			Protocol: "tcp", Direction: "inbound", PortStart: &value, PortEnd: &value,
			EndpointSpecType: "ip_prefixes", EndpointSpec: []string{managementCIDR},
		})
	}
	return result
}

func managedBastionFirewallRules(managementCIDR, privateSubnet string, cacheEnabled bool) []inspace.FirewallRule {
	managementCIDR = effectiveBastionManagementCIDR(managementCIDR)
	managementEndpointType, managementEndpoints := bastionManagementFirewallEndpoint(managementCIDR)
	port := int32(22)
	result := []inspace.FirewallRule{{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port,
		EndpointSpecType: managementEndpointType, EndpointSpec: append([]string(nil), managementEndpoints...),
	}, {
		Protocol: "icmp", Direction: "inbound",
		EndpointSpecType: managementEndpointType, EndpointSpec: append([]string(nil), managementEndpoints...),
	}}
	if cacheEnabled {
		cachePort := int32(BootstrapCachePort)
		result = append(result, inspace.FirewallRule{
			Protocol: "tcp", Direction: "inbound", PortStart: &cachePort, PortEnd: &cachePort,
			EndpointSpecType: "ip_prefixes", EndpointSpec: []string{privateSubnet},
		})
	}
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		result = append(result, inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"})
	}
	return result
}

func validateBastionFirewallPolicy(firewall *inspace.Firewall, managementCIDR, privateSubnet string, cacheEnabled bool) error {
	return validateBastionFirewallPolicyVersion(firewall, managementCIDR, privateSubnet, cacheEnabled, true)
}

func validateLegacyBastionFirewallPolicy(firewall *inspace.Firewall, managementCIDR, privateSubnet string, cacheEnabled bool) error {
	return validateBastionFirewallPolicyVersion(firewall, managementCIDR, privateSubnet, cacheEnabled, false)
}

func validateBastionFirewallPolicyVersion(firewall *inspace.Firewall, managementCIDR, privateSubnet string, cacheEnabled, requireICMP bool) error {
	if firewall == nil {
		return errors.New("bootstrap: bastion firewall is required")
	}
	managementCIDR = effectiveBastionManagementCIDR(managementCIDR)
	if err := validateManagementAccess(managementCIDR, []int{22}); err != nil {
		return err
	}
	expectedRules := 4
	if requireICMP {
		expectedRules++
	}
	if cacheEnabled {
		expectedRules++
	}
	if len(firewall.Rules) != expectedRules {
		return errors.New("bootstrap: bastion firewall has an unexpected rule count")
	}
	sshIngress := false
	icmpIngress := false
	cacheIngress := false
	outbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	for _, rule := range firewall.Rules {
		switch rule.Direction {
		case "inbound":
			switch rule.Protocol {
			case "tcp":
				if rule.PortStart == nil || rule.PortEnd == nil {
					return errors.New("bootstrap: bastion inbound TCP policy requires one explicit port")
				}
				switch {
				case *rule.PortStart == 22 && *rule.PortEnd == 22 && bastionManagementFirewallEndpointMatches(rule, managementCIDR) && !sshIngress:
					sshIngress = true
				case cacheEnabled && *rule.PortStart == BootstrapCachePort && *rule.PortEnd == BootstrapCachePort &&
					rule.EndpointSpecType == "ip_prefixes" && len(rule.EndpointSpec) == 1 && rule.EndpointSpec[0] == privateSubnet && !cacheIngress:
					cacheIngress = true
				default:
					return errors.New("bootstrap: bastion inbound TCP policy must contain only management TCP/22 and optional VPC TCP/8443")
				}
			case "icmp":
				if !requireICMP || rule.PortStart != nil || rule.PortEnd != nil || !bastionManagementFirewallEndpointMatches(rule, managementCIDR) || icmpIngress {
					return errors.New("bootstrap: bastion inbound ICMP policy must be one portless management rule")
				}
				icmpIngress = true
			default:
				return errors.New("bootstrap: bastion inbound policy supports only TCP and ICMP")
			}
		case "outbound":
			if _, ok := outbound[rule.Protocol]; !ok || outbound[rule.Protocol] || rule.PortStart != nil || rule.PortEnd != nil || rule.EndpointSpecType != "any" {
				return errors.New("bootstrap: bastion outbound policy must be one unrestricted TCP/UDP/ICMP rule")
			}
			outbound[rule.Protocol] = true
		default:
			return errors.New("bootstrap: bastion firewall has an invalid direction")
		}
	}
	if !sshIngress || icmpIngress != requireICMP || cacheIngress != cacheEnabled || !outbound["tcp"] || !outbound["udp"] || !outbound["icmp"] {
		return errors.New("bootstrap: bastion firewall policy is incomplete")
	}
	return nil
}

func effectiveBastionManagementCIDR(cidr string) string {
	if cidr == "" {
		return DefaultManagementCIDR
	}
	return cidr
}

func bastionManagementFirewallEndpoint(cidr string) (string, []string) {
	if effectiveBastionManagementCIDR(cidr) == DefaultManagementCIDR {
		return "any", nil
	}
	return "ip_prefixes", []string{cidr}
}

func bastionManagementFirewallEndpointMatches(rule inspace.FirewallRule, cidr string) bool {
	endpointType, endpoints := bastionManagementFirewallEndpoint(cidr)
	if rule.EndpointSpecType != endpointType || len(rule.EndpointSpec) != len(endpoints) {
		return false
	}
	for index := range endpoints {
		if rule.EndpointSpec[index] != endpoints[index] {
			return false
		}
	}
	return true
}

func validateOwnedFirewallAssignments(firewall *inspace.Firewall, allowed map[string]bool) error {
	if firewall == nil {
		return nil
	}
	for _, resource := range firewall.ResourcesAssigned {
		if resource.ResourceType != "vm" || !allowed[resource.ResourceUUID] {
			return errors.New("firewall contains a foreign or non-VM assignment")
		}
	}
	return nil
}

// validateReverseFirewallAssignments audits every firewall, not only the two
// deterministic managed objects. An owned VM must never be protected by a
// second or foreign firewall because that policy could silently widen access.
func validateReverseFirewallAssignments(firewalls []inspace.Firewall, nodeFirewall, bastionFirewall *inspace.Firewall, vms map[string]*inspace.VM, bastionVMName string, controlPlaneNames [ControlPlaneReplicas]string) error {
	type expectedAttachment struct {
		firewallUUID string
		role         string
	}
	expectedByVM := make(map[string]expectedAttachment, ControlPlaneReplicas+1)
	if bastion := vms[bastionVMName]; bastion != nil && bastion.UUID != "" {
		expectedUUID := ""
		if bastionFirewall != nil {
			expectedUUID = bastionFirewall.UUID
		}
		expectedByVM[bastion.UUID] = expectedAttachment{firewallUUID: expectedUUID, role: "bastion"}
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := vms[controlPlaneNames[slot]]
		if vm == nil || vm.UUID == "" {
			continue
		}
		expectedUUID := ""
		if nodeFirewall != nil {
			expectedUUID = nodeFirewall.UUID
		}
		expectedByVM[vm.UUID] = expectedAttachment{firewallUUID: expectedUUID, role: "control-plane"}
	}
	seen := make(map[string]string, len(expectedByVM))
	for i := range firewalls {
		firewall := &firewalls[i]
		for _, resource := range firewall.ResourcesAssigned {
			expected, owned := expectedByVM[resource.ResourceUUID]
			if !owned {
				continue
			}
			if resource.ResourceType != "vm" || expected.firewallUUID == "" || firewall.UUID != expected.firewallUUID {
				return fmt.Errorf("bootstrap: owned %s VM %s is attached to foreign firewall %q", expected.role, resource.ResourceUUID, firewall.EffectiveName())
			}
			if previous, duplicate := seen[resource.ResourceUUID]; duplicate {
				if previous == firewall.UUID {
					continue
				}
				return fmt.Errorf("bootstrap: owned %s VM %s has firewall attachments on UUIDs %q and %q", expected.role, resource.ResourceUUID, previous, firewall.UUID)
			}
			seen[resource.ResourceUUID] = firewall.UUID
		}
	}
	return nil
}

func validateFirewallPolicy(firewall *inspace.Firewall, subnet, podCIDR, managementCIDR string, managementTCPPorts []int) error {
	if firewall == nil {
		return errors.New("bootstrap: firewall is required")
	}
	if err := validateManagementAccess(managementCIDR, managementTCPPorts); err != nil {
		return err
	}
	if len(firewall.Rules) != 6+len(managementTCPPorts) {
		return fmt.Errorf("bootstrap: firewall must contain exactly private ingress, unrestricted egress, and configured management rules; got %d rules", len(firewall.Rules))
	}
	network, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bootstrap: parse private subnet: %w", err)
	}
	podNetwork, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return fmt.Errorf("bootstrap: parse pod CIDR: %w", err)
	}
	inboundNetwork := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	inboundPod := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	outbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	allowedManagementPorts := make(map[int32]bool, len(managementTCPPorts))
	seenManagementPorts := make(map[int32]bool, len(managementTCPPorts))
	for _, port := range managementTCPPorts {
		allowedManagementPorts[int32(port)] = true
	}
	for _, rule := range firewall.Rules {
		if _, ok := inboundNetwork[rule.Protocol]; !ok {
			return fmt.Errorf("bootstrap: firewall has unsupported protocol %q", rule.Protocol)
		}
		switch rule.Direction {
		case "inbound":
			if rule.PortStart != nil || rule.PortEnd != nil {
				if rule.Protocol != "tcp" || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
					return errors.New("bootstrap: public management ingress must be a single TCP port")
				}
				if !allowedManagementPorts[*rule.PortStart] || managementCIDR == "" {
					return fmt.Errorf("bootstrap: firewall has unapproved public TCP port %d", *rule.PortStart)
				}
				if rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) != 1 || rule.EndpointSpec[0] != managementCIDR {
					return errors.New("bootstrap: management ingress must match the configured management CIDR exactly")
				}
				seenManagementPorts[*rule.PortStart] = true
				continue
			}
			if rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) == 0 {
				return errors.New("bootstrap: inbound firewall rules must be restricted to private IP prefixes")
			}
			coversNetwork := false
			coversPodNetwork := false
			for _, raw := range rule.EndpointSpec {
				prefix, parseErr := netip.ParsePrefix(raw)
				if parseErr != nil {
					address, addrErr := netip.ParseAddr(raw)
					if addrErr != nil || !address.IsPrivate() || (!network.Contains(address) && !podNetwork.Contains(address)) {
						return errors.New("bootstrap: inbound firewall endpoint escapes the private or pod network")
					}
					continue
				}
				withinPrivate := network.Contains(prefix.Addr()) && prefix.Bits() >= network.Bits()
				withinPod := podNetwork.Contains(prefix.Addr()) && prefix.Bits() >= podNetwork.Bits()
				if !prefix.Addr().IsPrivate() || (!withinPrivate && !withinPod) {
					return errors.New("bootstrap: inbound firewall prefix escapes the private or pod network")
				}
				if prefix.Masked() == network.Masked() && prefix.Bits() == network.Bits() {
					coversNetwork = true
				}
				if prefix.Masked() == podNetwork.Masked() && prefix.Bits() == podNetwork.Bits() {
					coversPodNetwork = true
				}
			}
			inboundNetwork[rule.Protocol] = inboundNetwork[rule.Protocol] || coversNetwork
			inboundPod[rule.Protocol] = inboundPod[rule.Protocol] || coversPodNetwork
		case "outbound":
			if rule.PortStart != nil || rule.PortEnd != nil {
				return errors.New("bootstrap: outbound firewall rules must cover all ports")
			}
			if rule.EndpointSpecType != "any" {
				return errors.New("bootstrap: outbound firewall must allow internet egress")
			}
			outbound[rule.Protocol] = true
		default:
			return fmt.Errorf("bootstrap: firewall has invalid direction %q", rule.Direction)
		}
	}
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		if !inboundNetwork[protocol] || !inboundPod[protocol] || !outbound[protocol] {
			return fmt.Errorf("bootstrap: firewall lacks safe inbound/private+pod and outbound/any %s rules", protocol)
		}
	}
	for port := range allowedManagementPorts {
		if !seenManagementPorts[port] {
			return fmt.Errorf("bootstrap: firewall lacks configured management TCP/%d ingress", port)
		}
	}
	return nil
}

// ValidateDefaultNodeFirewallPolicy exposes the exact bootstrap-owned worker
// firewall contract to runtime controllers that must fail closed on cloud-side
// rule drift. Default workers have private VPC/pod ingress and unrestricted
// egress only; public Service edges are independent firewalls.
func ValidateDefaultNodeFirewallPolicy(firewall *inspace.Firewall, subnet, podCIDR string) error {
	return validateFirewallPolicy(firewall, subnet, podCIDR, "", nil)
}

func validatePrivateSubnet(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
		return fmt.Errorf("bootstrap: network subnet %q must be a private IPv4 CIDR", value)
	}
	return nil
}

func validateVirtualIPv4(subnet, value string) error {
	prefix, prefixErr := netip.ParsePrefix(subnet)
	address, addressErr := netip.ParseAddr(value)
	if prefixErr != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 || addressErr != nil || !address.Is4() || !address.IsPrivate() || !prefix.Contains(address) {
		return fmt.Errorf("bootstrap: virtual IPv4 %q must be a usable private host inside VPC subnet %q", value, subnet)
	}
	masked := prefix.Masked()
	if address == masked.Addr() {
		return fmt.Errorf("bootstrap: virtual IPv4 %q is the VPC network address", value)
	}
	bytes := masked.Addr().As4()
	addressBytes := address.As4()
	networkValue := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	addressValue := uint32(addressBytes[0])<<24 | uint32(addressBytes[1])<<16 | uint32(addressBytes[2])<<8 | uint32(addressBytes[3])
	hostMask := ^uint32(0) >> prefix.Bits()
	if addressValue == networkValue|hostMask {
		return fmt.Errorf("bootstrap: virtual IPv4 %q is the VPC broadcast address", value)
	}
	return nil
}

func validatePrivateLoadBalancerPool(subnet, podCIDR, serviceCIDR, virtualIPv4, startValue, stopValue string) (privateIPv4Range, error) {
	start, startErr := netip.ParseAddr(startValue)
	stop, stopErr := netip.ParseAddr(stopValue)
	if startErr != nil || stopErr != nil || !start.Is4() || !stop.Is4() || !start.IsPrivate() || !stop.IsPrivate() ||
		start.String() != startValue || stop.String() != stopValue {
		return privateIPv4Range{}, errors.New("bootstrap: private load-balancer pool start/stop must be canonical RFC1918 IPv4 addresses")
	}
	if start.Compare(stop) > 0 {
		return privateIPv4Range{}, errors.New("bootstrap: private load-balancer pool start must be less than or equal to stop")
	}
	addressCount := uint64(bootstrapIPv4Value(stop)-bootstrapIPv4Value(start)) + 1
	if addressCount < v1alpha1.PrivateLoadBalancerPoolMinAddresses || addressCount > v1alpha1.PrivateLoadBalancerPoolMaxAddresses {
		return privateIPv4Range{}, fmt.Errorf("bootstrap: private load-balancer pool must contain between %d and %d addresses", v1alpha1.PrivateLoadBalancerPoolMinAddresses, v1alpha1.PrivateLoadBalancerPoolMaxAddresses)
	}
	if err := validateVirtualIPv4(subnet, startValue); err != nil {
		return privateIPv4Range{}, fmt.Errorf("bootstrap: private load-balancer pool start is not a usable VPC host: %w", err)
	}
	if err := validateVirtualIPv4(subnet, stopValue); err != nil {
		return privateIPv4Range{}, fmt.Errorf("bootstrap: private load-balancer pool stop is not a usable VPC host: %w", err)
	}
	virtualAddress, err := netip.ParseAddr(virtualIPv4)
	if err != nil {
		return privateIPv4Range{}, fmt.Errorf("bootstrap: parse control-plane virtual IPv4: %w", err)
	}
	pool := privateIPv4Range{Start: start, Stop: stop, AddressCount: addressCount}
	if privatePoolContains(pool, virtualAddress) {
		return privateIPv4Range{}, errors.New("bootstrap: private load-balancer pool contains the control-plane virtual IPv4")
	}
	for _, network := range []struct{ name, value string }{{"pod", podCIDR}, {"service", serviceCIDR}} {
		prefix, parseErr := netip.ParsePrefix(network.value)
		if parseErr != nil {
			return privateIPv4Range{}, fmt.Errorf("bootstrap: parse %s CIDR: %w", network.name, parseErr)
		}
		if privatePoolOverlapsPrefix(pool, prefix) {
			return privateIPv4Range{}, fmt.Errorf("bootstrap: private load-balancer pool overlaps the %s CIDR %s", network.name, network.value)
		}
	}
	return pool, nil
}

func privatePoolContains(pool privateIPv4Range, address netip.Addr) bool {
	return pool.Start.IsValid() && address.Is4() && pool.Start.Compare(address) <= 0 && address.Compare(pool.Stop) <= 0
}

func privatePoolOverlapsPrefix(pool privateIPv4Range, prefix netip.Prefix) bool {
	if !prefix.Addr().Is4() {
		return false
	}
	masked := prefix.Masked()
	prefixStart := bootstrapIPv4Value(masked.Addr())
	prefixStop := prefixStart | (^uint32(0) >> masked.Bits())
	return bootstrapIPv4Value(pool.Start) <= prefixStop && prefixStart <= bootstrapIPv4Value(pool.Stop)
}

func bootstrapIPv4Value(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// vmsOnConfiguredNetwork scopes RFC1918 collision checks to the actual VPC.
// VM.NetworkUUID and Network.VMUUIDs are independent API evidence; when both
// are present they must agree, while either one can identify membership when
// the other field is omitted by a list response.
func vmsOnConfiguredNetwork(vms []inspace.VM, network *inspace.Network) ([]inspace.VM, error) {
	if network == nil || network.UUID == "" {
		return nil, errors.New("bootstrap: configured network readback lacks a UUID")
	}
	hasMembershipReadback := network.VMUUIDs != nil
	members := make(map[string]bool, len(network.VMUUIDs))
	for _, uuid := range network.VMUUIDs {
		if uuid == "" || members[uuid] {
			return nil, errors.New("bootstrap: configured network contains an empty or duplicate VM UUID")
		}
		members[uuid] = true
	}
	result := make([]inspace.VM, 0, len(vms))
	seenVMs := make(map[string]bool, len(vms))
	for i := range vms {
		if vms[i].UUID != "" {
			if seenVMs[vms[i].UUID] {
				return nil, fmt.Errorf("bootstrap: duplicate VM UUID %s in location readback", vms[i].UUID)
			}
			seenVMs[vms[i].UUID] = true
		}
		listed := members[vms[i].UUID]
		hasNetworkField := vms[i].NetworkUUID != ""
		fieldMatches := vms[i].NetworkUUID == network.UUID
		if hasNetworkField && hasMembershipReadback && listed != fieldMatches {
			return nil, fmt.Errorf("bootstrap: VM %q network UUID and configured VPC membership disagree", vms[i].Name)
		}
		if fieldMatches || listed {
			result = append(result, vms[i])
		}
	}
	if hasMembershipReadback {
		for uuid := range members {
			if !seenVMs[uuid] {
				return nil, fmt.Errorf("bootstrap: configured VPC lists VM %s missing from the location VM readback", uuid)
			}
		}
	}
	return result, nil
}

func validateNoVMPoolCollision(vms []inspace.VM, pool privateIPv4Range) error {
	for i := range vms {
		address, err := netip.ParseAddr(vms[i].PrivateIPv4)
		if err == nil && privatePoolContains(pool, address) {
			return fmt.Errorf("bootstrap: VM %q already uses reserved private load-balancer address %s", vms[i].Name, address)
		}
	}
	return nil
}

func validateNoLoadBalancerPoolCollision(loadBalancers []inspace.LoadBalancer, networkUUID string, pool privateIPv4Range) error {
	for i := range loadBalancers {
		loadBalancer := &loadBalancers[i]
		if loadBalancer.IsDeleted || loadBalancer.NetworkUUID != networkUUID {
			continue
		}
		address, err := netip.ParseAddr(strings.TrimSpace(loadBalancer.PrivateAddress))
		if err == nil && privatePoolContains(pool, address) {
			return fmt.Errorf("bootstrap: active load balancer %q already uses reserved private load-balancer address %s in the configured VPC", loadBalancer.DisplayName, address)
		}
	}
	return nil
}

func validateNoLoadBalancerVirtualIPCollision(loadBalancers []inspace.LoadBalancer, networkUUID, virtualIPv4 string) error {
	virtualAddress, err := netip.ParseAddr(virtualIPv4)
	if err != nil {
		return fmt.Errorf("bootstrap: parse control-plane virtual IPv4: %w", err)
	}
	for i := range loadBalancers {
		loadBalancer := &loadBalancers[i]
		if loadBalancer.IsDeleted || loadBalancer.NetworkUUID != networkUUID || strings.TrimSpace(loadBalancer.PrivateAddress) == "" {
			continue
		}
		privateAddress, parseErr := netip.ParseAddr(strings.TrimSpace(loadBalancer.PrivateAddress))
		if parseErr == nil && privateAddress == virtualAddress {
			return fmt.Errorf("bootstrap: active load balancer %q already uses control-plane virtual IPv4 %s in the configured VPC", loadBalancer.DisplayName, virtualIPv4)
		}
	}
	return nil
}

// validateControlPlaneBootstrapTopology allows slot 0 to initialize only when
// no control-plane VM exists. Replacing a missing initializer in an otherwise
// established cluster needs a manual, state-aware recovery lifecycle.
func validateControlPlaneBootstrapTopology(vms map[string]*inspace.VM, clusterName string) error {
	if vms[controlPlaneName(clusterName, 0)] != nil {
		return nil
	}
	for slot := 1; slot < ControlPlaneReplicas; slot++ {
		if vms[controlPlaneName(clusterName, slot)] != nil {
			return errors.New("bootstrap: control-plane slot 0 is absent while another control-plane VM exists; refusing automatic initializer replacement")
		}
	}
	return nil
}

func validateNoVirtualIPCollision(vms []inspace.VM, virtualIPv4 string) error {
	for i := range vms {
		if vms[i].PrivateIPv4 == virtualIPv4 {
			return fmt.Errorf("bootstrap: VM %q already uses control-plane virtual IPv4 %s", vms[i].Name, virtualIPv4)
		}
	}
	return nil
}

func validateVMPrivateIPv4(vm *inspace.VM, subnet, virtualIPv4 string, privatePool privateIPv4Range) error {
	prefix, prefixErr := netip.ParsePrefix(subnet)
	address, addressErr := netip.ParseAddr(vm.PrivateIPv4)
	if prefixErr != nil || !prefix.Addr().Is4() || addressErr != nil || !address.Is4() || !address.IsPrivate() || !prefix.Contains(address) {
		return fmt.Errorf("bootstrap: VM %q private IPv4 %q is not inside VPC subnet %q", vm.Name, vm.PrivateIPv4, subnet)
	}
	if vm.PrivateIPv4 == virtualIPv4 {
		return fmt.Errorf("bootstrap: VM %q private IPv4 collides with control-plane virtual IPv4 %s", vm.Name, virtualIPv4)
	}
	if privatePool.Start.IsValid() && privatePool.Start.Compare(address) <= 0 && address.Compare(privatePool.Stop) <= 0 {
		return fmt.Errorf("bootstrap: VM %q private IPv4 %s collides with the reserved private load-balancer pool", vm.Name, vm.PrivateIPv4)
	}
	return nil
}

func (r *Reconciler) validateOperatorAccess() error {
	username := strings.TrimSpace(r.SSHUsername)
	publicKey := strings.TrimSpace(r.SSHPublicKey)
	if username != r.SSHUsername {
		return errors.New("bootstrap: SSH username is invalid")
	}
	if publicKey != r.SSHPublicKey {
		return errors.New("bootstrap: SSH public key must be one supported authorized_keys line")
	}
	if (username == "") != (publicKey == "") {
		return errors.New("bootstrap: SSH username and public key must be configured together")
	}
	if username != "" {
		if !sshUsernamePattern.MatchString(username) {
			return errors.New("bootstrap: SSH username is invalid")
		}
		if strings.ContainsAny(publicKey, "\r\n") || !(strings.HasPrefix(publicKey, "ssh-rsa ") || strings.HasPrefix(publicKey, "ssh-ed25519 ") || strings.HasPrefix(publicKey, "ecdsa-sha2-")) {
			return errors.New("bootstrap: SSH public key must be one supported authorized_keys line")
		}
	}
	return validateManagementAccess(r.ManagementCIDR, r.ManagementTCPPorts)
}

func (r *Reconciler) validateBastionAccess() error {
	if err := r.validateOperatorAccess(); err != nil {
		return err
	}
	if r.SSHUsername == "" || r.SSHPublicKey == "" {
		return errors.New("bootstrap: bastion requires an SSH username and public key")
	}
	return validateBastionFirewallAccess(r.ManagementCIDR, r.ManagementTCPPorts)
}

func validateBastionFirewallAccess(cidr string, ports []int) error {
	cidr = effectiveBastionManagementCIDR(cidr)
	if len(ports) != 1 || ports[0] != 22 {
		return errors.New("bootstrap: bastion requires exactly management TCP/22")
	}
	return validateManagementAccess(cidr, ports)
}

func validateManagementAccess(cidr string, ports []int) error {
	if cidr == "" {
		if len(ports) != 0 {
			return errors.New("bootstrap: management TCP ports require Any or a public IPv4 /32")
		}
		return nil
	}
	prefix, err := netip.ParsePrefix(cidr)
	validAny := cidr == DefaultManagementCIDR
	validHost := err == nil && prefix.Addr().Is4() && prefix.Bits() == 32 && !prefix.Addr().IsPrivate() && prefix.Addr().IsGlobalUnicast()
	if err != nil || prefix.Masked().String() != cidr || (!validAny && !validHost) {
		return errors.New("bootstrap: management CIDR must be Any (0.0.0.0/0) or one canonical public IPv4 /32")
	}
	if len(ports) == 0 {
		return errors.New("bootstrap: management CIDR requires at least one explicit TCP port")
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("bootstrap: invalid management TCP port %d", port)
		}
		if seen[port] {
			return fmt.Errorf("bootstrap: duplicate management TCP port %d", port)
		}
		seen[port] = true
	}
	return nil
}

func validateNetworkCIDRs(privateSubnet, podCIDR, serviceCIDR string) error {
	privatePrefix, privateErr := netip.ParsePrefix(privateSubnet)
	podPrefix, podErr := netip.ParsePrefix(podCIDR)
	servicePrefix, serviceErr := netip.ParsePrefix(serviceCIDR)
	if privateErr != nil || podErr != nil || serviceErr != nil {
		return errors.New("bootstrap: private, pod, and service CIDRs must be valid")
	}
	if prefixesOverlap(privatePrefix, podPrefix) {
		return fmt.Errorf("bootstrap: InSpace subnet %s overlaps pod CIDR %s", privateSubnet, podCIDR)
	}
	if prefixesOverlap(privatePrefix, servicePrefix) {
		return fmt.Errorf("bootstrap: InSpace subnet %s overlaps service CIDR %s", privateSubnet, serviceCIDR)
	}
	return nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func ownerKey(cluster *v1alpha1.InSpaceCluster) string {
	raw := cluster.Metadata.Namespace + "/" + cluster.Metadata.Name
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func controlPlaneName(clusterName string, slot int) string {
	return fmt.Sprintf("%s-cp%d", clusterName, slot)
}
func legacyControlPlaneName(owner string, slot int) string {
	return fmt.Sprintf("rke2-%s-cp-%d", owner, slot)
}

func currentControlPlaneNames(clusterName string) [ControlPlaneReplicas]string {
	var names [ControlPlaneReplicas]string
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		names[slot] = controlPlaneName(clusterName, slot)
	}
	return names
}

func legacyControlPlaneNames(owner string) [ControlPlaneReplicas]string {
	var names [ControlPlaneReplicas]string
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		names[slot] = legacyControlPlaneName(owner, slot)
	}
	return names
}
func currentBastionName(clusterName string) string { return clusterName + "-bastion" }
func legacyBastionName(owner string) string        { return "rke2-" + owner + "-bastion" }

func currentBootstrapResourceNames(clusterName, owner string) bootstrapResourceNames {
	names := bootstrapResourceNames{
		NodeFirewall:      fmt.Sprintf("%s-nodes-%s", clusterName, owner),
		BastionFirewall:   fmt.Sprintf("%s-bastion-%s", clusterName, owner),
		BastionFloatingIP: clusterName + "-bastion-ip",
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		names.ControlPlaneFIP[slot] = fmt.Sprintf("%s-cp%d-ip", clusterName, slot)
	}
	return names
}

func legacyBootstrapResourceNames(owner string) bootstrapResourceNames {
	names := bootstrapResourceNames{
		NodeFirewall:      "rke2-" + owner + "-nodes",
		BastionFirewall:   "rke2-" + owner + "-bastion",
		BastionFloatingIP: "rke2-" + owner + "-bastion-ip",
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		names.ControlPlaneFIP[slot] = fmt.Sprintf("rke2-%s-cp-%d-ip", owner, slot)
	}
	return names
}

func bootstrapResourceTopologyPresent(floatingIPs []inspace.FloatingIP, firewalls []inspace.Firewall, names bootstrapResourceNames) bool {
	floatingIPNames := map[string]bool{names.BastionFloatingIP: true}
	for _, name := range names.ControlPlaneFIP {
		floatingIPNames[name] = true
	}
	for i := range floatingIPs {
		if !floatingIPs[i].IsDeleted && floatingIPNames[floatingIPs[i].Name] {
			return true
		}
	}
	for i := range firewalls {
		name := firewalls[i].EffectiveName()
		if name == names.NodeFirewall || name == names.BastionFirewall {
			return true
		}
	}
	return false
}

func validateCurrentBootstrapResourceTopology(floatingIPs []inspace.FloatingIP, firewalls []inspace.Firewall, legacy bootstrapResourceNames) error {
	if bootstrapResourceTopologyPresent(floatingIPs, firewalls, legacy) {
		return errors.New("bootstrap: legacy owner-prefixed firewall or floating-IP names require teardown before cluster-prefixed reconciliation")
	}
	return nil
}

func selectDestroyBootstrapResourceNames(floatingIPs []inspace.FloatingIP, firewalls []inspace.Firewall, current, legacy bootstrapResourceNames) (bootstrapResourceNames, error) {
	hasCurrent := bootstrapResourceTopologyPresent(floatingIPs, firewalls, current)
	hasLegacy := bootstrapResourceTopologyPresent(floatingIPs, firewalls, legacy)
	if hasCurrent && hasLegacy {
		return bootstrapResourceNames{}, errors.New("bootstrap: refusing mixed cluster-prefixed and legacy owner-prefixed firewall/floating-IP topology")
	}
	if hasLegacy {
		return legacy, nil
	}
	return current, nil
}

func uniqueOwnedVMs(vms []inspace.VM, owner, clusterName string) (map[string]*inspace.VM, error) {
	ownedPrefix := "rke2-" + owner + "-"
	expected := map[string]bool{currentBastionName(clusterName): true}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expected[controlPlaneName(clusterName, slot)] = true
	}
	result := make(map[string]*inspace.VM, len(vms))
	for i := range vms {
		if !strings.HasPrefix(vms[i].Name, ownedPrefix) && !expected[vms[i].Name] {
			continue
		}
		if _, exists := result[vms[i].Name]; exists {
			return nil, fmt.Errorf("bootstrap: duplicate VM name %q", vms[i].Name)
		}
		if !expected[vms[i].Name] {
			return nil, fmt.Errorf("bootstrap: unexpected VM %q uses the cluster ownership prefix", vms[i].Name)
		}
		result[vms[i].Name] = &vms[i]
	}
	return result, nil
}

// uniqueDestroyVMs recognizes the current display-name topology, the RC4
// owner-derived bastion with current control-plane names, and the fully legacy
// owner-derived topology. A mixed graph is never deletion authority: it can
// only be resolved by an explicit operator migration.
func uniqueDestroyVMs(vms []inspace.VM, owner, clusterName string) (map[string]*inspace.VM, [ControlPlaneReplicas]string, string, error) {
	ownedPrefix := "rke2-" + owner + "-"
	currentNames := currentControlPlaneNames(clusterName)
	legacyNames := legacyControlPlaneNames(owner)
	currentBastion := currentBastionName(clusterName)
	legacyBastion := legacyBastionName(owner)
	expectedCurrent := map[string]bool{currentBastion: true}
	expectedLegacy := map[string]bool{legacyBastion: true}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expectedCurrent[currentNames[slot]] = true
		expectedLegacy[legacyNames[slot]] = true
	}

	result := make(map[string]*inspace.VM, len(vms))
	hasCurrent := false
	hasLegacy := false
	hasCurrentBastion := false
	hasLegacyBastion := false
	for i := range vms {
		name := vms[i].Name
		isCurrentBastion := name == currentBastion
		isLegacyBastion := name == legacyBastion
		isCurrent := expectedCurrent[name] && !isCurrentBastion
		isLegacy := expectedLegacy[name] && !isLegacyBastion
		if !strings.HasPrefix(name, ownedPrefix) && !isCurrentBastion && !isCurrent {
			continue
		}
		if _, exists := result[name]; exists {
			return nil, currentNames, currentBastion, fmt.Errorf("bootstrap: duplicate VM name %q", name)
		}
		if !isCurrentBastion && !isLegacyBastion && !isCurrent && !isLegacy {
			return nil, currentNames, currentBastion, fmt.Errorf("bootstrap: unexpected VM %q uses the cluster ownership prefix", name)
		}
		result[name] = &vms[i]
		hasCurrent = hasCurrent || isCurrent
		hasLegacy = hasLegacy || isLegacy
		hasCurrentBastion = hasCurrentBastion || isCurrentBastion
		hasLegacyBastion = hasLegacyBastion || isLegacyBastion
	}
	if hasCurrentBastion && hasLegacyBastion {
		return nil, currentNames, currentBastion, errors.New("bootstrap: refusing both current and legacy bastion VMs")
	}
	if hasCurrent && hasLegacy {
		return nil, currentNames, currentBastion, errors.New("bootstrap: refusing mixed current and legacy control-plane VM topology")
	}
	if hasLegacy {
		if hasCurrentBastion {
			return nil, legacyNames, currentBastion, errors.New("bootstrap: refusing current bastion with legacy control-plane VM topology")
		}
		return result, legacyNames, legacyBastion, nil
	}
	if hasLegacyBastion {
		return result, currentNames, legacyBastion, nil
	}
	return result, currentNames, currentBastion, nil
}

func uniqueFirewallByName(items []inspace.Firewall, name string) (*inspace.Firewall, error) {
	var found *inspace.Firewall
	for i := range items {
		if items[i].EffectiveName() != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: duplicate firewall name %q", name)
		}
		found = &items[i]
	}
	return found, nil
}

func firewallHasVM(firewall *inspace.Firewall, uuid string) bool {
	for _, resource := range firewall.ResourcesAssigned {
		if resource.ResourceType == "vm" && resource.ResourceUUID == uuid {
			return true
		}
	}
	return false
}

func controlPlaneUUIDSet(vms map[string]*inspace.VM, names [ControlPlaneReplicas]string) map[string]bool {
	result := make(map[string]bool, ControlPlaneReplicas)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if vm := vms[names[slot]]; vm != nil {
			result[vm.UUID] = true
		}
	}
	return result
}

func bastionUUIDSet(vms map[string]*inspace.VM, bastionVMName string) map[string]bool {
	result := make(map[string]bool, 1)
	if vm := vms[bastionVMName]; vm != nil {
		result[vm.UUID] = true
	}
	return result
}

func isVMReady(vm *inspace.VM) bool {
	return vm != nil && strings.EqualFold(vm.Status, "running") && vm.PrivateIPv4 != ""
}

func progressResult(vms []*inspace.VM, message string) Result {
	ids := make([]string, 0, len(vms))
	for _, vm := range vms {
		if vm != nil {
			ids = append(ids, vm.UUID)
		}
	}
	sort.Strings(ids)
	return Result{RequeueAfter: 20 * time.Second, MaxParallelControlPlaneCreates: 1, ControlPlaneVMs: ids, Message: message}
}
