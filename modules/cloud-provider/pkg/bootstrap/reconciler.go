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
	ControlPlaneReplicas = 3
	BastionVCPU          = 1
	BastionMemoryMiB     = 2048
	BastionRootDiskGiB   = 30

	ownedVMDeletionTransitionTTL             = 5 * time.Minute
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
	ErrRetryableAmbiguousVMDelete = errors.New("bootstrap: retryable ambiguous VM deletion outcome")
)

type API interface {
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

	// ManagementCIDR permits a single public IPv4 /32 to reach only the exact
	// TCP ports listed here. This is intended for guarded bootstrap/E2E access.
	ManagementCIDR     string
	ManagementTCPPorts []int

	pendingDeletionMu  sync.Mutex
	pendingVMDeletions map[string]pendingVMDeletion
	now                func() time.Time

	protectionAuditTimeout            time.Duration
	protectionRequestTimeout          time.Duration
	protectionReadbackMinInterval     time.Duration
	protectionReadbackMaxInterval     time.Duration
	createdVMRecoveryTimeout          time.Duration
	createdVMFloatingIPCleanupTimeout time.Duration
	createdVMDeleteTimeout            time.Duration
}

type pendingVMDeletion struct {
	Owner        string
	Location     string
	Name         string
	UUID         string
	FirewallUUID string
	ExpiresAt    time.Time
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
		created, createErr := r.API.CreateVM(ctx, cluster.Spec.Location, bastionRequest)
		secured, secureErr := r.secureCreatedVMResponse(ctx, cluster, bastionFirewall, created, bastionRequest, resourceNames.BastionFloatingIP, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool)
		if secureErr != nil || createErr != nil {
			return Result{}, errors.Join(createErr, secureErr)
		}
		bastion = secured
		return baseResult(nil, "created and firewalled the private bastion; waiting for authoritative VM readback"), nil
	}
	bastionFirewall, err = r.ensureManagedBastionFirewall(ctx, cluster, network.Subnet, owner, bastionFirewall)
	if err != nil {
		return Result{}, err
	}
	protected, err := r.ensureVMProtection(ctx, cluster, bastionFirewall, bastion)
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

	type createOutcome struct {
		vm  *inspace.VM
		err error
	}
	outcomes := make([]createOutcome, ControlPlaneReplicas)
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
	}
	var creates sync.WaitGroup
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if controlled[slot] != nil {
			continue
		}
		creates.Add(1)
		go func(slot int) {
			defer creates.Done()
			if collisionErr := r.rejectResidualFloatingIPNames(ctx, cluster.Spec.Location, resourceNames.ControlPlaneFIP[slot]); collisionErr != nil {
				outcomes[slot].err = collisionErr
				return
			}
			created, createErr := r.API.CreateVM(ctx, cluster.Spec.Location, desiredRequests[slot])
			secured, secureErr := r.secureCreatedVMResponse(ctx, cluster, nodeFirewall, created, desiredRequests[slot], resourceNames.ControlPlaneFIP[slot], network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool)
			if secureErr != nil || createErr != nil {
				outcomes[slot].err = errors.Join(createErr, secureErr)
				return
			}
			outcomes[slot].vm = secured
		}(slot)
	}
	creates.Wait()
	if missing != 0 {
		var createErrs []error
		for slot := 0; slot < ControlPlaneReplicas; slot++ {
			if outcomes[slot].vm != nil {
				controlled[slot] = outcomes[slot].vm
			}
			if outcomes[slot].err != nil {
				createErrs = append(createErrs, fmt.Errorf("bootstrap: control-plane slot %d: %w", slot, outcomes[slot].err))
			}
		}
		result := baseResult(controlled, "created and firewalled missing private RKE2 control-plane VMs in parallel; waiting for authoritative VM readback")
		if len(createErrs) != 0 {
			return result, errors.Join(createErrs...)
		}
		return result, nil
	}
	nodeFirewall, err = r.ensureManagedNodeFirewall(ctx, cluster, network, owner, nodeFirewall)
	if err != nil {
		return Result{}, err
	}
	allProtected := true
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		protected, protectErr := r.ensureVMProtection(ctx, cluster, nodeFirewall, controlled[slot])
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
	floatingVMByName := map[string]*inspace.VM{bastionIPName: ownedVMs[bastionVMName]}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := resourceNames.ControlPlaneFIP[slot]
		floatingNames = append(floatingNames, name)
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
	if err := validateManagedBastionFirewall(bastionFirewall, cluster, network.Subnet, owner, resourceNames.BastionFirewall, r.ManagementCIDR); err != nil {
		return result, err
	}
	pendingDeletions, err := r.activePendingVMDeletions(owner, cluster.Spec.Location, firewalls)
	if err != nil {
		return result, err
	}
	nodeAllowed := controlPlaneUUIDSet(ownedVMs, controlPlaneNames)
	bastionAllowed := bastionUUIDSet(ownedVMs, bastionVMName)
	for _, deletion := range pendingDeletions {
		switch {
		case nodeFirewall != nil && deletion.FirewallUUID == nodeFirewall.UUID:
			nodeAllowed[deletion.UUID] = true
		case bastionFirewall != nil && deletion.FirewallUUID == bastionFirewall.UUID:
			bastionAllowed[deletion.UUID] = true
		default:
			return result, fmt.Errorf("bootstrap: pending deletion for VM %q references an unexpected managed firewall", deletion.Name)
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
		if item == nil {
			continue
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
		if item.AssignedTo != "" {
			updated, unassignErr := r.API.UnassignFloatingIP(ctx, cluster.Spec.Location, item.Address)
			if unassignErr == nil {
				if err := validateFloatingIPCleanupReadback(updated, cluster, name, item.Address); err != nil {
					return result, err
				}
			} else if !inspace.IsNotFound(unassignErr) {
				readback, readErr := r.findFloatingIPByAddress(ctx, cluster.Spec.Location, item.Address)
				if readErr != nil || readback == nil {
					return result, errors.Join(unassignErr, readErr)
				}
				if err := validateFloatingIPCleanupReadback(readback, cluster, name, item.Address); err != nil {
					return result, errors.Join(unassignErr, err)
				}
			}
			result.Message = "unassigned " + name
			return result, nil
		}
		if deleteErr := r.API.DeleteFloatingIP(ctx, cluster.Spec.Location, item.Address); deleteErr != nil && !inspace.IsNotFound(deleteErr) {
			readback, readErr := r.findFloatingIPByAddress(ctx, cluster.Spec.Location, item.Address)
			if readErr != nil || readback != nil {
				return result, errors.Join(deleteErr, readErr)
			}
		}
		result.Message = "deleted " + name
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
		r.rememberPendingVMDeletion(owner, cluster.Spec.Location, vm, firewallUUID)
		deleteErr := r.API.DeleteVM(ctx, cluster.Spec.Location, vm.UUID)
		switch {
		case deleteErr == nil || inspace.IsNotFound(deleteErr):
			r.refreshPendingVMDeletion(owner, cluster.Spec.Location, vm.UUID)
		case deleteVMFailureProvesNoDispatch(deleteErr):
			r.forgetPendingVMDeletion(owner, cluster.Spec.Location, vm.UUID)
			return result, deleteErr
		default:
			r.refreshPendingVMDeletion(owner, cluster.Spec.Location, vm.UUID)
			return result, fmt.Errorf("%w: %w", ErrRetryableAmbiguousVMDelete, deleteErr)
		}
		result.Message = "deleted " + vm.Name
		return result, nil
	}
	for _, firewall := range []*inspace.Firewall{bastionFirewall, nodeFirewall} {
		if firewall != nil {
			if len(firewall.ResourcesAssigned) != 0 {
				result.Message = "waiting for firewall assignments to clear after VM deletion"
				return result, nil
			}
			if err := r.API.DeleteFirewall(ctx, cluster.Spec.Location, firewall.UUID); err != nil && !inspace.IsNotFound(err) {
				return result, err
			}
			result.Message = "deleted " + firewall.EffectiveName()
			return result, nil
		}
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
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v4 owner=%s spec=", owner))
				prefixes = append(prefixes, fmt.Sprintf("inspace-rke2-bastion/v3 owner=%s spec=", owner))
			}
		}
		slot := -1
		for candidate := 0; candidate < ControlPlaneReplicas; candidate++ {
			if name == controlPlaneNames[candidate] {
				slot = candidate
				if name == controlPlaneName(clusterName, candidate) {
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
		} else {
			switch {
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v1 "):
				bastionSchema = 1
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v3 "):
				bastionSchema = 3
			case strings.HasPrefix(matchedPrefix, "inspace-rke2-bastion/v4 "):
				bastionSchema = 4
			}
		}
	}
	schemaCount := 0
	for _, present := range []bool{hasControlPlaneV2, hasControlPlaneV3, hasControlPlaneV4} {
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
		}
		expectedControlPlaneSchema := bastionSchema
		if bastionSchema == 1 {
			expectedControlPlaneSchema = 2
		}
		if expectedControlPlaneSchema != controlPlaneSchema {
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

func pendingVMDeletionKey(owner, location, uuid string) string {
	return owner + "\x00" + location + "\x00" + uuid
}

func (r *Reconciler) currentTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func configuredDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

// rememberPendingVMDeletion retains only the exact canonical VM and managed
// firewall identity that this Reconciler has just submitted for deletion. The
// bounded transition lets a later pass distinguish delayed assignment cleanup
// from a foreign UUID without treating arbitrary absent VMs as owned.
func (r *Reconciler) rememberPendingVMDeletion(owner, location string, vm *inspace.VM, firewallUUID string) {
	if vm == nil {
		return
	}
	r.pendingDeletionMu.Lock()
	defer r.pendingDeletionMu.Unlock()
	if r.pendingVMDeletions == nil {
		r.pendingVMDeletions = make(map[string]pendingVMDeletion)
	}
	r.pendingVMDeletions[pendingVMDeletionKey(owner, location, vm.UUID)] = pendingVMDeletion{
		Owner: owner, Location: location, Name: vm.Name, UUID: vm.UUID, FirewallUUID: firewallUUID,
		ExpiresAt: r.currentTime().Add(ownedVMDeletionTransitionTTL),
	}
}

func (r *Reconciler) refreshPendingVMDeletion(owner, location, uuid string) {
	r.pendingDeletionMu.Lock()
	defer r.pendingDeletionMu.Unlock()
	key := pendingVMDeletionKey(owner, location, uuid)
	deletion, exists := r.pendingVMDeletions[key]
	if !exists {
		return
	}
	deletion.ExpiresAt = r.currentTime().Add(ownedVMDeletionTransitionTTL)
	r.pendingVMDeletions[key] = deletion
}

func (r *Reconciler) forgetPendingVMDeletion(owner, location, uuid string) {
	r.pendingDeletionMu.Lock()
	defer r.pendingDeletionMu.Unlock()
	delete(r.pendingVMDeletions, pendingVMDeletionKey(owner, location, uuid))
}

// deleteVMFailureProvesNoDispatch recognizes only the explicit local mutation
// guard, which rejects the request before it can reach the network. HTTP/API
// retry metadata is not commit evidence: every such failure, plus transport
// errors and cancellations, must retain the exact deletion transition.
func deleteVMFailureProvesNoDispatch(err error) bool {
	return errors.Is(err, inspace.ErrMutationBlocked)
}

// activePendingVMDeletions returns only unexpired transitions whose UUID still
// appears exactly once as a VM assignment on the exact managed firewall that
// protected it at deletion time. Cleared transitions are discarded. Any
// wrong-firewall, wrong-type, duplicate, or expired residual assignment fails
// closed instead of widening deletion authority.
func (r *Reconciler) activePendingVMDeletions(owner, location string, firewalls []inspace.Firewall) ([]pendingVMDeletion, error) {
	r.pendingDeletionMu.Lock()
	defer r.pendingDeletionMu.Unlock()

	now := r.currentTime()
	active := make([]pendingVMDeletion, 0, len(r.pendingVMDeletions))
	for key, deletion := range r.pendingVMDeletions {
		if deletion.Owner != owner || deletion.Location != location {
			continue
		}
		assignmentCount := 0
		for i := range firewalls {
			for _, resource := range firewalls[i].ResourcesAssigned {
				if resource.ResourceUUID != deletion.UUID {
					continue
				}
				assignmentCount++
				if resource.ResourceType != "vm" || deletion.FirewallUUID == "" || firewalls[i].UUID != deletion.FirewallUUID {
					return nil, fmt.Errorf("bootstrap: pending deletion for VM %q has assignment drift", deletion.Name)
				}
			}
		}
		if assignmentCount == 0 {
			delete(r.pendingVMDeletions, key)
			continue
		}
		if assignmentCount != 1 {
			return nil, fmt.Errorf("bootstrap: pending deletion for VM %q has duplicate firewall assignments", deletion.Name)
		}
		if !now.Before(deletion.ExpiresAt) {
			return nil, fmt.Errorf("bootstrap: pending deletion assignment for VM %q did not clear within %s", deletion.Name, ownedVMDeletionTransitionTTL)
		}
		active = append(active, deletion)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Name < active[j].Name })
	return active, nil
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

func (r *Reconciler) rollbackMalformedCreatedVM(ctx context.Context, cluster *v1alpha1.InSpaceCluster, vm *inspace.VM, desired inspace.CreateVMRequest, floatingIPName string, responseErr error) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) || vm.Name != desired.Name {
		return responseErr
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMFloatingIPCleanupTimeout, defaultCreatedVMFloatingIPCleanupTimeout))
	cleanupErr := r.cleanupCreatedVMFloatingIP(cleanupCtx, cluster, vm, floatingIPName)
	cleanupCancel()
	deleteCtx, deleteCancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMDeleteTimeout, defaultCreatedVMDeleteTimeout))
	rollbackErr := r.API.DeleteVM(deleteCtx, cluster.Spec.Location, vm.UUID)
	deleteCancel()
	return errors.Join(responseErr, cleanupErr, rollbackErr)
}

// secureCreatedVMResponse closes the public-exposure window opened by
// ReservePublicIP before a create pass returns. A valid UUID from the just
// issued POST authorizes restrictive firewall attachment even when other
// response fields are sparse or contradictory. Destructive rollback remains
// stricter: it requires the exact requested VM name or a canonical
// name/ownership recovery.
func (r *Reconciler) secureCreatedVMResponse(ctx context.Context, cluster *v1alpha1.InSpaceCluster, firewall *inspace.Firewall, vm *inspace.VM, desired inspace.CreateVMRequest, floatingIPName, subnet, virtualIPv4 string, privatePool privateIPv4Range) (*inspace.VM, error) {
	responseErr := validateCreatedVMResponse(vm, desired, subnet, virtualIPv4, privatePool)
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
		identity, discoveryErr := r.discoverCreatedVMIdentity(ctx, cluster, desired)
		if discoveryErr != nil {
			return nil, errors.Join(responseErr, fmt.Errorf("bootstrap: created VM protection is uncertain because the POST returned no usable UUID and exact-name discovery did not converge: %w", discoveryErr))
		}
		// The exact deterministic list identity is enough to install and prove the
		// restrictive firewall. Do this before slower GetVM/GetNetwork ownership
		// recovery so the VM is not left publicly exposed for that audit window.
		if protectErr := r.protectReturnedVMUUID(ctx, cluster.Spec.Location, firewall, identity.UUID); protectErr != nil {
			return nil, r.rollbackMalformedCreatedVM(ctx, cluster, identity, desired, floatingIPName, errors.Join(responseErr, protectErr))
		}
		canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, identity.UUID, subnet, virtualIPv4, privatePool)
		if recoveryErr != nil {
			cause := errors.Join(responseErr, fmt.Errorf("bootstrap: canonical created VM recovery after firewall protection: %w", recoveryErr))
			return nil, r.rollbackMalformedCreatedVM(ctx, cluster, identity, desired, floatingIPName, cause)
		}
		return canonical, nil
	}

	protectErr := r.protectReturnedVMUUID(ctx, cluster.Spec.Location, firewall, vm.UUID)
	if protectErr != nil {
		cause := errors.Join(responseErr, protectErr)
		if vm.Name == desired.Name {
			return nil, r.rollbackMalformedCreatedVM(ctx, cluster, vm, desired, floatingIPName, cause)
		}
		return nil, errors.Join(cause, fmt.Errorf("bootstrap: returned VM UUID %s could not be protected and its mismatched name forbids destructive rollback", vm.UUID))
	}
	if responseErr == nil {
		return vm, nil
	}

	canonical, recoveryErr := r.recoverCreatedVM(ctx, cluster, desired, vm.UUID, subnet, virtualIPv4, privatePool)
	if recoveryErr == nil {
		return canonical, nil
	}
	cause := errors.Join(responseErr, fmt.Errorf("bootstrap: canonical created VM recovery: %w", recoveryErr))
	if vm.Name == desired.Name {
		return nil, r.rollbackMalformedCreatedVM(ctx, cluster, vm, desired, floatingIPName, cause)
	}
	return nil, errors.Join(cause, fmt.Errorf("bootstrap: returned VM UUID %s is firewalled but ownership remains uncertain", vm.UUID))
}

func (r *Reconciler) protectReturnedVMUUID(ctx context.Context, location string, firewall *inspace.Firewall, vmUUID string) error {
	if firewall == nil || !vmUUIDPattern.MatchString(firewall.UUID) {
		return errors.New("bootstrap: cannot protect a created VM without its validated managed firewall")
	}
	if !vmUUIDPattern.MatchString(vmUUID) {
		return errors.New("bootstrap: cannot protect a created VM without its returned or recovered UUID")
	}
	assignCtx, assignCancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout))
	assignErr := r.API.AssignFirewallToVM(assignCtx, location, firewall.UUID, vmUUID)
	assignCancel()
	readbackErr := r.waitForExactFirewallAssignment(context.WithoutCancel(ctx), location, firewall, vmUUID)
	if readbackErr == nil {
		return nil
	}
	if assignErr == nil {
		assignErr = errors.New("assignment call returned success without authoritative commit evidence")
	}
	return errors.Join(fmt.Errorf("bootstrap: assign managed firewall to newly created VM %s: %w", vmUUID, assignErr), readbackErr)
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

func (r *Reconciler) cleanupCreatedVMFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, vm *inspace.VM, expectedName string) error {
	items, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return err
	}
	var found *inspace.FloatingIP
	validationVM := *vm
	validationVM.PrivateIPv4 = ""
	for i := range items {
		item := &items[i]
		if item.IsDeleted || item.AssignedTo != vm.UUID && item.Name != expectedName {
			continue
		}
		if found != nil {
			return fmt.Errorf("bootstrap: refusing rollback for VM %q with multiple floating IPs", vm.Name)
		}
		if item.Name != "" && item.Name != expectedName {
			return fmt.Errorf("bootstrap: refusing rollback for VM %q with foreign floating IP name %q", vm.Name, item.Name)
		}
		if item.Name == "" {
			if err := validateAutoAssignedFloatingIP(item, cluster, &validationVM); err != nil {
				return err
			}
		} else if err := validateOwnedFloatingIP(item, cluster, expectedName, &validationVM); err != nil {
			return err
		}
		found = item
	}
	if found == nil {
		return fmt.Errorf("bootstrap: waiting for VM %q auto floating IP before rollback", vm.Name)
	}
	if found.Name == "" {
		renamed, ready, renameErr := r.ensureOwnedAutoFloatingIP(ctx, cluster, expectedName, &validationVM, found)
		if renameErr != nil {
			return renameErr
		}
		if !ready || renamed == nil {
			return fmt.Errorf("bootstrap: waiting to name VM %q auto floating IP before rollback", vm.Name)
		}
		found = renamed
	}
	if found.AssignedTo != "" {
		updated, unassignErr := r.API.UnassignFloatingIP(ctx, cluster.Spec.Location, found.Address)
		if unassignErr == nil {
			if err := validateFloatingIPCleanupReadback(updated, cluster, expectedName, found.Address); err != nil {
				return err
			}
		} else {
			readback, readErr := r.findFloatingIPByAddress(ctx, cluster.Spec.Location, found.Address)
			if readErr != nil || readback == nil {
				return errors.Join(unassignErr, readErr)
			}
			if err := validateFloatingIPCleanupReadback(readback, cluster, expectedName, found.Address); err != nil {
				return errors.Join(unassignErr, err)
			}
		}
	}
	if deleteErr := r.API.DeleteFloatingIP(ctx, cluster.Spec.Location, found.Address); deleteErr != nil && !inspace.IsNotFound(deleteErr) {
		readback, readErr := r.findFloatingIPByAddress(ctx, cluster.Spec.Location, found.Address)
		if readErr != nil || readback != nil {
			return errors.Join(deleteErr, readErr)
		}
	}
	return nil
}

func (r *Reconciler) ensureManagedNodeFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	if found != nil {
		return found, nil
	}
	expectedName := currentBootstrapResourceNames(cluster.Metadata.Name, owner).NodeFirewall
	created, err := r.API.CreateFirewall(ctx, cluster.Spec.Location, inspace.CreateFirewallRequest{
		DisplayName: expectedName, Description: "Managed RKE2 node firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedFirewallRules(network.Subnet, cluster.Spec.Network.PodCIDR, "", nil),
	})
	if err != nil {
		return nil, err
	}
	if err := validateCreatedFirewallResponse(
		created, expectedName, "Managed RKE2 node firewall for "+owner, cluster.Spec.BillingAccountID,
	); err != nil {
		return nil, fmt.Errorf("bootstrap: create node firewall response: %w", err)
	}
	items, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	readback, err := uniqueFirewallByName(items, expectedName)
	if err != nil || readback == nil || readback.UUID != created.UUID {
		return nil, errors.Join(errors.New("bootstrap: node firewall creation readback mismatch"), err)
	}
	if err := validateManagedNodeFirewall(readback, cluster, network, owner, expectedName); err != nil {
		return nil, err
	}
	return readback, nil
}

func (r *Reconciler) ensureManagedBastionFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, privateSubnet, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	if found != nil {
		return found, nil
	}
	expectedName := currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFirewall
	created, err := r.API.CreateFirewall(ctx, cluster.Spec.Location, inspace.CreateFirewallRequest{
		DisplayName: expectedName, Description: "Managed RKE2 bastion firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedBastionFirewallRules(r.ManagementCIDR, privateSubnet, !cluster.Spec.BootstrapCache.DirectDownload),
	})
	if err != nil {
		return nil, err
	}
	if err := validateCreatedFirewallResponse(
		created, expectedName, "Managed RKE2 bastion firewall for "+owner, cluster.Spec.BillingAccountID,
	); err != nil {
		return nil, fmt.Errorf("bootstrap: create bastion firewall response: %w", err)
	}
	items, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	readback, err := uniqueFirewallByName(items, expectedName)
	if err != nil || readback == nil || readback.UUID != created.UUID {
		return nil, errors.Join(errors.New("bootstrap: bastion firewall creation readback mismatch"), err)
	}
	if err := validateManagedBastionFirewall(readback, cluster, privateSubnet, owner, expectedName, r.ManagementCIDR); err != nil {
		return nil, err
	}
	return readback, nil
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
	if err := validateBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, !cluster.Spec.BootstrapCache.DirectDownload); err != nil {
		return fmt.Errorf("bootstrap: bastion firewall policy: %w", err)
	}
	return nil
}

func (r *Reconciler) ensureOwnedAutoFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM, item *inspace.FloatingIP) (*inspace.FloatingIP, bool, error) {
	if vm == nil {
		return nil, false, errors.New("bootstrap: cannot discover an auto floating IP without its owned VM")
	}
	if item == nil {
		return nil, false, nil
	}
	if item.Name == name {
		if err := validateOwnedFloatingIP(item, cluster, name, vm); err != nil {
			return nil, false, err
		}
		if item.AssignedTo != vm.UUID {
			return nil, false, fmt.Errorf("bootstrap: floating IP %q is not assigned to owned VM %q", name, vm.Name)
		}
		return item, true, nil
	}
	if err := validateAutoAssignedFloatingIP(item, cluster, vm); err != nil {
		return nil, false, err
	}
	updated, updateErr := r.API.UpdateFloatingIP(ctx, cluster.Spec.Location, item.Address, inspace.UpdateFloatingIPRequest{
		Name: name, BillingAccountID: cluster.Spec.BillingAccountID,
	})
	if updateErr == nil {
		if err := validateOwnedFloatingIP(updated, cluster, name, vm); err != nil {
			return nil, false, fmt.Errorf("bootstrap: update floating IP %q response: %w", name, err)
		}
	}
	readback, readErr := r.findFloatingIP(ctx, cluster, name, vm, item.Address)
	if readErr != nil || readback == nil {
		return nil, false, errors.Join(updateErr, readErr, fmt.Errorf("bootstrap: floating IP %q update did not converge", name))
	}
	return readback, true, nil
}

func (r *Reconciler) ensureVMProtection(ctx context.Context, cluster *v1alpha1.InSpaceCluster, firewall *inspace.Firewall, vm *inspace.VM) (bool, error) {
	if !firewallHasVM(firewall, vm.UUID) {
		requestCtx, cancel := context.WithTimeout(ctx, configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout))
		assignErr := r.API.AssignFirewallToVM(requestCtx, cluster.Spec.Location, firewall.UUID, vm.UUID)
		cancel()
		if readbackErr := r.waitForExactFirewallAssignment(ctx, cluster.Spec.Location, firewall, vm.UUID); readbackErr != nil {
			if assignErr == nil {
				assignErr = errors.New("assignment call returned success without authoritative commit evidence")
			}
			return false, errors.Join(fmt.Errorf("bootstrap: assign firewall: %w", assignErr), readbackErr)
		}
		return true, nil
	}
	return true, nil
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
			expectedRows := 0
			assignmentRows := 0
			for i := range items {
				firewall := &items[i]
				if firewall.UUID == expectedFirewall.UUID {
					expectedRows++
					if firewall.EffectiveName() != expectedFirewall.EffectiveName() || firewall.BillingAccountID != expectedFirewall.BillingAccountID {
						return errors.New("bootstrap: managed firewall identity drifted during assignment readback")
					}
					if !sameFirewallPolicy(firewall.Rules, expectedFirewall.Rules) {
						return errors.New("bootstrap: managed firewall policy drifted during assignment readback")
					}
				}
				for _, resource := range firewall.ResourcesAssigned {
					if resource.ResourceUUID != vmUUID {
						continue
					}
					assignmentRows++
					if resource.ResourceType != "vm" || firewall.UUID != expectedFirewall.UUID {
						return fmt.Errorf("bootstrap: VM %s appeared on the wrong firewall or resource type during assignment readback", vmUUID)
					}
				}
			}
			if expectedRows > 1 {
				return fmt.Errorf("bootstrap: expected one managed firewall row during assignment readback, got %d", expectedRows)
			}
			if expectedRows == 0 {
				lastErr = errors.New("bootstrap: managed firewall row is not yet visible during assignment readback")
			} else {
				switch assignmentRows {
				case 1:
					return nil
				case 0:
					lastErr = fmt.Errorf("bootstrap: VM %s firewall assignment is not yet visible", vmUUID)
				default:
					return fmt.Errorf("bootstrap: VM %s has duplicate firewall assignments during readback", vmUUID)
				}
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
	if _, err := renderCacheImageManifest(cluster.Spec.RKE2.Version, r.ModuleVersion); err != nil {
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
		BootstrapCache: cache,
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
	request.Description = fmt.Sprintf("inspace-rke2-cp/v4 owner=%s slot=%d spec=%s", owner, slot, hex.EncodeToString(sum[:]))
	return request, nil
}

func (r *Reconciler) desiredBastionVMRequest(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, material cacheTLSMaterial) (inspace.CreateVMRequest, error) {
	name := currentBastionName(cluster.Metadata.Name)
	cloudInit := ""
	var err error
	if cluster.Spec.BootstrapCache.DirectDownload {
		cloudInit, err = RenderBastionCloudInitJSON(name)
	} else {
		cloudInit, err = RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
			NodeName: name, PrivateSubnet: network.Subnet, CacheHostname: bootstrapCacheHostname(cluster.Metadata.Name),
			RKE2Version: cluster.Spec.RKE2.Version, ModuleVersion: r.ModuleVersion,
			CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
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
	request.Description = fmt.Sprintf("inspace-rke2-bastion/v4 owner=%s spec=%s", owner, hex.EncodeToString(sum[:]))
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
	if vm.BillingAccountID != 0 && vm.BillingAccountID != desired.BillingAccountID {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q from another billing account", vm.Name)
	}
	if vm.NetworkUUID != "" && vm.NetworkUUID != desired.NetworkUUID {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q from another private network", vm.Name)
	}
	onNetwork := false
	for _, uuid := range network.VMUUIDs {
		if uuid == vm.UUID {
			onNetwork = true
			break
		}
	}
	if !onNetwork {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q not attached to the configured private network", vm.Name)
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

func (r *Reconciler) findFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM, address string) (*inspace.FloatingIP, error) {
	items, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return nil, err
	}
	var found *inspace.FloatingIP
	for i := range items {
		if items[i].IsDeleted || items[i].Name != name && items[i].AssignedTo != vm.UUID {
			continue
		}
		if items[i].Name != name {
			return nil, fmt.Errorf("bootstrap: foreign floating IP name %q remains assigned to VM %q after update", items[i].Name, vm.Name)
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: multiple floating IPs resolve to owned slot %q", name)
		}
		found = &items[i]
	}
	if found != nil {
		if found.Address != address {
			return nil, fmt.Errorf("bootstrap: floating IP %q update changed address from %s to %s", name, address, found.Address)
		}
		if err := validateOwnedFloatingIP(found, cluster, name, vm); err != nil {
			return nil, err
		}
		if found.AssignedTo != vm.UUID {
			return nil, fmt.Errorf("bootstrap: floating IP %q update lost its VM assignment", name)
		}
	}
	return found, nil
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
	port := int32(22)
	result := []inspace.FirewallRule{{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port,
		EndpointSpecType: "ip_prefixes", EndpointSpec: []string{managementCIDR},
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
	if firewall == nil {
		return errors.New("bootstrap: bastion firewall is required")
	}
	if err := validateManagementAccess(managementCIDR, []int{22}); err != nil {
		return err
	}
	expectedRules := 4
	if cacheEnabled {
		expectedRules++
	}
	if len(firewall.Rules) != expectedRules {
		return errors.New("bootstrap: bastion firewall has an unexpected rule count")
	}
	sshIngress := false
	cacheIngress := false
	outbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	for _, rule := range firewall.Rules {
		switch rule.Direction {
		case "inbound":
			if rule.Protocol != "tcp" || rule.PortStart == nil || rule.PortEnd == nil || rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) != 1 {
				return errors.New("bootstrap: bastion inbound policy is invalid")
			}
			switch {
			case *rule.PortStart == 22 && *rule.PortEnd == 22 && rule.EndpointSpec[0] == managementCIDR && !sshIngress:
				sshIngress = true
			case cacheEnabled && *rule.PortStart == BootstrapCachePort && *rule.PortEnd == BootstrapCachePort && rule.EndpointSpec[0] == privateSubnet && !cacheIngress:
				cacheIngress = true
			default:
				return errors.New("bootstrap: bastion inbound policy must contain only management TCP/22 and optional VPC TCP/8443")
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
	if !sshIngress || cacheIngress != cacheEnabled || !outbound["tcp"] || !outbound["udp"] || !outbound["icmp"] {
		return errors.New("bootstrap: bastion firewall policy is incomplete")
	}
	return nil
}

func validateOwnedFirewallAssignments(firewall *inspace.Firewall, allowed map[string]bool) error {
	if firewall == nil {
		return nil
	}
	seen := make(map[string]bool, len(firewall.ResourcesAssigned))
	for _, resource := range firewall.ResourcesAssigned {
		if resource.ResourceType != "vm" || !allowed[resource.ResourceUUID] || seen[resource.ResourceUUID] {
			return errors.New("firewall contains a foreign, non-VM, or duplicate assignment")
		}
		seen[resource.ResourceUUID] = true
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
				return fmt.Errorf("bootstrap: owned %s VM %s has duplicate firewall attachments %q and %q", expected.role, resource.ResourceUUID, previous, firewall.EffectiveName())
			}
			seen[resource.ResourceUUID] = firewall.EffectiveName()
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
					return errors.New("bootstrap: management ingress must match the configured public /32 exactly")
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
	if cidr == "" || len(ports) != 1 || ports[0] != 22 {
		return errors.New("bootstrap: bastion requires exactly management public IPv4 /32 TCP/22")
	}
	return validateManagementAccess(cidr, ports)
}

func validateManagementAccess(cidr string, ports []int) error {
	if cidr == "" {
		if len(ports) != 0 {
			return errors.New("bootstrap: management TCP ports require a public IPv4 /32")
		}
		return nil
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.Addr().IsPrivate() || !prefix.Addr().IsGlobalUnicast() {
		return errors.New("bootstrap: management CIDR must be one public IPv4 /32")
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
	return Result{RequeueAfter: 20 * time.Second, MaxParallelControlPlaneCreates: ControlPlaneReplicas, ControlPlaneVMs: ids, Message: message}
}
