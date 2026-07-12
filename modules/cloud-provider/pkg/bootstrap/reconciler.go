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

	ownedVMDeletionTransitionTTL = 5 * time.Minute
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
	CreateFloatingIP(context.Context, string, inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error)
	AssignFloatingIP(context.Context, string, string, string, string) (*inspace.FloatingIP, error)
	UnassignFloatingIP(context.Context, string, string) (*inspace.FloatingIP, error)
	DeleteFloatingIP(context.Context, string, string) error
}

type Reconciler struct {
	API API

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
	owner := ownerKey(cluster)
	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	configuredNetworkVMs, err := vmsOnConfiguredNetwork(vms, network)
	if err != nil {
		return Result{}, err
	}
	byName, err := uniqueOwnedVMs(vms, owner)
	if err != nil {
		return Result{}, err
	}
	if err := validateControlPlaneBootstrapTopology(byName, owner); err != nil {
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
	floatingByName, err := validateOwnedFloatingIPs(floatingIPSnapshot, cluster, owner, byName)
	if err != nil {
		return Result{}, err
	}
	firewalls, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	nodeFirewall, err := uniqueFirewallByName(firewalls, firewallName(owner))
	if err != nil {
		return Result{}, err
	}
	bastionFirewall, err := uniqueFirewallByName(firewalls, bastionFirewallName(owner))
	if err != nil {
		return Result{}, err
	}
	if err := validateManagedNodeFirewall(nodeFirewall, cluster, network, owner); err != nil {
		return Result{}, err
	}
	if err := validateManagedBastionFirewall(bastionFirewall, cluster, owner, r.ManagementCIDR); err != nil {
		return Result{}, err
	}
	if err := validateOwnedFirewallAssignments(nodeFirewall, controlPlaneUUIDSet(byName, owner)); err != nil {
		return Result{}, fmt.Errorf("bootstrap: node firewall assignment drift: %w", err)
	}
	if err := validateOwnedFirewallAssignments(bastionFirewall, bastionUUIDSet(byName, owner)); err != nil {
		return Result{}, fmt.Errorf("bootstrap: bastion firewall assignment drift: %w", err)
	}
	if err := validateReverseFirewallAssignments(firewalls, nodeFirewall, bastionFirewall, byName, owner); err != nil {
		return Result{}, err
	}
	if err := r.validateExistingVMs(cluster, network, privatePool, owner, byName, floatingByName, rke2Token); err != nil {
		return Result{}, err
	}

	nodeFirewall, err = r.ensureManagedNodeFirewall(ctx, cluster, network, owner, nodeFirewall)
	if err != nil {
		return Result{}, err
	}
	bastionFirewall, err = r.ensureManagedBastionFirewall(ctx, cluster, owner, bastionFirewall)
	if err != nil {
		return Result{}, err
	}
	bastion := byName[bastionName(owner)]
	bastionIP, err := r.ensureOwnedFloatingIP(ctx, cluster, bastionFloatingIPName(owner), bastion, floatingByName[bastionFloatingIPName(owner)])
	if err != nil {
		return Result{}, err
	}
	baseResult := func(vms []*inspace.VM, message string) Result {
		result := progressResult(vms, message)
		result.Owner = owner
		result.FirewallUUID = nodeFirewall.UUID
		result.BastionFirewallUUID = bastionFirewall.UUID
		result.ControlPlaneEndpoint = fmt.Sprintf("https://%s:6443", cluster.Spec.Endpoint.VirtualIPv4)
		result.PrivateControlPlaneEndpoint = result.ControlPlaneEndpoint
		result.PrivateRegistrationEndpoint = fmt.Sprintf("https://%s:9345", cluster.Spec.Endpoint.VirtualIPv4)
		result.BastionPublicIPv4 = bastionIP.Address
		if bastion != nil {
			result.BastionVMUUID = bastion.UUID
			result.BastionPrivateIPv4 = bastion.PrivateIPv4
		}
		return result
	}
	bastionRequest, err := r.desiredBastionVMRequest(cluster, owner)
	if err != nil {
		return Result{}, err
	}
	if bastion == nil {
		created, createErr := r.API.CreateVM(ctx, cluster.Spec.Location, bastionRequest)
		if createErr != nil {
			return Result{}, createErr
		}
		if responseErr := validateCreatedVMResponse(created, bastionRequest, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); responseErr != nil {
			return Result{}, r.rollbackMalformedCreatedVM(ctx, cluster.Spec.Location, created, bastionRequest, responseErr)
		}
		bastion = created
		return baseResult(nil, "created the private bastion; waiting for authoritative VM readback before protection"), nil
	}
	if !isVMReady(bastion) {
		return baseResult(nil, "waiting for bastion private networking"), nil
	}
	if err := validateVMPrivateIPv4(bastion, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
		return Result{}, err
	}
	protected, err := r.ensureVMProtection(ctx, cluster, bastionFirewall, bastionIP, bastion)
	if err != nil {
		return Result{}, err
	}
	if !protected {
		return baseResult(nil, "waiting for bastion firewall or floating IP assignment readback"), nil
	}

	controlled := make([]*inspace.VM, ControlPlaneReplicas)
	floatingIPs := make([]*inspace.FloatingIP, ControlPlaneReplicas)
	desiredRequests := make([]inspace.CreateVMRequest, ControlPlaneReplicas)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := controlPlaneName(owner, slot)
		vm := byName[name]
		floatingIP, ipErr := r.ensureOwnedFloatingIP(ctx, cluster, nodeFloatingIPName(owner, slot), vm, floatingByName[nodeFloatingIPName(owner, slot)])
		if ipErr != nil {
			return Result{}, ipErr
		}
		floatingIPs[slot] = floatingIP
		controlled[slot] = vm
		desired, desiredErr := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, floatingIP.Address, cluster.Spec.Endpoint.VirtualIPv4, rke2Token)
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
	var creates sync.WaitGroup
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if controlled[slot] != nil {
			continue
		}
		missing++
		creates.Add(1)
		go func(slot int) {
			defer creates.Done()
			created, createErr := r.API.CreateVM(ctx, cluster.Spec.Location, desiredRequests[slot])
			if createErr != nil {
				outcomes[slot].err = createErr
				return
			}
			if responseErr := validateCreatedVMResponse(created, desiredRequests[slot], network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); responseErr != nil {
				outcomes[slot].err = r.rollbackMalformedCreatedVM(ctx, cluster.Spec.Location, created, desiredRequests[slot], responseErr)
				return
			}
			outcomes[slot].vm = created
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
		result := baseResult(controlled, "created missing private RKE2 control-plane VMs in parallel; waiting for authoritative VM readback before protection")
		if len(createErrs) != 0 {
			return result, errors.Join(createErrs...)
		}
		return result, nil
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
		protected, err := r.ensureVMProtection(ctx, cluster, nodeFirewall, floatingIPs[slot], vm)
		if err != nil {
			return Result{}, err
		}
		if !protected {
			result := baseResult(controlled, "waiting for firewall or floating IP assignment readback")
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
	if errs := cluster.Validate(); len(errs) != 0 {
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
	ownedVMs, err := uniqueOwnedVMs(vms, owner)
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
	if err := validateDestroyVMOwnership(ownedVMs, owner); err != nil {
		return result, err
	}
	floatingIPSnapshot, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return result, err
	}
	floatingByName, err := validateOwnedFloatingIPs(floatingIPSnapshot, cluster, owner, ownedVMs)
	if err != nil {
		return result, err
	}
	floatingNames := []string{bastionFloatingIPName(owner)}
	floatingVMByName := map[string]*inspace.VM{bastionFloatingIPName(owner): ownedVMs[bastionName(owner)]}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := nodeFloatingIPName(owner, slot)
		floatingNames = append(floatingNames, name)
		floatingVMByName[name] = ownedVMs[controlPlaneName(owner, slot)]
	}
	for _, name := range floatingNames {
		item := floatingByName[name]
		if item != nil {
			result.Remaining = append(result.Remaining, "floating-ip/"+name)
		}
	}
	firewalls, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return result, err
	}
	nodeFirewall, err := uniqueFirewallByName(firewalls, firewallName(owner))
	if err != nil {
		return result, err
	}
	bastionFirewall, err := uniqueFirewallByName(firewalls, bastionFirewallName(owner))
	if err != nil {
		return result, err
	}
	if err := validateManagedNodeFirewall(nodeFirewall, cluster, network, owner); err != nil {
		return result, err
	}
	if err := validateManagedBastionFirewall(bastionFirewall, cluster, owner, r.ManagementCIDR); err != nil {
		return result, err
	}
	pendingDeletions, err := r.activePendingVMDeletions(owner, cluster.Spec.Location, firewalls)
	if err != nil {
		return result, err
	}
	nodeAllowed := controlPlaneUUIDSet(ownedVMs, owner)
	bastionAllowed := bastionUUIDSet(ownedVMs, owner)
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
	if err := validateReverseFirewallAssignments(firewalls, nodeFirewall, bastionFirewall, ownedVMs, owner); err != nil {
		return result, err
	}
	vmNames := []string{bastionName(owner)}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vmNames = append(vmNames, controlPlaneName(owner, slot))
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
		if item.AssignedTo != "" {
			updated, unassignErr := r.API.UnassignFloatingIP(ctx, cluster.Spec.Location, item.Address)
			if unassignErr != nil && !inspace.IsNotFound(unassignErr) {
				return result, unassignErr
			}
			if unassignErr == nil {
				if err := validateOwnedFloatingIP(updated, cluster, name, floatingVMByName[name]); err != nil {
					return result, err
				}
				if updated.AssignedTo != "" {
					return result, fmt.Errorf("bootstrap: floating IP %q remained assigned after unassign", name)
				}
			}
			result.Message = "unassigned " + name
			return result, nil
		}
		if err := r.API.DeleteFloatingIP(ctx, cluster.Spec.Location, item.Address); err != nil && !inspace.IsNotFound(err) {
			return result, err
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
		if name == bastionName(owner) {
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
		case deleteVMFailureProvesNoCommit(deleteErr):
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
func validateDestroyVMOwnership(vms map[string]*inspace.VM, owner string) error {
	for name, vm := range vms {
		if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
			return fmt.Errorf("bootstrap: refusing to delete VM %q with an invalid UUID", name)
		}
		prefix := ""
		if name == bastionName(owner) {
			prefix = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=", owner)
		}
		slot := -1
		for candidate := 0; candidate < ControlPlaneReplicas; candidate++ {
			if name == controlPlaneName(owner, candidate) {
				slot = candidate
				prefix = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=", owner, slot)
				break
			}
		}
		if prefix == "" {
			return fmt.Errorf("bootstrap: refusing to delete VM %q outside the owned bastion/control-plane slots", name)
		}
		hash := strings.TrimPrefix(vm.Description, prefix)
		if hash == vm.Description || len(hash) != sha256.Size*2 {
			return fmt.Errorf("bootstrap: refusing to delete VM %q without the expected ownership record", name)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("bootstrap: refusing to delete VM %q with an invalid ownership hash", name)
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

// deleteVMFailureProvesNoCommit recognizes only failures known to occur before
// a VM deletion can commit. Retryable API responses, transport errors, and
// cancellations are ambiguous and deliberately retain the exact deletion
// transition for the next read-before-mutate pass.
func deleteVMFailureProvesNoCommit(err error) bool {
	if errors.Is(err, inspace.ErrMutationBlocked) {
		return true
	}
	var apiErr *inspace.APIError
	return errors.As(err, &apiErr) && !apiErr.Retryable
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
// actually supplied. Firewall and floating-IP attachment is deliberately
// deferred until the next reconcile has validated the authoritative VM,
// network, and ownership list readback.
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

func (r *Reconciler) rollbackMalformedCreatedVM(ctx context.Context, location string, vm *inspace.VM, desired inspace.CreateVMRequest, responseErr error) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) || vm.Name != desired.Name || vm.Description != desired.Description {
		return responseErr
	}
	rollbackErr := r.API.DeleteVM(ctx, location, vm.UUID)
	return errors.Join(responseErr, rollbackErr)
}

func (r *Reconciler) ensureManagedNodeFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	if found != nil {
		return found, nil
	}
	created, err := r.API.CreateFirewall(ctx, cluster.Spec.Location, inspace.CreateFirewallRequest{
		DisplayName: firewallName(owner), Description: "Managed RKE2 node firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedFirewallRules(network.Subnet, cluster.Spec.Network.PodCIDR, "", nil),
	})
	if err != nil {
		return nil, err
	}
	if err := validateCreatedFirewallResponse(
		created, firewallName(owner), "Managed RKE2 node firewall for "+owner, cluster.Spec.BillingAccountID,
	); err != nil {
		return nil, fmt.Errorf("bootstrap: create node firewall response: %w", err)
	}
	items, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	readback, err := uniqueFirewallByName(items, firewallName(owner))
	if err != nil || readback == nil || readback.UUID != created.UUID {
		return nil, errors.Join(errors.New("bootstrap: node firewall creation readback mismatch"), err)
	}
	if err := validateManagedNodeFirewall(readback, cluster, network, owner); err != nil {
		return nil, err
	}
	return readback, nil
}

func (r *Reconciler) ensureManagedBastionFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, owner string, found *inspace.Firewall) (*inspace.Firewall, error) {
	if found != nil {
		return found, nil
	}
	created, err := r.API.CreateFirewall(ctx, cluster.Spec.Location, inspace.CreateFirewallRequest{
		DisplayName: bastionFirewallName(owner), Description: "Managed RKE2 bastion firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedBastionFirewallRules(r.ManagementCIDR),
	})
	if err != nil {
		return nil, err
	}
	if err := validateCreatedFirewallResponse(
		created, bastionFirewallName(owner), "Managed RKE2 bastion firewall for "+owner, cluster.Spec.BillingAccountID,
	); err != nil {
		return nil, fmt.Errorf("bootstrap: create bastion firewall response: %w", err)
	}
	items, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	readback, err := uniqueFirewallByName(items, bastionFirewallName(owner))
	if err != nil || readback == nil || readback.UUID != created.UUID {
		return nil, errors.Join(errors.New("bootstrap: bastion firewall creation readback mismatch"), err)
	}
	if err := validateManagedBastionFirewall(readback, cluster, owner, r.ManagementCIDR); err != nil {
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

func validateManagedNodeFirewall(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string) error {
	if firewall == nil {
		return nil
	}
	expectedDescription := "Managed RKE2 node firewall for " + owner
	if firewall.EffectiveName() != firewallName(owner) || firewall.BillingAccountID != cluster.Spec.BillingAccountID {
		return errors.New("bootstrap: node firewall lacks the expected owner-derived name or billing-account identity")
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

func validateManagedBastionFirewall(firewall *inspace.Firewall, cluster *v1alpha1.InSpaceCluster, owner, managementCIDR string) error {
	if firewall == nil {
		return nil
	}
	expectedDescription := "Managed RKE2 bastion firewall for " + owner
	if firewall.EffectiveName() != bastionFirewallName(owner) || firewall.BillingAccountID != cluster.Spec.BillingAccountID {
		return errors.New("bootstrap: bastion firewall lacks the expected owner-derived name or billing-account identity")
	}
	if firewall.Description != "" && firewall.Description != expectedDescription {
		return errors.New("bootstrap: bastion firewall has an unexpected description")
	}
	if err := validateBastionFirewallPolicy(firewall, managementCIDR); err != nil {
		return fmt.Errorf("bootstrap: bastion firewall policy: %w", err)
	}
	return nil
}

func (r *Reconciler) ensureOwnedFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM, item *inspace.FloatingIP) (*inspace.FloatingIP, error) {
	var err error
	if item == nil {
		item, err = r.API.CreateFloatingIP(ctx, cluster.Spec.Location, inspace.CreateFloatingIPRequest{Name: name, BillingAccountID: cluster.Spec.BillingAccountID})
		if err != nil {
			return nil, err
		}
	}
	if err := validateOwnedFloatingIP(item, cluster, name, vm); err != nil {
		return nil, err
	}
	return item, nil
}

func (r *Reconciler) ensureVMProtection(ctx context.Context, cluster *v1alpha1.InSpaceCluster, firewall *inspace.Firewall, floatingIP *inspace.FloatingIP, vm *inspace.VM) (bool, error) {
	if !firewallHasVM(firewall, vm.UUID) {
		if err := r.API.AssignFirewallToVM(ctx, cluster.Spec.Location, firewall.UUID, vm.UUID); err != nil {
			if !r.firewallAssignmentVisible(ctx, cluster.Spec.Location, firewall.UUID, vm.UUID) {
				return false, fmt.Errorf("bootstrap: assign firewall: %w", err)
			}
		}
		return false, nil
	}
	if floatingIP.AssignedTo == "" {
		assigned, err := r.API.AssignFloatingIP(ctx, cluster.Spec.Location, floatingIP.Address, vm.UUID, "virtual_machine")
		if err == nil {
			if validateErr := validateOwnedFloatingIP(assigned, cluster, floatingIP.Name, vm); validateErr != nil {
				return false, validateErr
			}
			return false, nil
		}
		readback, readErr := r.findFloatingIP(ctx, cluster, floatingIP.Name, vm)
		if readErr != nil || readback == nil || readback.AssignedTo != vm.UUID {
			return false, errors.Join(err, readErr)
		}
		return false, nil
	}
	return true, nil
}

func (r *Reconciler) firewallAssignmentVisible(ctx context.Context, location, firewallUUID, vmUUID string) bool {
	items, err := r.API.ListFirewalls(ctx, location)
	if err != nil {
		return false
	}
	for i := range items {
		if items[i].UUID == firewallUUID {
			return firewallHasVM(&items[i], vmUUID)
		}
	}
	return false
}

func (r *Reconciler) desiredControlPlaneVMRequest(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, slot int, externalIP, joinAddress, token string) (inspace.CreateVMRequest, error) {
	tlsNames := append([]string{cluster.Spec.Endpoint.VirtualIPv4}, cluster.Spec.RKE2.TLSSubjectAltNames...)
	cloudInit, err := RenderCloudInitJSON(CloudInitInput{
		NodeName: controlPlaneName(owner, slot), NodeExternalIPv4: externalIP, PrivateSubnet: network.Subnet, VirtualIPv4: cluster.Spec.Endpoint.VirtualIPv4,
		RKE2Version: cluster.Spec.RKE2.Version, RKE2Token: token, Initialize: slot == 0, ServerAddress: joinAddress,
		PodCIDR: cluster.Spec.Network.PodCIDR, ServiceCIDR: cluster.Spec.Network.ServiceCIDR,
		PrivateLoadBalancerPoolStart: cluster.Spec.Network.PrivateLoadBalancerPool.Start,
		PrivateLoadBalancerPoolStop:  cluster.Spec.Network.PrivateLoadBalancerPool.Stop,
		TLSSubjectAltNames:           tlsNames, Disable: cluster.Spec.RKE2.Disable,
	})
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	reserve := false
	machine := cluster.Spec.ControlPlane.Machine
	request := inspace.CreateVMRequest{
		Name:   controlPlaneName(owner, slot),
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
	request.Description = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=%s", owner, slot, hex.EncodeToString(sum[:]))
	return request, nil
}

func (r *Reconciler) desiredBastionVMRequest(cluster *v1alpha1.InSpaceCluster, owner string) (inspace.CreateVMRequest, error) {
	cloudInit, err := RenderBastionCloudInitJSON()
	if err != nil {
		return inspace.CreateVMRequest{}, err
	}
	reserve := false
	request := inspace.CreateVMRequest{
		Name: bastionName(owner), OSName: "ubuntu", OSVersion: "24.04", DiskGiB: BastionRootDiskGiB,
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
	request.Description = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=%s", owner, hex.EncodeToString(sum[:]))
	return request, nil
}

func (r *Reconciler) validateExistingVMs(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, privatePool privateIPv4Range, owner string, byName map[string]*inspace.VM, floatingByName map[string]*inspace.FloatingIP, token string) error {
	if bastion := byName[bastionName(owner)]; bastion != nil {
		if bastion.PrivateIPv4 != "" {
			if err := validateVMPrivateIPv4(bastion, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
				return err
			}
		}
		if floatingByName[bastionFloatingIPName(owner)] == nil {
			return errors.New("bootstrap: refusing to adopt bastion without its deterministic floating IP")
		}
		desired, err := r.desiredBastionVMRequest(cluster, owner)
		if err != nil {
			return err
		}
		if err := validateOwnedVM(bastion, desired, network); err != nil {
			return err
		}
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := byName[controlPlaneName(owner, slot)]
		if vm == nil {
			continue
		}
		if vm.PrivateIPv4 != "" {
			if err := validateVMPrivateIPv4(vm, network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privatePool); err != nil {
				return err
			}
		}
		floatingIP := floatingByName[nodeFloatingIPName(owner, slot)]
		if floatingIP == nil {
			return fmt.Errorf("bootstrap: refusing to adopt control-plane slot %d without its deterministic floating IP", slot)
		}
		desired, err := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, floatingIP.Address, cluster.Spec.Endpoint.VirtualIPv4, token)
		if err != nil {
			return err
		}
		if err := validateOwnedVM(vm, desired, network); err != nil {
			return err
		}
	}
	return nil
}

func validateOwnedFloatingIPs(items []inspace.FloatingIP, cluster *v1alpha1.InSpaceCluster, owner string, ownedVMs map[string]*inspace.VM) (map[string]*inspace.FloatingIP, error) {
	expected := map[string]*inspace.VM{bastionFloatingIPName(owner): ownedVMs[bastionName(owner)]}
	ownedUUIDs := bastionUUIDSet(ownedVMs, owner)
	for uuid := range controlPlaneUUIDSet(ownedVMs, owner) {
		ownedUUIDs[uuid] = true
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expected[nodeFloatingIPName(owner, slot)] = ownedVMs[controlPlaneName(owner, slot)]
	}
	result := make(map[string]*inspace.FloatingIP, len(expected))
	for i := range items {
		item := &items[i]
		if item.IsDeleted {
			continue
		}
		vm, isOwnedName := expected[item.Name]
		if !isOwnedName {
			if ownedUUIDs[item.AssignedTo] {
				return nil, fmt.Errorf("bootstrap: unknown floating IP %s is assigned to an owned VM", item.Address)
			}
			continue
		}
		if result[item.Name] != nil {
			return nil, fmt.Errorf("bootstrap: duplicate owned floating IP name %q", item.Name)
		}
		if err := validateOwnedFloatingIP(item, cluster, item.Name, vm); err != nil {
			return nil, err
		}
		result[item.Name] = item
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
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
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
	if vm.PrivateIPv4 != "" && item.AssignedToPrivateIP != "" && item.AssignedToPrivateIP != vm.PrivateIPv4 {
		return fmt.Errorf("bootstrap: floating IP %q assignment private IPv4 does not match VM %q", expectedName, vm.Name)
	}
	return nil
}

func validateOwnedVM(vm *inspace.VM, desired inspace.CreateVMRequest, network *inspace.Network) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
		return fmt.Errorf("bootstrap: refusing to adopt VM %q with an invalid UUID", desired.Name)
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

func (r *Reconciler) findFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string, vm *inspace.VM) (*inspace.FloatingIP, error) {
	items, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, nil)
	if err != nil {
		return nil, err
	}
	var found *inspace.FloatingIP
	for i := range items {
		if items[i].Name != name || items[i].IsDeleted {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: duplicate owned floating IP name %q", name)
		}
		found = &items[i]
	}
	if found != nil {
		if err := validateOwnedFloatingIP(found, cluster, name, vm); err != nil {
			return nil, err
		}
	}
	return found, nil
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

func managedBastionFirewallRules(managementCIDR string) []inspace.FirewallRule {
	port := int32(22)
	result := []inspace.FirewallRule{{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port,
		EndpointSpecType: "ip_prefixes", EndpointSpec: []string{managementCIDR},
	}}
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		result = append(result, inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"})
	}
	return result
}

func validateBastionFirewallPolicy(firewall *inspace.Firewall, managementCIDR string) error {
	if firewall == nil {
		return errors.New("bootstrap: bastion firewall is required")
	}
	if err := validateManagementAccess(managementCIDR, []int{22}); err != nil {
		return err
	}
	if len(firewall.Rules) != 4 {
		return errors.New("bootstrap: bastion firewall must contain exactly SSH ingress plus TCP/UDP/ICMP egress")
	}
	sshIngress := false
	outbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	for _, rule := range firewall.Rules {
		switch rule.Direction {
		case "inbound":
			if sshIngress || rule.Protocol != "tcp" || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != 22 || *rule.PortEnd != 22 ||
				rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) != 1 || rule.EndpointSpec[0] != managementCIDR {
				return errors.New("bootstrap: bastion inbound policy must be only management /32 TCP/22")
			}
			sshIngress = true
		case "outbound":
			if _, ok := outbound[rule.Protocol]; !ok || outbound[rule.Protocol] || rule.PortStart != nil || rule.PortEnd != nil || rule.EndpointSpecType != "any" {
				return errors.New("bootstrap: bastion outbound policy must be one unrestricted TCP/UDP/ICMP rule")
			}
			outbound[rule.Protocol] = true
		default:
			return errors.New("bootstrap: bastion firewall has an invalid direction")
		}
	}
	if !sshIngress || !outbound["tcp"] || !outbound["udp"] || !outbound["icmp"] {
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
func validateReverseFirewallAssignments(firewalls []inspace.Firewall, nodeFirewall, bastionFirewall *inspace.Firewall, vms map[string]*inspace.VM, owner string) error {
	type expectedAttachment struct {
		firewallUUID string
		role         string
	}
	expectedByVM := make(map[string]expectedAttachment, ControlPlaneReplicas+1)
	if bastion := vms[bastionName(owner)]; bastion != nil && bastion.UUID != "" {
		expectedUUID := ""
		if bastionFirewall != nil {
			expectedUUID = bastionFirewall.UUID
		}
		expectedByVM[bastion.UUID] = expectedAttachment{firewallUUID: expectedUUID, role: "bastion"}
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := vms[controlPlaneName(owner, slot)]
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
func validateControlPlaneBootstrapTopology(vms map[string]*inspace.VM, owner string) error {
	if vms[controlPlaneName(owner, 0)] != nil {
		return nil
	}
	for slot := 1; slot < ControlPlaneReplicas; slot++ {
		if vms[controlPlaneName(owner, slot)] != nil {
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

func controlPlaneName(owner string, slot int) string {
	return fmt.Sprintf("rke2-%s-cp-%d", owner, slot)
}
func bastionName(owner string) string         { return "rke2-" + owner + "-bastion" }
func firewallName(owner string) string        { return "rke2-" + owner + "-nodes" }
func bastionFirewallName(owner string) string { return "rke2-" + owner + "-bastion" }
func bastionFloatingIPName(owner string) string {
	return "rke2-" + owner + "-bastion-ip"
}
func nodeFloatingIPName(owner string, slot int) string {
	return fmt.Sprintf("rke2-%s-cp-%d-ip", owner, slot)
}

func uniqueOwnedVMs(vms []inspace.VM, owner string) (map[string]*inspace.VM, error) {
	ownedPrefix := "rke2-" + owner + "-"
	expected := map[string]bool{bastionName(owner): true}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expected[controlPlaneName(owner, slot)] = true
	}
	result := make(map[string]*inspace.VM, len(vms))
	for i := range vms {
		if !strings.HasPrefix(vms[i].Name, ownedPrefix) {
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

func controlPlaneUUIDSet(vms map[string]*inspace.VM, owner string) map[string]bool {
	result := make(map[string]bool, ControlPlaneReplicas)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if vm := vms[controlPlaneName(owner, slot)]; vm != nil {
			result[vm.UUID] = true
		}
	}
	return result
}

func bastionUUIDSet(vms map[string]*inspace.VM, owner string) map[string]bool {
	result := make(map[string]bool, 1)
	if vm := vms[bastionName(owner)]; vm != nil {
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
