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
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/inspace"
)

const ControlPlaneReplicas = 3

var sshUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,29}$`)

type API interface {
	GetNetwork(context.Context, string, string) (*inspace.Network, error)
	ListVMs(context.Context, string) ([]inspace.VM, error)
	CreateVM(context.Context, string, inspace.CreateVMRequest) (*inspace.VM, error)
	DeleteVM(context.Context, string, string) error
	ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error)
	CreateLoadBalancer(context.Context, string, inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error)
	AddLoadBalancerTarget(context.Context, string, string, string) (*inspace.LoadBalancerTarget, error)
	DeleteLoadBalancer(context.Context, string, string) error
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
}

type Result struct {
	Ready                       bool          `json:"ready"`
	RequeueAfter                time.Duration `json:"requeueAfter"`
	Owner                       string        `json:"owner"`
	FirewallUUID                string        `json:"firewallUUID,omitempty"`
	APILoadBalancerUUID         string        `json:"apiLoadBalancerUUID,omitempty"`
	ControlPlaneEndpoint        string        `json:"controlPlaneEndpoint,omitempty"`
	PrivateControlPlaneEndpoint string        `json:"privateControlPlaneEndpoint,omitempty"`
	AllocatedEndpointIPv4       string        `json:"allocatedEndpointIPv4,omitempty"`
	ControlPlaneVMs             []string      `json:"controlPlaneVMs,omitempty"`
	Message                     string        `json:"message,omitempty"`
}

type DestroyResult struct {
	Done      bool     `json:"done"`
	Owner     string   `json:"owner"`
	Remaining []string `json:"remaining,omitempty"`
	Message   string   `json:"message,omitempty"`
}

func (r *Reconciler) Reconcile(ctx context.Context, cluster *v1alpha1.InSpaceCluster, k3sToken string) (Result, error) {
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
	if k3sToken == "" {
		return Result{}, errors.New("bootstrap: K3s token is required")
	}
	if err := r.validateOperatorAccess(); err != nil {
		return Result{}, err
	}
	network, err := r.API.GetNetwork(ctx, cluster.Spec.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return Result{}, err
	}
	if err := validatePrivateSubnet(network.Subnet); err != nil {
		return Result{}, err
	}
	if err := validateNetworkCIDRs(network.Subnet, cluster.Spec.Network.PodCIDR, cluster.Spec.Network.ServiceCIDR); err != nil {
		return Result{}, err
	}
	owner := ownerKey(cluster)
	firewall, err := r.ensureFirewall(ctx, cluster, network, owner)
	if err != nil {
		return Result{}, err
	}
	lb, err := r.ensureAPILoadBalancer(ctx, cluster, owner)
	if err != nil {
		return Result{}, err
	}
	if lb.PrivateAddress == "" {
		return Result{RequeueAfter: 20 * time.Second, Owner: owner, FirewallUUID: firewall.UUID, APILoadBalancerUUID: lb.UUID, Message: "waiting for private API load balancer address"}, nil
	}
	apiPublicIPv4 := ""
	if cluster.Spec.Endpoint.Public {
		apiIP, ipErr := r.ensureAPIFloatingIP(ctx, cluster, owner, lb)
		if ipErr != nil {
			return Result{}, ipErr
		}
		apiPublicIPv4 = apiIP.Address
	}
	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return Result{}, err
	}
	byName, err := uniqueVMsByName(vms, "k3s-"+owner+"-cp-")
	if err != nil {
		return Result{}, err
	}

	controlled := make([]*inspace.VM, ControlPlaneReplicas)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		name := controlPlaneName(owner, slot)
		vm := byName[name]
		floatingIP, ipErr := r.ensureNodeFloatingIP(ctx, cluster, owner, slot, vm)
		if ipErr != nil {
			return Result{}, ipErr
		}
		if vm == nil {
			if slot > 0 && !isVMReady(controlled[slot-1]) {
				return progressResult(controlled, "waiting for preceding control-plane VM"), nil
			}
			desired, desiredErr := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, floatingIP.Address, lb.PrivateAddress, apiPublicIPv4, k3sToken)
			if desiredErr != nil {
				return Result{}, desiredErr
			}
			created, createErr := r.API.CreateVM(ctx, cluster.Spec.Location, desired)
			if createErr != nil {
				return Result{}, createErr
			}
			if assignErr := r.API.AssignFirewallToVM(ctx, cluster.Spec.Location, firewall.UUID, created.UUID); assignErr != nil {
				if !r.firewallAssignmentVisible(ctx, cluster.Spec.Location, firewall.UUID, created.UUID) {
					rollbackErr := r.API.DeleteVM(ctx, cluster.Spec.Location, created.UUID)
					return Result{}, errors.Join(fmt.Errorf("bootstrap: assign firewall: %w", assignErr), rollbackErr)
				}
			}
			controlled[slot] = created
			return progressResult(controlled, "created one private control-plane VM; waiting for firewall association before public IP assignment"), nil
		}
		controlled[slot] = vm
		desired, desiredErr := r.desiredControlPlaneVMRequest(cluster, network, owner, slot, floatingIP.Address, lb.PrivateAddress, apiPublicIPv4, k3sToken)
		if desiredErr != nil {
			return Result{}, desiredErr
		}
		if err := validateOwnedVM(vm, desired, network); err != nil {
			return Result{}, err
		}
		protected, err := r.ensureVMProtection(ctx, cluster, firewall, floatingIP, vm)
		if err != nil {
			return Result{}, err
		}
		if !protected {
			return progressResult(controlled, "waiting for firewall or floating IP assignment readback"), nil
		}
		if !isVMReady(vm) {
			return progressResult(controlled, "waiting for control-plane VM private networking"), nil
		}
		if !hasTarget(lb, vm.UUID) {
			if _, err := r.API.AddLoadBalancerTarget(ctx, cluster.Spec.Location, lb.UUID, vm.UUID); err != nil {
				return Result{}, err
			}
			return progressResult(controlled, "added one API load balancer target"), nil
		}
	}
	for _, vm := range controlled {
		if !hasTarget(lb, vm.UUID) {
			if _, err := r.API.AddLoadBalancerTarget(ctx, cluster.Spec.Location, lb.UUID, vm.UUID); err != nil {
				return Result{}, err
			}
			return progressResult(controlled, "added one API load balancer target"), nil
		}
	}
	result := progressResult(controlled, "infrastructure reconciled; K3s API health is not yet probed")
	result.Ready = true
	result.RequeueAfter = 0
	result.ControlPlaneEndpoint = fmt.Sprintf("https://%s:6443", cluster.Spec.Endpoint.Host)
	result.PrivateControlPlaneEndpoint = fmt.Sprintf("https://%s:6443", lb.PrivateAddress)
	result.AllocatedEndpointIPv4 = apiPublicIPv4
	result.Owner = owner
	result.FirewallUUID = firewall.UUID
	result.APILoadBalancerUUID = lb.UUID
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
	owner := ownerKey(cluster)
	result := DestroyResult{Owner: owner}

	vms, err := r.API.ListVMs(ctx, cluster.Spec.Location)
	if err != nil {
		return result, err
	}
	ownedVMs, err := uniqueVMsByName(vms, "k3s-"+owner+"-cp-")
	if err != nil {
		return result, err
	}
	if err := validateDestroyVMOwnership(ownedVMs, owner); err != nil {
		return result, err
	}
	lb, err := r.findLoadBalancer(ctx, cluster.Spec.Location, apiLoadBalancerName(owner))
	if err != nil {
		return result, err
	}
	if lb != nil && (lb.NetworkUUID != cluster.Spec.Network.UUID ||
		(lb.BillingAccountID != 0 && lb.BillingAccountID != cluster.Spec.BillingAccountID) ||
		len(lb.ForwardingRules) != 1 || lb.ForwardingRules[0].SourcePort != 6443 ||
		lb.ForwardingRules[0].TargetPort != 6443 ||
		(lb.ForwardingRules[0].Protocol != "" && lb.ForwardingRules[0].Protocol != "TCP")) {
		return result, errors.New("bootstrap: refusing to delete API load balancer with mismatched ownership/configuration")
	}

	floatingByName := map[string]*inspace.FloatingIP{}
	floatingNames := []string{apiFloatingIPName(owner)}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		floatingNames = append(floatingNames, nodeFloatingIPName(owner, slot))
	}
	for _, name := range floatingNames {
		item, findErr := r.findFloatingIP(ctx, cluster, name)
		if findErr != nil {
			return result, findErr
		}
		if item != nil {
			floatingByName[name] = item
			result.Remaining = append(result.Remaining, "floating-ip/"+name)
		}
	}
	if lb != nil {
		result.Remaining = append(result.Remaining, "load-balancer/"+lb.DisplayName)
	}
	vmNames := make([]string, 0, len(ownedVMs))
	for name := range ownedVMs {
		vmNames = append(vmNames, name)
		result.Remaining = append(result.Remaining, "vm/"+name)
	}
	sort.Strings(vmNames)

	var firewall *inspace.Firewall
	if cluster.Spec.Firewall.Managed {
		firewalls, listErr := r.API.ListFirewalls(ctx, cluster.Spec.Location)
		if listErr != nil {
			return result, listErr
		}
		firewall, err = uniqueFirewallByName(firewalls, firewallName(owner))
		if err != nil {
			return result, err
		}
		if firewall != nil {
			expectedDescription := "Managed K3s node firewall for " + owner
			// The live InSpace API currently returns a null/empty firewall
			// description even when it accepted one on create. Enforce it when
			// preserved, then fall back to the deterministic name, billing
			// account, and exact safe policy that the API does preserve.
			if (firewall.Description != "" && firewall.Description != expectedDescription) ||
				firewall.BillingAccountID != cluster.Spec.BillingAccountID {
				return result, errors.New("bootstrap: refusing to delete firewall without the expected ownership record")
			}
			network, networkErr := r.API.GetNetwork(ctx, cluster.Spec.Location, cluster.Spec.Network.UUID)
			if networkErr != nil {
				return result, networkErr
			}
			if policyErr := validateFirewallPolicy(firewall, network.Subnet, r.ManagementCIDR, r.ManagementTCPPorts); policyErr != nil {
				return result, fmt.Errorf("bootstrap: refusing to delete firewall with mismatched policy: %w", policyErr)
			}
			result.Remaining = append(result.Remaining, "firewall/"+firewall.EffectiveName())
		}
	}
	sort.Strings(result.Remaining)

	expectedAssignment := func(name string) (string, string) {
		expectedUUID := ""
		expectedType := ""
		if name == apiFloatingIPName(owner) {
			if lb != nil {
				expectedUUID, expectedType = lb.UUID, "load_balancer"
			}
		} else {
			for slot := 0; slot < ControlPlaneReplicas; slot++ {
				if name == nodeFloatingIPName(owner, slot) {
					if vm := ownedVMs[controlPlaneName(owner, slot)]; vm != nil {
						expectedUUID, expectedType = vm.UUID, "virtual_machine"
					}
					break
				}
			}
		}
		return expectedUUID, expectedType
	}
	// Validate every assignment before the first mutation. A later-owned name
	// must not reveal an ownership mismatch after an earlier resource changed.
	for _, name := range floatingNames {
		item := floatingByName[name]
		if item == nil || item.AssignedTo == "" {
			continue
		}
		expectedUUID, expectedType := expectedAssignment(name)
		if expectedUUID == "" || item.AssignedTo != expectedUUID || item.AssignedToResourceType != expectedType {
			return result, fmt.Errorf("bootstrap: refusing to unassign owned floating IP %s from unexpected %s %s", item.Address, item.AssignedToResourceType, item.AssignedTo)
		}
	}

	for _, name := range floatingNames {
		item := floatingByName[name]
		if item == nil {
			continue
		}
		if item.AssignedTo != "" {
			if _, err := r.API.UnassignFloatingIP(ctx, cluster.Spec.Location, item.Address); err != nil && !inspace.IsNotFound(err) {
				return result, err
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

	if lb != nil {
		if err := r.API.DeleteLoadBalancer(ctx, cluster.Spec.Location, lb.UUID); err != nil && !inspace.IsNotFound(err) {
			return result, err
		}
		result.Message = "deleted " + lb.DisplayName
		return result, nil
	}
	if len(vmNames) != 0 {
		vm := ownedVMs[vmNames[0]]
		if err := r.API.DeleteVM(ctx, cluster.Spec.Location, vm.UUID); err != nil && !inspace.IsNotFound(err) {
			return result, err
		}
		result.Message = "deleted " + vm.Name
		return result, nil
	}
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

	result.Done = true
	result.Message = "owned control-plane infrastructure is absent"
	return result, nil
}

// validateDestroyVMOwnership prevents deterministic-name collisions from
// becoming deletion authority. Destroy cannot recompute the full spec hash
// without the original K3s token, but it can require the versioned ownership
// record written by this controller and an exact control-plane slot name.
func validateDestroyVMOwnership(vms map[string]*inspace.VM, owner string) error {
	for name, vm := range vms {
		slot := -1
		for candidate := 0; candidate < ControlPlaneReplicas; candidate++ {
			if name == controlPlaneName(owner, candidate) {
				slot = candidate
				break
			}
		}
		if slot == -1 {
			return fmt.Errorf("bootstrap: refusing to delete VM %q outside the three owned control-plane slots", name)
		}
		prefix := fmt.Sprintf("inspace-k3s-cp/v1 owner=%s slot=%d spec=", owner, slot)
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

func (r *Reconciler) ensureFirewall(ctx context.Context, cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string) (*inspace.Firewall, error) {
	items, err := r.API.ListFirewalls(ctx, cluster.Spec.Location)
	if err != nil {
		return nil, err
	}
	if cluster.Spec.Firewall.UUID != "" {
		for i := range items {
			if items[i].UUID == cluster.Spec.Firewall.UUID {
				if err := validateFirewallPolicy(&items[i], network.Subnet, r.ManagementCIDR, r.ManagementTCPPorts); err != nil {
					return nil, err
				}
				return &items[i], nil
			}
		}
		return nil, errors.New("bootstrap: configured firewall UUID was not found")
	}
	name := firewallName(owner)
	found, err := uniqueFirewallByName(items, name)
	if err != nil {
		return nil, err
	}
	if found != nil {
		if err := validateFirewallPolicy(found, network.Subnet, r.ManagementCIDR, r.ManagementTCPPorts); err != nil {
			return nil, err
		}
		return found, nil
	}
	rules := managedFirewallRules(network.Subnet, r.ManagementCIDR, r.ManagementTCPPorts)
	created, err := r.API.CreateFirewall(ctx, cluster.Spec.Location, inspace.CreateFirewallRequest{
		DisplayName: name, Description: "Managed K3s node firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID, Rules: rules,
	})
	if err != nil {
		return nil, err
	}
	if err := validateFirewallPolicy(created, network.Subnet, r.ManagementCIDR, r.ManagementTCPPorts); err != nil {
		return nil, err
	}
	return created, nil
}

func (r *Reconciler) ensureNodeFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, owner string, slot int, vm *inspace.VM) (*inspace.FloatingIP, error) {
	name := nodeFloatingIPName(owner, slot)
	item, err := r.findFloatingIP(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		item, err = r.API.CreateFloatingIP(ctx, cluster.Spec.Location, inspace.CreateFloatingIPRequest{Name: name, BillingAccountID: cluster.Spec.BillingAccountID})
		if err != nil {
			return nil, err
		}
	}
	if item.AssignedTo != "" && (vm == nil || item.AssignedTo != vm.UUID || item.AssignedToResourceType != "virtual_machine") {
		return nil, fmt.Errorf("bootstrap: refusing to reassign floating IP %s from %s", item.Address, item.AssignedTo)
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
		if _, err := r.API.AssignFloatingIP(ctx, cluster.Spec.Location, floatingIP.Address, vm.UUID, "virtual_machine"); err != nil {
			readback, readErr := r.findFloatingIP(ctx, cluster, floatingIP.Name)
			if readErr != nil || readback == nil || readback.AssignedTo != vm.UUID || readback.AssignedToResourceType != "virtual_machine" {
				return false, err
			}
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

func (r *Reconciler) desiredControlPlaneVMRequest(cluster *v1alpha1.InSpaceCluster, network *inspace.Network, owner string, slot int, externalIP, joinAddress, apiPublicIPv4, token string) (inspace.CreateVMRequest, error) {
	tlsNames := append([]string{cluster.Spec.Endpoint.Host, joinAddress}, cluster.Spec.K3s.TLSSubjectAltNames...)
	if apiPublicIPv4 != "" {
		tlsNames = append(tlsNames, apiPublicIPv4)
	}
	cloudInit, err := RenderCloudInitJSON(CloudInitInput{
		NodeName: controlPlaneName(owner, slot), NodeExternalIPv4: externalIP, PrivateSubnet: network.Subnet,
		K3sVersion: cluster.Spec.K3s.Version, K3sToken: token, ClusterInit: slot == 0, ServerAddress: joinAddress,
		PodCIDR: cluster.Spec.Network.PodCIDR, ServiceCIDR: cluster.Spec.Network.ServiceCIDR,
		TLSSubjectAltNames: tlsNames, Disable: cluster.Spec.K3s.Disable,
		ManagementCIDR: r.ManagementCIDR, ManagementTCPPorts: r.ManagementTCPPorts,
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
	request.Description = fmt.Sprintf("inspace-k3s-cp/v1 owner=%s slot=%d spec=%s", owner, slot, hex.EncodeToString(sum[:]))
	return request, nil
}

func validateOwnedVM(vm *inspace.VM, desired inspace.CreateVMRequest, network *inspace.Network) error {
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

func (r *Reconciler) ensureAPILoadBalancer(ctx context.Context, cluster *v1alpha1.InSpaceCluster, owner string) (*inspace.LoadBalancer, error) {
	name := apiLoadBalancerName(owner)
	lb, err := r.findLoadBalancer(ctx, cluster.Spec.Location, name)
	if err != nil {
		return nil, err
	}
	if lb != nil {
		if lb.NetworkUUID != cluster.Spec.Network.UUID || len(lb.ForwardingRules) != 1 || lb.ForwardingRules[0].SourcePort != 6443 || lb.ForwardingRules[0].TargetPort != 6443 || (lb.ForwardingRules[0].Protocol != "" && lb.ForwardingRules[0].Protocol != "TCP") {
			return nil, errors.New("bootstrap: owned API load balancer has an unsafe or unexpected configuration")
		}
		return lb, nil
	}
	return r.API.CreateLoadBalancer(ctx, cluster.Spec.Location, inspace.CreateLoadBalancerRequest{
		DisplayName: name, BillingAccountID: cluster.Spec.BillingAccountID, NetworkUUID: cluster.Spec.Network.UUID,
		ReservePublicIP: false,
		Rules:           []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 6443, TargetPort: 6443}},
		Targets:         []inspace.LoadBalancerTarget{},
	})
}

func (r *Reconciler) ensureAPIFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, owner string, lb *inspace.LoadBalancer) (*inspace.FloatingIP, error) {
	name := apiFloatingIPName(owner)
	item, err := r.findFloatingIP(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		item, err = r.API.CreateFloatingIP(ctx, cluster.Spec.Location, inspace.CreateFloatingIPRequest{Name: name, BillingAccountID: cluster.Spec.BillingAccountID})
		if err != nil {
			return nil, err
		}
	}
	if item.AssignedTo != "" && (item.AssignedTo != lb.UUID || item.AssignedToResourceType != "load_balancer") {
		return nil, fmt.Errorf("bootstrap: refusing to reassign API floating IP %s", item.Address)
	}
	if item.AssignedTo == "" {
		item, err = r.API.AssignFloatingIP(ctx, cluster.Spec.Location, item.Address, lb.UUID, "load_balancer")
	}
	return item, err
}

func (r *Reconciler) findFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, name string) (*inspace.FloatingIP, error) {
	items, err := r.API.ListFloatingIPs(ctx, cluster.Spec.Location, &inspace.FloatingIPFilters{BillingAccountID: cluster.Spec.BillingAccountID})
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
	return found, nil
}

func (r *Reconciler) findLoadBalancer(ctx context.Context, location, name string) (*inspace.LoadBalancer, error) {
	items, err := r.API.ListLoadBalancers(ctx, location)
	if err != nil {
		return nil, err
	}
	var found *inspace.LoadBalancer
	for i := range items {
		if items[i].DisplayName != name || items[i].IsDeleted {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: duplicate owned load balancer name %q", name)
		}
		found = &items[i]
	}
	return found, nil
}

func managedFirewallRules(subnet, managementCIDR string, managementTCPPorts []int) []inspace.FirewallRule {
	result := make([]inspace.FirewallRule, 0, 6+len(managementTCPPorts))
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		result = append(result, inspace.FirewallRule{Protocol: protocol, Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{subnet}})
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

func validateFirewallPolicy(firewall *inspace.Firewall, subnet, managementCIDR string, managementTCPPorts []int) error {
	if firewall == nil {
		return errors.New("bootstrap: firewall is required")
	}
	if err := validateManagementAccess(managementCIDR, managementTCPPorts); err != nil {
		return err
	}
	network, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("bootstrap: parse private subnet: %w", err)
	}
	inbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	outbound := map[string]bool{"tcp": false, "udp": false, "icmp": false}
	allowedManagementPorts := make(map[int32]bool, len(managementTCPPorts))
	seenManagementPorts := make(map[int32]bool, len(managementTCPPorts))
	for _, port := range managementTCPPorts {
		allowedManagementPorts[int32(port)] = true
	}
	for _, rule := range firewall.Rules {
		if _, ok := inbound[rule.Protocol]; !ok {
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
			for _, raw := range rule.EndpointSpec {
				prefix, parseErr := netip.ParsePrefix(raw)
				if parseErr != nil {
					address, addrErr := netip.ParseAddr(raw)
					if addrErr != nil || !address.IsPrivate() || !network.Contains(address) {
						return errors.New("bootstrap: inbound firewall endpoint escapes the configured private network")
					}
					continue
				}
				if !prefix.Addr().IsPrivate() || !network.Contains(prefix.Addr()) || prefix.Bits() < network.Bits() {
					return errors.New("bootstrap: inbound firewall prefix escapes the configured private network")
				}
				if prefix.Masked() == network.Masked() && prefix.Bits() == network.Bits() {
					coversNetwork = true
				}
			}
			if coversNetwork {
				inbound[rule.Protocol] = true
			}
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
		if !inbound[protocol] || !outbound[protocol] {
			return fmt.Errorf("bootstrap: firewall lacks safe inbound/private and outbound/any %s rules", protocol)
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
	if err != nil || !prefix.Addr().IsPrivate() {
		return fmt.Errorf("bootstrap: network subnet %q must be a private CIDR", value)
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

func controlPlaneName(owner string, slot int) string { return fmt.Sprintf("k3s-%s-cp-%d", owner, slot) }
func firewallName(owner string) string               { return "k3s-" + owner + "-nodes" }
func apiLoadBalancerName(owner string) string        { return "k3s-" + owner + "-api" }
func apiFloatingIPName(owner string) string          { return "k3s-" + owner + "-api-ip" }
func nodeFloatingIPName(owner string, slot int) string {
	return fmt.Sprintf("k3s-%s-cp-%d-ip", owner, slot)
}

func uniqueVMsByName(vms []inspace.VM, ownedPrefix string) (map[string]*inspace.VM, error) {
	result := make(map[string]*inspace.VM, len(vms))
	for i := range vms {
		if !strings.HasPrefix(vms[i].Name, ownedPrefix) {
			continue
		}
		if _, exists := result[vms[i].Name]; exists {
			return nil, fmt.Errorf("bootstrap: duplicate VM name %q", vms[i].Name)
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

func hasTarget(lb *inspace.LoadBalancer, uuid string) bool {
	for _, target := range lb.Targets {
		if target.TargetUUID == uuid {
			return true
		}
	}
	return false
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
	return Result{RequeueAfter: 20 * time.Second, ControlPlaneVMs: ids, Message: message}
}
