// Package cloudprovider implements the Kubernetes external cloud-provider
// contracts for InSpace Cloud.
package cloudprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	cloud "k8s.io/cloud-provider"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	ProviderName = "inspace"

	AnnotationPublicLoadBalancer = "service.beta.kubernetes.io/inspace-load-balancer-public"
	LabelLoadBalancerScope       = "inspace.cloud/load-balancer-scope"
	LoadBalancerScopePublic      = "public"
	LoadBalancerScopePrivate     = "private"
)

// API is the exact SDK surface used by the CCM and permits loopback-only
// contract tests without network access.
type API interface {
	ListVMs(context.Context, string) ([]inspace.VM, error)
	GetVM(context.Context, string, string) (*inspace.VM, error)
	ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error)
	CreateLoadBalancer(context.Context, string, inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error)
	DeleteLoadBalancer(context.Context, string, string) error
	AddLoadBalancerTarget(context.Context, string, string, string) (*inspace.LoadBalancerTarget, error)
	RemoveLoadBalancerTarget(context.Context, string, string, string) error
	AddLoadBalancerRule(context.Context, string, string, inspace.LoadBalancerRule) (*inspace.LoadBalancerRule, error)
	RemoveLoadBalancerRule(context.Context, string, string, string) error
	ListFloatingIPs(context.Context, string, *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error)
	CreateFloatingIP(context.Context, string, inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error)
	AssignFloatingIP(context.Context, string, string, string, string) (*inspace.FloatingIP, error)
	UnassignFloatingIP(context.Context, string, string) (*inspace.FloatingIP, error)
	DeleteFloatingIP(context.Context, string, string) error
}

type Config struct {
	Location                     string
	Region                       string
	NetworkUUID                  string
	BillingAccountID             int64
	ClusterID                    string
	ControlPlaneVIP              string
	PrivateLoadBalancerPoolStart string
	PrivateLoadBalancerPoolStop  string
}

type Provider struct {
	api                          API
	config                       Config
	controlPlaneVIP              netip.Addr
	privateLoadBalancerPoolStart netip.Addr
	privateLoadBalancerPoolStop  netip.Addr
}

func New(api API, config Config) (*Provider, error) {
	if api == nil {
		return nil, errors.New("cloudprovider: API client is required")
	}
	if strings.TrimSpace(config.Location) == "" {
		return nil, errors.New("cloudprovider: location is required")
	}
	if strings.TrimSpace(config.NetworkUUID) == "" {
		return nil, errors.New("cloudprovider: network UUID is required")
	}
	if strings.TrimSpace(config.ClusterID) == "" {
		return nil, errors.New("cloudprovider: cluster ID is required")
	}
	if config.Region == "" {
		config.Region = config.Location
	}
	poolStart, poolStop, err := parsePrivateLoadBalancerPool(config.PrivateLoadBalancerPoolStart, config.PrivateLoadBalancerPoolStop)
	if err != nil {
		return nil, err
	}
	controlPlaneVIP, err := parseControlPlaneVIP(config.ControlPlaneVIP)
	if err != nil {
		return nil, err
	}
	if poolStart.Compare(controlPlaneVIP) <= 0 && controlPlaneVIP.Compare(poolStop) <= 0 {
		return nil, errors.New("cloudprovider: control-plane VIP must not overlap the private load-balancer pool")
	}
	return &Provider{
		api: api, config: config, controlPlaneVIP: controlPlaneVIP,
		privateLoadBalancerPoolStart: poolStart, privateLoadBalancerPoolStop: poolStop,
	}, nil
}

func parseControlPlaneVIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != value {
		return netip.Addr{}, errors.New("cloudprovider: control-plane VIP must be a canonical RFC1918 IPv4 address")
	}
	for _, reserved := range fixedClusterCIDRs() {
		if reserved.Contains(address) {
			return netip.Addr{}, fmt.Errorf("cloudprovider: control-plane VIP must not overlap fixed cluster CIDR %s", reserved)
		}
	}
	return address, nil
}

func parsePrivateLoadBalancerPool(startValue, stopValue string) (netip.Addr, netip.Addr, error) {
	start, startErr := netip.ParseAddr(startValue)
	stop, stopErr := netip.ParseAddr(stopValue)
	if startErr != nil || stopErr != nil || !start.Is4() || !stop.Is4() || !start.IsPrivate() || !stop.IsPrivate() ||
		start.String() != startValue || stop.String() != stopValue {
		return netip.Addr{}, netip.Addr{}, errors.New("cloudprovider: private load-balancer pool start/stop must be canonical RFC1918 IPv4 addresses")
	}
	if start.Compare(stop) > 0 {
		return netip.Addr{}, netip.Addr{}, errors.New("cloudprovider: private load-balancer pool start must be less than or equal to stop")
	}
	count := uint64(cloudIPv4Value(stop)-cloudIPv4Value(start)) + 1
	if count < v1alpha1.PrivateLoadBalancerPoolMinAddresses || count > v1alpha1.PrivateLoadBalancerPoolMaxAddresses {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("cloudprovider: private load-balancer pool must contain between %d and %d addresses", v1alpha1.PrivateLoadBalancerPoolMinAddresses, v1alpha1.PrivateLoadBalancerPoolMaxAddresses)
	}
	for _, reserved := range fixedClusterCIDRs() {
		if cloudIPv4RangeOverlapsPrefix(start, stop, reserved) {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("cloudprovider: private load-balancer pool must not overlap fixed cluster CIDR %s", reserved)
		}
	}
	return start, stop, nil
}

func fixedClusterCIDRs() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix(v1alpha1.CiliumNativeRoutingPodCIDR),
		netip.MustParsePrefix(v1alpha1.KubernetesServiceCIDR),
	}
}

func cloudIPv4RangeOverlapsPrefix(start, stop netip.Addr, prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	prefixStart := cloudIPv4Value(prefix.Addr())
	prefixStop := prefixStart | (^uint32(0) >> prefix.Bits())
	return cloudIPv4Value(start) <= prefixStop && prefixStart <= cloudIPv4Value(stop)
}

func cloudIPv4Value(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func (p *Provider) Initialize(cloud.ControllerClientBuilder, <-chan struct{}) {}
func (p *Provider) ProviderName() string                                      { return ProviderName }
func (p *Provider) HasClusterID() bool                                        { return p.config.ClusterID != "" }
func (p *Provider) Instances() (cloud.Instances, bool)                        { return nil, false }
func (p *Provider) InstancesV2() (cloud.InstancesV2, bool)                    { return p, true }
func (p *Provider) LoadBalancer() (cloud.LoadBalancer, bool)                  { return p, true }
func (p *Provider) Zones() (cloud.Zones, bool)                                { return nil, false }
func (p *Provider) Clusters() (cloud.Clusters, bool)                          { return nil, false }
func (p *Provider) Routes() (cloud.Routes, bool)                              { return nil, false }

func (p *Provider) InstanceExists(ctx context.Context, node *corev1.Node) (bool, error) {
	_, err := p.resolveVM(ctx, node)
	if inspace.IsNotFound(err) || errors.Is(err, cloud.InstanceNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (p *Provider) InstanceShutdown(ctx context.Context, node *corev1.Node) (bool, error) {
	vm, err := p.resolveVM(ctx, node)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(vm.Status) {
	case "stopped", "shutoff", "shutdown", "deleted":
		return true, nil
	default:
		return false, nil
	}
}

func (p *Provider) InstanceMetadata(ctx context.Context, node *corev1.Node) (*cloud.InstanceMetadata, error) {
	vm, err := p.resolveVM(ctx, node)
	if err != nil {
		return nil, err
	}
	location := p.config.Location
	if node.Spec.ProviderID != "" {
		id, parseErr := providerid.Parse(node.Spec.ProviderID)
		if parseErr == nil {
			location = id.Location
		}
	}
	id, err := providerid.New(location, vm.UUID)
	if err != nil {
		return nil, err
	}
	addresses := make([]corev1.NodeAddress, 0, 4)
	if vm.PrivateIPv4 != "" {
		addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: vm.PrivateIPv4})
	}
	externalIPv4, err := p.externalIPv4ForVM(ctx, location, vm)
	if err != nil {
		return nil, err
	}
	if externalIPv4 != "" {
		addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: externalIPv4})
	}
	if vm.PublicIPv6 != "" {
		addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: vm.PublicIPv6})
	}
	if vm.Hostname != "" {
		addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeHostName, Address: vm.Hostname})
	}
	return &cloud.InstanceMetadata{
		ProviderID:    id,
		InstanceType:  instanceTypeForVM(vm),
		NodeAddresses: addresses,
		Zone:          location,
		Region:        p.config.Region,
	}, nil
}

// instanceTypeForVM preserves the Karpenter catalog identity written into the
// provider-owned VM description. This keeps CCM's cloud-node-controller from
// replacing node.kubernetes.io/instance-type with a generic capacity string.
// Non-Karpenter VMs and malformed/untrusted descriptions use a safe fallback.
func instanceTypeForVM(vm *inspace.VM) string {
	fallback := fmt.Sprintf("inspace-%dc-%dmib", vm.VCPU, vm.MemoryMiB)
	var record struct {
		Schema       string `json:"schema"`
		InstanceType string `json:"instanceType"`
	}
	if json.Unmarshal([]byte(vm.Description), &record) != nil ||
		(record.Schema != "karpenter.inspace.cloud/v1" && record.Schema != "karpenter.inspace.cloud/v2") {
		return fallback
	}
	if record.InstanceType == "" || len(utilvalidation.IsValidLabelValue(record.InstanceType)) != 0 {
		return fallback
	}
	return record.InstanceType
}

func (p *Provider) externalIPv4ForVM(ctx context.Context, location string, vm *inspace.VM) (string, error) {
	items, err := p.api.ListFloatingIPs(ctx, location, &inspace.FloatingIPFilters{VMUUID: vm.UUID})
	if err != nil {
		return "", err
	}
	address := ""
	for _, item := range items {
		if item.IsDeleted || item.AssignedTo != vm.UUID || item.AssignedToResourceType != "virtual_machine" {
			continue
		}
		if net.ParseIP(item.Address) == nil {
			return "", fmt.Errorf("cloudprovider: floating IP %q is invalid", item.Address)
		}
		if address != "" && address != item.Address {
			return "", fmt.Errorf("cloudprovider: VM %s has multiple assigned floating IPv4 addresses", vm.UUID)
		}
		address = item.Address
	}
	if address != "" {
		return address, nil
	}
	return vm.PublicIPv4, nil
}

func (p *Provider) resolveVM(ctx context.Context, node *corev1.Node) (*inspace.VM, error) {
	if node == nil {
		return nil, cloud.InstanceNotFound
	}
	if node.Spec.ProviderID != "" {
		id, err := providerid.Parse(node.Spec.ProviderID)
		if err != nil {
			return nil, fmt.Errorf("cloudprovider: parse provider ID: %w", err)
		}
		return p.api.GetVM(ctx, id.Location, id.UUID)
	}
	vms, err := p.api.ListVMs(ctx, p.config.Location)
	if err != nil {
		return nil, err
	}
	var matches []*inspace.VM
	for i := range vms {
		if vms[i].Name == node.Name || vms[i].Hostname == node.Name {
			matches = append(matches, &vms[i])
		}
	}
	if len(matches) == 0 {
		return nil, cloud.InstanceNotFound
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("cloudprovider: node name %q matches %d VMs", node.Name, len(matches))
	}
	return matches[0], nil
}

func (p *Provider) GetLoadBalancerName(_ context.Context, _ string, service *corev1.Service) string {
	if service == nil {
		return ""
	}
	return p.loadBalancerName(service)
}

func (p *Provider) loadBalancerName(service *corev1.Service) string {
	serviceID := string(service.UID)
	if serviceID == "" {
		serviceID = service.Namespace + "/" + service.Name
	}
	clusterHash := shortHash(p.config.ClusterID)
	serviceHash := shortHash(serviceID)
	return "k8s-" + clusterHash + "-" + serviceHash
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func (p *Provider) GetLoadBalancer(ctx context.Context, _ string, service *corev1.Service) (*corev1.LoadBalancerStatus, bool, error) {
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return nil, false, err
	}
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil {
		return nil, lb != nil, err
	}
	if lb == nil && floatingIP == nil {
		return nil, false, nil
	}
	if lb == nil {
		return nil, true, errors.New("cloudprovider: deterministically owned floating IP exists without its load balancer")
	}
	if lb.NetworkUUID != p.config.NetworkUUID {
		return nil, true, fmt.Errorf("cloudprovider: refusing to report owned load balancer %q on network %q", lb.DisplayName, lb.NetworkUUID)
	}
	publicAddress := ""
	if floatingIP != nil {
		if err := validateServiceFloatingIPAssignment(floatingIP, lb.UUID, lb.PrivateAddress); err != nil {
			return nil, true, errors.New("cloudprovider: owned load balancer floating IP has an unexpected assignment")
		}
		publicAddress = floatingIP.Address
	}
	status, err := statusForLoadBalancer(lb, publicAddress)
	return status, true, err
}

func (p *Provider) GetLoadBalancerNameForService(service *corev1.Service) string {
	return p.loadBalancerName(service)
}

func (p *Provider) EnsureLoadBalancer(ctx context.Context, _ string, service *corev1.Service, nodes []*corev1.Node) (*corev1.LoadBalancerStatus, error) {
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return nil, err
	}
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil {
		return nil, err
	}
	explicitPublic, markerErr := explicitPublicRequested(service)
	if markerErr != nil {
		return nil, markerErr
	}
	if !explicitPublic {
		if lb == nil && floatingIP == nil {
			return nil, cloud.ImplementedElsewhere
		}
		if err := p.cleanupOwnedLoadBalancer(ctx, service, lb); err != nil {
			return nil, err
		}
		return &corev1.LoadBalancerStatus{}, nil
	}
	if err := validateServiceFloatingIPState(floatingIP, lb); err != nil {
		return nil, err
	}
	if lb != nil {
		if err := p.validatePublicLoadBalancerAddress(ctx, service, lb); err != nil {
			return nil, err
		}
	}
	if err := validateService(service); err != nil {
		return nil, err
	}
	if p.config.BillingAccountID < 1 {
		return nil, errors.New("cloudprovider: public load balancer requires INSPACE_BILLING_ACCOUNT_ID")
	}
	targets, err := targetUUIDs(nodes, p.config.Location)
	if err != nil {
		return nil, err
	}
	rules := serviceRules(service)
	created := false
	if lb == nil {
		request := inspace.CreateLoadBalancerRequest{
			DisplayName:      p.loadBalancerName(service),
			BillingAccountID: p.config.BillingAccountID,
			NetworkUUID:      p.config.NetworkUUID,
			ReservePublicIP:  false,
			Rules:            rules,
			Targets:          make([]inspace.LoadBalancerTarget, 0, len(targets)),
		}
		for _, uuid := range targets {
			request.Targets = append(request.Targets, inspace.LoadBalancerTarget{TargetUUID: uuid, TargetType: "vm"})
		}
		// The SDK has no automatic retry. If the response is lost after creation,
		// the next Service reconciliation lists and adopts this deterministic name.
		lb, err = p.api.CreateLoadBalancer(ctx, p.config.Location, request)
		if err != nil {
			return nil, err
		}
		created = true
	}
	if created {
		if err := p.validatePublicLoadBalancerAddress(ctx, service, lb); err != nil {
			return nil, err
		}
	}
	if !created {
		if err := p.reconcileLoadBalancer(ctx, lb, targets, rules); err != nil {
			return nil, err
		}
	}
	floatingIP, err = p.ensurePublicFloatingIP(ctx, service, lb)
	if err != nil {
		return nil, err
	}
	return statusForLoadBalancer(lb, floatingIP.Address)
}

func (p *Provider) UpdateLoadBalancer(ctx context.Context, _ string, service *corev1.Service, nodes []*corev1.Node) error {
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return err
	}
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil {
		return err
	}
	explicitPublic, markerErr := explicitPublicRequested(service)
	if markerErr != nil {
		return markerErr
	}
	if !explicitPublic {
		if lb == nil && floatingIP == nil {
			return cloud.ImplementedElsewhere
		}
		return p.cleanupOwnedLoadBalancer(ctx, service, lb)
	}
	if err := validateServiceFloatingIPState(floatingIP, lb); err != nil {
		return err
	}
	if lb == nil {
		return errors.New("cloudprovider: managed public load balancer does not exist")
	}
	if err := p.validatePublicLoadBalancerAddress(ctx, service, lb); err != nil {
		return err
	}
	if err := validateService(service); err != nil {
		return err
	}
	targets, err := targetUUIDs(nodes, p.config.Location)
	if err != nil {
		return err
	}
	if err := p.reconcileLoadBalancer(ctx, lb, targets, serviceRules(service)); err != nil {
		return err
	}
	_, err = p.ensurePublicFloatingIP(ctx, service, lb)
	return err
}

func (p *Provider) EnsureLoadBalancerDeleted(ctx context.Context, _ string, service *corev1.Service) error {
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return err
	}
	return p.cleanupOwnedLoadBalancer(ctx, service, lb)
}

func (p *Provider) cleanupOwnedLoadBalancer(ctx context.Context, service *corev1.Service, lb *inspace.LoadBalancer) error {
	expectedLoadBalancerUUID := ""
	expectedLoadBalancerPrivateAddress := ""
	if lb != nil {
		// Recheck the authoritative VPC identity at the mutation boundary. Discovery
		// normally enforces this first, but cleanup must never rely on a caller to
		// protect a same-name load balancer belonging to another network.
		if err := p.validateOwnedLoadBalancerIdentity(service, lb); err != nil {
			return err
		}
		expectedLoadBalancerUUID = lb.UUID
		expectedLoadBalancerPrivateAddress = lb.PrivateAddress
	}
	if err := p.cleanupOwnedFloatingIP(ctx, service, expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress); err != nil {
		return err
	}
	if lb == nil {
		return nil
	}
	err := p.api.DeleteLoadBalancer(ctx, p.config.Location, lb.UUID)
	if inspace.IsNotFound(err) {
		return nil
	}
	return err
}

func (p *Provider) validatePublicLoadBalancerAddress(ctx context.Context, service *corev1.Service, lb *inspace.LoadBalancer) error {
	if err := p.validateOwnedLoadBalancerIdentity(service, lb); err != nil {
		return err
	}
	address, err := netip.ParseAddr(strings.TrimSpace(lb.PrivateAddress))
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return errors.New("cloudprovider: load balancer private IPv4 is not ready")
	}
	collisionTarget := ""
	if address == p.controlPlaneVIP {
		collisionTarget = "reserved RKE2 control-plane VIP"
	} else if p.privateLoadBalancerPoolStart.Compare(address) <= 0 && address.Compare(p.privateLoadBalancerPoolStop) <= 0 {
		collisionTarget = "reserved Cilium private load-balancer pool"
	}
	if collisionTarget != "" {
		collisionErr := fmt.Errorf("cloudprovider: owned public load balancer %q private address %s collides with the %s", lb.DisplayName, address, collisionTarget)
		cleanupErr := p.cleanupOwnedLoadBalancer(ctx, service, lb)
		return errors.Join(collisionErr, cleanupErr)
	}
	return nil
}

func (p *Provider) cleanupOwnedFloatingIP(ctx context.Context, service *corev1.Service, expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress string) error {
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil || floatingIP == nil {
		return err
	}
	if floatingIP.AssignedTo != "" {
		if err := validateServiceFloatingIPAssignment(floatingIP, expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress); err != nil {
			return err
		}
		unassigned, unassignErr := p.api.UnassignFloatingIP(ctx, p.config.Location, floatingIP.Address)
		if unassignErr != nil && !inspace.IsNotFound(unassignErr) {
			return unassignErr
		}
		if unassignErr == nil {
			if err := p.validateServiceFloatingIPIdentity(unassigned, service); err != nil {
				return err
			}
			if err := validateServiceFloatingIPUnassigned(unassigned); err != nil {
				return err
			}
		}
	} else if err := validateServiceFloatingIPUnassigned(floatingIP); err != nil {
		return err
	}
	if err := p.api.DeleteFloatingIP(ctx, p.config.Location, floatingIP.Address); err != nil && !inspace.IsNotFound(err) {
		return err
	}
	return nil
}

func (p *Provider) floatingIPName(service *corev1.Service) string {
	return p.loadBalancerName(service) + "-ip"
}

func (p *Provider) findOwnedFloatingIP(ctx context.Context, service *corev1.Service) (*inspace.FloatingIP, error) {
	items, err := p.api.ListFloatingIPs(ctx, p.config.Location, nil)
	if err != nil {
		return nil, err
	}
	name := p.floatingIPName(service)
	var found *inspace.FloatingIP
	for i := range items {
		// InSpace retains soft-deleted rows in list responses. They no longer
		// represent mutable ownership and must not block recreation with the same
		// deterministic Service name.
		if items[i].Name != name || items[i].IsDeleted {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("cloudprovider: multiple floating IPs have ownership name %q", name)
		}
		if err := p.validateServiceFloatingIPIdentity(&items[i], service); err != nil {
			return nil, err
		}
		found = &items[i]
	}
	return found, nil
}

func (p *Provider) ensurePublicFloatingIP(ctx context.Context, service *corev1.Service, loadBalancer *inspace.LoadBalancer) (*inspace.FloatingIP, error) {
	if p.config.BillingAccountID < 1 {
		return nil, errors.New("cloudprovider: public load balancer requires INSPACE_BILLING_ACCOUNT_ID")
	}
	if loadBalancer == nil || loadBalancer.UUID == "" {
		return nil, errors.New("cloudprovider: public load balancer lacks a stable UUID")
	}
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil {
		return nil, err
	}
	if floatingIP == nil {
		floatingIP, err = p.api.CreateFloatingIP(ctx, p.config.Location, inspace.CreateFloatingIPRequest{
			Name: p.floatingIPName(service), BillingAccountID: p.config.BillingAccountID,
		})
		if err != nil {
			return nil, err
		}
		if err := p.validateServiceFloatingIPIdentity(floatingIP, service); err != nil {
			return nil, err
		}
		if err := validateServiceFloatingIPUnassigned(floatingIP); err != nil {
			return nil, err
		}
	}
	if floatingIP.AssignedTo != "" {
		if err := validateServiceFloatingIPAssignment(floatingIP, loadBalancer.UUID, loadBalancer.PrivateAddress); err != nil {
			return nil, err
		}
		return floatingIP, nil
	}
	if err := validateServiceFloatingIPUnassigned(floatingIP); err != nil {
		return nil, err
	}
	floatingIP, err = p.api.AssignFloatingIP(ctx, p.config.Location, floatingIP.Address, loadBalancer.UUID, "load_balancer")
	if err != nil {
		return nil, err
	}
	if err := p.validateServiceFloatingIPIdentity(floatingIP, service); err != nil {
		return nil, err
	}
	if err := validateServiceFloatingIPAssignment(floatingIP, loadBalancer.UUID, loadBalancer.PrivateAddress); err != nil {
		return nil, err
	}
	return floatingIP, nil
}

func (p *Provider) validateServiceFloatingIPIdentity(item *inspace.FloatingIP, service *corev1.Service) error {
	if item == nil {
		return errors.New("cloudprovider: owned Service floating IP returned an empty response")
	}
	expectedName := p.floatingIPName(service)
	if item.Name != expectedName || item.BillingAccountID != p.config.BillingAccountID {
		return fmt.Errorf("cloudprovider: floating IP %q lacks the expected Service ownership name or billing account", expectedName)
	}
	if !item.Enabled || item.IsDeleted || item.IsVirtual || item.Type != "public" {
		return fmt.Errorf("cloudprovider: floating IP %q must be enabled, active, non-virtual, and type public", expectedName)
	}
	address, err := netip.ParseAddr(item.Address)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != item.Address {
		return fmt.Errorf("cloudprovider: floating IP %q must contain one canonical global public IPv4 address", expectedName)
	}
	return nil
}

func validateServiceFloatingIPUnassigned(item *inspace.FloatingIP) error {
	if item.AssignedTo != "" || item.AssignedToResourceType != "" || item.AssignedToPrivateIP != "" {
		return errors.New("cloudprovider: owned Service floating IP has residual or unexpected assignment metadata")
	}
	return nil
}

func validateServiceFloatingIPAssignment(item *inspace.FloatingIP, loadBalancerUUID, loadBalancerPrivateAddress string) error {
	if loadBalancerUUID == "" || item.AssignedTo != loadBalancerUUID || item.AssignedToResourceType != "load_balancer" {
		return fmt.Errorf("cloudprovider: owned Service floating IP is not assigned to the exact owned NLB %s", loadBalancerUUID)
	}
	if item.AssignedToPrivateIP != "" && item.AssignedToPrivateIP != loadBalancerPrivateAddress {
		return fmt.Errorf("cloudprovider: owned Service floating IP assignment private IPv4 does not match the exact owned NLB %s", loadBalancerUUID)
	}
	return nil
}

func validateServiceFloatingIPState(item *inspace.FloatingIP, loadBalancer *inspace.LoadBalancer) error {
	if item == nil {
		return nil
	}
	if item.AssignedTo == "" {
		return validateServiceFloatingIPUnassigned(item)
	}
	if loadBalancer == nil {
		return errors.New("cloudprovider: owned Service floating IP is assigned while its deterministic NLB is absent")
	}
	return validateServiceFloatingIPAssignment(item, loadBalancer.UUID, loadBalancer.PrivateAddress)
}

func (p *Provider) findOwnedLoadBalancer(ctx context.Context, service *corev1.Service) (*inspace.LoadBalancer, error) {
	if service == nil {
		return nil, errors.New("cloudprovider: service is required")
	}
	lbs, err := p.api.ListLoadBalancers(ctx, p.config.Location)
	if err != nil {
		return nil, err
	}
	name := p.loadBalancerName(service)
	var found *inspace.LoadBalancer
	for i := range lbs {
		if lbs[i].DisplayName != name || lbs[i].IsDeleted {
			continue
		}
		if err := p.validateOwnedLoadBalancerIdentity(service, &lbs[i]); err != nil {
			return nil, err
		}
		if found != nil {
			return nil, fmt.Errorf("cloudprovider: multiple load balancers have ownership name %q", name)
		}
		found = &lbs[i]
	}
	return found, nil
}

func (p *Provider) validateOwnedLoadBalancerIdentity(service *corev1.Service, lb *inspace.LoadBalancer) error {
	if service == nil {
		return errors.New("cloudprovider: service is required")
	}
	if lb == nil {
		return errors.New("cloudprovider: owned load balancer response is empty")
	}
	expectedName := p.loadBalancerName(service)
	if lb.DisplayName != expectedName {
		return fmt.Errorf("cloudprovider: load balancer %q lacks deterministic ownership name %q", lb.DisplayName, expectedName)
	}
	if lb.NetworkUUID != p.config.NetworkUUID {
		return fmt.Errorf("cloudprovider: load balancer ownership name %q exists on network %q, not configured network %q", expectedName, lb.NetworkUUID, p.config.NetworkUUID)
	}
	if lb.IsDeleted {
		return fmt.Errorf("cloudprovider: load balancer ownership name %q is deleted", expectedName)
	}
	if strings.TrimSpace(lb.UUID) == "" {
		return fmt.Errorf("cloudprovider: load balancer ownership name %q has no stable UUID", expectedName)
	}
	return nil
}

func (p *Provider) reconcileLoadBalancer(ctx context.Context, lb *inspace.LoadBalancer, targetUUIDs []string, rules []inspace.LoadBalancerRule) error {
	desiredTargets := make(map[string]struct{}, len(targetUUIDs))
	for _, uuid := range targetUUIDs {
		desiredTargets[uuid] = struct{}{}
	}
	currentTargets := make(map[string]struct{}, len(lb.Targets))
	for _, target := range lb.Targets {
		currentTargets[target.TargetUUID] = struct{}{}
		if _, wanted := desiredTargets[target.TargetUUID]; !wanted {
			if err := p.api.RemoveLoadBalancerTarget(ctx, p.config.Location, lb.UUID, target.TargetUUID); err != nil && !inspace.IsNotFound(err) {
				return err
			}
		}
	}
	for _, uuid := range targetUUIDs {
		if _, exists := currentTargets[uuid]; !exists {
			if _, err := p.api.AddLoadBalancerTarget(ctx, p.config.Location, lb.UUID, uuid); err != nil {
				return err
			}
		}
	}

	desiredRules := make(map[int32]inspace.LoadBalancerRule, len(rules))
	for _, rule := range rules {
		desiredRules[rule.SourcePort] = rule
	}
	currentRules := make(map[int32]inspace.LoadBalancerRule, len(lb.ForwardingRules))
	for _, current := range lb.ForwardingRules {
		currentRules[current.SourcePort] = current
		desired, wanted := desiredRules[current.SourcePort]
		if !wanted || desired.TargetPort != current.TargetPort || (current.Protocol != "" && current.Protocol != "TCP") {
			if current.UUID == "" {
				return fmt.Errorf("cloudprovider: forwarding rule on port %d has no UUID", current.SourcePort)
			}
			if err := p.api.RemoveLoadBalancerRule(ctx, p.config.Location, lb.UUID, current.UUID); err != nil && !inspace.IsNotFound(err) {
				return err
			}
			delete(currentRules, current.SourcePort)
		}
	}
	for _, desired := range rules {
		if current, exists := currentRules[desired.SourcePort]; exists && current.TargetPort == desired.TargetPort {
			continue
		}
		if _, err := p.api.AddLoadBalancerRule(ctx, p.config.Location, lb.UUID, desired); err != nil {
			return err
		}
	}
	return nil
}

func validateService(service *corev1.Service) error {
	if service == nil {
		return errors.New("cloudprovider: service is required")
	}
	if len(service.Spec.LoadBalancerSourceRanges) != 0 {
		return errors.New("cloudprovider: loadBalancerSourceRanges is unsupported; InSpace NLB exposes TCP forwarding only")
	}
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		return errors.New("cloudprovider: externalTrafficPolicy=Local is unsupported because InSpace NLB has no Kubernetes endpoint health filtering")
	}
	explicitPublic, err := explicitPublicRequested(service)
	if err != nil {
		return err
	}
	if !explicitPublic {
		return errors.New("cloudprovider: InSpace NLB requires the public scope label and public=true annotation")
	}
	for _, port := range service.Spec.Ports {
		if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
			return fmt.Errorf("cloudprovider: InSpace NLB supports TCP only, got %s on service port %d", port.Protocol, port.Port)
		}
		if port.Port < 1 || port.NodePort < 1 {
			return fmt.Errorf("cloudprovider: service port %d requires a nodePort", port.Port)
		}
	}
	if len(service.Spec.Ports) == 0 {
		return errors.New("cloudprovider: service must expose at least one TCP port")
	}
	return nil
}

func serviceRules(service *corev1.Service) []inspace.LoadBalancerRule {
	rules := make([]inspace.LoadBalancerRule, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		rules = append(rules, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: port.Port, TargetPort: port.NodePort})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].SourcePort < rules[j].SourcePort })
	return rules
}

func targetUUIDs(nodes []*corev1.Node, location string) ([]string, error) {
	set := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if node == nil || node.Spec.ProviderID == "" {
			return nil, errors.New("cloudprovider: every load balancer node needs an InSpace provider ID")
		}
		id, err := providerid.Parse(node.Spec.ProviderID)
		if err != nil {
			return nil, err
		}
		if id.Location != location {
			return nil, fmt.Errorf("cloudprovider: node %q is in location %q, load balancer is in %q", node.Name, id.Location, location)
		}
		set[id.UUID] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for uuid := range set {
		result = append(result, uuid)
	}
	sort.Strings(result)
	return result, nil
}

func explicitPublicRequested(service *corev1.Service) (bool, error) {
	if service == nil {
		return false, errors.New("cloudprovider: service is required")
	}
	annotationRequested, err := publicAnnotationRequested(service)
	if err != nil {
		return false, err
	}
	return service.Labels[LabelLoadBalancerScope] == LoadBalancerScopePublic && annotationRequested, nil
}

func publicAnnotationRequested(service *corev1.Service) (bool, error) {
	value, exists := service.Annotations[AnnotationPublicLoadBalancer]
	if !exists || value == "" {
		return false, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("cloudprovider: annotation %s must be exactly true or false", AnnotationPublicLoadBalancer)
	}
}

func statusForLoadBalancer(lb *inspace.LoadBalancer, publicAddress string) (*corev1.LoadBalancerStatus, error) {
	address := lb.PrivateAddress
	if publicAddress != "" {
		address = publicAddress
	}
	if address == "" {
		return nil, errors.New("cloudprovider: NLB address is not ready")
	}
	ingress := corev1.LoadBalancerIngress{}
	if net.ParseIP(address) != nil {
		ingress.IP = address
	} else {
		ingress.Hostname = address
	}
	return &corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{ingress}}, nil
}

var (
	_ cloud.Interface    = (*Provider)(nil)
	_ cloud.InstancesV2  = (*Provider)(nil)
	_ cloud.LoadBalancer = (*Provider)(nil)
)
