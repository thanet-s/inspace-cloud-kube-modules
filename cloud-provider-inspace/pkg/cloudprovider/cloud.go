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
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	cloud "k8s.io/cloud-provider"

	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/providerid"
)

const (
	ProviderName = "inspace"

	AnnotationPublicLoadBalancer = "service.beta.kubernetes.io/inspace-load-balancer-public"
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
	Location         string
	Region           string
	NetworkUUID      string
	BillingAccountID int64
	ClusterID        string
}

type Provider struct {
	api    API
	config Config
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
	return &Provider{api: api, config: config}, nil
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
	if json.Unmarshal([]byte(vm.Description), &record) != nil || record.Schema != "karpenter.inspace.cloud/v1" {
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
	if lb == nil {
		return nil, false, nil
	}
	publicAddress := ""
	public, err := publicRequested(service)
	if err != nil {
		return nil, true, err
	}
	if public {
		floatingIP, findErr := p.findOwnedFloatingIP(ctx, service)
		if findErr != nil {
			return nil, true, findErr
		}
		if floatingIP == nil || floatingIP.AssignedTo != lb.UUID {
			return nil, true, errors.New("cloudprovider: public load balancer floating IP is not ready")
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
	if err := validateService(service); err != nil {
		return nil, err
	}
	targets, err := targetUUIDs(nodes, p.config.Location)
	if err != nil {
		return nil, err
	}
	rules := serviceRules(service)
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return nil, err
	}
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
	} else {
		if lb.NetworkUUID != p.config.NetworkUUID {
			return nil, fmt.Errorf("cloudprovider: refusing to adopt load balancer %q on network %q", lb.DisplayName, lb.NetworkUUID)
		}
		if err := p.reconcileLoadBalancer(ctx, lb, targets, rules); err != nil {
			return nil, err
		}
	}
	public, _ := publicRequested(service) // validateService checked this above.
	publicAddress := ""
	if public {
		floatingIP, err := p.ensurePublicFloatingIP(ctx, service, lb.UUID)
		if err != nil {
			return nil, err
		}
		publicAddress = floatingIP.Address
	} else if err := p.cleanupOwnedFloatingIP(ctx, service, lb.UUID); err != nil {
		return nil, err
	}
	return statusForLoadBalancer(lb, publicAddress)
}

func (p *Provider) UpdateLoadBalancer(ctx context.Context, _ string, service *corev1.Service, nodes []*corev1.Node) error {
	if err := validateService(service); err != nil {
		return err
	}
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return err
	}
	if lb == nil {
		return errors.New("cloudprovider: managed load balancer does not exist")
	}
	targets, err := targetUUIDs(nodes, p.config.Location)
	if err != nil {
		return err
	}
	if err := p.reconcileLoadBalancer(ctx, lb, targets, serviceRules(service)); err != nil {
		return err
	}
	public, _ := publicRequested(service)
	if public {
		_, err = p.ensurePublicFloatingIP(ctx, service, lb.UUID)
		return err
	}
	return p.cleanupOwnedFloatingIP(ctx, service, lb.UUID)
}

func (p *Provider) EnsureLoadBalancerDeleted(ctx context.Context, _ string, service *corev1.Service) error {
	lb, err := p.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		return err
	}
	expectedLoadBalancerUUID := ""
	if lb != nil {
		expectedLoadBalancerUUID = lb.UUID
	}
	if err := p.cleanupOwnedFloatingIP(ctx, service, expectedLoadBalancerUUID); err != nil {
		return err
	}
	if lb == nil {
		return nil
	}
	err = p.api.DeleteLoadBalancer(ctx, p.config.Location, lb.UUID)
	if inspace.IsNotFound(err) {
		return nil
	}
	return err
}

func (p *Provider) cleanupOwnedFloatingIP(ctx context.Context, service *corev1.Service, expectedLoadBalancerUUID string) error {
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil || floatingIP == nil {
		return err
	}
	if floatingIP.AssignedTo != "" {
		if expectedLoadBalancerUUID == "" || floatingIP.AssignedTo != expectedLoadBalancerUUID || floatingIP.AssignedToResourceType != "load_balancer" {
			return fmt.Errorf("cloudprovider: refusing to unassign owned floating IP %s from unexpected %s %s", floatingIP.Address, floatingIP.AssignedToResourceType, floatingIP.AssignedTo)
		}
		if _, err := p.api.UnassignFloatingIP(ctx, p.config.Location, floatingIP.Address); err != nil && !inspace.IsNotFound(err) {
			return err
		}
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
	filters := &inspace.FloatingIPFilters{BillingAccountID: p.config.BillingAccountID}
	items, err := p.api.ListFloatingIPs(ctx, p.config.Location, filters)
	if err != nil {
		return nil, err
	}
	name := p.floatingIPName(service)
	var found *inspace.FloatingIP
	for i := range items {
		if items[i].Name != name || items[i].IsDeleted {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("cloudprovider: multiple floating IPs have ownership name %q", name)
		}
		found = &items[i]
	}
	return found, nil
}

func (p *Provider) ensurePublicFloatingIP(ctx context.Context, service *corev1.Service, loadBalancerUUID string) (*inspace.FloatingIP, error) {
	if p.config.BillingAccountID < 1 {
		return nil, errors.New("cloudprovider: public load balancer requires INSPACE_BILLING_ACCOUNT_ID")
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
	}
	if floatingIP.AssignedTo != "" && (floatingIP.AssignedTo != loadBalancerUUID || floatingIP.AssignedToResourceType != "load_balancer") {
		return nil, fmt.Errorf("cloudprovider: refusing to reassign owned floating IP %s from %s", floatingIP.Address, floatingIP.AssignedTo)
	}
	if floatingIP.AssignedTo == "" {
		floatingIP, err = p.api.AssignFloatingIP(ctx, p.config.Location, floatingIP.Address, loadBalancerUUID, "load_balancer")
		if err != nil {
			return nil, err
		}
	}
	return floatingIP, nil
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
		if found != nil {
			return nil, fmt.Errorf("cloudprovider: multiple load balancers have ownership name %q", name)
		}
		found = &lbs[i]
	}
	return found, nil
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
	if _, err := publicRequested(service); err != nil {
		return err
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

func publicRequested(service *corev1.Service) (bool, error) {
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
