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
	"io"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	cloud "k8s.io/cloud-provider"
	"k8s.io/klog/v2"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	ProviderName = "inspace"

	AnnotationPublicLoadBalancer    = "service.beta.kubernetes.io/inspace-load-balancer-public"
	annotationLoadBalancerReconcile = "inspace.cloud/load-balancer-reconcile"
	annotationStandardNLBMutation   = "service.inspace.cloud/public-nlb-mutation"
	LabelLoadBalancerScope          = "inspace.cloud/load-balancer-scope"
	LoadBalancerScopePublic         = "public"
	LoadBalancerScopePrivate        = "private"

	clusterAutoscalerDeletionTaint = "ToBeDeletedByClusterAutoscaler"
	karpenterDisruptionTaint       = "karpenter.sh/disrupted"
	nodeRoleControlPlaneLabel      = "node-role.kubernetes.io/control-plane"
	nodeRoleMasterLabel            = "node-role.kubernetes.io/master"

	// Version 1 was shipped by the additive-mutation fence. Version 2 extends
	// the same receipt with durable negative evidence for removals. Keep v1
	// readable so an upgrade can resolve an already-issued create/add without
	// authorizing a replay.
	standardNLBLegacyMutationVersion = 1
	standardNLBMutationVersion       = 2
	standardNLBPhaseIntent           = "intent"
	standardNLBPhaseIssued           = "issued"

	standardNLBCreateLoadBalancer = "create-load-balancer"
	standardNLBCreateFloatingIP   = "create-floating-ip"
	standardNLBAssignFloatingIP   = "assign-floating-ip"
	standardNLBAddTarget          = "add-target"
	standardNLBAddRule            = "add-rule"
	standardNLBUnassignFloatingIP = "unassign-floating-ip"
	standardNLBDeleteFloatingIP   = "delete-floating-ip"
	standardNLBRemoveTarget       = "remove-target"
	standardNLBRemoveRule         = "remove-rule"
	standardNLBDeleteLoadBalancer = "delete-load-balancer"

	standardNLBRemovalAbsenceDelay = 30 * time.Second
)

var errStandardNLBRemovalPending = errors.New("cloudprovider: public NLB removal remains durably pending")

// standardNLBServiceStore is the durable metadata boundary used by the paid
// InSpace NLB path. The production implementation is installed by Initialize;
// the narrow interface also lets unit tests model controller restarts without
// making cloud calls.
type standardNLBServiceStore interface {
	GetExact(context.Context, *corev1.Service) (*corev1.Service, error)
	UpdateExact(context.Context, *corev1.Service) (*corev1.Service, error)
}

type kubernetesStandardNLBServiceStore struct {
	client kubernetes.Interface
}

func (s kubernetesStandardNLBServiceStore) GetExact(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	return s.client.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
}

func (s kubernetesStandardNLBServiceStore) UpdateExact(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	return s.client.CoreV1().Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
}

type standardNLBMutationFence struct {
	Version           int    `json:"version"`
	Operation         string `json:"operation"`
	Phase             string `json:"phase"`
	RequestHash       string `json:"requestHash"`
	ResourceName      string `json:"resourceName,omitempty"`
	LoadBalancerUUID  string `json:"loadBalancerUUID,omitempty"`
	TargetUUID        string `json:"targetUUID,omitempty"`
	RuleUUID          string `json:"ruleUUID,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	SourcePort        int32  `json:"sourcePort,omitempty"`
	TargetPort        int32  `json:"targetPort,omitempty"`
	IssuedAt          string `json:"issuedAt,omitempty"`
	AbsenceObservedAt string `json:"absenceObservedAt,omitempty"`
}

// API is the exact SDK surface used by the CCM and permits loopback-only
// contract tests without network access.
type API interface {
	GetNetwork(context.Context, string, string) (*inspace.Network, error)
	ListVMs(context.Context, string) ([]inspace.VM, error)
	GetVM(context.Context, string, string) (*inspace.VM, error)
	ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error)
	GetLoadBalancer(context.Context, string, string) (*inspace.LoadBalancer, error)
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
	ListFirewalls(context.Context, string) ([]inspace.Firewall, error)
	CreateFirewall(context.Context, string, inspace.CreateFirewallRequest) (*inspace.Firewall, error)
	UpdateFirewall(context.Context, string, string, inspace.UpdateFirewallRequest) (*inspace.Firewall, error)
	DeleteFirewall(context.Context, string, string) error
	AssignFirewallToVM(context.Context, string, string, string) error
	UnassignFirewallFromVM(context.Context, string, string, string) error
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
	NodeLoadBalancer             NodeLoadBalancerConfig
}

// NodeLoadBalancerConfig controls the optional CCM-managed public node load
// balancer. A controller-owned private-VIP Service supplies the Cilium eBPF
// dataplane; Karpenter supplies dedicated, tainted nodes and InSpace firewalls
// restrict every Service to its declared public ports.
type NodeLoadBalancerConfig struct {
	Enabled          bool
	DefaultNodeClass string
	NodesPerShard    int32
}

type Provider struct {
	api                          API
	config                       Config
	controlPlaneVIP              netip.Addr
	privateLoadBalancerPoolStart netip.Addr
	privateLoadBalancerPoolStop  netip.Addr
	loadBalancerMu               sync.Mutex
	stopCh                       <-chan struct{}
	kubeClient                   kubernetes.Interface
	standardNLBServiceStore      standardNLBServiceStore
	dynamicClient                dynamic.Interface
	endpointSliceLister          discoverylisters.EndpointSliceLister
	endpointSlicesSynced         cache.InformerSynced
	standardNLBNow               func() time.Time
	standardNLBAbsentDelay       time.Duration
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
	if config.BillingAccountID < 1 {
		return nil, errors.New("cloudprovider: billing account ID must be a positive integer")
	}
	if strings.TrimSpace(config.ClusterID) == "" {
		return nil, errors.New("cloudprovider: cluster ID is required")
	}
	if config.Region == "" {
		config.Region = config.Location
	}
	if config.NodeLoadBalancer.Enabled {
		if strings.TrimSpace(config.NodeLoadBalancer.DefaultNodeClass) == "" {
			return nil, errors.New("cloudprovider: node load balancer default NodeClass is required when enabled")
		}
		if messages := utilvalidation.IsDNS1123Subdomain(config.NodeLoadBalancer.DefaultNodeClass); len(messages) != 0 {
			return nil, fmt.Errorf("cloudprovider: node load balancer default NodeClass must be a DNS-1123 subdomain: %s", strings.Join(messages, "; "))
		}
		if messages := utilvalidation.IsDNS1123Label(config.ClusterID); len(messages) != 0 {
			return nil, fmt.Errorf("cloudprovider: cluster ID must be a DNS-1123 label when the node load balancer is enabled: %s", strings.Join(messages, "; "))
		}
		if config.NodeLoadBalancer.NodesPerShard == 0 {
			config.NodeLoadBalancer.NodesPerShard = 1
		}
		if config.NodeLoadBalancer.NodesPerShard < 1 || config.NodeLoadBalancer.NodesPerShard > 10 {
			return nil, errors.New("cloudprovider: node load balancer nodes per shard must be between 1 and 10")
		}
		// Generated NodePools are 13 characters and Karpenter appends its
		// five-character NodeClaim suffix. Keep the provider's
		// <cluster>-karp-<nodeclaim> VM/hostname contract within DNS-1123's
		// 63-character limit before any billable static capacity is requested.
		if len(config.ClusterID) > 38 {
			return nil, errors.New("cloudprovider: cluster ID must be at most 38 characters when the node load balancer is enabled")
		}
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
		standardNLBAbsentDelay: -1,
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

func (p *Provider) Initialize(clientBuilder cloud.ControllerClientBuilder, stopCh <-chan struct{}) {
	if clientBuilder == nil {
		panic("cloudprovider: controller client builder is required")
	}
	client, err := clientBuilder.Client("inspace-load-balancer-target-controller")
	if err != nil {
		panic(fmt.Sprintf("cloudprovider: initialize Kubernetes client: %v", err))
	}
	if client == nil {
		panic("cloudprovider: controller client builder returned a nil Kubernetes client")
	}
	p.kubeClient = client
	p.standardNLBServiceStore = kubernetesStandardNLBServiceStore{client: client}
	if p.config.NodeLoadBalancer.Enabled {
		restConfig, err := clientBuilder.Config("inspace-node-load-balancer-controller")
		if err != nil {
			panic(fmt.Sprintf("cloudprovider: initialize node load balancer REST config: %v", err))
		}
		dynamicClient, err := dynamic.NewForConfig(restConfig)
		if err != nil {
			panic(fmt.Sprintf("cloudprovider: initialize node load balancer dynamic client: %v", err))
		}
		p.dynamicClient = dynamicClient
	}
	p.stopCh = stopCh
}

// SetInformers wires the provider-specific target reconciler into the same
// leader-elected informer factory as the standard cloud-controller-manager.
// The standard Service controller intentionally does not react to Node Ready
// transitions or EndpointSlice changes, both of which affect InSpace targets.
func (p *Provider) SetInformers(factory informers.SharedInformerFactory) {
	if p.stopCh == nil || p.kubeClient == nil {
		panic("cloudprovider: Initialize must be called before SetInformers")
	}
	controller, err := newLoadBalancerTargetController(p, factory)
	if err != nil {
		panic(fmt.Sprintf("cloudprovider: initialize load-balancer target controller: %v", err))
	}
	p.endpointSliceLister = controller.endpointSlices
	p.endpointSlicesSynced = controller.endpointSlicesSynced
	go controller.Run(p.stopCh)
	if p.config.NodeLoadBalancer.Enabled {
		nodeController, err := newNodeLoadBalancerController(p, factory)
		if err != nil {
			panic(fmt.Sprintf("cloudprovider: initialize node load balancer controller: %v", err))
		}
		go nodeController.Run(p.stopCh)
	}
}

func (p *Provider) ProviderName() string                     { return ProviderName }
func (p *Provider) HasClusterID() bool                       { return p.config.ClusterID != "" }
func (p *Provider) Instances() (cloud.Instances, bool)       { return nil, false }
func (p *Provider) InstancesV2() (cloud.InstancesV2, bool)   { return p, true }
func (p *Provider) LoadBalancer() (cloud.LoadBalancer, bool) { return p, true }
func (p *Provider) Zones() (cloud.Zones, bool)               { return nil, false }
func (p *Provider) Clusters() (cloud.Clusters, bool)         { return nil, false }
func (p *Provider) Routes() (cloud.Routes, bool)             { return nil, false }

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
		(record.Schema != "karpenter.inspace.cloud/v1" &&
			record.Schema != "karpenter.inspace.cloud/v2" &&
			record.Schema != "karpenter.inspace.cloud/v3") {
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
	if len(items) == 0 {
		// InSpace floating addresses are not guest-NIC addresses. Without an
		// authoritative assignment row, vm.PublicIPv4 cannot prove ownership,
		// billing account, or assignment state and must not be published.
		return "", nil
	}
	if len(items) != 1 {
		return "", fmt.Errorf("cloudprovider: VM %s has %d floating IPv4 assignment rows; expected exactly one", vm.UUID, len(items))
	}
	if err := p.validateVMFloatingIPv4(&items[0], vm); err != nil {
		return "", err
	}
	return items[0].Address, nil
}

func (p *Provider) validateVMFloatingIPv4(item *inspace.FloatingIP, vm *inspace.VM) error {
	if item == nil {
		return errors.New("cloudprovider: VM floating IP returned an empty response")
	}
	if item.BillingAccountID != p.config.BillingAccountID {
		return fmt.Errorf("cloudprovider: floating IP %q for VM %s belongs to billing account %d, expected %d", item.Address, vm.UUID, item.BillingAccountID, p.config.BillingAccountID)
	}
	if !item.Enabled || item.IsDeleted || item.IsVirtual || item.Type != "public" {
		return fmt.Errorf("cloudprovider: floating IP %q for VM %s must be enabled, active, non-virtual, and type public", item.Address, vm.UUID)
	}
	address, err := netip.ParseAddr(item.Address)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != item.Address {
		return fmt.Errorf("cloudprovider: floating IP %q for VM %s must be one canonical global public IPv4 address", item.Address, vm.UUID)
	}
	if item.AssignedTo != vm.UUID || item.AssignedToResourceType != "virtual_machine" {
		return fmt.Errorf("cloudprovider: floating IP %q is not assigned to the exact VM %s as resource type virtual_machine", item.Address, vm.UUID)
	}
	if vm.PrivateIPv4 != "" && item.AssignedToPrivateIP != vm.PrivateIPv4 {
		return fmt.Errorf("cloudprovider: floating IP %q assignment private IPv4 %q does not match VM %s private IPv4 %q", item.Address, item.AssignedToPrivateIP, vm.UUID, vm.PrivateIPv4)
	}
	return nil
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

func standardNLBRequestHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("cloudprovider: encode public NLB mutation intent: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (f standardNLBMutationFence) validate() error {
	if f.Version != standardNLBLegacyMutationVersion && f.Version != standardNLBMutationVersion {
		return fmt.Errorf("cloudprovider: unsupported public NLB mutation fence version %d", f.Version)
	}
	if len(f.RequestHash) != sha256.Size*2 {
		return errors.New("cloudprovider: public NLB mutation fence has an invalid request hash")
	}
	if _, err := hex.DecodeString(f.RequestHash); err != nil {
		return errors.New("cloudprovider: public NLB mutation fence has a non-hex request hash")
	}
	switch f.Phase {
	case standardNLBPhaseIntent:
		if f.IssuedAt != "" || f.AbsenceObservedAt != "" {
			return errors.New("cloudprovider: unissued public NLB mutation intent has issued state")
		}
	case standardNLBPhaseIssued:
		issuedAt, err := time.Parse(time.RFC3339Nano, f.IssuedAt)
		if err != nil || issuedAt.Location() != time.UTC {
			return errors.New("cloudprovider: issued public NLB mutation fence has an invalid timestamp")
		}
		if f.AbsenceObservedAt != "" {
			observedAt, err := time.Parse(time.RFC3339Nano, f.AbsenceObservedAt)
			if err != nil || observedAt.Location() != time.UTC {
				return errors.New("cloudprovider: public NLB removal fence has an invalid absence timestamp")
			}
			if observedAt.Before(issuedAt) {
				return errors.New("cloudprovider: public NLB removal fence observed absence before the mutation was issued")
			}
		}
	default:
		return fmt.Errorf("cloudprovider: public NLB mutation fence has invalid phase %q", f.Phase)
	}

	switch f.Operation {
	case standardNLBCreateLoadBalancer, standardNLBCreateFloatingIP:
		if strings.TrimSpace(f.ResourceName) == "" || f.LoadBalancerUUID != "" || f.TargetUUID != "" ||
			f.RuleUUID != "" || f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 || f.AbsenceObservedAt != "" {
			return fmt.Errorf("cloudprovider: %s fence has inconsistent resource identity", f.Operation)
		}
	case standardNLBAssignFloatingIP:
		address, err := netip.ParseAddr(f.ResourceName)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != f.ResourceName ||
			!validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || f.TargetUUID != "" || f.RuleUUID != "" ||
			f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 || f.AbsenceObservedAt != "" {
			return errors.New("cloudprovider: assign-floating-ip fence has inconsistent resource identity")
		}
	case standardNLBAddTarget:
		if !validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || !validNodeLoadBalancerCloudUUID(f.TargetUUID) ||
			f.ResourceName != "" || f.RuleUUID != "" || f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 || f.AbsenceObservedAt != "" {
			return errors.New("cloudprovider: add-target fence has inconsistent resource identity")
		}
	case standardNLBAddRule:
		if !validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || f.ResourceName != "" || f.TargetUUID != "" ||
			f.RuleUUID != "" || f.Protocol != "TCP" || f.SourcePort < 1 || f.SourcePort > 65535 || f.TargetPort < 1 || f.TargetPort > 65535 ||
			f.AbsenceObservedAt != "" {
			return errors.New("cloudprovider: add-rule fence has inconsistent resource identity")
		}
	case standardNLBUnassignFloatingIP:
		address, err := netip.ParseAddr(f.ResourceName)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != f.ResourceName ||
			!validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || f.TargetUUID != "" || f.RuleUUID != "" ||
			f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 {
			return errors.New("cloudprovider: unassign-floating-ip fence has inconsistent resource identity")
		}
	case standardNLBDeleteFloatingIP:
		address, err := netip.ParseAddr(f.ResourceName)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != f.ResourceName ||
			f.LoadBalancerUUID != "" || f.TargetUUID != "" || f.RuleUUID != "" || f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 {
			return errors.New("cloudprovider: delete-floating-ip fence has inconsistent resource identity")
		}
	case standardNLBRemoveTarget:
		if !validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || !validNodeLoadBalancerCloudUUID(f.TargetUUID) ||
			f.ResourceName != "" || f.RuleUUID != "" || f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 {
			return errors.New("cloudprovider: remove-target fence has inconsistent resource identity")
		}
	case standardNLBRemoveRule:
		if !validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || !validNodeLoadBalancerCloudUUID(f.RuleUUID) ||
			f.ResourceName != "" || f.TargetUUID != "" || f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 {
			return errors.New("cloudprovider: remove-rule fence has inconsistent resource identity")
		}
	case standardNLBDeleteLoadBalancer:
		if !validNodeLoadBalancerCloudUUID(f.LoadBalancerUUID) || f.ResourceName != "" || f.TargetUUID != "" || f.RuleUUID != "" ||
			f.Protocol != "" || f.SourcePort != 0 || f.TargetPort != 0 {
			return errors.New("cloudprovider: delete-load-balancer fence has inconsistent resource identity")
		}
	default:
		return fmt.Errorf("cloudprovider: public NLB mutation fence has unknown operation %q", f.Operation)
	}
	if f.Version == standardNLBLegacyMutationVersion && standardNLBRemovalOperation(f.Operation) {
		return fmt.Errorf("cloudprovider: legacy public NLB mutation fence version %d cannot describe removal %q", f.Version, f.Operation)
	}
	if standardNLBRemovalOperation(f.Operation) {
		expectedHash, err := standardNLBRemovalRequestHash(f)
		if err != nil {
			return err
		}
		if f.RequestHash != expectedHash {
			return errors.New("cloudprovider: public NLB removal fence request hash does not match its exact resource identity")
		}
	}
	return nil
}

func standardNLBRemovalRequestHash(f standardNLBMutationFence) (string, error) {
	switch f.Operation {
	case standardNLBUnassignFloatingIP:
		return standardNLBRequestHash(struct {
			Address          string `json:"address"`
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{Address: f.ResourceName, LoadBalancerUUID: f.LoadBalancerUUID})
	case standardNLBDeleteFloatingIP:
		return standardNLBRequestHash(struct {
			Address string `json:"address"`
		}{Address: f.ResourceName})
	case standardNLBRemoveTarget:
		return standardNLBRequestHash(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
			TargetUUID       string `json:"targetUUID"`
		}{LoadBalancerUUID: f.LoadBalancerUUID, TargetUUID: f.TargetUUID})
	case standardNLBRemoveRule:
		return standardNLBRequestHash(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
			RuleUUID         string `json:"ruleUUID"`
		}{LoadBalancerUUID: f.LoadBalancerUUID, RuleUUID: f.RuleUUID})
	case standardNLBDeleteLoadBalancer:
		return standardNLBRequestHash(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{LoadBalancerUUID: f.LoadBalancerUUID})
	default:
		return "", fmt.Errorf("cloudprovider: %q is not a public NLB removal operation", f.Operation)
	}
}

func parseStandardNLBFence(raw string) (*standardNLBMutationFence, error) {
	if raw == "" {
		return nil, nil
	}
	var fence standardNLBMutationFence
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fence); err != nil {
		return nil, fmt.Errorf("cloudprovider: decode public NLB mutation fence: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("cloudprovider: decode public NLB mutation fence: multiple JSON values")
		}
		return nil, fmt.Errorf("cloudprovider: decode public NLB mutation fence trailing data: %w", err)
	}
	if err := fence.validate(); err != nil {
		return nil, err
	}
	return &fence, nil
}

func encodeStandardNLBFence(fence *standardNLBMutationFence) (string, error) {
	if fence == nil {
		return "", nil
	}
	if err := fence.validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(fence)
	if err != nil {
		return "", fmt.Errorf("cloudprovider: encode public NLB mutation fence: %w", err)
	}
	return string(encoded), nil
}

func sameStandardNLBMutationIntent(left, right standardNLBMutationFence) bool {
	return left.Version == right.Version && left.Operation == right.Operation &&
		left.RequestHash == right.RequestHash && left.ResourceName == right.ResourceName &&
		left.LoadBalancerUUID == right.LoadBalancerUUID && left.TargetUUID == right.TargetUUID &&
		left.RuleUUID == right.RuleUUID && left.Protocol == right.Protocol && left.SourcePort == right.SourcePort && left.TargetPort == right.TargetPort
}

func validateExactStandardNLBService(anchor, current *corev1.Service) error {
	if anchor == nil || current == nil {
		return errors.New("cloudprovider: public NLB mutation requires a live Service")
	}
	if anchor.Namespace == "" || anchor.Name == "" || anchor.UID == "" {
		return errors.New("cloudprovider: public NLB mutation requires a namespaced Service with a stable UID")
	}
	if current.Namespace != anchor.Namespace || current.Name != anchor.Name || current.UID != anchor.UID {
		return fmt.Errorf("cloudprovider: Service %s/%s identity changed while fencing a public NLB mutation", anchor.Namespace, anchor.Name)
	}
	return nil
}

func (p *Provider) readStandardNLBFence(ctx context.Context, service *corev1.Service) (*standardNLBMutationFence, string, error) {
	if p.standardNLBServiceStore == nil {
		return nil, "", errors.New("cloudprovider: Initialize must install the Service metadata store before public NLB mutation")
	}
	current, err := p.standardNLBServiceStore.GetExact(ctx, service)
	if err != nil {
		return nil, "", fmt.Errorf("cloudprovider: read public NLB mutation fence: %w", err)
	}
	if err := validateExactStandardNLBService(service, current); err != nil {
		return nil, "", err
	}
	raw := current.Annotations[annotationStandardNLBMutation]
	fence, err := parseStandardNLBFence(raw)
	return fence, raw, err
}

func (p *Provider) replaceStandardNLBFence(
	ctx context.Context,
	service *corev1.Service,
	expectedRaw string,
	next *standardNLBMutationFence,
) (string, error) {
	desiredRaw, err := encodeStandardNLBFence(next)
	if err != nil {
		return "", err
	}
	current, err := p.standardNLBServiceStore.GetExact(ctx, service)
	if err != nil {
		return "", fmt.Errorf("cloudprovider: read Service before public NLB fence update: %w", err)
	}
	if err := validateExactStandardNLBService(service, current); err != nil {
		return "", err
	}
	if current.Annotations[annotationStandardNLBMutation] != expectedRaw {
		return "", errors.New("cloudprovider: public NLB mutation fence changed concurrently")
	}
	if desiredRaw != expectedRaw {
		copy := current.DeepCopy()
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if desiredRaw == "" {
			delete(copy.Annotations, annotationStandardNLBMutation)
		} else {
			copy.Annotations[annotationStandardNLBMutation] = desiredRaw
		}
		updated, updateErr := p.standardNLBServiceStore.UpdateExact(ctx, copy)
		if updateErr != nil {
			return "", fmt.Errorf("cloudprovider: persist public NLB mutation fence: %w", updateErr)
		}
		if err := validateExactStandardNLBService(service, updated); err != nil {
			return "", err
		}
	}
	verified, err := p.standardNLBServiceStore.GetExact(ctx, service)
	if err != nil {
		return "", fmt.Errorf("cloudprovider: read back public NLB mutation fence: %w", err)
	}
	if err := validateExactStandardNLBService(service, verified); err != nil {
		return "", err
	}
	if verified.Annotations[annotationStandardNLBMutation] != desiredRaw {
		return "", errors.New("cloudprovider: public NLB mutation fence readback did not match the persisted value")
	}
	return desiredRaw, nil
}

func (p *Provider) stageStandardNLBMutation(
	ctx context.Context,
	service *corev1.Service,
	desired standardNLBMutationFence,
) (standardNLBMutationFence, string, error) {
	desired.Version = standardNLBMutationVersion
	desired.Phase = standardNLBPhaseIntent
	desired.IssuedAt = ""
	desired.AbsenceObservedAt = ""
	if err := desired.validate(); err != nil {
		return standardNLBMutationFence{}, "", err
	}
	existing, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil {
		return standardNLBMutationFence{}, "", err
	}
	if existing != nil {
		if existing.Phase == standardNLBPhaseIssued && !sameStandardNLBMutationIntent(*existing, desired) {
			return standardNLBMutationFence{}, "", fmt.Errorf("cloudprovider: issued %s mutation must resolve before staging %s", existing.Operation, desired.Operation)
		}
		if sameStandardNLBMutationIntent(*existing, desired) {
			return *existing, raw, nil
		}
	}
	raw, err = p.replaceStandardNLBFence(ctx, service, raw, &desired)
	return desired, raw, err
}

func (p *Provider) issueStandardNLBMutation(
	ctx context.Context,
	service *corev1.Service,
	fence standardNLBMutationFence,
	raw string,
) (standardNLBMutationFence, string, error) {
	if fence.Phase == standardNLBPhaseIssued {
		return fence, raw, nil
	}
	fence.Phase = standardNLBPhaseIssued
	fence.IssuedAt = p.standardNLBTime().Format(time.RFC3339Nano)
	raw, err := p.replaceStandardNLBFence(ctx, service, raw, &fence)
	return fence, raw, err
}

func standardNLBMutationKnownPreDispatch(err error) bool {
	return errors.Is(err, inspace.ErrMutationBlocked)
}

func standardNLBMutationError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("cloudprovider: %s: %w", action, err)
}

func standardNLBRemovalOperation(operation string) bool {
	switch operation {
	case standardNLBUnassignFloatingIP, standardNLBDeleteFloatingIP, standardNLBRemoveTarget,
		standardNLBRemoveRule, standardNLBDeleteLoadBalancer:
		return true
	default:
		return false
	}
}

func (p *Provider) standardNLBTime() time.Time {
	if p.standardNLBNow != nil {
		return p.standardNLBNow().UTC()
	}
	return time.Now().UTC()
}

func (p *Provider) standardNLBRemovalDelay() time.Duration {
	if p.standardNLBAbsentDelay < 0 {
		return standardNLBRemovalAbsenceDelay
	}
	return p.standardNLBAbsentDelay
}

// observeStandardNLBRemoval advances only the durable Service receipt. A
// dispatched removal is never authorized again merely because a stale read
// still shows the old object or relation. Completion requires two exact
// negative observations separated by the provider-convergence delay.
func (p *Provider) observeStandardNLBRemoval(
	ctx context.Context,
	service *corev1.Service,
	desired standardNLBMutationFence,
	absent bool,
) (bool, error) {
	desired.Version = standardNLBMutationVersion
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil {
		return false, err
	}
	if fence == nil {
		if absent {
			return true, nil
		}
		return false, errors.New("cloudprovider: public NLB removal receipt disappeared while the exact resource remains visible")
	}
	if !standardNLBRemovalOperation(fence.Operation) || !sameStandardNLBMutationIntent(*fence, desired) {
		return false, fmt.Errorf("cloudprovider: public NLB removal receipt changed from %s while observing %s", fence.Operation, desired.Operation)
	}
	if fence.Phase == standardNLBPhaseIntent {
		if !absent {
			return false, nil
		}
		_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return err == nil, err
	}
	if !absent {
		if fence.AbsenceObservedAt == "" {
			return false, nil
		}
		updated := *fence
		updated.AbsenceObservedAt = ""
		_, err := p.replaceStandardNLBFence(ctx, service, raw, &updated)
		return false, err
	}
	if fence.AbsenceObservedAt == "" {
		updated := *fence
		updated.AbsenceObservedAt = p.standardNLBTime().Format(time.RFC3339Nano)
		_, err := p.replaceStandardNLBFence(ctx, service, raw, &updated)
		return false, err
	}
	observedAt, err := time.Parse(time.RFC3339Nano, fence.AbsenceObservedAt)
	if err != nil || observedAt.Location() != time.UTC {
		return false, errors.New("cloudprovider: public NLB removal receipt contains invalid absence evidence")
	}
	if p.standardNLBTime().Before(observedAt.Add(p.standardNLBRemovalDelay())) {
		return false, nil
	}
	_, err = p.replaceStandardNLBFence(ctx, service, raw, nil)
	return err == nil, err
}

// issueStandardNLBRemoval persists exact intent and issued state before the
// caller may make one cloud request. An already-issued receipt is read-only.
func (p *Provider) issueStandardNLBRemoval(
	ctx context.Context,
	service *corev1.Service,
	desired standardNLBMutationFence,
) (standardNLBMutationFence, string, bool, error) {
	fence, raw, err := p.stageStandardNLBMutation(ctx, service, desired)
	if err != nil {
		return standardNLBMutationFence{}, "", false, err
	}
	if fence.Phase == standardNLBPhaseIssued {
		return fence, raw, false, nil
	}
	fence, raw, err = p.issueStandardNLBMutation(ctx, service, fence, raw)
	return fence, raw, err == nil, err
}

func standardNLBRemovalPending(fence standardNLBMutationFence) error {
	return fmt.Errorf(
		"%w: %s issued at %s remains unresolved behind its durable Service receipt; refusing a second mutation",
		errStandardNLBRemovalPending, fence.Operation, fence.IssuedAt,
	)
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

func (p *Provider) ensureStandardNLBLoadBalancer(
	ctx context.Context,
	service *corev1.Service,
	discovered *inspace.LoadBalancer,
	request inspace.CreateLoadBalancerRequest,
) (*inspace.LoadBalancer, bool, error) {
	requestHash, err := standardNLBRequestHash(request)
	if err != nil {
		return nil, false, err
	}
	desired := standardNLBMutationFence{
		Operation:    standardNLBCreateLoadBalancer,
		RequestHash:  requestHash,
		ResourceName: request.DisplayName,
	}
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil {
		return nil, false, err
	}
	if discovered != nil {
		if err := p.validateOwnedLoadBalancerIdentity(service, discovered); err != nil {
			return nil, false, err
		}
		if fence == nil || fence.Operation != standardNLBCreateLoadBalancer {
			return discovered, false, nil
		}
		if fence.ResourceName != request.DisplayName {
			return nil, false, fmt.Errorf("cloudprovider: visible NLB %s does not match fenced create name %q", discovered.UUID, fence.ResourceName)
		}
		if fence.RequestHash != requestHash {
			return nil, false, errors.New("cloudprovider: visible NLB cannot resolve its create fence because the exact requested rules or targets changed")
		}
		if err := validateStandardNLBInitialPolicy(discovered, request); err != nil {
			return nil, false, err
		}
		if _, err := p.replaceStandardNLBFence(ctx, service, raw, nil); err != nil {
			return nil, false, fmt.Errorf("cloudprovider: promote visible fenced NLB %s: %w", discovered.UUID, err)
		}
		return discovered, true, nil
	}
	if fence != nil && fence.Operation != standardNLBCreateLoadBalancer {
		return nil, false, fmt.Errorf("cloudprovider: %s mutation must resolve before creating the public NLB", fence.Operation)
	}

	fenceValue, raw, err := p.stageStandardNLBMutation(ctx, service, desired)
	if err != nil {
		return nil, false, err
	}
	if fenceValue.Phase == standardNLBPhaseIssued {
		return nil, false, fmt.Errorf(
			"cloudprovider: public NLB create issued at %s remains ambiguous; refusing a second paid create until %q is observable or the Service fence is manually resolved",
			fenceValue.IssuedAt, fenceValue.ResourceName,
		)
	}
	fenceValue, raw, err = p.issueStandardNLBMutation(ctx, service, fenceValue, raw)
	if err != nil {
		return nil, false, err
	}
	appeared, authorityErr := p.findOwnedLoadBalancer(ctx, service)
	if authorityErr != nil {
		return nil, false, fmt.Errorf("cloudprovider: public NLB post-issue absence authority: %w", authorityErr)
	}
	if appeared != nil {
		if err := validateStandardNLBInitialPolicy(appeared, request); err != nil {
			return nil, false, fmt.Errorf("cloudprovider: public NLB appeared after issue with a different initial payload: %w", err)
		}
		if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
			return nil, false, fmt.Errorf("cloudprovider: promote public NLB that appeared after issue: %w", clearErr)
		}
		return appeared, true, nil
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fenceValue); err != nil {
		return nil, false, fmt.Errorf("cloudprovider: reject public NLB create at final Service authority: %w", err)
	}
	created, createErr := p.api.CreateLoadBalancer(ctx, p.config.Location, request)
	observed, listErr := p.findOwnedLoadBalancer(ctx, service)
	if listErr != nil {
		return nil, false, errors.Join(standardNLBMutationError("create public NLB", createErr), fmt.Errorf("cloudprovider: authoritative NLB create readback: %w", listErr))
	}
	if observed != nil {
		if created != nil && created.UUID != "" && created.UUID != observed.UUID {
			return nil, false, fmt.Errorf("cloudprovider: public NLB create returned UUID %s but deterministic name resolved to %s", created.UUID, observed.UUID)
		}
		if err := validateStandardNLBInitialPolicy(observed, request); err != nil {
			return nil, false, err
		}
		if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
			return nil, false, fmt.Errorf("cloudprovider: promote authoritatively observed public NLB %s: %w", observed.UUID, clearErr)
		}
		return observed, true, nil
	}
	if standardNLBMutationKnownPreDispatch(createErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, false, errors.Join(fmt.Errorf("cloudprovider: create public NLB: %w", createErr), clearErr)
	}
	if createErr != nil {
		return nil, false, fmt.Errorf(
			"cloudprovider: public NLB create issued at %s remains ambiguous after error: %w",
			fenceValue.IssuedAt, createErr,
		)
	}
	return nil, false, fmt.Errorf(
		"cloudprovider: public NLB create issued at %s is not yet observable; refusing a second paid create",
		fenceValue.IssuedAt,
	)
}

func (p *Provider) ensureStandardNLBPublicFloatingIP(
	ctx context.Context,
	service *corev1.Service,
	discovered *inspace.FloatingIP,
) (*inspace.FloatingIP, error) {
	request := inspace.CreateFloatingIPRequest{
		Name:             p.floatingIPName(service),
		BillingAccountID: p.config.BillingAccountID,
	}
	requestHash, err := standardNLBRequestHash(request)
	if err != nil {
		return nil, err
	}
	desired := standardNLBMutationFence{
		Operation:    standardNLBCreateFloatingIP,
		RequestHash:  requestHash,
		ResourceName: request.Name,
	}
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil {
		return nil, err
	}
	if discovered != nil {
		if err := p.validateServiceFloatingIPIdentity(discovered, service); err != nil {
			return nil, err
		}
		if fence == nil {
			return discovered, nil
		}
		if fence.Operation == standardNLBAssignFloatingIP {
			return discovered, nil
		}
		if fence.Operation != standardNLBCreateFloatingIP {
			return nil, fmt.Errorf("cloudprovider: %s mutation remains fenced while the public floating IP is present", fence.Operation)
		}
		if fence.ResourceName != request.Name {
			return nil, fmt.Errorf("cloudprovider: visible floating IP %q does not match fenced create name %q", discovered.Address, fence.ResourceName)
		}
		if _, err := p.replaceStandardNLBFence(ctx, service, raw, nil); err != nil {
			return nil, fmt.Errorf("cloudprovider: promote visible fenced floating IP %q: %w", discovered.Address, err)
		}
		return discovered, nil
	}
	if fence != nil && fence.Operation != standardNLBCreateFloatingIP {
		return nil, fmt.Errorf("cloudprovider: %s mutation must resolve before creating the public floating IP", fence.Operation)
	}

	fenceValue, raw, err := p.stageStandardNLBMutation(ctx, service, desired)
	if err != nil {
		return nil, err
	}
	if fenceValue.Phase == standardNLBPhaseIssued {
		return nil, fmt.Errorf(
			"cloudprovider: public floating IP create issued at %s remains ambiguous; refusing a second create until %q is observable or the Service fence is manually resolved",
			fenceValue.IssuedAt, fenceValue.ResourceName,
		)
	}
	fenceValue, raw, err = p.issueStandardNLBMutation(ctx, service, fenceValue, raw)
	if err != nil {
		return nil, err
	}
	appeared, authorityErr := p.findOwnedFloatingIP(ctx, service)
	if authorityErr != nil {
		return nil, fmt.Errorf("cloudprovider: public floating-IP post-issue absence authority: %w", authorityErr)
	}
	if appeared != nil {
		if validateErr := validateServiceFloatingIPUnassigned(appeared); validateErr != nil {
			return nil, fmt.Errorf("cloudprovider: public floating IP appeared after issue in an unexpected state: %w", validateErr)
		}
		if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
			return nil, fmt.Errorf("cloudprovider: promote public floating IP that appeared after issue: %w", clearErr)
		}
		return appeared, nil
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fenceValue); err != nil {
		return nil, fmt.Errorf("cloudprovider: reject public floating-IP create at final Service authority: %w", err)
	}
	created, createErr := p.api.CreateFloatingIP(ctx, p.config.Location, request)
	observed, listErr := p.findOwnedFloatingIP(ctx, service)
	if listErr != nil {
		return nil, errors.Join(standardNLBMutationError("create public floating IP", createErr), fmt.Errorf("cloudprovider: authoritative floating IP create readback: %w", listErr))
	}
	if observed != nil {
		if created != nil && created.Address != "" && created.Address != observed.Address {
			return nil, fmt.Errorf("cloudprovider: floating IP create returned %s but deterministic name resolved to %s", created.Address, observed.Address)
		}
		if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
			return nil, fmt.Errorf("cloudprovider: promote authoritatively observed floating IP %s: %w", observed.Address, clearErr)
		}
		return observed, nil
	}
	if standardNLBMutationKnownPreDispatch(createErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(fmt.Errorf("cloudprovider: create public floating IP: %w", createErr), clearErr)
	}
	if createErr != nil {
		return nil, fmt.Errorf(
			"cloudprovider: public floating IP create issued at %s remains ambiguous after error: %w",
			fenceValue.IssuedAt, createErr,
		)
	}
	return nil, fmt.Errorf(
		"cloudprovider: public floating IP create issued at %s is not yet observable; refusing a second create",
		fenceValue.IssuedAt,
	)
}

func (p *Provider) ensureStandardNLBFloatingIPAssignment(
	ctx context.Context,
	service *corev1.Service,
	loadBalancer *inspace.LoadBalancer,
	floatingIP *inspace.FloatingIP,
) (*inspace.FloatingIP, error) {
	if err := p.validateServiceFloatingIPIdentity(floatingIP, service); err != nil {
		return nil, err
	}
	payload := struct {
		Address          string `json:"address"`
		LoadBalancerUUID string `json:"loadBalancerUUID"`
	}{Address: floatingIP.Address, LoadBalancerUUID: loadBalancer.UUID}
	requestHash, err := standardNLBRequestHash(payload)
	if err != nil {
		return nil, err
	}
	desired := standardNLBMutationFence{
		Operation: standardNLBAssignFloatingIP, RequestHash: requestHash,
		ResourceName: floatingIP.Address, LoadBalancerUUID: loadBalancer.UUID,
	}
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil {
		return nil, err
	}
	if fence != nil {
		if fence.Operation != standardNLBAssignFloatingIP {
			return nil, fmt.Errorf("cloudprovider: %s mutation must resolve before assigning the public floating IP", fence.Operation)
		}
		if fence.ResourceName != floatingIP.Address || fence.LoadBalancerUUID != loadBalancer.UUID {
			return nil, errors.New("cloudprovider: floating IP assignment fence does not match the exact address and NLB UUID")
		}
	}
	if floatingIP.AssignedTo != "" {
		if err := validateServiceFloatingIPAssignment(floatingIP, loadBalancer.UUID, loadBalancer.PrivateAddress); err != nil {
			return nil, err
		}
		if fence != nil {
			if _, err := p.replaceStandardNLBFence(ctx, service, raw, nil); err != nil {
				return nil, fmt.Errorf("cloudprovider: promote visible floating IP assignment: %w", err)
			}
		}
		return floatingIP, nil
	}
	if err := validateServiceFloatingIPUnassigned(floatingIP); err != nil {
		return nil, err
	}
	fenceValue, raw, err := p.stageStandardNLBMutation(ctx, service, desired)
	if err != nil {
		return nil, err
	}
	if fenceValue.Phase == standardNLBPhaseIssued {
		return nil, fmt.Errorf(
			"cloudprovider: floating IP %s assignment to NLB %s issued at %s remains ambiguous; refusing a blind replay",
			floatingIP.Address, loadBalancer.UUID, fenceValue.IssuedAt,
		)
	}
	fenceValue, raw, err = p.issueStandardNLBMutation(ctx, service, fenceValue, raw)
	if err != nil {
		return nil, err
	}
	freshLoadBalancer, err := p.authorizeStandardNLBLoadBalancerIdentityPreDispatch(ctx, service, loadBalancer)
	if err != nil {
		return nil, fmt.Errorf("cloudprovider: reject floating-IP assignment at final pre-dispatch authority: %w", err)
	}
	freshFloatingIP, err := p.authorizeStandardNLBFloatingIPPreDispatch(ctx, service, floatingIP)
	if err != nil {
		return nil, fmt.Errorf("cloudprovider: reject floating-IP assignment at final pre-dispatch authority: %w", err)
	}
	if err := validateServiceFloatingIPUnassigned(freshFloatingIP); err != nil {
		return nil, fmt.Errorf("cloudprovider: reject floating-IP assignment after issue: %w", err)
	}
	if freshLoadBalancer.UUID != fenceValue.LoadBalancerUUID || freshFloatingIP.Address != fenceValue.ResourceName {
		return nil, errors.New("cloudprovider: floating-IP assignment payload changed after issue")
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fenceValue); err != nil {
		return nil, fmt.Errorf("cloudprovider: reject floating-IP assignment at final Service authority: %w", err)
	}
	_, mutationErr := p.api.AssignFloatingIP(ctx, p.config.Location, floatingIP.Address, loadBalancer.UUID, "load_balancer")
	observed, listErr := p.findOwnedFloatingIP(ctx, service)
	if listErr != nil {
		return nil, errors.Join(mutationErr, fmt.Errorf("cloudprovider: authoritative floating IP assignment readback: %w", listErr))
	}
	if observed != nil && observed.AssignedTo != "" {
		if err := validateServiceFloatingIPAssignment(observed, loadBalancer.UUID, loadBalancer.PrivateAddress); err != nil {
			return nil, err
		}
		if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
			return nil, fmt.Errorf("cloudprovider: promote authoritatively observed floating IP assignment: %w", clearErr)
		}
		return observed, nil
	}
	if observed != nil {
		if err := validateServiceFloatingIPUnassigned(observed); err != nil {
			return nil, err
		}
	}
	if standardNLBMutationKnownPreDispatch(mutationErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(mutationErr, clearErr)
	}
	if mutationErr != nil {
		return nil, fmt.Errorf(
			"cloudprovider: floating IP %s assignment to NLB %s remains ambiguous after error: %w",
			floatingIP.Address, loadBalancer.UUID, mutationErr,
		)
	}
	return nil, fmt.Errorf(
		"cloudprovider: floating IP %s assignment to NLB %s issued at %s is not yet observable",
		floatingIP.Address, loadBalancer.UUID, fenceValue.IssuedAt,
	)
}

func (p *Provider) EnsureLoadBalancer(ctx context.Context, _ string, service *corev1.Service, nodes []*corev1.Node) (*corev1.LoadBalancerStatus, error) {
	p.loadBalancerMu.Lock()
	defer p.loadBalancerMu.Unlock()

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
			fence, _, fenceErr := p.readStandardNLBFence(ctx, service)
			if fenceErr != nil {
				return nil, fenceErr
			}
			if fence == nil {
				return nil, cloud.ImplementedElsewhere
			}
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
	targets, err := p.targetUUIDs(ctx, service, nodes)
	if err != nil {
		return nil, err
	}
	rules := serviceRules(service)
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
	lb, created, err := p.ensureStandardNLBLoadBalancer(ctx, service, lb, request)
	if err != nil {
		return nil, err
	}
	if created {
		if err := p.validatePublicLoadBalancerAddress(ctx, service, lb); err != nil {
			return nil, err
		}
	}
	if !created {
		if err := p.reconcileLoadBalancer(ctx, service, lb, targets, rules); err != nil {
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
	p.loadBalancerMu.Lock()
	defer p.loadBalancerMu.Unlock()
	return p.updateLoadBalancer(ctx, service, nodes, false)
}

func (p *Provider) updateLoadBalancer(ctx context.Context, service *corev1.Service, nodes []*corev1.Node, allowMissing bool) error {
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
			fence, _, fenceErr := p.readStandardNLBFence(ctx, service)
			if fenceErr != nil {
				return fenceErr
			}
			if fence == nil {
				return cloud.ImplementedElsewhere
			}
		}
		return p.cleanupOwnedLoadBalancer(ctx, service, lb)
	}
	if err := validateServiceFloatingIPState(floatingIP, lb); err != nil {
		return err
	}
	if lb == nil {
		if allowMissing {
			// The provider-specific target controller can observe a Service or
			// EndpointSlice before the standard Service controller creates the
			// NLB. EnsureLoadBalancer will use the same target resolver.
			return nil
		}
		return errors.New("cloudprovider: managed public load balancer does not exist")
	}
	if err := p.validatePublicLoadBalancerAddress(ctx, service, lb); err != nil {
		return err
	}
	if err := validateService(service); err != nil {
		return err
	}
	targets, err := p.targetUUIDs(ctx, service, nodes)
	if err != nil {
		return err
	}
	if err := p.reconcileLoadBalancer(ctx, service, lb, targets, serviceRules(service)); err != nil {
		return err
	}
	_, err = p.ensurePublicFloatingIP(ctx, service, lb)
	return err
}

func (p *Provider) reconcileLoadBalancerTargets(ctx context.Context, service *corev1.Service, nodes []*corev1.Node) error {
	p.loadBalancerMu.Lock()
	defer p.loadBalancerMu.Unlock()
	return p.updateLoadBalancer(ctx, service, nodes, true)
}

func (p *Provider) EnsureLoadBalancerDeleted(ctx context.Context, _ string, service *corev1.Service) error {
	p.loadBalancerMu.Lock()
	defer p.loadBalancerMu.Unlock()

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
	floatingIP, err := p.findOwnedFloatingIP(ctx, service)
	if err != nil {
		return err
	}
	if err := p.resolveStandardNLBDeletionFence(ctx, service, lb, floatingIP); err != nil {
		return err
	}
	if err := p.cleanupOwnedFloatingIP(ctx, service, floatingIP, expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress); err != nil {
		return err
	}
	if lb == nil {
		return nil
	}
	requestHash, err := standardNLBRequestHash(struct {
		LoadBalancerUUID string `json:"loadBalancerUUID"`
	}{LoadBalancerUUID: lb.UUID})
	if err != nil {
		return err
	}
	desired := standardNLBMutationFence{
		Operation: standardNLBDeleteLoadBalancer, RequestHash: requestHash, LoadBalancerUUID: lb.UUID,
	}
	fence, raw, issue, err := p.issueStandardNLBRemoval(ctx, service, desired)
	if err != nil {
		return err
	}
	if !issue {
		return standardNLBRemovalPending(fence)
	}
	freshLoadBalancer, authorityErr := p.authorizeStandardNLBLoadBalancerIdentityPreDispatch(ctx, service, lb)
	if authorityErr != nil || freshLoadBalancer.UUID != fence.LoadBalancerUUID {
		return errors.Join(
			errors.New("cloudprovider: reject public NLB delete at final pre-dispatch authority"),
			authorityErr,
		)
	}
	if authorityErr := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); authorityErr != nil {
		return fmt.Errorf("cloudprovider: reject public NLB delete at final Service authority: %w", authorityErr)
	}
	deleteErr := p.api.DeleteLoadBalancer(ctx, p.config.Location, lb.UUID)
	if standardNLBMutationKnownPreDispatch(deleteErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return errors.Join(deleteErr, clearErr)
	}
	_, absent, readErr := p.readExactOwnedStandardNLB(ctx, service, lb.UUID)
	if readErr != nil {
		return errors.Join(
			standardNLBMutationError("delete public NLB", deleteErr),
			fmt.Errorf("cloudprovider: authoritative NLB delete readback: %w", readErr),
		)
	}
	complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, absent)
	if complete {
		return errors.Join(deleteErr, observeErr)
	}
	return errors.Join(deleteErr, observeErr, standardNLBRemovalPending(fence))
}

func (p *Provider) resolveStandardNLBDeletionFence(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	floatingIP *inspace.FloatingIP,
) error {
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil || fence == nil {
		return err
	}
	if fence.Phase == standardNLBPhaseIntent {
		_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return err
	}
	if standardNLBRemovalOperation(fence.Operation) {
		absent := false
		switch fence.Operation {
		case standardNLBDeleteLoadBalancer:
			_, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
		case standardNLBDeleteFloatingIP:
			_, exactAbsent, exactErr := p.readExactOwnedStandardNLBFloatingIP(ctx, service, fence.ResourceName)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
		case standardNLBUnassignFloatingIP:
			exactFloatingIP, exactAbsent, exactErr := p.readExactOwnedStandardNLBFloatingIP(ctx, service, fence.ResourceName)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
			if !exactAbsent {
				if exactFloatingIP.AssignedTo == "" {
					if err := validateServiceFloatingIPUnassigned(exactFloatingIP); err != nil {
						return err
					}
					absent = true
				} else {
					exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
					if exactErr != nil {
						return exactErr
					}
					if exactAbsent {
						return errors.New("cloudprovider: floating-IP unassign receipt no longer matches its exact NLB relation")
					}
					if err := validateServiceFloatingIPAssignment(exactFloatingIP, exactLB.UUID, exactLB.PrivateAddress); err != nil {
						return err
					}
				}
			}
		case standardNLBRemoveTarget:
			exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
			if !exactAbsent {
				visible, visibleErr := standardNLBTargetVisible(exactLB, fence.TargetUUID)
				if visibleErr != nil {
					return visibleErr
				}
				absent = !visible
			}
		case standardNLBRemoveRule:
			exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
			if !exactAbsent {
				absent = true
				for _, rule := range exactLB.ForwardingRules {
					if rule.UUID == fence.RuleUUID {
						absent = false
						break
					}
				}
			}
		}
		complete, observeErr := p.observeStandardNLBRemoval(ctx, service, *fence, absent)
		if observeErr != nil {
			return observeErr
		}
		if !complete {
			return standardNLBRemovalPending(*fence)
		}
		return nil
	}
	switch fence.Operation {
	case standardNLBCreateLoadBalancer:
		if lb == nil {
			return fmt.Errorf(
				"cloudprovider: public NLB create issued at %s remains ambiguous during Service cleanup; retaining the cleanup finalizer",
				fence.IssuedAt,
			)
		}
		if fence.ResourceName != p.loadBalancerName(service) {
			return errors.New("cloudprovider: visible NLB does not match its cleanup fence")
		}
	case standardNLBCreateFloatingIP:
		if floatingIP == nil {
			return fmt.Errorf(
				"cloudprovider: public floating IP create issued at %s remains ambiguous during Service cleanup; retaining the cleanup finalizer",
				fence.IssuedAt,
			)
		}
		if fence.ResourceName != p.floatingIPName(service) {
			return errors.New("cloudprovider: visible floating IP does not match its cleanup fence")
		}
	case standardNLBAssignFloatingIP:
		if floatingIP == nil || floatingIP.Address != fence.ResourceName {
			return fmt.Errorf("cloudprovider: floating IP assignment issued at %s remains ambiguous during Service cleanup; retaining the cleanup finalizer", fence.IssuedAt)
		}
		exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
		if exactErr != nil {
			return exactErr
		}
		if exactAbsent {
			return fmt.Errorf("cloudprovider: floating IP assignment issued at %s remains ambiguous during Service cleanup; retaining the cleanup finalizer", fence.IssuedAt)
		}
		if floatingIP.AssignedTo == "" {
			return fmt.Errorf("cloudprovider: floating IP assignment issued at %s remains ambiguous during Service cleanup; retaining the cleanup finalizer", fence.IssuedAt)
		}
		if err := validateServiceFloatingIPAssignment(floatingIP, exactLB.UUID, exactLB.PrivateAddress); err != nil {
			return err
		}
	case standardNLBAddTarget:
		exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
		if exactErr != nil {
			return exactErr
		}
		if exactAbsent {
			return fmt.Errorf("cloudprovider: add-target mutation issued at %s remains ambiguous during Service cleanup", fence.IssuedAt)
		}
		visible, visibleErr := standardNLBTargetVisible(exactLB, fence.TargetUUID)
		if visibleErr != nil {
			return visibleErr
		}
		if !visible {
			return fmt.Errorf("cloudprovider: add-target mutation issued at %s remains ambiguous during Service cleanup", fence.IssuedAt)
		}
	case standardNLBAddRule:
		exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
		if exactErr != nil {
			return exactErr
		}
		if exactAbsent {
			return fmt.Errorf("cloudprovider: add-rule mutation issued at %s remains ambiguous during Service cleanup", fence.IssuedAt)
		}
		visible, visibleErr := standardNLBRuleVisible(exactLB, inspace.LoadBalancerRule{
			Protocol: fence.Protocol, SourcePort: fence.SourcePort, TargetPort: fence.TargetPort,
		})
		if visibleErr != nil {
			return visibleErr
		}
		if !visible {
			return fmt.Errorf("cloudprovider: add-rule mutation issued at %s remains ambiguous during Service cleanup", fence.IssuedAt)
		}
	default:
		return fmt.Errorf("cloudprovider: unknown public NLB mutation %q during cleanup", fence.Operation)
	}
	_, err = p.replaceStandardNLBFence(ctx, service, raw, nil)
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

func (p *Provider) cleanupOwnedFloatingIP(
	ctx context.Context,
	service *corev1.Service,
	floatingIP *inspace.FloatingIP,
	expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress string,
) error {
	if floatingIP == nil {
		return nil
	}
	if floatingIP.AssignedTo != "" {
		if err := validateServiceFloatingIPAssignment(floatingIP, expectedLoadBalancerUUID, expectedLoadBalancerPrivateAddress); err != nil {
			return err
		}
		preIssueLoadBalancer, exactAbsent, err := p.readExactOwnedStandardNLB(ctx, service, expectedLoadBalancerUUID)
		if err != nil {
			return fmt.Errorf("cloudprovider: read exact NLB before floating-IP unassign issue: %w", err)
		}
		if exactAbsent || preIssueLoadBalancer.PrivateAddress != expectedLoadBalancerPrivateAddress {
			return errors.New("cloudprovider: exact owned NLB changed before floating-IP unassign issue")
		}
		address := floatingIP.Address
		requestHash, err := standardNLBRequestHash(struct {
			Address          string `json:"address"`
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{Address: address, LoadBalancerUUID: expectedLoadBalancerUUID})
		if err != nil {
			return err
		}
		desired := standardNLBMutationFence{
			Operation: standardNLBUnassignFloatingIP, RequestHash: requestHash,
			ResourceName: address, LoadBalancerUUID: expectedLoadBalancerUUID,
		}
		fence, raw, issue, err := p.issueStandardNLBRemoval(ctx, service, desired)
		if err != nil {
			return err
		}
		if !issue {
			return standardNLBRemovalPending(fence)
		}
		freshLoadBalancer, authorityErr := p.authorizeStandardNLBLoadBalancerIdentityPreDispatch(ctx, service, preIssueLoadBalancer)
		if authorityErr != nil {
			return fmt.Errorf("cloudprovider: reject floating-IP unassign at final NLB authority: %w", authorityErr)
		}
		freshFloatingIP, authorityErr := p.authorizeStandardNLBFloatingIPPreDispatch(ctx, service, floatingIP)
		if authorityErr != nil {
			return fmt.Errorf("cloudprovider: reject floating-IP unassign at final address authority: %w", authorityErr)
		}
		if err := validateServiceFloatingIPAssignment(
			freshFloatingIP,
			freshLoadBalancer.UUID,
			freshLoadBalancer.PrivateAddress,
		); err != nil {
			return fmt.Errorf("cloudprovider: reject floating-IP unassign after issue: %w", err)
		}
		if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); err != nil {
			return fmt.Errorf("cloudprovider: reject floating-IP unassign at final Service authority: %w", err)
		}
		_, unassignErr := p.api.UnassignFloatingIP(ctx, p.config.Location, address)
		if standardNLBMutationKnownPreDispatch(unassignErr) {
			_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return errors.Join(unassignErr, clearErr)
		}
		observed, exactAbsent, readErr := p.readExactOwnedStandardNLBFloatingIP(ctx, service, address)
		if readErr != nil {
			return errors.Join(
				standardNLBMutationError("unassign public NLB floating IP", unassignErr),
				fmt.Errorf("cloudprovider: authoritative floating IP unassign readback: %w", readErr),
			)
		}
		if exactAbsent {
			complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, true)
			if complete {
				return observeErr
			}
			return errors.Join(unassignErr, observeErr, standardNLBRemovalPending(fence))
		}
		if observed.Address != address {
			return fmt.Errorf("cloudprovider: owned floating IP changed from %s to %s during unassign readback", address, observed.Address)
		}
		if observed.AssignedTo != "" {
			_, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, false)
			return errors.Join(unassignErr, observeErr, standardNLBRemovalPending(fence))
		}
		if err := validateServiceFloatingIPUnassigned(observed); err != nil {
			return err
		}
		complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, true)
		if !complete {
			return errors.Join(unassignErr, observeErr, standardNLBRemovalPending(fence))
		}
		floatingIP = observed
	} else if err := validateServiceFloatingIPUnassigned(floatingIP); err != nil {
		return err
	}
	address := floatingIP.Address
	requestHash, err := standardNLBRequestHash(struct {
		Address string `json:"address"`
	}{Address: address})
	if err != nil {
		return err
	}
	desired := standardNLBMutationFence{
		Operation: standardNLBDeleteFloatingIP, RequestHash: requestHash, ResourceName: address,
	}
	fence, raw, issue, err := p.issueStandardNLBRemoval(ctx, service, desired)
	if err != nil {
		return err
	}
	if !issue {
		return standardNLBRemovalPending(fence)
	}
	freshFloatingIP, authorityErr := p.authorizeStandardNLBFloatingIPPreDispatch(ctx, service, floatingIP)
	if authorityErr != nil {
		return fmt.Errorf("cloudprovider: reject floating-IP delete at final pre-dispatch authority: %w", authorityErr)
	}
	if freshFloatingIP.Address != fence.ResourceName {
		return errors.New("cloudprovider: floating-IP delete payload changed after issue")
	}
	if err := validateServiceFloatingIPUnassigned(freshFloatingIP); err != nil {
		return fmt.Errorf("cloudprovider: reject assigned floating-IP delete after issue: %w", err)
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); err != nil {
		return fmt.Errorf("cloudprovider: reject floating-IP delete at final Service authority: %w", err)
	}
	deleteErr := p.api.DeleteFloatingIP(ctx, p.config.Location, address)
	if standardNLBMutationKnownPreDispatch(deleteErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return errors.Join(deleteErr, clearErr)
	}
	_, exactAbsent, readErr := p.readExactOwnedStandardNLBFloatingIP(ctx, service, address)
	if readErr != nil {
		return errors.Join(
			standardNLBMutationError("delete public NLB floating IP", deleteErr),
			fmt.Errorf("cloudprovider: authoritative floating IP delete readback: %w", readErr),
		)
	}
	complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, exactAbsent)
	if complete {
		return observeErr
	}
	return errors.Join(deleteErr, observeErr, standardNLBRemovalPending(fence))
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

// readExactOwnedStandardNLBFloatingIP scans the unfiltered address inventory,
// because the API exposes no exact-address GET. A removal is absent only when
// neither the fenced address nor the deterministic ownership name is active.
// Renames, account drift, and name reuse are positive conflicts and retain the
// receipt rather than becoming false negative evidence.
func (p *Provider) readExactOwnedStandardNLBFloatingIP(
	ctx context.Context,
	service *corev1.Service,
	address string,
) (*inspace.FloatingIP, bool, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.String() != address {
		return nil, false, errors.New("cloudprovider: exact public NLB floating-IP read requires a canonical global IPv4 address")
	}
	items, err := p.api.ListFloatingIPs(ctx, p.config.Location, nil)
	if err != nil {
		return nil, false, fmt.Errorf("cloudprovider: list exact public NLB floating IP %s: %w", address, err)
	}
	expectedName := p.floatingIPName(service)
	var exact *inspace.FloatingIP
	var named *inspace.FloatingIP
	for index := range items {
		item := &items[index]
		if item.IsDeleted {
			continue
		}
		if item.Address == address {
			if exact != nil {
				return nil, false, fmt.Errorf("cloudprovider: public floating IP address %s appears multiple times", address)
			}
			exact = item
		}
		if item.Name != expectedName {
			continue
		}
		if err := p.validateServiceFloatingIPIdentity(item, service); err != nil {
			return nil, false, err
		}
		if named != nil {
			return nil, false, fmt.Errorf("cloudprovider: multiple floating IPs have ownership name %q", expectedName)
		}
		named = item
	}
	if exact == nil {
		if named != nil {
			return nil, false, fmt.Errorf(
				"cloudprovider: fenced floating IP %s is absent but ownership name %q now resolves to %s",
				address, expectedName, named.Address,
			)
		}
		return nil, true, nil
	}
	if err := p.validateServiceFloatingIPIdentity(exact, service); err != nil {
		return nil, false, err
	}
	if named == nil || named.Address != address {
		return nil, false, fmt.Errorf("cloudprovider: exact floating IP %s is present but missing from its deterministic ownership name", address)
	}
	return exact, false, nil
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
	floatingIP, err = p.ensureStandardNLBPublicFloatingIP(ctx, service, floatingIP)
	if err != nil {
		return nil, err
	}
	return p.ensureStandardNLBFloatingIPAssignment(ctx, service, loadBalancer, floatingIP)
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

// readExactOwnedStandardNLB corroborates the receipt's immutable UUID through
// both the exact-resource endpoint and the deterministic-name list view. A
// negative observation is trustworthy only when GET returns 404 and the list
// contains neither that UUID nor the owned name. Conversely, an exact object
// that was renamed, moved, or billed elsewhere is positive drift, never
// absence; callers retain the receipt and refuse further mutations.
func (p *Provider) readExactOwnedStandardNLB(
	ctx context.Context,
	service *corev1.Service,
	loadBalancerUUID string,
) (*inspace.LoadBalancer, bool, error) {
	if !validNodeLoadBalancerCloudUUID(loadBalancerUUID) {
		return nil, false, errors.New("cloudprovider: exact public NLB read requires a canonical UUID")
	}
	exact, getErr := p.api.GetLoadBalancer(ctx, p.config.Location, loadBalancerUUID)
	exactAbsent := false
	if getErr != nil {
		if !inspace.IsNotFound(getErr) {
			return nil, false, fmt.Errorf("cloudprovider: read exact public NLB %s: %w", loadBalancerUUID, getErr)
		}
		exactAbsent = true
		exact = nil
	} else if exact == nil {
		return nil, false, fmt.Errorf("cloudprovider: exact public NLB %s returned an empty response", loadBalancerUUID)
	}

	items, listErr := p.api.ListLoadBalancers(ctx, p.config.Location)
	if listErr != nil {
		return nil, false, fmt.Errorf("cloudprovider: corroborate exact public NLB %s through list: %w", loadBalancerUUID, listErr)
	}
	expectedName := p.loadBalancerName(service)
	var named *inspace.LoadBalancer
	var exactInList *inspace.LoadBalancer
	for index := range items {
		item := &items[index]
		if item.IsDeleted {
			continue
		}
		if item.UUID == loadBalancerUUID {
			if exactInList != nil {
				return nil, false, fmt.Errorf("cloudprovider: exact public NLB UUID %s appears multiple times in list readback", loadBalancerUUID)
			}
			exactInList = item
		}
		if item.DisplayName != expectedName {
			continue
		}
		if err := p.validateOwnedLoadBalancerIdentity(service, item); err != nil {
			return nil, false, err
		}
		if named != nil {
			return nil, false, fmt.Errorf("cloudprovider: multiple load balancers have ownership name %q", expectedName)
		}
		named = item
	}

	if exactAbsent {
		if exactInList != nil {
			return nil, false, fmt.Errorf("cloudprovider: exact public NLB %s returned 404 but remains visible in list readback", loadBalancerUUID)
		}
		if named != nil {
			return nil, false, fmt.Errorf(
				"cloudprovider: exact public NLB %s is absent but ownership name %q now resolves to UUID %s",
				loadBalancerUUID, expectedName, named.UUID,
			)
		}
		return nil, true, nil
	}
	if exact.UUID != loadBalancerUUID {
		return nil, false, fmt.Errorf("cloudprovider: exact public NLB read returned UUID %s, expected %s", exact.UUID, loadBalancerUUID)
	}
	if err := p.validateOwnedLoadBalancerIdentity(service, exact); err != nil {
		return nil, false, err
	}
	if exactInList == nil || named == nil {
		return nil, false, fmt.Errorf("cloudprovider: exact public NLB %s is present but missing from its deterministic-name list readback", loadBalancerUUID)
	}
	if exactInList.UUID != loadBalancerUUID || named.UUID != loadBalancerUUID {
		return nil, false, fmt.Errorf("cloudprovider: public NLB exact and deterministic-name identities disagree for UUID %s", loadBalancerUUID)
	}
	return exact, false, nil
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
	if lb.BillingAccountID != p.config.BillingAccountID {
		return fmt.Errorf(
			"cloudprovider: load balancer ownership name %q belongs to billing account %d, not configured billing account %d",
			expectedName, lb.BillingAccountID, p.config.BillingAccountID,
		)
	}
	if lb.IsDeleted {
		return fmt.Errorf("cloudprovider: load balancer ownership name %q is deleted", expectedName)
	}
	if strings.TrimSpace(lb.UUID) == "" {
		return fmt.Errorf("cloudprovider: load balancer ownership name %q has no stable UUID", expectedName)
	}
	return nil
}

func standardNLBMutationStateEqual(before, after *inspace.LoadBalancer) bool {
	if before == nil || after == nil || before.UUID != after.UUID || before.DisplayName != after.DisplayName ||
		before.NetworkUUID != after.NetworkUUID ||
		before.PrivateAddress != after.PrivateAddress || before.IsDeleted != after.IsDeleted {
		return false
	}
	beforeTargets := append([]inspace.LoadBalancerTarget(nil), before.Targets...)
	afterTargets := append([]inspace.LoadBalancerTarget(nil), after.Targets...)
	sort.Slice(beforeTargets, func(i, j int) bool {
		return beforeTargets[i].TargetUUID+"\x00"+beforeTargets[i].TargetType < beforeTargets[j].TargetUUID+"\x00"+beforeTargets[j].TargetType
	})
	sort.Slice(afterTargets, func(i, j int) bool {
		return afterTargets[i].TargetUUID+"\x00"+afterTargets[i].TargetType < afterTargets[j].TargetUUID+"\x00"+afterTargets[j].TargetType
	})
	beforeRules := append([]inspace.LoadBalancerRule(nil), before.ForwardingRules...)
	afterRules := append([]inspace.LoadBalancerRule(nil), after.ForwardingRules...)
	sort.Slice(beforeRules, func(i, j int) bool {
		left := standardNLBInitialRuleKey(beforeRules[i].Protocol, beforeRules[i].SourcePort, beforeRules[i].TargetPort) + "\x00" + beforeRules[i].UUID
		right := standardNLBInitialRuleKey(beforeRules[j].Protocol, beforeRules[j].SourcePort, beforeRules[j].TargetPort) + "\x00" + beforeRules[j].UUID
		return left < right
	})
	sort.Slice(afterRules, func(i, j int) bool {
		left := standardNLBInitialRuleKey(afterRules[i].Protocol, afterRules[i].SourcePort, afterRules[i].TargetPort) + "\x00" + afterRules[i].UUID
		right := standardNLBInitialRuleKey(afterRules[j].Protocol, afterRules[j].SourcePort, afterRules[j].TargetPort) + "\x00" + afterRules[j].UUID
		return left < right
	})
	return reflect.DeepEqual(beforeTargets, afterTargets) && reflect.DeepEqual(beforeRules, afterRules)
}

func standardNLBFloatingIPMutationStateEqual(before, after *inspace.FloatingIP) bool {
	return before != nil && after != nil &&
		before.Name == after.Name && before.Address == after.Address &&
		before.BillingAccountID == after.BillingAccountID && before.Type == after.Type &&
		before.Enabled == after.Enabled && before.IsDeleted == after.IsDeleted && before.IsVirtual == after.IsVirtual &&
		before.AssignedTo == after.AssignedTo && before.AssignedToResourceType == after.AssignedToResourceType &&
		before.AssignedToPrivateIP == after.AssignedToPrivateIP
}

type standardNLBLiveDesiredState struct {
	service          *corev1.Service
	public           bool
	lifecycleCleanup bool
	targets          []string
	rules            []inspace.LoadBalancerRule
}

func (p *Provider) readStandardNLBLiveDesiredState(
	ctx context.Context,
	anchor *corev1.Service,
	fence standardNLBMutationFence,
) (standardNLBLiveDesiredState, error) {
	if p.standardNLBServiceStore == nil {
		return standardNLBLiveDesiredState{}, errors.New("cloudprovider: public NLB Service metadata store is unavailable")
	}
	current, err := p.standardNLBServiceStore.GetExact(ctx, anchor)
	if err != nil {
		return standardNLBLiveDesiredState{}, fmt.Errorf("cloudprovider: final public NLB Service authority: %w", err)
	}
	if err := validateExactStandardNLBService(anchor, current); err != nil {
		return standardNLBLiveDesiredState{}, err
	}
	storedFence, err := parseStandardNLBFence(current.Annotations[annotationStandardNLBMutation])
	if err != nil {
		return standardNLBLiveDesiredState{}, err
	}
	if storedFence == nil || *storedFence != fence || fence.Phase != standardNLBPhaseIssued {
		return standardNLBLiveDesiredState{}, errors.New("cloudprovider: public NLB issued receipt changed before cloud dispatch")
	}
	network, err := p.api.GetNetwork(ctx, p.config.Location, p.config.NetworkUUID)
	if err != nil {
		return standardNLBLiveDesiredState{}, fmt.Errorf("cloudprovider: final configured VPC authority: %w", err)
	}
	if network == nil || network.UUID != p.config.NetworkUUID {
		return standardNLBLiveDesiredState{}, errors.New("cloudprovider: configured VPC identity changed before cloud dispatch")
	}

	state := standardNLBLiveDesiredState{service: current}
	state.lifecycleCleanup = current.DeletionTimestamp != nil ||
		current.Spec.Type != corev1.ServiceTypeLoadBalancer || current.Spec.LoadBalancerClass != nil
	if !state.lifecycleCleanup {
		explicitPublic, publicErr := explicitPublicRequested(current)
		if publicErr != nil {
			return standardNLBLiveDesiredState{}, publicErr
		}
		state.lifecycleCleanup = !explicitPublic
		state.public = explicitPublic
	}
	needsLivePolicy := true
	switch fence.Operation {
	case standardNLBUnassignFloatingIP, standardNLBDeleteFloatingIP, standardNLBDeleteLoadBalancer:
		// These operations are authorized only by lifecycle cleanup or by an
		// exact reserved-private-address collision.  Collision remediation must
		// remain possible even when the still-public Service has an otherwise
		// invalid or transitional port policy.
		needsLivePolicy = false
	}
	if state.public && needsLivePolicy {
		if err := validateService(current); err != nil {
			return standardNLBLiveDesiredState{}, fmt.Errorf("cloudprovider: final public NLB Service policy: %w", err)
		}
		state.targets, err = p.freshStandardNLBTargetUUIDs(ctx, current)
		if err != nil {
			return standardNLBLiveDesiredState{}, err
		}
		state.rules = serviceRules(current)
	}
	return state, nil
}

func (p *Provider) standardNLBLoadBalancerCollision(lb *inspace.LoadBalancer) bool {
	if lb == nil {
		return false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(lb.PrivateAddress))
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return false
	}
	return address == p.controlPlaneVIP ||
		(p.privateLoadBalancerPoolStart.Compare(address) <= 0 && address.Compare(p.privateLoadBalancerPoolStop) <= 0)
}

func standardNLBDesiredRequest(
	p *Provider,
	service *corev1.Service,
	targets []string,
	rules []inspace.LoadBalancerRule,
) inspace.CreateLoadBalancerRequest {
	request := inspace.CreateLoadBalancerRequest{
		DisplayName: p.loadBalancerName(service), BillingAccountID: p.config.BillingAccountID,
		NetworkUUID: p.config.NetworkUUID, ReservePublicIP: false,
		Rules: rules, Targets: make([]inspace.LoadBalancerTarget, 0, len(targets)),
	}
	for _, uuid := range targets {
		request.Targets = append(request.Targets, inspace.LoadBalancerTarget{TargetUUID: uuid, TargetType: "vm"})
	}
	return request
}

func (p *Provider) authorizeStandardNLBTopology(
	ctx context.Context,
	state standardNLBLiveDesiredState,
) (*inspace.LoadBalancer, error) {
	lb, err := p.findOwnedLoadBalancer(ctx, state.service)
	if err != nil {
		return nil, err
	}
	if lb == nil {
		return nil, errors.New("cloudprovider: public NLB topology authority requires the exact owned load balancer")
	}
	if err := validateStandardNLBInitialPolicy(
		lb,
		standardNLBDesiredRequest(p, state.service, state.targets, state.rules),
	); err != nil {
		return nil, fmt.Errorf("cloudprovider: live public NLB topology no longer matches the Service: %w", err)
	}
	return lb, nil
}

func (p *Provider) authorizeStandardNLBCleanup(
	ctx context.Context,
	state standardNLBLiveDesiredState,
	fence standardNLBMutationFence,
) error {
	if state.lifecycleCleanup {
		return nil
	}
	if !state.public {
		return errors.New("cloudprovider: public NLB cleanup lacks a live lifecycle reason")
	}
	var lb *inspace.LoadBalancer
	var err error
	if fence.LoadBalancerUUID != "" {
		var absent bool
		lb, absent, err = p.readExactOwnedStandardNLB(ctx, state.service, fence.LoadBalancerUUID)
		if err == nil && absent {
			return errors.New("cloudprovider: collision cleanup load balancer is absent before dispatch")
		}
	} else {
		lb, err = p.findOwnedLoadBalancer(ctx, state.service)
	}
	if err != nil {
		return err
	}
	if !p.standardNLBLoadBalancerCollision(lb) {
		return errors.New("cloudprovider: live explicit-public Service no longer authorizes collision cleanup")
	}
	return nil
}

func (p *Provider) authorizeStandardNLBMutationPreDispatch(
	ctx context.Context,
	anchor *corev1.Service,
	fence standardNLBMutationFence,
) error {
	state, err := p.readStandardNLBLiveDesiredState(ctx, anchor, fence)
	if err != nil {
		return err
	}
	requirePublic := func() error {
		if !state.public || state.lifecycleCleanup || state.service.DeletionTimestamp != nil {
			return errors.New("cloudprovider: additive public NLB mutation is no longer desired by a live non-deleting Service")
		}
		return nil
	}
	requestHashMatches := func(value any) error {
		hash, hashErr := standardNLBRequestHash(value)
		if hashErr != nil {
			return hashErr
		}
		if hash != fence.RequestHash {
			return errors.New("cloudprovider: public NLB mutation payload changed after issue")
		}
		return nil
	}

	switch fence.Operation {
	case standardNLBCreateLoadBalancer:
		if err := requirePublic(); err != nil {
			return err
		}
		request := standardNLBDesiredRequest(p, state.service, state.targets, state.rules)
		if request.DisplayName != fence.ResourceName {
			return errors.New("cloudprovider: public NLB create name changed after issue")
		}
		if err := requestHashMatches(request); err != nil {
			return err
		}
		for _, uuid := range state.targets {
			if err := p.authorizeStandardNLBTargetVMPreDispatch(ctx, uuid); err != nil {
				return err
			}
		}
		return nil
	case standardNLBCreateFloatingIP:
		if err := requirePublic(); err != nil {
			return err
		}
		request := inspace.CreateFloatingIPRequest{
			Name: p.floatingIPName(state.service), BillingAccountID: p.config.BillingAccountID,
		}
		if request.Name != fence.ResourceName {
			return errors.New("cloudprovider: public floating-IP create name changed after issue")
		}
		if err := requestHashMatches(request); err != nil {
			return err
		}
		_, err := p.authorizeStandardNLBTopology(ctx, state)
		return err
	case standardNLBAssignFloatingIP:
		if err := requirePublic(); err != nil {
			return err
		}
		if err := requestHashMatches(struct {
			Address          string `json:"address"`
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{Address: fence.ResourceName, LoadBalancerUUID: fence.LoadBalancerUUID}); err != nil {
			return err
		}
		lb, err := p.authorizeStandardNLBTopology(ctx, state)
		if err != nil {
			return err
		}
		if lb.UUID != fence.LoadBalancerUUID {
			return errors.New("cloudprovider: public floating-IP assignment NLB changed after issue")
		}
		return nil
	case standardNLBAddTarget:
		if err := requirePublic(); err != nil {
			return err
		}
		if !desiredStandardNLBTarget(state.targets, fence.TargetUUID) {
			return errors.New("cloudprovider: add-target VM is no longer desired by the live Service")
		}
		if err := requestHashMatches(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
			TargetUUID       string `json:"targetUUID"`
		}{LoadBalancerUUID: fence.LoadBalancerUUID, TargetUUID: fence.TargetUUID}); err != nil {
			return err
		}
		return p.authorizeStandardNLBTargetVMPreDispatch(ctx, fence.TargetUUID)
	case standardNLBAddRule:
		if err := requirePublic(); err != nil {
			return err
		}
		if !desiredStandardNLBRule(state.rules, fence) {
			return errors.New("cloudprovider: add-rule policy is no longer desired by the live Service")
		}
		return requestHashMatches(struct {
			LoadBalancerUUID string                   `json:"loadBalancerUUID"`
			Rule             inspace.LoadBalancerRule `json:"rule"`
		}{LoadBalancerUUID: fence.LoadBalancerUUID, Rule: inspace.LoadBalancerRule{
			Protocol: fence.Protocol, SourcePort: fence.SourcePort, TargetPort: fence.TargetPort,
		}})
	case standardNLBRemoveTarget:
		if err := requestHashMatches(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
			TargetUUID       string `json:"targetUUID"`
		}{LoadBalancerUUID: fence.LoadBalancerUUID, TargetUUID: fence.TargetUUID}); err != nil {
			return err
		}
		if state.public && desiredStandardNLBTarget(state.targets, fence.TargetUUID) {
			return errors.New("cloudprovider: remove-target VM became desired again after issue")
		}
		return nil
	case standardNLBRemoveRule:
		if err := requestHashMatches(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
			RuleUUID         string `json:"ruleUUID"`
		}{LoadBalancerUUID: fence.LoadBalancerUUID, RuleUUID: fence.RuleUUID}); err != nil {
			return err
		}
		if !state.public {
			return nil
		}
		lb, absent, readErr := p.readExactOwnedStandardNLB(ctx, state.service, fence.LoadBalancerUUID)
		if readErr != nil {
			return readErr
		}
		if absent {
			return errors.New("cloudprovider: remove-rule NLB became absent after issue")
		}
		matches := 0
		var removing inspace.LoadBalancerRule
		for _, rule := range lb.ForwardingRules {
			if rule.UUID == fence.RuleUUID {
				matches++
				removing = rule
			}
		}
		if matches != 1 {
			return fmt.Errorf("cloudprovider: remove-rule UUID has %d exact rows after issue", matches)
		}
		for _, desired := range state.rules {
			protocol := removing.Protocol
			if protocol == "" {
				protocol = "TCP"
			}
			if desired.Protocol == protocol && desired.SourcePort == removing.SourcePort && desired.TargetPort == removing.TargetPort {
				return errors.New("cloudprovider: remove-rule policy became desired again after issue")
			}
		}
		return nil
	case standardNLBUnassignFloatingIP:
		if err := requestHashMatches(struct {
			Address          string `json:"address"`
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{Address: fence.ResourceName, LoadBalancerUUID: fence.LoadBalancerUUID}); err != nil {
			return err
		}
		return p.authorizeStandardNLBCleanup(ctx, state, fence)
	case standardNLBDeleteFloatingIP:
		if err := requestHashMatches(struct {
			Address string `json:"address"`
		}{Address: fence.ResourceName}); err != nil {
			return err
		}
		return p.authorizeStandardNLBCleanup(ctx, state, fence)
	case standardNLBDeleteLoadBalancer:
		if err := requestHashMatches(struct {
			LoadBalancerUUID string `json:"loadBalancerUUID"`
		}{LoadBalancerUUID: fence.LoadBalancerUUID}); err != nil {
			return err
		}
		return p.authorizeStandardNLBCleanup(ctx, state, fence)
	default:
		return fmt.Errorf("cloudprovider: unsupported public NLB mutation %q at final authority", fence.Operation)
	}
}

func (p *Provider) authorizeStandardNLBLoadBalancerPreDispatch(
	ctx context.Context,
	service *corev1.Service,
	before *inspace.LoadBalancer,
) (*inspace.LoadBalancer, error) {
	if before == nil || !validNodeLoadBalancerCloudUUID(before.UUID) {
		return nil, errors.New("cloudprovider: public NLB pre-dispatch authority requires a canonical prior UUID")
	}
	fresh, absent, err := p.readExactOwnedStandardNLB(ctx, service, before.UUID)
	if err != nil {
		return nil, err
	}
	if absent || !standardNLBMutationStateEqual(before, fresh) {
		return nil, errors.New("cloudprovider: public NLB changed after mutation issue; retaining the durable fence")
	}
	return fresh, nil
}

func (p *Provider) authorizeStandardNLBLoadBalancerIdentityPreDispatch(
	ctx context.Context,
	service *corev1.Service,
	before *inspace.LoadBalancer,
) (*inspace.LoadBalancer, error) {
	if before == nil || !validNodeLoadBalancerCloudUUID(before.UUID) {
		return nil, errors.New("cloudprovider: public NLB pre-dispatch identity requires a canonical prior UUID")
	}
	fresh, absent, err := p.readExactOwnedStandardNLB(ctx, service, before.UUID)
	if err != nil {
		return nil, err
	}
	if absent || fresh.UUID != before.UUID || fresh.DisplayName != before.DisplayName ||
		fresh.NetworkUUID != before.NetworkUUID ||
		fresh.PrivateAddress != before.PrivateAddress || fresh.IsDeleted != before.IsDeleted {
		return nil, errors.New("cloudprovider: public NLB identity changed after mutation issue; retaining the durable fence")
	}
	return fresh, nil
}

func (p *Provider) authorizeStandardNLBFloatingIPPreDispatch(
	ctx context.Context,
	service *corev1.Service,
	before *inspace.FloatingIP,
) (*inspace.FloatingIP, error) {
	if before == nil || before.Address == "" {
		return nil, errors.New("cloudprovider: floating-IP pre-dispatch authority requires a prior address")
	}
	fresh, absent, err := p.readExactOwnedStandardNLBFloatingIP(ctx, service, before.Address)
	if err != nil {
		return nil, err
	}
	if absent || !standardNLBFloatingIPMutationStateEqual(before, fresh) {
		return nil, errors.New("cloudprovider: public floating IP changed after mutation issue; retaining the durable fence")
	}
	return fresh, nil
}

func (p *Provider) authorizeStandardNLBTargetVMPreDispatch(ctx context.Context, vmUUID string) error {
	if !validNodeLoadBalancerCloudUUID(vmUUID) {
		return errors.New("cloudprovider: public NLB target pre-dispatch authority requires a canonical VM UUID")
	}
	vm, err := p.api.GetVM(ctx, p.config.Location, vmUUID)
	if err != nil {
		return fmt.Errorf("cloudprovider: read exact public NLB target VM %s at pre-dispatch: %w", vmUUID, err)
	}
	if vm == nil || vm.UUID != vmUUID || vm.BillingAccountID != p.config.BillingAccountID ||
		vm.NetworkUUID != p.config.NetworkUUID {
		return fmt.Errorf("cloudprovider: public NLB target VM %s lost exact account/VPC authority", vmUUID)
	}
	vms, err := p.api.ListVMs(ctx, p.config.Location)
	if err != nil {
		return fmt.Errorf("cloudprovider: list public NLB target VMs at pre-dispatch: %w", err)
	}
	listMatches := 0
	var listed *inspace.VM
	for index := range vms {
		if !strings.EqualFold(vms[index].UUID, vmUUID) {
			continue
		}
		listMatches++
		if vms[index].UUID == vmUUID {
			copy := vms[index]
			listed = &copy
		}
	}
	if listMatches != 1 || listed == nil || listed.BillingAccountID != p.config.BillingAccountID ||
		listed.NetworkUUID != p.config.NetworkUUID {
		return fmt.Errorf(
			"cloudprovider: public NLB target VM %s lacks unique exact list/account/VPC authority (rows=%d)",
			vmUUID,
			listMatches,
		)
	}
	network, err := p.api.GetNetwork(ctx, p.config.Location, p.config.NetworkUUID)
	if err != nil {
		return fmt.Errorf("cloudprovider: read public NLB target VPC at pre-dispatch: %w", err)
	}
	if network == nil || network.UUID != p.config.NetworkUUID {
		return errors.New("cloudprovider: public NLB target VPC identity changed at pre-dispatch")
	}
	memberships := 0
	exactMembership := false
	for _, candidate := range network.VMUUIDs {
		if !strings.EqualFold(candidate, vmUUID) {
			continue
		}
		memberships++
		exactMembership = exactMembership || candidate == vmUUID
	}
	if memberships != 1 || !exactMembership {
		return fmt.Errorf(
			"cloudprovider: public NLB target VM %s lacks unique exact VPC membership (memberships=%d)",
			vmUUID,
			memberships,
		)
	}
	return nil
}

func (p *Provider) authorizeStandardNLBTargetKubernetesPreDispatch(
	ctx context.Context,
	service *corev1.Service,
	vmUUID string,
) error {
	if p.kubeClient == nil {
		return errors.New("cloudprovider: Kubernetes client is unavailable for final public NLB target authority")
	}
	current, err := p.standardNLBServiceStore.GetExact(ctx, service)
	if err != nil {
		return fmt.Errorf("cloudprovider: re-read Service for final public NLB target authority: %w", err)
	}
	nodes, err := p.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("cloudprovider: list Nodes for final public NLB target authority: %w", err)
	}
	var exact *corev1.Node
	matches := 0
	for index := range nodes.Items {
		candidate := &nodes.Items[index]
		if candidate.Spec.ProviderID == "" {
			continue
		}
		identity, parseErr := providerid.Parse(candidate.Spec.ProviderID)
		if parseErr != nil || identity.Location != p.config.Location ||
			!strings.EqualFold(identity.UUID, vmUUID) {
			continue
		}
		matches++
		if identity.UUID == vmUUID && identity.String() == candidate.Spec.ProviderID {
			exact = candidate.DeepCopy()
		}
	}
	if matches != 1 || exact == nil || !loadBalancerNodeEligible(exact) {
		return fmt.Errorf(
			"cloudprovider: public NLB target VM %s lacks one exact live eligible Kubernetes Node (matches=%d)",
			vmUUID,
			matches,
		)
	}
	if current.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		return nil
	}
	selector := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: current.Name})
	slices, err := p.kubeClient.DiscoveryV1().EndpointSlices(current.Namespace).List(
		ctx,
		metav1.ListOptions{LabelSelector: selector.String()},
	)
	if err != nil {
		return fmt.Errorf("cloudprovider: list EndpointSlices for final public NLB target authority: %w", err)
	}
	for index := range slices.Items {
		if _, ready := readyEndpointNodes(&slices.Items[index])[exact.Name]; ready {
			return nil
		}
	}
	return fmt.Errorf(
		"cloudprovider: public NLB target VM %s lost its Ready local Service endpoint after mutation issue",
		vmUUID,
	)
}

// validateStandardNLBInitialPolicy is intentionally limited to promotion of
// an issued create receipt. Rules and targets legitimately change after
// creation, so the steady-state ownership predicate uses stable name, network,
// billing account, and UUID instead. During ambiguous create recovery, though,
// accepting a same-name object with a different initial policy would clear the
// only durable evidence tying that object to the exact POST.
func validateStandardNLBInitialPolicy(lb *inspace.LoadBalancer, request inspace.CreateLoadBalancerRequest) error {
	desiredRules := make(map[string]struct{}, len(request.Rules))
	for _, rule := range request.Rules {
		key := standardNLBInitialRuleKey(rule.Protocol, rule.SourcePort, rule.TargetPort)
		if _, duplicate := desiredRules[key]; duplicate {
			return errors.New("cloudprovider: public NLB create request contains duplicate forwarding rules")
		}
		desiredRules[key] = struct{}{}
	}
	observedRules := make(map[string]struct{}, len(lb.ForwardingRules))
	for _, rule := range lb.ForwardingRules {
		protocol := rule.Protocol
		if protocol == "" {
			// InSpace has historically omitted TCP in some relationship
			// readbacks. The paid NLB API supports TCP only, so this omission is
			// unambiguous while every port mapping remains exact.
			protocol = "TCP"
		}
		key := standardNLBInitialRuleKey(protocol, rule.SourcePort, rule.TargetPort)
		if _, wanted := desiredRules[key]; !wanted {
			return fmt.Errorf(
				"cloudprovider: visible NLB %s does not match the exact forwarding rules of its create fence",
				lb.UUID,
			)
		}
		if _, duplicate := observedRules[key]; duplicate {
			return fmt.Errorf("cloudprovider: visible NLB %s contains duplicate forwarding rules", lb.UUID)
		}
		observedRules[key] = struct{}{}
	}
	if len(observedRules) != len(desiredRules) {
		return fmt.Errorf(
			"cloudprovider: visible NLB %s is missing forwarding rules from its exact create fence",
			lb.UUID,
		)
	}

	desiredTargets := make(map[string]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		if target.TargetType != "vm" {
			return errors.New("cloudprovider: public NLB create request contains a non-VM target")
		}
		if _, duplicate := desiredTargets[target.TargetUUID]; duplicate {
			return errors.New("cloudprovider: public NLB create request contains duplicate VM targets")
		}
		desiredTargets[target.TargetUUID] = struct{}{}
	}
	observedTargets := make(map[string]struct{}, len(lb.Targets))
	for _, target := range lb.Targets {
		if target.TargetType != "" && target.TargetType != "vm" {
			return fmt.Errorf("cloudprovider: visible NLB %s contains non-VM target %s", lb.UUID, target.TargetUUID)
		}
		if _, wanted := desiredTargets[target.TargetUUID]; !wanted {
			return fmt.Errorf(
				"cloudprovider: visible NLB %s does not match the exact VM targets of its create fence",
				lb.UUID,
			)
		}
		if _, duplicate := observedTargets[target.TargetUUID]; duplicate {
			return fmt.Errorf("cloudprovider: visible NLB %s contains duplicate VM targets", lb.UUID)
		}
		observedTargets[target.TargetUUID] = struct{}{}
	}
	if len(observedTargets) != len(desiredTargets) {
		return fmt.Errorf(
			"cloudprovider: visible NLB %s is missing VM targets from its exact create fence",
			lb.UUID,
		)
	}
	return nil
}

func standardNLBInitialRuleKey(protocol string, sourcePort, targetPort int32) string {
	return protocol + "/" + strconv.FormatInt(int64(sourcePort), 10) + "/" + strconv.FormatInt(int64(targetPort), 10)
}

func standardNLBTargetVisible(lb *inspace.LoadBalancer, targetUUID string) (bool, error) {
	visible := false
	for _, target := range lb.Targets {
		if target.TargetUUID != targetUUID {
			continue
		}
		if target.TargetType != "" && target.TargetType != "vm" {
			return false, fmt.Errorf("cloudprovider: NLB target %s has unexpected type %q", targetUUID, target.TargetType)
		}
		// InSpace can return the same committed relationship more than once.
		// Normalize byte-equivalent VM rows as one set member; a conflicting row
		// above remains fail-closed.
		visible = true
	}
	return visible, nil
}

func standardNLBRuleVisible(lb *inspace.LoadBalancer, desired inspace.LoadBalancerRule) (bool, error) {
	visible := false
	for _, rule := range lb.ForwardingRules {
		if rule.SourcePort != desired.SourcePort {
			continue
		}
		if rule.TargetPort != desired.TargetPort || (rule.Protocol != "" && rule.Protocol != desired.Protocol) {
			return false, fmt.Errorf(
				"cloudprovider: NLB source port %d has conflicting %s rule to target port %d",
				desired.SourcePort, rule.Protocol, rule.TargetPort,
			)
		}
		// Identical rows are a duplicate representation of one relationship, not
		// evidence that another additive mutation is needed.
		visible = true
	}
	return visible, nil
}

func desiredStandardNLBTarget(targetUUIDs []string, targetUUID string) bool {
	for _, desired := range targetUUIDs {
		if desired == targetUUID {
			return true
		}
	}
	return false
}

func desiredStandardNLBRule(rules []inspace.LoadBalancerRule, fence standardNLBMutationFence) bool {
	for _, desired := range rules {
		if desired.Protocol == fence.Protocol && desired.SourcePort == fence.SourcePort && desired.TargetPort == fence.TargetPort {
			return true
		}
	}
	return false
}

func (p *Provider) resolvePendingStandardNLBAdd(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	targetUUIDs []string,
	rules []inspace.LoadBalancerRule,
) error {
	fence, raw, err := p.readStandardNLBFence(ctx, service)
	if err != nil || fence == nil {
		return err
	}
	if standardNLBRemovalOperation(fence.Operation) {
		if fence.Phase == standardNLBPhaseIntent {
			_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return err
		}
		absent := false
		switch fence.Operation {
		case standardNLBRemoveTarget:
			exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
			if !exactAbsent {
				visible, visibleErr := standardNLBTargetVisible(exactLB, fence.TargetUUID)
				if visibleErr != nil {
					return visibleErr
				}
				absent = !visible
			}
		case standardNLBRemoveRule:
			exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
			if exactErr != nil {
				return exactErr
			}
			absent = exactAbsent
			if !exactAbsent {
				absent = true
				for _, rule := range exactLB.ForwardingRules {
					if rule.UUID == fence.RuleUUID {
						absent = false
						break
					}
				}
			}
		default:
			// Deletion and floating-IP removals are resolved by the cleanup or
			// public-address reconcilers, never by forwarding-state updates.
			return standardNLBRemovalPending(*fence)
		}
		complete, observeErr := p.observeStandardNLBRemoval(ctx, service, *fence, absent)
		if observeErr != nil {
			return observeErr
		}
		if !complete {
			return standardNLBRemovalPending(*fence)
		}
		return nil
	}
	switch fence.Operation {
	case standardNLBCreateFloatingIP, standardNLBAssignFloatingIP:
		// Floating-IP creation is resolved by ensurePublicFloatingIP after the NLB
		// rule and target state has been checked.
		return nil
	case standardNLBCreateLoadBalancer:
		if fence.ResourceName != p.loadBalancerName(service) {
			return errors.New("cloudprovider: visible NLB does not match its pending create fence")
		}
		_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return err
	case standardNLBAddTarget:
		exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
		if exactErr != nil {
			return exactErr
		}
		if exactAbsent {
			return fmt.Errorf("cloudprovider: add-target fence belongs to absent NLB %s", fence.LoadBalancerUUID)
		}
		visible, visibleErr := standardNLBTargetVisible(exactLB, fence.TargetUUID)
		if visibleErr != nil {
			return visibleErr
		}
		if visible {
			_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return err
		}
		if fence.Phase == standardNLBPhaseIssued {
			return fmt.Errorf(
				"cloudprovider: add target %s to NLB %s issued at %s remains ambiguous; refusing a blind replay",
				fence.TargetUUID, fence.LoadBalancerUUID, fence.IssuedAt,
			)
		}
		if !desiredStandardNLBTarget(targetUUIDs, fence.TargetUUID) {
			_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return err
		}
		return nil
	case standardNLBAddRule:
		exactLB, exactAbsent, exactErr := p.readExactOwnedStandardNLB(ctx, service, fence.LoadBalancerUUID)
		if exactErr != nil {
			return exactErr
		}
		if exactAbsent {
			return fmt.Errorf("cloudprovider: add-rule fence belongs to absent NLB %s", fence.LoadBalancerUUID)
		}
		desired := inspace.LoadBalancerRule{Protocol: fence.Protocol, SourcePort: fence.SourcePort, TargetPort: fence.TargetPort}
		visible, visibleErr := standardNLBRuleVisible(exactLB, desired)
		if visibleErr != nil {
			return visibleErr
		}
		if visible {
			_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return err
		}
		if fence.Phase == standardNLBPhaseIssued {
			return fmt.Errorf(
				"cloudprovider: add rule %d->%d to NLB %s issued at %s remains ambiguous; refusing a blind replay",
				fence.SourcePort, fence.TargetPort, fence.LoadBalancerUUID, fence.IssuedAt,
			)
		}
		if !desiredStandardNLBRule(rules, *fence) {
			_, err := p.replaceStandardNLBFence(ctx, service, raw, nil)
			return err
		}
		return nil
	default:
		return fmt.Errorf("cloudprovider: unsupported pending public NLB mutation %q", fence.Operation)
	}
}

func (p *Provider) addStandardNLBTarget(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	targetUUID string,
) (*inspace.LoadBalancer, error) {
	payload := struct {
		LoadBalancerUUID string `json:"loadBalancerUUID"`
		TargetUUID       string `json:"targetUUID"`
	}{LoadBalancerUUID: lb.UUID, TargetUUID: targetUUID}
	requestHash, err := standardNLBRequestHash(payload)
	if err != nil {
		return nil, err
	}
	fence, raw, err := p.stageStandardNLBMutation(ctx, service, standardNLBMutationFence{
		Operation: standardNLBAddTarget, RequestHash: requestHash,
		LoadBalancerUUID: lb.UUID, TargetUUID: targetUUID,
	})
	if err != nil {
		return nil, err
	}
	if fence.Phase == standardNLBPhaseIssued {
		return nil, fmt.Errorf("cloudprovider: add target %s to NLB %s issued at %s remains ambiguous", targetUUID, lb.UUID, fence.IssuedAt)
	}
	fence, raw, err = p.issueStandardNLBMutation(ctx, service, fence, raw)
	if err != nil {
		return nil, err
	}
	fresh, err := p.authorizeStandardNLBLoadBalancerPreDispatch(ctx, service, lb)
	if err != nil {
		return nil, fmt.Errorf("cloudprovider: reject add-target at final NLB authority: %w", err)
	}
	visible, err := standardNLBTargetVisible(fresh, targetUUID)
	if err != nil || visible {
		return nil, errors.Join(err, errors.New("cloudprovider: add-target relation changed after issue"))
	}
	if err := p.authorizeStandardNLBTargetVMPreDispatch(ctx, targetUUID); err != nil {
		return nil, err
	}
	if err := p.authorizeStandardNLBTargetKubernetesPreDispatch(ctx, service, targetUUID); err != nil {
		return nil, err
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); err != nil {
		return nil, fmt.Errorf("cloudprovider: reject add-target at final Service authority: %w", err)
	}
	response, mutationErr := p.api.AddLoadBalancerTarget(ctx, p.config.Location, lb.UUID, targetUUID)
	observed, exactAbsent, readErr := p.readExactOwnedStandardNLB(ctx, service, lb.UUID)
	if readErr != nil {
		return nil, errors.Join(mutationErr, fmt.Errorf("cloudprovider: authoritative NLB target readback: %w", readErr))
	}
	if !exactAbsent {
		visible, visibleErr := standardNLBTargetVisible(observed, targetUUID)
		if visibleErr != nil {
			return nil, visibleErr
		}
		if visible {
			if response != nil && response.TargetUUID != "" && response.TargetUUID != targetUUID {
				return nil, fmt.Errorf("cloudprovider: add-target response names VM %s, expected %s", response.TargetUUID, targetUUID)
			}
			if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
				return nil, clearErr
			}
			return observed, nil
		}
	}
	if standardNLBMutationKnownPreDispatch(mutationErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(mutationErr, clearErr)
	}
	if mutationErr != nil {
		return nil, fmt.Errorf("cloudprovider: add target %s to NLB %s remains ambiguous after error: %w", targetUUID, lb.UUID, mutationErr)
	}
	return nil, fmt.Errorf("cloudprovider: add target %s to NLB %s issued at %s is not yet observable", targetUUID, lb.UUID, fence.IssuedAt)
}

func (p *Provider) addStandardNLBRule(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	rule inspace.LoadBalancerRule,
) (*inspace.LoadBalancer, error) {
	payload := struct {
		LoadBalancerUUID string                   `json:"loadBalancerUUID"`
		Rule             inspace.LoadBalancerRule `json:"rule"`
	}{LoadBalancerUUID: lb.UUID, Rule: rule}
	requestHash, err := standardNLBRequestHash(payload)
	if err != nil {
		return nil, err
	}
	fence, raw, err := p.stageStandardNLBMutation(ctx, service, standardNLBMutationFence{
		Operation: standardNLBAddRule, RequestHash: requestHash,
		LoadBalancerUUID: lb.UUID, Protocol: rule.Protocol, SourcePort: rule.SourcePort, TargetPort: rule.TargetPort,
	})
	if err != nil {
		return nil, err
	}
	if fence.Phase == standardNLBPhaseIssued {
		return nil, fmt.Errorf("cloudprovider: add rule %d->%d to NLB %s issued at %s remains ambiguous", rule.SourcePort, rule.TargetPort, lb.UUID, fence.IssuedAt)
	}
	fence, raw, err = p.issueStandardNLBMutation(ctx, service, fence, raw)
	if err != nil {
		return nil, err
	}
	fresh, err := p.authorizeStandardNLBLoadBalancerPreDispatch(ctx, service, lb)
	if err != nil {
		return nil, fmt.Errorf("cloudprovider: reject add-rule at final NLB authority: %w", err)
	}
	visible, err := standardNLBRuleVisible(fresh, rule)
	if err != nil || visible {
		return nil, errors.Join(err, errors.New("cloudprovider: add-rule relation changed after issue"))
	}
	if err := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); err != nil {
		return nil, fmt.Errorf("cloudprovider: reject add-rule at final Service authority: %w", err)
	}
	response, mutationErr := p.api.AddLoadBalancerRule(ctx, p.config.Location, lb.UUID, rule)
	observed, exactAbsent, readErr := p.readExactOwnedStandardNLB(ctx, service, lb.UUID)
	if readErr != nil {
		return nil, errors.Join(mutationErr, fmt.Errorf("cloudprovider: authoritative NLB rule readback: %w", readErr))
	}
	if !exactAbsent {
		visible, visibleErr := standardNLBRuleVisible(observed, rule)
		if visibleErr != nil {
			return nil, visibleErr
		}
		if visible {
			if response != nil && (response.SourcePort != rule.SourcePort || response.TargetPort != rule.TargetPort ||
				(response.Protocol != "" && response.Protocol != rule.Protocol)) {
				return nil, errors.New("cloudprovider: add-rule response does not match the fenced forwarding rule")
			}
			if _, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil); clearErr != nil {
				return nil, clearErr
			}
			return observed, nil
		}
	}
	if standardNLBMutationKnownPreDispatch(mutationErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(mutationErr, clearErr)
	}
	if mutationErr != nil {
		return nil, fmt.Errorf("cloudprovider: add rule %d->%d to NLB %s remains ambiguous after error: %w", rule.SourcePort, rule.TargetPort, lb.UUID, mutationErr)
	}
	return nil, fmt.Errorf("cloudprovider: add rule %d->%d to NLB %s issued at %s is not yet observable", rule.SourcePort, rule.TargetPort, lb.UUID, fence.IssuedAt)
}

func (p *Provider) removeStandardNLBTarget(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	targetUUID string,
) (*inspace.LoadBalancer, error) {
	payload := struct {
		LoadBalancerUUID string `json:"loadBalancerUUID"`
		TargetUUID       string `json:"targetUUID"`
	}{LoadBalancerUUID: lb.UUID, TargetUUID: targetUUID}
	requestHash, err := standardNLBRequestHash(payload)
	if err != nil {
		return nil, err
	}
	desired := standardNLBMutationFence{
		Operation: standardNLBRemoveTarget, RequestHash: requestHash,
		LoadBalancerUUID: lb.UUID, TargetUUID: targetUUID,
	}
	fence, raw, issue, err := p.issueStandardNLBRemoval(ctx, service, desired)
	if err != nil {
		return nil, err
	}
	if !issue {
		return nil, standardNLBRemovalPending(fence)
	}
	fresh, authorityErr := p.authorizeStandardNLBLoadBalancerPreDispatch(ctx, service, lb)
	if authorityErr != nil {
		return nil, fmt.Errorf("cloudprovider: reject remove-target at final NLB authority: %w", authorityErr)
	}
	preDispatchVisible, visibilityErr := standardNLBTargetVisible(fresh, targetUUID)
	if visibilityErr != nil || !preDispatchVisible {
		return nil, errors.Join(visibilityErr, errors.New("cloudprovider: remove-target relation changed after issue"))
	}
	if authorityErr := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); authorityErr != nil {
		return nil, fmt.Errorf("cloudprovider: reject remove-target at final Service authority: %w", authorityErr)
	}
	mutationErr := p.api.RemoveLoadBalancerTarget(ctx, p.config.Location, lb.UUID, targetUUID)
	if standardNLBMutationKnownPreDispatch(mutationErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(mutationErr, clearErr)
	}
	observed, exactAbsent, readErr := p.readExactOwnedStandardNLB(ctx, service, lb.UUID)
	if readErr != nil {
		return nil, errors.Join(mutationErr, fmt.Errorf("cloudprovider: authoritative NLB target-removal readback: %w", readErr))
	}
	visible := false
	if !exactAbsent {
		var visibilityErr error
		visible, visibilityErr = standardNLBTargetVisible(observed, targetUUID)
		if visibilityErr != nil {
			return nil, visibilityErr
		}
	}
	complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, !visible)
	if complete {
		return observed, observeErr
	}
	return nil, errors.Join(mutationErr, observeErr, standardNLBRemovalPending(fence))
}

func (p *Provider) removeStandardNLBRule(
	ctx context.Context,
	service *corev1.Service,
	lb *inspace.LoadBalancer,
	ruleUUID string,
) (*inspace.LoadBalancer, error) {
	payload := struct {
		LoadBalancerUUID string `json:"loadBalancerUUID"`
		RuleUUID         string `json:"ruleUUID"`
	}{LoadBalancerUUID: lb.UUID, RuleUUID: ruleUUID}
	requestHash, err := standardNLBRequestHash(payload)
	if err != nil {
		return nil, err
	}
	desired := standardNLBMutationFence{
		Operation: standardNLBRemoveRule, RequestHash: requestHash,
		LoadBalancerUUID: lb.UUID, RuleUUID: ruleUUID,
	}
	fence, raw, issue, err := p.issueStandardNLBRemoval(ctx, service, desired)
	if err != nil {
		return nil, err
	}
	if !issue {
		return nil, standardNLBRemovalPending(fence)
	}
	fresh, authorityErr := p.authorizeStandardNLBLoadBalancerPreDispatch(ctx, service, lb)
	if authorityErr != nil {
		return nil, fmt.Errorf("cloudprovider: reject remove-rule at final NLB authority: %w", authorityErr)
	}
	ruleVisible := false
	for _, current := range fresh.ForwardingRules {
		if current.UUID == ruleUUID {
			ruleVisible = true
			break
		}
	}
	if !ruleVisible {
		return nil, errors.New("cloudprovider: remove-rule relation changed after issue")
	}
	if authorityErr := p.authorizeStandardNLBMutationPreDispatch(ctx, service, fence); authorityErr != nil {
		return nil, fmt.Errorf("cloudprovider: reject remove-rule at final Service authority: %w", authorityErr)
	}
	mutationErr := p.api.RemoveLoadBalancerRule(ctx, p.config.Location, lb.UUID, ruleUUID)
	if standardNLBMutationKnownPreDispatch(mutationErr) {
		_, clearErr := p.replaceStandardNLBFence(ctx, service, raw, nil)
		return nil, errors.Join(mutationErr, clearErr)
	}
	observed, exactAbsent, readErr := p.readExactOwnedStandardNLB(ctx, service, lb.UUID)
	if readErr != nil {
		return nil, errors.Join(mutationErr, fmt.Errorf("cloudprovider: authoritative NLB rule-removal readback: %w", readErr))
	}
	visible := false
	if !exactAbsent {
		for _, current := range observed.ForwardingRules {
			if current.UUID == ruleUUID {
				visible = true
				break
			}
		}
	}
	complete, observeErr := p.observeStandardNLBRemoval(ctx, service, desired, !visible)
	if complete {
		return observed, observeErr
	}
	return nil, errors.Join(mutationErr, observeErr, standardNLBRemovalPending(fence))
}

func (p *Provider) reconcileLoadBalancer(ctx context.Context, service *corev1.Service, lb *inspace.LoadBalancer, targetUUIDs []string, rules []inspace.LoadBalancerRule) error {
	if err := p.resolvePendingStandardNLBAdd(ctx, service, lb, targetUUIDs, rules); err != nil {
		return err
	}
	desiredTargets := make(map[string]struct{}, len(targetUUIDs))
	for _, uuid := range targetUUIDs {
		desiredTargets[uuid] = struct{}{}
	}
	currentTargets := make(map[string]struct{}, len(lb.Targets))
	for _, target := range lb.Targets {
		currentTargets[target.TargetUUID] = struct{}{}
		if _, wanted := desiredTargets[target.TargetUUID]; !wanted {
			_, err := p.removeStandardNLBTarget(ctx, service, lb, target.TargetUUID)
			return err
		}
	}
	for _, uuid := range targetUUIDs {
		if _, exists := currentTargets[uuid]; !exists {
			refreshed, err := p.addStandardNLBTarget(ctx, service, lb, uuid)
			if err != nil {
				return err
			}
			lb = refreshed
			currentTargets[uuid] = struct{}{}
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
			_, err := p.removeStandardNLBRule(ctx, service, lb, current.UUID)
			return err
		}
	}
	for _, desired := range rules {
		if current, exists := currentRules[desired.SourcePort]; exists && current.TargetPort == desired.TargetPort {
			continue
		}
		refreshed, err := p.addStandardNLBRule(ctx, service, lb, desired)
		if err != nil {
			return err
		}
		lb = refreshed
		currentRules[desired.SourcePort] = desired
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

func (p *Provider) targetUUIDs(ctx context.Context, service *corev1.Service, nodes []*corev1.Node) ([]string, error) {
	var localNodes map[string]struct{}
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		if p.endpointSliceLister == nil || p.endpointSlicesSynced == nil || !p.endpointSlicesSynced() {
			return nil, errors.New("cloudprovider: externalTrafficPolicy=Local requires a synchronized EndpointSlice informer")
		}
		selector := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: service.Name})
		slices, err := p.endpointSliceLister.EndpointSlices(service.Namespace).List(selector)
		if err != nil {
			return nil, fmt.Errorf("cloudprovider: list EndpointSlices for Service %s/%s: %w", service.Namespace, service.Name, err)
		}
		localNodes = make(map[string]struct{})
		for _, slice := range slices {
			for nodeName := range readyEndpointNodes(slice) {
				localNodes[nodeName] = struct{}{}
			}
		}
	}
	return p.targetUUIDsFromNodes(ctx, nodes, localNodes)
}

func (p *Provider) freshStandardNLBTargetUUIDs(
	ctx context.Context,
	service *corev1.Service,
) ([]string, error) {
	if p.kubeClient == nil {
		return nil, errors.New("cloudprovider: Kubernetes client is unavailable for final public NLB target authority")
	}
	nodeList, err := p.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("cloudprovider: list Nodes for final public NLB desired state: %w", err)
	}
	nodes := make([]*corev1.Node, 0, len(nodeList.Items))
	for index := range nodeList.Items {
		nodes = append(nodes, &nodeList.Items[index])
	}
	var localNodes map[string]struct{}
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		selector := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: service.Name})
		slices, listErr := p.kubeClient.DiscoveryV1().EndpointSlices(service.Namespace).List(
			ctx,
			metav1.ListOptions{LabelSelector: selector.String()},
		)
		if listErr != nil {
			return nil, fmt.Errorf(
				"cloudprovider: list EndpointSlices for final public NLB desired state: %w",
				listErr,
			)
		}
		localNodes = make(map[string]struct{})
		for index := range slices.Items {
			for nodeName := range readyEndpointNodes(&slices.Items[index]) {
				localNodes[nodeName] = struct{}{}
			}
		}
	}
	return p.targetUUIDsFromNodes(ctx, nodes, localNodes)
}

func (p *Provider) targetUUIDsFromNodes(
	ctx context.Context,
	nodes []*corev1.Node,
	localNodes map[string]struct{},
) ([]string, error) {

	set := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if !loadBalancerNodeEligible(node) {
			continue
		}
		if localNodes != nil {
			if _, exists := localNodes[node.Name]; !exists {
				continue
			}
		}
		if node.Spec.ProviderID == "" {
			// A newly registered cloud node can become Ready immediately before
			// cloud-node-controller writes its provider ID. It is not a safe NLB
			// target until that stable identity exists.
			continue
		}
		id, err := providerid.Parse(node.Spec.ProviderID)
		if err != nil {
			klog.ErrorS(err, "skipping load-balancer node with malformed provider ID", "node", node.Name, "providerID", node.Spec.ProviderID)
			continue
		}
		if id.String() != node.Spec.ProviderID {
			return nil, fmt.Errorf("cloudprovider: Node %s has non-canonical providerID %q", node.Name, node.Spec.ProviderID)
		}
		if id.Location != p.config.Location {
			klog.ErrorS(nil, "skipping load-balancer node outside the configured location", "node", node.Name, "nodeLocation", id.Location, "loadBalancerLocation", p.config.Location)
			continue
		}
		if _, duplicate := set[id.UUID]; duplicate {
			return nil, fmt.Errorf("cloudprovider: multiple eligible Nodes claim exact InSpace VM %s", id.UUID)
		}
		vm, err := p.api.GetVM(ctx, id.Location, id.UUID)
		if err != nil {
			return nil, fmt.Errorf("cloudprovider: read exact NLB target VM %s for Node %s: %w", id.UUID, node.Name, err)
		}
		if vm == nil || vm.UUID != id.UUID {
			return nil, fmt.Errorf("cloudprovider: exact NLB target VM identity does not match providerID for Node %s", node.Name)
		}
		if vm.BillingAccountID != p.config.BillingAccountID {
			return nil, fmt.Errorf(
				"cloudprovider: NLB target VM %s for Node %s belongs to billing account %d, expected %d",
				id.UUID, node.Name, vm.BillingAccountID, p.config.BillingAccountID,
			)
		}
		if vm.NetworkUUID != p.config.NetworkUUID {
			return nil, fmt.Errorf(
				"cloudprovider: NLB target VM %s for Node %s belongs to network %q, expected %q",
				id.UUID, node.Name, vm.NetworkUUID, p.config.NetworkUUID,
			)
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

func loadBalancerNodeEligible(node *corev1.Node) bool {
	if node == nil || !node.DeletionTimestamp.IsZero() || nodeExcludedFromLoadBalancers(node) || nodeHasControlPlaneRole(node) {
		return false
	}
	for _, taint := range node.Spec.Taints {
		if taint.Key == clusterAutoscalerDeletionTaint || taint.Key == karpenterDisruptionTaint {
			return false
		}
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func nodeHasControlPlaneRole(node *corev1.Node) bool {
	if node == nil {
		return false
	}
	_, controlPlane := node.Labels[nodeRoleControlPlaneLabel]
	_, legacyMaster := node.Labels[nodeRoleMasterLabel]
	return controlPlane || legacyMaster
}

func nodeExcludedFromLoadBalancers(node *corev1.Node) bool {
	value, exists := node.Labels[corev1.LabelNodeExcludeBalancers]
	if !exists {
		return false
	}
	excluded, err := strconv.ParseBool(value)
	return err != nil || excluded
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
	_ cloud.InformerUser = (*Provider)(nil)
	_ cloud.InstancesV2  = (*Provider)(nil)
	_ cloud.LoadBalancer = (*Provider)(nil)
)
