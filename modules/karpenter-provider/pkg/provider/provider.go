package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/operatorpkg/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"
	"sigs.k8s.io/karpenter/pkg/scheduling"
	"sigs.k8s.io/karpenter/pkg/utils/resources"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/providerid"
)

const (
	AnnotationNodeClassHash  = "karpenter.inspace.cloud/nodeclass-hash"
	AnnotationBootstrapHash  = "karpenter.inspace.cloud/bootstrap-hash"
	AnnotationVMState        = "karpenter.inspace.cloud/vm-state"
	AnnotationPublicIPv4     = "karpenter.inspace.cloud/public-ipv4"
	AnnotationFloatingIP     = "karpenter.inspace.cloud/floating-ip-name"
	AnnotationBillingAccount = "karpenter.inspace.cloud/billing-account-id"
	AnnotationNodeName       = "karpenter.inspace.cloud/node-name"
	DriftReasonNodeClass     = cloudprovider.DriftReason("NodeClassDrifted")
	ProviderSchemaVersion    = "inspace-provider-v2"
)

var _ cloudprovider.CloudProvider = (*CloudProvider)(nil)

type Options struct {
	ClusterName             string
	DefaultNodeClassName    string
	Location                string
	NetworkUUID             string
	ControlPlaneVIP         string
	PrivateLoadBalancerPool inspacev1.PrivateLoadBalancerPool
}

type CloudProvider struct {
	cloud    cloudapi.Cloud
	resolver NodeClassResolver
	opts     Options
}

func New(cloud cloudapi.Cloud, resolver NodeClassResolver, opts Options) (*CloudProvider, error) {
	if cloud == nil || resolver == nil {
		return nil, fmt.Errorf("cloud and NodeClass resolver are required")
	}
	if opts.ClusterName == "" || opts.DefaultNodeClassName == "" || opts.NetworkUUID == "" || opts.ControlPlaneVIP == "" {
		return nil, fmt.Errorf("cluster name, default NodeClass name, network UUID, and control-plane VIP are required")
	}
	if messages := k8svalidation.IsDNS1123Label(opts.ClusterName); len(messages) != 0 {
		return nil, fmt.Errorf("cluster name %q must be a DNS-1123 hostname label: %s", opts.ClusterName, strings.Join(messages, "; "))
	}
	if err := inspacev1.ValidateNetworkUUID(opts.NetworkUUID); err != nil {
		return nil, fmt.Errorf("controller network UUID: %w", err)
	}
	controlPlaneVIP, err := inspacev1.ParseControlPlaneVIP(opts.ControlPlaneVIP)
	if err != nil {
		return nil, fmt.Errorf("controller control-plane VIP: %w", err)
	}
	opts.ControlPlaneVIP = controlPlaneVIP.String()
	if err := opts.PrivateLoadBalancerPool.ValidateForSupervisor(controlPlaneVIP); err != nil {
		return nil, fmt.Errorf("controller private load-balancer pool: %w", err)
	}
	if opts.Location == "" {
		opts.Location = inspacev1.LocationBangkok
	}
	return &CloudProvider{cloud: cloud, resolver: resolver, opts: opts}, nil
}

func (p *CloudProvider) Create(ctx context.Context, nodeClaim *karpv1.NodeClaim) (*karpv1.NodeClaim, error) {
	workerName, err := workerNodeName(p.opts.ClusterName, nodeClaim)
	if err != nil {
		return nil, fmt.Errorf("deriving worker node name: %w", err)
	}
	nodeClass, err := p.resolveNodeClass(ctx, nodeClaim.Spec.NodeClassRef)
	if err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	if errs := nodeClass.Validate(); len(errs) != 0 {
		return nil, cloudprovider.NewNodeClassNotReadyError(errs.ToAggregate())
	}
	if err := p.validateNodeClassControllerContract(nodeClass); err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	if err := ensureNodeClassReady(nodeClass); err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	controlPlaneVIP, err := nodeClass.Spec.RKE2.ServerVIP()
	if err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	instanceTypes, err := instanceTypesFor(nodeClass)
	if err != nil {
		return nil, err
	}
	instanceType, offering, err := selectInstanceType(nodeClaim, instanceTypes)
	if err != nil {
		return nil, err
	}
	labels := resolvedLabels(nodeClaim.Labels, instanceType, offering)
	token, err := p.resolver.ResolveAgentToken(ctx, nodeClass)
	if err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	userData, err := bootstrap.RenderCloudInit(bootstrap.Config{
		NodeName:         workerName,
		Server:           nodeClass.Spec.RKE2.Server,
		Token:            token,
		RKE2Version:      nodeClass.Spec.RKE2.Version,
		Labels:           labels,
		Taints:           append(append([]corev1.Taint{}, nodeClaim.Spec.Taints...), nodeClaim.Spec.StartupTaints...),
		AdditionalScript: nodeClass.Spec.AdditionalUserData,
	})
	if err != nil {
		return nil, fmt.Errorf("rendering worker bootstrap: %w", err)
	}
	hostPoolUUID, _ := nodeClass.Spec.HostPoolSelector.UUID()
	idempotencyKey := string(nodeClaim.UID)
	if idempotencyKey == "" {
		idempotencyKey = nodeClaim.Name
	}
	memoryGiB := int(instanceType.Capacity.Memory().Value() / (1024 * 1024 * 1024))
	request := cloudapi.CreateVMRequest{
		IdempotencyKey:               idempotencyKey,
		Name:                         workerName,
		ClusterName:                  p.opts.ClusterName,
		BillingAccountID:             nodeClass.Spec.BillingAccountID,
		NodeClaimName:                nodeClaim.Name,
		Location:                     nodeClass.Spec.Location,
		NetworkUUID:                  nodeClass.Spec.NetworkUUID,
		ControlPlaneVIP:              controlPlaneVIP.String(),
		PrivateLoadBalancerPoolStart: nodeClass.Spec.PrivateLoadBalancerPool.Start,
		PrivateLoadBalancerPoolStop:  nodeClass.Spec.PrivateLoadBalancerPool.Stop,
		FirewallUUID:                 nodeClass.Spec.FirewallUUID,
		OSName:                       nodeClass.Spec.ImageSelector.OSName,
		OSVersion:                    nodeClass.Spec.ImageSelector.OSVersion,
		HostPoolUUID:                 hostPoolUUID,
		HostClass:                    nodeClass.Spec.HostPoolSelector.Class,
		InstanceType:                 instanceType.Name,
		VCPU:                         int(instanceType.Capacity.Cpu().Value()),
		MemoryGiB:                    memoryGiB,
		RootDiskGiB:                  nodeClass.Spec.RootDiskGiB,
		PublicIPv4:                   nodeClass.Spec.ReservePublicIPv4,
		SSHUsername:                  nodeClass.Spec.SSHUsername,
		SSHPublicKey:                 nodeClass.Spec.SSHPublicKey,
		CloudInitJSON:                userData,
		SpecHash:                     NodeClassHash(nodeClass),
		BootstrapHash:                BootstrapHash(nodeClass),
	}
	vm, err := p.cloud.CreateVM(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("creating InSpace VM: %w", err)
	}
	created := nodeClaim.DeepCopy()
	created.Labels = labels
	if created.Annotations == nil {
		created.Annotations = map[string]string{}
	}
	created.Annotations[AnnotationNodeClassHash] = NodeClassHash(nodeClass)
	created.Annotations[AnnotationBootstrapHash] = BootstrapHash(nodeClass)
	created.Annotations[AnnotationVMState] = string(vm.State)
	created.Annotations[AnnotationPublicIPv4] = vm.PublicIPv4
	created.Annotations[AnnotationFloatingIP] = vm.FloatingIPName
	created.Annotations[AnnotationBillingAccount] = strconv.FormatInt(vm.BillingAccountID, 10)
	created.Annotations[AnnotationNodeName] = vm.Name
	created.Status = karpv1.NodeClaimStatus{
		ProviderID:  providerid.New(vm.Location, vm.UUID),
		ImageID:     vm.ImageID(),
		Capacity:    copyResourceList(instanceType.Capacity),
		Allocatable: copyResourceList(instanceType.Allocatable()),
	}
	return created, nil
}

func (p *CloudProvider) Delete(ctx context.Context, nodeClaim *karpv1.NodeClaim) error {
	id, err := providerid.Parse(nodeClaim.Status.ProviderID)
	if err != nil {
		return fmt.Errorf("parsing provider ID for deletion: %w", err)
	}
	deleteIdentity := cloudapi.DeleteVMIdentity{
		FloatingIPName: nodeClaim.Annotations[AnnotationFloatingIP],
		PublicIPv4:     nodeClaim.Annotations[AnnotationPublicIPv4],
	}
	if value := nodeClaim.Annotations[AnnotationBillingAccount]; value != "" {
		billingAccountID, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || billingAccountID <= 0 {
			return fmt.Errorf("durable billing-account annotation for deletion must be a positive decimal integer: %q", value)
		}
		deleteIdentity.BillingAccountID = billingAccountID
	}
	if err := p.cloud.DeleteVM(ctx, id.Location, id.VMUUID, p.opts.ClusterName, nodeClaim.Name, deleteIdentity); err != nil {
		if errors.Is(err, cloudapi.ErrNotFound) {
			return cloudprovider.NewNodeClaimNotFoundError(fmt.Errorf("VM %s no longer exists", id.VMUUID))
		}
		return fmt.Errorf("deleting VM %s: %w", id.VMUUID, err)
	}
	return nil
}

func (p *CloudProvider) Get(ctx context.Context, value string) (*karpv1.NodeClaim, error) {
	id, err := providerid.Parse(value)
	if err != nil {
		return nil, cloudprovider.NewNodeClaimNotFoundError(err)
	}
	vm, err := p.cloud.GetVM(ctx, id.Location, id.VMUUID, p.opts.ClusterName)
	if err != nil {
		if errors.Is(err, cloudapi.ErrNotFound) {
			return nil, cloudprovider.NewNodeClaimNotFoundError(fmt.Errorf("VM %s no longer exists", id.VMUUID))
		}
		return nil, err
	}
	if vm.ClusterName != p.opts.ClusterName {
		return nil, cloudprovider.NewNodeClaimNotFoundError(fmt.Errorf("VM is not owned by cluster %q", p.opts.ClusterName))
	}
	if vm.Location != id.Location {
		return nil, cloudprovider.NewNodeClaimNotFoundError(fmt.Errorf("VM location %q does not match provider ID location %q", vm.Location, id.Location))
	}
	if err := p.validateVMControllerContract(vm); err != nil {
		return nil, err
	}
	return nodeClaimFromVM(vm), nil
}

func (p *CloudProvider) List(ctx context.Context) ([]*karpv1.NodeClaim, error) {
	vms, err := p.cloud.ListVMs(ctx, p.opts.Location, p.opts.ClusterName)
	if err != nil {
		return nil, err
	}
	result := make([]*karpv1.NodeClaim, 0, len(vms))
	for _, vm := range vms {
		if err := p.validateVMControllerContract(vm); err != nil {
			return nil, err
		}
		result = append(result, nodeClaimFromVM(vm))
	}
	return result, nil
}

func (p *CloudProvider) GetInstanceTypes(ctx context.Context, nodePool *karpv1.NodePool) ([]*cloudprovider.InstanceType, error) {
	name := p.opts.DefaultNodeClassName
	if nodePool != nil && nodePool.Spec.Template.Spec.NodeClassRef != nil {
		ref := nodePool.Spec.Template.Spec.NodeClassRef
		if ref.Group != inspacev1.Group || ref.Kind != inspacev1.Kind {
			return nil, fmt.Errorf("unsupported NodeClass %s/%s", ref.Group, ref.Kind)
		}
		name = ref.Name
	}
	nodeClass, err := p.resolver.GetNodeClass(ctx, name)
	if err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	if errs := nodeClass.Validate(); len(errs) != 0 {
		return nil, cloudprovider.NewNodeClassNotReadyError(errs.ToAggregate())
	}
	if err := p.validateNodeClassControllerContract(nodeClass); err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	return instanceTypesFor(nodeClass)
}

func (p *CloudProvider) IsDrifted(ctx context.Context, nodeClaim *karpv1.NodeClaim) (cloudprovider.DriftReason, error) {
	nodeClass, err := p.resolveNodeClass(ctx, nodeClaim.Spec.NodeClassRef)
	if err != nil {
		return "", err
	}
	if err := p.validateNodeClassControllerContract(nodeClass); err != nil {
		return "", cloudprovider.NewNodeClassNotReadyError(err)
	}
	if nodeClaim.Annotations[AnnotationNodeClassHash] != "" && nodeClaim.Annotations[AnnotationNodeClassHash] != NodeClassHash(nodeClass) {
		return DriftReasonNodeClass, nil
	}
	if nodeClaim.Annotations[AnnotationBootstrapHash] != "" && nodeClaim.Annotations[AnnotationBootstrapHash] != BootstrapHash(nodeClass) {
		return DriftReasonNodeClass, nil
	}
	if nodeClaim.Status.ImageID != "" && nodeClaim.Status.ImageID != nodeClass.Spec.ImageSelector.ID() {
		return DriftReasonNodeClass, nil
	}
	return "", nil
}

func (p *CloudProvider) validateNodeClassControllerContract(nodeClass *inspacev1.InSpaceNodeClass) error {
	if nodeClass == nil {
		return fmt.Errorf("NodeClass is required")
	}
	if nodeClass.Spec.ClusterName != p.opts.ClusterName {
		return fmt.Errorf("NodeClass cluster %q does not match provider cluster %q", nodeClass.Spec.ClusterName, p.opts.ClusterName)
	}
	if nodeClass.Spec.Location != p.opts.Location {
		return fmt.Errorf("NodeClass location %q does not match provider location %q", nodeClass.Spec.Location, p.opts.Location)
	}
	if nodeClass.Spec.NetworkUUID != p.opts.NetworkUUID {
		return fmt.Errorf("NodeClass network %q does not match controller network %q", nodeClass.Spec.NetworkUUID, p.opts.NetworkUUID)
	}
	controlPlaneVIP, err := nodeClass.Spec.RKE2.ServerVIP()
	if err != nil {
		return err
	}
	if controlPlaneVIP.String() != p.opts.ControlPlaneVIP {
		return fmt.Errorf("NodeClass control-plane VIP %q does not match controller control-plane VIP %q", controlPlaneVIP, p.opts.ControlPlaneVIP)
	}
	if nodeClass.Spec.PrivateLoadBalancerPool != p.opts.PrivateLoadBalancerPool {
		return fmt.Errorf("NodeClass private load-balancer pool %+v does not match controller pool %+v", nodeClass.Spec.PrivateLoadBalancerPool, p.opts.PrivateLoadBalancerPool)
	}
	return nil
}

func (p *CloudProvider) validateVMControllerContract(vm *cloudapi.VM) error {
	if vm == nil {
		return fmt.Errorf("cloud VM is required")
	}
	if vm.NetworkUUID != p.opts.NetworkUUID || vm.ControlPlaneVIP != p.opts.ControlPlaneVIP ||
		vm.PrivateLoadBalancerPoolStart != p.opts.PrivateLoadBalancerPool.Start || vm.PrivateLoadBalancerPoolStop != p.opts.PrivateLoadBalancerPool.Stop {
		return fmt.Errorf("cloud VM %s network, control-plane VIP, or private load-balancer pool does not match controller configuration", vm.UUID)
	}
	return nil
}

func (p *CloudProvider) RepairPolicies() []cloudprovider.RepairPolicy { return nil }
func (p *CloudProvider) Name() string                                 { return "inspace" }
func (p *CloudProvider) GetSupportedNodeClasses() []status.Object {
	return []status.Object{&inspacev1.InSpaceNodeClass{}}
}

func (p *CloudProvider) resolveNodeClass(ctx context.Context, ref *karpv1.NodeClassReference) (*inspacev1.InSpaceNodeClass, error) {
	if ref == nil {
		return nil, fmt.Errorf("NodeClassRef is required")
	}
	if ref.Group != inspacev1.Group || ref.Kind != inspacev1.Kind {
		return nil, fmt.Errorf("unsupported NodeClass %s/%s", ref.Group, ref.Kind)
	}
	return p.resolver.GetNodeClass(ctx, ref.Name)
}

func ensureNodeClassReady(nodeClass *inspacev1.InSpaceNodeClass) error {
	if !nodeClass.StatusConditions(status.WithObservedOnly()).IsTrue(status.ConditionReady) {
		return fmt.Errorf("InSpaceNodeClass %q is not Ready", nodeClass.Name)
	}
	if nodeClass.Status.ObservedGeneration != nodeClass.Generation || nodeClass.Status.ObservedSpecHash != NodeClassHash(nodeClass) {
		return fmt.Errorf("InSpaceNodeClass %q readiness is stale", nodeClass.Name)
	}
	return nil
}

func instanceTypesFor(nodeClass *inspacev1.InSpaceNodeClass) ([]*cloudprovider.InstanceType, error) {
	return catalog.New(catalog.Options{
		Location:    nodeClass.Spec.Location,
		HostClass:   nodeClass.Spec.HostPoolSelector.Class,
		RootDiskGiB: nodeClass.Spec.RootDiskGiB,
	})
}

func selectInstanceType(nodeClaim *karpv1.NodeClaim, instanceTypes []*cloudprovider.InstanceType) (*cloudprovider.InstanceType, *cloudprovider.Offering, error) {
	requirements := scheduling.NewNodeSelectorRequirementsWithMinValues(nodeClaim.Spec.Requirements...)
	type candidate struct {
		instanceType *cloudprovider.InstanceType
		offering     *cloudprovider.Offering
	}
	var candidates []candidate
	for _, instanceType := range instanceTypes {
		if !requirements.IsCompatible(instanceType.Requirements, scheduling.AllowUndefinedWellKnownLabels) || !resources.Fits(nodeClaim.Spec.Resources.Requests, instanceType.Allocatable()) {
			continue
		}
		compatible := instanceType.Offerings.Available().Compatible(requirements)
		if len(compatible) == 0 {
			continue
		}
		candidates = append(candidates, candidate{instanceType: instanceType, offering: compatible.Cheapest()})
	}
	if len(candidates) == 0 {
		return nil, nil, cloudprovider.NewInsufficientCapacityError(fmt.Errorf("no InSpace instance variant satisfies NodeClaim %q", nodeClaim.Name))
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].offering.Price == candidates[j].offering.Price {
			return candidates[i].instanceType.Name < candidates[j].instanceType.Name
		}
		return candidates[i].offering.Price < candidates[j].offering.Price
	})
	return candidates[0].instanceType, candidates[0].offering, nil
}

func resolvedLabels(existing map[string]string, instanceType *cloudprovider.InstanceType, offering *cloudprovider.Offering) map[string]string {
	labels := make(map[string]string, len(existing)+len(instanceType.Requirements)+len(offering.Requirements))
	for key, value := range existing {
		labels[key] = value
	}
	for _, requirements := range []scheduling.Requirements{instanceType.Requirements, offering.Requirements} {
		for key, requirement := range requirements {
			if requirement.Operator() == corev1.NodeSelectorOpIn && len(requirement.Values()) != 0 {
				labels[key] = requirement.Any()
			}
		}
	}
	return labels
}

func nodeClaimFromVM(vm *cloudapi.VM) *karpv1.NodeClaim {
	capacity, allocatable := resourcesForVM(vm)
	return &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vm.NodeClaimName,
			Labels: map[string]string{corev1.LabelInstanceTypeStable: vm.InstanceType, catalog.LabelHostClass: vm.HostClass},
			Annotations: map[string]string{
				AnnotationNodeClassHash:  vm.SpecHash,
				AnnotationBootstrapHash:  vm.BootstrapHash,
				AnnotationVMState:        string(vm.State),
				AnnotationPublicIPv4:     vm.PublicIPv4,
				AnnotationFloatingIP:     vm.FloatingIPName,
				AnnotationBillingAccount: strconv.FormatInt(vm.BillingAccountID, 10),
				AnnotationNodeName:       vm.Name,
			},
		},
		Status: karpv1.NodeClaimStatus{
			ProviderID:  providerid.New(vm.Location, vm.UUID),
			ImageID:     vm.ImageID(),
			Capacity:    capacity,
			Allocatable: allocatable,
		},
	}
}

// workerNodeName returns the stable guest hostname, RKE2 node name, and cloud
// VM name for one NodeClaim. The NodeClaim remains the ownership identity and
// is deliberately not inferred back from this display name. Karpenter binds
// the registered Node to the NodeClaim through the exact provider ID.
func workerNodeName(clusterName string, nodeClaim *karpv1.NodeClaim) (string, error) {
	if nodeClaim == nil {
		return "", fmt.Errorf("NodeClaim is required")
	}
	nodePoolName := nodeClaim.Labels[karpv1.NodePoolLabelKey]
	if nodePoolName == "" {
		return "", fmt.Errorf("NodeClaim %q lacks required label %q", nodeClaim.Name, karpv1.NodePoolLabelKey)
	}
	if messages := k8svalidation.IsDNS1123Label(clusterName); len(messages) != 0 {
		return "", fmt.Errorf("cluster name %q is not a DNS-1123 hostname label: %s", clusterName, strings.Join(messages, "; "))
	}
	if messages := k8svalidation.IsDNS1123Label(nodePoolName); len(messages) != 0 {
		return "", fmt.Errorf("NodePool name %q is not a DNS-1123 hostname label: %s", nodePoolName, strings.Join(messages, "; "))
	}
	if messages := k8svalidation.IsDNS1123Label(nodeClaim.Name); len(messages) != 0 {
		return "", fmt.Errorf("NodeClaim name %q is not a DNS-1123 hostname label: %s", nodeClaim.Name, strings.Join(messages, "; "))
	}
	nodePoolPrefix := nodePoolName + "-"
	if !strings.HasPrefix(nodeClaim.Name, nodePoolPrefix) || len(nodeClaim.Name) == len(nodePoolPrefix) {
		return "", fmt.Errorf("NodeClaim name %q must use the NodePool-generated prefix %q followed by a nonempty random suffix", nodeClaim.Name, nodePoolPrefix)
	}
	name := clusterName + "-karp-" + nodeClaim.Name
	if messages := k8svalidation.IsDNS1123Label(name); len(messages) != 0 {
		return "", fmt.Errorf("derived worker name %q is not a DNS-1123 hostname label: %s", name, strings.Join(messages, "; "))
	}
	return name, nil
}

func resourcesForVM(vm *cloudapi.VM) (corev1.ResourceList, corev1.ResourceList) {
	instanceTypes, err := catalog.New(catalog.Options{Location: vm.Location, HostClass: vm.HostClass, RootDiskGiB: vm.RootDiskGiB})
	if err == nil {
		for _, instanceType := range instanceTypes {
			if instanceType.Name == vm.InstanceType {
				return copyResourceList(instanceType.Capacity), copyResourceList(instanceType.Allocatable())
			}
		}
	}
	// Keep Get/List useful for an older or unknown VM shape while never
	// advertising more than the cloud record's raw resources.
	capacity := corev1.ResourceList{
		corev1.ResourceCPU:              *resource.NewQuantity(int64(vm.VCPU), resource.DecimalSI),
		corev1.ResourceMemory:           resource.MustParse(fmt.Sprintf("%dGi", vm.MemoryGiB)),
		corev1.ResourceEphemeralStorage: resource.MustParse(fmt.Sprintf("%dGi", vm.RootDiskGiB)),
		corev1.ResourcePods:             resource.MustParse("110"),
	}
	return capacity, copyResourceList(capacity)
}

func NodeClassHash(nodeClass *inspacev1.InSpaceNodeClass) string {
	data, _ := json.Marshal(struct {
		ProviderSchema  string
		BootstrapSchema string
		Spec            inspacev1.InSpaceNodeClassSpec
	}{ProviderSchema: ProviderSchemaVersion, BootstrapSchema: bootstrap.SchemaVersion, Spec: nodeClass.Spec})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

func BootstrapHash(nodeClass *inspacev1.InSpaceNodeClass) string {
	data, _ := json.Marshal(struct {
		Schema             string
		Image              inspacev1.ImageSelector
		RKE2               inspacev1.RKE2Config
		SSHUsername        string
		SSHPublicKey       string
		AdditionalUserData string
	}{
		Schema: bootstrap.SchemaVersion, Image: nodeClass.Spec.ImageSelector, RKE2: nodeClass.Spec.RKE2,
		SSHUsername: nodeClass.Spec.SSHUsername, SSHPublicKey: nodeClass.Spec.SSHPublicKey,
		AdditionalUserData: nodeClass.Spec.AdditionalUserData,
	})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

func copyResourceList(input corev1.ResourceList) corev1.ResourceList {
	result := make(corev1.ResourceList, len(input))
	for name, quantity := range input {
		result[name] = quantity.DeepCopy()
	}
	return result
}
