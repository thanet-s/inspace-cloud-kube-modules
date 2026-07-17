package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
	ProviderSchemaVersion    = "inspace-provider-v3"
)

var _ cloudprovider.CloudProvider = (*CloudProvider)(nil)

type Options struct {
	ClusterName             string
	DefaultNodeClassName    string
	Location                string
	NetworkUUID             string
	ControlPlaneVIP         string
	PrivateLoadBalancerPool inspacev1.PrivateLoadBalancerPool
	CreateFenceStore        CreateFenceStore
	// CacheHealthProber is injectable for deterministic tests. Nil uses the
	// strict private-HTTPS implementation.
	CacheHealthProber CacheHealthProber
}

type CloudProvider struct {
	cloud    cloudapi.Cloud
	resolver NodeClassResolver
	opts     Options
	cache    CacheHealthProber
	fences   CreateFenceStore
}

func New(cloud cloudapi.Cloud, resolver NodeClassResolver, opts Options) (*CloudProvider, error) {
	if cloud == nil || resolver == nil || opts.CreateFenceStore == nil {
		return nil, fmt.Errorf("cloud, NodeClass resolver, and durable VM create fence store are required")
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
	cache := opts.CacheHealthProber
	if cache == nil {
		cache = HTTPSCacheHealthProber{}
	}
	return &CloudProvider{cloud: cloud, resolver: resolver, opts: opts, cache: cache, fences: opts.CreateFenceStore}, nil
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
	if !nodeClass.Spec.BootstrapCache.DirectDownload {
		if err := p.cache.Probe(ctx,
			inspacev1.BootstrapCacheHealthURL(nodeClass.Spec.ClusterName),
			nodeClass.Spec.BootstrapCache.Address,
			nodeClass.Spec.BootstrapCache.CABundle,
		); err != nil {
			return nil, cloudprovider.NewNodeClassNotReadyError(fmt.Errorf("bootstrap cache health probe: %w", err))
		}
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
	hostClass, hostPoolUUID, err := hostPoolForOffering(offering)
	if err != nil {
		return nil, fmt.Errorf("resolving selected host-class offering: %w", err)
	}
	labels := resolvedLabels(nodeClaim.Labels, instanceType, offering)
	token, err := p.resolver.ResolveAgentToken(ctx, nodeClass)
	if err != nil {
		return nil, cloudprovider.NewNodeClassNotReadyError(err)
	}
	bootstrapConfig := bootstrap.Config{
		NodeName:         workerName,
		Server:           nodeClass.Spec.RKE2.Server,
		Token:            token,
		RKE2Version:      nodeClass.Spec.RKE2.Version,
		SkipOSUpgrade:    nodeClass.Spec.RKE2.SkipOSUpgrade,
		Labels:           labels,
		Taints:           append(append([]corev1.Taint{}, nodeClaim.Spec.Taints...), nodeClaim.Spec.StartupTaints...),
		AdditionalScript: nodeClass.Spec.AdditionalUserData,
	}
	if !nodeClass.Spec.BootstrapCache.DirectDownload {
		bootstrapConfig.BootstrapCache = &bootstrap.CacheConfig{
			Host:     inspacev1.BootstrapCacheHost(nodeClass.Spec.ClusterName),
			Address:  nodeClass.Spec.BootstrapCache.Address,
			CABundle: nodeClass.Spec.BootstrapCache.CABundle,
		}
	}
	userData, err := bootstrap.RenderCloudInit(bootstrapConfig)
	if err != nil {
		return nil, fmt.Errorf("rendering worker bootstrap: %w", err)
	}
	idempotencyKey := string(nodeClaim.UID)
	if idempotencyKey == "" {
		idempotencyKey = nodeClaim.Name
	}
	nodePoolName := ""
	if profile := nodeClass.Spec.EffectiveFirewallProfile(); profile == inspacev1.FirewallProfilePublicNodeLoadBalancer || profile == inspacev1.FirewallProfilePublicNodeLocal {
		nodePoolName = nodeClaim.Labels[karpv1.NodePoolLabelKey]
	}
	memoryGiB := int(instanceType.Capacity.Memory().Value() / (1024 * 1024 * 1024))
	request := cloudapi.CreateVMRequest{
		IdempotencyKey:               idempotencyKey,
		Name:                         workerName,
		ClusterName:                  p.opts.ClusterName,
		BillingAccountID:             nodeClass.Spec.BillingAccountID,
		NodePoolName:                 nodePoolName,
		NodeClaimName:                nodeClaim.Name,
		Location:                     nodeClass.Spec.Location,
		NetworkUUID:                  nodeClass.Spec.NetworkUUID,
		ControlPlaneVIP:              controlPlaneVIP.String(),
		PrivateLoadBalancerPoolStart: nodeClass.Spec.PrivateLoadBalancerPool.Start,
		PrivateLoadBalancerPoolStop:  nodeClass.Spec.PrivateLoadBalancerPool.Stop,
		FirewallUUID:                 nodeClass.Spec.FirewallUUID,
		FirewallProfile:              nodeClass.Spec.EffectiveFirewallProfile(),
		OSName:                       nodeClass.Spec.ImageSelector.OSName,
		OSVersion:                    nodeClass.Spec.ImageSelector.OSVersion,
		HostPoolUUID:                 hostPoolUUID,
		HostClass:                    hostClass,
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
	requestIdentity, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encoding exact VM create-fence identity: %w", err)
	}
	binding := createFenceBinding{
		NodeClaimUID:       string(nodeClaim.UID),
		IdempotencyKeyHash: createFenceHash(idempotencyKey),
		RequestHash:        createFenceHash(string(requestIdentity)),
		SpecHash:           request.SpecHash,
		BootstrapHash:      request.BootstrapHash,
	}
	cleanupIdentity := createFenceCleanupIdentity{
		ClusterName: request.ClusterName, Location: request.Location, NetworkUUID: request.NetworkUUID,
		NodePoolName: request.NodePoolName, ControlPlaneVIP: request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: request.PrivateLoadBalancerPoolStop,
		FirewallUUID: request.FirewallUUID, FirewallProfile: inspacev1.EffectiveFirewallProfile(request.FirewallProfile), NodeClaimName: request.NodeClaimName,
		VMName: request.Name, BillingAccountID: request.BillingAccountID, OwnershipKeyHash: cloudapi.OwnershipKeyHash(idempotencyKey),
	}
	fencedClaim, fence, exists, err := p.fences.Get(ctx, nodeClaim, binding, cleanupIdentity)
	if err != nil {
		return nil, fmt.Errorf("reading durable VM create fence: %w", err)
	}
	allowPOST := false
	if exists {
		allowPOST = !fence.Issued
	} else {
		baseline, prepareErr := p.cloud.PrepareCreate(ctx, request)
		if prepareErr != nil {
			return nil, fmt.Errorf("preparing bounded pre-POST cloud inventory: %w", prepareErr)
		}
		fencedClaim, fence, allowPOST, err = p.fences.Ensure(ctx, nodeClaim, binding, cleanupIdentity, baseline)
		if err != nil {
			return nil, fmt.Errorf("establishing durable VM create fence: %w", err)
		}
	}
	if fence.RollbackChosen || fence.HasCleanupHistory {
		return nil, fmt.Errorf("%w: durable rollback or deletion cleanup already selected for NodeClaim %q", cloudapi.ErrCreateAttemptPending, nodeClaim.Name)
	}
	fencedClaim, err = p.fences.EnsureRemovalFence(ctx, fencedClaim, binding, fence.Token)
	if err != nil {
		return nil, fmt.Errorf("establishing durable removal mutation fence: %w", err)
	}
	request.CreateAttemptToken = fence.Token
	request.CreateAttemptStartedAt = fence.StartedAt
	request.CreateAttemptAllowPOST = allowPOST
	request.CreateAttemptIntent = fence.Intent
	request.CreatedVMUUID = fence.CreatedVMUUID
	request.CreateBaseline = fence.Baseline
	request.BaseFirewallAssignment = fence.BaseFirewallAssignment
	authorizedIssueID := fence.IssueID
	createdVMUUID := fence.CreatedVMUUID
	request.AuthorizeLaunch = func(authorizeCtx context.Context, intent cloudapi.CreateAuthorizationKind) error {
		issuedClaim, authorizeErr := p.fences.Authorize(authorizeCtx, fencedClaim, binding, fence.Token, intent)
		if issuedClaim != nil {
			fencedClaim = issuedClaim
			if record, decodeErr := decodeCreateFence(issuedClaim.Annotations[AnnotationCreateFence]); decodeErr == nil {
				authorizedIssueID = record.IssueID
			}
		}
		return authorizeErr
	}
	request.RecordCreatedVM = func(anchorCtx context.Context, vmUUID string) error {
		anchorCtx, cancel := detachedCreateFenceContext(anchorCtx)
		defer cancel()
		anchoredClaim, anchorErr := p.fences.RecordCreatedVM(anchorCtx, fencedClaim, binding, fence.Token, authorizedIssueID, vmUUID)
		if anchorErr == nil {
			fencedClaim = anchoredClaim
			createdVMUUID = strings.ToLower(vmUUID)
		}
		return anchorErr
	}
	request.AuthorizeBaseFirewall = func(authorizeCtx context.Context, vmUUID string) (cloudapi.FirewallAssignmentAuthorization, error) {
		authorizedClaim, authorization, authorizeErr := p.fences.AuthorizeBaseFirewall(authorizeCtx, fencedClaim, binding, fence.Token, vmUUID)
		if authorizedClaim != nil {
			fencedClaim = authorizedClaim
		}
		return authorization, authorizeErr
	}
	request.ObserveBaseFirewall = func(observeCtx context.Context, vmUUID, issueID string) error {
		observeCtx, cancel := detachedCreateFenceContext(observeCtx)
		defer cancel()
		observedClaim, observeErr := p.fences.ObserveBaseFirewall(observeCtx, fencedClaim, binding, fence.Token, vmUUID, issueID)
		if observeErr == nil {
			fencedClaim = observedClaim
		}
		return observeErr
	}
	request.RejectBaseFirewall = func(rejectCtx context.Context, vmUUID, issueID string) error {
		rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
		defer cancel()
		rejectedClaim, rejectErr := p.fences.RejectBaseFirewall(rejectCtx, fencedClaim, binding, fence.Token, vmUUID, issueID)
		if rejectErr == nil {
			fencedClaim = rejectedClaim
		}
		return rejectErr
	}
	request.AuthorizeBaseFirewallDetach = func(authorizeCtx context.Context, vmUUID string) (cloudapi.FirewallDetachmentAuthorization, error) {
		return p.fences.AuthorizeBaseFirewallDetach(authorizeCtx, fencedClaim, binding, fence.Token, vmUUID)
	}
	request.ObserveBaseFirewallDetach = func(observeCtx context.Context, detachFence cloudapi.FirewallDetachmentFence) error {
		observeCtx, cancel := detachedCreateFenceContext(observeCtx)
		defer cancel()
		return p.fences.ObserveBaseFirewallDetach(observeCtx, fencedClaim, binding, fence.Token, detachFence)
	}
	request.RejectBaseFirewallDetach = func(rejectCtx context.Context, detachFence cloudapi.FirewallDetachmentFence) error {
		rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
		defer cancel()
		return p.fences.RejectBaseFirewallDetach(rejectCtx, fencedClaim, binding, fence.Token, detachFence)
	}
	request.AuthorizeFloatingIPUpdate = func(authorizeCtx context.Context, vmUUID, address, name string, billingAccountID int64) (cloudapi.FloatingIPUpdateAuthorization, error) {
		authorizedClaim, authorization, authorizeErr := p.fences.AuthorizeFloatingIPUpdate(authorizeCtx, fencedClaim, binding, fence.Token, vmUUID, address, name, billingAccountID)
		if authorizedClaim != nil {
			fencedClaim = authorizedClaim
		}
		return authorization, authorizeErr
	}
	request.ObserveFloatingIPUpdate = func(observeCtx context.Context, updateFence cloudapi.FloatingIPUpdateFence) error {
		observeCtx, cancel := detachedCreateFenceContext(observeCtx)
		defer cancel()
		observedClaim, observeErr := p.fences.ObserveFloatingIPUpdate(observeCtx, fencedClaim, binding, fence.Token, updateFence)
		if observedClaim != nil {
			fencedClaim = observedClaim
		}
		return observeErr
	}
	request.RejectFloatingIPUpdate = func(rejectCtx context.Context, updateFence cloudapi.FloatingIPUpdateFence) error {
		rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
		defer cancel()
		rejectedClaim, rejectErr := p.fences.RejectFloatingIPUpdate(rejectCtx, fencedClaim, binding, fence.Token, updateFence)
		if rejectedClaim != nil {
			fencedClaim = rejectedClaim
		}
		return rejectErr
	}
	request.AuthorizeRemovalMutation = func(authorizeCtx context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
		authorizedClaim, authorization, authorizeErr := p.fences.AuthorizeRemovalMutation(authorizeCtx, fencedClaim, binding, fence.Token, mutation, present)
		if authorizedClaim != nil {
			fencedClaim = authorizedClaim
		}
		return authorization, authorizeErr
	}
	request.ObserveRemovalMutation = func(observeCtx context.Context, removalFence cloudapi.RemovalMutationFence) error {
		observeCtx, cancel := detachedCreateFenceContext(observeCtx)
		defer cancel()
		observedClaim, observeErr := p.fences.ObserveRemovalMutation(observeCtx, fencedClaim, binding, fence.Token, removalFence)
		if observedClaim != nil {
			fencedClaim = observedClaim
		}
		return observeErr
	}
	request.RejectRemovalMutation = func(rejectCtx context.Context, removalFence cloudapi.RemovalMutationFence) error {
		rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
		defer cancel()
		rejectedClaim, rejectErr := p.fences.RejectRemovalMutation(rejectCtx, fencedClaim, binding, fence.Token, removalFence)
		if rejectedClaim != nil {
			fencedClaim = rejectedClaim
		}
		return rejectErr
	}
	request.ChooseRollback = func(rollbackCtx context.Context, vmUUID string, resolution *cloudapi.FencedCreateCleanupResolution) error {
		rollbackCtx, cancel := detachedCreateFenceContext(rollbackCtx)
		defer cancel()
		rollbackClaim, rollbackErr := p.fences.ChooseRollback(rollbackCtx, fencedClaim, binding, fence.Token, authorizedIssueID, vmUUID, resolution)
		if rollbackErr == nil {
			fencedClaim = rollbackClaim
		}
		return rollbackErr
	}
	vm, err := p.cloud.CreateVM(ctx, request)
	if err != nil {
		if errors.Is(err, cloudapi.ErrCreateAttemptRejected) && createdVMUUID == "" {
			terminalCtx, cancel := detachedCreateFenceContext(ctx)
			rejectedClaim, rejectErr := p.fences.MarkRejected(terminalCtx, fencedClaim, binding, fence.Token, authorizedIssueID)
			cancel()
			if rejectErr != nil {
				return nil, fmt.Errorf("creating InSpace VM was locally blocked before dispatch, but persisting that terminal fence state failed: %w", errors.Join(err, rejectErr))
			}
			fencedClaim = rejectedClaim
		}
		return nil, fmt.Errorf("creating InSpace VM: %w", err)
	}
	if vm != nil {
		vm.UUID = strings.ToLower(vm.UUID)
		if publicIP, parseErr := netip.ParseAddr(vm.PublicIPv4); parseErr == nil {
			vm.PublicIPv4 = publicIP.String()
		}
	}
	terminalCtx, cancel := detachedCreateFenceContext(ctx)
	fencedClaim, err = p.fences.MarkMaterialized(terminalCtx, fencedClaim, binding, fence.Token, vm)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("persisting exact materialized VM identity before ProviderID: %w", err)
	}
	created := fencedClaim.DeepCopy()
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
		NetworkUUID:    p.opts.NetworkUUID,
	}
	deleteClusterName := p.opts.ClusterName
	if encodedFence := nodeClaim.Annotations[AnnotationCreateFence]; encodedFence != "" {
		record, decodeErr := decodeCreateFence(encodedFence)
		if decodeErr != nil {
			return fmt.Errorf("decoding retained launch identity for deletion: %w", decodeErr)
		}
		if record.Binding.NodeClaimUID != string(nodeClaim.UID) || record.Cleanup.NodeClaimName != nodeClaim.Name ||
			record.Cleanup.Location != id.Location || record.Phase != createFenceMaterialized ||
			!strings.EqualFold(record.ObservedVMUUID, id.VMUUID) {
			return fmt.Errorf("retained launch identity does not match NodeClaim %q ProviderID", nodeClaim.Name)
		}
		deleteIdentity = cloudapi.DeleteVMIdentity{
			FloatingIPName:   record.FloatingIPName,
			PublicIPv4:       record.PublicIPv4,
			BillingAccountID: record.Cleanup.BillingAccountID,
			NetworkUUID:      record.Cleanup.NetworkUUID,
			FirewallUUID:     record.Cleanup.FirewallUUID,
		}
		deleteIdentity.AuthorizeBaseFirewallDetach = func(authorizeCtx context.Context, vmUUID string) (cloudapi.FirewallDetachmentAuthorization, error) {
			return p.fences.AuthorizeBaseFirewallDetach(authorizeCtx, nodeClaim, record.Binding, record.Token, vmUUID)
		}
		deleteIdentity.ObserveBaseFirewallDetach = func(observeCtx context.Context, detachFence cloudapi.FirewallDetachmentFence) error {
			observeCtx, cancel := detachedCreateFenceContext(observeCtx)
			defer cancel()
			return p.fences.ObserveBaseFirewallDetach(observeCtx, nodeClaim, record.Binding, record.Token, detachFence)
		}
		deleteIdentity.RejectBaseFirewallDetach = func(rejectCtx context.Context, detachFence cloudapi.FirewallDetachmentFence) error {
			rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
			defer cancel()
			return p.fences.RejectBaseFirewallDetach(rejectCtx, nodeClaim, record.Binding, record.Token, detachFence)
		}
		deleteIdentity.AuthorizeRemovalMutation = func(authorizeCtx context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
			_, authorization, authorizeErr := p.fences.AuthorizeRemovalMutation(authorizeCtx, nodeClaim, record.Binding, record.Token, mutation, present)
			return authorization, authorizeErr
		}
		deleteIdentity.ObserveRemovalMutation = func(observeCtx context.Context, removalFence cloudapi.RemovalMutationFence) error {
			observeCtx, cancel := detachedCreateFenceContext(observeCtx)
			defer cancel()
			_, observeErr := p.fences.ObserveRemovalMutation(observeCtx, nodeClaim, record.Binding, record.Token, removalFence)
			return observeErr
		}
		deleteIdentity.RejectRemovalMutation = func(rejectCtx context.Context, removalFence cloudapi.RemovalMutationFence) error {
			rejectCtx, cancel := detachedCreateFenceContext(rejectCtx)
			defer cancel()
			_, rejectErr := p.fences.RejectRemovalMutation(rejectCtx, nodeClaim, record.Binding, record.Token, removalFence)
			return rejectErr
		}
		deleteClusterName = record.Cleanup.ClusterName
	}
	if value := nodeClaim.Annotations[AnnotationBillingAccount]; value != "" {
		billingAccountID, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || billingAccountID <= 0 {
			return fmt.Errorf("durable billing-account annotation for deletion must be a positive decimal integer: %q", value)
		}
		if deleteIdentity.BillingAccountID != 0 && deleteIdentity.BillingAccountID != billingAccountID {
			return fmt.Errorf("durable billing-account annotation does not match retained launch identity")
		}
		deleteIdentity.BillingAccountID = billingAccountID
	}
	if err := p.cloud.DeleteVM(ctx, id.Location, id.VMUUID, deleteClusterName, nodeClaim.Name, deleteIdentity); err != nil {
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

func hostPoolForOffering(offering *cloudprovider.Offering) (string, string, error) {
	if offering == nil {
		return "", "", fmt.Errorf("offering is required")
	}
	requirement := offering.Requirements.Get(catalog.LabelHostClass)
	if requirement == nil || requirement.Operator() != corev1.NodeSelectorOpIn || len(requirement.Values()) != 1 {
		return "", "", fmt.Errorf("offering must contain exactly one %q value", catalog.LabelHostClass)
	}
	hostClass := requirement.Any()
	hostPoolUUID, ok := inspacev1.HostPoolUUIDForClass(hostClass)
	if !ok {
		return "", "", fmt.Errorf("unsupported host class %q", hostClass)
	}
	return hostClass, hostPoolUUID, nil
}

func nodeClaimFromVM(vm *cloudapi.VM) *karpv1.NodeClaim {
	capacity, allocatable := resourcesForVM(vm)
	labels := map[string]string{
		corev1.LabelInstanceTypeStable: vm.InstanceType,
		catalog.LabelHostClass:         vm.HostClass,
		catalog.LabelInstanceCPU:       strconv.Itoa(vm.VCPU),
		catalog.LabelInstanceMemory:    strconv.Itoa(vm.MemoryGiB * 1024),
		catalog.LabelLocation:          vm.Location,
	}
	if vm.NodePoolName != "" {
		labels[karpv1.NodePoolLabelKey] = vm.NodePoolName
	}
	if instanceType, offering := instanceTypeAndOfferingForVM(vm); instanceType != nil && offering != nil {
		labels = resolvedLabels(labels, instanceType, offering)
	}
	return &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vm.NodeClaimName,
			Labels: labels,
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
	if err := validateNodePoolClaimIdentity(nodePoolName, nodeClaim.Name); err != nil {
		return "", err
	}
	name := clusterName + "-karp-" + nodeClaim.Name
	if messages := k8svalidation.IsDNS1123Label(name); len(messages) != 0 {
		return "", fmt.Errorf("derived worker name %q is not a DNS-1123 hostname label: %s", name, strings.Join(messages, "; "))
	}
	return name, nil
}

func validateNodePoolClaimIdentity(nodePoolName, nodeClaimName string) error {
	if messages := k8svalidation.IsDNS1123Label(nodePoolName); len(messages) != 0 {
		return fmt.Errorf("NodePool name %q is not a DNS-1123 hostname label: %s", nodePoolName, strings.Join(messages, "; "))
	}
	if messages := k8svalidation.IsDNS1123Label(nodeClaimName); len(messages) != 0 {
		return fmt.Errorf("NodeClaim name %q is not a DNS-1123 hostname label: %s", nodeClaimName, strings.Join(messages, "; "))
	}
	nodePoolPrefix := nodePoolName + "-"
	if !strings.HasPrefix(nodeClaimName, nodePoolPrefix) || len(nodeClaimName) == len(nodePoolPrefix) {
		return fmt.Errorf("NodeClaim name %q must use the NodePool-generated prefix %q followed by a nonempty random suffix", nodeClaimName, nodePoolPrefix)
	}
	return nil
}

func resourcesForVM(vm *cloudapi.VM) (corev1.ResourceList, corev1.ResourceList) {
	if instanceType, _ := instanceTypeAndOfferingForVM(vm); instanceType != nil {
		return copyResourceList(instanceType.Capacity), copyResourceList(instanceType.Allocatable())
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

func instanceTypeAndOfferingForVM(vm *cloudapi.VM) (*cloudprovider.InstanceType, *cloudprovider.Offering) {
	instanceTypes, err := catalog.New(catalog.Options{Location: vm.Location, RootDiskGiB: vm.RootDiskGiB})
	if err != nil {
		return nil, nil
	}
	for _, instanceType := range instanceTypes {
		if instanceType.Name != vm.InstanceType || int(instanceType.Capacity.Cpu().Value()) != vm.VCPU ||
			int(instanceType.Capacity.Memory().Value()/(1024*1024*1024)) != vm.MemoryGiB {
			continue
		}
		for _, offering := range instanceType.Offerings {
			hostClass, _, offeringErr := hostPoolForOffering(offering)
			if offeringErr == nil && hostClass == vm.HostClass {
				return instanceType, offering
			}
		}
	}
	return nil, nil
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
		BootstrapCache     inspacev1.BootstrapCacheSpec
	}{
		Schema: bootstrap.SchemaVersion, Image: nodeClass.Spec.ImageSelector, RKE2: nodeClass.Spec.RKE2,
		SSHUsername: nodeClass.Spec.SSHUsername, SSHPublicKey: nodeClass.Spec.SSHPublicKey,
		AdditionalUserData: nodeClass.Spec.AdditionalUserData,
		BootstrapCache:     nodeClass.Spec.BootstrapCache,
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
