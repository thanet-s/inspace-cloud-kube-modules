package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const createFenceCleanupRequeue = 10 * time.Second

// CreateFenceController owns the narrow crash window between an issued
// InSpace VM POST and durable NodeClaim ProviderID persistence. Karpenter's
// lifecycle finalizer handles normal launched claims. This controller waits
// for that finalizer when ProviderID exists, but independently cleans/proves
// absence for issued claims that are deleted while ProviderID is still empty.
type CreateFenceController struct {
	kubeClient client.Client
	apiReader  client.Reader
	cloud      cloudapi.Cloud
}

func NewCreateFenceController(kubeClient client.Client, apiReader client.Reader, cloud cloudapi.Cloud) (*CreateFenceController, error) {
	if kubeClient == nil || apiReader == nil || cloud == nil {
		return nil, fmt.Errorf("Kubernetes client, uncached API reader, and cloud are required for VM create-protection finalization")
	}
	return &CreateFenceController{kubeClient: kubeClient, apiReader: apiReader, cloud: cloud}, nil
}

func (c *CreateFenceController) Name() string { return "inspace.nodeclaim.create-protection" }

func (c *CreateFenceController) Reconcile(ctx context.Context, nodeClaim *karpv1.NodeClaim) (reconcile.Result, error) {
	if !controllerutil.ContainsFinalizer(nodeClaim, CreateFenceFinalizer) {
		return reconcile.Result{}, nil
	}
	var exact karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &exact); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if exact.UID != nodeClaim.UID {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q UID changed before create-protection reconciliation", nodeClaim.Name)
	}
	nodeClaim = &exact
	if !controllerutil.ContainsFinalizer(nodeClaim, CreateFenceFinalizer) {
		return reconcile.Result{}, nil
	}
	record, err := decodeCreateFence(nodeClaim.Annotations[AnnotationCreateFence])
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q create-protection finalizer has no valid fence: %w", nodeClaim.Name, err)
	}
	if record.Binding.NodeClaimUID != string(nodeClaim.UID) || record.Cleanup.NodeClaimName != nodeClaim.Name {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q create-protection identity does not match its UID/name", nodeClaim.Name)
	}

	deleting := !nodeClaim.DeletionTimestamp.IsZero()
	rollbackChosen := record.Phase == createFenceIssued && record.RollbackAt != nil

	if record.Phase == createFenceIssued && record.IssuedAt == nil {
		return reconcile.Result{}, fmt.Errorf("issued NodeClaim %q fence has no durable issue time", nodeClaim.Name)
	}
	// Avoid racing Karpenter's normal Delete path. Once its finalizer disappears,
	// independently prove that no VM/FIP escaped before releasing ours.
	if deleting && nodeClaim.Status.ProviderID != "" && controllerutil.ContainsFinalizer(nodeClaim, karpv1.TerminationFinalizer) {
		return reconcile.Result{RequeueAfter: createFenceCleanupRequeue}, nil
	}
	if deleting && record.Phase == createFenceIssued && record.CreatedVMUUID != "" && record.RollbackAt == nil {
		// Deletion can race the Create() invocation after the exact UUID anchor
		// but before protection/materialization. Persist dependent-pending before
		// any VM DELETE can auto-unassign an unnamed FIP and erase correlation.
		var anchorReceipt *cloudapi.FencedCreateCleanupResolution
		for i := range record.CleanupResolutions {
			if strings.EqualFold(record.CleanupResolutions[i].VMUUID, record.CreatedVMUUID) {
				copy := record.CleanupResolutions[i]
				anchorReceipt = &copy
				break
			}
		}
		store := &kubernetesCreateFenceStore{writer: c.kubeClient, reader: c.apiReader, now: time.Now, nonce: createFenceNonce}
		rollbackCtx, cancel := detachedCreateFenceContext(ctx)
		_, rollbackErr := store.ChooseRollback(rollbackCtx, nodeClaim, record.Binding, record.Token, record.IssueID, record.CreatedVMUUID, anchorReceipt)
		cancel()
		if rollbackErr != nil {
			return reconcile.Result{}, fmt.Errorf("persisting deletion rollback for anchored VM %s: %w", record.CreatedVMUUID, rollbackErr)
		}
		return reconcile.Result{Requeue: true}, nil
	}
	resolutions := append([]cloudapi.FencedCreateCleanupResolution(nil), record.CleanupResolutions...)
	if record.ObservedVMUUID != "" {
		var err error
		resolutions, err = appendCleanupResolution(resolutions, cloudapi.FencedCreateCleanupResolution{
			VMUUID: record.ObservedVMUUID, FloatingIPName: record.FloatingIPName, PublicIPv4: record.PublicIPv4,
		})
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q materialized cleanup receipt: %w", nodeClaim.Name, err)
		}
	}
	attemptResolved := record.Phase == createFenceMaterialized || record.Phase == createFenceRejected || record.Intent == cloudapi.CreateAuthorizationAdoption
	baselineVMs := make(map[string]struct{}, len(record.Baseline.VMs))
	for _, vmUUID := range record.Baseline.VMs {
		baselineVMs[vmUUID] = struct{}{}
	}
	for _, resolution := range resolutions {
		if _, existedBeforeFence := baselineVMs[resolution.VMUUID]; !existedBeforeFence {
			attemptResolved = true
			break
		}
	}
	if record.CreatedVMUUID != "" {
		if _, existedBeforeFence := baselineVMs[record.CreatedVMUUID]; !existedBeforeFence {
			attemptResolved = true
		}
	}
	cleanup := cloudapi.FencedCreateCleanupRequest{
		ClusterName: record.Cleanup.ClusterName, Location: record.Cleanup.Location,
		NetworkUUID:  record.Cleanup.NetworkUUID,
		NodePoolName: record.Cleanup.NodePoolName, ControlPlaneVIP: record.Cleanup.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: record.Cleanup.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: record.Cleanup.PrivateLoadBalancerPoolStop,
		FirewallUUID: record.Cleanup.FirewallUUID, FirewallProfile: record.Cleanup.FirewallProfile,
		SpecHash: record.Binding.SpecHash, BootstrapHash: record.Binding.BootstrapHash,
		NodeClaimName: record.Cleanup.NodeClaimName, VMName: record.Cleanup.VMName,
		BillingAccountID: record.Cleanup.BillingAccountID, OwnershipKeyHash: record.Cleanup.OwnershipKeyHash,
		AttemptToken:        record.Token,
		POSTIssued:          record.IssuedAt != nil && record.Intent == cloudapi.CreateAuthorizationPost,
		POSTRejected:        record.Phase == createFenceRejected && record.Intent == cloudapi.CreateAuthorizationPost,
		AttemptResolved:     attemptResolved,
		CreatedVMUUID:       strings.ToLower(record.CreatedVMUUID),
		RollbackChosen:      rollbackChosen,
		DependentUnresolved: record.DependentUnresolved,
		DependentsResolved:  record.DependentsResolvedAt != nil,
		ObservedVMUUID:      strings.ToLower(record.ObservedVMUUID),
		FloatingIPName:      record.FloatingIPName, PublicIPv4: record.PublicIPv4,
		Resolutions: resolutions, Baseline: cloneCreateInventory(record.Baseline),
	}
	if record.CleanupVMUUID != "" {
		cleanup.ObservedVMUUID = record.CleanupVMUUID
		cleanup.FloatingIPName = record.CleanupFloatingIPName
		cleanup.PublicIPv4 = record.CleanupPublicIPv4
	}
	if record.IssuedAt != nil {
		cleanup.AttemptIssuedAt = *record.IssuedAt
	}
	if encodedResolution := nodeClaim.Annotations[AnnotationCreateFenceResolution]; encodedResolution != "" {
		resolution, resolutionErr := decodeCreateFenceOperatorResolution(encodedResolution)
		if resolutionErr != nil {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q operator create-fence resolution: %w", nodeClaim.Name, resolutionErr)
		}
		return c.resolveOperatorCreateFence(ctx, nodeClaim, record, cleanup, resolution)
	}
	if !deleting && !rollbackChosen {
		// An anchored public VM can exist after a process crash before Create()
		// completes. Re-establish/read back the base deny firewall. A bounded
		// protection failure irreversibly chooses rollback so the next pass
		// deletes the exact UUID instead of exposing it indefinitely.
		if record.Phase == createFenceIssued && record.CreatedVMUUID != "" {
			if protectErr := c.cloud.ProtectFencedCreate(ctx, cleanup); protectErr != nil {
				store := &kubernetesCreateFenceStore{writer: c.kubeClient, reader: c.apiReader, now: time.Now, nonce: createFenceNonce}
				rollbackCtx, cancel := detachedCreateFenceContext(ctx)
				_, rollbackErr := store.ChooseRollback(rollbackCtx, nodeClaim, record.Binding, record.Token, record.IssueID, record.CreatedVMUUID, nil)
				cancel()
				if rollbackErr != nil {
					return reconcile.Result{}, fmt.Errorf("protecting anchored VM %s failed and persisting rollback also failed: %w", record.CreatedVMUUID, errors.Join(protectErr, rollbackErr))
				}
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{RequeueAfter: createFenceCleanupRequeue}, nil
		}
		// Retain the provider fence through the complete NodeClaim lifetime. On
		// deletion it follows Karpenter's normal finalizer and then performs a
		// location-wide exact-ownership/dependent rescan for legacy duplicates.
		return reconcile.Result{}, nil
	}
	result, err := c.cloud.CleanupFencedCreate(ctx, cleanup)
	if result.Resolution != nil && result.DependentsResolved {
		return reconcile.Result{}, fmt.Errorf("cloud returned both a fenced cleanup receipt and dependent-absence proof")
	}
	if result.Resolution != nil {
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("cloud returned both fenced cleanup resolution and error: %w", err)
		}
		if err := c.persistCleanupResolution(ctx, nodeClaim, record, result.Resolution); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	if result.DependentsResolved {
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("cloud returned dependent-absence proof with an error: %w", err)
		}
		if err := c.persistDependentResolution(ctx, nodeClaim, record); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	if err == nil {
		if !deleting {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, c.removeProtection(ctx, nodeClaim)
	}
	if errors.Is(err, cloudapi.ErrNotFound) {
		if !deleting {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, c.removeProtection(ctx, nodeClaim)
	}
	if errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		return reconcile.Result{RequeueAfter: createFenceCleanupRequeue}, nil
	}
	if errors.Is(err, cloudapi.ErrCreateAttemptUnresolved) {
		return reconcile.Result{}, err
	}
	if err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: createFenceCleanupRequeue}, nil
}

func (c *CreateFenceController) resolveOperatorCreateFence(
	ctx context.Context,
	nodeClaim *karpv1.NodeClaim,
	record createFenceRecord,
	cleanup cloudapi.FencedCreateCleanupRequest,
	resolution createFenceOperatorResolution,
) (reconcile.Result, error) {
	if record.IssueID == "" || resolution.IssueID != record.IssueID {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q operator resolution issue ID does not match the exact durable attempt", nodeClaim.Name)
	}
	store := &kubernetesCreateFenceStore{writer: c.kubeClient, reader: c.apiReader, now: time.Now, nonce: createFenceNonce}
	switch resolution.Result {
	case createFenceResolutionVM:
		if record.Phase == createFenceMaterialized && record.CreatedVMUUID == resolution.VMUUID ||
			record.Phase == createFenceIssued && record.CreatedVMUUID == resolution.VMUUID {
			if err := c.clearOperatorCreateFenceResolution(ctx, nodeClaim); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{Requeue: true}, nil
		}
		if record.Phase != createFenceIssued || record.CreatedVMUUID != "" || record.RollbackAt != nil {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q cannot apply a VM result to create-fence phase %q", nodeClaim.Name, record.Phase)
		}
		candidate := cleanup
		candidate.CreatedVMUUID = resolution.VMUUID
		if err := c.cloud.ProtectFencedCreate(ctx, candidate); err != nil {
			return reconcile.Result{}, fmt.Errorf("validating and protecting operator-resolved VM %s: %w", resolution.VMUUID, err)
		}
		writeCtx, cancel := detachedCreateFenceContext(ctx)
		anchored, err := store.RecordCreatedVM(writeCtx, nodeClaim, record.Binding, record.Token, record.IssueID, resolution.VMUUID)
		cancel()
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("persisting operator-resolved VM %s: %w", resolution.VMUUID, err)
		}
		if err := c.clearOperatorCreateFenceResolution(ctx, anchored); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil

	case createFenceResolutionNoResult:
		if record.Phase == createFenceRejected && record.CreatedVMUUID == "" {
			if err := c.clearOperatorCreateFenceResolution(ctx, nodeClaim); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{Requeue: true}, nil
		}
		if record.Phase != createFenceIssued || record.CreatedVMUUID != "" || record.RollbackAt != nil {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q cannot apply no-result to create-fence phase %q", nodeClaim.Name, record.Phase)
		}
		result, auditErr := c.cloud.CleanupFencedCreate(ctx, cleanup)
		if result.Resolution != nil || result.DependentsResolved {
			return reconcile.Result{}, fmt.Errorf("operator no-result audit discovered a cloud result; resolve the exact VM instead")
		}
		if errors.Is(auditErr, cloudapi.ErrCreateAttemptPending) {
			return reconcile.Result{RequeueAfter: createFenceCleanupRequeue}, nil
		}
		if !errors.Is(auditErr, cloudapi.ErrCreateAttemptUnresolved) {
			return reconcile.Result{}, fmt.Errorf("operator no-result audit did not produce three authoritative empty observations: %w", auditErr)
		}
		writeCtx, cancel := detachedCreateFenceContext(ctx)
		rejected, err := store.MarkRejected(writeCtx, nodeClaim, record.Binding, record.Token, record.IssueID)
		cancel()
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("persisting support-confirmed no-result create fence: %w", err)
		}
		if err := c.clearOperatorCreateFenceResolution(ctx, rejected); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	default:
		return reconcile.Result{}, fmt.Errorf("unsupported operator create-fence result %q", resolution.Result)
	}
}

func (c *CreateFenceController) clearOperatorCreateFenceResolution(ctx context.Context, nodeClaim *karpv1.NodeClaim) error {
	stored := nodeClaim.DeepCopy()
	updated := nodeClaim.DeepCopy()
	delete(updated.Annotations, AnnotationCreateFenceResolution)
	if err := c.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("clearing NodeClaim %q consumed create-fence resolution: %w", nodeClaim.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &readback); err != nil {
		return fmt.Errorf("reading back NodeClaim %q consumed create-fence resolution: %w", nodeClaim.Name, err)
	}
	if readback.UID != nodeClaim.UID || readback.Annotations[AnnotationCreateFenceResolution] != "" || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return fmt.Errorf("NodeClaim %q operator resolution clear did not survive exact readback", nodeClaim.Name)
	}
	return nil
}

func (c *CreateFenceController) persistDependentResolution(ctx context.Context, nodeClaim *karpv1.NodeClaim, record createFenceRecord) error {
	if !record.DependentUnresolved || record.RollbackAt == nil || record.CreatedVMUUID == "" {
		return fmt.Errorf("NodeClaim %q has no unresolved anchored dependent to complete", nodeClaim.Name)
	}
	record.DependentUnresolved = false
	now := time.Now().UTC()
	record.DependentsResolvedAt = &now
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding NodeClaim %q dependent absence proof: %w", nodeClaim.Name, err)
	}
	stored := nodeClaim.DeepCopy()
	updated := nodeClaim.DeepCopy()
	updated.Annotations[AnnotationCreateFence] = string(encoded)
	if err := c.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("persisting NodeClaim %q dependent absence proof: %w", nodeClaim.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &readback); err != nil {
		return fmt.Errorf("reading back NodeClaim %q dependent absence proof: %w", nodeClaim.Name, err)
	}
	if readback.UID != nodeClaim.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return fmt.Errorf("NodeClaim %q changed identity or lost protection while persisting dependent absence", nodeClaim.Name)
	}
	readbackRecord, err := decodeCreateFence(readback.Annotations[AnnotationCreateFence])
	if err != nil {
		return err
	}
	if readbackRecord.DependentUnresolved || readbackRecord.DependentsResolvedAt == nil || readbackRecord.DependentsResolvedAt.IsZero() ||
		readbackRecord.RollbackAt == nil || readbackRecord.CreatedVMUUID != record.CreatedVMUUID {
		return fmt.Errorf("NodeClaim %q dependent absence proof did not survive exact readback", nodeClaim.Name)
	}
	return nil
}

// persistCleanupResolution is the durable half of the cleanup handshake. The
// adapter only discovers and validates an exact owned VM on the first pass;
// no destructive delete is permitted until this receipt survives an uncached
// NodeClaim readback and is supplied to a later cleanup pass.
func (c *CreateFenceController) persistCleanupResolution(
	ctx context.Context,
	nodeClaim *karpv1.NodeClaim,
	record createFenceRecord,
	resolution *cloudapi.FencedCreateCleanupResolution,
) error {
	if resolution == nil || !createFenceVMUUIDPattern.MatchString(resolution.VMUUID) || resolution.FloatingIPName == "" {
		return fmt.Errorf("cloud returned an incomplete fenced cleanup resolution")
	}
	vmUUID := strings.ToLower(resolution.VMUUID)
	publicIP, err := netip.ParseAddr(resolution.PublicIPv4)
	if err != nil || !publicIP.Is4() || !publicIP.IsGlobalUnicast() {
		return fmt.Errorf("cloud returned invalid fenced cleanup public IPv4 %q", resolution.PublicIPv4)
	}
	if record.CleanupVMUUID == vmUUID && record.CleanupFloatingIPName == resolution.FloatingIPName && record.CleanupPublicIPv4 == publicIP.String() {
		return fmt.Errorf("cloud rediscovered fenced VM %s without consuming its durable cleanup receipt", vmUUID)
	}
	if record.ObservedVMUUID != "" {
		record.CleanupResolutions, err = appendCleanupResolution(record.CleanupResolutions, cloudapi.FencedCreateCleanupResolution{
			VMUUID: record.ObservedVMUUID, FloatingIPName: record.FloatingIPName, PublicIPv4: record.PublicIPv4,
		})
		if err != nil {
			return fmt.Errorf("recording NodeClaim %q materialized cleanup receipt: %w", nodeClaim.Name, err)
		}
	}
	if err := applyCleanupResolution(&record, *resolution); err != nil {
		return fmt.Errorf("recording NodeClaim %q cleanup receipt: %w", nodeClaim.Name, err)
	}
	if record.CreatedVMUUID != "" && strings.EqualFold(record.CreatedVMUUID, resolution.VMUUID) {
		record.DependentUnresolved = false
		record.DependentsResolvedAt = nil
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding NodeClaim %q fenced cleanup resolution: %w", nodeClaim.Name, err)
	}
	stored := nodeClaim.DeepCopy()
	nodeClaim = nodeClaim.DeepCopy()
	nodeClaim.Annotations[AnnotationCreateFence] = string(encoded)
	if err := c.kubeClient.Patch(ctx, nodeClaim, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("persisting NodeClaim %q fenced cleanup resolution: %w", nodeClaim.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &readback); err != nil {
		return fmt.Errorf("reading back NodeClaim %q fenced cleanup resolution: %w", nodeClaim.Name, err)
	}
	if readback.UID != nodeClaim.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return fmt.Errorf("NodeClaim %q changed identity or lost create protection while persisting cleanup resolution", nodeClaim.Name)
	}
	readbackRecord, err := decodeCreateFence(readback.Annotations[AnnotationCreateFence])
	if err != nil {
		return err
	}
	if readbackRecord.CleanupVMUUID != vmUUID || readbackRecord.CleanupFloatingIPName != resolution.FloatingIPName || readbackRecord.CleanupPublicIPv4 != publicIP.String() {
		return fmt.Errorf("NodeClaim %q fenced cleanup resolution did not survive exact readback", nodeClaim.Name)
	}
	return nil
}

func (c *CreateFenceController) removeProtection(ctx context.Context, nodeClaim *karpv1.NodeClaim) error {
	stored := nodeClaim.DeepCopy()
	controllerutil.RemoveFinalizer(nodeClaim, CreateFenceFinalizer)
	delete(nodeClaim.Annotations, AnnotationCreateFence)
	if err := c.kubeClient.Patch(ctx, nodeClaim, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf("NodeClaim %q create-protection CAS conflicted: %w", nodeClaim.Name, err)
		}
		return client.IgnoreNotFound(err)
	}
	return nil
}

func (c *CreateFenceController) Register(_ context.Context, m manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(m).
		Named(c.Name()).
		For(&karpv1.NodeClaim{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 5}).
		Complete(reconcile.AsReconciler(m.GetClient(), c))
}

func (c *CreateFenceController) ReconcileByName(ctx context.Context, name string) (reconcile.Result, error) {
	var nodeClaim karpv1.NodeClaim
	if err := c.kubeClient.Get(ctx, types.NamespacedName{Name: name}, &nodeClaim); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	return c.Reconcile(ctx, &nodeClaim)
}
