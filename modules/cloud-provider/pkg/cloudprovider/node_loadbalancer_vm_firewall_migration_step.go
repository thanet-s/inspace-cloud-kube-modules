package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// errVMFirewallMigrationSourceChanged says a Service or firewall the plan
// retires is no longer what the plan recorded.
type errVMFirewallMigrationSourceChanged struct{ reason string }

func (e *errVMFirewallMigrationSourceChanged) Error() string {
	return "public-node-local: a migration source changed: " + e.reason
}

func sourceChanged(format string, args ...any) error {
	return &errVMFirewallMigrationSourceChanged{reason: fmt.Sprintf(format, args...)}
}

// vmFirewallMigrationBaseFirewall is the trusted base firewall of the cluster:
// the one the default NodeClass names in its spec and confirms in its status.
// The planner counts every other firewall on a VM as a candidate source.
func (c *nodeLoadBalancerController) vmFirewallMigrationBaseFirewall(ctx context.Context) (string, error) {
	name := c.provider.config.NodeLoadBalancer.DefaultNodeClass
	if name == "" || c.provider.dynamicClient == nil {
		return "", errors.New("public-node-local: the configured default NodeClass is required to identify the base firewall")
	}
	base, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("public-node-local: get the default NodeClass %q: %w", name, err)
	}
	return c.trustedNodeLoadBalancerBaseFirewall(ctx, base)
}

// vmFirewallMigrationRead is one fresh read of the cloud and of the Services a
// migration step decides from.
type vmFirewallMigrationRead struct {
	items    []inspace.Firewall
	services map[string]*corev1.Service
}

func (c *nodeLoadBalancerController) readVMFirewallMigration(ctx context.Context) (vmFirewallMigrationRead, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return vmFirewallMigrationRead{}, fmt.Errorf("public-node-local: list firewalls for a migration step: %w", err)
	}
	list, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return vmFirewallMigrationRead{}, fmt.Errorf("public-node-local: list Services for a migration step: %w", err)
	}
	read := vmFirewallMigrationRead{items: items, services: make(map[string]*corev1.Service, len(list.Items))}
	for index := range list.Items {
		read.services[string(list.Items[index].UID)] = &list.Items[index]
	}
	return read, nil
}

// validateVMFirewallMigrationSources requires every source to still be what the
// plan recorded. Before the per-VM firewall is open (strict) each Service must
// also be steady and each firewall must still carry exactly its policy on this
// VM; later, only the identities are checked, because the migration itself
// changes the relation receipts and detaches the firewalls.
func (c *nodeLoadBalancerController) validateVMFirewallMigrationSources(
	vmUUID string,
	plan vmFirewallMigrationPlan,
	view vmFirewallAnchorView,
	read vmFirewallMigrationRead,
	strict bool,
) error {
	for _, source := range plan.Sources {
		svc := read.services[source.UID]
		if svc == nil || svc.DeletionTimestamp != nil {
			if strict && !(plan.Strategy == vmFirewallMigrationStrategyAdopt && view.uuid() != "") {
				return sourceChanged("the Service %s of firewall %s is gone or being deleted", source.UID, source.Firewall)
			}
			// A Service that is leaving takes its own firewall with it, and its entry
			// leaves the per-VM firewall with its withdrawal; the migration only waits.
			continue
		}
		if svc.Annotations[annotationNodeLoadBalancerFirewallUUID] != source.Firewall ||
			svc.Annotations[annotationPublicNodeLocalActivePolicy] != source.Policy || publicNodeLocalServicePerVM(svc) {
			return sourceChanged("Service %s/%s no longer names firewall %s under policy %s", svc.Namespace, svc.Name, source.Firewall, source.Policy)
		}
		if !strict {
			continue
		}
		if reason := vmFirewallMigrationServiceWaiting(svc); reason != "" {
			return sourceChanged("Service %s/%s %s", svc.Namespace, svc.Name, reason)
		}
		firewall, err := exactNodeLoadBalancerFirewallFromItems(read.items, source.Firewall)
		if err != nil {
			return sourceChanged("firewall %s: %v", source.Firewall, err)
		}
		if view.uuid() != "" && strings.EqualFold(view.uuid(), source.Firewall) {
			continue // the adoptee, renamed: the anchor validates it
		}
		if !vmFirewallAttachedTo(*firewall, vmUUID) {
			return sourceChanged("firewall %s is no longer attached to VM %s", source.Firewall, vmUUID)
		}
		hash, hashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
		if hashErr != nil || hash != source.Policy ||
			!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, source.UID, c.provider.config.BillingAccountID) {
			return sourceChanged("firewall %s no longer carries policy %s of Service %s", source.Firewall, source.Policy, source.UID)
		}
	}
	return nil
}

// writeVMFirewallMigrationPlan replaces the migration record by next, as a
// compare-and-swap on the record it was derived from.
func (c *nodeLoadBalancerController) writeVMFirewallMigrationPlan(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	from, next vmFirewallMigrationPlan,
) (*corev1.ConfigMap, error) {
	fromRaw, err := encodeVMFirewallMigrationPlan(from)
	if err != nil {
		return nil, err
	}
	nextRaw, err := encodeVMFirewallMigrationPlan(next)
	if err != nil {
		return nil, err
	}
	updated, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		current := cm.Annotations[annotationVMFirewallMigration]
		if current == nextRaw {
			return false, nil
		}
		if current != fromRaw {
			return false, errors.New("public-node-local: the migration record changed before its phase was advanced")
		}
		cm.Annotations[annotationVMFirewallMigration] = nextRaw
		return true, nil
	})
	return updated, err
}

// stepVMFirewallMigration advances the migration recorded on an anchor by at
// most one durable step. It reports whether the migration owns this pass; it
// does not when the VM has no public-node-local Node any more, and the pass
// then goes on with the VM's ordinary upkeep, which collects what a gone VM
// left. Every phase resumes from the record and the receipts, so a restart
// between any two writes continues where the last one stopped.
func (c *nodeLoadBalancerController) stepVMFirewallMigration(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	plan, ok, err := view.migration()
	if err != nil || !ok {
		return err != nil, err
	}
	node, err := c.publicNodeLocalNodeOfVM(ctx, vmUUID)
	if err != nil {
		return true, err
	}
	if node == nil {
		return false, nil
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return true, err
	}
	if allowed, reason := c.vmFirewallMigrationAllowed(ctx, vmUUID, node, anchors, c.nodeLoadBalancerFirewallRelationTime()); !allowed {
		if vmFirewallMigrationReasonSilent(reason) {
			return true, nil
		}
		return true, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the migration of VM %s waits: %s", vmUUID, reason)
	}
	if plan.Direction == vmFirewallMigrationDirectionReverse {
		return true, c.stepVMFirewallReverse(ctx, vmUUID, anchor, plan)
	}
	switch plan.Phase {
	case vmFirewallMigrationPhasePlanned:
		err = c.openVMFirewallMigration(ctx, vmUUID, anchor, plan)
	case vmFirewallMigrationPhaseOpened:
		err = c.settleVMFirewallMigration(ctx, anchor, plan)
	case vmFirewallMigrationPhaseDetaching:
		err = c.detachVMFirewallMigration(ctx, vmUUID, anchor, plan)
	case vmFirewallMigrationPhaseDone:
		// Nothing left to flip: the pass is the ordinary upkeep's again (drift,
		// entries of Services that are gone, a gone VM, an empty anchor).
		return c.cleanupVMFirewallMigration(ctx, plan)
	case vmFirewallMigrationPhaseAborting:
		err = c.abortVMFirewallMigration(ctx, vmUUID, anchor, plan)
	default:
		err = fmt.Errorf("public-node-local: the migration of VM %s is in phase %q, which this build can not continue", vmUUID, plan.Phase)
	}
	return true, err
}

// authorizeVMFirewallMigrationOpen is the final authority of an add of the
// opening phase: the plan is still the recorded one and every source is steady.
func (c *nodeLoadBalancerController) authorizeVMFirewallMigrationOpen(vmUUID string, plan vmFirewallMigrationPlan) vmFirewallDeltaAuthority {
	return func(ctx context.Context, anchor *corev1.ConfigMap, _ *inspace.Firewall) error {
		fresh, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if fresh == nil {
			return errors.New("public-node-local: the VM firewall anchor disappeared during the migration")
		}
		view := vmFirewallAnchorView{cm: fresh}
		current, ok, err := view.migration()
		if err != nil {
			return err
		}
		if !ok || current.Phase != vmFirewallMigrationPhasePlanned || fmt.Sprint(current.Sources) != fmt.Sprint(plan.Sources) {
			return errors.New("public-node-local: the migration record changed before the per-VM firewall was opened")
		}
		read, err := c.readVMFirewallMigration(ctx)
		if err != nil {
			return err
		}
		return c.validateVMFirewallMigrationSources(vmUUID, plan, view, read, true)
	}
}

// openVMFirewallMigration is M2 and M3: it carries the sources one by one into
// the per-VM firewall, then records that it is open.
func (c *nodeLoadBalancerController) openVMFirewallMigration(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	view := vmFirewallAnchorView{cm: anchor}
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	if err := c.validateVMFirewallMigrationSources(vmUUID, plan, view, read, true); err != nil {
		return c.sourceChangedBeforeOpen(ctx, vmUUID, anchor, plan, err)
	}
	if plan.Strategy == vmFirewallMigrationStrategyAdopt {
		return c.adoptVMFirewallMigration(ctx, vmUUID, anchor, plan, read)
	}
	for _, source := range plan.Sources {
		firewall, err := exactNodeLoadBalancerFirewallFromItems(read.items, source.Firewall)
		if err != nil {
			return sourceChanged("firewall %s: %v", source.Firewall, err)
		}
		member, err := vmFirewallMemberFromFirewall(source.UID, source.Policy, *firewall)
		if err != nil {
			return sourceChanged("firewall %s: %v", source.Firewall, err)
		}
		result, err := c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Add: &member},
			c.authorizeVMFirewallMigrationOpen(vmUUID, plan), c.vmFirewallMemberLookup(vmUUID, nil))
		var changed *errVMFirewallMigrationSourceChanged
		if errors.As(err, &changed) {
			// The final authority found a source changed after the plan was checked.
			return c.sourceChangedBeforeOpen(ctx, vmUUID, anchor, plan, err)
		}
		if err != nil {
			return err
		}
		if !result.Converged {
			c.queueVMFirewall(vmUUID)
			return nil
		}
	}
	return c.markVMFirewallMigrationOpened(ctx, vmUUID, plan)
}

// markVMFirewallMigrationOpened is M3: every source has an applied entry and
// the per-VM firewall is attached and read back.
func (c *nodeLoadBalancerController) markVMFirewallMigrationOpened(ctx context.Context, vmUUID string, plan vmFirewallMigrationPlan) error {
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil || anchor == nil {
		return errors.Join(err, errors.New("public-node-local: the VM firewall anchor is gone"))
	}
	view := vmFirewallAnchorView{cm: anchor}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	for _, source := range plan.Sources {
		if svc := read.services[source.UID]; svc == nil || svc.DeletionTimestamp != nil {
			continue // its withdrawal took the entry off, or will
		}
		if _, present := applied.find(vmFirewallMemberKey{UID: source.UID, Policy: source.Policy}); !present {
			return fmt.Errorf("public-node-local: the per-VM firewall of VM %s does not hold the entry of Service %s yet", vmUUID, source.UID)
		}
	}
	next := plan
	next.Phase = vmFirewallMigrationPhaseOpened
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// settleVMFirewallMigration is M4: the sources are detached only once the
// per-VM firewall has been open for the settle delay.
func (c *nodeLoadBalancerController) settleVMFirewallMigration(ctx context.Context, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	if remaining := vmFirewallSettleRemaining(anchor, c.provider.vmFirewallSettle(), c.nodeLoadBalancerFirewallRelationTime()); remaining > 0 {
		return &errPublicNodeLocalVMFirewallSettling{vmUUID: (vmFirewallAnchorView{cm: anchor}).vm(), retryAfter: remaining}
	}
	next := plan
	next.Phase = vmFirewallMigrationPhaseDetaching
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall((vmFirewallAnchorView{cm: anchor}).vm())
	return nil
}

// authorizeVMFirewallMigrationDetach is the final authority before a source
// leaves the VM: the plan is open, the settle delay has passed, the Service is
// open on this VM under its own policy through the per-VM firewall (spec 4.5),
// and that firewall allows everything the source allows.
func (c *nodeLoadBalancerController) authorizeVMFirewallMigrationDetach(
	ctx context.Context,
	vmUUID string,
	source vmFirewallMigrationSource,
	before inspace.Firewall,
) error {
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	if anchor == nil {
		return errors.New("public-node-local: the VM firewall anchor disappeared during the migration")
	}
	view := vmFirewallAnchorView{cm: anchor}
	plan, ok, err := view.migration()
	if err != nil {
		return err
	}
	if !ok || (plan.Phase != vmFirewallMigrationPhaseOpened && plan.Phase != vmFirewallMigrationPhaseDetaching) {
		return errors.New("public-node-local: the migration is not open, so no firewall may leave the VM")
	}
	if _, listed := plan.source(source.Firewall); !listed || strings.EqualFold(plan.Adoptee, source.Firewall) {
		return fmt.Errorf("public-node-local: firewall %s is not a firewall this migration retires", source.Firewall)
	}
	if remaining := vmFirewallSettleRemaining(anchor, c.provider.vmFirewallSettle(), c.nodeLoadBalancerFirewallRelationTime()); remaining > 0 {
		return fmt.Errorf("public-node-local: the per-VM firewall of VM %s has not settled for %s yet", vmUUID, remaining)
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return err
	}
	open, err := c.vmEdgeAssigned(source.UID, source.Policy, items, []corev1.ConfigMap{*anchor})
	if err != nil {
		return err
	}
	if _, isOpen := open[vmUUID]; !isOpen {
		return fmt.Errorf("public-node-local: Service %s is not open on VM %s through the per-VM firewall", source.UID, vmUUID)
	}
	perVM, err := exactNodeLoadBalancerFirewallFromItems(items, view.uuid())
	if err != nil {
		return err
	}
	if vmFirewallMergedNarrows(before.Rules, perVM.Rules) {
		return fmt.Errorf("public-node-local: the per-VM firewall of VM %s does not allow everything firewall %s allows", vmUUID, source.Firewall)
	}
	return nil
}

// detachVMFirewallMigration is M5: one source leaves the VM per pass, through
// its own Service's relation fence.
func (c *nodeLoadBalancerController) detachVMFirewallMigration(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	view := vmFirewallAnchorView{cm: anchor}
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	if err := c.validateVMFirewallMigrationSources(vmUUID, plan, view, read, false); err != nil {
		return err
	}
	for _, source := range plan.Sources {
		if strings.EqualFold(plan.Adoptee, source.Firewall) {
			continue
		}
		svc := read.services[source.UID]
		if svc == nil || svc.DeletionTimestamp != nil {
			if firewall, listed := exactNodeLoadBalancerFirewallFromItemsOptional(read.items, source.Firewall); listed && vmFirewallAttachedTo(*firewall, vmUUID) {
				return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s is leaving; its cleanup detaches firewall %s from VM %s", source.UID, source.Firewall, vmUUID)
			}
			continue
		}
		if svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
			// A receipt of an earlier detach (ours, or one that survived a restart)
			// is resolved before anything else is issued for the Service.
			if _, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.serviceFirewallRelationOwner(svc), nil); err != nil {
				return err
			}
			return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s: resolving its firewall relation receipt", svc.Namespace, svc.Name)
		}
		firewall, listed := exactNodeLoadBalancerFirewallFromItemsOptional(read.items, source.Firewall)
		if !listed || !vmFirewallAttachedTo(*firewall, vmUUID) {
			continue
		}
		owner := c.serviceFirewallRelationOwner(svc)
		inner := owner.authorize
		owner.authorize = func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			if err := inner(ctx, fence, before); err != nil {
				return err
			}
			return c.authorizeVMFirewallMigrationDetach(ctx, vmUUID, source, before)
		}
		fence := nodeLoadBalancerFirewallRelationFence{
			operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: source.Firewall, vmUUID: vmUUID,
		}
		klog.Infof("node load balancer: detach firewall %s of Service %s from VM %s: the per-VM firewall carries its rules", source.Firewall, source.UID, vmUUID)
		converged, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, &fence)
		if err != nil {
			return err
		}
		if !converged {
			return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: firewall %s is being detached from VM %s", source.Firewall, vmUUID)
		}
		c.queueVMFirewall(vmUUID)
		return nil
	}
	next := plan
	next.Phase = vmFirewallMigrationPhaseDone
	next.DoneAt = c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	// This VM may have made a firewall of another VM single-VM, which a deferred
	// migration was waiting for.
	c.queueDeferredVMFirewallMigrations(ctx)
	return nil
}

// exactNodeLoadBalancerFirewallFromItemsOptional is the exact lookup that treats
// a missing firewall as a plain absence.
func exactNodeLoadBalancerFirewallFromItemsOptional(items []inspace.Firewall, uuid string) (*inspace.Firewall, bool) {
	if !vmFirewallListed(items, uuid) {
		return nil, false
	}
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, uuid)
	if err != nil {
		return nil, false
	}
	return firewall, true
}
