package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// vmFirewallOpUnadopt is the receipt of the PUT that renames the per-VM firewall
// into the own firewall of one member Service (reverse strategy B). Its
// adopt-uuid is the per-VM firewall, its pending ledger holds the one entry of
// the adoptee, and its pending hash is that entry's policy.
const vmFirewallOpUnadopt vmFirewallOp = "unadopt"

// vmFirewallReverseTimeNow is the time the reverse migration paces itself by.
func (c *nodeLoadBalancerController) vmFirewallReverseTimeNow() time.Time {
	return c.nodeLoadBalancerFirewallRelationTime()
}

// noteVMFirewallAnchorGone remembers in memory when an anchor was last deleted,
// for the pacing of the next reverse VM. The durable copy is the stamp on the
// anchors that are left (stampVMFirewallReverseDone); this one only covers the
// last anchor of all.
func (c *nodeLoadBalancerController) noteVMFirewallAnchorGone() {
	c.vmFirewallOrphanMu.Lock()
	c.vmFirewallLastGoneAt = c.vmFirewallReverseTimeNow()
	c.vmFirewallOrphanMu.Unlock()
}

func (c *nodeLoadBalancerController) vmFirewallLastGone() time.Time {
	c.vmFirewallOrphanMu.Lock()
	defer c.vmFirewallOrphanMu.Unlock()
	return c.vmFirewallLastGoneAt
}

// annotationVMFirewallReverseDoneAt is stamped on every other anchor just before
// the anchor of a reversed VM is deleted: the reverse ends with its anchor, so
// the time it ended lives on the anchors of the VMs still to come, and the pacing
// delay survives a restart.
const annotationVMFirewallReverseDoneAt = vmFirewallAnnotationPrefix + "reverse-done-at"

// stampVMFirewallReverseDone writes the time a reverse migration is ending onto
// every other anchor. It runs before the anchor of the finished VM is deleted, so
// a crash leaves the stamp or the anchor, never neither.
func (c *nodeLoadBalancerController) stampVMFirewallReverseDone(ctx context.Context, finished *corev1.ConfigMap) error {
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return err
	}
	now := c.vmFirewallReverseTimeNow().Format(time.RFC3339Nano)
	for index := range anchors {
		if anchors[index].Name == finished.Name {
			continue
		}
		if _, _, err := c.updateVMFirewallAnchor(ctx, &anchors[index], func(cm *corev1.ConfigMap) (bool, error) {
			if cm.Annotations[annotationVMFirewallReverseDoneAt] == now {
				return false, nil
			}
			cm.Annotations[annotationVMFirewallReverseDoneAt] = now
			return true, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// vmFirewallReverseLastDone is the latest end of a reverse migration the anchors
// or this process remember.
func (c *nodeLoadBalancerController) vmFirewallReverseLastDone(anchors []corev1.ConfigMap) time.Time {
	last := c.vmFirewallLastGone()
	for index := range anchors {
		if at, err := time.Parse(time.RFC3339Nano, anchors[index].Annotations[annotationVMFirewallReverseDoneAt]); err == nil && at.After(last) {
			last = at
		}
	}
	return last
}

// isAdoptee says whether the Service takes the per-VM firewall by rename (reverse
// strategy B).
func (p vmFirewallMigrationPlan) isAdoptee(uid string) bool {
	return p.Strategy == vmFirewallMigrationStrategyAdopt && p.Adoptee == uid
}

// syncVMFirewallPerService is the VM pass of a controller that does not run the
// per-VM mode. It never creates or changes per-VM state: it resolves receipts a
// run of the per-VM mode left, and it moves the Services of a per-VM firewall
// back onto per-Service firewalls (spec section 7.4). Without an anchor there is
// nothing to do; the audit keeps holding the Services of such a VM.
func (c *nodeLoadBalancerController) syncVMFirewallPerService(ctx context.Context, vmUUID string) error {
	if _, err := c.vmFirewallNamespace(); err != nil {
		return nil
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil || anchor == nil {
		return err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return fmt.Errorf("public-node-local: list firewalls for VM %s: %w", vmUUID, err)
	}
	members := c.vmFirewallMemberLookup(vmUUID, nil)
	view := vmFirewallAnchorView{cm: anchor}
	if view.hasReceipt() {
		_, err := c.resolveVMFirewallReceipt(ctx, anchor, items, members)
		return err
	}
	if anchor.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		_, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.vmFirewallRelationOwner(vmUUID, members), nil)
		return err
	}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	raw := view.get(annotationVMFirewallMigration)
	plan, hasPlan, err := view.migration()
	if err != nil {
		return err
	}
	switch {
	case hasPlan && (plan.Direction == vmFirewallMigrationDirectionReverse ||
		plan.Direction == vmFirewallMigrationDirectionForward && plan.Phase == vmFirewallMigrationPhaseAborting):
		handled, err := c.stepVMFirewallMigration(ctx, vmUUID, anchor)
		if handled || err != nil {
			return err
		}
		// The VM has no Node any more: what a gone VM left is the upkeep's.
		return c.collectGoneVMEntries(ctx, vmUUID, applied, members)
	case len(applied.Members) == 0 && view.uuid() == "":
		return c.collectEmptyVMFirewallAnchor(ctx, vmUUID, anchor, items)
	case len(applied.Members) == 0:
		return vmFirewallDrift(vmUUID, "the anchor records firewall %s but no entries", view.uuid())
	case hasPlan && plan.Direction == vmFirewallMigrationDirectionForward && plan.Phase == vmFirewallMigrationPhasePlanned && view.uuid() == "":
		// A forward plan that opened nothing yet: the abort undoes it.
		next := plan
		next.Phase = vmFirewallMigrationPhaseAborting
		if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
			return err
		}
		c.queueVMFirewall(vmUUID)
		return nil
	}
	// No record, a finished forward record, or a forward migration that had
	// opened the per-VM firewall: plan the way back.
	return c.startVMFirewallReverse(ctx, vmUUID, anchor, raw, view, items)
}

// startVMFirewallReverse is the gate and the plan of a reverse migration: the
// hold annotation, one VM at a time, the pacing delay, a healthy Node, and
// Services that are steady. Nothing in the cloud changes.
func (c *nodeLoadBalancerController) startVMFirewallReverse(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	fromRaw string,
	view vmFirewallAnchorView,
	items []inspace.Firewall,
) error {
	members := c.vmFirewallMemberLookup(vmUUID, nil)
	node, err := c.publicNodeLocalNodeOfVM(ctx, vmUUID)
	if err != nil {
		return err
	}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if node == nil {
		// The Node is gone; a VM that is proven gone takes its entries off with the
		// ordinary upkeep, and nothing else is safe to decide without a Node.
		return c.collectGoneVMEntries(ctx, vmUUID, applied, members)
	}
	exist, err := c.serviceUIDsExist(ctx)
	if err != nil {
		return err
	}
	for _, member := range applied.Members {
		if _, found := exist[member.UID]; !found {
			// A Service that is gone leaves with its entry, after two spaced reads.
			_, err := c.collectGoneServiceEntries(ctx, vmUUID, anchor, applied, members)
			return err
		}
	}
	if strings.TrimSpace(node.Annotations[annotationPublicNodeLocalVMFirewallMigrate]) == vmFirewallMigrateValueHold {
		return nil
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return err
	}
	for index := range anchors {
		other := vmFirewallAnchorView{cm: &anchors[index]}
		if other.vm() != vmUUID && vmFirewallMigrationInFlight(&anchors[index]) {
			return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the reverse migration of VM %s waits: VM %s is migrating; VMs migrate one at a time", vmUUID, other.vm())
		}
	}
	now := c.vmFirewallReverseTimeNow()
	if last := c.vmFirewallReverseLastDone(anchors); !last.IsZero() {
		if until := last.Add(4 * c.provider.vmFirewallSettle()); now.Before(until) {
			return vmFirewallWait(until.Sub(now), "public-node-local: the reverse migration of VM %s waits for the pacing delay after the last VM", vmUUID)
		}
	}
	if !publicNodeLocalVMNodeHealthy(node) {
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the reverse migration of VM %s waits: its Node %s is not healthy", vmUUID, node.Name)
	}
	services, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: list Services to plan the reverse migration of VM %s: %w", vmUUID, err)
	}
	plan, err := planVMFirewallReverse(vmUUID, anchor, items, services.Items,
		c.provider.config.ClusterID, c.provider.config.BillingAccountID, c.provider.maxFirewallsPerVM())
	if err != nil {
		return c.reportVMFirewallReversePlanError(ctx, vmUUID, members, err)
	}
	if len(plan.Sources) == 0 {
		return nil
	}
	nextRaw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		return err
	}
	klog.Infof("node load balancer: plan the reverse migration of VM %s to per-Service firewalls (strategy %s, %d Services)", vmUUID, plan.Strategy, len(plan.Sources))
	if _, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		current := cm.Annotations[annotationVMFirewallMigration]
		if current == nextRaw {
			return false, nil
		}
		if current != fromRaw {
			return false, errors.New("public-node-local: the migration record changed before the reverse migration was planned")
		}
		if (vmFirewallAnchorView{cm: cm}).hasReceipt() {
			return false, errors.New("public-node-local: the VM firewall anchor has a receipt, so the reverse migration is not planned over it")
		}
		cm.Annotations[annotationVMFirewallMigration] = nextRaw
		return true, nil
	}); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// reportVMFirewallReversePlanError announces a deferral or a block on the member
// Services of the VM and turns it into the wait or hold the caller returns.
func (c *nodeLoadBalancerController) reportVMFirewallReversePlanError(
	ctx context.Context,
	vmUUID string,
	members func(context.Context) []*corev1.Service,
	cause error,
) error {
	var deferred *errVMFirewallMigrationDeferred
	var blocked *errVMFirewallMigrationBlocked
	reason := ""
	switch {
	case errors.As(cause, &deferred):
		reason = publicNodeLocalReasonVMFirewallMigrationWaiting
	case errors.As(cause, &blocked):
		reason = publicNodeLocalReasonVMFirewallMigrationBlocked
	default:
		return cause
	}
	c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), reason, cause)
	if blocked != nil {
		return cause
	}
	return vmFirewallWait(nodeLoadBalancerRetry, "%v", cause)
}

// reversePlanOfAdoptedMigration is the reverse migration that undoes a forward
// adopt which committed: the per-VM firewall goes back under the name and rules
// of the Service whose firewall it was, and the other Services keep the firewalls
// they still have on the VM. It does not look at the Services: the reverse steps
// wait for each of them to be steady before they act.
func reversePlanOfAdoptedMigration(forward vmFirewallMigrationPlan) vmFirewallMigrationPlan {
	plan := vmFirewallMigrationPlan{
		Direction: vmFirewallMigrationDirectionReverse, Phase: vmFirewallMigrationPhasePlanned,
		Strategy: vmFirewallMigrationStrategyAdopt,
	}
	for _, source := range forward.Sources {
		member := vmFirewallMigrationSource{Firewall: source.Firewall, UID: source.UID, Policy: source.Policy}
		if strings.EqualFold(source.Firewall, forward.Adoptee) {
			plan.Adoptee = source.UID
			member.Firewall = ""
		}
		plan.Sources = append(plan.Sources, member)
	}
	sort.Slice(plan.Sources, func(i, j int) bool { return plan.Sources[i].UID < plan.Sources[j].UID })
	return plan
}

// convertAdoptedMigrationToReverse turns a forward migration whose adopt
// committed into the reverse migration that undoes it, and says so.
func (c *nodeLoadBalancerController) convertAdoptedMigrationToReverse(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	forward vmFirewallMigrationPlan,
	cause error,
) error {
	next := reversePlanOfAdoptedMigration(forward)
	klog.Warningf("node load balancer: turn the migration of VM %s to the per-VM firewall around: %v", vmUUID, cause)
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, forward, next); err != nil {
		return err
	}
	c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, c.vmFirewallMemberLookup(vmUUID, nil)),
		publicNodeLocalReasonVMFirewallMigrationWaiting,
		fmt.Errorf("public-node-local: the migration of VM %s is turned around: %w; its per-VM firewall goes back under the name of Service %s", vmUUID, cause, next.Adoptee))
	c.queueVMFirewall(vmUUID)
	return nil
}

// stepVMFirewallReverse advances a reverse migration by at most one durable
// step. Phases: planned attaches the own firewall of every member (adoptee
// excepted) to the VM, opened lets that settle, detaching takes the members off
// the per-VM firewall: one entry per pass (strategy A) until the last removal
// deletes the firewall and the anchor, or one rename (strategy B) that turns the
// per-VM firewall into the adoptee's own and deletes the anchor.
func (c *nodeLoadBalancerController) stepVMFirewallReverse(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	switch plan.Phase {
	case vmFirewallMigrationPhasePlanned:
		return c.attachVMFirewallReverse(ctx, vmUUID, anchor, plan, read)
	case vmFirewallMigrationPhaseOpened:
		return c.settleVMFirewallReverse(ctx, anchor, plan)
	case vmFirewallMigrationPhaseDetaching:
		return c.detachVMFirewallReverse(ctx, vmUUID, anchor, plan, read)
	default:
		return fmt.Errorf("public-node-local: the reverse migration of VM %s is in phase %q, which this build can not continue", vmUUID, plan.Phase)
	}
}

// reverseMemberChanged says a member is no longer what the plan recorded.
func (c *nodeLoadBalancerController) reverseMemberChanged(svc *corev1.Service, source vmFirewallMigrationSource, allowReceipt bool) error {
	if svc.DeletionTimestamp != nil {
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s is being deleted; the reverse migration waits for it", svc.Namespace, svc.Name)
	}
	if reason := vmFirewallReverseServiceWaiting(svc, allowReceipt); reason != "" {
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the reverse migration waits: Service %s/%s %s", svc.Namespace, svc.Name, reason)
	}
	desired, err := c.desiredServiceFirewall(svc)
	if err != nil {
		return err
	}
	if desired.Hash != source.Policy || svc.Annotations[annotationPublicNodeLocalActivePolicy] != source.Policy {
		return sourceChanged("Service %s/%s wants policy %s, the reverse migration moves %s", svc.Namespace, svc.Name, desired.Hash, source.Policy)
	}
	return nil
}

// ensureReverseServiceFirewall returns the own firewall of a member once the Service
// records it. A step that created the firewall or recorded it returns nil and
// true: the caller's pass ends there.
func (c *nodeLoadBalancerController) ensureReverseServiceFirewall(
	ctx context.Context,
	svc *corev1.Service,
	source vmFirewallMigrationSource,
	read vmFirewallMigrationRead,
) (*inspace.Firewall, bool, error) {
	desired, err := c.desiredServiceFirewall(svc)
	if err != nil {
		return nil, false, err
	}
	if own := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]; own != "" {
		firewall, err := exactNodeLoadBalancerFirewallFromItems(read.items, own)
		if err != nil {
			return nil, false, sourceChanged("the own firewall %s of Service %s/%s: %v", own, svc.Namespace, svc.Name, err)
		}
		if !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
			!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, source.UID, c.provider.config.BillingAccountID) ||
			svc.Annotations[annotationNodeLoadBalancerFirewallHash] != source.Policy {
			return nil, false, sourceChanged("firewall %s is not the exact own firewall of Service %s/%s", own, svc.Namespace, svc.Name)
		}
		return firewall, false, nil
	}
	firewall, _, _, err := c.ensureServiceFirewall(ctx, svc, nil)
	if err != nil {
		return nil, false, err
	}
	if firewall == nil {
		return nil, true, nil
	}
	if _, err := c.ensureFirewallMetadata(ctx, svc, firewall, ""); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

// attachVMFirewallReverse attaches the own firewall of each member to the VM, one
// durable step per pass, and opens the plan when every one is attached.
func (c *nodeLoadBalancerController) attachVMFirewallReverse(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan, read vmFirewallMigrationRead) error {
	view := vmFirewallAnchorView{cm: anchor}
	if view.uuid() == "" {
		return vmFirewallDrift(vmUUID, "the reverse migration has no per-VM firewall to retire")
	}
	for _, source := range plan.Sources {
		if plan.isAdoptee(source.UID) {
			continue
		}
		svc := read.services[source.UID]
		if svc == nil {
			continue // gone: its entry leaves with the ordinary upkeep
		}
		if svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
			svc.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
			// A receipt of an earlier attach (ours, or one that survived a restart) is
			// resolved before anything else is decided for the Service.
			if _, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.serviceFirewallRelationOwner(svc), nil); err != nil {
				return err
			}
			c.queueVMFirewall(vmUUID)
			return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s: resolving its firewall relation receipt", svc.Namespace, svc.Name)
		}
		if err := c.reverseMemberChanged(svc, source, false); err != nil {
			return err
		}
		firewall, acted, err := c.ensureReverseServiceFirewall(ctx, svc, source, read)
		if err != nil {
			return err
		}
		if acted {
			c.queueVMFirewall(vmUUID)
			return nil
		}
		if vmFirewallAttachedTo(*firewall, vmUUID) {
			continue
		}
		owner := c.serviceFirewallRelationOwner(svc)
		owner.authorize = func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			return c.authorizeVMFirewallReverseAttach(ctx, vmUUID, source, fence, before)
		}
		fence := nodeLoadBalancerFirewallRelationFence{
			operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
		}
		klog.Infof("node load balancer: attach firewall %s of Service %s to VM %s: the reverse migration moves it off the per-VM firewall", firewall.UUID, source.UID, vmUUID)
		converged, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, &fence)
		if err != nil {
			return err
		}
		if !converged {
			return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: firewall %s is being attached to VM %s", firewall.UUID, vmUUID)
		}
		c.queueVMFirewall(vmUUID)
		return nil
	}
	next := plan
	next.Phase = vmFirewallMigrationPhaseOpened
	next.OpenedAt = c.vmFirewallReverseTimeNow().Format(time.RFC3339Nano)
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// authorizeVMFirewallReverseAttach is the final authority before a member's own
// firewall is attached to the VM: the plan is the recorded one and still
// planned, the member is steady under the policy the plan moves, the firewall is
// unchanged since it was read and is exactly that policy, and the Node is healthy.
func (c *nodeLoadBalancerController) authorizeVMFirewallReverseAttach(
	ctx context.Context,
	vmUUID string,
	source vmFirewallMigrationSource,
	fence nodeLoadBalancerFirewallRelationFence,
	before inspace.Firewall,
) error {
	if fence.operation != nodeLoadBalancerFirewallRelationAssign || !strings.EqualFold(fence.vmUUID, vmUUID) {
		return fmt.Errorf("public-node-local: relation %s is not an attach to VM %s", fence.logicalString(), vmUUID)
	}
	validate := func() error {
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if anchor == nil {
			return errors.New("public-node-local: the VM firewall anchor disappeared during the reverse migration")
		}
		current, ok, err := (vmFirewallAnchorView{cm: anchor}).migration()
		if err != nil {
			return err
		}
		if !ok || current.Direction != vmFirewallMigrationDirectionReverse || current.Phase != vmFirewallMigrationPhasePlanned {
			return errors.New("public-node-local: the reverse migration is not attaching, so no firewall may be attached")
		}
		if _, listed := current.sourceOfService(source.UID); !listed {
			return fmt.Errorf("public-node-local: Service %s is no member of this reverse migration", source.UID)
		}
		svc, err := c.getExactParentServiceByUID(ctx, source.UID)
		if err != nil {
			return err
		}
		// The attach itself holds the relation receipt of the Service by now.
		if err := c.reverseMemberChanged(svc, source, true); err != nil {
			return err
		}
		if svc.Annotations[annotationNodeLoadBalancerFirewallUUID] != fence.firewallUUID {
			return fmt.Errorf("public-node-local: Service %s/%s no longer names firewall %s", svc.Namespace, svc.Name, fence.firewallUUID)
		}
		firewall, err := c.exactNodeLoadBalancerFirewallFresh(ctx, fence.firewallUUID)
		if err != nil {
			return err
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *firewall) {
			return fmt.Errorf("public-node-local: firewall %s changed after the attach was issued", fence.firewallUUID)
		}
		desired, err := c.desiredServiceFirewall(svc)
		if err != nil {
			return err
		}
		if !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
			!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, source.UID, c.provider.config.BillingAccountID) {
			return fmt.Errorf("public-node-local: firewall %s is no longer the exact own firewall of Service %s", fence.firewallUUID, source.UID)
		}
		return nil
	}
	if err := validate(); err != nil {
		return err
	}
	node, err := c.exactNodeForFirewallRelationVM(ctx, fence.vmUUID)
	if err != nil {
		return err
	}
	if err := requirePublicNodeLocalFirewallVM([]*corev1.Node{node}, fence.vmUUID); err != nil {
		return err
	}
	return validate()
}

// getExactParentServiceByUID reads the live Service with a UID, or fails when
// there is none.
func (c *nodeLoadBalancerController) getExactParentServiceByUID(ctx context.Context, uid string) (*corev1.Service, error) {
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return nil, err
	}
	svc := read.services[uid]
	if svc == nil {
		return nil, fmt.Errorf("public-node-local: Service %s no longer exists", uid)
	}
	return svc, nil
}

// settleVMFirewallReverse waits for the attached firewalls to take effect before
// the per-VM firewall narrows.
func (c *nodeLoadBalancerController) settleVMFirewallReverse(ctx context.Context, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	vmUUID := (vmFirewallAnchorView{cm: anchor}).vm()
	if remaining := c.vmFirewallReverseSettleRemaining(plan); remaining > 0 {
		return &errPublicNodeLocalVMFirewallSettling{vmUUID: vmUUID, retryAfter: remaining}
	}
	next := plan
	next.Phase = vmFirewallMigrationPhaseDetaching
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

func (c *nodeLoadBalancerController) vmFirewallReverseSettleRemaining(plan vmFirewallMigrationPlan) time.Duration {
	opened, err := time.Parse(time.RFC3339Nano, plan.OpenedAt)
	if err != nil {
		return c.provider.vmFirewallSettle() // unreadable fails closed: the full delay
	}
	if remaining := opened.Add(c.provider.vmFirewallSettle()).Sub(c.vmFirewallReverseTimeNow()); remaining > 0 {
		return remaining
	}
	return 0
}

// authorizeVMFirewallReverseRemove is the verified intent of taking one entry off
// the per-VM firewall: the plan is detaching and settled, the member is steady
// under that policy, and its own firewall is attached to this VM, is exactly
// that policy, and so allows everything the entry allows.
func (c *nodeLoadBalancerController) authorizeVMFirewallReverseRemove(vmUUID string, key vmFirewallMemberKey) vmFirewallDeltaAuthority {
	return func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if anchor == nil {
			return errors.New("public-node-local: the VM firewall anchor disappeared during the reverse migration")
		}
		plan, ok, err := (vmFirewallAnchorView{cm: anchor}).migration()
		if err != nil {
			return err
		}
		if !ok || plan.Direction != vmFirewallMigrationDirectionReverse || plan.Phase != vmFirewallMigrationPhaseDetaching ||
			plan.Strategy != vmFirewallMigrationStrategyHeadroom {
			return errors.New("public-node-local: the reverse migration is not retiring entries, so no entry may leave the per-VM firewall")
		}
		source, listed := plan.sourceOfService(key.UID)
		if !listed || source.Policy != key.Policy {
			return fmt.Errorf("public-node-local: entry %s/%s is no member of this reverse migration", key.UID, key.Policy)
		}
		if remaining := c.vmFirewallReverseSettleRemaining(plan); remaining > 0 {
			return fmt.Errorf("public-node-local: the own firewalls of VM %s have not settled for %s yet", vmUUID, remaining)
		}
		read, err := c.readVMFirewallMigration(ctx)
		if err != nil {
			return err
		}
		svc := read.services[key.UID]
		if svc == nil {
			return fmt.Errorf("public-node-local: Service %s is gone; its entry leaves through the upkeep after two spaced reads", key.UID)
		}
		if err := c.reverseMemberChanged(svc, source, false); err != nil {
			return err
		}
		own := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]
		firewall, err := exactNodeLoadBalancerFirewallFromItems(read.items, own)
		if err != nil {
			return fmt.Errorf("public-node-local: the own firewall of Service %s: %w", key.UID, err)
		}
		desired, err := c.desiredServiceFirewall(svc)
		if err != nil {
			return err
		}
		if !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
			!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, key.UID, c.provider.config.BillingAccountID) ||
			svc.Annotations[annotationNodeLoadBalancerFirewallHash] != key.Policy {
			return fmt.Errorf("public-node-local: firewall %s is not the exact own firewall of Service %s", own, key.UID)
		}
		if !vmFirewallAttachedTo(*firewall, vmUUID) {
			return fmt.Errorf("public-node-local: the own firewall %s of Service %s is not attached to VM %s", own, key.UID, vmUUID)
		}
		return nil
	}
}

// detachVMFirewallReverse takes the members off the per-VM firewall.
func (c *nodeLoadBalancerController) detachVMFirewallReverse(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan, read vmFirewallMigrationRead) error {
	view := vmFirewallAnchorView{cm: anchor}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if len(applied.Members) == 0 {
		return vmFirewallDrift(vmUUID, "the reverse migration has no entry left to retire and the per-VM firewall is not being deleted")
	}
	members := c.vmFirewallMemberLookup(vmUUID, nil)
	for _, member := range applied.Members {
		if read.services[member.UID] == nil {
			// A Service that is gone takes its entry with it, after two spaced reads.
			_, err := c.collectGoneServiceEntries(ctx, vmUUID, anchor, applied, members)
			return err
		}
	}
	if plan.Strategy == vmFirewallMigrationStrategyAdopt {
		return c.unadoptVMFirewallReverse(ctx, vmUUID, anchor, plan, applied, read)
	}
	member := applied.Members[0]
	key := member.key()
	source, listed := plan.sourceOfService(key.UID)
	if !listed {
		return vmFirewallDrift(vmUUID, "the per-VM firewall holds an entry of Service %s that the reverse migration does not move", key.UID)
	}
	if svc := read.services[key.UID]; svc != nil {
		if err := c.reverseMemberChanged(svc, source, false); err != nil {
			return err
		}
	}
	klog.Infof("node load balancer: take Service %s off the per-VM firewall of VM %s: its own firewall carries its rules", key.UID, vmUUID)
	if _, err := c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Remove: &key}, c.authorizeVMFirewallReverseRemove(vmUUID, key), members); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}
