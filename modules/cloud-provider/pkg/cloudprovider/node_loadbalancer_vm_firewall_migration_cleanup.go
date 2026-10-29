package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// publishedVMsOfService lists the VMs whose public address the Service has in
// its status.
func (c *nodeLoadBalancerController) publishedVMsOfService(ctx context.Context, svc *corev1.Service) ([]string, error) {
	list, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	fips := publicNodeLocalIngressSet(svc.Status.LoadBalancer)
	var vms []string
	for index := range list.Items {
		node := &list.Items[index]
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			continue
		}
		if public, hasPublic := nodeLoadBalancerNodeExternalIPv4(node); hasPublic {
			if _, published := fips[public]; published {
				vms = append(vms, vmUUID)
			}
		}
	}
	return vms, nil
}

// cleanupVMFirewallMigration is M6 for the Services of a finished VM: each one
// whose VMs are all open on the per-VM firewall, and whose own firewall is on no
// VM, gives that firewall up and flips to the per-VM edge. One durable step per
// call.
func (c *nodeLoadBalancerController) cleanupVMFirewallMigration(ctx context.Context, plan vmFirewallMigrationPlan) error {
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return err
	}
	for _, source := range plan.Sources {
		svc := read.services[source.UID]
		if svc == nil || svc.DeletionTimestamp != nil || publicNodeLocalServicePerVM(svc) {
			continue // a deleted Service is the Service pass's; a flipped one is done
		}
		if uuid := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]; uuid != source.Firewall && uuid != "" {
			continue
		}
		acted, err := c.cleanupMigratedService(ctx, svc, source, read, anchors)
		if err != nil || acted {
			return err
		}
	}
	return nil
}

// cleanupMigratedService reports whether it made a durable step.
func (c *nodeLoadBalancerController) cleanupMigratedService(
	ctx context.Context,
	svc *corev1.Service,
	source vmFirewallMigrationSource,
	read vmFirewallMigrationRead,
	anchors []corev1.ConfigMap,
) (bool, error) {
	if svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		if _, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.serviceFirewallRelationOwner(svc), nil); err != nil {
			return true, err
		}
		return true, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s: resolving its firewall relation receipt", svc.Namespace, svc.Name)
	}
	isAdoptee := false
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		if strings.EqualFold(view.uuid(), source.Firewall) {
			isAdoptee = true
		}
		// Another VM of the Service that has not finished still needs the firewall
		// and the Service state as the plan recorded them.
		if plan, ok, err := view.migration(); err != nil {
			return false, err
		} else if ok && plan.Phase != vmFirewallMigrationPhaseDone {
			if _, listed := plan.source(source.Firewall); listed {
				return false, nil
			}
		}
	}
	firewall, listed := exactNodeLoadBalancerFirewallFromItemsOptional(read.items, source.Firewall)
	if listed && !isAdoptee {
		rows, err := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
		if err != nil {
			return false, err
		}
		if len(rows) != 0 {
			return false, nil // still guarding a VM that has not migrated
		}
	}
	// Every VM the Service is published on must be open through the per-VM firewall.
	published, err := c.publishedVMsOfService(ctx, svc)
	if err != nil {
		return false, err
	}
	open, err := c.vmEdgeAssigned(source.UID, source.Policy, read.items, anchors)
	if err != nil {
		return true, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s: %v", svc.Namespace, svc.Name, err)
	}
	for _, vmUUID := range published {
		if _, isOpen := open[vmUUID]; !isOpen {
			return false, nil
		}
	}
	// An earlier pass may have sent the DELETE already: the receipt on the Service
	// then still waits for its spaced absent reads, with the firewall not listed.
	if (listed || svc.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != "") && !isAdoptee {
		done, err := c.deleteOwnedServiceFirewall(ctx, svc, source.Firewall)
		if err != nil {
			return true, err
		}
		if !done {
			return true, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: Service %s/%s: its firewall %s is being deleted", svc.Namespace, svc.Name, source.Firewall)
		}
		c.requeuePublicNodeLocal(svc.Namespace + "/" + svc.Name)
		return true, nil
	}
	_, changed, err := c.updateExactParentService(ctx, svc, func(copy *corev1.Service) (bool, error) {
		if uuid := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]; uuid != source.Firewall && uuid != "" {
			return false, errors.New("public-node-local: the Service names another firewall than the migration retired")
		}
		for _, key := range []string{annotationNodeLoadBalancerFWDeleteTarget, annotationNodeLoadBalancerFWDeleteIssued} {
			if copy.Annotations[key] != "" {
				return false, errors.New("public-node-local: the Service has a firewall delete receipt in flight")
			}
		}
		for _, key := range []string{
			annotationNodeLoadBalancerFirewallUUID, annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerFirewallAbsent, annotationNodeLoadBalancerFirewallChecked,
			annotationNodeLoadBalancerCleanupFWAbsent, annotationNodeLoadBalancerCleanupFWChecked,
		} {
			delete(copy.Annotations, key)
		}
		copy.Annotations[annotationPublicNodeLocalFirewallMode] = publicNodeLocalEdgePerVM
		return true, nil
	})
	if err != nil {
		return true, err
	}
	if changed {
		klog.Infof("node load balancer: Service %s/%s now lives on the per-VM firewall", svc.Namespace, svc.Name)
		c.requeuePublicNodeLocal(svc.Namespace + "/" + svc.Name)
	}
	return changed, nil
}

// blockVMFirewallMigration announces that the migration of a VM can not go on
// without an operator and holds it.
func (c *nodeLoadBalancerController) blockVMFirewallMigration(ctx context.Context, vmUUID string, plan vmFirewallMigrationPlan, reason string) error {
	cause := &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: reason}
	read, err := c.readVMFirewallMigration(ctx)
	if err == nil {
		var services []*corev1.Service
		for _, source := range plan.Sources {
			if svc := read.services[source.UID]; svc != nil {
				services = append(services, svc.DeepCopy())
			}
		}
		c.recordVMFirewallEvent(ctx, services, publicNodeLocalReasonVMFirewallMigrationBlocked, cause)
	}
	return cause
}

// sourceChangedBeforeOpen handles a source that changed before the per-VM
// firewall was open (spec section 7.2, abort before M3). The plan becomes an
// abort, which undoes what was added. An adopt that already committed can not be
// undone here: the rename would have to be reversed, which the reverse migration
// does; until then the VM holds and says so.
func (c *nodeLoadBalancerController) sourceChangedBeforeOpen(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	plan vmFirewallMigrationPlan,
	cause error,
) error {
	view := vmFirewallAnchorView{cm: anchor}
	if plan.Strategy == vmFirewallMigrationStrategyAdopt && view.uuid() != "" {
		return c.blockVMFirewallMigration(ctx, vmUUID, plan,
			fmt.Sprintf("a source changed after firewall %s was renamed into the per-VM firewall (%v); the rename has to be reversed", plan.Adoptee, cause))
	}
	klog.Warningf("node load balancer: abort the migration of VM %s to the per-VM firewall: %v", vmUUID, cause)
	next := plan
	next.Phase = vmFirewallMigrationPhaseAborting
	if _, err := c.writeVMFirewallMigrationPlan(ctx, anchor, plan, next); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// authorizeVMFirewallMigrationAbort is the verified intent of the removals an
// abort makes: the anchor's record says aborting.
func (c *nodeLoadBalancerController) authorizeVMFirewallMigrationAbort(vmUUID string) vmFirewallDeltaAuthority {
	return func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		fresh, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if fresh == nil {
			return errors.New("public-node-local: the VM firewall anchor disappeared during the abort")
		}
		plan, ok, err := (vmFirewallAnchorView{cm: fresh}).migration()
		if err != nil {
			return err
		}
		if !ok || plan.Phase != vmFirewallMigrationPhaseAborting {
			return errors.New("public-node-local: the migration is not aborting, so no entry may leave the per-VM firewall")
		}
		return nil
	}
}

// abortVMFirewallMigration undoes an unopened migration one durable step at a
// time. The per-Service firewalls are untouched and stay attached throughout, so
// taking entries off the per-VM firewall narrows nothing that serves. The last
// entry stages the delete of the per-VM firewall; the delete ends with the anchor,
// and its record with it. With nothing in the cloud the record is dropped and
// the empty anchor is collected.
func (c *nodeLoadBalancerController) abortVMFirewallMigration(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap, plan vmFirewallMigrationPlan) error {
	view := vmFirewallAnchorView{cm: anchor}
	if plan.Strategy == vmFirewallMigrationStrategyAdopt && view.uuid() != "" {
		return c.blockVMFirewallMigration(ctx, vmUUID, plan, "the adopted firewall can not be un-adopted by an abort; the rename has to be reversed")
	}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if len(applied.Members) != 0 {
		key := applied.Members[0].key()
		_, err := c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Remove: &key},
			c.authorizeVMFirewallMigrationAbort(vmUUID), c.vmFirewallMemberLookup(vmUUID, nil))
		if err == nil {
			c.queueVMFirewall(vmUUID)
		}
		return err
	}
	if view.uuid() != "" {
		return vmFirewallDrift(vmUUID, "the anchor records firewall %s but no entries during an abort", view.uuid())
	}
	raw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		return err
	}
	if _, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.Annotations[annotationVMFirewallMigration] != raw {
			return false, errors.New("public-node-local: the migration record changed before the abort ended")
		}
		delete(cm.Annotations, annotationVMFirewallMigration)
		return true, nil
	}); err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// queueDeferredVMFirewallMigrations queues every VM a migration may start on,
// so one that was deferred for want of a single-VM firewall plans again.
func (c *nodeLoadBalancerController) queueDeferredVMFirewallMigrations(ctx context.Context) {
	candidates, err := c.vmFirewallMigrationCandidateVMs(ctx)
	if err != nil {
		klog.V(2).Infof("node load balancer: list Nodes to requeue deferred migrations: %v", err)
		return
	}
	for _, vmUUID := range candidates {
		c.queueVMFirewall(vmUUID)
	}
}
