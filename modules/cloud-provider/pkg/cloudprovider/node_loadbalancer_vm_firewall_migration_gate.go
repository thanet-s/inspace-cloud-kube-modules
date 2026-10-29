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

const (
	// The silent reasons: a VM that is not asked for, or is on hold, is not an
	// event worth requeueing for.
	vmFirewallMigrationReasonNotRequested = "the migration of this VM was not requested"
	vmFirewallMigrationReasonHold         = "the Node is on hold"
)

func vmFirewallMigrationReasonSilent(reason string) bool {
	return reason == vmFirewallMigrationReasonNotRequested || reason == vmFirewallMigrationReasonHold
}

func (c *nodeLoadBalancerController) vmFirewallMigrationAuto() bool {
	return c.provider.config.NodeLoadBalancer.VMFirewallMigration == VMFirewallMigrationAuto
}

// publicNodeLocalNodeOfVM returns the one public-node-local Node of a VM, or nil
// when it has none.
func (c *nodeLoadBalancerController) publicNodeLocalNodeOfVM(ctx context.Context, vmUUID string) (*corev1.Node, error) {
	list, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list Nodes for VM %s: %w", vmUUID, err)
	}
	var found *corev1.Node
	for index := range list.Items {
		node := &list.Items[index]
		if id, ok := nodeLoadBalancerVMUUID(node); !ok || !strings.EqualFold(id, vmUUID) || node.Labels[publicNodeLocalPoolLabel] == "" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("public-node-local: VM %s has more than one public-node-local Node", vmUUID)
		}
		found = node.DeepCopy()
	}
	return found, nil
}

// vmFirewallMigrationAllowed says whether VM vmUUID may take a migration step
// now, and if not, why (spec sections 4.1 and 7.1). A migration that already
// started continues unless its Node is on hold; a new one needs the Node
// annotation in manual mode, no other VM mid-migration, and the pacing delay
// (four settle periods) since the last VM finished.
func (c *nodeLoadBalancerController) vmFirewallMigrationAllowed(
	ctx context.Context,
	vmUUID string,
	node *corev1.Node,
	anchors []corev1.ConfigMap,
	now time.Time,
) (bool, string) {
	if node == nil {
		return false, "the VM has no public-node-local Node"
	}
	value := strings.TrimSpace(node.Annotations[annotationPublicNodeLocalVMFirewallMigrate])
	if value == vmFirewallMigrateValueHold {
		return false, vmFirewallMigrationReasonHold
	}
	var lastDone time.Time
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		plan, ok, err := view.migration()
		if err != nil {
			return false, fmt.Sprintf("the migration record of VM %s is unreadable", view.vm())
		}
		if !ok {
			continue
		}
		if view.vm() == vmUUID {
			// A migration that started continues, and so does the cleanup after it,
			// whatever the Node annotation says now; only a hold stops it.
			return true, ""
		}
		if plan.Phase != vmFirewallMigrationPhaseDone {
			continue
		}
		if at, parseErr := time.Parse(time.RFC3339Nano, plan.DoneAt); parseErr == nil && at.After(lastDone) {
			lastDone = at
		}
	}
	if !c.vmFirewallMigrationAuto() && value != vmFirewallMigrateValueTrue {
		return false, vmFirewallMigrationReasonNotRequested
	}
	for index := range anchors {
		if view := (vmFirewallAnchorView{cm: &anchors[index]}); view.vm() != vmUUID && vmFirewallMigrationInFlight(&anchors[index]) {
			return false, fmt.Sprintf("VM %s is migrating; VMs migrate one at a time", view.vm())
		}
	}
	if !lastDone.IsZero() {
		if until := lastDone.Add(4 * c.provider.vmFirewallSettle()); now.Before(until) {
			return false, fmt.Sprintf("the last VM finished %s ago; the next one waits for %s", now.Sub(lastDone).Round(time.Second), until.Sub(now).Round(time.Second))
		}
	}
	return true, ""
}

// publicNodeLocalVMFirewallMigrationHold holds every edge mutation of a
// per-Service Service while a migration has it as a source, from the moment the
// plan is recorded until its own cleanup flips it to the per-VM firewall. A
// Service on several VMs is "mixed" in between: some of its VMs carry the
// per-VM firewall and some its own, and only the migration may touch either.
func (c *nodeLoadBalancerController) publicNodeLocalVMFirewallMigrationHold(ctx context.Context, svc *corev1.Service) error {
	// The firewall-uuid annotation is not a condition: the cleanup of a source
	// deletes its firewall, which clears that annotation, before it flips the
	// Service to the per-VM firewall. In between, the Service has no firewall of
	// its own and must not create one.
	if !c.publicNodeLocalPerVMModeEnabled() {
		return nil
	}
	onPerVM := publicNodeLocalServicePerVM(svc)
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return err
	}
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		plan, ok, planErr := view.migration()
		if planErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, svc, planErr)
		}
		if !ok {
			continue
		}
		// A Service on the per-VM firewall is held only by a reverse migration that
		// started while the mode was off and is moving it back.
		if onPerVM && plan.Direction != vmFirewallMigrationDirectionReverse {
			continue
		}
		for _, source := range plan.Sources {
			if source.UID != string(svc.UID) {
				continue
			}
			target := "the per-VM firewall"
			if plan.Direction == vmFirewallMigrationDirectionReverse {
				target = "per-Service firewalls"
			}
			cause := vmFirewallWait(nodeLoadBalancerRetry,
				"public-node-local: Service %s/%s waits: VM %s is moving to %s (%s)", svc.Namespace, svc.Name, view.vm(), target, plan.Phase)
			c.recordPublicNodeLocalEvent(ctx, svc, publicNodeLocalReasonVMFirewallMigrationWaiting, cause)
			return c.holdOrFailPublicNodeLocal(ctx, svc, cause)
		}
	}
	return nil
}

// vmFirewallMigrationCandidateVMs lists the VMs a migration may start on: in
// manual mode the Nodes that ask for it (or are on hold, so the hold is seen),
// in auto mode every public-node-local Node.
func (c *nodeLoadBalancerController) vmFirewallMigrationCandidateVMs(ctx context.Context) ([]string, error) {
	list, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var vms []string
	for index := range list.Items {
		node := &list.Items[index]
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok || node.Labels[publicNodeLocalPoolLabel] == "" {
			continue
		}
		if !c.vmFirewallMigrationAuto() && node.Annotations[annotationPublicNodeLocalVMFirewallMigrate] == "" {
			continue
		}
		vms = append(vms, vmUUID)
	}
	return vms, nil
}

// startVMFirewallMigration is M0 and M1 for a VM with no anchor: plan it, and
// record the plan on a new anchor. Nothing in the cloud changes.
func (c *nodeLoadBalancerController) startVMFirewallMigration(ctx context.Context, vmUUID string, items []inspace.Firewall) error {
	if !c.publicNodeLocalPerVMModeEnabled() {
		return nil
	}
	node, err := c.publicNodeLocalNodeOfVM(ctx, vmUUID)
	if err != nil || node == nil {
		return err
	}
	value := strings.TrimSpace(node.Annotations[annotationPublicNodeLocalVMFirewallMigrate])
	if value == vmFirewallMigrateValueHold || (!c.vmFirewallMigrationAuto() && value != vmFirewallMigrateValueTrue) {
		return nil
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return err
	}
	if allowed, reason := c.vmFirewallMigrationAllowed(ctx, vmUUID, node, anchors, c.nodeLoadBalancerFirewallRelationTime()); !allowed {
		if vmFirewallMigrationReasonSilent(reason) {
			return nil
		}
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the migration of VM %s waits: %s", vmUUID, reason)
	}
	// The per-VM firewall is attached to this VM, which needs a healthy Node.
	if !publicNodeLocalVMNodeHealthy(node) {
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the migration of VM %s waits: its Node %s is not healthy", vmUUID, node.Name)
	}
	baseUUID, err := c.vmFirewallMigrationBaseFirewall(ctx)
	if err != nil {
		return err
	}
	services, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: list Services to plan the migration of VM %s: %w", vmUUID, err)
	}
	plan, err := planVMFirewallMigration(vmUUID, items, services.Items,
		c.provider.config.ClusterID, c.provider.config.BillingAccountID, baseUUID, c.provider.maxFirewallsPerVM())
	if err != nil {
		return c.reportVMFirewallMigrationPlanError(ctx, vmUUID, services.Items, items, err)
	}
	if len(plan.Sources) == 0 {
		return nil
	}
	raw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		return err
	}
	anchor, err := c.createVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	klog.Infof("node load balancer: plan the migration of VM %s to the per-VM firewall (strategy %s, %d sources)", vmUUID, plan.Strategy, len(plan.Sources))
	_, _, err = c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.Annotations[annotationVMFirewallMigration] != "" {
			return false, nil
		}
		if (vmFirewallAnchorView{cm: cm}).hasReceipt() || cm.Annotations[annotationVMFirewallUUID] != "" || cm.Annotations[annotationVMFirewallApplied] != "" {
			return false, errors.New("public-node-local: the VM firewall anchor already holds state, so the migration is not planned over it")
		}
		cm.Annotations[annotationVMFirewallMigration] = raw
		return true, nil
	})
	if err != nil {
		return err
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// reportVMFirewallMigrationPlanError announces a deferral or a block on the
// Services of the VM and turns it into the wait or hold the caller returns.
func (c *nodeLoadBalancerController) reportVMFirewallMigrationPlanError(
	ctx context.Context,
	vmUUID string,
	services []corev1.Service,
	items []inspace.Firewall,
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
	var affected []*corev1.Service
	for index := range services {
		uuid := services[index].Annotations[annotationNodeLoadBalancerFirewallUUID]
		if uuid == "" {
			continue
		}
		for _, firewall := range items {
			if firewall.UUID == uuid && vmFirewallAttachedTo(firewall, vmUUID) {
				affected = append(affected, services[index].DeepCopy())
			}
		}
	}
	c.recordVMFirewallEvent(ctx, affected, reason, cause)
	if blocked != nil {
		return cause
	}
	return vmFirewallWait(nodeLoadBalancerRetry, "%v", cause)
}

// queueVMFirewall queues the VM pass of one VM, when a queue exists.
func (c *nodeLoadBalancerController) queueVMFirewall(vmUUID string) {
	if c.queue != nil {
		c.queue.Add(vmFirewallQueueKey(vmUUID))
	}
}
