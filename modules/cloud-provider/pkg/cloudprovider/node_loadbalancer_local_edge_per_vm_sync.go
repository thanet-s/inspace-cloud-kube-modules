package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	// vmFirewallQueuePrefix keys the work queue entry of one VM. It holds a
	// colon, which no namespace or Service name can, so it never collides with a
	// "namespace/name" key.
	vmFirewallQueuePrefix = "vmfw:"

	// annotationVMFirewallGonePrefix records, on the anchor, when the Service of
	// an entry was first seen gone. One annotation per Service UID.
	annotationVMFirewallGonePrefix = vmFirewallAnnotationPrefix + "gone-"

	// vmFirewallEnqueueDebounce bounds how often the anchors are listed for the
	// work queue: Service and Node events can arrive many times a second.
	vmFirewallEnqueueDebounce = 10 * time.Second

	// vmFirewallOrphanScanInterval is how often the cloud is listed to find a
	// per-VM firewall that has no anchor.
	vmFirewallOrphanScanInterval = 10 * time.Minute
)

func vmFirewallQueueKey(vmUUID string) string { return vmFirewallQueuePrefix + vmUUID }

// parseVMFirewallQueueKey recognizes the queue key of a VM.
func parseVMFirewallQueueKey(key string) (string, bool) {
	vmUUID, ok := strings.CutPrefix(key, vmFirewallQueuePrefix)
	if !ok || validateVMFirewallAnchorVMUUID(vmUUID) != nil {
		return "", false
	}
	return vmUUID, true
}

// enqueueVMFirewalls queues every VM that has an anchor. It is silent when the
// anchors cannot be listed: the per-Service mode needs no ConfigMap access.
func (c *nodeLoadBalancerController) enqueueVMFirewalls() {
	if !c.publicNodeLocalPerVMModeEnabled() || c.queue == nil {
		return
	}
	now := time.Now()
	c.vmFirewallOrphanMu.Lock()
	if now.Sub(c.vmFirewallEnqueuedAt) < vmFirewallEnqueueDebounce {
		c.vmFirewallOrphanMu.Unlock()
		return
	}
	c.vmFirewallEnqueuedAt = now
	c.vmFirewallOrphanMu.Unlock()
	anchors, err := c.listVMFirewallAnchors(context.Background())
	if err != nil {
		klog.V(2).Infof("node load balancer: list VM firewall anchors for the queue: %v", err)
		return
	}
	for index := range anchors {
		c.queue.Add(vmFirewallQueueKey((vmFirewallAnchorView{cm: &anchors[index]}).vm()))
	}
}

// enqueueVMFirewallOrphans queues the VM of every per-VM firewall in the cloud,
// so one that lost its anchor is rebuilt or collected.
func (c *nodeLoadBalancerController) enqueueVMFirewallOrphans(ctx context.Context) {
	if !c.publicNodeLocalPerVMModeEnabled() || c.queue == nil {
		return
	}
	now := time.Now()
	c.vmFirewallOrphanMu.Lock()
	if now.Sub(c.vmFirewallScannedAt) < vmFirewallOrphanScanInterval {
		c.vmFirewallOrphanMu.Unlock()
		return
	}
	c.vmFirewallScannedAt = now
	c.vmFirewallOrphanMu.Unlock()
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		klog.V(2).Infof("node load balancer: list firewalls for the VM firewall orphan scan: %v", err)
		return
	}
	for index := range items {
		if vmUUID, ok := inspace.ParseNodeLoadBalancerVMFirewallName(c.provider.config.ClusterID, items[index].EffectiveName()); ok {
			c.queue.Add(vmFirewallQueueKey(vmUUID))
		}
	}
}

// syncVMFirewall is the pass of one VM that no Service owns: it resolves a
// receipt, repairs on request, reports drift, takes the entries of Services
// that are gone off the VM, and collects what is empty or orphaned. Every step
// holds on anything it cannot verify; none removes a rule on a guess.
func (c *nodeLoadBalancerController) syncVMFirewall(ctx context.Context, vmUUID string) error {
	if !c.publicNodeLocalPerVMModeEnabled() {
		return nil
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return fmt.Errorf("public-node-local: list firewalls for VM %s: %w", vmUUID, err)
	}
	members := c.vmFirewallMemberLookup(vmUUID, nil)
	if anchor == nil {
		return c.syncUnanchoredVMFirewall(ctx, vmUUID, items, members)
	}
	view := vmFirewallAnchorView{cm: anchor}
	if view.hasReceipt() {
		_, err := c.resolveVMFirewallReceipt(ctx, anchor, items, members)
		return err
	}
	if anchor.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		_, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.vmFirewallRelationOwner(vmUUID, members), nil)
		return err
	}
	if view.get(annotationVMFirewallRepair) != "" {
		return c.repairVMFirewall(ctx, anchor)
	}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if len(applied.Members) == 0 && view.uuid() == "" {
		return c.collectEmptyVMFirewallAnchor(ctx, vmUUID, anchor, items)
	}
	if _, err := c.observeVMFirewall(vmUUID, view, applied, items); err != nil {
		if errors.Is(err, errVMFirewallDrift) {
			c.recordVMFirewallEvent(ctx, members(ctx), vmFirewallDriftReason, err)
		}
		return err
	}
	if acted, err := c.collectGoneServiceEntries(ctx, vmUUID, anchor, applied, members); acted || err != nil {
		return err
	}
	return c.collectGoneVMEntries(ctx, vmUUID, applied, members)
}

// syncUnanchoredVMFirewall handles a per-VM firewall whose anchor is gone: an
// attached one gets its ledger rebuilt by exact attribution, or holds; an
// unattached one is collected once its VM is proven absent.
func (c *nodeLoadBalancerController) syncUnanchoredVMFirewall(
	ctx context.Context,
	vmUUID string,
	items []inspace.Firewall,
	members func(context.Context) []*corev1.Service,
) error {
	name, err := inspace.NodeLoadBalancerVMFirewallName(c.provider.config.ClusterID, vmUUID)
	if err != nil {
		return err
	}
	firewall, err := vmFirewallByNameFromItems(items, name)
	if err != nil {
		return vmFirewallDrift(vmUUID, "%v", err)
	}
	if firewall == nil {
		return nil
	}
	if len(firewall.ResourcesAssigned) == 0 {
		return c.collectOrphanVMFirewall(ctx, *firewall, members)
	}
	list, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: list Services to rebuild the ledger of VM %s: %w", vmUUID, err)
	}
	return c.rebuildVMFirewallAnchor(ctx, vmUUID, *firewall, list.Items)
}

// collectEmptyVMFirewallAnchor deletes an anchor that never recorded anything
// and has no firewall: what a refused create leaves behind.
func (c *nodeLoadBalancerController) collectEmptyVMFirewallAnchor(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	items []inspace.Firewall,
) error {
	name, err := inspace.NodeLoadBalancerVMFirewallName(c.provider.config.ClusterID, vmUUID)
	if err != nil {
		return err
	}
	if firewall, nameErr := vmFirewallByNameFromItems(items, name); nameErr != nil || firewall != nil {
		return nameErr
	}
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return err
	}
	cms := c.provider.kubeClient.CoreV1().ConfigMaps(namespace)
	fresh, err := cms.Get(ctx, anchor.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fresh.UID != anchor.UID || (vmFirewallAnchorView{cm: fresh}).hasReceipt() || fresh.Annotations[annotationVMFirewallApplied] != "" ||
		fresh.Annotations[annotationVMFirewallUUID] != "" || fresh.Annotations[annotationVMFirewallMigration] != "" {
		return nil
	}
	stripped := fresh.DeepCopy()
	stripped.Finalizers = nil
	for _, finalizer := range fresh.Finalizers {
		if finalizer != vmFirewallAnchorFinalizer {
			stripped.Finalizers = append(stripped.Finalizers, finalizer)
		}
	}
	if _, err := cms.Update(ctx, stripped, metav1.UpdateOptions{}); err != nil {
		return err
	}
	uid := fresh.UID
	if err := cms.Delete(ctx, anchor.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// serviceUIDsExist lists the UIDs of the Services that exist in the cluster.
func (c *nodeLoadBalancerController) serviceUIDsExist(ctx context.Context) (map[string]struct{}, error) {
	list, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list Services: %w", err)
	}
	uids := make(map[string]struct{}, len(list.Items))
	for index := range list.Items {
		uids[string(list.Items[index].UID)] = struct{}{}
	}
	return uids, nil
}

// collectGoneServiceEntries takes the entries of Services that no longer exist
// off the VM (spec section 6.4, case 4): the Service must be absent on two
// reads at least one confirmation delay apart, the first of which is recorded
// on the anchor, so a restart can only delay the removal. It reports whether it
// acted.
func (c *nodeLoadBalancerController) collectGoneServiceEntries(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	applied vmFirewallLedger,
	members func(context.Context) []*corev1.Service,
) (bool, error) {
	exist, err := c.serviceUIDsExist(ctx)
	if err != nil {
		return false, err
	}
	gone := map[string]struct{}{}
	for _, member := range applied.Members {
		if _, found := exist[member.UID]; !found {
			gone[member.UID] = struct{}{}
		}
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	// Forget the Services that came back, record the ones just seen gone.
	var firstSeen map[string]time.Time
	_, _, err = c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		changed := false
		firstSeen = map[string]time.Time{}
		for key, value := range cm.Annotations {
			uid, isGone := strings.CutPrefix(key, annotationVMFirewallGonePrefix)
			if !isGone {
				continue
			}
			if _, stillGone := gone[uid]; !stillGone {
				delete(cm.Annotations, key)
				changed = true
				continue
			}
			if at, parseErr := time.Parse(time.RFC3339Nano, value); parseErr == nil {
				firstSeen[uid] = at
			} else {
				delete(cm.Annotations, key)
				changed = true
			}
		}
		for uid := range gone {
			if _, seen := firstSeen[uid]; !seen {
				cm.Annotations[annotationVMFirewallGonePrefix+uid] = now.Format(time.RFC3339Nano)
				firstSeen[uid] = now
				changed = true
			}
		}
		return changed, nil
	})
	if err != nil {
		return false, err
	}
	if len(gone) == 0 {
		return false, nil
	}
	delay := c.nodeLoadBalancerFirewallRelationAbsenceDelay()
	uids := make([]string, 0, len(gone))
	for uid := range gone {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		if remaining := firstSeen[uid].Add(delay).Sub(now); remaining > 0 {
			return true, vmFirewallWait(remaining, "public-node-local: Service %s is gone from VM %s; waiting for a second spaced read before its entries leave", uid, vmUUID)
		}
		var key *vmFirewallMemberKey
		for _, member := range applied.Members {
			if member.UID == uid {
				k := member.key()
				key = &k
				break
			}
		}
		if key == nil {
			continue
		}
		recheck := func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
			again, err := c.serviceUIDsExist(ctx)
			if err != nil {
				return err
			}
			if _, found := again[uid]; found {
				return fmt.Errorf("public-node-local: Service %s exists again", uid)
			}
			return nil
		}
		_, err := c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Remove: key}, recheck, members)
		return true, err
	}
	return false, nil
}

// collectGoneVMEntries removes the entries of a VM that is proven gone from its
// ledger, without a PUT: nothing can reach a deleted VM, and the last removal
// deletes the firewall and the anchor.
func (c *nodeLoadBalancerController) collectGoneVMEntries(
	ctx context.Context,
	vmUUID string,
	applied vmFirewallLedger,
	members func(context.Context) []*corev1.Service,
) error {
	if len(applied.Members) == 0 {
		return nil
	}
	owned, absent, err := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, vmUUID)
	if err != nil || owned || !absent {
		return err
	}
	key := applied.Members[0].key()
	proven := func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		owned, absent, err := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, vmUUID)
		if err != nil {
			return err
		}
		if owned || !absent {
			return fmt.Errorf("public-node-local: VM %s is not proven gone", vmUUID)
		}
		return nil
	}
	_, err = c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Remove: &key, LedgerOnly: true}, proven, members)
	return err
}
