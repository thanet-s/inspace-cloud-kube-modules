package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const vmFirewallLedgerRebuiltReason = "PublicNodeLocalVMFirewallLedgerRebuilt"

var errVMFirewallNoRepair = errors.New("public-node-local: no VM firewall repair was requested on the anchor")

func emptyVMFirewallLedgerJSON() (string, error) {
	return encodeVMFirewallLedger(vmFirewallLedger{V: vmFirewallLedgerVersion, Members: []vmFirewallMember{}})
}

// stageVMFirewallDelete records the intent to remove the whole per-VM firewall.
// The pre-dispatch authority runs first: once the delete is staged the anchor
// is the durable verified intent, and any pass may carry it out.
func (c *nodeLoadBalancerController) stageVMFirewallDelete(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	observation vmFirewallObservation,
	authorize vmFirewallDeltaAuthority,
) error {
	if observation.firewall == nil {
		return errors.New("public-node-local: there is no VM firewall to delete")
	}
	if err := authorize(ctx, anchor, observation.firewall); err != nil {
		return fmt.Errorf("public-node-local: reject VM firewall delete for %s at final authority: %w", anchor.Annotations[annotationVMFirewallVM], err)
	}
	empty, err := emptyVMFirewallLedgerJSON()
	if err != nil {
		return err
	}
	appliedRaw := anchor.Annotations[annotationVMFirewallApplied]
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	_, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != appliedRaw {
			return false, errors.New("public-node-local: the VM firewall anchor changed before the delete was staged")
		}
		cm.Annotations[annotationVMFirewallPending] = empty
		cm.Annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpDelete)
		cm.Annotations[annotationVMFirewallPendingAt] = now
		return true, nil
	})
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("public-node-local: the VM firewall delete was not staged")
	}
	return nil
}

// removeVMFirewallEntryLedgerOnly drops one entry of a VM that is gone. Nothing
// can reach a deleted VM, so no PUT is made; the last entry starts the delete.
func (c *nodeLoadBalancerController) removeVMFirewallEntryLedgerOnly(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	observation vmFirewallObservation,
	next vmFirewallLedger,
	authorize vmFirewallDeltaAuthority,
) error {
	owned, absent, err := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, vmUUID)
	if err != nil {
		return err
	}
	if owned || !absent {
		return fmt.Errorf("public-node-local: a ledger-only removal needs VM %s to be gone, and it is not", vmUUID)
	}
	if len(next.Members) == 0 {
		return c.stageVMFirewallDelete(ctx, anchor, observation, authorize)
	}
	if err := authorize(ctx, anchor, observation.firewall); err != nil {
		return fmt.Errorf("public-node-local: reject ledger-only VM firewall removal for %s: %w", vmUUID, err)
	}
	nextRaw, err := encodeVMFirewallLedger(next)
	if err != nil {
		return err
	}
	appliedRaw := anchor.Annotations[annotationVMFirewallApplied]
	_, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != appliedRaw {
			return false, errors.New("public-node-local: the VM firewall anchor changed before the ledger-only removal")
		}
		// applied-hash keeps describing the firewall as it is in the cloud.
		cm.Annotations[annotationVMFirewallApplied] = nextRaw
		return true, nil
	})
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("public-node-local: the ledger-only removal was not persisted")
	}
	return nil
}

func (c *nodeLoadBalancerController) clearVMFirewallDeleteIssue(ctx context.Context, anchor *corev1.ConfigMap, clearAbsence, clearIssued bool) error {
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	_, _, err := c.updateVMFirewallAnchor(resetCtx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		changed := false
		for key, clear := range map[string]bool{
			annotationVMFirewallAbsenceCount:     clearAbsence,
			annotationVMFirewallAbsenceCheckedAt: clearAbsence,
			annotationVMFirewallDeleteIssued:     clearIssued,
		} {
			if _, present := cm.Annotations[key]; clear && present {
				delete(cm.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

// deleteVMFirewall carries a staged delete one durable step further: detach,
// then DELETE under an issued receipt, then three absent reads spaced by the
// confirmation delay (a visible firewall resets the count), then the anchor
// finalizer and the anchor. It returns true once the anchor is gone.
func (c *nodeLoadBalancerController) deleteVMFirewall(ctx context.Context, anchor *corev1.ConfigMap) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	vmUUID, uuid := view.vm(), view.uuid()
	if view.pendingOp() != string(vmFirewallOpDelete) || !validNodeLoadBalancerCloudUUID(uuid) {
		return false, corruptVMFirewallLedger("anchor %s has no valid staged delete", anchor.Name)
	}
	cluster := c.provider.config.ClusterID
	owner := c.vmFirewallRelationOwner(vmUUID, nil)
	if anchor.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		_, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, nil)
		return false, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, fmt.Errorf("public-node-local: list firewalls to delete the VM firewall of %s: %w", vmUUID, err)
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	delay := c.nodeLoadBalancerFirewallRelationAbsenceDelay()
	var firewall *inspace.Firewall
	matches := 0
	for index := range items {
		if strings.EqualFold(items[index].UUID, uuid) {
			matches++
			if items[index].UUID == uuid {
				copied := items[index]
				firewall = &copied
			}
		}
	}
	if matches > 1 || (matches == 1 && firewall == nil) {
		return false, fmt.Errorf("public-node-local: firewall UUID %s has %d case-folded rows during its delete", uuid, matches)
	}
	target, issuedRaw := view.get(annotationVMFirewallDeleteTarget), view.get(annotationVMFirewallDeleteIssued)
	if target != "" && target != uuid {
		return false, corruptVMFirewallLedger("anchor %s delete targets %s, not %s", anchor.Name, target, uuid)
	}
	absenceRaw := view.get(annotationVMFirewallAbsenceCount)

	if firewall != nil {
		if err := inspace.ValidateNodeLoadBalancerVMFirewallIdentity(*firewall, cluster, vmUUID, c.provider.config.BillingAccountID); err != nil {
			return false, vmFirewallDrift(vmUUID, "refusing to delete firewall %s: %v", uuid, err)
		}
		rows, err := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
		if err != nil {
			return false, err
		}
		if len(rows) != 0 {
			for _, row := range rows {
				fence := nodeLoadBalancerFirewallRelationFence{
					operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: uuid, vmUUID: row,
				}
				converged, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, &fence)
				if err != nil || !converged {
					return false, err
				}
			}
			return false, nil
		}
		if issuedRaw != "" {
			if absenceRaw != "" {
				// The firewall is visible again: the absence proof starts over.
				return false, c.clearVMFirewallDeleteIssue(ctx, anchor, true, false)
			}
			issuedAt, err := time.Parse(time.RFC3339Nano, issuedRaw)
			if err != nil {
				return false, corruptVMFirewallLedger("anchor %s delete-issued %q", anchor.Name, issuedRaw)
			}
			if wait := issuedAt.Add(nodeLoadBalancerFirewallRelationRetireDelay).Sub(now); wait > 0 {
				return false, vmFirewallWait(min(wait, nodeLoadBalancerRetry), "public-node-local: VM firewall %s was deleted but is still listed; waiting", uuid)
			}
			// The DELETE can no longer be in flight and the same unassigned,
			// owned UUID is still listed: it did not commit. Allow it once more.
			return false, c.clearVMFirewallDeleteIssue(ctx, anchor, false, true)
		}
		return c.issueVMFirewallDelete(ctx, anchor, *firewall)
	}

	// The firewall is not listed.
	if target == "" {
		_, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
			if cm.Annotations[annotationVMFirewallDeleteTarget] != "" {
				return false, nil
			}
			cm.Annotations[annotationVMFirewallDeleteTarget] = uuid
			return true, nil
		})
		return false, err
	}
	count := 0
	if absenceRaw != "" {
		parsed, err := strconv.Atoi(absenceRaw)
		if err != nil || parsed < 1 || parsed > nodeLoadBalancerAbsenceConfirmations {
			return false, corruptVMFirewallLedger("anchor %s absence count %q", anchor.Name, absenceRaw)
		}
		count = parsed
		checked, err := time.Parse(time.RFC3339Nano, view.get(annotationVMFirewallAbsenceCheckedAt))
		if err != nil {
			return false, corruptVMFirewallLedger("anchor %s absence-checked-at %q", anchor.Name, view.get(annotationVMFirewallAbsenceCheckedAt))
		}
		if wait := checked.Add(delay).Sub(now); wait > 0 {
			return false, vmFirewallWait(wait, "public-node-local: VM firewall %s: waiting for the next spaced absent read", uuid)
		}
	}
	if count+1 >= nodeLoadBalancerAbsenceConfirmations {
		return true, c.finalizeVMFirewallAnchor(ctx, anchor)
	}
	_, _, err = c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.Annotations[annotationVMFirewallDeleteTarget] != uuid || cm.Annotations[annotationVMFirewallAbsenceCount] != absenceRaw {
			return false, errors.New("public-node-local: the VM firewall delete receipt changed during its absence proof")
		}
		cm.Annotations[annotationVMFirewallAbsenceCount] = strconv.Itoa(count + 1)
		cm.Annotations[annotationVMFirewallAbsenceCheckedAt] = now.Format(time.RFC3339Nano)
		return true, nil
	})
	if err != nil {
		return false, err
	}
	return false, vmFirewallWait(delay, "public-node-local: VM firewall %s: absent read %d recorded", uuid, count+1)
}

// issueVMFirewallDelete writes the delete-issued receipt, re-authorizes, and
// only then sends the DELETE.
func (c *nodeLoadBalancerController) issueVMFirewallDelete(ctx context.Context, anchor *corev1.ConfigMap, firewall inspace.Firewall) (bool, error) {
	vmUUID, uuid := anchor.Annotations[annotationVMFirewallVM], firewall.UUID
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	issued, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpDelete) || cm.Annotations[annotationVMFirewallDeleteIssued] != "" {
			return false, errors.New("public-node-local: the VM firewall delete changed before it was issued")
		}
		cm.Annotations[annotationVMFirewallDeleteTarget] = uuid
		cm.Annotations[annotationVMFirewallDeleteIssued] = now
		delete(cm.Annotations, annotationVMFirewallAbsenceCount)
		delete(cm.Annotations, annotationVMFirewallAbsenceCheckedAt)
		return true, nil
	})
	if err != nil {
		return false, err
	}
	if !changed {
		return false, errors.New("public-node-local: the VM firewall delete was not issued")
	}
	reject := func(cause error) (bool, error) {
		rejection := fmt.Errorf("public-node-local: reject VM firewall delete for %s at final authority: %w", vmUUID, cause)
		if resetErr := c.clearVMFirewallDeleteIssue(ctx, issued, false, true); resetErr != nil {
			return false, errors.Join(rejection, resetErr)
		}
		return false, rejection
	}
	current, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return reject(err)
	}
	if current == nil || current.UID != issued.UID ||
		current.Annotations[annotationVMFirewallDeleteIssued] != now ||
		current.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpDelete) {
		return reject(errors.New("the delete receipt changed after it was issued"))
	}
	fresh, err := c.exactNodeLoadBalancerFirewallFresh(ctx, uuid)
	if err != nil {
		return reject(err)
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(firewall, *fresh) {
		return reject(fmt.Errorf("firewall %s changed after the delete was issued", uuid))
	}
	if err := inspace.ValidateNodeLoadBalancerVMFirewallIdentity(*fresh, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID); err != nil {
		return reject(err)
	}
	if len(fresh.ResourcesAssigned) != 0 {
		return reject(fmt.Errorf("firewall %s is still attached", uuid))
	}
	callCtx, cancel := context.WithTimeout(ctx, vmFirewallMutationTimeoutBase)
	defer cancel()
	klog.Infof("node load balancer: delete VM firewall %s of VM %s", uuid, vmUUID)
	deleteErr := c.provider.api.DeleteFirewall(callCtx, c.provider.config.Location, uuid)
	if deleteErr != nil {
		deleteErr = fmt.Errorf("public-node-local: delete VM firewall %s: %w", uuid, deleteErr)
		if nodeLoadBalancerMutationKnownPreDispatch(deleteErr) {
			return false, errors.Join(deleteErr, c.clearVMFirewallDeleteIssue(ctx, issued, false, true))
		}
		// Ambiguous: the receipt stays, and the readback decides.
		return false, errors.Join(deleteErr, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: VM firewall %s delete is ambiguous", uuid))
	}
	return false, nil
}

// finalizeVMFirewallAnchor removes the anchor finalizer and deletes the anchor,
// last, after the firewall is proven absent.
func (c *nodeLoadBalancerController) finalizeVMFirewallAnchor(ctx context.Context, anchor *corev1.ConfigMap) error {
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
		return fmt.Errorf("public-node-local: read the VM firewall anchor to finalize it: %w", err)
	}
	if fresh.UID != anchor.UID || fresh.Annotations[annotationVMFirewallDeleteTarget] != anchor.Annotations[annotationVMFirewallDeleteTarget] ||
		fresh.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpDelete) {
		return errors.New("public-node-local: the VM firewall delete receipt changed before the anchor was finalized")
	}
	stripped := fresh.DeepCopy()
	kept := stripped.Finalizers[:0]
	for _, finalizer := range stripped.Finalizers {
		if finalizer != vmFirewallAnchorFinalizer {
			kept = append(kept, finalizer)
		}
	}
	stripped.Finalizers = kept
	if _, err := cms.Update(ctx, stripped, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("public-node-local: remove the VM firewall anchor finalizer: %w", err)
	}
	uid := fresh.UID
	err = cms.Delete(ctx, anchor.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("public-node-local: delete the VM firewall anchor: %w", err)
	}
	return nil
}

// repairVMFirewall re-PUTs merged(applied) over a drifted firewall when, and
// only when, the anchor carries the repair annotation. The annotation is
// removed in the commit that reads the repair back, so it is single use.
func (c *nodeLoadBalancerController) repairVMFirewall(ctx context.Context, anchor *corev1.ConfigMap) error {
	view := vmFirewallAnchorView{cm: anchor}
	vmUUID := view.vm()
	if view.get(annotationVMFirewallRepair) == "" {
		return errVMFirewallNoRepair
	}
	if view.hasReceipt() {
		return vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: VM firewall of %s has an open receipt; resolve it before a repair", vmUUID)
	}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if len(applied.Members) == 0 || !validNodeLoadBalancerCloudUUID(view.uuid()) {
		return fmt.Errorf("public-node-local: VM firewall of %s has no applied ledger to restore", vmUUID)
	}
	merged, err := mergeVMFirewallLedger(applied)
	if err != nil {
		return err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return fmt.Errorf("public-node-local: list firewalls to repair the VM firewall of %s: %w", vmUUID, err)
	}
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, view.uuid())
	if err != nil {
		return err
	}
	if err := inspace.ValidateNodeLoadBalancerVMFirewallIdentity(*firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID); err != nil {
		return fmt.Errorf("public-node-local: refusing to repair a firewall that is not the VM firewall of %s: %w", vmUUID, err)
	}
	stillRequested := func(_ context.Context, current *corev1.ConfigMap, _ *inspace.Firewall) error {
		if current.Annotations[annotationVMFirewallRepair] == "" {
			return errVMFirewallNoRepair
		}
		return nil
	}
	return c.runVMFirewallMutation(ctx, vmUUID, anchor, vmFirewallObservation{firewall: firewall, attached: vmFirewallAttachedTo(*firewall, vmUUID)},
		vmFirewallOpUpdate, applied, merged, stillRequested, nil)
}

type vmFirewallRuleKey string

func vmFirewallFirewallRuleKey(rule inspace.FirewallRule) vmFirewallRuleKey {
	port := int32(0)
	if rule.PortStart != nil {
		port = *rule.PortStart
	}
	sources := "any"
	if rule.EndpointSpecType != "any" {
		sorted := append([]string(nil), rule.EndpointSpec...)
		sort.Strings(sorted)
		sources = strings.Join(sorted, ",")
	}
	return vmFirewallRuleKey(fmt.Sprintf("%s/%d/%s", rule.Protocol, port, sources))
}

// rebuildVMFirewallAnchor recovers the ledger of a per-VM firewall whose anchor
// is lost, by attribution: every rule must belong to exactly one live Service,
// and the rules attributed to a Service must be exactly its policy's rules.
// Anything else holds the VM. A rebuild never mutates the cloud.
func (c *nodeLoadBalancerController) rebuildVMFirewallAnchor(
	ctx context.Context,
	vmUUID string,
	firewall inspace.Firewall,
	services []corev1.Service,
) error {
	cluster := c.provider.config.ClusterID
	if err := inspace.ValidateNodeLoadBalancerVMFirewallIdentity(firewall, cluster, vmUUID, c.provider.config.BillingAccountID); err != nil {
		return fmt.Errorf("public-node-local: refusing to rebuild from a firewall that is not the VM firewall of %s: %w", vmUUID, err)
	}
	existing, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	if existing != nil {
		applied, appliedErr := vmFirewallAnchorView{cm: existing}.applied()
		if appliedErr != nil {
			return appliedErr
		}
		if len(applied.Members) != 0 {
			return fmt.Errorf("public-node-local: VM %s already has an applied ledger; a rebuild would replace evidence", vmUUID)
		}
	}
	pointers := make([]*corev1.Service, 0, len(services))
	for index := range services {
		pointers = append(pointers, &services[index])
	}
	hold := func(format string, args ...any) error {
		err := vmFirewallDrift(vmUUID, "cannot rebuild the ledger: "+format, args...)
		c.recordVMFirewallEvent(ctx, pointers, vmFirewallDriftReason, err)
		return err
	}

	type candidate struct {
		service *corev1.Service
		member  vmFirewallMember
	}
	candidates := make([]candidate, 0, len(services))
	for _, service := range pointers {
		desired, desiredErr := c.desiredServiceFirewall(service)
		if desiredErr != nil {
			continue // a Service with an unusable spec can own nothing it cannot state
		}
		member, memberErr := vmFirewallMemberFromDesired(string(service.UID), desired)
		if memberErr != nil {
			continue
		}
		candidates = append(candidates, candidate{service: service, member: member})
	}
	owners := map[vmFirewallRuleKey][]int{}
	for index, cand := range candidates {
		for _, rule := range vmFirewallMemberFirewallRules(cand.member) {
			key := vmFirewallFirewallRuleKey(rule)
			owners[key] = append(owners[key], index)
		}
	}
	attributed := map[int]int{}
	for _, rule := range firewall.Rules {
		key := vmFirewallFirewallRuleKey(rule)
		who := owners[key]
		switch len(who) {
		case 0:
			return hold("rule %s belongs to no live Service", key)
		case 1:
			attributed[who[0]]++
		default:
			return hold("rule %s could belong to %d Services", key, len(who))
		}
	}
	ledger := vmFirewallLedger{V: vmFirewallLedgerVersion, Members: []vmFirewallMember{}}
	members := []*corev1.Service{}
	for index, count := range attributed {
		cand := candidates[index]
		if count != len(cand.member.Rules) {
			return hold("Service %s owns %d of the %d rules of its policy %s", cand.member.UID, count, len(cand.member.Rules), cand.member.Policy)
		}
		ledger, err = ledger.with(cand.member)
		if err != nil {
			return hold("%v", err)
		}
		members = append(members, cand.service)
	}
	if len(ledger.Members) == 0 {
		return hold("no Service owns any rule")
	}
	merged, err := mergeVMFirewallLedger(ledger)
	if err != nil {
		return hold("%v", err)
	}
	mergedHash, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged)
	if err != nil {
		return hold("%v", err)
	}
	actualHash, err := inspace.NodeLoadBalancerVMFirewallSpecHash(firewall.Rules)
	if err != nil {
		return hold("%v", err)
	}
	if mergedHash != actualHash {
		return hold("the attributed ledger hashes to %s, the firewall to %s", mergedHash, actualHash)
	}
	encoded, err := encodeVMFirewallLedger(ledger)
	if err != nil {
		return err
	}
	anchor := existing
	if anchor == nil {
		if anchor, err = c.createVMFirewallAnchor(ctx, vmUUID); err != nil {
			return err
		}
	}
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	_, _, err = c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != "" {
			return false, errors.New("public-node-local: the VM firewall anchor changed during its rebuild")
		}
		cm.Annotations[annotationVMFirewallUUID] = firewall.UUID
		cm.Annotations[annotationVMFirewallApplied] = encoded
		cm.Annotations[annotationVMFirewallAppliedHash] = actualHash
		cm.Annotations[annotationVMFirewallAppliedAt] = now
		return true, nil
	})
	if err != nil {
		return err
	}
	c.recordVMFirewallEvent(ctx, members, vmFirewallLedgerRebuiltReason,
		fmt.Errorf("the ledger of the VM firewall of %s was rebuilt from %d Service(s) by exact attribution", vmUUID, len(ledger.Members)))
	return nil
}

// collectOrphanVMFirewall deletes a per-VM firewall that has no anchor, no
// assignment and a VM that is gone, after two absent reads of the VM spaced by
// the confirmation delay. The first read is kept in memory only: a restart can
// only delay the delete. An attached orphan, or one of a live VM, is held.
func (c *nodeLoadBalancerController) collectOrphanVMFirewall(
	ctx context.Context,
	firewall inspace.Firewall,
	members func(context.Context) []*corev1.Service,
) error {
	cluster := c.provider.config.ClusterID
	vmUUID, ok := inspace.ParseNodeLoadBalancerVMFirewallName(cluster, firewall.EffectiveName())
	if !ok || firewall.BillingAccountID != c.provider.config.BillingAccountID {
		return fmt.Errorf("public-node-local: firewall %q is not a per-VM firewall of this cluster", firewall.EffectiveName())
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	if anchor != nil {
		return nil
	}
	if len(firewall.ResourcesAssigned) != 0 {
		err := vmFirewallDrift(vmUUID, "firewall %s has no anchor but is still attached", firewall.UUID)
		c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), vmFirewallDriftReason, err)
		return err
	}
	owned, absent, err := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, vmUUID)
	if err != nil {
		return err
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	c.vmFirewallOrphanMu.Lock()
	first, seen := c.vmFirewallOrphanSince[vmUUID]
	switch {
	case owned || !absent:
		delete(c.vmFirewallOrphanSince, vmUUID)
		c.vmFirewallOrphanMu.Unlock()
		return nil
	case !seen:
		if c.vmFirewallOrphanSince == nil {
			c.vmFirewallOrphanSince = map[string]time.Time{}
		}
		c.vmFirewallOrphanSince[vmUUID] = now
		c.vmFirewallOrphanMu.Unlock()
		return vmFirewallWait(c.nodeLoadBalancerFirewallRelationAbsenceDelay(), "public-node-local: VM %s is absent; waiting for a second spaced read before deleting its orphan firewall", vmUUID)
	case now.Before(first.Add(c.nodeLoadBalancerFirewallRelationAbsenceDelay())):
		c.vmFirewallOrphanMu.Unlock()
		return vmFirewallWait(first.Add(c.nodeLoadBalancerFirewallRelationAbsenceDelay()).Sub(now), "public-node-local: VM %s is absent; the second read is not spaced enough yet", vmUUID)
	}
	delete(c.vmFirewallOrphanSince, vmUUID)
	c.vmFirewallOrphanMu.Unlock()

	fresh, err := c.exactNodeLoadBalancerFirewallFresh(ctx, firewall.UUID)
	if err != nil {
		return err
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(firewall, *fresh) || len(fresh.ResourcesAssigned) != 0 {
		return vmFirewallDrift(vmUUID, "orphan firewall %s changed before its delete", firewall.UUID)
	}
	if again, getErr := c.getVMFirewallAnchor(ctx, vmUUID); getErr != nil || again != nil {
		return getErr
	}
	callCtx, cancel := context.WithTimeout(ctx, vmFirewallMutationTimeoutBase)
	defer cancel()
	klog.Infof("node load balancer: delete orphan VM firewall %s of the absent VM %s", firewall.UUID, vmUUID)
	if err := c.provider.api.DeleteFirewall(callCtx, c.provider.config.Location, firewall.UUID); err != nil {
		return fmt.Errorf("public-node-local: delete orphan VM firewall %s: %w", firewall.UUID, err)
	}
	return nil
}
