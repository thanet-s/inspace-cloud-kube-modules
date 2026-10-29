package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// vmFirewallUnadoptRequest is the PUT body that turns the per-VM firewall back
// into the own firewall of one Service: the name goes out as display_name (the
// only field InSpace honours), and the rules shrink to that Service's policy.
// Rules whose protocol/port survive keep their provider UUID, so the port that
// serves is never closed and reopened.
func vmFirewallUnadoptRequest(current inspace.Firewall, desired desiredNodeLoadBalancerFirewall) (inspace.UpdateFirewallRequest, error) {
	if !vmFirewallRenameSupportedForTest {
		return inspace.UpdateFirewallRequest{}, errors.New("public-node-local: renaming a firewall is not supported")
	}
	if !nodeLoadBalancerFirewallUUIDPattern.MatchString(current.UUID) {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: firewall UUID %q to rename is invalid", current.UUID)
	}
	if current.EffectiveName() == desired.Request.DisplayName {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: firewall %s already carries the name %q", current.UUID, desired.Request.DisplayName)
	}
	seen := map[string]struct{}{}
	for _, rule := range current.Rules {
		if rule.UUID == "" {
			continue
		}
		if !nodeLoadBalancerFirewallUUIDPattern.MatchString(rule.UUID) {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: rule UUID %q of the firewall to rename is invalid", rule.UUID)
		}
		if _, duplicate := seen[strings.ToLower(rule.UUID)]; duplicate {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: the firewall to rename reuses rule UUID %q", rule.UUID)
		}
		seen[strings.ToLower(rule.UUID)] = struct{}{}
	}
	return inspace.UpdateFirewallRequest{
		Name:        desired.Request.DisplayName,
		Description: desired.Request.Description,
		Rules:       retainFirewallRuleUUIDs(current.Rules, desired.Request.Rules),
	}, nil
}

// reverseMemberOpenOnVM proves that a member's own firewall carries the member
// on this VM: the Service is steady under the plan's policy, and its own firewall
// is the exact firewall of that policy and is attached to the VM.
func (c *nodeLoadBalancerController) reverseMemberOpenOnVM(
	vmUUID string,
	svc *corev1.Service,
	source vmFirewallMigrationSource,
	items []inspace.Firewall,
) error {
	if err := c.reverseMemberChanged(svc, source, false); err != nil {
		return err
	}
	own := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, own)
	if err != nil {
		return fmt.Errorf("public-node-local: the own firewall of Service %s: %w", source.UID, err)
	}
	desired, err := c.desiredServiceFirewall(svc)
	if err != nil {
		return err
	}
	if !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
		!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, source.UID, c.provider.config.BillingAccountID) ||
		svc.Annotations[annotationNodeLoadBalancerFirewallHash] != source.Policy {
		return fmt.Errorf("public-node-local: firewall %s is not the exact own firewall of Service %s", own, source.UID)
	}
	if !vmFirewallAttachedTo(*firewall, vmUUID) {
		return fmt.Errorf("public-node-local: the own firewall %s of Service %s is not attached to VM %s", own, source.UID, vmUUID)
	}
	return nil
}

// stageVMFirewallUnadopt records the entry of the adoptee as pending, together
// with the firewall being renamed, in one write, so a receipt never exists
// without its target.
func (c *nodeLoadBalancerController) stageVMFirewallUnadopt(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	pendingRaw, policy string,
) (*corev1.ConfigMap, error) {
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	appliedRaw := anchor.Annotations[annotationVMFirewallApplied]
	uuid := (vmFirewallAnchorView{cm: anchor}).uuid()
	updated, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != appliedRaw || view.uuid() != uuid {
			return false, errors.New("public-node-local: the VM firewall anchor changed before the rename was staged")
		}
		cm.Annotations[annotationVMFirewallPending] = pendingRaw
		cm.Annotations[annotationVMFirewallPendingHash] = policy
		cm.Annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpUnadopt)
		cm.Annotations[annotationVMFirewallPendingAt] = now
		cm.Annotations[annotationVMFirewallAdoptUUID] = uuid
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("public-node-local: the VM firewall rename was not staged")
	}
	return updated, nil
}

// authorizeVMFirewallUnadopt is the final authority before the rename PUT: the
// receipt is the one this process issued, the plan is the recorded settled one,
// the firewall is unchanged and attached to this VM alone, every other member's
// own firewall is on the VM and covers its rules, the adoptee is steady, and the
// name it takes is free.
func (c *nodeLoadBalancerController) authorizeVMFirewallUnadopt(
	ctx context.Context,
	vmUUID string,
	issued *corev1.ConfigMap,
	plan vmFirewallMigrationPlan,
	adoptee vmFirewallMigrationSource,
	desired desiredNodeLoadBalancerFirewall,
	before inspace.Firewall,
) error {
	sameReceipt := func() (*corev1.ConfigMap, error) {
		current, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return nil, err
		}
		if current == nil || current.UID != issued.UID || !vmFirewallSameReceipt(current.Annotations, issued.Annotations) {
			return nil, errors.New("public-node-local: the VM firewall receipt changed during final authority")
		}
		return current, nil
	}
	anchor, err := sameReceipt()
	if err != nil {
		return err
	}
	current, ok, err := (vmFirewallAnchorView{cm: anchor}).migration()
	if err != nil {
		return err
	}
	if !ok || current.Direction != vmFirewallMigrationDirectionReverse || current.Phase != vmFirewallMigrationPhaseDetaching ||
		current.Adoptee != plan.Adoptee || fmt.Sprint(current.Sources) != fmt.Sprint(plan.Sources) {
		return errors.New("public-node-local: the migration record changed before the rename")
	}
	if remaining := c.vmFirewallReverseSettleRemaining(current); remaining > 0 {
		return fmt.Errorf("public-node-local: the own firewalls of VM %s have not settled for %s yet", vmUUID, remaining)
	}
	fresh, err := c.exactNodeLoadBalancerFirewallFresh(ctx, before.UUID)
	if err != nil {
		return err
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *fresh) {
		return fmt.Errorf("public-node-local: firewall %s changed after the rename was issued", fresh.UUID)
	}
	rows, err := nodeLoadBalancerFirewallAssignmentVMs(*fresh)
	if err != nil {
		return err
	}
	if len(rows) != 1 || !strings.EqualFold(rows[0], vmUUID) {
		return fmt.Errorf("public-node-local: firewall %s is not attached to VM %s alone, so it can not be renamed", fresh.UUID, vmUUID)
	}
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	applied, err := (vmFirewallAnchorView{cm: anchor}).applied()
	if err != nil {
		return err
	}
	for _, member := range applied.Members {
		svc := read.services[member.UID]
		if svc == nil {
			return fmt.Errorf("public-node-local: Service %s is gone; its entry leaves through the upkeep first", member.UID)
		}
		source, listed := plan.sourceOfService(member.UID)
		if !listed {
			return fmt.Errorf("public-node-local: the per-VM firewall holds an entry of Service %s that the reverse migration does not move", member.UID)
		}
		if member.UID == adoptee.UID {
			if err := c.reverseMemberChanged(svc, source, false); err != nil {
				return err
			}
			if own := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]; own != "" && !strings.EqualFold(own, fresh.UUID) {
				return fmt.Errorf("public-node-local: Service %s/%s names firewall %s, not the one being renamed", svc.Namespace, svc.Name, own)
			}
			continue
		}
		if err := c.reverseMemberOpenOnVM(vmUUID, svc, source, read.items); err != nil {
			return err
		}
	}
	existing, err := vmFirewallByNameFromItems(read.items, desired.Request.DisplayName)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("public-node-local: firewall %s already carries the name %q", existing.UUID, desired.Request.DisplayName)
	}
	if count := len(vmFirewallsAttachedTo(read.items, vmUUID)); count > c.provider.maxFirewallsPerVM() {
		return fmt.Errorf("public-node-local: VM %s carries %d firewalls, above the limit", vmUUID, count)
	}
	_, err = sameReceipt()
	return err
}

// unadoptVMFirewallReverse is the reverse adopt (strategy B): one PUT renames the
// per-VM firewall into the own firewall of the adoptee, with the adoptee's
// rules. The other members' own firewalls are attached and settled before; so
// the VM never carries more firewalls than before, nothing is attached, and the
// rules of the other members are closed only where another firewall holds them.
func (c *nodeLoadBalancerController) unadoptVMFirewallReverse(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	plan vmFirewallMigrationPlan,
	applied vmFirewallLedger,
	read vmFirewallMigrationRead,
) error {
	view := vmFirewallAnchorView{cm: anchor}
	adoptee, listed := plan.sourceOfService(plan.Adoptee)
	if !listed {
		return corruptVMFirewallLedger("anchor %s reverse-adopts %s, which its migration record does not list", anchor.Name, plan.Adoptee)
	}
	svc := read.services[adoptee.UID]
	entry, present := applied.find(vmFirewallMemberKey{UID: adoptee.UID, Policy: adoptee.Policy})
	if svc == nil || !present {
		return vmFirewallDrift(vmUUID, "the adoptee %s is not on the per-VM firewall", adoptee.UID)
	}
	if err := c.reverseMemberChanged(svc, adoptee, false); err != nil {
		return err
	}
	desired, err := c.desiredServiceFirewall(svc)
	if err != nil {
		return err
	}
	current, err := exactNodeLoadBalancerFirewallFromItems(read.items, view.uuid())
	if err != nil {
		return vmFirewallDrift(vmUUID, "the per-VM firewall %s is not readable: %v", view.uuid(), err)
	}
	request, err := vmFirewallUnadoptRequest(*current, desired)
	if err != nil {
		return err
	}
	pending, err := encodeVMFirewallLedger(vmFirewallLedger{V: vmFirewallLedgerVersion, Members: []vmFirewallMember{entry}})
	if err != nil {
		return err
	}
	staged, err := c.stageVMFirewallUnadopt(ctx, anchor, pending, adoptee.Policy)
	if err != nil {
		return err
	}
	issued, err := c.issueVMFirewallMutation(ctx, staged)
	if err != nil {
		return err
	}
	if err := c.authorizeVMFirewallUnadopt(ctx, vmUUID, issued, plan, adoptee, desired, *current); err != nil {
		rejection := fmt.Errorf("public-node-local: reject the rename of firewall %s for %s at final pre-dispatch authority: %w", current.UUID, vmUUID, err)
		if resetErr := c.resetVMFirewallReceipt(ctx, issued); resetErr != nil {
			return errors.Join(rejection, resetErr)
		}
		return rejection
	}
	callCtx, cancel := context.WithTimeout(ctx, vmFirewallMutationTimeout(len(request.Rules)))
	defer cancel()
	klog.Infof("node load balancer: rename the per-VM firewall %s of %s into the firewall of Service %s with %d rules", current.UUID, vmUUID, adoptee.UID, len(request.Rules))
	_, dispatchErr := c.provider.api.UpdateFirewall(callCtx, c.provider.config.Location, current.UUID, request)
	if dispatchErr != nil {
		dispatchErr = fmt.Errorf("public-node-local: rename firewall %s for %s: %w", current.UUID, vmUUID, dispatchErr)
		if nodeLoadBalancerMutationKnownPreDispatch(dispatchErr) {
			return errors.Join(dispatchErr, c.resetVMFirewallReceipt(ctx, issued))
		}
	}
	items, listErr := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if listErr != nil {
		return errors.Join(dispatchErr, fmt.Errorf("public-node-local: read back the renamed firewall of %s: %w", vmUUID, listErr))
	}
	fresh, getErr := c.getVMFirewallAnchor(ctx, vmUUID)
	if getErr != nil || fresh == nil {
		return errors.Join(dispatchErr, getErr, errors.New("public-node-local: the VM firewall anchor disappeared during a rename"))
	}
	if _, resolveErr := c.resolveVMFirewallReceipt(ctx, fresh, items, c.vmFirewallMemberLookup(vmUUID, nil)); resolveErr != nil {
		return errors.Join(dispatchErr, resolveErr)
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// resolveVMFirewallUnadoptReceipt settles an issued or staged rename of the
// per-VM firewall into a Service's own firewall, from a fresh listing. The
// firewall is found by its UUID. It reports true once the receipt is gone:
// committed (the Service records the firewall and the anchor is deleted) or
// reset.
func (c *nodeLoadBalancerController) resolveVMFirewallUnadoptReceipt(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	items []inspace.Firewall,
	members func(context.Context) []*corev1.Service,
) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	vmUUID := view.vm()
	fvUUID := view.get(annotationVMFirewallAdoptUUID)
	if !validNodeLoadBalancerCloudUUID(fvUUID) || !strings.EqualFold(fvUUID, view.uuid()) {
		return false, corruptVMFirewallLedger("anchor %s has a rename receipt without the per-VM firewall as its target (%q)", anchor.Name, fvUUID)
	}
	if view.get(annotationVMFirewallIssuedAt) == "" {
		// Staged but never issued: no request was ever authorized.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, view.get(annotationVMFirewallIssuedAt))
	if err != nil {
		return false, corruptVMFirewallLedger("anchor %s issued-at %q: %v", anchor.Name, view.get(annotationVMFirewallIssuedAt), err)
	}
	pending, err := view.pending()
	if err != nil {
		return false, err
	}
	policy := view.get(annotationVMFirewallPendingHash)
	if len(pending.Members) != 1 || pending.Members[0].Policy != policy {
		return false, corruptVMFirewallLedger("anchor %s rename receipt does not name exactly one entry", anchor.Name)
	}
	uid := pending.Members[0].UID
	plan, ok, err := view.migration()
	if err != nil {
		return false, err
	}
	if !ok || plan.Direction != vmFirewallMigrationDirectionReverse || plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != uid {
		return false, corruptVMFirewallLedger("anchor %s renames into Service %s, which its migration record does not name as the adoptee", anchor.Name, uid)
	}
	cluster := c.provider.config.ClusterID
	perVMName, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return false, err
	}
	ownName := nodeLoadBalancerFirewallName(cluster, uid, policy)
	drift := func(format string, args ...any) (bool, error) {
		err := vmFirewallDrift(vmUUID, format, args...)
		c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), vmFirewallDriftReason, err)
		return false, err
	}
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, fvUUID)
	if err != nil {
		return drift("the firewall %s being renamed is not readable: %v", fvUUID, err)
	}
	byOwnName, err := vmFirewallByNameFromItems(items, ownName)
	if err != nil {
		return drift("%v", err)
	}
	if byOwnName != nil && byOwnName.UUID != firewall.UUID {
		return drift("firewall %s carries the name %q, not the one being renamed (%s)", byOwnName.UUID, ownName, fvUUID)
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	retireAt := issuedAt.Add(nodeLoadBalancerFirewallRelationRetireDelay)
	untilRetire := retireAt.Sub(now)
	if untilRetire > nodeLoadBalancerRetry {
		untilRetire = nodeLoadBalancerRetry
	}
	serviceHash, serviceHashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
	vmHash, vmHashErr := inspace.NodeLoadBalancerVMFirewallSpecHash(firewall.Rules)
	renamed := vmFirewallRenameApplied(*firewall, ownName)
	stillPerVM := vmFirewallRenameApplied(*firewall, perVMName)

	switch {
	case renamed && serviceHashErr == nil && serviceHash == policy:
		if !nodeLoadBalancerFirewallOwnedByService(*firewall, cluster, uid, c.provider.config.BillingAccountID) {
			return drift("renamed firewall %s is not owned by Service %s", fvUUID, uid)
		}
		rows, err := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
		if err != nil || len(rows) != 1 || !strings.EqualFold(rows[0], vmUUID) {
			return drift("renamed firewall %s is not attached to VM %s alone", fvUUID, vmUUID)
		}
		return true, c.finishVMFirewallUnadopt(ctx, anchor, *firewall, uid, policy)
	case stillPerVM && vmHashErr == nil && vmHash == view.appliedHash():
		// Still the per-VM firewall as it was: the PUT did not commit, or has not shown yet.
		if now.Before(retireAt) {
			return false, vmFirewallWait(untilRetire, "public-node-local: the rename of firewall %s for %s is ambiguous; waiting for readback", fvUUID, vmUUID)
		}
		// The request can no longer be in flight and a fresh read still shows the
		// firewall as it was: it did not commit. The next pass derives it again.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	case stillPerVM && serviceHashErr == nil && serviceHash == policy:
		return drift("firewall %s took the rules of Service %s but not its name; the rename did not take effect", fvUUID, uid)
	default:
		return drift("firewall %s is neither the per-VM firewall as it was nor the own firewall of Service %s", fvUUID, uid)
	}
}

// finishVMFirewallUnadopt ends a committed rename: the Service records the
// firewall as its own, then the anchor is deleted last. Both steps are
// idempotent; the receipt stays on the anchor until the anchor is gone, so a
// restart in between runs them again.
func (c *nodeLoadBalancerController) finishVMFirewallUnadopt(ctx context.Context, anchor *corev1.ConfigMap, firewall inspace.Firewall, uid, policy string) error {
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	if svc := read.services[uid]; svc != nil {
		if _, _, err := c.updateExactParentService(ctx, svc, func(copy *corev1.Service) (bool, error) {
			if own := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]; own != "" && !strings.EqualFold(own, firewall.UUID) {
				return false, errors.New("public-node-local: the Service names another firewall than the one renamed into its own")
			}
			changed := false
			for key, value := range map[string]string{
				annotationNodeLoadBalancerFirewallUUID: firewall.UUID,
				annotationNodeLoadBalancerFirewallHash: policy,
			} {
				if copy.Annotations[key] != value {
					copy.Annotations[key] = value
					changed = true
				}
			}
			for _, key := range []string{annotationNodeLoadBalancerFirewallAbsent, annotationNodeLoadBalancerFirewallChecked} {
				if copy.Annotations[key] != "" {
					delete(copy.Annotations, key)
					changed = true
				}
			}
			return changed, nil
		}); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(svc.Namespace + "/" + svc.Name)
	}
	return c.deleteVMFirewallAnchorAfterUnadopt(ctx, anchor)
}

// deleteVMFirewallAnchorAfterUnadopt removes the finalizer of an anchor whose
// firewall now belongs to a Service, then the anchor itself.
func (c *nodeLoadBalancerController) deleteVMFirewallAnchorAfterUnadopt(ctx context.Context, anchor *corev1.ConfigMap) error {
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return err
	}
	cms := c.provider.kubeClient.CoreV1().ConfigMaps(namespace)
	fresh, err := cms.Get(ctx, anchor.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		c.noteVMFirewallAnchorGone()
		return nil
	}
	if err != nil {
		return fmt.Errorf("public-node-local: read the VM firewall anchor to delete it: %w", err)
	}
	if fresh.UID != anchor.UID || fresh.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpUnadopt) {
		return errors.New("public-node-local: the VM firewall rename receipt changed before the anchor was deleted")
	}
	if containsString(fresh.Finalizers, vmFirewallAnchorFinalizer) {
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
	}
	uid := fresh.UID
	if err := cms.Delete(ctx, anchor.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("public-node-local: delete the VM firewall anchor: %w", err)
	}
	c.noteVMFirewallAnchorGone()
	return nil
}

// flipReversedPublicNodeLocal ends the reverse migration of a Service. A
// Service that still carries the per-VM mark while this controller runs the
// per-Service mode is held; it goes back to its own firewall once no anchor
// lists it, its own firewall is recorded, exact, and attached to every VM it is
// published on. The flip is one compare-and-swap that removes the mark. It
// reports true when it flipped.
func (c *nodeLoadBalancerController) flipReversedPublicNodeLocal(ctx context.Context, svc *corev1.Service) (bool, error) {
	if !publicNodeLocalServicePerVM(svc) || c.publicNodeLocalPerVMModeEnabled() {
		return false, nil
	}
	// The VM passes do the reverse work; make sure they run.
	c.enqueueVMFirewalls(true)
	if _, err := c.vmFirewallNamespace(); err != nil {
		return false, nil
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, err
	}
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		for _, read := range []func() (vmFirewallLedger, error){view.applied, view.pending} {
			ledger, ledgerErr := read()
			if ledgerErr != nil {
				return false, nil // a corrupt anchor holds
			}
			for _, member := range ledger.Members {
				if member.UID == string(svc.UID) {
					return false, nil
				}
			}
		}
		if plan, ok, planErr := view.migration(); planErr != nil {
			return false, nil
		} else if ok {
			if _, listed := plan.sourceOfService(string(svc.UID)); listed {
				return false, nil
			}
		}
	}
	// A Service that is being deleted goes back too: its own cleanup then runs on
	// the per-Service path.
	probe := svc.DeepCopy()
	probe.DeletionTimestamp = nil
	own, hash := svc.Annotations[annotationNodeLoadBalancerFirewallUUID], svc.Annotations[annotationNodeLoadBalancerFirewallHash]
	policy := svc.Annotations[annotationPublicNodeLocalActivePolicy]
	if own == "" || hash == "" || hash != policy || vmFirewallReverseServiceWaiting(probe, false) != "" || vmFirewallReverseCreateInFlight(svc) {
		return false, nil
	}
	desired, err := c.desiredServiceFirewall(svc)
	if err != nil || desired.Hash != policy {
		return false, nil
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, own)
	if err != nil || !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
		!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, string(svc.UID), c.provider.config.BillingAccountID) {
		return false, nil
	}
	published, err := c.publishedVMsOfService(ctx, svc)
	if err != nil {
		return false, err
	}
	for _, vmUUID := range published {
		if !vmFirewallAttachedTo(*firewall, vmUUID) {
			return false, nil
		}
	}
	_, changed, err := c.updateExactParentService(ctx, svc, func(copy *corev1.Service) (bool, error) {
		if !publicNodeLocalServicePerVM(copy) {
			return false, nil
		}
		if copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != own || copy.Annotations[annotationNodeLoadBalancerFirewallHash] != hash ||
			copy.Annotations[annotationPublicNodeLocalActivePolicy] != policy {
			return false, errors.New("public-node-local: the Service changed before it went back to its own firewall")
		}
		delete(copy.Annotations, annotationPublicNodeLocalFirewallMode)
		return true, nil
	})
	if err != nil {
		return false, err
	}
	if changed {
		klog.Infof("node load balancer: Service %s/%s is back on its own firewall %s", svc.Namespace, svc.Name, own)
	}
	return changed, nil
}
