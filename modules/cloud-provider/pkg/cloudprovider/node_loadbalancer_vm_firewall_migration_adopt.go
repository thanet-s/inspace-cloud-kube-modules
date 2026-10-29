package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// vmFirewallAdoptRequest is the PUT body that turns the per-Service firewall of
// one Service into the per-VM firewall of a VM in one request: the name goes
// out as display_name (the only field InSpace honours), and the rules become
// the union. Rules whose protocol/port survive keep their provider UUID, so the
// port that serves is never closed and reopened.
func vmFirewallAdoptRequest(cluster, vmUUID string, current inspace.Firewall, merged []inspace.FirewallRule) (inspace.UpdateFirewallRequest, error) {
	if !vmFirewallRenameSupportedForTest {
		return inspace.UpdateFirewallRequest{}, errors.New("public-node-local: renaming a firewall is not supported")
	}
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return inspace.UpdateFirewallRequest{}, err
	}
	if !nodeLoadBalancerFirewallUUIDPattern.MatchString(current.UUID) {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: firewall UUID %q to adopt is invalid", current.UUID)
	}
	if current.Name != "" && current.DisplayName != "" && current.Name != current.DisplayName {
		return inspace.UpdateFirewallRequest{}, errors.New("public-node-local: the firewall to adopt has conflicting name fields")
	}
	if current.EffectiveName() == name {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: firewall %s already carries the per-VM name", current.UUID)
	}
	seen := map[string]struct{}{}
	for _, rule := range current.Rules {
		if rule.UUID == "" {
			continue
		}
		if !nodeLoadBalancerFirewallUUIDPattern.MatchString(rule.UUID) {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: rule UUID %q of the firewall to adopt is invalid", rule.UUID)
		}
		if _, duplicate := seen[strings.ToLower(rule.UUID)]; duplicate {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: the firewall to adopt reuses rule UUID %q", rule.UUID)
		}
		seen[strings.ToLower(rule.UUID)] = struct{}{}
	}
	if _, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged); err != nil {
		return inspace.UpdateFirewallRequest{}, err
	}
	return inspace.UpdateFirewallRequest{
		Name:        name,
		Description: inspace.NodeLoadBalancerVMFirewallDescription,
		Rules:       retainFirewallRuleUUIDs(current.Rules, merged),
	}, nil
}

// stageVMFirewallAdopt records the next ledger as pending together with the
// firewall being adopted, in the one write, so a receipt never exists without
// its target.
func (c *nodeLoadBalancerController) stageVMFirewallAdopt(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	adoptUUID, pendingRaw, pendingHash string,
) (*corev1.ConfigMap, error) {
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	appliedRaw := anchor.Annotations[annotationVMFirewallApplied]
	updated, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != appliedRaw || view.uuid() != "" {
			return false, errors.New("public-node-local: the VM firewall anchor changed before the adopt was staged")
		}
		cm.Annotations[annotationVMFirewallPending] = pendingRaw
		cm.Annotations[annotationVMFirewallPendingHash] = pendingHash
		cm.Annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpAdopt)
		cm.Annotations[annotationVMFirewallPendingAt] = now
		cm.Annotations[annotationVMFirewallAdoptUUID] = adoptUUID
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("public-node-local: the VM firewall adopt was not staged")
	}
	return updated, nil
}

// authorizeVMFirewallAdopt is the final authority before the rename PUT: the
// receipt is the one this process issued, the adoptee is unchanged since it
// was read and is attached to this VM alone under its own name, and every
// source of the plan is still what the plan recorded.
func (c *nodeLoadBalancerController) authorizeVMFirewallAdopt(
	ctx context.Context,
	vmUUID string,
	issued *corev1.ConfigMap,
	plan vmFirewallMigrationPlan,
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
	view := vmFirewallAnchorView{cm: anchor}
	current, ok, err := view.migration()
	if err != nil {
		return err
	}
	if !ok || current.Phase != vmFirewallMigrationPhasePlanned || current.Adoptee != plan.Adoptee || fmt.Sprint(current.Sources) != fmt.Sprint(plan.Sources) {
		return errors.New("public-node-local: the migration record changed before the adopt")
	}
	fresh, err := c.exactNodeLoadBalancerFirewallFresh(ctx, before.UUID)
	if err != nil {
		return err
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *fresh) {
		return fmt.Errorf("public-node-local: firewall %s changed after the adopt was issued", fresh.UUID)
	}
	rows, err := nodeLoadBalancerFirewallAssignmentVMs(*fresh)
	if err != nil {
		return err
	}
	if len(rows) != 1 || !strings.EqualFold(rows[0], vmUUID) {
		return fmt.Errorf("public-node-local: firewall %s is no longer attached to VM %s alone, so it can not be adopted", fresh.UUID, vmUUID)
	}
	read, err := c.readVMFirewallMigration(ctx)
	if err != nil {
		return err
	}
	if err := c.validateVMFirewallMigrationSources(vmUUID, plan, view, read, true); err != nil {
		return err
	}
	if count := len(vmFirewallsAttachedTo(read.items, vmUUID)); count > c.provider.maxFirewallsPerVM() {
		return fmt.Errorf("public-node-local: VM %s carries %d firewalls, above the limit", vmUUID, count)
	}
	_, err = sameReceipt()
	return err
}

func vmFirewallsAttachedTo(items []inspace.Firewall, vmUUID string) []inspace.Firewall {
	var out []inspace.Firewall
	for _, firewall := range items {
		if vmFirewallAttachedTo(firewall, vmUUID) {
			out = append(out, firewall)
		}
	}
	return out
}

// adoptVMFirewallMigration is M2 and M3 of the strategy for a full VM: one PUT
// renames the adoptee into the per-VM firewall and gives it the union of the
// rules, so the VM never carries more firewalls than it did and nothing is
// attached. When the rename has read back, the plan is open.
func (c *nodeLoadBalancerController) adoptVMFirewallMigration(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	plan vmFirewallMigrationPlan,
	read vmFirewallMigrationRead,
) error {
	view := vmFirewallAnchorView{cm: anchor}
	applied, err := view.applied()
	if err != nil {
		return err
	}
	if view.uuid() != "" {
		// The rename committed. Check what the anchor recorded against the cloud, and
		// open the plan.
		if !strings.EqualFold(view.uuid(), plan.Adoptee) {
			return vmFirewallDrift(vmUUID, "the anchor records firewall %s, the plan adopts %s", view.uuid(), plan.Adoptee)
		}
		for _, source := range plan.Sources {
			if _, present := applied.find(vmFirewallMemberKey{UID: source.UID, Policy: source.Policy}); !present {
				return vmFirewallDrift(vmUUID, "the adopted firewall does not record Service %s", source.UID)
			}
		}
		observation, err := c.observeVMFirewall(vmUUID, view, applied, read.items)
		if err != nil {
			return err
		}
		if !observation.attached {
			return vmFirewallDrift(vmUUID, "the adopted firewall %s is not attached to the VM", view.uuid())
		}
		return c.markVMFirewallMigrationOpened(ctx, vmUUID, plan)
	}
	if len(applied.Members) != 0 {
		return vmFirewallDrift(vmUUID, "the anchor records a ledger but no firewall during an adopt")
	}
	adoptee, err := exactNodeLoadBalancerFirewallFromItems(read.items, plan.Adoptee)
	if err != nil {
		return sourceChanged("adoptee %s: %v", plan.Adoptee, err)
	}
	members := make([]vmFirewallMember, 0, len(plan.Sources))
	for _, source := range plan.Sources {
		firewall, err := exactNodeLoadBalancerFirewallFromItems(read.items, source.Firewall)
		if err != nil {
			return sourceChanged("firewall %s: %v", source.Firewall, err)
		}
		member, err := vmFirewallMemberFromFirewall(source.UID, source.Policy, *firewall)
		if err != nil {
			return sourceChanged("firewall %s: %v", source.Firewall, err)
		}
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].UID != members[j].UID {
			return members[i].UID < members[j].UID
		}
		return members[i].Policy < members[j].Policy
	})
	next := canonicalVMFirewallLedger(vmFirewallLedger{V: vmFirewallLedgerVersion, Members: members})
	merged, err := mergeVMFirewallLedger(next)
	if err != nil {
		return err
	}
	nextRaw, err := encodeVMFirewallLedger(next)
	if err != nil {
		return err
	}
	hash, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged)
	if err != nil {
		return err
	}
	request, err := vmFirewallAdoptRequest(c.provider.config.ClusterID, vmUUID, *adoptee, merged)
	if err != nil {
		return err
	}
	staged, err := c.stageVMFirewallAdopt(ctx, anchor, adoptee.UUID, nextRaw, hash)
	if err != nil {
		return err
	}
	issued, err := c.issueVMFirewallMutation(ctx, staged)
	if err != nil {
		return err
	}
	if err := c.authorizeVMFirewallAdopt(ctx, vmUUID, issued, plan, *adoptee); err != nil {
		rejection := fmt.Errorf("public-node-local: reject the adopt of firewall %s for %s at final pre-dispatch authority: %w", adoptee.UUID, vmUUID, err)
		if resetErr := c.resetVMFirewallReceipt(ctx, issued); resetErr != nil {
			return errors.Join(rejection, resetErr)
		}
		return rejection
	}
	callCtx, cancel := context.WithTimeout(ctx, vmFirewallMutationTimeout(len(merged)))
	defer cancel()
	klog.Infof("node load balancer: adopt firewall %s as the per-VM firewall of %s with %d rules", adoptee.UUID, vmUUID, len(merged))
	_, dispatchErr := c.provider.api.UpdateFirewall(callCtx, c.provider.config.Location, adoptee.UUID, request)
	if dispatchErr != nil {
		dispatchErr = fmt.Errorf("public-node-local: adopt firewall %s for %s: %w", adoptee.UUID, vmUUID, dispatchErr)
		if nodeLoadBalancerMutationKnownPreDispatch(dispatchErr) {
			return errors.Join(dispatchErr, c.resetVMFirewallReceipt(ctx, issued))
		}
	}
	items, listErr := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if listErr != nil {
		return errors.Join(dispatchErr, fmt.Errorf("public-node-local: read back the adopted firewall of %s: %w", vmUUID, listErr))
	}
	current, getErr := c.getVMFirewallAnchor(ctx, vmUUID)
	if getErr != nil || current == nil {
		return errors.Join(dispatchErr, getErr, errors.New("public-node-local: the VM firewall anchor disappeared during an adopt"))
	}
	if _, resolveErr := c.resolveVMFirewallReceipt(ctx, current, items, c.vmFirewallMemberLookup(vmUUID, nil)); resolveErr != nil {
		return errors.Join(dispatchErr, resolveErr)
	}
	c.queueVMFirewall(vmUUID)
	return nil
}

// resolveVMFirewallAdoptReceipt settles an issued or staged adopt from a fresh
// listing. The adoptee is found by its UUID, never by the per-VM name, because
// it carries another name until the rename reads back. It reports true once
// the receipt is gone: committed or reset.
func (c *nodeLoadBalancerController) resolveVMFirewallAdoptReceipt(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	items []inspace.Firewall,
	members func(context.Context) []*corev1.Service,
) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	vmUUID := view.vm()
	adoptUUID := view.get(annotationVMFirewallAdoptUUID)
	if !validNodeLoadBalancerCloudUUID(adoptUUID) {
		return false, corruptVMFirewallLedger("anchor %s has an adopt receipt without a valid adopt-uuid (%q)", anchor.Name, adoptUUID)
	}
	if view.get(annotationVMFirewallIssuedAt) == "" {
		// Staged but never issued: no request was ever authorized.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, view.get(annotationVMFirewallIssuedAt))
	if err != nil {
		return false, corruptVMFirewallLedger("anchor %s issued-at %q: %v", anchor.Name, view.get(annotationVMFirewallIssuedAt), err)
	}
	plan, ok, err := view.migration()
	if err != nil {
		return false, err
	}
	source, listed := plan.source(adoptUUID)
	if !ok || !listed || !strings.EqualFold(plan.Adoptee, adoptUUID) {
		return false, corruptVMFirewallLedger("anchor %s adopts %s, which its migration record does not name as the adoptee", anchor.Name, adoptUUID)
	}
	cluster := c.provider.config.ClusterID
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return false, err
	}
	drift := func(format string, args ...any) (bool, error) {
		err := vmFirewallDrift(vmUUID, format, args...)
		c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), vmFirewallDriftReason, err)
		return false, err
	}
	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, adoptUUID)
	if err != nil {
		return drift("the firewall %s being adopted is not readable: %v", adoptUUID, err)
	}
	byName, err := vmFirewallByNameFromItems(items, name)
	if err != nil {
		return drift("%v", err)
	}
	if byName != nil && byName.UUID != firewall.UUID {
		return drift("firewall %s carries the per-VM name, not the one being adopted (%s)", byName.UUID, adoptUUID)
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	retireAt := issuedAt.Add(nodeLoadBalancerFirewallRelationRetireDelay)
	untilRetire := retireAt.Sub(now)
	if untilRetire > nodeLoadBalancerRetry {
		untilRetire = nodeLoadBalancerRetry
	}
	pendingHash := view.get(annotationVMFirewallPendingHash)
	vmHash, vmHashErr := inspace.NodeLoadBalancerVMFirewallSpecHash(firewall.Rules)
	serviceHash, serviceHashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
	renamed := vmFirewallRenameApplied(*firewall, name)

	switch {
	case renamed && vmHashErr == nil && vmHash == pendingHash:
		if err := inspace.ValidateNodeLoadBalancerVMFirewall(*firewall, cluster, vmUUID, c.provider.config.BillingAccountID, pendingHash); err != nil {
			return drift("adopted firewall %s: %v", adoptUUID, err)
		}
		rows, err := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
		if err != nil || len(rows) != 1 || !strings.EqualFold(rows[0], vmUUID) {
			return drift("adopted firewall %s is not attached to VM %s alone", adoptUUID, vmUUID)
		}
		return true, c.commitVMFirewallMutation(ctx, anchor, *firewall)
	case !renamed && serviceHashErr == nil && serviceHash == source.Policy:
		// Still the adoptee as it was: the PUT did not commit, or has not shown yet.
		if now.Before(retireAt) {
			return false, vmFirewallWait(untilRetire, "public-node-local: the adopt of firewall %s for %s is ambiguous; waiting for readback", adoptUUID, vmUUID)
		}
		// The request can no longer be in flight and a fresh read still shows the
		// firewall as it was: it did not commit. The next pass derives it again.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	case !renamed && vmHashErr == nil && vmHash == pendingHash:
		return drift("firewall %s took the union rules but not the per-VM name; the rename did not take effect", adoptUUID)
	default:
		return drift("firewall %s is neither the adoptee as it was nor the adopted per-VM firewall", adoptUUID)
	}
}
