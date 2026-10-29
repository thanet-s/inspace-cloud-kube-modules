package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const vmFirewallPendingOpDelete = "delete"

// vmFirewallRelationOwner makes the anchor ConfigMap of one VM the owner of the
// attach and detach receipts of its per-VM firewall, so the generic relation
// fence (retire delay, parking, VM-absence proof, capacity guard) applies to
// it unchanged. members returns the Services whose ledger entries live on the
// VM; they receive the refusal Event, because the anchor has no Service of its
// own.
func (c *nodeLoadBalancerController) vmFirewallRelationOwner(
	vmUUID string,
	members func(context.Context) []*corev1.Service,
) nodeLoadBalancerFirewallRelationOwner {
	return nodeLoadBalancerFirewallRelationOwner{
		description: "VM firewall anchor " + vmUUID,
		parkRetired: true,
		members:     members,
		authorize: func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			return c.authorizeVMFirewallRelationPreDispatch(ctx, vmUUID, fence, before)
		},
		read: func(ctx context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error) {
			anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
			if err != nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, err
			}
			if anchor == nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, fmt.Errorf("public-node-local: VM firewall anchor of %s does not exist", vmUUID)
			}
			snapshot := copyNodeLoadBalancerAnnotations(anchor.Annotations)
			uid := anchor.UID
			return nodeLoadBalancerFirewallRelationOwnerSnapshot{
				annotations: copyNodeLoadBalancerAnnotations(snapshot),
				uid:         uid,
				commit: func(ctx context.Context, values map[string]string) error {
					return c.commitVMFirewallAnchorDiff(ctx, anchor, snapshot, values)
				},
			}, nil
		},
	}
}

// commitVMFirewallAnchorDiff writes only the annotations that differ between
// the snapshot the relation fence read and the values it wants. If a conflict
// re-runs the write on a fresh anchor, every changed key must still hold its
// snapshot value there, so a concurrent change is never overwritten.
func (c *nodeLoadBalancerController) commitVMFirewallAnchorDiff(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	snapshot, values map[string]string,
) error {
	_, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.UID != anchor.UID {
			return false, errors.New("public-node-local: VM firewall anchor identity changed before the relation fence update")
		}
		changed := false
		unchangedUnderneath := func(key string) bool {
			have, inSnapshot := snapshot[key]
			current, inCurrent := cm.Annotations[key]
			return inSnapshot == inCurrent && have == current
		}
		for key, want := range values {
			if have, inSnapshot := snapshot[key]; inSnapshot && have == want {
				continue
			}
			if !unchangedUnderneath(key) {
				return false, fmt.Errorf("public-node-local: VM firewall anchor annotation %s changed under the relation fence", key)
			}
			cm.Annotations[key] = want
			changed = true
		}
		for key := range snapshot {
			if _, kept := values[key]; kept {
				continue
			}
			if !unchangedUnderneath(key) {
				return false, fmt.Errorf("public-node-local: VM firewall anchor annotation %s changed under the relation fence", key)
			}
			delete(cm.Annotations, key)
			changed = true
		}
		return changed, nil
	})
	return err
}

// vmFirewallPutReceiptOpen reports an unresolved create, PUT or adopt, issued or
// only staged. A staged delete is not one: it is the intent that authorizes the
// detach.
func vmFirewallPutReceiptOpen(view vmFirewallAnchorView) bool {
	if view.get(annotationVMFirewallIssuedAt) != "" {
		return true
	}
	op := view.pendingOp()
	return op != "" && op != vmFirewallPendingOpDelete
}

// authorizeVMFirewallRelationPreDispatch is the final authority before an
// attach or detach of a per-VM firewall crosses the provider boundary.
func (c *nodeLoadBalancerController) authorizeVMFirewallRelationPreDispatch(
	ctx context.Context,
	vmUUID string,
	fence nodeLoadBalancerFirewallRelationFence,
	before inspace.Firewall,
) error {
	if !strings.EqualFold(fence.vmUUID, vmUUID) {
		return fmt.Errorf("public-node-local: relation names VM %s, but the anchor belongs to %s", fence.vmUUID, vmUUID)
	}
	validate := func() (*inspace.Firewall, vmFirewallAnchorView, error) {
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return nil, vmFirewallAnchorView{}, err
		}
		if anchor == nil {
			return nil, vmFirewallAnchorView{}, fmt.Errorf("public-node-local: VM firewall anchor of %s does not exist", vmUUID)
		}
		view := vmFirewallAnchorView{cm: anchor}
		if !strings.EqualFold(view.uuid(), fence.firewallUUID) {
			return nil, view, fmt.Errorf("public-node-local: anchor firewall %q is not the relation firewall %s", view.uuid(), fence.firewallUUID)
		}
		if vmFirewallPutReceiptOpen(view) {
			return nil, view, errors.New("public-node-local: the per-VM firewall has an unresolved create or PUT receipt")
		}
		firewall, err := c.exactNodeLoadBalancerFirewallFresh(ctx, fence.firewallUUID)
		if err != nil {
			return nil, view, err
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *firewall) {
			return nil, view, fmt.Errorf("public-node-local: VM firewall %s changed after relation issue", fence.firewallUUID)
		}
		if err := inspace.ValidateNodeLoadBalancerVMFirewallIdentity(
			*firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID,
		); err != nil {
			return nil, view, fmt.Errorf("public-node-local: VM firewall %s lost exact ownership: %w", fence.firewallUUID, err)
		}
		return firewall, view, nil
	}
	firewall, view, err := validate()
	if err != nil {
		return err
	}
	switch fence.operation {
	case nodeLoadBalancerFirewallRelationUnassign:
		if view.pendingOp() != vmFirewallPendingOpDelete {
			// Without a staged delete the only reason to detach is a VM that no
			// longer exists. A live VM keeps its firewall.
			owned, _, ownedErr := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, fence.vmUUID)
			if ownedErr != nil {
				return ownedErr
			}
			if owned {
				return errors.New("public-node-local: refusing to detach the firewall of a live VM without a verified delete intent")
			}
		}
		return c.authorizeFirewallRelationUnassignVM(ctx, fence)
	case nodeLoadBalancerFirewallRelationAssign:
		if view.pendingOp() == vmFirewallPendingOpDelete {
			return errors.New("public-node-local: the per-VM firewall is being deleted")
		}
		applied, err := view.applied()
		if err != nil {
			return err
		}
		if len(applied.Members) == 0 || view.appliedHash() == "" {
			return errors.New("public-node-local: the per-VM firewall has no applied ledger to attach")
		}
		if err := inspace.ValidateNodeLoadBalancerVMFirewall(
			*firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID, view.appliedHash(),
		); err != nil {
			return fmt.Errorf("public-node-local: VM firewall %s does not match its applied ledger: %w", fence.firewallUUID, err)
		}
		node, err := c.exactNodeForFirewallRelationVM(ctx, fence.vmUUID)
		if err != nil {
			return err
		}
		if err := requireAuthorizedNodeLoadBalancerFirewallVM([]*corev1.Node{node}, fence.vmUUID); err != nil {
			return err
		}
		// The firewall and the anchor are the final observations before the call.
		_, _, err = validate()
		return err
	default:
		return fmt.Errorf("unsupported firewall relation operation %q", fence.operation)
	}
}
