package cloudprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// vmFirewallMigrationPlanAudit is the part of an anchor's migration record the
// audit reads: the phase and the per-Service firewalls the migration is
// retiring. The migration itself writes and owns the record.
type vmFirewallMigrationPlanAudit struct {
	Phase   string `json:"phase"`
	Sources []struct {
		Firewall string `json:"firewall"`
	} `json:"sources"`
}

const vmFirewallMigrationPhaseDone = "done"

// perVMFirewallAttachedTo says whether a valid per-VM firewall of vmUUID is
// attached to it.
func perVMFirewallAttachedTo(items []inspace.Firewall, cluster string, billingAccountID int64, vmUUID string) bool {
	for index := range items {
		firewall := items[index]
		if owner, ok := inspace.ParseNodeLoadBalancerVMFirewallName(cluster, firewall.EffectiveName()); !ok || owner != vmUUID {
			continue
		}
		if inspace.ValidateNodeLoadBalancerVMFirewallIdentity(firewall, cluster, vmUUID, billingAccountID) == nil && vmFirewallAttachedTo(firewall, vmUUID) {
			return true
		}
	}
	return false
}

// auditPerVMFirewall accepts the one per-VM firewall of a VM when its rules are
// the ones its anchor recorded (or, while a PUT is in flight, the ones that PUT
// asked for). Without an anchor the VM holds, and the VM pass rebuilds the
// ledger or collects the firewall. count is the number of per-VM firewalls the
// audit has seen on this VM so far, this one included.
func (c *nodeLoadBalancerController) auditPerVMFirewall(ctx context.Context, vmUUID string, firewall inspace.Firewall, count int) error {
	if count > 1 {
		return fmt.Errorf("VM %s carries more than one per-VM firewall (also %s)", vmUUID, firewall.UUID)
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	if anchor == nil {
		if c.queue != nil {
			c.queue.Add(vmFirewallQueueKey(vmUUID))
		}
		return fmt.Errorf("VM %s carries per-VM firewall %s that no anchor records; holding until its ledger is rebuilt", vmUUID, firewall.UUID)
	}
	view := vmFirewallAnchorView{cm: anchor}
	if view.uuid() != "" && !strings.EqualFold(view.uuid(), firewall.UUID) {
		return fmt.Errorf("VM %s carries per-VM firewall %s but its anchor records %s", vmUUID, firewall.UUID, view.uuid())
	}
	hashes := []string{view.appliedHash()}
	if view.hasReceipt() {
		hashes = append(hashes, view.get(annotationVMFirewallPendingHash))
	}
	var lastErr error
	for _, hash := range hashes {
		if hash == "" {
			continue
		}
		if lastErr = inspace.ValidateNodeLoadBalancerVMFirewall(firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID, hash); lastErr == nil {
			return nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("the anchor records no rules for it")
	}
	return fmt.Errorf("VM %s per-VM firewall %s does not match its anchor: %w", vmUUID, firewall.UUID, lastErr)
}

// auditPerServiceFirewallOnPerVMMode decides whether a per-Service firewall may
// sit next to the per-VM firewall of its VM. On a VM that has no per-VM
// firewall yet it may, as it always could. Next to one, it may only while the
// anchor's migration is retiring it.
func (c *nodeLoadBalancerController) auditPerServiceFirewallOnPerVMMode(
	ctx context.Context,
	vmUUID string,
	firewall inspace.Firewall,
	vmFirewallAttached bool,
) error {
	if !vmFirewallAttached ||
		inspace.ValidateNodeLoadBalancerServiceFirewall(firewall, c.provider.config.ClusterID, c.provider.config.BillingAccountID) != nil {
		return nil
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return err
	}
	if anchor != nil {
		if raw := anchor.Annotations[annotationVMFirewallMigration]; raw != "" {
			var plan vmFirewallMigrationPlanAudit
			if json.Unmarshal([]byte(raw), &plan) == nil && plan.Phase != vmFirewallMigrationPhaseDone {
				for _, source := range plan.Sources {
					if strings.EqualFold(source.Firewall, firewall.UUID) {
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("VM %s has unauthorized additional firewall %s next to its per-VM firewall", vmUUID, firewall.UUID)
}
