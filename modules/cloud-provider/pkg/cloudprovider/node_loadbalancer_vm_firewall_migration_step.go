package cloudprovider

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

// stepVMFirewallMigration advances the migration recorded on an anchor by at
// most one durable step. It reports true once the VM is done.
func (c *nodeLoadBalancerController) stepVMFirewallMigration(ctx context.Context, vmUUID string, anchor *corev1.ConfigMap) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	plan, ok, err := view.migration()
	if err != nil || !ok {
		return false, err
	}
	node, err := c.publicNodeLocalNodeOfVM(ctx, vmUUID)
	if err != nil {
		return false, err
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, err
	}
	if allowed, reason := c.vmFirewallMigrationAllowed(ctx, vmUUID, node, anchors, c.nodeLoadBalancerFirewallRelationTime()); !allowed {
		if vmFirewallMigrationReasonSilent(reason) {
			return false, nil
		}
		return false, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the migration of VM %s waits: %s", vmUUID, reason)
	}
	return plan.Phase == vmFirewallMigrationPhaseDone, nil
}
