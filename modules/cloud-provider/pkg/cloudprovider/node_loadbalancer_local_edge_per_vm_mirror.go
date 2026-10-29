package cloudprovider

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

// waitForPerVMVM is the mirror of waitForUnmigratedVM: in the per-VM mode, a
// Service that is still on a per-Service firewall does not attach it to a VM
// that already carries a per-VM firewall, or the next audit would mark the VM
// unverified for every Service on it. It waits for its own migration.
func (c *nodeLoadBalancerController) waitForPerVMVM(ctx context.Context, svc *corev1.Service, addresses []nodeLoadBalancerAddress) error {
	if !c.publicNodeLocalPerVMModeEnabled() {
		return nil
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		vmUUID, ok := nodeLoadBalancerVMUUID(address.Node)
		if !ok || !perVMFirewallAttachedTo(items, c.provider.config.ClusterID, c.provider.config.BillingAccountID, vmUUID) {
			continue
		}
		cause := vmFirewallWait(nodeLoadBalancerRetry,
			"public-node-local: VM %s carries a per-VM firewall; Service %s/%s is still on a per-Service firewall and waits for its migration",
			vmUUID, svc.Namespace, svc.Name)
		c.recordPublicNodeLocalEvent(ctx, svc, publicNodeLocalReasonVMFirewallMigrationWaiting, cause)
		return cause
	}
	return nil
}
