package cloudprovider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// The helpers below are the per-VM counterparts of the public-node-local
// helpers that read a Service's own per-Service firewalls. PR 2 routed only the
// eight edge operations through publicNodeLocalEdge; these four still looked at
// ownedServiceFirewalls and would see nothing for a Service that lives on the
// per-VM firewall.

// perVMActiveRules returns the rules the Service's ledger entry of policy
// recorded, or nil when no anchor has that entry. They are what the VM firewalls
// enforce for the Service.
func (c *nodeLoadBalancerController) perVMActiveRules(ctx context.Context, service *corev1.Service, policy string) ([]inspace.FirewallRule, error) {
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return nil, err
	}
	for index := range anchors {
		ledger, err := (vmFirewallAnchorView{cm: &anchors[index]}).applied()
		if err != nil {
			continue
		}
		if member, found := ledger.find(vmFirewallMemberKey{UID: string(service.UID), Policy: policy}); found {
			return vmFirewallMemberFirewallRules(member), nil
		}
	}
	return nil, nil
}

// perVMAssignedPairs lists the VM firewall/VM pairs on which the Service has an
// entry now, in the form the rebuild journal records, bounded to 3000 bytes (an
// empty string when they do not fit).
func (c *nodeLoadBalancerController) perVMAssignedPairs(ctx context.Context, service *corev1.Service) (string, error) {
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return "", err
	}
	var pairs []string
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		if len(view.memberKeys(string(service.UID))) == 0 || view.uuid() == "" {
			continue
		}
		pairs = append(pairs, view.uuid()+"/"+view.vm())
	}
	sort.Strings(pairs)
	joined := strings.Join(pairs, ",")
	if len(joined) > 3000 {
		return "", nil
	}
	return joined, nil
}

// perVMRebuildDetachReadBack is publicNodeLocalRebuildDetachReadBack for a
// Service on the per-VM firewall: a pair of the journal counts as read back
// once the Service has no entry on that VM any more, or the VM firewall is no
// longer attached to it. The firewall itself stays while other Services use it.
func (c *nodeLoadBalancerController) perVMRebuildDetachReadBack(ctx context.Context, service *corev1.Service, journal string) (bool, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, err
	}
	entries := map[string]struct{}{}
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		if len(view.memberKeys(string(service.UID))) != 0 {
			entries[view.vm()] = struct{}{}
		}
	}
	for _, pair := range strings.Split(journal, ",") {
		firewallUUID, vmUUID, found := strings.Cut(pair, "/")
		if !found {
			continue
		}
		if _, listed := entries[vmUUID]; !listed {
			return true, nil
		}
		firewall, exactErr := exactNodeLoadBalancerFirewallFromItems(items, firewallUUID)
		if exactErr != nil || !vmFirewallAttachedTo(*firewall, vmUUID) {
			return true, nil
		}
	}
	return false, nil
}

// finalizePerVMPublicNodeLocal ends the cleanup of a Service that lived on the
// per-VM firewall. The Service is finalized only once no VM carries its ports:
// the withdrawal that came before proved it, and the proof is read again here.
func (c *nodeLoadBalancerController) finalizePerVMPublicNodeLocal(ctx context.Context, key string, service *corev1.Service) error {
	closed, _, err := c.vmFirewallServiceClosed(ctx, string(service.UID))
	if err != nil {
		return err
	}
	if !closed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	return c.finalizePublicNodeLocal(ctx, service)
}

// vmFirewallExposesService reports whether any VM firewall ledger still lists the
// Service, for the conflict check of its peers.
func (c *nodeLoadBalancerController) vmFirewallExposesService(ctx context.Context, service *corev1.Service) (bool, error) {
	if !c.publicNodeLocalPerVMModeEnabled() && !publicNodeLocalServicePerVM(service) {
		return false, nil
	}
	closed, _, err := c.vmFirewallServiceClosed(ctx, string(service.UID))
	if err != nil {
		return false, fmt.Errorf("public-node-local: inspect conflict peer VM firewalls: %w", err)
	}
	return !closed, nil
}
