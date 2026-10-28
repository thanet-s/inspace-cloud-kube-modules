package cloudprovider

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

const (
	// DefaultMaxFirewallsPerVM is the most firewalls the CCM lets one VM carry.
	// InSpace drops every new outbound connection of a VM with four or more
	// firewalls attached, regardless of the rule count, so three is the ceiling.
	DefaultMaxFirewallsPerVM int32 = 3

	// FirewallLimitExceededReason is the Event reason recorded on the Service
	// whose firewall attachment was refused.
	FirewallLimitExceededReason = "FirewallLimitExceeded"
)

// FirewallLimitExceededError reports that attaching a firewall would push a VM
// over the per-VM firewall limit. Nothing was attached.
type FirewallLimitExceededError struct {
	VMUUID       string
	FirewallUUID string
	// Current is the number of firewalls already attached to the VM.
	Current int
	Limit   int
}

func (e *FirewallLimitExceededError) Error() string {
	return fmt.Sprintf(
		"firewall limit exceeded: VM %s already has %d firewalls attached and the limit is %d; refusing to attach firewall %s",
		e.VMUUID, e.Current, e.Limit, e.FirewallUUID,
	)
}

// maxFirewallsPerVM returns the configured per-VM firewall limit. A value below
// one means the default.
func (p *Provider) maxFirewallsPerVM() int {
	if limit := p.config.NodeLoadBalancer.MaxFirewallsPerVM; limit >= 1 {
		return int(limit)
	}
	return int(DefaultMaxFirewallsPerVM)
}

// requireFirewallVMCapacity is the guard in front of every firewall
// attachment. It reads the VM's current assignments from the API, counting
// every firewall on the VM and not only the ones the CCM owns, and refuses when
// the attachment would exceed the limit. A firewall that is already attached
// does not add to the count. A failed readback also refuses.
func (c *nodeLoadBalancerController) requireFirewallVMCapacity(ctx context.Context, firewallUUID, vmUUID string) error {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return fmt.Errorf("node load balancer: read firewalls of VM %s before attaching firewall %s: %w", vmUUID, firewallUUID, err)
	}
	attached := map[string]struct{}{}
	for index := range items {
		for _, resource := range items[index].ResourcesAssigned {
			if strings.EqualFold(resource.ResourceType, "vm") && strings.EqualFold(resource.ResourceUUID, vmUUID) {
				attached[strings.ToLower(items[index].UUID)] = struct{}{}
				break
			}
		}
	}
	if _, already := attached[strings.ToLower(firewallUUID)]; already {
		return nil
	}
	limit := c.provider.maxFirewallsPerVM()
	if len(attached)+1 > limit {
		return &FirewallLimitExceededError{VMUUID: vmUUID, FirewallUUID: firewallUUID, Current: len(attached), Limit: limit}
	}
	return nil
}

// recordFirewallLimitExceeded makes a refused attachment visible. The Event is
// recorded on the owning Service when there is one; every owner gets a log line.
func (c *nodeLoadBalancerController) recordFirewallLimitExceeded(ctx context.Context, service *corev1.Service, owner string, cause error) {
	klog.Warningf("node load balancer: %s: %v", owner, cause)
	if service == nil {
		return
	}
	if err := c.recordPublicNodeLocalHoldEvent(ctx, service, FirewallLimitExceededReason, cause); err != nil {
		klog.Warningf("node load balancer: %s: record %s Event: %v", owner, FirewallLimitExceededReason, err)
	}
}
