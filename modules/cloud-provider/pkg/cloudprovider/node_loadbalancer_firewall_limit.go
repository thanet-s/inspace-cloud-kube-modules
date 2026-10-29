package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
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

// recentFirewallAssignTTL is how long an acknowledged attachment is counted
// even when the firewall listing does not show it yet.
const recentFirewallAssignTTL = 2 * time.Minute

// rememberFirewallAssign records an attachment the API acknowledged.
func (p *Provider) rememberFirewallAssign(vmUUID, firewallUUID string, now time.Time) {
	p.recentFirewallMu.Lock()
	defer p.recentFirewallMu.Unlock()
	if p.recentFirewallAssigns == nil {
		p.recentFirewallAssigns = map[string]map[string]time.Time{}
	}
	vm := strings.ToLower(vmUUID)
	if p.recentFirewallAssigns[vm] == nil {
		p.recentFirewallAssigns[vm] = map[string]time.Time{}
	}
	p.recentFirewallAssigns[vm][strings.ToLower(firewallUUID)] = now
}

// forgetFirewallAssign drops a remembered attachment, after a detach.
func (p *Provider) forgetFirewallAssign(vmUUID, firewallUUID string) {
	p.recentFirewallMu.Lock()
	defer p.recentFirewallMu.Unlock()
	vm := strings.ToLower(vmUUID)
	delete(p.recentFirewallAssigns[vm], strings.ToLower(firewallUUID))
	if len(p.recentFirewallAssigns[vm]) == 0 {
		delete(p.recentFirewallAssigns, vm)
	}
}

// recentFirewallAssignsFor returns the non-expired remembered firewall UUIDs of
// a VM and drops the expired ones.
func (p *Provider) recentFirewallAssignsFor(vmUUID string, now time.Time) []string {
	p.recentFirewallMu.Lock()
	defer p.recentFirewallMu.Unlock()
	vm := strings.ToLower(vmUUID)
	var result []string
	for firewallUUID, at := range p.recentFirewallAssigns[vm] {
		if now.Sub(at) >= recentFirewallAssignTTL {
			delete(p.recentFirewallAssigns[vm], firewallUUID)
			continue
		}
		result = append(result, firewallUUID)
	}
	if len(p.recentFirewallAssigns[vm]) == 0 {
		delete(p.recentFirewallAssigns, vm)
	}
	return result
}

// firewallVMCapacityFromItems is the pure capacity check. It counts every
// firewall in items that lists the VM, plus recently acknowledged attachments
// the listing may lag behind, and refuses when attaching firewallUUID would
// exceed the limit. A firewall already on the VM does not add to the count.
func (c *nodeLoadBalancerController) firewallVMCapacityFromItems(items []inspace.Firewall, firewallUUID, vmUUID string) error {
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
	for _, recent := range c.provider.recentFirewallAssignsFor(vmUUID, c.nodeLoadBalancerFirewallRelationTime()) {
		attached[recent] = struct{}{}
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

// requireFirewallVMCapacity reads the VM's current assignments from the API and
// applies the capacity check. A failed readback also refuses.
func (c *nodeLoadBalancerController) requireFirewallVMCapacity(ctx context.Context, firewallUUID, vmUUID string) error {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return fmt.Errorf("node load balancer: read firewalls of VM %s before attaching firewall %s: %w", vmUUID, firewallUUID, err)
	}
	return c.firewallVMCapacityFromItems(items, firewallUUID, vmUUID)
}

// refuseFirewallAttach logs a refused attachment and, for a limit refusal,
// raises the Warning Event on the owning Service.
func (c *nodeLoadBalancerController) refuseFirewallAttach(ctx context.Context, owner nodeLoadBalancerFirewallRelationOwner, fence nodeLoadBalancerFirewallRelationFence, cause error) {
	var limitErr *FirewallLimitExceededError
	if errors.As(cause, &limitErr) {
		c.recordFirewallLimitExceeded(ctx, owner.service, owner.description, cause)
		if owner.members != nil {
			for _, member := range owner.members(ctx) {
				if member == nil || (owner.service != nil && member.UID == owner.service.UID) {
					continue
				}
				c.recordFirewallLimitExceeded(ctx, member, owner.description, cause)
			}
		}
		return
	}
	klog.Warningf("node load balancer: %s: refuse to attach firewall %s to VM %s: %v",
		owner.description, fence.firewallUUID, fence.vmUUID, cause)
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
