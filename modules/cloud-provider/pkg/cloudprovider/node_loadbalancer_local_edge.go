package cloudprovider

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// edgeID names the firewall edge a public-node-local Service serves through.
type edgeID struct {
	// policy is the firewall policy hash the edge enforces. The per-Service
	// backend fills it for the callers but does not read it: it works from
	// firewallUUID and the ledger annotations. The per-VM backend (its Retire
	// in particular) reads it.
	policy string
	// firewallUUID is the cloud firewall of the edge (per-Service only).
	firewallUUID string
	// snapshot is the firewall read Prepare or Active made (per-Service only).
	snapshot *inspace.Firewall
}

// fenceValue is what the durable assignment fence stores for the edge.
func (id edgeID) fenceValue() string {
	return id.firewallUUID
}

// publicNodeLocalEdge is every operation the public-node-local state machine
// performs on the cloud firewall edge. The state machine decides what to
// attach and detach; the edge decides how the firewall holds it.
type publicNodeLocalEdge interface {
	// Prepare returns the edge of the Service's current policy and, while a
	// policy change is in flight, the previous one. It may write.
	Prepare(ctx context.Context, svc *corev1.Service, desired desiredNodeLoadBalancerFirewall) (svcOut *corev1.Service, current, previous edgeID, waiting bool, err error)
	// Active is the read-only form of Prepare for a Service whose policy is held.
	Active(ctx context.Context, svc *corev1.Service, activePolicy string) (current, previous edgeID, err error)
	// Assigned returns the VMs the edge is attached to, as read by Prepare or Active.
	Assigned(ctx context.Context, svc *corev1.Service, id edgeID) (map[string]struct{}, error)
	// ResolvePending settles an unresolved relation receipt. resolved is false
	// when there was one, so the caller requeues.
	ResolvePending(ctx context.Context, svc *corev1.Service) (resolved bool, err error)
	// Assign attaches the edge to the addresses' VMs under the assignment fence.
	Assign(ctx context.Context, svc *corev1.Service, intent nodeLoadBalancerIntent, desired desiredNodeLoadBalancerFirewall, id edgeID, addresses []nodeLoadBalancerAddress) (converged bool, err error)
	// Unassign detaches the edge from every VM not in keep and names the VMs
	// whose relation is parked.
	Unassign(ctx context.Context, svc *corev1.Service, id edgeID, keep []*corev1.Node) (parked []string, err error)
	// Retire removes the previous edge once nothing needs it.
	Retire(ctx context.Context, svc *corev1.Service, id edgeID) (done bool, err error)
	// WithdrawAll closes every edge of the Service. proven is true only when
	// the readback shows nothing attached.
	WithdrawAll(ctx context.Context, svc *corev1.Service) (proven bool, err error)
}

// perServiceEdge is the edge of one firewall per Service.
type perServiceEdge struct{ c *nodeLoadBalancerController }

var _ publicNodeLocalEdge = perServiceEdge{}

// publicNodeLocalEdgeFor picks the edge backend of a Service.
func (c *nodeLoadBalancerController) publicNodeLocalEdgeFor(_ *corev1.Service) publicNodeLocalEdge {
	return perServiceEdge{c: c}
}

func perServiceEdgeID(firewall *inspace.Firewall, policy string) edgeID {
	if firewall == nil {
		return edgeID{}
	}
	return edgeID{policy: policy, firewallUUID: firewall.UUID, snapshot: firewall}
}

// perServicePreviousPolicy is the policy hash of the previous firewall, from
// its rules; empty when it cannot be computed. It is informational for the
// per-Service backend, which never reads edgeID.policy, so a hashing failure
// must not turn into an error here: that would change behaviour. The per-VM
// backend must not rely on this fallback.
func perServicePreviousPolicy(previous *inspace.Firewall) string {
	if previous == nil {
		return ""
	}
	hash, err := nodeLoadBalancerFirewallSpecHash(previous.Rules)
	if err != nil {
		return ""
	}
	return hash
}

func (e perServiceEdge) Prepare(ctx context.Context, svc *corev1.Service, desired desiredNodeLoadBalancerFirewall) (*corev1.Service, edgeID, edgeID, bool, error) {
	out, current, previous, waiting, err := e.c.preparePublicNodeLocalFirewall(ctx, svc)
	return out, perServiceEdgeID(current, desired.Hash), perServiceEdgeID(previous, perServicePreviousPolicy(previous)), waiting, err
}

func (e perServiceEdge) Active(ctx context.Context, svc *corev1.Service, activePolicy string) (edgeID, edgeID, error) {
	current, previous, err := e.c.activePublicNodeLocalFirewall(ctx, svc, activePolicy)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	return perServiceEdgeID(current, activePolicy), perServiceEdgeID(previous, perServicePreviousPolicy(previous)), nil
}

func (e perServiceEdge) Assigned(_ context.Context, _ *corev1.Service, id edgeID) (map[string]struct{}, error) {
	if id.snapshot == nil {
		return nil, errors.New("public-node-local: no firewall snapshot to read assignments from")
	}
	return nodeLoadBalancerFirewallVMAssignments(*id.snapshot)
}

func (e perServiceEdge) ResolvePending(ctx context.Context, svc *corev1.Service) (bool, error) {
	if svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" &&
		svc.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] == "" {
		return true, nil
	}
	// Resolve the unresolved relation receipt before planning on top of it.
	if _, err := e.c.reconcileNodeLoadBalancerFirewallRelation(ctx, e.c.serviceFirewallRelationOwner(svc), nil); err != nil {
		return false, err
	}
	return false, nil
}

func (e perServiceEdge) Assign(ctx context.Context, svc *corev1.Service, intent nodeLoadBalancerIntent, desired desiredNodeLoadBalancerFirewall, id edgeID, addresses []nodeLoadBalancerAddress) (bool, error) {
	if err := e.c.assignPublicNodeLocalFirewallWithFence(ctx, svc, intent, desired, id.snapshot, addresses); err != nil {
		return false, err
	}
	return true, nil
}

func (e perServiceEdge) Unassign(ctx context.Context, svc *corev1.Service, id edgeID, keep []*corev1.Node) ([]string, error) {
	return e.c.detachServiceFirewallFromOtherNodesParked(ctx, svc, id.snapshot, keep)
}

func (e perServiceEdge) Retire(ctx context.Context, svc *corev1.Service, _ edgeID) (bool, error) {
	if err := e.c.cleanupPreviousFirewall(ctx, svc); err != nil {
		return false, err
	}
	return true, nil
}

func (e perServiceEdge) WithdrawAll(ctx context.Context, svc *corev1.Service) (bool, error) {
	if err := e.c.detachOwnedServiceFirewallsForFailure(ctx, svc); err != nil {
		return false, err
	}
	return e.c.serviceFirewallsDetached(ctx, svc)
}
