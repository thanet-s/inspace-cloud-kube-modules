package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	publicNodeLocalReasonRebuildAllowed = "PublicNodeLocalRebuildAllowed"
)

// publicNodeLocalPassMode says which identity a convergence pass works under.
type publicNodeLocalPassMode int

const (
	// publicNodeLocalPassNormal: the intent equals the active exposure.
	publicNodeLocalPassNormal publicNodeLocalPassMode = iota
	// publicNodeLocalPassPoolHeld: only the pool differs from the active one.
	// The pass runs in full, under the active pool.
	publicNodeLocalPassPoolHeld
	// publicNodeLocalPassPolicyHeld: the ports or source ranges differ from the
	// active policy. The Service spec no longer describes what is serving, so
	// the pass only removes nodes, under the ledger firewall and the child as
	// they are. Adds and child spec repair wait for a make-before-break
	// transition.
	publicNodeLocalPassPolicyHeld
	// publicNodeLocalPassUnion: the Service converges to a target pool or policy
	// while the active exposure keeps serving. The intent is the target.
	publicNodeLocalPassUnion
)

// syncPendingPublicNodeLocalTransition handles a serving Service whose pool or
// firewall policy differs from the active exposure. The intent is never applied
// by a blind withdrawal, because that would be an outage the operator did not
// ask for:
//
//   - the escape hatch annotation permits the old withdraw and rebuild;
//   - an admissible change (a pool switch, a widening, a narrowing or a mix)
//     starts a make-before-break transition: the target is recorded next to the
//     active identity and the next passes serve the union (see
//     convergeActivePublicNodeLocal);
//   - a change that cannot start yet (the target pool would lose a port claim, a
//     previous firewall or an assignment is still being settled) keeps the active
//     exposure serving and keeps converging nodes under the active identity.
//     The pass holds and requeues with the hold delay.
func (c *nodeLoadBalancerController) syncPendingPublicNodeLocalTransition(
	ctx context.Context,
	key string,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
) error {
	activePool := service.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := service.Annotations[annotationPublicNodeLocalActivePolicy]
	cause := fmt.Errorf(
		"public-node-local: the Service intent (pool %q, firewall policy %q) differs from the active exposure (pool %q, firewall policy %q); keeping the active exposure",
		intent.Pool, desired.Hash, activePool, activePolicy,
	)

	allowed, allowErr := c.consumePublicNodeLocalRebuildAllowance(ctx, service, intent, desired)
	if allowErr != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, allowErr)
	}
	if allowed {
		c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonRebuildAllowed, fmt.Errorf(
			"public-node-local: %s permits one withdraw and rebuild for this change: %w", annotationNodeLoadBalancerAllowRebuild, cause))
		return c.withdrawAndRequeuePublicNodeLocal(ctx, key, service)
	}

	reason := publicNodeLocalReasonTransitionPending
	refusal, admitErr := c.publicNodeLocalTransitionAdmissible(ctx, service, intent)
	if admitErr != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, admitErr)
	}
	if refusal != nil {
		reason, cause = publicNodeLocalReasonTransitionRefused, refusal
	}
	if refusal == nil && !publicNodeLocalOldEdgePending(service) &&
		!publicNodeLocalAssignmentFencePresent(service) {
		started, startErr := c.startPublicNodeLocalTransition(ctx, service, intent, desired)
		if startErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, startErr)
		}
		if started {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}
	c.recordPublicNodeLocalEvent(ctx, service, reason, cause)
	mode := publicNodeLocalPassPoolHeld
	activeIntent := intent
	activeDesired := desired
	if activePolicy != desired.Hash {
		mode = publicNodeLocalPassPolicyHeld
		activeDesired = desiredNodeLoadBalancerFirewall{Hash: activePolicy}
	}
	activeIntent.Pool = activePool
	if err := c.convergeActivePublicNodeLocal(ctx, key, service, activeIntent, activeDesired, mode); err != nil {
		return err
	}
	// Nothing else to do under the active identity: hold, and look again later.
	// The delay grows while the same change stays pending.
	retryAfter, _ := c.nextPublicNodeLocalHoldDelay(string(service.UID), cause)
	return &errPublicNodeLocalHolding{cause: cause, retryAfter: retryAfter}
}

// publicNodeLocalAgeSince is the time since a recorded instant, rounded to the
// minute so an Event that carries it changes once a minute, not once a pass.
func publicNodeLocalAgeSince(now time.Time, recorded string) (time.Duration, bool) {
	since, err := time.Parse(time.RFC3339, recorded)
	if err != nil {
		return 0, false
	}
	age := now.Sub(since)
	if age < 0 {
		age = 0
	}
	return age.Round(time.Minute), true
}

const publicNodeLocalReasonOldFirewallAttached = "PublicNodeLocalOldFirewallAttached"

// noteOldFirewallAttached tells the operator how long a narrowed old firewall has
// stayed attached after the promotion. The narrowing is applied by the new
// firewall only once the old one is detached, so the age is the length of the
// window in which a port or source range that the Service dropped is still open.
func (c *nodeLoadBalancerController) noteOldFirewallAttached(ctx context.Context, service *corev1.Service, current, previous edgeID) {
	if current.snapshot == nil || previous.snapshot == nil || service.Annotations[annotationPublicNodeLocalTargetPolicy] != "" {
		return
	}
	assignments, err := c.publicNodeLocalEdgeFor(service).Assigned(ctx, service, previous)
	if err != nil || len(assignments) == 0 {
		return
	}
	kept := make(map[string]struct{}, len(current.snapshot.Rules))
	for _, rule := range current.snapshot.Rules {
		kept[nodeLoadBalancerFirewallRuleKey(rule)] = struct{}{}
	}
	narrowed := false
	for _, rule := range previous.snapshot.Rules {
		if _, found := kept[nodeLoadBalancerFirewallRuleKey(rule)]; !found {
			narrowed = true
		}
	}
	if !narrowed {
		return
	}
	age, found := publicNodeLocalAgeSince(c.publicNodeLocalClock(), service.Annotations[annotationPublicNodeLocalPromotedAt])
	if !found {
		return
	}
	c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonOldFirewallAttached, fmt.Errorf(
		"public-node-local: the narrowed previous firewall %s is still attached to %d VM(s), %s after the promotion; what the Service dropped stays open until it is detached",
		previous.firewallUUID, len(assignments), age))
}

// unparkPublicNodeLocalUnassign ends the park of a detach of the previous
// firewall. Detaching is the safe direction, so it is retried at the normal
// cadence instead of waiting out the park.
func (c *nodeLoadBalancerController) unparkPublicNodeLocalUnassign(ctx context.Context, service *corev1.Service, firewallUUID string, vmUUIDs []string) error {
	if len(vmUUIDs) == 0 {
		return nil
	}
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, vmUUID := range vmUUIDs {
			key := nodeLoadBalancerFirewallRelationKey(nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewallUUID, vmUUID: vmUUID,
			})
			if clearNodeLoadBalancerFirewallRelationRetirement(copy.Annotations, key, c.nodeLoadBalancerFirewallRelationTime()) {
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

// holdPendingPublicNodeLocalTransition holds a transition that cannot move on
// yet, with the Pending Event and the backoff of an unchanged hold.
func (c *nodeLoadBalancerController) holdPendingPublicNodeLocalTransition(ctx context.Context, service *corev1.Service, cause error) error {
	if age, found := publicNodeLocalAgeSince(c.publicNodeLocalClock(), service.Annotations[annotationPublicNodeLocalTargetSince]); found {
		cause = fmt.Errorf("%w (union age %s)", cause, age)
	}
	c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonTransitionPending, cause)
	retryAfter, _ := c.nextPublicNodeLocalHoldDelay(string(service.UID), cause)
	return &errPublicNodeLocalHolding{cause: cause, retryAfter: retryAfter}
}

// consumePublicNodeLocalRebuildAllowance decides whether the operator escape
// hatch applies, and records the use before anything is withdrawn. The raw
// annotation value is the key: any value is honoured exactly once, until the
// annotation is changed (a new value counts again) or removed. A manifest that
// keeps a value therefore cannot replay a rebuild on a later change, of any kind.
func (c *nodeLoadBalancerController) consumePublicNodeLocalRebuildAllowance(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
) (bool, error) {
	raw := strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerAllowRebuild])
	if raw == "" {
		return false, nil
	}
	consumed := service.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed]
	if consumed == raw {
		return false, nil
	}
	// What is assigned now tells, later, whether a detach has been read back.
	assigned, err := c.publicNodeLocalAssignedPairs(ctx, service)
	if err != nil {
		return false, err
	}
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerAllowRebuild] != raw ||
			copy.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] != consumed {
			return false, errors.New("public-node-local: the escape hatch changed before it was consumed")
		}
		copy.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] = raw
		copy.Annotations[annotationNodeLoadBalancerRebuilding] = raw
		if assigned != "" {
			copy.Annotations[annotationNodeLoadBalancerRebuildingAssigned] = assigned
		}
		return true, nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// clearPublicNodeLocalRebuildConsumed forgets the consumed target once the
// operator removed the annotation, so a later deliberate use counts again.
func (c *nodeLoadBalancerController) clearPublicNodeLocalRebuildConsumed(ctx context.Context, service *corev1.Service) (bool, error) {
	if service.Annotations[annotationNodeLoadBalancerAllowRebuild] != "" ||
		service.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] == "" {
		return false, nil
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerAllowRebuild] != "" ||
			copy.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] == "" {
			return false, nil
		}
		delete(copy.Annotations, annotationNodeLoadBalancerAllowRebuildConsumed)
		return true, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) recordPublicNodeLocalEvent(ctx context.Context, service *corev1.Service, reason string, cause error) {
	if err := c.recordPublicNodeLocalHoldEvent(ctx, service, reason, cause); err != nil {
		klog.Warningf("public-node-local %s/%s: record %s Event: %v", service.Namespace, service.Name, reason, err)
	}
}

// withdrawAndRequeuePublicNodeLocal closes the serving exposure so the next pass
// rebuilds it under the current intent.
func (c *nodeLoadBalancerController) withdrawAndRequeuePublicNodeLocal(ctx context.Context, key string, service *corev1.Service) error {
	if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
		return err
	}
	c.requeuePublicNodeLocal(key)
	return nil
}

// activePublicNodeLocalFirewall returns the ledger firewall of a serving
// Service and proves that its rules are the active policy.
func (c *nodeLoadBalancerController) activePublicNodeLocalFirewall(
	ctx context.Context,
	service *corev1.Service,
	activePolicy string,
) (*inspace.Firewall, *inspace.Firewall, error) {
	firewallUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	if firewallUUID == "" || service.Annotations[annotationNodeLoadBalancerFirewallHash] != activePolicy {
		return nil, nil, errors.New("public-node-local: the firewall ledger does not match the active policy")
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return nil, nil, err
	}
	var current, previous *inspace.Firewall
	for index := range owned {
		switch owned[index].UUID {
		case firewallUUID:
			hash, hashErr := nodeLoadBalancerFirewallSpecHash(owned[index].Rules)
			if hashErr != nil || hash != activePolicy {
				return nil, nil, errors.New("public-node-local: the ledger firewall rules are not the active policy")
			}
			current = &owned[index]
		case service.Annotations[annotationNodeLoadBalancerPreviousFirewall]:
			previous = &owned[index]
		}
	}
	if current == nil {
		return nil, nil, fmt.Errorf("public-node-local: ledger firewall %s is not owned by the Service", firewallUUID)
	}
	return current, previous, nil
}

// finishPreviousPublicNodeLocalFirewall retires the firewall of the old policy
// after a promotion: it is detached from every VM that holds the current
// firewall, and deleted once nothing is assigned. A VM that does not hold the
// current firewall yet keeps the old one, so a kept node is never left without
// a gate. The old firewall is therefore attached only as long as it is needed:
// from the promotion until the current firewall is attached to every VM and
// read back. The child ports stay at the union until the old firewall is gone.
func (c *nodeLoadBalancerController) finishPreviousPublicNodeLocalFirewall(
	ctx context.Context,
	key string,
	service *corev1.Service,
	edge publicNodeLocalEdge,
	current, previous edgeID,
	currentAssigned map[string]struct{},
	keep map[string]struct{},
	members map[string]publicNodeLocalMember,
) (bool, error) {
	if !publicNodeLocalOldEdgePending(service) {
		return false, nil
	}
	if previous.known() {
		stay := map[string]struct{}{}
		var stayNodes []*corev1.Node
		for name := range keep {
			member := members[name]
			if member.vmUUID == "" {
				continue
			}
			if _, covered := currentAssigned[member.vmUUID]; !covered {
				stay[member.vmUUID] = struct{}{}
				stayNodes = append(stayNodes, member.node)
			}
		}
		stale, err := previous.stale(stay)
		if err != nil {
			return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if len(stale) != 0 {
			parked, err := edge.Unassign(ctx, service, previous, stayNodes)
			if err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			if len(parked) != 0 && !previous.perVM {
				if err := c.unparkPublicNodeLocalUnassign(ctx, service, previous.firewallUUID, parked); err != nil {
					return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
				}
				c.requeuePublicNodeLocal(key)
				return true, nil
			}
			c.requeuePublicNodeLocal(key)
			return true, nil
		}
		if len(stay) != 0 {
			// Kept nodes without the current firewall: the old one stays on them.
			return false, nil
		}
	}
	if _, err := edge.Retire(ctx, service, previous); err != nil {
		return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	c.requeuePublicNodeLocal(key)
	return true, nil
}

// readPublicNodeLocalDatapathHeld reads the child of a Service whose spec no
// longer describes it. A missing child is nil. A foreign one is an error.
func (c *nodeLoadBalancerController) readPublicNodeLocalDatapathHeld(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("public-node-local: get private datapath Service: %w", err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) || datapath.DeletionTimestamp != nil {
		return nil, fmt.Errorf("public-node-local: datapath Service %s/%s is foreign or being deleted", service.Namespace, datapath.Name)
	}
	return datapath, nil
}

// setPublicNodeLocalDatapathStatusHeld writes the VIPs of a child whose spec is
// not compared with the held Service spec.
func (c *nodeLoadBalancerController) setPublicNodeLocalDatapathStatusHeld(
	ctx context.Context,
	service, datapath *corev1.Service,
	status corev1.LoadBalancerStatus,
) error {
	if datapath == nil || !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return errors.New("public-node-local: refuse status publication to a missing or foreign private datapath")
	}
	copy := datapath.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: publish private datapath status: %w", err)
	}
	if updated.UID != datapath.UID {
		return errors.New("public-node-local: private datapath identity changed during status publication")
	}
	return nil
}

const (
	annotationPublicNodeLocalTargetPool   = "service.inspace.cloud/public-node-local-target-pool"
	annotationPublicNodeLocalTargetPolicy = "service.inspace.cloud/public-node-local-target-policy"
	// annotationPublicNodeLocalTargetSince is when the union started, and
	// annotationPublicNodeLocalPromotedAt when the target was promoted. They give
	// the age that the Events report.
	annotationPublicNodeLocalTargetSince = "service.inspace.cloud/public-node-local-target-since"
	annotationPublicNodeLocalPromotedAt  = "service.inspace.cloud/public-node-local-promoted-at"
	// annotationPublicNodeLocalDatapathTargetPool is set on the child while a
	// transition is in progress, so peers can attribute its exposure to both pools.
	annotationPublicNodeLocalDatapathTargetPool = "service.inspace.cloud/public-node-local-target-pool"
)

type publicNodeLocalTransitionPhase int

const (
	// publicNodeLocalPhaseInactive: nothing is serving.
	publicNodeLocalPhaseInactive publicNodeLocalTransitionPhase = iota
	// publicNodeLocalPhaseSteady: the active exposure is the only one.
	publicNodeLocalPhaseSteady
	// publicNodeLocalPhaseUnion: the active and the target exposure are both
	// being served until the target is converged.
	publicNodeLocalPhaseUnion
	// publicNodeLocalPhasePromoted: the target was promoted and the old
	// firewall is still being detached and deleted.
	publicNodeLocalPhasePromoted
	// publicNodeLocalPhaseInvalid: the annotations contradict each other.
	publicNodeLocalPhaseInvalid
)

type publicNodeLocalTransitionState struct {
	Phase        publicNodeLocalTransitionPhase
	ActivePool   string
	ActivePolicy string
	TargetPool   string
	TargetPolicy string
}

// Work is the identity that adds converge to: the target while a union runs,
// the active identity otherwise.
func (s publicNodeLocalTransitionState) Work() (pool, policy string) {
	if s.Phase == publicNodeLocalPhaseUnion {
		return s.TargetPool, s.TargetPolicy
	}
	return s.ActivePool, s.ActivePolicy
}

// publicNodeLocalTransition reads the transition phase from the parent
// annotations. An inconsistent set is Invalid and must be held, never acted on.
func publicNodeLocalTransition(service *corev1.Service) (publicNodeLocalTransitionState, error) {
	state := publicNodeLocalTransitionState{
		ActivePool:   service.Annotations[annotationPublicNodeLocalActivePool],
		ActivePolicy: service.Annotations[annotationPublicNodeLocalActivePolicy],
		TargetPool:   service.Annotations[annotationPublicNodeLocalTargetPool],
		TargetPolicy: service.Annotations[annotationPublicNodeLocalTargetPolicy],
	}
	invalid := func(reason string) (publicNodeLocalTransitionState, error) {
		state.Phase = publicNodeLocalPhaseInvalid
		return state, fmt.Errorf("public-node-local: invalid transition annotations: %s", reason)
	}
	if (state.ActivePool == "") != (state.ActivePolicy == "") {
		return invalid("incomplete activation identity")
	}
	if (state.TargetPool == "") != (state.TargetPolicy == "") {
		return invalid("target pool and policy must be set together")
	}
	if state.TargetPool != "" {
		if state.ActivePool == "" {
			return invalid("a target without an activation")
		}
		if state.TargetPool == state.ActivePool && state.TargetPolicy == state.ActivePolicy {
			return invalid("the target equals the active identity")
		}
		state.Phase = publicNodeLocalPhaseUnion
		return state, nil
	}
	switch {
	case state.ActivePool == "":
		state.Phase = publicNodeLocalPhaseInactive
	case publicNodeLocalOldEdgePending(service):
		state.Phase = publicNodeLocalPhasePromoted
	default:
		state.Phase = publicNodeLocalPhaseSteady
	}
	return state, nil
}

const publicNodeLocalReasonTransitionRefused = "PublicNodeLocalTransitionRefused"

// publicNodeLocalTransitionAdmissible says whether a serving Service may start
// a transition to the target intent. The target pool must not take a protocol
// and port that a peer already serves there. Ports this Service already serves
// in the same pool are not new claims. A refusal is returned as the first
// value; an error means the answer could not be established.
func (c *nodeLoadBalancerController) publicNodeLocalTransitionAdmissible(
	ctx context.Context,
	service *corev1.Service,
	target nodeLoadBalancerIntent,
) (refusal error, err error) {
	claims := target.Ports
	if service.Annotations[annotationPublicNodeLocalActivePool] == target.Pool {
		child, readErr := c.readPublicNodeLocalDatapathHeld(ctx, service)
		if readErr != nil {
			return nil, readErr
		}
		if child != nil {
			if served, claimErr := nodeLoadBalancerPortClaims(child); claimErr == nil {
				servedSet := make(map[nodeLoadBalancerPortClaim]struct{}, len(served))
				for _, claim := range served {
					servedSet[claim] = struct{}{}
				}
				fresh := make([]nodeLoadBalancerPortClaim, 0, len(claims))
				for _, claim := range claims {
					if _, already := servedSet[claim]; !already {
						fresh = append(fresh, claim)
					}
				}
				claims = fresh
			}
		}
	}
	if len(claims) == 0 {
		return nil, nil
	}
	newClaims := target
	newClaims.Ports = claims
	services, listErr := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if listErr != nil {
		return nil, fmt.Errorf("public-node-local: list Services for transition admission: %w", listErr)
	}
	for index := range services.Items {
		other := &services.Items[index]
		if other.UID == service.UID || other.Spec.LoadBalancerClass == nil ||
			*other.Spec.LoadBalancerClass != nodeLoadBalancerClass {
			// Child datapath Services use their own class and are not peers.
			continue
		}
		exposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, other)
		if exposureErr != nil {
			return nil, exposureErr
		}
		if !exposed {
			continue
		}
		blocks, blockErr := c.publicNodeLocalStaleExposureBlocks(ctx, other, newClaims)
		if blockErr != nil {
			return nil, blockErr
		}
		if blocks {
			return fmt.Errorf(
				"public-node-local: pool %s already serves a protocol/port claim of Service %s/%s that this Service would take; the transition is refused and the active exposure stays",
				target.Pool, other.Namespace, other.Name,
			), nil
		}
	}
	return nil, nil
}

// startPublicNodeLocalTransition records the target of a pool or policy change
// next to the active identity. From then on the Service serves the union of
// both until the target is converged and promoted. Nothing is changed in the
// cloud. The write is a compare-and-swap on the exact parent: it only applies if
// the live Service still wants this target and still serves this activation.
func (c *nodeLoadBalancerController) startPublicNodeLocalTransition(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
) (bool, error) {
	activePool := service.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := service.Annotations[annotationPublicNodeLocalActivePolicy]
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		liveIntent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		liveDesired, desiredErr := c.desiredServiceFirewall(copy)
		if parseErr != nil || desiredErr != nil || liveIntent.Pool != intent.Pool || liveDesired.Hash != desired.Hash ||
			copy.Annotations[annotationPublicNodeLocalActivePool] != activePool ||
			copy.Annotations[annotationPublicNodeLocalActivePolicy] != activePolicy ||
			copy.Annotations[annotationPublicNodeLocalTargetPool] != "" ||
			copy.Annotations[annotationPublicNodeLocalTargetPolicy] != "" ||
			publicNodeLocalOldEdgePending(copy) ||
			publicNodeLocalAssignmentFencePresent(copy) {
			return false, errors.Join(errors.New("public-node-local: the Service changed before the transition could start"), parseErr, desiredErr)
		}
		copy.Annotations[annotationPublicNodeLocalTargetPool] = intent.Pool
		copy.Annotations[annotationPublicNodeLocalTargetPolicy] = desired.Hash
		copy.Annotations[annotationPublicNodeLocalTargetSince] = c.publicNodeLocalClock().Format(time.RFC3339)
		return true, nil
	})
	return changed, err
}

// promotePublicNodeLocalTransition makes the converged target the active
// identity. Old-pool Nodes are then Gone, and the normal removal order takes
// them off the edge one by one.
func (c *nodeLoadBalancerController) promotePublicNodeLocalTransition(
	ctx context.Context,
	service *corev1.Service,
	targetPool, targetPolicy, firewallUUID string,
) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		perVM := publicNodeLocalServicePerVM(copy)
		if copy.Annotations[annotationPublicNodeLocalTargetPool] != targetPool ||
			copy.Annotations[annotationPublicNodeLocalTargetPolicy] != targetPolicy ||
			(!perVM && (copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
				copy.Annotations[annotationNodeLoadBalancerFirewallHash] != targetPolicy)) ||
			(perVM && (copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != "" || copy.Annotations[annotationNodeLoadBalancerFirewallHash] != "")) ||
			publicNodeLocalAssignmentFencePresent(copy) {
			return false, errors.New("public-node-local: the transition changed before promotion")
		}
		// The ports recorded below are the spec of this write, so the live spec
		// must still be the target the pass converged to.
		liveIntent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		liveDesired, desiredErr := c.desiredServiceFirewall(copy)
		if parseErr != nil || desiredErr != nil || liveIntent.Pool != targetPool || liveDesired.Hash != targetPolicy {
			return false, errors.Join(errors.New("public-node-local: the live Service is no longer the target at promotion"), parseErr, desiredErr)
		}
		oldPolicy := copy.Annotations[annotationPublicNodeLocalActivePolicy]
		copy.Annotations[annotationPublicNodeLocalActivePool] = targetPool
		copy.Annotations[annotationPublicNodeLocalActivePolicy] = targetPolicy
		setPublicNodeLocalActivePorts(copy)
		delete(copy.Annotations, annotationPublicNodeLocalTargetPool)
		delete(copy.Annotations, annotationPublicNodeLocalTargetPolicy)
		delete(copy.Annotations, annotationPublicNodeLocalTargetSince)
		// A per-VM Service has no previous firewall. Its old policy entries are the
		// tail, marked here until the last one is retired.
		if copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" || (perVM && oldPolicy != targetPolicy) {
			copy.Annotations[annotationPublicNodeLocalPromotedAt] = c.publicNodeLocalClock().Format(time.RFC3339)
		}
		return true, nil
	})
	return err
}

const publicNodeLocalReasonTransitionAborted = "PublicNodeLocalTransitionAborted"

// abortPublicNodeLocalTransition ends a union that the intent no longer wants:
// the pool or policy went back to the active one, moved on to a third, or the
// target lost a claim. The target annotations are cleared and the active
// exposure keeps serving. Nodes that joined for the target only are then Gone
// under the active identity, and the normal removal order takes them off. When
// the policy had moved the firewall ledger to the target firewall, the ledger is
// handed back to the active firewall, and the target one becomes the previous
// firewall that the normal cleanup detaches and deletes.
func (c *nodeLoadBalancerController) abortPublicNodeLocalTransition(
	ctx context.Context,
	key string,
	service *corev1.Service,
	cause error,
) error {
	state, err := publicNodeLocalTransition(service)
	if err != nil || state.Phase != publicNodeLocalPhaseUnion {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.Join(err, errors.New("public-node-local: no transition to abort")))
	}
	var restore *inspace.Firewall
	ledgerPolicy := service.Annotations[annotationNodeLoadBalancerFirewallHash]
	previousUUID := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	perVM := publicNodeLocalServicePerVM(service)
	if !perVM && ledgerPolicy != state.ActivePolicy {
		// The ledger already moved to the target firewall. Only the exact previous
		// firewall, proven to carry the active policy, may take it back.
		if previousUUID == "" {
			return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: cannot abort a transition whose active firewall is unknown"))
		}
		owned, ownedErr := c.ownedServiceFirewalls(ctx, service)
		if ownedErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, ownedErr)
		}
		for index := range owned {
			if owned[index].UUID != previousUUID {
				continue
			}
			if hash, hashErr := nodeLoadBalancerFirewallSpecHash(owned[index].Rules); hashErr == nil && hash == state.ActivePolicy {
				restore = &owned[index]
			}
		}
		if restore == nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: the previous firewall does not prove the active policy"))
		}
	}
	c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonTransitionAborted, fmt.Errorf(
		"public-node-local: the transition to pool %q (policy %q) is abandoned and the active exposure stays: %w",
		state.TargetPool, state.TargetPolicy, cause))
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalTargetPool] != state.TargetPool ||
			copy.Annotations[annotationPublicNodeLocalTargetPolicy] != state.TargetPolicy ||
			copy.Annotations[annotationPublicNodeLocalActivePool] != state.ActivePool ||
			copy.Annotations[annotationPublicNodeLocalActivePolicy] != state.ActivePolicy {
			return false, errors.New("public-node-local: the transition changed before it could be abandoned")
		}
		if restore != nil {
			copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = copy.Annotations[annotationNodeLoadBalancerFirewallUUID]
			copy.Annotations[annotationNodeLoadBalancerFirewallUUID] = restore.UUID
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] = state.ActivePolicy
		}
		delete(copy.Annotations, annotationPublicNodeLocalTargetPool)
		delete(copy.Annotations, annotationPublicNodeLocalTargetPolicy)
		delete(copy.Annotations, annotationPublicNodeLocalTargetSince)
		if perVM && state.TargetPolicy != state.ActivePolicy {
			// The target's entries are the old policy now: the tail retires them
			// once the active policy is open wherever they stand.
			copy.Annotations[annotationPublicNodeLocalPromotedAt] = c.publicNodeLocalClock().Format(time.RFC3339)
		}
		if restore != nil {
			// The assignment intent named the target firewall, which is retired now.
			// Nothing is assigned under it any more; a stale receipt is resolved by
			// the relation fence as usual.
			for _, fenceKey := range []string{
				annotationNodeLoadBalancerFirewallAssigning,
				annotationNodeLoadBalancerFirewallAssignAt,
				annotationPublicNodeLocalAssignPolicy,
				annotationPublicNodeLocalAssignVMs,
				annotationPublicNodeLocalAssignEdge,
			} {
				delete(copy.Annotations, fenceKey)
			}
		}
		return true, nil
	})
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	c.requeuePublicNodeLocal(key)
	return nil
}

// publicNodeLocalChildFromActiveFirewall rebuilds what a lost child served
// before, from the rules of the firewall that carries the active policy: the
// ports it allows and the source ranges it allows. The target ports are unknown
// (the Service spec describes the pending policy), so the port itself is used.
// It returns nil when no firewall proves the active policy.
func (c *nodeLoadBalancerController) publicNodeLocalChildFromActiveFirewall(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, error) {
	activePolicy := service.Annotations[annotationPublicNodeLocalActivePolicy]
	if activePolicy == "" {
		return nil, nil
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return nil, err
	}
	for index := range owned {
		hash, hashErr := nodeLoadBalancerFirewallSpecHash(owned[index].Rules)
		if hashErr != nil || hash != activePolicy {
			continue
		}
		child := &corev1.Service{}
		recordedPorts := publicNodeLocalActivePorts(service)
		anySource := false
		sources := map[string]struct{}{}
		for _, rule := range owned[index].Rules {
			if !strings.EqualFold(rule.Direction, "inbound") || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
				continue
			}
			protocol := corev1.ProtocolTCP
			if strings.EqualFold(rule.Protocol, "udp") {
				protocol = corev1.ProtocolUDP
			} else if !strings.EqualFold(rule.Protocol, "tcp") {
				continue
			}
			port := corev1.ServicePort{
				Name: fmt.Sprintf("t-%s-%d", strings.ToLower(string(protocol)), *rule.PortStart), Protocol: protocol,
				Port: *rule.PortStart, TargetPort: intstr.FromInt32(*rule.PortStart),
			}
			// The recorded active ports know the real name and target port.
			for _, recorded := range recordedPorts {
				if recorded.Port == port.Port && recorded.Protocol == protocol {
					port = recorded
				}
			}
			child.Spec.Ports = append(child.Spec.Ports, port)
			if rule.EndpointSpecType != "ip_prefixes" {
				anySource = true
			}
			for _, source := range rule.EndpointSpec {
				sources[source] = struct{}{}
			}
		}
		if !anySource {
			for source := range sources {
				child.Spec.LoadBalancerSourceRanges = append(child.Spec.LoadBalancerSourceRanges, source)
			}
			sort.Strings(child.Spec.LoadBalancerSourceRanges)
		}
		return child, nil
	}
	return nil, nil
}

// createPublicNodeLocalDatapathHeld recreates a lost child while the Service
// spec describes a pending policy: the pending ports, plus the ports of the
// active firewall, so nothing the active firewall allows is blackholed.
func (c *nodeLoadBalancerController) createPublicNodeLocalDatapathHeld(
	ctx context.Context,
	service *corev1.Service,
	pool string,
) error {
	desired := desiredPublicNodeLocalDatapath(service, pool)
	previous, err := c.publicNodeLocalChildFromActiveFirewall(ctx, service)
	if err != nil {
		return err
	}
	if previous != nil {
		// Only what the active firewall allows is served: a pending port that was
		// refused must not look served (and so claimed) because the child has it.
		type portKey struct {
			protocol corev1.Protocol
			port     int32
		}
		served := map[portKey]struct{}{}
		for _, port := range previous.Spec.Ports {
			served[portKey{port.Protocol, port.Port}] = struct{}{}
		}
		kept := make([]corev1.ServicePort, 0, len(desired.Spec.Ports))
		for _, port := range desired.Spec.Ports {
			protocol := port.Protocol
			if protocol == "" {
				protocol = corev1.ProtocolTCP
			}
			if _, active := served[portKey{protocol, port.Port}]; active {
				kept = append(kept, port)
			}
		}
		desired.Spec.Ports = kept
		desired = mergePublicNodeLocalDatapathUnion(desired, previous)
		desired.Spec.LoadBalancerSourceRanges = append([]string(nil), previous.Spec.LoadBalancerSourceRanges...)
	}
	if _, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Create(ctx, desired, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("public-node-local: recreate the private datapath Service: %w", err)
	}
	return nil
}

const (
	// annotationPublicNodeLocalActivePorts records the Service ports that the
	// active exposure serves: name, protocol, port and target port. A child that
	// is lost during a transition is rebuilt from it, because the Service spec
	// already describes the target and the real target ports of a port that the
	// change drops are not recoverable from anywhere else.
	annotationPublicNodeLocalActivePorts = "service.inspace.cloud/public-node-local-active-ports"

	// publicNodeLocalActivePortsMaxBytes bounds the annotation. A Service whose
	// ports do not fit is rebuilt from the firewall alone, with the port number as
	// target port.
	publicNodeLocalActivePortsMaxBytes = 4096
)

type publicNodeLocalActivePort struct {
	Name       string `json:"n,omitempty"`
	Protocol   string `json:"pr"`
	Port       int32  `json:"p"`
	TargetInt  int32  `json:"ti,omitempty"`
	TargetName string `json:"ts,omitempty"`
}

// encodePublicNodeLocalActivePorts returns the annotation value, or "" when the
// ports do not fit the bound.
func encodePublicNodeLocalActivePorts(ports []corev1.ServicePort) string {
	records := make([]publicNodeLocalActivePort, 0, len(ports))
	for _, port := range ports {
		record := publicNodeLocalActivePort{Name: port.Name, Protocol: string(port.Protocol), Port: port.Port}
		if record.Protocol == "" {
			record.Protocol = string(corev1.ProtocolTCP)
		}
		if port.TargetPort.Type == intstr.String {
			record.TargetName = port.TargetPort.StrVal
		} else {
			record.TargetInt = port.TargetPort.IntVal
		}
		records = append(records, record)
	}
	encoded, err := json.Marshal(records)
	if err != nil || len(encoded) > publicNodeLocalActivePortsMaxBytes {
		return ""
	}
	return string(encoded)
}

// publicNodeLocalActivePorts reads the recorded ports. A malformed value counts
// as no record.
func publicNodeLocalActivePorts(service *corev1.Service) []corev1.ServicePort {
	raw := service.Annotations[annotationPublicNodeLocalActivePorts]
	if raw == "" {
		return nil
	}
	var records []publicNodeLocalActivePort
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		return nil
	}
	ports := make([]corev1.ServicePort, 0, len(records))
	for _, record := range records {
		port := corev1.ServicePort{Name: record.Name, Protocol: corev1.Protocol(record.Protocol), Port: record.Port}
		if record.TargetName != "" {
			port.TargetPort = intstr.FromString(record.TargetName)
		} else {
			port.TargetPort = intstr.FromInt32(record.TargetInt)
		}
		ports = append(ports, port)
	}
	return ports
}

// setPublicNodeLocalActivePorts records the ports of the spec as the active
// ones, or drops a stale record that no longer fits.
func setPublicNodeLocalActivePorts(copy *corev1.Service) bool {
	encoded := encodePublicNodeLocalActivePorts(copy.Spec.Ports)
	if copy.Annotations[annotationPublicNodeLocalActivePorts] == encoded {
		return false
	}
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	if encoded == "" {
		delete(copy.Annotations, annotationPublicNodeLocalActivePorts)
	} else {
		copy.Annotations[annotationPublicNodeLocalActivePorts] = encoded
	}
	return true
}

// backfillPublicNodeLocalActivePorts keeps the recorded ports equal to the spec
// of a Service in the steady state: it records a Service that was activated
// before the ports were recorded, and rewrites a record that a spec change
// (a new target port, a renamed port) left stale while the policy hash stayed.
// It only runs when the intent is the active identity, so the spec is the
// active ports.
func (c *nodeLoadBalancerController) backfillPublicNodeLocalActivePorts(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	if service.Annotations[annotationPublicNodeLocalActivePorts] == encodePublicNodeLocalActivePorts(service.Spec.Ports) {
		return service, nil
	}
	updated, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalTargetPool] != "" {
			return false, nil
		}
		return setPublicNodeLocalActivePorts(copy), nil
	})
	if err != nil {
		return service, err
	}
	return updated, nil
}

const publicNodeLocalReasonRebuildStuck = "PublicNodeLocalRebuildStuck"

// publicNodeLocalAssignedPairs lists the firewall/VM pairs that are assigned now,
// bounded to 3000 bytes (an empty string when they do not fit).
func (c *nodeLoadBalancerController) publicNodeLocalAssignedPairs(ctx context.Context, service *corev1.Service) (string, error) {
	firewalls, err := c.serviceFirewallsForEmergencyDetach(ctx, service)
	if err != nil {
		return "", err
	}
	var pairs []string
	for _, firewall := range firewalls {
		assignments, assignErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignErr != nil {
			return "", assignErr
		}
		for vmUUID := range assignments {
			pairs = append(pairs, firewall.UUID+"/"+vmUUID)
		}
	}
	sort.Strings(pairs)
	joined := strings.Join(pairs, ",")
	if len(joined) > 3000 {
		return "", nil
	}
	return joined, nil
}

// publicNodeLocalRebuildDetachReadBack reports whether a firewall detach of the
// running rebuild has already been read back: some pair that was assigned when
// the rebuild began is no longer assigned in the cloud. Until then nothing has
// been taken from the edge, so the rebuild can still be cancelled.
func (c *nodeLoadBalancerController) publicNodeLocalRebuildDetachReadBack(ctx context.Context, service *corev1.Service) (bool, error) {
	journal := strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerRebuildingAssigned])
	if journal == "" {
		// The assignments at the start were not recorded (none, or too many to
		// keep): nothing proves that no detach was read back, so do not cancel.
		return true, nil
	}
	firewalls, err := c.serviceFirewallsForEmergencyDetach(ctx, service)
	if err != nil {
		return false, err
	}
	byUUID := make(map[string]inspace.Firewall, len(firewalls))
	for _, firewall := range firewalls {
		byUUID[firewall.UUID] = firewall
	}
	for _, pair := range strings.Split(journal, ",") {
		firewallUUID, vmUUID, found := strings.Cut(pair, "/")
		if !found {
			continue
		}
		firewall, exists := byUUID[firewallUUID]
		if !exists || !firewallAssignedToVM(firewall, vmUUID) {
			return true, nil
		}
	}
	return false, nil
}

// cancelPublicNodeLocalRebuild ends a rebuild that has not taken anything from
// the edge: the marker and the detach journal go, and the Service returns to
// normal convergence. A detach that was dispatched and lands later is an
// unassigned VM of a published node, which the normal add step assigns again.
func (c *nodeLoadBalancerController) cancelPublicNodeLocalRebuild(ctx context.Context, service *corev1.Service) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerAllowRebuild] != "" {
			return false, errors.New("public-node-local: the escape hatch was set again before the rebuild was cancelled")
		}
		for _, key := range []string{
			annotationNodeLoadBalancerRebuilding,
			annotationNodeLoadBalancerRebuildingAssigned,
			annotationNodeLoadBalancerWithdrawFWDetach,
			annotationNodeLoadBalancerWithdrawFWDetachAt,
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
		} {
			delete(copy.Annotations, key)
		}
		return true, nil
	})
	return err
}
