package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

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
	if refusal == nil && service.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" &&
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

// holdPendingPublicNodeLocalTransition holds a transition that cannot move on
// yet, with the Pending Event and the backoff of an unchanged hold.
func (c *nodeLoadBalancerController) holdPendingPublicNodeLocalTransition(ctx context.Context, service *corev1.Service, cause error) error {
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
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerAllowRebuild] != raw ||
			copy.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] != consumed {
			return false, errors.New("public-node-local: the escape hatch changed before it was consumed")
		}
		copy.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] = raw
		copy.Annotations[annotationNodeLoadBalancerRebuilding] = raw
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
	current, previous *inspace.Firewall,
	currentAssigned map[string]struct{},
	keep map[string]struct{},
	members map[string]publicNodeLocalMember,
) (bool, error) {
	if service.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		return false, nil
	}
	if previous != nil {
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
		stale, err := staleNodeLoadBalancerFirewallAssignments(*previous, stay)
		if err != nil {
			return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if len(stale) != 0 {
			parked, err := c.detachServiceFirewallFromOtherNodesParked(ctx, service, previous, stayNodes)
			if err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			if len(publicNodeLocalWithout(stale, parked)) == 0 {
				// Only parked relations are left: they are retried when the park
				// ends, and must not stop the pass meanwhile.
				return false, nil
			}
			c.requeuePublicNodeLocal(key)
			return true, nil
		}
		if len(stay) != 0 {
			// Kept nodes without the current firewall: the old one stays on them.
			return false, nil
		}
	}
	if err := c.cleanupPreviousFirewall(ctx, service); err != nil {
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
	case service.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "":
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
			copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" ||
			publicNodeLocalAssignmentFencePresent(copy) {
			return false, errors.Join(errors.New("public-node-local: the Service changed before the transition could start"), parseErr, desiredErr)
		}
		copy.Annotations[annotationPublicNodeLocalTargetPool] = intent.Pool
		copy.Annotations[annotationPublicNodeLocalTargetPolicy] = desired.Hash
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
		if copy.Annotations[annotationPublicNodeLocalTargetPool] != targetPool ||
			copy.Annotations[annotationPublicNodeLocalTargetPolicy] != targetPolicy ||
			copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != targetPolicy ||
			publicNodeLocalAssignmentFencePresent(copy) {
			return false, errors.New("public-node-local: the transition changed before promotion")
		}
		copy.Annotations[annotationPublicNodeLocalActivePool] = targetPool
		copy.Annotations[annotationPublicNodeLocalActivePolicy] = targetPolicy
		delete(copy.Annotations, annotationPublicNodeLocalTargetPool)
		delete(copy.Annotations, annotationPublicNodeLocalTargetPolicy)
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
	if ledgerPolicy != state.ActivePolicy {
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
		if restore != nil {
			// The assignment intent named the target firewall, which is retired now.
			// Nothing is assigned under it any more; a stale receipt is resolved by
			// the relation fence as usual.
			for _, fenceKey := range []string{
				annotationNodeLoadBalancerFirewallAssigning,
				annotationNodeLoadBalancerFirewallAssignAt,
				annotationPublicNodeLocalAssignPolicy,
				annotationPublicNodeLocalAssignVMs,
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
			child.Spec.Ports = append(child.Spec.Ports, corev1.ServicePort{
				Name: fmt.Sprintf("t-%s-%d", strings.ToLower(string(protocol)), *rule.PortStart), Protocol: protocol,
				Port: *rule.PortStart, TargetPort: intstr.FromInt32(*rule.PortStart),
			})
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
