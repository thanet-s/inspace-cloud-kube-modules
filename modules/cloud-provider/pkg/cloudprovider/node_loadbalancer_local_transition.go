package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	publicNodeLocalReasonPolicyNarrowed = "PublicNodeLocalPolicyNarrowed"
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
)

// syncPendingPublicNodeLocalTransition handles a serving Service whose pool or
// firewall policy differs from the active exposure. The intent is never applied
// by a blind withdrawal, because that would be an outage the operator did not
// ask for:
//
//   - the escape hatch annotation permits the old withdraw and rebuild;
//   - a strict narrowing of the policy (fewer ports, or source ranges that are a
//     subset) is verified intent that only removes exposure, so it is applied
//     promptly by withdrawing and rebuilding under the narrower policy;
//   - anything else (a pool change, a widening, a mix) keeps the active
//     exposure serving and keeps converging nodes under the active identity.
//     The pass holds and requeues with the hold delay until Phase B ships a
//     make-before-break transition.
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

	if strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerAllowRebuild]) == "true" {
		c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonRebuildAllowed, fmt.Errorf(
			"public-node-local: %s=true permits a withdraw and rebuild for this change: %w", annotationNodeLoadBalancerAllowRebuild, cause))
		return c.withdrawAndRequeuePublicNodeLocal(ctx, key, service)
	}

	if activePool == intent.Pool {
		narrowing, err := c.publicNodeLocalPolicyNarrows(ctx, service, activePolicy, desired)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if narrowing {
			c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonPolicyNarrowed, fmt.Errorf(
				"public-node-local: the new policy only narrows the active one, so it is applied now by rebuilding the exposure: %w", cause))
			return c.withdrawAndRequeuePublicNodeLocal(ctx, key, service)
		}
	}

	reason := publicNodeLocalReasonTransitionPending
	refusal, admitErr := c.publicNodeLocalTransitionAdmissible(ctx, service, intent)
	if admitErr != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, admitErr)
	}
	if refusal != nil {
		reason, cause = publicNodeLocalReasonTransitionRefused, refusal
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

// publicNodeLocalPolicyNarrows reports whether the desired policy is a strict
// narrowing of the policy that is serving. The serving rules are read from the
// ledger firewall in the cloud and must hash to the persisted active policy, so
// a missing or foreign firewall proves nothing and counts as not narrowing.
func (c *nodeLoadBalancerController) publicNodeLocalPolicyNarrows(
	ctx context.Context,
	service *corev1.Service,
	activePolicy string,
	desired desiredNodeLoadBalancerFirewall,
) (bool, error) {
	firewallUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	if firewallUUID == "" || service.Annotations[annotationNodeLoadBalancerFirewallHash] != activePolicy {
		return false, nil
	}
	firewall, err := c.activePublicNodeLocalFirewall(ctx, service, activePolicy)
	if err != nil {
		if inspace.IsTransient(err) {
			return false, err
		}
		// A firewall that does not prove the active policy is not evidence.
		return false, nil
	}
	return publicNodeLocalRulesNarrow(firewall.Rules, desired.Request.Rules), nil
}

// activePublicNodeLocalFirewall returns the ledger firewall of a serving
// Service and proves that its rules are the active policy.
func (c *nodeLoadBalancerController) activePublicNodeLocalFirewall(
	ctx context.Context,
	service *corev1.Service,
	activePolicy string,
) (*inspace.Firewall, error) {
	firewallUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	if firewallUUID == "" || service.Annotations[annotationNodeLoadBalancerFirewallHash] != activePolicy {
		return nil, errors.New("public-node-local: the firewall ledger does not match the active policy")
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return nil, err
	}
	for index := range owned {
		if owned[index].UUID != firewallUUID {
			continue
		}
		hash, hashErr := nodeLoadBalancerFirewallSpecHash(owned[index].Rules)
		if hashErr != nil || hash != activePolicy {
			return nil, errors.New("public-node-local: the ledger firewall rules are not the active policy")
		}
		return &owned[index], nil
	}
	return nil, fmt.Errorf("public-node-local: ledger firewall %s is not owned by the Service", firewallUUID)
}

// publicNodeLocalRulesNarrow reports whether the new rules are a strict
// narrowing of the old ones: every new rule is covered by an old rule, and at
// least one old rule is not covered by the new rules.
func publicNodeLocalRulesNarrow(old, new []inspace.FirewallRule) bool {
	if len(new) == 0 {
		return false
	}
	for _, rule := range new {
		if !publicNodeLocalRuleCoveredBy(rule, old) {
			return false
		}
	}
	for _, rule := range old {
		if !publicNodeLocalRuleCoveredBy(rule, new) {
			return true
		}
	}
	return false
}

func publicNodeLocalRuleCoveredBy(inner inspace.FirewallRule, outers []inspace.FirewallRule) bool {
	for _, outer := range outers {
		if publicNodeLocalRuleCovers(outer, inner) {
			return true
		}
	}
	return false
}

// publicNodeLocalRuleCovers reports whether everything the inner rule permits is
// also permitted by the outer rule. Anything it cannot prove is not covered.
func publicNodeLocalRuleCovers(outer, inner inspace.FirewallRule) bool {
	if !strings.EqualFold(outer.Protocol, inner.Protocol) || !strings.EqualFold(outer.Direction, inner.Direction) {
		return false
	}
	outerAllPorts := outer.PortStart == nil && outer.PortEnd == nil
	innerAllPorts := inner.PortStart == nil && inner.PortEnd == nil
	if !outerAllPorts {
		if innerAllPorts || outer.PortStart == nil || outer.PortEnd == nil || inner.PortStart == nil || inner.PortEnd == nil ||
			*inner.PortStart < *outer.PortStart || *inner.PortEnd > *outer.PortEnd {
			return false
		}
	}
	if outer.EndpointSpecType == "any" {
		return true
	}
	if outer.EndpointSpecType != "ip_prefixes" || inner.EndpointSpecType != "ip_prefixes" || len(inner.EndpointSpec) == 0 {
		return false
	}
	for _, innerValue := range inner.EndpointSpec {
		innerPrefix, err := netip.ParsePrefix(strings.TrimSpace(innerValue))
		if err != nil {
			return false
		}
		covered := false
		for _, outerValue := range outer.EndpointSpec {
			outerPrefix, outerErr := netip.ParsePrefix(strings.TrimSpace(outerValue))
			if outerErr == nil && outerPrefix.Bits() <= innerPrefix.Bits() && outerPrefix.Contains(innerPrefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
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
