package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudv1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	publicNodeLocalFinalizer = "service.inspace.cloud/public-node-local"

	annotationPublicNodeLocalActivePool   = "service.inspace.cloud/public-node-local-active-pool"
	annotationPublicNodeLocalActivePolicy = "service.inspace.cloud/public-node-local-active-policy"
	annotationPublicNodeLocalDatapathPool = "service.inspace.cloud/public-node-local-pool"
	annotationPublicNodeLocalConflict     = "service.inspace.cloud/public-node-local-conflict"
	annotationPublicNodeLocalAssignPolicy = "service.inspace.cloud/public-node-local-assigning-policy"
	annotationPublicNodeLocalAssignVMs    = "service.inspace.cloud/public-node-local-assigning-vms"

	publicNodeLocalFirewallProfile = "public-node-local"
)

type publicNodeLocalVMOwnership struct {
	Schema           string `json:"schema"`
	Cluster          string `json:"cluster"`
	NodePool         string `json:"nodePool"`
	NodeClaim        string `json:"nodeClaim"`
	VMName           string `json:"vmName"`
	FirewallProfile  string `json:"firewallProfile"`
	FirewallUUID     string `json:"firewallUUID"`
	NetworkUUID      string `json:"networkUUID"`
	BillingAccountID int64  `json:"billingAccountID"`
	FloatingIPName   string `json:"floatingIPName"`
	PublicIPv4       string `json:"publicIPv4"`
}

func publicNodeLocalRequested(service *corev1.Service) bool {
	return isNodeLoadBalancerService(service) &&
		strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerMode]) == nodeLoadBalancerModeLocal
}

func (c *nodeLoadBalancerController) syncPublicNodeLocal(
	ctx context.Context,
	key string,
	service *corev1.Service,
) error {
	err := c.syncPublicNodeLocalPass(ctx, key, service)
	var holding *errPublicNodeLocalHolding
	if service != nil && !errors.As(err, &holding) {
		// Only an unchanged hold backs off. Progress, or any other outcome, resets it.
		c.resetPublicNodeLocalHold(string(service.UID))
	}
	return err
}

func (c *nodeLoadBalancerController) syncPublicNodeLocalPass(
	ctx context.Context,
	key string,
	service *corev1.Service,
) error {
	if service == nil {
		return errors.New("public-node-local: Service is required")
	}
	if service.DeletionTimestamp != nil || !publicNodeLocalRequested(service) {
		if containsString(service.Finalizers, publicNodeLocalFinalizer) {
			return c.cleanupPublicNodeLocal(ctx, key, service)
		}
		return nil
	}

	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	intent, err := parseNodeLoadBalancerService(service, defaults)
	if err != nil || intent.Mode != nodeLoadBalancerModeLocal {
		cause := err
		if cause == nil {
			cause = errors.New("public-node-local: parsed Service mode is not public-node-local")
		}
		eventErr := c.recordNodeLoadBalancerReservedPortEvent(ctx, service, cause)
		if containsString(service.Finalizers, publicNodeLocalFinalizer) {
			return errors.Join(c.holdOrFailPublicNodeLocal(ctx, service, cause), eventErr)
		}
		return errors.Join(cause, eventErr)
	}
	if !containsString(service.Finalizers, publicNodeLocalFinalizer) {
		patched, err := c.ensurePublicNodeLocalFinalizer(ctx, service)
		if err != nil || patched {
			return err
		}
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}

	desiredFirewall, err := c.desiredServiceFirewall(service)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	activePool := service.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := service.Annotations[annotationPublicNodeLocalActivePolicy]
	if (activePool == "") != (activePolicy == "") {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: incomplete persisted activation identity"))
	}
	if activePool == "" && len(service.Status.LoadBalancer.Ingress) != 0 {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: public status exists without persisted activation authorization"))
	}
	if cleared, clearErr := c.clearPublicNodeLocalRebuildConsumed(ctx, service); clearErr != nil || cleared {
		if cleared {
			c.requeuePublicNodeLocal(key)
		}
		return clearErr
	}
	if activePool != "" && service.Annotations[annotationNodeLoadBalancerRebuilding] != "" {
		// A rebuild the operator asked for has begun. It is finished as a rebuild:
		// the marker goes away with the activation when the withdrawal is complete.
		// Starting a transition on top of a half-done withdrawal would leave its
		// detach journal and unassign receipt behind a half-closed edge.
		if strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerAllowRebuild]) == "" {
			// The operator took the escape hatch away. Before any detach has been
			// read back nothing was taken from the edge, so the rebuild is cancelled.
			readBack, readErr := c.publicNodeLocalRebuildDetachReadBack(ctx, service)
			if readErr != nil {
				return c.holdOrFailPublicNodeLocal(ctx, service, readErr)
			}
			if !readBack {
				if err := c.cancelPublicNodeLocalRebuild(ctx, service); err != nil {
					return c.holdOrFailPublicNodeLocal(ctx, service, err)
				}
				c.requeuePublicNodeLocal(key)
				return nil
			}
			c.recordPublicNodeLocalEvent(ctx, service, publicNodeLocalReasonRebuildStuck, errors.New(
				"public-node-local: the rebuild cannot be cancelled by removing "+annotationNodeLoadBalancerAllowRebuild+
					" because a firewall detach was already read back, so the withdrawal goes on. To recover, make the blocked detach possible"+
					" (a VM of another billing account or VPC, or a parked firewall relation, blocks the readback; see the runbook in the chart README),"+
					" or delete and recreate the Service"))
		}
		return c.withdrawAndRequeuePublicNodeLocal(ctx, key, service)
	}
	if activePool != "" && activePool == intent.Pool && activePolicy == desiredFirewall.Hash &&
		service.Annotations[annotationPublicNodeLocalTargetPool] == "" {
		// The pass goes on with the updated Service: recording the ports is not a
		// change of the edge.
		recorded, backfillErr := c.backfillPublicNodeLocalActivePorts(ctx, service)
		if backfillErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, backfillErr)
		}
		service = recorded
	}
	if activePool != "" {
		state, stateErr := publicNodeLocalTransition(service)
		if stateErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, stateErr)
		}
		if state.Phase == publicNodeLocalPhaseUnion {
			if intent.Pool == state.TargetPool && desiredFirewall.Hash == state.TargetPolicy {
				return c.convergeActivePublicNodeLocal(ctx, key, service, intent, desiredFirewall, publicNodeLocalPassUnion)
			}
			// The intent moved away from the target: back to the active identity,
			// or on to a third one. Either way the union ends first.
			return c.abortPublicNodeLocalTransition(ctx, key, service, fmt.Errorf(
				"the Service intent (pool %q, firewall policy %q) is no longer the target", intent.Pool, desiredFirewall.Hash))
		}
	}
	if activePool != "" && (activePool != intent.Pool || activePolicy != desiredFirewall.Hash) {
		return c.syncPendingPublicNodeLocalTransition(ctx, key, service, intent, desiredFirewall)
	}

	if activePool != "" {
		return c.convergeActivePublicNodeLocal(ctx, key, service, intent, desiredFirewall, publicNodeLocalPassNormal)
	}
	// Everything below is the bootstrap of a Service that is not serving yet.

	addresses, patchedNode, err := c.publicNodeLocalAddresses(ctx, service, intent)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, service, intent)
	if loses {
		cause := conflictErr
		if cause == nil {
			cause = fmt.Errorf("public-node-local: Service %s/%s lost a deterministic protocol/port claim in pool %s", service.Namespace, service.Name, intent.Pool)
		}
		return errors.Join(c.recordPublicNodeLocalConflictEvent(ctx, service, cause), c.failPublicNodeLocalClosed(ctx, service, cause))
	}
	if conflictErr != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, conflictErr)
	}
	if cleared, err := c.clearPublicNodeLocalConflict(ctx, service); err != nil || cleared {
		if cleared {
			c.requeuePublicNodeLocal(key)
		}
		return err
	}
	if winnerWaiting {
		// A serving Service never reaches the bootstrap, so it keeps its own claim
		// in convergeActivePublicNodeLocal. Here nothing is serving yet.
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	desiredPublicStatus := nodeLoadBalancerStatus(append([]nodeLoadBalancerAddress(nil), addresses...), true)
	if len(service.Status.LoadBalancer.Ingress) != 0 && !reflect.DeepEqual(service.Status.LoadBalancer, desiredPublicStatus) {
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	datapath, changed, err := c.ensurePublicNodeLocalDatapath(ctx, service, intent.Pool)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if changed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	selectedNodes := make([]*corev1.Node, 0, len(addresses))
	for _, address := range addresses {
		selectedNodes = append(selectedNodes, address.Node)
	}
	desiredPrivateStatus := nodeLoadBalancerStatus(append([]nodeLoadBalancerAddress(nil), addresses...), false)
	if len(selectedNodes) == 0 || publicNodeLocalStatusRemovesAddress(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		// A removed private frontend must never precede closure of its public
		// firewall edge. Withdraw all assignments and prove the readback first;
		// a later reconciliation rebuilds the retained/additional frontends.
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		if len(selectedNodes) != 0 || patchedNode {
			c.requeuePublicNodeLocal(key)
		}
		return nil
	}
	edge := c.publicNodeLocalEdgeFor(service)
	var current edgeID
	var waiting bool
	service, current, _, waiting, err = edge.Prepare(ctx, service, desiredFirewall)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if waiting {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if activePool == "" && !reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		// Recovery and first bootstrap both prove the Service firewall fully
		// detached before reactivating the private Cilium frontend. This
		// closes the stale-assignment window after an uncertain cloud read.
		if _, err := edge.Unassign(ctx, service, current, nil); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
	}
	datapath, changed, err = c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, intent.Pool, desiredPrivateStatus)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if changed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if !reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: private datapath status did not read back exactly"))
	}

	if _, err := edge.Unassign(ctx, service, current, selectedNodes); err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}

	assignmentsMatch, err := c.publicNodeLocalFirewallAssignmentsMatch(ctx, service, intent, desiredFirewall, current, selectedNodes)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if !assignmentsMatch {
		authorized, _, err := c.ensurePublicNodeLocalAssignmentIntent(ctx, service, intent, desiredFirewall, current, addresses)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		service = authorized
		// A fresh exact fence may have been persisted by a previous process that
		// crashed before (or midway through) the cloud assignment. Always resume
		// the idempotent missing assignments after the helper has validated that
		// durable authorization; the cloud mutation validates it again per VM.
		if _, err := edge.Assign(ctx, service, intent, desiredFirewall, current, addresses); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	assignmentsMatch, err = c.publicNodeLocalFirewallAssignmentsMatch(ctx, service, intent, desiredFirewall, current, selectedNodes)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if !assignmentsMatch {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: firewall assignments changed after exact readback"))
	}
	assignmentFencePresent := publicNodeLocalAssignmentFencePresent(service)
	if assignmentFencePresent && service.Annotations[annotationNodeLoadBalancerFirewallAssigning] == "" {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: incomplete durable assignment authorization cannot be adopted"))
	}
	if !assignmentFencePresent {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: inactive or unpublished firewall assignment has no durable authorization fence"))
	}
	if service.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" && len(service.Status.LoadBalancer.Ingress) == 0 {
		if cleared, clearErr := c.clearPublicNodeLocalWithdrawalEvidenceAfterAssignment(ctx, service, intent, desiredFirewall, current, addresses); clearErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, clearErr)
		} else if cleared {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}

	validated, err := c.validatePublicNodeLocalPublicationState(ctx, service, intent, desiredFirewall, current, addresses, activePool != "", false)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	service = validated
	if activePool == "" {
		patched, err := c.ensurePublicNodeLocalActivation(ctx, service, intent.Pool, desiredFirewall.Hash)
		if err != nil || patched {
			if patched {
				c.requeuePublicNodeLocal(key)
			}
			return err
		}
	}
	validated, err = c.validatePublicNodeLocalPublicationState(ctx, service, intent, desiredFirewall, current, addresses, true, false)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	service = validated
	published, _, err := c.updatePublicNodeLocalStatusBound(ctx, service, desiredPublicStatus)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	updated, err := c.validatePublicNodeLocalPublicationState(ctx, published, intent, desiredFirewall, current, addresses, true, true)
	if err != nil {
		// A failed gate returns no Service; withdraw through the pre-gate one.
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if updated.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" {
		cleared, wasCleared, err := c.clearPublicNodeLocalAssignmentIntent(ctx, updated, intent, desiredFirewall, current, addresses)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, updated, err)
		}
		if wasCleared {
			if _, err := c.validatePublicNodeLocalPublicationState(ctx, cleared, intent, desiredFirewall, current, addresses, true, true); err != nil {
				return c.holdOrFailPublicNodeLocal(ctx, updated, err)
			}
		}
	}
	if patchedNode {
		c.requeuePublicNodeLocal(key)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalFinalizer(ctx context.Context, service *corev1.Service) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !publicNodeLocalRequested(copy) || containsString(copy.Finalizers, nodeLoadBalancerFinalizer) {
			return false, errors.New("public-node-local: Service changed before finalizer persistence")
		}
		intent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		if parseErr != nil || intent.Mode != nodeLoadBalancerModeLocal {
			return false, joinWithExplanation(errors.New("public-node-local: invalid Service intent before finalizer persistence"), parseErr)
		}
		if containsString(copy.Finalizers, publicNodeLocalFinalizer) {
			return false, nil
		}
		copy.Finalizers = append(copy.Finalizers, publicNodeLocalFinalizer)
		return true, nil
	})
	return changed, err
}

// preparePublicNodeLocalFirewall returns the firewall of the current policy
// and, while a policy change is in flight, the previous one. Two owned
// firewalls are expected exactly when the ledger names a previous one.
func (c *nodeLoadBalancerController) preparePublicNodeLocalFirewall(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, *inspace.Firewall, *inspace.Firewall, bool, error) {
	firewall, previousUUID, _, err := c.ensureServiceFirewall(ctx, service, nil)
	if err != nil {
		return service, nil, nil, false, err
	}
	if firewall == nil {
		return service, nil, nil, true, nil
	}
	if patched, err := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); err != nil || patched {
		return service, nil, nil, patched, err
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return service, nil, nil, false, err
	}
	if err := c.cleanupPreviousFirewall(ctx, service); err != nil {
		return service, nil, nil, false, err
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return service, nil, nil, false, err
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return service, nil, nil, false, err
	}
	var current, previous *inspace.Firewall
	previousAnnotation := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	for index := range owned {
		switch {
		case owned[index].UUID == firewall.UUID:
			current = &owned[index]
		case previousAnnotation != "" && owned[index].UUID == previousAnnotation:
			previous = &owned[index]
		default:
			return service, nil, nil, true, nil
		}
	}
	if current == nil {
		return service, nil, nil, true, nil
	}
	return service, current, previous, false, nil
}

// desiredPublicNodeLocalDatapathFor is the child a Service wants, given the
// child that exists. While a policy transition runs, or its old firewall is
// still being detached, the child keeps the ports and source ranges it already
// serves next to the new ones, so no port closes before the firewall that
// guards it is gone.
func desiredPublicNodeLocalDatapathFor(service *corev1.Service, pool string, existing *corev1.Service) *corev1.Service {
	desired := desiredPublicNodeLocalDatapath(service, pool)
	if target := service.Annotations[annotationPublicNodeLocalTargetPool]; target != "" {
		desired.Annotations[annotationPublicNodeLocalDatapathTargetPool] = target
	}
	if existing == nil || !publicNodeLocalUnionWanted(service) {
		return desired
	}
	return mergePublicNodeLocalDatapathUnion(desired, existing)
}

// publicNodeLocalUnionWanted says whether the child must keep serving what the
// old firewall still allows: from the start of a policy transition until the
// old firewall is gone.
func publicNodeLocalUnionWanted(service *corev1.Service) bool {
	return service.Annotations[annotationPublicNodeLocalTargetPolicy] != "" ||
		service.Annotations[annotationNodeLoadBalancerPreviousFirewall] != ""
}

// mergePublicNodeLocalDatapathUnion adds the ports and source ranges of the
// existing child to the desired one. For a port both have, the desired one
// wins; the existing position and name are kept.
func mergePublicNodeLocalDatapathUnion(desired, existing *corev1.Service) *corev1.Service {
	type portKey struct {
		protocol corev1.Protocol
		port     int32
	}
	keyOf := func(port corev1.ServicePort) portKey {
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		return portKey{protocol: protocol, port: port.Port}
	}
	wanted := make(map[portKey]corev1.ServicePort, len(desired.Spec.Ports))
	for _, port := range desired.Spec.Ports {
		wanted[keyOf(port)] = port
	}
	names := map[string]struct{}{}
	merged := make([]corev1.ServicePort, 0, len(existing.Spec.Ports)+len(desired.Spec.Ports))
	for _, port := range existing.Spec.Ports {
		if replacement, found := wanted[keyOf(port)]; found {
			port = replacement
			delete(wanted, keyOf(port))
		}
		names[port.Name] = struct{}{}
		merged = append(merged, port)
	}
	for _, port := range desired.Spec.Ports {
		if _, pending := wanted[keyOf(port)]; !pending {
			continue
		}
		if _, taken := names[port.Name]; taken {
			port.Name = fmt.Sprintf("t-%s-%d", strings.ToLower(string(keyOf(port).protocol)), port.Port)
		}
		names[port.Name] = struct{}{}
		merged = append(merged, port)
	}
	desired.Spec.Ports = merged
	// An empty list means any source, which is the widest. During the union the
	// child therefore admits the widest of the old and the new source ranges. The
	// per-Service VM firewall is the gate for traffic from outside the VPC, but
	// sources inside the VPC are admitted by the base node firewall and only
	// Cilium filters them by these ranges, so for the length of the union an
	// in-VPC source that the new policy excludes (a narrowing) can still reach the
	// frontends, and one that the new policy admits (a widening) is already
	// admitted by the child while the VM firewall still blocks it from outside.
	// The window ends when the old firewall is gone and the child is trimmed.
	if len(existing.Spec.LoadBalancerSourceRanges) == 0 || len(desired.Spec.LoadBalancerSourceRanges) == 0 {
		desired.Spec.LoadBalancerSourceRanges = nil
	} else {
		seen := map[string]struct{}{}
		union := make([]string, 0)
		for _, list := range [][]string{existing.Spec.LoadBalancerSourceRanges, desired.Spec.LoadBalancerSourceRanges} {
			for _, value := range list {
				if _, dup := seen[value]; !dup {
					seen[value] = struct{}{}
					union = append(union, value)
				}
			}
		}
		sort.Strings(union)
		desired.Spec.LoadBalancerSourceRanges = union
	}
	return desired
}

func desiredPublicNodeLocalDatapath(service *corev1.Service, pool string) *corev1.Service {
	name := nodeLoadBalancerDatapathName(service)
	class := nodeLoadBalancerDatapathClass
	allocateNodePorts := false
	controller := true
	blockOwnerDeletion := true
	ports := append([]corev1.ServicePort(nil), service.Spec.Ports...)
	for index := range ports {
		ports[index].NodePort = 0
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: service.Namespace,
			Name:      name,
			Labels: map[string]string{
				nodeLoadBalancerDatapathLabel:        "true",
				nodeLoadBalancerServiceIdentityLabel: nodeLoadBalancerServiceIdentity(service),
			},
			Annotations: map[string]string{annotationPublicNodeLocalDatapathPool: pool},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass:             &class,
			AllocateLoadBalancerNodePorts: &allocateNodePorts,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyLocal,
			Selector:                      copyStringMap(service.Spec.Selector),
			Ports:                         ports,
			SessionAffinity:               service.Spec.SessionAffinity,
			SessionAffinityConfig:         service.Spec.SessionAffinityConfig.DeepCopy(),
			PublishNotReadyAddresses:      false,
			LoadBalancerSourceRanges:      append([]string(nil), service.Spec.LoadBalancerSourceRanges...),
			IPFamilyPolicy:                service.Spec.IPFamilyPolicy,
			IPFamilies:                    append([]corev1.IPFamily(nil), service.Spec.IPFamilies...),
			InternalTrafficPolicy:         service.Spec.InternalTrafficPolicy,
			TrafficDistribution:           service.Spec.TrafficDistribution,
		},
	}
}

func publicNodeLocalDatapathMatches(datapath, service *corev1.Service, pool string) bool {
	if datapath == nil || service == nil || datapath.DeletionTimestamp != nil ||
		!nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return false
	}
	desired := normalizedDesiredPublicNodeLocalDatapath(desiredPublicNodeLocalDatapathFor(service, pool, datapath), datapath)
	return reflect.DeepEqual(datapath.Labels, desired.Labels) &&
		reflect.DeepEqual(datapath.Annotations, desired.Annotations) &&
		reflect.DeepEqual(datapath.OwnerReferences, desired.OwnerReferences) &&
		reflect.DeepEqual(datapath.Spec, desired.Spec)
}

func normalizedDesiredPublicNodeLocalDatapath(desired, existing *corev1.Service) *corev1.Service {
	normalized := normalizedDesiredNodeLoadBalancerDatapath(desired, existing)
	if normalized != nil && existing != nil {
		// The apiserver allocates this even when Service NodePorts are disabled
		// because externalTrafficPolicy=Local needs a health-check frontend.
		normalized.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
	}
	return normalized
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalDatapath(
	ctx context.Context,
	service *corev1.Service,
	pool string,
) (*corev1.Service, bool, error) {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	name := nodeLoadBalancerDatapathName(service)
	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, fmt.Errorf("public-node-local: get private datapath Service: %w", err)
	}
	base := existing
	if apierrors.IsNotFound(err) && publicNodeLocalUnionWanted(service) {
		// A child lost during a transition comes back with the ports the old
		// firewall still allows, not only the target ones.
		rebuilt, rebuildErr := c.publicNodeLocalChildFromActiveFirewall(ctx, service)
		if rebuildErr != nil {
			return nil, false, rebuildErr
		}
		if rebuilt != nil {
			base = rebuilt
		}
	}
	desired := desiredPublicNodeLocalDatapathFor(service, pool, base)
	// The child only carries the private VIPs for Cilium; the public gate is the
	// firewall on the VM. Repairing the child therefore never needs the parent
	// to be withdrawn, and the status subresource survives a spec update.
	if apierrors.IsNotFound(err) {
		created, createErr := client.Create(ctx, desired, metav1.CreateOptions{})
		return created, createErr == nil, createErr
	}
	if !nodeLoadBalancerDatapathOwnedByService(existing, service) {
		return nil, false, fmt.Errorf("public-node-local: datapath Service %s/%s has foreign ownership", service.Namespace, name)
	}
	if existing.DeletionTimestamp != nil {
		return existing, true, nil
	}
	if existing.Spec.LoadBalancerClass == nil || *existing.Spec.LoadBalancerClass != nodeLoadBalancerDatapathClass {
		if err := deleteServiceWithUIDPrecondition(ctx, client, existing); err != nil && !apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("public-node-local: replace exact-owned datapath with immutable class drift: %w", err)
		}
		if eventErr := c.recordPublicNodeLocalHoldEvent(ctx, service, "PublicNodeLocalDatapathReplaced", fmt.Errorf(
			"public-node-local: replaced private datapath Service %s/%s that drifted to another load balancer class", service.Namespace, name)); eventErr != nil {
			klog.Warningf("public-node-local %s/%s: record Event: %v", service.Namespace, service.Name, eventErr)
		}
		return nil, true, nil
	}
	desired = normalizedDesiredPublicNodeLocalDatapath(desired, existing)
	if publicNodeLocalDatapathMatches(existing, service, pool) {
		return existing, false, nil
	}
	desired.Status = *existing.Status.DeepCopy()
	updated, updateErr := client.Update(ctx, desired, metav1.UpdateOptions{})
	return updated, updateErr == nil, updateErr
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalDatapathStatus(
	ctx context.Context,
	service, datapath *corev1.Service,
	pool string,
	status corev1.LoadBalancerStatus,
) (*corev1.Service, bool, error) {
	if !publicNodeLocalDatapathMatches(datapath, service, pool) {
		return nil, false, errors.New("public-node-local: refuse status publication to a drifted private datapath")
	}
	if reflect.DeepEqual(datapath.Status.LoadBalancer, status) {
		return datapath, false, nil
	}
	copy := datapath.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("public-node-local: publish private datapath status: %w", err)
	}
	if updated.UID != datapath.UID || !publicNodeLocalDatapathMatches(updated, service, pool) {
		return nil, false, errors.New("public-node-local: private datapath identity changed during status publication")
	}
	return updated, true, nil
}

// publicNodeLocalNodeKind is what one pass could prove about one Node. The
// zero value proves nothing, so a missing verdict can never remove exposure.
type publicNodeLocalNodeKind int

const (
	publicNodeLocalNodeUnverified publicNodeLocalNodeKind = iota
	publicNodeLocalNodeAuthorized
	// Gone means the Node, its VM or its pool membership is verifiably gone.
	publicNodeLocalNodeGone
	// NotEligible means the Node does not qualify now, but nothing proves it gone.
	publicNodeLocalNodeNotEligible
)

type publicNodeLocalNodeVerdict struct {
	kind   publicNodeLocalNodeKind
	reason string
	// nodeObject marks a Gone verdict that rests on the Node object itself (its
	// labels), not only on a cloud answer.
	nodeObject bool
	// foreign marks a Gone verdict for a VM of another billing account or VPC.
	// The relation fence never touches such a VM.
	foreign bool
}

func publicNodeLocalNodeIs(kind publicNodeLocalNodeKind, reason string) publicNodeLocalNodeVerdict {
	return publicNodeLocalNodeVerdict{kind: kind, reason: reason}
}

// publicNodeLocalNodeSet sorts the cluster's Nodes by what is proven about
// them. Ready Nodes may be published. Gone Nodes (keyed by Node name, or by
// published IP when the Node object is absent) may be removed. Every other
// class keeps what is already published and never gains a new publication.
type publicNodeLocalNodeSet struct {
	Ready           []nodeLoadBalancerAddress
	Gone            map[string]string
	Unverified      map[string]error
	EndpointMissing map[string]nodeLoadBalancerAddress
	NotEligible     map[string]string
	// NodeEvidence names the Gone entries that rest on the Node object itself
	// (deleted, excluded, left the pool, absent), not only on a cloud answer.
	NodeEvidence map[string]struct{}
	// Foreign names the Gone Nodes whose VM belongs to another billing account or
	// VPC. The relation fence refuses to detach a firewall from such a VM.
	Foreign map[string]struct{}
	// Nodes holds every listed Node by name, so callers can resolve identities.
	Nodes map[string]*corev1.Node
	// PoolOf names the pool that authorized each Ready Node. During a union it
	// tells the active pool's Nodes from the target pool's.
	PoolOf map[string]string
}

// publicNodeLocalAddresses returns the Nodes that may be published. It stops
// at the first Node that cannot be verified, which keeps the bootstrap path
// and the publication gates strict.
func (c *nodeLoadBalancerController) publicNodeLocalAddresses(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) ([]nodeLoadBalancerAddress, bool, error) {
	set, patchedNode, unverifiedErr, err := c.classifyPublicNodeLocalNodesMode(ctx, service, intent, true, true)
	if err != nil {
		return nil, patchedNode, err
	}
	if unverifiedErr != nil {
		return nil, patchedNode, unverifiedErr
	}
	return set.Ready, patchedNode, nil
}

// classifyPublicNodeLocalNodes classifies every Node without stopping at the
// first one that cannot be verified. It returns an error only when the Node
// list, the EndpointSlice lister, the published child Service or the Node
// addresses cannot give a consistent answer.
func (c *nodeLoadBalancerController) classifyPublicNodeLocalNodes(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) (publicNodeLocalNodeSet, bool, error) {
	return c.classifyPublicNodeLocalNodesChild(ctx, service, intent, true)
}

// classifyPublicNodeLocalNodesChild is classifyPublicNodeLocalNodes for a pass
// that may run while the Service spec describes a pending policy. With childStrict
// false, the child must be exact-owned but its spec is not compared with the
// Service spec, since the spec no longer describes it.
func (c *nodeLoadBalancerController) classifyPublicNodeLocalNodesChild(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	childStrict bool,
) (publicNodeLocalNodeSet, bool, error) {
	set, patched, _, err := c.classifyPublicNodeLocalNodesMode(ctx, service, intent, false, childStrict)
	return set, patched, err
}

// publicNodeLocalChildPool is the pool the child datapath is recorded under.
// It follows the persisted activation, not the pool of the pending intent.
func publicNodeLocalChildPool(service *corev1.Service, fallback string) string {
	if active := service.Annotations[annotationPublicNodeLocalActivePool]; active != "" {
		return active
	}
	return fallback
}

func (c *nodeLoadBalancerController) classifyPublicNodeLocalNodesMode(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	failFast, childStrict bool,
) (publicNodeLocalNodeSet, bool, error, error) {
	return c.classifyPublicNodeLocalNodesPools(ctx, service, []string{intent.Pool}, publicNodeLocalChildPool(service, intent.Pool), failFast, childStrict)
}

// classifyPublicNodeLocalNodesPools classifies every Node against a set of
// pools. A Node that one of the pools authorizes is Ready for that pool; it is
// Gone only when every pool says so.
func (c *nodeLoadBalancerController) classifyPublicNodeLocalNodesPools(
	ctx context.Context,
	service *corev1.Service,
	pools []string,
	childPool string,
	failFast, childStrict bool,
) (publicNodeLocalNodeSet, bool, error, error) {
	set := publicNodeLocalNodeSet{
		PoolOf:          map[string]string{},
		Gone:            map[string]string{},
		Unverified:      map[string]error{},
		EndpointMissing: map[string]nodeLoadBalancerAddress{},
		NotEligible:     map[string]string{},
		NodeEvidence:    map[string]struct{}{},
		Foreign:         map[string]struct{}{},
		Nodes:           map[string]*corev1.Node{},
	}
	readyEndpoints, err := c.publicNodeLocalReadyEndpointNodes(service)
	if err != nil {
		return set, false, nil, err
	}
	nodeList, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return set, false, nil, fmt.Errorf("public-node-local: list live Nodes: %w", err)
	}
	seenPrivate := map[string]string{}
	seenPublic := map[string]string{}
	knownPrivate := map[string]struct{}{}
	knownPublic := map[string]struct{}{}
	patchedNode := false
	for index := range nodeList.Items {
		node := &nodeList.Items[index]
		set.Nodes[node.Name] = node
		if ip, ok := nodeLoadBalancerNodeInternalIPv4(node); ok {
			knownPrivate[ip] = struct{}{}
		}
		if ip, ok := nodeLoadBalancerNodeExternalIPv4(node); ok {
			knownPublic[ip] = struct{}{}
		}
		if !node.DeletionTimestamp.IsZero() {
			set.Gone[node.Name] = "the Node is being deleted"
			set.NodeEvidence[node.Name] = struct{}{}
			continue
		}
		if nodeExcludedFromLoadBalancers(node) || nodeHasControlPlaneRole(node) {
			// Both are explicit operator intent, so the Node leaves the edge.
			set.Gone[node.Name] = "the Node is excluded from external load balancers or is a control-plane Node"
			set.NodeEvidence[node.Name] = struct{}{}
			continue
		}
		if !loadBalancerNodeEligible(node) {
			set.NotEligible[node.Name] = "the Node is not Ready or is being disrupted"
			continue
		}
		verdict, authorizedPool, patched, authErr := c.authorizePublicNodeLocalNodeAcrossPools(ctx, node, pools, service)
		patchedNode = patchedNode || patched
		if failFast && authErr != nil {
			return set, patchedNode, authErr, nil
		}
		switch verdict.kind {
		case publicNodeLocalNodeGone:
			set.Gone[node.Name] = verdict.reason
			if verdict.nodeObject {
				set.NodeEvidence[node.Name] = struct{}{}
			}
			if verdict.foreign {
				set.Foreign[node.Name] = struct{}{}
			}
			continue
		case publicNodeLocalNodeNotEligible:
			set.NotEligible[node.Name] = verdict.reason
			continue
		case publicNodeLocalNodeAuthorized:
		default:
			if authErr == nil {
				authErr = fmt.Errorf("public-node-local: Node %s could not be verified", node.Name)
			}
			set.Unverified[node.Name] = authErr
			continue
		}
		if _, serves := readyEndpoints[node.Name]; !serves {
			// No metadata lookup is needed: this Node is only kept or removed,
			// never published, so its own addresses are enough to match status.
			missing := nodeLoadBalancerAddress{Node: node.DeepCopy()}
			missing.PrivateIPv4, _ = nodeLoadBalancerNodeInternalIPv4(node)
			missing.PublicIPv4, _ = nodeLoadBalancerNodeExternalIPv4(node)
			set.EndpointMissing[node.Name] = missing
			continue
		}
		address, err := c.publicNodeLocalAddress(ctx, node)
		if err != nil {
			if failFast {
				return set, patchedNode, err, nil
			}
			set.Unverified[node.Name] = err
			continue
		}
		if other := seenPrivate[address.PrivateIPv4]; other != "" {
			return set, patchedNode, nil, fmt.Errorf("public-node-local: Nodes %s and %s share private IPv4 %s", other, node.Name, address.PrivateIPv4)
		}
		if other := seenPublic[address.PublicIPv4]; other != "" {
			return set, patchedNode, nil, fmt.Errorf("public-node-local: Nodes %s and %s share public IPv4 %s", other, node.Name, address.PublicIPv4)
		}
		seenPrivate[address.PrivateIPv4] = node.Name
		seenPublic[address.PublicIPv4] = node.Name
		set.PoolOf[node.Name] = authorizedPool
		set.Ready = append(set.Ready, address)
	}
	sort.Slice(set.Ready, func(i, j int) bool {
		left := netip.MustParseAddr(set.Ready[i].PublicIPv4)
		right := netip.MustParseAddr(set.Ready[j].PublicIPv4)
		if comparison := left.Compare(right); comparison != 0 {
			return comparison < 0
		}
		return set.Ready[i].Node.Name < set.Ready[j].Node.Name
	})
	if failFast {
		return set, patchedNode, nil, nil
	}
	// A published entry that matches no Node object at all belongs to a Node
	// that has been removed from the cluster.
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err != nil && !apierrors.IsNotFound(err) {
		return set, patchedNode, nil, fmt.Errorf("public-node-local: read published private datapath: %w", err)
	}
	if err == nil {
		if childStrict && !publicNodeLocalDatapathMatches(datapath, service, childPool) {
			return set, patchedNode, nil, errors.New("public-node-local: private datapath spec drifted; its published VIPs cannot be trusted")
		}
		if !childStrict && !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
			return set, patchedNode, nil, errors.New("public-node-local: private datapath has foreign ownership; its published VIPs cannot be trusted")
		}
		for _, ingress := range datapath.Status.LoadBalancer.Ingress {
			if _, known := knownPrivate[ingress.IP]; !known {
				set.Gone[ingress.IP] = "the Node object is absent"
				set.NodeEvidence[ingress.IP] = struct{}{}
			}
		}
	}
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		if _, known := knownPublic[ingress.IP]; !known {
			set.Gone[ingress.IP] = "the Node object is absent"
			set.NodeEvidence[ingress.IP] = struct{}{}
		}
	}
	return set, patchedNode, nil, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalReadyEndpointNodes(service *corev1.Service) (map[string]struct{}, error) {
	if c.endpointSlices == nil {
		return nil, errors.New("public-node-local: EndpointSlice informer is unavailable")
	}
	slices, err := c.endpointSlices.EndpointSlices(service.Namespace).List(labels.SelectorFromSet(labels.Set{
		discoveryv1.LabelServiceName: service.Name,
	}))
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list EndpointSlices: %w", err)
	}
	result := map[string]struct{}{}
	for _, endpointSlice := range slices {
		if !publicNodeLocalEndpointSliceOwnedByService(endpointSlice, service) {
			continue
		}
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.NodeName == nil || endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
				(endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				continue
			}
			result[*endpoint.NodeName] = struct{}{}
		}
	}
	return result, nil
}

func publicNodeLocalEndpointSliceOwnedByService(endpointSlice *discoveryv1.EndpointSlice, service *corev1.Service) bool {
	if endpointSlice == nil || service == nil || endpointSlice.DeletionTimestamp != nil ||
		endpointSlice.Namespace != service.Namespace ||
		endpointSlice.Labels[discoveryv1.LabelServiceName] != service.Name {
		return false
	}
	matches := 0
	for _, owner := range endpointSlice.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Service" {
			matches++
			if owner.Name != service.Name || owner.UID != service.UID || owner.Controller == nil || !*owner.Controller {
				return false
			}
		}
	}
	return matches == 1
}

// authorizePublicNodeLocalNodeAcrossPools asks each pool in turn. The best
// answer wins: authorized, then unverified, then not eligible, then gone. A
// Gone answer rests on the Node object only when every pool's answer does.
func (c *nodeLoadBalancerController) authorizePublicNodeLocalNodeAcrossPools(
	ctx context.Context,
	node *corev1.Node,
	pools []string,
	subject *corev1.Service,
) (publicNodeLocalNodeVerdict, string, bool, error) {
	if len(pools) == 1 {
		verdict, patched, err := c.authorizePublicNodeLocalNodeVerdict(ctx, node, pools[0], subject)
		return verdict, pools[0], patched, err
	}
	rank := func(kind publicNodeLocalNodeKind) int {
		switch kind {
		case publicNodeLocalNodeAuthorized:
			return 3
		case publicNodeLocalNodeUnverified:
			return 2
		case publicNodeLocalNodeNotEligible:
			return 1
		}
		return 0
	}
	var best publicNodeLocalNodeVerdict
	var bestErr error
	bestPool := ""
	anyPatched, allNodeObject, anyForeign := false, true, false
	for index, pool := range pools {
		verdict, patched, err := c.authorizePublicNodeLocalNodeVerdict(ctx, node, pool, subject)
		anyPatched = anyPatched || patched
		anyForeign = anyForeign || verdict.foreign
		if verdict.kind == publicNodeLocalNodeGone && !verdict.nodeObject {
			allNodeObject = false
		}
		if index == 0 || rank(verdict.kind) > rank(best.kind) {
			best, bestErr, bestPool = verdict, err, pool
		}
	}
	if best.kind == publicNodeLocalNodeGone {
		best.nodeObject = allNodeObject
		best.foreign = anyForeign
	}
	return best, bestPool, anyPatched, bestErr
}

func (c *nodeLoadBalancerController) authorizePublicNodeLocalNode(
	ctx context.Context,
	node *corev1.Node,
	pool string,
) (bool, bool, error) {
	verdict, patched, err := c.authorizePublicNodeLocalNodeVerdict(ctx, node, pool, nil)
	return verdict.kind == publicNodeLocalNodeAuthorized, patched, err
}

// authorizePublicNodeLocalNodeVerdict says what is proven about one Node. An
// error means the Node could not be verified (Unverified), except for an exact
// VM not-found, which is Gone and still reports its error to strict callers.
func (c *nodeLoadBalancerController) authorizePublicNodeLocalNodeVerdict(
	ctx context.Context,
	node *corev1.Node,
	pool string,
	subject *corev1.Service,
) (publicNodeLocalNodeVerdict, bool, error) {
	unverified := publicNodeLocalNodeVerdict{}
	notEligible := func(reason string) (publicNodeLocalNodeVerdict, bool, error) {
		return publicNodeLocalNodeIs(publicNodeLocalNodeNotEligible, reason), false, nil
	}
	gone := func(reason string) (publicNodeLocalNodeVerdict, bool, error) {
		return publicNodeLocalNodeIs(publicNodeLocalNodeGone, reason), false, nil
	}
	karpenterBacked := node.Labels[karpenterNodePoolLabel] != ""
	for _, owner := range node.OwnerReferences {
		if owner.APIVersion == "karpenter.sh/v1" && owner.Kind == "NodeClaim" {
			karpenterBacked = true
		}
	}
	if !karpenterBacked && node.Labels[publicNodeLocalPoolLabel] != pool {
		verdict, patched, err := gone("the Node left the " + pool + " pool")
		verdict.nodeObject = true
		return verdict, patched, err
	}
	providerIdentity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || providerIdentity.Location != c.provider.config.Location || providerIdentity.String() != node.Spec.ProviderID {
		return notEligible("the Node has an invalid or foreign providerID")
	}
	vm, err := c.provider.api.GetVM(ctx, providerIdentity.Location, providerIdentity.UUID)
	if err != nil {
		wrapped := fmt.Errorf("public-node-local: read canonical VM ownership for Node %s: %w", node.Name, err)
		if inspace.IsNotFound(err) {
			return publicNodeLocalNodeIs(publicNodeLocalNodeGone, "the VM does not exist"), false, wrapped
		}
		return unverified, false, wrapped
	}
	if vm == nil || vm.UUID != providerIdentity.UUID {
		return gone("the VM identity does not match the providerID")
	}
	if strings.EqualFold(strings.TrimSpace(vm.Status), "deleted") {
		return gone("the VM is deleted")
	}
	if vm.BillingAccountID != c.provider.config.BillingAccountID {
		verdict, patched, err := gone("the VM belongs to another billing account")
		verdict.foreign = true
		return verdict, patched, err
	}
	if vm.NetworkUUID != "" && !strings.EqualFold(vm.NetworkUUID, c.provider.config.NetworkUUID) {
		verdict, patched, err := gone("the VM is outside the configured VPC")
		verdict.foreign = true
		return verdict, patched, err
	}
	network, err := c.provider.api.GetNetwork(ctx, providerIdentity.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return unverified, false, fmt.Errorf("public-node-local: read canonical VPC membership for Node %s: %w", node.Name, err)
	}
	if network == nil || !strings.EqualFold(network.UUID, c.provider.config.NetworkUUID) {
		return notEligible("the VPC identity does not match the configuration")
	}
	members, membershipErr := canonicalConfiguredVPCVMUUIDs(providerIdentity.Location, network)
	if membershipErr != nil {
		return unverified, false, fmt.Errorf("public-node-local: canonical VPC membership for Node %s is invalid: %w", node.Name, membershipErr)
	}
	member, present := members[providerIdentity.UUID]
	if !present {
		return gone("the VM is not a member of the configured VPC")
	}
	if member != providerIdentity.UUID {
		return notEligible("the VPC membership row is not canonical")
	}
	var ownership publicNodeLocalVMOwnership
	ownershipErr := error(nil)
	if vm.Description != "" {
		if parseErr := json.Unmarshal([]byte(vm.Description), &ownership); parseErr != nil &&
			strings.Contains(vm.Description, "karpenter.inspace.cloud/") {
			ownershipErr = parseErr
		}
	}
	if ownership.Schema == "karpenter.inspace.cloud/v3" {
		karpenterBacked = true
	}
	var claims *unstructured.UnstructuredList
	if c.provider.dynamicClient != nil {
		claims, err = c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return unverified, false, fmt.Errorf("public-node-local: list NodeClaims before manual/Karpenter classification: %w", err)
		}
		for index := range claims.Items {
			claim := &claims.Items[index]
			claimProviderID, providerFound, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
			claimNodeName, nodeFound, nodeErr := unstructured.NestedString(claim.Object, "status", "nodeName")
			if providerErr == nil && nodeErr == nil &&
				((providerFound && claimProviderID == node.Spec.ProviderID) || (nodeFound && claimNodeName == node.Name)) {
				karpenterBacked = true
				break
			}
		}
	}
	if !karpenterBacked {
		if node.Labels[publicNodeLocalPoolLabel] == pool && ownershipErr == nil {
			return publicNodeLocalNodeIs(publicNodeLocalNodeAuthorized, ""), false, nil
		}
		return notEligible("the VM ownership record is malformed")
	}
	if c.provider.dynamicClient == nil {
		return unverified, false, errors.New("public-node-local: dynamic client is required to authorize a Karpenter Node")
	}
	matching := make([]*unstructured.Unstructured, 0, 1)
	for index := range claims.Items {
		claim := &claims.Items[index]
		claimProviderID, providerFound, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
		claimNodeName, nodeFound, nodeErr := unstructured.NestedString(claim.Object, "status", "nodeName")
		if providerErr == nil && nodeErr == nil &&
			((providerFound && claimProviderID == node.Spec.ProviderID) || (nodeFound && claimNodeName == node.Name)) {
			matching = append(matching, claim.DeepCopy())
		}
	}
	if len(matching) == 0 {
		return gone("the NodeClaim is absent")
	}
	if len(matching) != 1 {
		return notEligible("more than one NodeClaim matches the Node")
	}
	claim := matching[0]
	if claim.GetDeletionTimestamp() != nil {
		return gone("the NodeClaim is being deleted")
	}
	claimProviderID, providerFound, _ := unstructured.NestedString(claim.Object, "status", "providerID")
	claimNodeName, nodeFound, _ := unstructured.NestedString(claim.Object, "status", "nodeName")
	if !providerFound || !nodeFound || claimProviderID != node.Spec.ProviderID || claimNodeName != node.Name ||
		claim.GetUID() == "" ||
		!hasExactSingleNodeLoadBalancerOwnerReference(node.OwnerReferences, "karpenter.sh/v1", "NodeClaim", claim.GetName(), claim.GetUID()) {
		return notEligible("the NodeClaim identity does not match the Node")
	}
	poolName := claim.GetLabels()[karpenterNodePoolLabel]
	if poolName == "" || node.Labels[karpenterNodePoolLabel] != poolName {
		return notEligible("the NodeClaim and Node disagree on the NodePool")
	}
	nodePool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, poolName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return gone("the NodePool is absent")
	}
	if err != nil {
		return unverified, false, fmt.Errorf("public-node-local: get NodePool %s: %w", poolName, err)
	}
	if nodePool.GetDeletionTimestamp() != nil {
		return gone("the NodePool is being deleted")
	}
	if nodePool.GetUID() == "" ||
		!hasExactSingleNodeLoadBalancerOwnerReference(claim.GetOwnerReferences(), "karpenter.sh/v1", "NodePool", nodePool.GetName(), nodePool.GetUID()) {
		return notEligible("the NodeClaim is not owned by the NodePool")
	}
	templateLabels, found, err := unstructured.NestedStringMap(nodePool.Object, "spec", "template", "metadata", "labels")
	if err != nil || !found {
		return notEligible("the NodePool template labels are unreadable")
	}
	if templateLabels[publicNodeLocalPoolLabel] != pool {
		return gone("the NodePool no longer places Nodes in the " + pool + " pool")
	}
	claimClassName, ok := publicNodeLocalNodeClassRefName(claim, []string{"spec", "nodeClassRef"})
	if !ok {
		return notEligible("the NodeClaim has no valid nodeClassRef")
	}
	poolClassName, ok := publicNodeLocalNodeClassRefName(nodePool, []string{"spec", "template", "spec", "nodeClassRef"})
	if !ok || poolClassName != claimClassName {
		return notEligible("the NodePool and NodeClaim disagree on the node class")
	}
	nodeClass, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, claimClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return notEligible("the InSpaceNodeClass is absent")
	}
	if err != nil {
		return unverified, false, fmt.Errorf("public-node-local: get InSpaceNodeClass %s: %w", claimClassName, err)
	}
	profile, profileFound, profileErr := unstructured.NestedString(nodeClass.Object, "spec", "firewallProfile")
	if nodeClass.GetDeletionTimestamp() != nil || profileErr != nil || !profileFound || profile != publicNodeLocalFirewallProfile {
		return gone("the InSpaceNodeClass is not a public-node-local class")
	}
	if err := c.validateBaseNodeClass(nodeClass); err != nil {
		return unverified, false, fmt.Errorf("public-node-local: validate InSpaceNodeClass %s: %w", claimClassName, err)
	}
	baseFirewallUUID, err := c.publicNodeLocalTrustedBaseFirewall(ctx, nodeClass)
	if err != nil {
		return unverified, false, fmt.Errorf("public-node-local: validate InSpaceNodeClass %s security base: %w", claimClassName, err)
	}
	if ownershipErr != nil ||
		ownership.Schema != "karpenter.inspace.cloud/v3" || ownership.Cluster != c.provider.config.ClusterID ||
		ownership.NodePool != poolName || ownership.NodeClaim != claim.GetName() ||
		ownership.VMName == "" || ownership.VMName != vm.Name || ownership.VMName != node.Name ||
		ownership.FirewallProfile != publicNodeLocalFirewallProfile || ownership.FirewallUUID != baseFirewallUUID ||
		ownership.NetworkUUID != c.provider.config.NetworkUUID || ownership.BillingAccountID != c.provider.config.BillingAccountID {
		return notEligible("the VM ownership record does not match the NodeClaim")
	}
	if node.Labels[publicNodeLocalPoolLabel] != pool {
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{
			"resourceVersion": node.ResourceVersion,
			"labels":          map[string]any{publicNodeLocalPoolLabel: pool},
		}})
		if _, err := c.provider.kubeClient.CoreV1().Nodes().Patch(ctx, node.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return unverified, false, fmt.Errorf("public-node-local: mirror protected pool label to Node %s: %w", node.Name, err)
		}
		// Do not authorize from a stale pre-patch Node object. The next
		// reconciliation must observe the protected label and then complete the
		// VM firewall audit against the exact live Service state.
		return publicNodeLocalNodeIs(publicNodeLocalNodeNotEligible, "the protected pool label was just mirrored"), true, nil
	}
	if err := c.auditPublicNodeLocalVMFirewalls(ctx, node, baseFirewallUUID, subject); err != nil {
		return unverified, false, fmt.Errorf("public-node-local: audit VM %s firewall assignments: %w", node.Name, err)
	}
	return publicNodeLocalNodeIs(publicNodeLocalNodeAuthorized, ""), false, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalTrustedBaseFirewall(
	ctx context.Context,
	nodeClass *unstructured.Unstructured,
) (string, error) {
	if nodeClass == nil {
		return "", errors.New("NodeClass is required")
	}
	reservePublic, found, err := unstructured.NestedBool(nodeClass.Object, "spec", "reservePublicIPv4")
	if err != nil || !found || !reservePublic {
		return "", errors.New("spec.reservePublicIPv4 must be true")
	}
	return c.trustedNodeLoadBalancerBaseFirewall(ctx, nodeClass)
}

// trustedNodeLoadBalancerBaseFirewall binds a derived public NodeClass back to
// the configured private-worker security boundary. Both NodeClass status
// objects must confirm the same canonical firewall UUID before a VM ownership
// record may use it as authorization for any additional public firewall.
func (c *nodeLoadBalancerController) trustedNodeLoadBalancerBaseFirewall(
	ctx context.Context,
	nodeClass *unstructured.Unstructured,
) (string, error) {
	if nodeClass == nil || c.provider.config.NodeLoadBalancer.DefaultNodeClass == "" {
		return "", errors.New("configured default NodeClass is required")
	}
	localFirewallUUID, found, err := unstructured.NestedString(nodeClass.Object, "spec", "firewallUUID")
	if err != nil || !found || !validNodeLoadBalancerCloudUUID(localFirewallUUID) {
		return "", errors.New("spec.firewallUUID must be a canonical cloud UUID")
	}
	localStatusFirewallUUID, found, err := unstructured.NestedString(nodeClass.Object, "status", "firewallUUID")
	if err != nil || !found || localStatusFirewallUUID != localFirewallUUID {
		return "", errors.New("status.firewallUUID must exactly confirm spec.firewallUUID")
	}
	base, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(
		ctx, c.provider.config.NodeLoadBalancer.DefaultNodeClass, metav1.GetOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("get configured default NodeClass %q: %w", c.provider.config.NodeLoadBalancer.DefaultNodeClass, err)
	}
	if base.GetDeletionTimestamp() != nil {
		return "", errors.New("configured default NodeClass is deleting")
	}
	if err := c.validateBaseNodeClass(base); err != nil {
		return "", err
	}
	baseFirewallUUID, found, err := unstructured.NestedString(base.Object, "spec", "firewallUUID")
	if err != nil || !found || !validNodeLoadBalancerCloudUUID(baseFirewallUUID) {
		return "", errors.New("configured default NodeClass has no canonical spec.firewallUUID")
	}
	baseStatusFirewallUUID, found, err := unstructured.NestedString(base.Object, "status", "firewallUUID")
	if err != nil || !found || baseStatusFirewallUUID != baseFirewallUUID {
		return "", errors.New("configured default NodeClass status.firewallUUID does not confirm its spec")
	}
	if localFirewallUUID != baseFirewallUUID {
		return "", fmt.Errorf("spec.firewallUUID %s does not match trusted default NodeClass firewall %s", localFirewallUUID, baseFirewallUUID)
	}
	return baseFirewallUUID, nil
}

// auditManagedNodeLoadBalancerBaseFirewall proves the live cloud security
// boundary for one managed VM. NodeClass spec/status and the VM description
// identify the intended firewall, but only this fresh inventory read proves
// that the UUID still has our billing identity, exact private-worker policy,
// and exactly one attachment row for the VM being authorized.
func (c *nodeLoadBalancerController) auditManagedNodeLoadBalancerBaseFirewall(
	ctx context.Context,
	vmUUID, baseFirewallUUID, subnet string,
) error {
	base, err := c.exactNodeLoadBalancerFirewallFresh(ctx, baseFirewallUUID)
	if err != nil {
		return err
	}
	if base.BillingAccountID != c.provider.config.BillingAccountID {
		return fmt.Errorf("trusted base firewall %s has foreign billing identity", baseFirewallUUID)
	}
	if err := bootstrap.ValidateDefaultNodeFirewallPolicy(base, subnet, cloudv1.CiliumNativeRoutingPodCIDR); err != nil {
		return fmt.Errorf("trusted base firewall %s policy drifted: %w", baseFirewallUUID, err)
	}
	assignments := 0
	for _, relation := range base.ResourcesAssigned {
		if !strings.EqualFold(relation.ResourceType, "vm") || !validNodeLoadBalancerCloudUUID(relation.ResourceUUID) {
			return fmt.Errorf("trusted base firewall %s has malformed assignment %#v", baseFirewallUUID, relation)
		}
		if strings.EqualFold(relation.ResourceUUID, vmUUID) {
			if relation.ResourceUUID != vmUUID {
				return fmt.Errorf("trusted base firewall %s has non-canonical VM assignment %q", baseFirewallUUID, relation.ResourceUUID)
			}
			assignments++
		}
	}
	if assignments != 1 {
		return fmt.Errorf("VM %s must have exactly one trusted base firewall %s assignment, got %d", vmUUID, baseFirewallUUID, assignments)
	}
	return nil
}

func (c *nodeLoadBalancerController) auditPublicNodeLocalVMFirewalls(
	ctx context.Context,
	node *corev1.Node,
	baseFirewallUUID string,
	subject *corev1.Service,
) error {
	vmUUID, ok := nodeLoadBalancerVMUUID(node)
	if !ok {
		return errors.New("Node has no canonical VM identity")
	}
	metadata, err := c.provider.InstanceMetadata(ctx, node)
	if err != nil || metadata.ProviderID != node.Spec.ProviderID {
		return joinWithExplanation(errors.New("Node provider identity changed during firewall authorization"), err)
	}
	authoritativePublicIP, publicOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeExternalIP, false)
	nodePublicIP, nodePublicOK := nodeLoadBalancerNodeExternalIPv4(node)
	if !publicOK || !nodePublicOK || authoritativePublicIP != nodePublicIP {
		return errors.New("Node public IPv4 does not match authoritative VM/FIP metadata during firewall authorization")
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return err
	}
	network, err := c.provider.api.GetNetwork(ctx, c.provider.config.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return fmt.Errorf("read trusted VPC policy boundary: %w", err)
	}
	if network == nil || network.UUID != c.provider.config.NetworkUUID {
		return errors.New("trusted VPC identity changed during firewall audit")
	}
	seen := make(map[string]struct{}, len(items))
	baseAssignments := 0
	var baseFirewall *inspace.Firewall
	for index := range items {
		firewall := items[index]
		if !validNodeLoadBalancerCloudUUID(firewall.UUID) {
			return fmt.Errorf("firewall list row has invalid UUID %q", firewall.UUID)
		}
		if _, duplicate := seen[firewall.UUID]; duplicate {
			return fmt.Errorf("firewall list contains duplicate UUID %s", firewall.UUID)
		}
		seen[firewall.UUID] = struct{}{}
		if firewall.UUID == baseFirewallUUID {
			copy := firewall
			baseFirewall = &copy
			if firewall.BillingAccountID != c.provider.config.BillingAccountID {
				return fmt.Errorf("trusted base firewall %s has foreign billing identity", baseFirewallUUID)
			}
		}
		assignments, assignmentErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignmentErr != nil {
			return assignmentErr
		}
		if _, assigned := assignments[strings.ToLower(vmUUID)]; !assigned {
			continue
		}
		if firewall.UUID == baseFirewallUUID {
			baseAssignments++
			continue
		}
		if firewallVM, isVMFirewall := inspace.ParseNodeLoadBalancerVMFirewallName(c.provider.config.ClusterID, firewall.EffectiveName()); isVMFirewall &&
			firewallVM == vmUUID &&
			inspace.ValidateNodeLoadBalancerVMFirewallIdentity(firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID) == nil &&
			!c.publicNodeLocalPerVMModeEnabled() {
			return &publicNodeLocalPerVMStatePresentError{vmUUID: vmUUID, firewallUUID: firewall.UUID}
		}
		if err := inspace.ValidateNodeLoadBalancerServiceFirewall(
			firewall,
			c.provider.config.ClusterID,
			c.provider.config.BillingAccountID,
		); err != nil {
			return fmt.Errorf("VM %s has unauthorized additional firewall %s: %w", vmUUID, firewall.UUID, err)
		}
		if subject != nil && nodeLoadBalancerFirewallIdentityOwnedByService(
			firewall, c.provider.config.ClusterID, string(subject.UID), c.provider.config.BillingAccountID,
		) {
			// The subject's own reconcile repairs its own firewall.
			continue
		}
		if err := c.validateLivePublicNodeLocalServiceFirewall(ctx, node, authoritativePublicIP, firewall); err != nil {
			var sibling *publicNodeLocalSiblingError
			if !errors.As(err, &sibling) {
				return err
			}
			// One Service's imperfect firewall must not fail the node for every
			// other Service. Its own reconcile handles it.
			klog.Warningf("public-node-local: ignoring imperfect sibling firewall %s on VM %s: %v", firewall.UUID, vmUUID, err)
			if c.queue != nil {
				c.queue.Add(sibling.key)
			}
		}
	}
	if baseFirewall == nil {
		return fmt.Errorf("trusted base firewall %s is absent", baseFirewallUUID)
	}
	if err := bootstrap.ValidateDefaultNodeFirewallPolicy(baseFirewall, network.Subnet, cloudv1.CiliumNativeRoutingPodCIDR); err != nil {
		return fmt.Errorf("trusted base firewall %s policy drifted: %w", baseFirewallUUID, err)
	}
	if baseAssignments != 1 {
		return fmt.Errorf("VM %s must have exactly one trusted base firewall %s assignment, got %d", vmUUID, baseFirewallUUID, baseAssignments)
	}
	return nil
}

func (c *nodeLoadBalancerController) validateLivePublicNodeLocalServiceFirewall(
	ctx context.Context,
	node *corev1.Node,
	authoritativePublicIP string,
	firewall inspace.Firewall,
) error {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: list live Services for VM firewall authorization: %w", err)
	}
	vmUUID, _ := nodeLoadBalancerVMUUID(node)
	privateIP, privateOK := nodeLoadBalancerNodeInternalIPv4(node)
	if !privateOK {
		return fmt.Errorf("public-node-local: Node %s has no canonical private IP", node.Name)
	}
	matches := 0
	for index := range services.Items {
		service := &services.Items[index]
		if !nodeLoadBalancerFirewallOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			string(service.UID),
			c.provider.config.BillingAccountID,
		) {
			continue
		}
		matches++
		siblingErr := func(cause error) error {
			return &publicNodeLocalSiblingError{key: service.Namespace + "/" + service.Name, cause: cause}
		}
		intent, parseErr := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		// A sibling in a transition serves its active pool and its target pool.
		servedPool := node.Labels[publicNodeLocalPoolLabel] == intent.Pool ||
			(service.Annotations[annotationPublicNodeLocalActivePool] != "" &&
				node.Labels[publicNodeLocalPoolLabel] == service.Annotations[annotationPublicNodeLocalActivePool]) ||
			(service.Annotations[annotationPublicNodeLocalTargetPool] != "" &&
				node.Labels[publicNodeLocalPoolLabel] == service.Annotations[annotationPublicNodeLocalTargetPool])
		if parseErr != nil || service.DeletionTimestamp != nil || intent.Mode != nodeLoadBalancerModeLocal ||
			!containsString(service.Finalizers, publicNodeLocalFinalizer) || !servedPool {
			return siblingErr(errors.Join(parseErr, fmt.Errorf("public-node-local: firewall %s is not bound to a live valid local Service", firewall.UUID)))
		}
		desired, desiredErr := c.desiredServiceFirewall(service)
		previousHash, previousHashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
		// During a policy transition the old firewall is the previous one in the
		// ledger and carries the active policy.
		isPrevious := service.Annotations[annotationNodeLoadBalancerPreviousFirewall] == firewall.UUID &&
			previousHashErr == nil && previousHash == service.Annotations[annotationPublicNodeLocalActivePolicy]
		if !isPrevious && (desiredErr != nil || service.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewall.UUID ||
			service.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
			!nodeLoadBalancerFirewallMatches(firewall, desired)) {
			return siblingErr(errors.Join(desiredErr, fmt.Errorf("public-node-local: firewall %s lost its exact live Service ledger", firewall.UUID)))
		}
		if isPrevious {
			desired.Hash = previousHash
		}
		readyNodes, endpointErr := c.publicNodeLocalReadyEndpointNodes(service)
		if endpointErr != nil {
			return endpointErr
		}
		if _, ready := readyNodes[node.Name]; !ready {
			return siblingErr(fmt.Errorf("public-node-local: firewall %s is assigned to VM %s without a Ready local endpoint", firewall.UUID, vmUUID))
		}
		datapath, datapathErr := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
			ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
		)
		if datapathErr != nil || !publicNodeLocalDatapathMatches(datapath, service, intent.Pool) {
			return siblingErr(errors.Join(datapathErr, fmt.Errorf("public-node-local: firewall %s has no exact live child datapath", firewall.UUID)))
		}
		privateAdvertised := false
		for _, ingress := range datapath.Status.LoadBalancer.Ingress {
			if ingress.IP == privateIP && ingress.IPMode != nil && *ingress.IPMode == corev1.LoadBalancerIPModeVIP {
				privateAdvertised = true
				break
			}
		}
		if !privateAdvertised {
			return siblingErr(fmt.Errorf("public-node-local: firewall %s VM %s is absent from the exact child VIP status", firewall.UUID, vmUUID))
		}
		publicAdvertised := false
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP == authoritativePublicIP && ingress.IPMode != nil && *ingress.IPMode == corev1.LoadBalancerIPModeProxy {
				if publicAdvertised {
					return siblingErr(fmt.Errorf("public-node-local: firewall %s VM %s has a duplicate public status entry", firewall.UUID, vmUUID))
				}
				publicAdvertised = true
			}
		}
		servedPolicy := desired.Hash == service.Annotations[annotationPublicNodeLocalActivePolicy] ||
			(service.Annotations[annotationPublicNodeLocalTargetPolicy] != "" &&
				desired.Hash == service.Annotations[annotationPublicNodeLocalTargetPolicy])
		active := publicAdvertised && servedPolicy &&
			(service.Annotations[annotationPublicNodeLocalActivePool] == intent.Pool ||
				service.Annotations[annotationPublicNodeLocalActivePool] == node.Labels[publicNodeLocalPoolLabel])
		staged := false
		if service.Annotations[annotationNodeLoadBalancerFirewallAssigning] == firewall.UUID &&
			service.Annotations[annotationPublicNodeLocalAssignPolicy] == desired.Hash {
			vmSet := strings.Split(service.Annotations[annotationPublicNodeLocalAssignVMs], ",")
			sortedVMs := append([]string(nil), vmSet...)
			sort.Strings(sortedVMs)
			canonical := len(sortedVMs) != 0 && reflect.DeepEqual(vmSet, sortedVMs)
			seenVM := false
			for _, candidate := range vmSet {
				if !validNodeLoadBalancerCloudUUID(candidate) {
					canonical = false
				}
				if candidate == vmUUID {
					if seenVM {
						canonical = false
					}
					seenVM = true
				}
			}
			startedAt, timeErr := time.Parse(time.RFC3339Nano, service.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
			now := time.Now().UTC()
			staged = canonical && seenVM && timeErr == nil && !startedAt.After(now) && now.Before(startedAt.Add(nodeLoadBalancerPublicNodeLocalAssignTimeout))
		}
		if !active && !staged {
			return siblingErr(fmt.Errorf("public-node-local: firewall %s VM assignment has no active or durable staged authorization", firewall.UUID))
		}
	}
	if matches != 1 {
		return fmt.Errorf("public-node-local: Service firewall %s resolves to %d live exact owners", firewall.UUID, matches)
	}
	return nil
}

func publicNodeLocalNodeClassRefName(object *unstructured.Unstructured, path []string) (string, bool) {
	group, groupFound, groupErr := unstructured.NestedString(object.Object, append(path, "group")...)
	kind, kindFound, kindErr := unstructured.NestedString(object.Object, append(path, "kind")...)
	name, nameFound, nameErr := unstructured.NestedString(object.Object, append(path, "name")...)
	return name, groupErr == nil && kindErr == nil && nameErr == nil && groupFound && kindFound && nameFound &&
		group == "karpenter.inspace.cloud" && kind == "InSpaceNodeClass" && name != ""
}

func (c *nodeLoadBalancerController) publicNodeLocalAddress(ctx context.Context, node *corev1.Node) (nodeLoadBalancerAddress, error) {
	identity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || identity.Location != c.provider.config.Location || identity.String() != node.Spec.ProviderID {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s has an invalid or foreign providerID", node.Name)
	}
	metadata, err := c.provider.InstanceMetadata(ctx, node)
	if err != nil {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: resolve provider metadata for Node %s: %w", node.Name, err)
	}
	if metadata.ProviderID != node.Spec.ProviderID {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s provider identity changed during metadata lookup", node.Name)
	}
	privateIP, privateOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeInternalIP, true)
	publicIP, publicOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeExternalIP, false)
	nodePrivate, nodePrivateOK := nodeLoadBalancerNodeInternalIPv4(node)
	nodePublic, nodePublicOK := nodeLoadBalancerNodeExternalIPv4(node)
	if !privateOK || !publicOK || !nodePrivateOK || !nodePublicOK || privateIP != nodePrivate || publicIP != nodePublic {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s addresses do not match authoritative VM/FIP metadata", node.Name)
	}
	return nodeLoadBalancerAddress{Node: node.DeepCopy(), PrivateIPv4: privateIP, PublicIPv4: publicIP}, nil
}

func exactNodeAddressIPv4(addresses []corev1.NodeAddress, addressType corev1.NodeAddressType, private bool) (string, bool) {
	result := ""
	for _, address := range addresses {
		if address.Type != addressType {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.String() != address.Address || parsed.IsPrivate() != private || result != "" {
			return "", false
		}
		result = parsed.String()
	}
	return result, result != ""
}

func publicNodeLocalAddressIdentities(addresses []nodeLoadBalancerAddress) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Node.Name+"|"+address.Node.Spec.ProviderID+"|"+address.PrivateIPv4+"|"+address.PublicIPv4)
	}
	sort.Strings(result)
	return result
}

// publicNodeLocalIncumbentInPool reports whether the Service already serves
// the pool with a claim that overlaps ports. The parent decides: a persisted
// activation in the pool plus its own intent ports (ownPorts) prove the claim.
// The child datapath only adds the ports that are actually served after an
// intent change. A child that is absent, unparsable or unreadable can never
// make a serving Service lose its claim: it holds instead.
func (c *nodeLoadBalancerController) publicNodeLocalIncumbentInPool(
	ctx context.Context,
	service *corev1.Service,
	pool string,
	ownPorts, ports []nodeLoadBalancerPortClaim,
) (bool, error) {
	if strings.TrimSpace(service.Annotations[annotationPublicNodeLocalActivePool]) != pool &&
		strings.TrimSpace(service.Annotations[annotationPublicNodeLocalTargetPool]) != pool {
		return false, nil
	}
	if publicNodeLocalPortsOverlap(ports, ownPorts) {
		return true, nil
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("public-node-local: inspect incumbent datapath: %w", err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return false, fmt.Errorf("public-node-local: conflict peer %s/%s has a foreign datapath identity", service.Namespace, service.Name)
	}
	childPorts, err := nodeLoadBalancerPortClaims(datapath)
	if err != nil {
		// The activation is proven and the served ports are not: keep the claim.
		return true, nil
	}
	return publicNodeLocalPortsOverlap(ports, childPorts), nil
}

func (c *nodeLoadBalancerController) publicNodeLocalPortConflict(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) (loses, winnerWaiting bool, resultErr error) {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: list Services for port claims: %w", err)
	}
	for index := range services.Items {
		other := &services.Items[index]
		if other.UID == service.UID {
			continue
		}

		validDesiredConflict := false
		if other.DeletionTimestamp == nil && publicNodeLocalRequested(other) {
			otherIntent, parseErr := parseNodeLoadBalancerService(other, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
			if parseErr == nil && otherIntent.Mode == nodeLoadBalancerModeLocal && otherIntent.Pool == intent.Pool &&
				publicNodeLocalPortsOverlap(intent.Ports, otherIntent.Ports) {
				validDesiredConflict = true
				// A Service that already serves the claim keeps it against a newcomer,
				// whatever the UID order. Within the same class the lowest UID wins.
				selfIncumbent, incumbentErr := c.publicNodeLocalIncumbentInPool(ctx, service, intent.Pool, intent.Ports, otherIntent.Ports)
				if incumbentErr != nil {
					return false, false, incumbentErr
				}
				otherIncumbent, incumbentErr := c.publicNodeLocalIncumbentInPool(ctx, other, intent.Pool, otherIntent.Ports, intent.Ports)
				if incumbentErr != nil {
					return false, false, incumbentErr
				}
				otherWins := string(other.UID) < string(service.UID)
				if selfIncumbent != otherIncumbent {
					otherWins = otherIncumbent
				}
				if otherWins {
					return true, false, fmt.Errorf(
						"public-node-local: pool %s protocol/port claim belongs to lexicographic winner %s/%s (UID %s); Service %s/%s (UID %s) must remain closed",
						intent.Pool, other.Namespace, other.Name, other.UID, service.Namespace, service.Name, service.UID,
					)
				}
			}
		}

		aggregateOwned := containsString(other.Finalizers, nodeLoadBalancerFinalizer) &&
			!containsString(other.Finalizers, publicNodeLocalFinalizer) &&
			other.Annotations[annotationPublicNodeLocalActivePool] == "" &&
			other.Annotations[annotationPublicNodeLocalActivePolicy] == "" &&
			!publicNodeLocalAssignmentFencePresent(other) &&
			other.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] == "" &&
			other.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] == ""
		mayRetainLocalState := containsString(other.Finalizers, publicNodeLocalFinalizer) ||
			other.Annotations[annotationPublicNodeLocalActivePool] != "" ||
			other.Annotations[annotationPublicNodeLocalActivePolicy] != "" ||
			(!aggregateOwned && len(other.Status.LoadBalancer.Ingress) != 0 && other.Spec.LoadBalancerClass != nil &&
				*other.Spec.LoadBalancerClass == nodeLoadBalancerClass)
		if !validDesiredConflict && !mayRetainLocalState {
			continue
		}
		stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, other)
		if exposureErr != nil {
			return false, false, exposureErr
		}
		if !stillExposed {
			continue
		}
		if validDesiredConflict {
			winnerWaiting = true
		}
		if mayRetainLocalState {
			blocks, blockErr := c.publicNodeLocalStaleExposureBlocks(ctx, other, intent)
			if blockErr != nil {
				return false, false, blockErr
			}
			if blocks {
				winnerWaiting = true
			}
		}
	}
	return false, winnerWaiting, nil
}

// publicNodeLocalStaleExposureBlocks compares the persisted activation
// identity with the exact-owned child that implements the old datapath. A
// Service spec can change before its cleanup reconciliation runs, so its new
// desired pool and ports are not evidence that the old exposure disappeared.
func (c *nodeLoadBalancerController) publicNodeLocalStaleExposureBlocks(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) (bool, error) {
	activePool := strings.TrimSpace(service.Annotations[annotationPublicNodeLocalActivePool])
	targetPool := strings.TrimSpace(service.Annotations[annotationPublicNodeLocalTargetPool])
	childPool, childTargetPool := "", ""
	var childPorts []nodeLoadBalancerPortClaim
	childPortsProven := false
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
			return false, fmt.Errorf("public-node-local: conflict peer %s/%s has a foreign datapath identity", service.Namespace, service.Name)
		}
		childPool = strings.TrimSpace(datapath.Annotations[annotationPublicNodeLocalDatapathPool])
		childTargetPool = strings.TrimSpace(datapath.Annotations[annotationPublicNodeLocalDatapathTargetPool])
		childPorts, err = nodeLoadBalancerPortClaims(datapath)
		childPortsProven = err == nil && len(childPorts) != 0
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("public-node-local: inspect conflict peer persisted datapath: %w", err)
	}

	// A Service in a transition exposes in every pool it names: the active one,
	// the target one, and the pools its child records.
	exposurePools := map[string]struct{}{}
	for _, pool := range []string{activePool, targetPool, childPool, childTargetPool} {
		if pool != "" {
			exposurePools[pool] = struct{}{}
		}
	}
	// Port claims are per pool, but VIPs are on Nodes: Cilium programs a claim on
	// every Node that carries a VIP of this Service, whatever pool that Node is
	// in now. A pool that was drained by a promotion or an abort, or a Node that
	// was relabelled, stays attributed until its last VIP is gone.
	if datapath != nil {
		vipPools, vipErr := c.publicNodeLocalVIPNodePools(ctx, datapath)
		if vipErr != nil {
			return false, vipErr
		}
		for pool := range vipPools {
			exposurePools[pool] = struct{}{}
		}
	}
	if len(exposurePools) == 0 {
		// A privileged status/firewall proves exposure, but no persisted pool
		// proves where it belongs. The only safe temporary choice is to block.
		return true, nil
	}
	if _, named := exposurePools[intent.Pool]; !named {
		return false, nil
	}
	// Disagreement between the two persisted identities means the exact old
	// port set cannot be attributed safely. Block either named pool until the
	// peer's withdrawal removes the exposure.
	if activePool != "" && childPool != "" && activePool != childPool {
		return true, nil
	}
	if targetPool != "" && intent.Pool == targetPool && childTargetPool != targetPool {
		// The child does not record the transition yet, so its ports do not
		// prove the claim the peer is taking in the target pool.
		return true, nil
	}
	if !childPortsProven || childPool == "" {
		// activePool is authoritative for the pool, but only the exact-owned
		// child proves the frontend ports. Missing/drifted evidence blocks
		// that pool until cleanup completes.
		return true, nil
	}
	return publicNodeLocalPortsOverlap(intent.Ports, childPorts), nil
}

// publicNodeLocalVIPNodePools names the pools of the Nodes that carry a VIP of
// the child. A VIP that matches no Node has nothing to program and names none.
func (c *nodeLoadBalancerController) publicNodeLocalVIPNodePools(ctx context.Context, datapath *corev1.Service) (map[string]struct{}, error) {
	pools := map[string]struct{}{}
	if len(datapath.Status.LoadBalancer.Ingress) == 0 {
		return pools, nil
	}
	nodes, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list Nodes to attribute conflict peer VIPs: %w", err)
	}
	vips := publicNodeLocalIngressSet(datapath.Status.LoadBalancer)
	for index := range nodes.Items {
		node := &nodes.Items[index]
		private, ok := nodeLoadBalancerNodeInternalIPv4(node)
		if !ok {
			continue
		}
		if _, carries := vips[private]; !carries {
			continue
		}
		if pool := node.Labels[publicNodeLocalPoolLabel]; pool != "" {
			pools[pool] = struct{}{}
		}
	}
	return pools, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalServiceStillExposed(
	ctx context.Context,
	service *corev1.Service,
) (bool, error) {
	if len(service.Status.LoadBalancer.Ingress) != 0 ||
		service.Annotations[annotationPublicNodeLocalActivePool] != "" ||
		service.Annotations[annotationPublicNodeLocalActivePolicy] != "" ||
		publicNodeLocalAssignmentFencePresent(service) ||
		service.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != "" ||
		service.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] != "" {
		return true, nil
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
			return false, fmt.Errorf("public-node-local: conflict peer %s/%s has a foreign datapath identity", service.Namespace, service.Name)
		}
		if len(datapath.Status.LoadBalancer.Ingress) != 0 {
			return true, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("public-node-local: inspect conflict peer datapath: %w", err)
	}
	owned, err := c.serviceFirewallsForEmergencyDetach(ctx, service)
	if err != nil {
		return false, fmt.Errorf("public-node-local: inspect conflict peer firewalls: %w", err)
	}
	for _, firewall := range owned {
		assignments, assignmentErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignmentErr != nil {
			return false, assignmentErr
		}
		if len(assignments) != 0 {
			return true, nil
		}
	}
	return false, nil
}

func (c *nodeLoadBalancerController) recordPublicNodeLocalConflictEvent(
	ctx context.Context,
	service *corev1.Service,
	cause error,
) error {
	if service == nil || cause == nil {
		return nil
	}
	conflictID := shortHash(cause.Error())
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalConflict] == conflictID {
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationPublicNodeLocalConflict] = conflictID
		return true, nil
	})
	if err != nil || !changed {
		return err
	}
	now := metav1.Now()
	client := c.provider.kubeClient.CoreV1().Events(service.Namespace)
	_, err = client.Create(ctx, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: service.Name + ".", Namespace: service.Namespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1", Kind: "Service", Namespace: service.Namespace,
			Name: service.Name, UID: service.UID,
		},
		Reason:         "PublicNodeLocalPortConflict",
		Message:        cause.Error(),
		Source:         corev1.EventSource{Component: "inspace-cloud-controller-manager"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Type:           corev1.EventTypeWarning,
	}, metav1.CreateOptions{})
	return err
}

// recordNodeLoadBalancerReservedPortEvent makes a reserved-port rejection
// visible on the Service. The Event name is derived from the Service UID and
// the exact rejection, so retries neither mutate the Service nor spam Events.
func (c *nodeLoadBalancerController) recordNodeLoadBalancerReservedPortEvent(
	ctx context.Context,
	service *corev1.Service,
	cause error,
) error {
	if service == nil || !errors.Is(cause, errNodeLoadBalancerReservedPort) {
		return nil
	}
	now := metav1.Now()
	_, err := c.provider.kubeClient.CoreV1().Events(service.Namespace).Create(ctx, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.Name + "." + shortHash(string(service.UID)+"\x00"+cause.Error()),
			Namespace: service.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1", Kind: "Service", Namespace: service.Namespace,
			Name: service.Name, UID: service.UID,
		},
		Reason:         "NodeLoadBalancerReservedPort",
		Message:        cause.Error(),
		Source:         corev1.EventSource{Component: "inspace-cloud-controller-manager"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Type:           corev1.EventTypeWarning,
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalConflict(ctx context.Context, service *corev1.Service) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalConflict] == "" {
			return false, nil
		}
		delete(copy.Annotations, annotationPublicNodeLocalConflict)
		return true, nil
	})
	return changed, err
}

func publicNodeLocalPortsOverlap(left, right []nodeLoadBalancerPortClaim) bool {
	set := make(map[nodeLoadBalancerPortClaim]struct{}, len(left))
	for _, claim := range left {
		set[claim] = struct{}{}
	}
	for _, claim := range right {
		if _, found := set[claim]; found {
			return true
		}
	}
	return false
}

func publicNodeLocalVMSet(addresses []nodeLoadBalancerAddress) (string, error) {
	vmUUIDs := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		vmUUID, ok := nodeLoadBalancerVMUUID(address.Node)
		if !ok || !validNodeLoadBalancerCloudUUID(vmUUID) {
			return "", fmt.Errorf("public-node-local: Node %s has no valid VM identity", address.Node.Name)
		}
		if _, duplicate := seen[vmUUID]; duplicate {
			return "", fmt.Errorf("public-node-local: duplicate VM identity %s", vmUUID)
		}
		seen[vmUUID] = struct{}{}
		vmUUIDs = append(vmUUIDs, vmUUID)
	}
	sort.Strings(vmUUIDs)
	return strings.Join(vmUUIDs, ","), nil
}

func publicNodeLocalAssignmentFencePresent(service *corev1.Service) bool {
	if service == nil {
		return false
	}
	for _, key := range []string{
		annotationNodeLoadBalancerFirewallAssigning,
		annotationNodeLoadBalancerFirewallAssignAt,
		annotationPublicNodeLocalAssignPolicy,
		annotationPublicNodeLocalAssignVMs,
	} {
		if service.Annotations[key] != "" {
			return true
		}
	}
	return false
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, bool, error) {
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil || vmSet == "" {
		return service, false, joinWithExplanation(errors.New("public-node-local: non-empty VM set is required before assignment authorization"), err)
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return service, false, err
	}
	if err := c.validatePublicNodeLocalAssignmentState(ctx, current, intent, desired, edge, addresses, false, false); err != nil {
		return current, false, err
	}
	now := time.Now().UTC()
	updated, changed, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		assigning := copy.Annotations[annotationNodeLoadBalancerFirewallAssigning]
		started := copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		policy := copy.Annotations[annotationPublicNodeLocalAssignPolicy]
		storedVMs := copy.Annotations[annotationPublicNodeLocalAssignVMs]
		if assigning != "" || started != "" || policy != "" || storedVMs != "" {
			startedAt, parseErr := time.Parse(time.RFC3339Nano, started)
			expired := started != "" && parseErr == nil &&
				!now.Before(startedAt.Add(nodeLoadBalancerPublicNodeLocalAssignTimeout))
			if expired {
				if copy.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
					// An unresolved relation receipt still owns this intent. Wait for
					// its bounded retirement instead of failing the Service.
					return false, &nodeLoadBalancerFirewallRelationPendingError{
						message:    "public-node-local: expired assignment authorization is waiting for its firewall relation receipt to resolve",
						retryAfter: nodeLoadBalancerRetry,
					}
				}
				// Nothing was dispatched under the expired intent, so renew it for the
				// current VM set rather than failing a Service that may be serving.
			} else {
				if assigning != edge.fenceValue() || policy != desired.Hash || storedVMs != vmSet || started == "" {
					return false, errors.New("public-node-local: durable firewall assignment authorization no longer matches the desired VM set")
				}
				if parseErr != nil {
					return false, fmt.Errorf("public-node-local: invalid assignment authorization timestamp: %w", parseErr)
				}
				return false, nil
			}
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] = edge.fenceValue()
		copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = now.Format(time.RFC3339Nano)
		copy.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
		copy.Annotations[annotationPublicNodeLocalAssignVMs] = vmSet
		return true, nil
	})
	if err != nil {
		return current, false, err
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) assignPublicNodeLocalFirewallWithFence(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewall *inspace.Firewall,
	addresses []nodeLoadBalancerAddress,
) error {
	if firewall == nil || !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
		!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, string(service.UID), c.provider.config.BillingAccountID) {
		return errors.New("public-node-local: refuse assignment without exact Service firewall ownership and policy")
	}
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.serviceFirewallRelationOwner(service),
		nil,
	)
	if err != nil || !converged {
		return err
	}
	assignments, err := nodeLoadBalancerFirewallVMAssignments(*firewall)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		if _, assigned := assignments[strings.ToLower(vmUUID)]; assigned {
			continue
		}
		var validateErr error
		if service.Annotations[annotationPublicNodeLocalActivePool] != "" {
			validateErr = c.validateActivePublicNodeLocalAssignState(ctx, service, intent, desired, perServiceEdgeID(firewall, desired.Hash), vmUUID)
		} else {
			validateErr = c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, perServiceEdgeID(firewall, desired.Hash), addresses, true, false)
		}
		if validateErr != nil {
			return validateErr
		}
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.serviceFirewallRelationOwner(service),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if errors.Is(relationErr, errNodeLoadBalancerFirewallRelationParked) {
			c.recordPublicNodeLocalStuckRelation(ctx, service, relationErr)
			continue
		}
		if relationErr != nil {
			return fmt.Errorf("public-node-local: assign firewall %s to VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		if !converged {
			return nil
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) validatePublicNodeLocalAssignmentState(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	addresses []nodeLoadBalancerAddress,
	requireFence, requirePublished bool,
) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return joinWithExplanation(errors.New("public-node-local: live Service contract changed during firewall assignment authorization"), err)
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != edge.fenceValue() ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return errors.New("public-node-local: live firewall ledger or policy changed during assignment authorization")
	}
	if requirePublished {
		if !reflect.DeepEqual(current.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, true)) {
			return errors.New("public-node-local: exact public Proxy status is required for final assignment-fence clearance")
		}
	} else if len(current.Status.LoadBalancer.Ingress) != 0 {
		return errors.New("public-node-local: public Proxy status must be empty during pre-publication firewall assignment authorization")
	}
	activePool := current.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := current.Annotations[annotationPublicNodeLocalActivePolicy]
	if (activePool == "") != (activePolicy == "") ||
		(activePool != "" && (activePool != intent.Pool || activePolicy != desired.Hash)) {
		return errors.New("public-node-local: persisted activation identity changed during assignment authorization")
	}
	if requirePublished && activePool == "" {
		return errors.New("public-node-local: exact activation identity is required for final assignment-fence clearance")
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("public-node-local: read private datapath during assignment authorization: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, intent.Pool) ||
		!reflect.DeepEqual(datapath.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, false)) {
		return errors.New("public-node-local: private datapath changed during firewall assignment authorization")
	}
	verified, _, err := c.publicNodeLocalAddresses(ctx, current, currentIntent)
	if err != nil || !reflect.DeepEqual(publicNodeLocalAddressIdentities(verified), publicNodeLocalAddressIdentities(addresses)) {
		return joinWithExplanation(errors.New("public-node-local: endpoint or Node eligibility changed during firewall assignment authorization"), err)
	}
	if requireFence {
		vmSet, vmErr := publicNodeLocalVMSet(addresses)
		if vmErr != nil {
			return vmErr
		}
		started := current.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		if current.Annotations[annotationNodeLoadBalancerFirewallAssigning] != edge.fenceValue() || started == "" ||
			current.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			current.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return errors.New("public-node-local: durable firewall assignment fence changed before the cloud mutation")
		}
		startedAt, err := time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return fmt.Errorf("public-node-local: invalid durable assignment timestamp: %w", err)
		}
		now := time.Now().UTC()
		if startedAt.After(now) || !now.Before(startedAt.Add(nodeLoadBalancerPublicNodeLocalAssignTimeout)) {
			return errors.New("public-node-local: durable firewall assignment fence is not fresh")
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, bool, error) {
	if err := c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, edge, addresses, true, true); err != nil {
		return service, false, err
	}
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil {
		return service, false, err
	}
	updated, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != edge.fenceValue() ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] == "" ||
			copy.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			copy.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return false, errors.New("public-node-local: assignment fence changed before exact readback clearance")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssigning)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssignAt)
		delete(copy.Annotations, annotationPublicNodeLocalAssignPolicy)
		delete(copy.Annotations, annotationPublicNodeLocalAssignVMs)
		return true, nil
	})
	return updated, changed, err
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalWithdrawalEvidenceAfterAssignment(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	addresses []nodeLoadBalancerAddress,
) (bool, error) {
	if len(addresses) == 0 {
		return false, errors.New("public-node-local: positive non-empty assignment proof is required to reset withdrawal evidence")
	}
	if err := c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, edge, addresses, true, false); err != nil {
		return false, err
	}
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil {
		return false, err
	}
	provedPairs := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !loadBalancerNodeEligible(address.Node) {
			return false, fmt.Errorf("public-node-local: Node %s is not eligible withdrawal recovery proof", address.Node.Name)
		}
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		provedPairs[edge.fenceValue()+"/"+vmUUID] = struct{}{}
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != edge.fenceValue() ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != edge.fenceValue() ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] == "" ||
			copy.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			copy.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return false, errors.New("public-node-local: positive assignment proof lost its exact Service identity")
		}
		changed := false
		for _, key := range []string{
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
		} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		storedSet := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach]
		storedAt := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt]
		if (storedSet == "") != (storedAt == "") {
			return false, errors.New("public-node-local: incomplete firewall withdrawal detach fence during recovery")
		}
		if storedSet == "" {
			return changed, nil
		}
		if err := validateNodeLoadBalancerFirewallDetachSet(storedSet); err != nil {
			return false, err
		}
		detachedAt, parseErr := parseNodeLoadBalancerFirewallDetachTimes(storedAt)
		if parseErr != nil {
			return false, parseErr
		}
		for pair := range provedPairs {
			if _, recorded := detachedAt[pair]; recorded {
				delete(detachedAt, pair)
				changed = true
			}
		}
		if len(detachedAt) == 0 {
			delete(copy.Annotations, annotationNodeLoadBalancerWithdrawFWDetach)
			delete(copy.Annotations, annotationNodeLoadBalancerWithdrawFWDetachAt)
			return changed, nil
		}
		if changed {
			encodedTimes, marshalErr := json.Marshal(detachedAt)
			if marshalErr != nil {
				return false, fmt.Errorf("public-node-local: encode retained firewall withdrawal timestamps: %w", marshalErr)
			}
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = nodeLoadBalancerFirewallDetachSetFromTimes(detachedAt)
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(encodedTimes)
		}
		return changed, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) publicNodeLocalFirewallAssignmentsMatch(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	nodes []*corev1.Node,
) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return false, joinWithExplanation(errors.New("public-node-local: live Service intent changed before firewall assignment readback"), err)
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != edge.fenceValue() ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return false, errors.New("public-node-local: firewall assignment readback is not bound to the exact current Service ledger and policy")
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		current.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		return false, nil
	}
	desiredVMs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			return false, fmt.Errorf("public-node-local: Node %s has no valid VM identity", node.Name)
		}
		desiredVMs[vmUUID] = struct{}{}
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	matches := 0
	for _, firewall := range items {
		if firewall.UUID != edge.fenceValue() {
			continue
		}
		matches++
		if !nodeLoadBalancerFirewallOwnedByService(firewall, c.provider.config.ClusterID, string(current.UID), c.provider.config.BillingAccountID) ||
			!nodeLoadBalancerFirewallMatches(firewall, desired) {
			return false, errors.New("public-node-local: current firewall lost exact Service ownership")
		}
		stale, err := staleNodeLoadBalancerFirewallAssignments(firewall, desiredVMs)
		if err != nil {
			return false, err
		}
		normalizedAssignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
		if err != nil {
			return false, err
		}
		if len(stale) != 0 || len(normalizedAssignments) != len(desiredVMs) {
			return false, nil
		}
	}
	if matches > 1 {
		return false, fmt.Errorf("public-node-local: firewall UUID %s appears multiple times", edge.fenceValue())
	}
	return matches == 1, nil
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalActivation(
	ctx context.Context,
	service *corev1.Service,
	pool, policy string,
) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		intent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		if parseErr != nil || intent.Mode != nodeLoadBalancerModeLocal || intent.Pool != pool ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != policy {
			return false, joinWithExplanation(errors.New("public-node-local: Service changed before activation persistence"), parseErr)
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if copy.Annotations[annotationPublicNodeLocalActivePool] == pool && copy.Annotations[annotationPublicNodeLocalActivePolicy] == policy {
			return false, nil
		}
		if copy.Annotations[annotationPublicNodeLocalActivePool] != "" || copy.Annotations[annotationPublicNodeLocalActivePolicy] != "" {
			return false, errors.New("public-node-local: another activation identity is still persisted")
		}
		copy.Annotations[annotationPublicNodeLocalActivePool] = pool
		copy.Annotations[annotationPublicNodeLocalActivePolicy] = policy
		setPublicNodeLocalActivePorts(copy)
		return true, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) validatePublicNodeLocalPublicationState(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	edge edgeID,
	addresses []nodeLoadBalancerAddress,
	requireActivation, requirePublished bool,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return nil, joinWithExplanation(errors.New("public-node-local: live Service intent changed at the publication gate"), err)
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != edge.fenceValue() ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return nil, errors.New("public-node-local: live firewall ledger or policy changed at the publication gate")
	}
	if requireActivation {
		if current.Annotations[annotationPublicNodeLocalActivePool] != intent.Pool ||
			current.Annotations[annotationPublicNodeLocalActivePolicy] != desired.Hash {
			return nil, errors.New("public-node-local: activation authorization changed at the publication gate")
		}
	} else if current.Annotations[annotationPublicNodeLocalActivePool] != "" ||
		current.Annotations[annotationPublicNodeLocalActivePolicy] != "" {
		return nil, errors.New("public-node-local: unexpected activation authorization at the pre-activation gate")
	}
	desiredPrivateStatus := nodeLoadBalancerStatus(addresses, false)
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("public-node-local: read private datapath at publication gate: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, intent.Pool) ||
		!reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		return nil, errors.New("public-node-local: private datapath spec or status changed at the publication gate")
	}
	verified, _, err := c.publicNodeLocalAddresses(ctx, current, currentIntent)
	if err != nil || !reflect.DeepEqual(publicNodeLocalAddressIdentities(verified), publicNodeLocalAddressIdentities(addresses)) {
		return nil, joinWithExplanation(errors.New("public-node-local: endpoint, Node, VM, or FIP proof changed at the publication gate"), err)
	}
	loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, current, currentIntent)
	if conflictErr != nil || loses || winnerWaiting {
		return nil, joinWithExplanation(errors.New("public-node-local: protocol/port ownership changed at the publication gate"), conflictErr)
	}
	nodes := make([]*corev1.Node, 0, len(addresses))
	for _, address := range addresses {
		nodes = append(nodes, address.Node)
	}
	assignmentsMatch, err := c.publicNodeLocalFirewallAssignmentsMatch(ctx, current, currentIntent, currentDesired, edge, nodes)
	if err != nil || !assignmentsMatch {
		return nil, joinWithExplanation(errors.New("public-node-local: exact firewall assignment proof changed at the publication gate"), err)
	}
	desiredPublicStatus := nodeLoadBalancerStatus(addresses, true)
	if requirePublished {
		if !reflect.DeepEqual(current.Status.LoadBalancer, desiredPublicStatus) {
			return nil, errors.New("public-node-local: public Proxy status did not read back exactly at the publication gate")
		}
	} else if len(current.Status.LoadBalancer.Ingress) != 0 &&
		!reflect.DeepEqual(current.Status.LoadBalancer, desiredPublicStatus) {
		return nil, errors.New("public-node-local: unexpected public status at the publication gate")
	}
	return current, nil
}

// updatePublicNodeLocalStatusBound deliberately uses the ResourceVersion from
// the fully validated parent read. Unlike a helper that re-GETs internally,
// this makes a concurrent selector/port/session edit conflict before status is
// published; the post-publication gate catches a change racing immediately
// after the update.
func (c *nodeLoadBalancerController) updatePublicNodeLocalStatusBound(
	ctx context.Context,
	service *corev1.Service,
	status corev1.LoadBalancerStatus,
) (*corev1.Service, bool, error) {
	if service == nil || service.UID == "" || service.ResourceVersion == "" {
		// The simple client-go fake does not assign ResourceVersions. Production
		// apiservers always do, while the exact object still provides UID fencing
		// for unit tests.
		if service == nil || service.UID == "" {
			return nil, false, errors.New("public-node-local: exact parent identity is required for bound status publication")
		}
	}
	if reflect.DeepEqual(service.Status.LoadBalancer, status) {
		return service, false, nil
	}
	copy := service.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, err
	}
	if updated.UID != service.UID || updated.Generation != service.Generation {
		return nil, false, errors.New("public-node-local: parent identity or generation changed during bound status publication")
	}
	return updated, true, nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalActivation(ctx context.Context, service *corev1.Service) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, key := range []string{
			annotationPublicNodeLocalActivePool,
			annotationPublicNodeLocalActivePolicy,
			annotationPublicNodeLocalTargetPool,
			annotationPublicNodeLocalTargetPolicy,
			annotationPublicNodeLocalActivePorts,
			annotationNodeLoadBalancerRebuildingAssigned,
			annotationPublicNodeLocalTargetSince,
			annotationPublicNodeLocalPromotedAt,
			annotationNodeLoadBalancerRebuilding,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
			annotationPublicNodeLocalAssignPolicy,
			annotationPublicNodeLocalAssignVMs,
		} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *nodeLoadBalancerController) detachPublicNodeLocalFirewalls(
	ctx context.Context,
	service *corev1.Service,
	nodes []*corev1.Node,
) error {
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	for index := range owned {
		if err := c.detachServiceFirewallFromOtherNodes(ctx, service, &owned[index], nodes); err != nil {
			return err
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalDatapathStatus(ctx context.Context, service *corev1.Service) error {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return errors.New("public-node-local: refuse to clear foreign datapath status")
	}
	if len(datapath.Status.LoadBalancer.Ingress) == 0 {
		return nil
	}
	copy := datapath.DeepCopy()
	copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	_, err = client.UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *nodeLoadBalancerController) withdrawPublicNodeLocal(ctx context.Context, service *corev1.Service) error {
	// The cloud firewall is the functional public edge. Close and positively
	// read it back before removing either Kubernetes status; otherwise a crash
	// can leave a FIP reaching a host listener after the private VIP vanished.
	proven, err := c.publicNodeLocalEdgeFor(service).WithdrawAll(ctx, service)
	if err != nil {
		return err
	}
	if !proven {
		return errors.New("public-node-local: waiting for exact Service firewall detachment readback")
	}
	if err := c.clearServiceLoadBalancerStatus(ctx, service); err != nil {
		return err
	}
	if err := c.clearPublicNodeLocalDatapathStatus(ctx, service); err != nil {
		return err
	}
	return c.clearPublicNodeLocalActivation(ctx, service)
}

func (c *nodeLoadBalancerController) failPublicNodeLocalClosed(ctx context.Context, service *corev1.Service, cause error) error {
	if deferral := deferOnTransientProviderError("public-node-local", cause); deferral != nil {
		return deferral
	}
	return errors.Join(cause, c.withdrawPublicNodeLocal(ctx, service))
}

const (
	publicNodeLocalReasonHolding           = "PublicNodeLocalHolding"
	publicNodeLocalReasonTransitionPending = "PublicNodeLocalTransitionPending"
	publicNodeLocalReasonRelationStuck     = "PublicNodeLocalFirewallRelationStuck"
	publicNodeLocalReasonHoldBackoff       = "PublicNodeLocalHoldBackoff"

	// publicNodeLocalHoldBackoffNotice is the repeat count at which the backoff
	// is announced.
	publicNodeLocalHoldBackoffNotice = 3

	// publicNodeLocalHoldBackoffMax caps the requeue delay of a hold whose cause
	// does not change.
	publicNodeLocalHoldBackoffMax = 5 * time.Minute

	// publicNodeLocalHoldEventRefresh is how often an unchanged hold Event is
	// rewritten.
	publicNodeLocalHoldEventRefresh = 5 * time.Minute
)

const publicNodeLocalReasonPerVMStatePresent = "PublicNodeLocalPerVMStatePresent"

// publicNodeLocalPerVMStatePresentError reports that a VM carries its own
// per-VM firewall while this controller does not run the per-VM mode. The
// Service holds and never touches that firewall.
type publicNodeLocalPerVMStatePresentError struct{ vmUUID, firewallUUID string }

func (e *publicNodeLocalPerVMStatePresentError) Error() string {
	return fmt.Sprintf("VM %s carries per-VM firewall %s but the per-VM firewall mode is not enabled; holding", e.vmUUID, e.firewallUUID)
}

// publicNodeLocalPerVMModeEnabled reports whether this controller owns per-VM
// firewalls. Until the mode flag exists it is always false.
func (c *nodeLoadBalancerController) publicNodeLocalPerVMModeEnabled() bool { return false }

// recordPublicNodeLocalStuckRelation makes a parked firewall relation visible.
func (c *nodeLoadBalancerController) recordPublicNodeLocalStuckRelation(ctx context.Context, service *corev1.Service, cause error) {
	if err := c.recordPublicNodeLocalHoldEvent(ctx, service, publicNodeLocalReasonRelationStuck, cause); err != nil {
		klog.Warningf("public-node-local %s/%s: record Event: %v", service.Namespace, service.Name, err)
	}
}

// holdOrFailPublicNodeLocal is the failure path for every cause that is not
// verified intent. A Service that is already serving keeps its last known good
// exposure and reports the cause; only a Service that exposes nothing yet
// fails closed. Transient provider causes defer, as before.
func (c *nodeLoadBalancerController) holdOrFailPublicNodeLocal(ctx context.Context, service *corev1.Service, cause error) error {
	if deferral := deferOnTransientProviderError("public-node-local", cause); deferral != nil {
		return deferral
	}
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if errors.As(cause, &pending) {
		// A bounded wait for cloud readback is not a fault, and withdrawing
		// while a relation receipt is unresolved would only add more fences.
		return cause
	}
	if service == nil || (service.Annotations[annotationPublicNodeLocalActivePool] == "" && len(service.Status.LoadBalancer.Ingress) == 0) {
		return c.failPublicNodeLocalClosed(ctx, service, cause)
	}
	holdReason := publicNodeLocalReasonHolding
	var perVMState *publicNodeLocalPerVMStatePresentError
	if errors.As(cause, &perVMState) {
		holdReason = publicNodeLocalReasonPerVMStatePresent
	}
	if eventErr := c.recordPublicNodeLocalHoldEvent(ctx, service, holdReason, cause); eventErr != nil {
		klog.Warningf("public-node-local %s/%s: record hold Event: %v", service.Namespace, service.Name, eventErr)
	}
	retryAfter, held := c.nextPublicNodeLocalHoldDelay(string(service.UID), cause)
	if held == publicNodeLocalHoldBackoffNotice {
		// One stable Event per repeating hold tells the operator it backs off.
		if eventErr := c.recordPublicNodeLocalHoldEvent(ctx, service, publicNodeLocalReasonHoldBackoff, fmt.Errorf(
			"public-node-local: the same hold repeats; retries back off up to %s: %w", publicNodeLocalHoldBackoffMax, cause)); eventErr != nil {
			klog.Warningf("public-node-local %s/%s: record backoff Event: %v", service.Namespace, service.Name, eventErr)
		}
	}
	return &errPublicNodeLocalHolding{cause: cause, retryAfter: retryAfter}
}

// publicNodeLocalCauseClass names the kind of a hold cause. It is stable across
// repeats of the same fault, unlike the cause text, which embeds UUIDs, names
// and timestamps.
func publicNodeLocalCauseClass(cause error) string {
	var pending *nodeLoadBalancerFirewallRelationPendingError
	var status *apierrors.StatusError
	var api *inspace.APIError
	var limit *FirewallLimitExceededError
	var perVMState *publicNodeLocalPerVMStatePresentError
	switch {
	case errors.As(cause, &perVMState):
		return "per-vm-state"
	case errors.As(cause, &limit):
		return "firewall-limit"
	case errors.Is(cause, errNodeLoadBalancerFirewallRelationParked):
		return "relation-parked"
	case errors.As(cause, &pending):
		return "relation-pending"
	case errors.As(cause, &status):
		return "kubernetes-api"
	case errors.As(cause, &api):
		return "provider-api"
	default:
		return "state"
	}
}

// recordPublicNodeLocalHoldEvent makes a hold visible on the Service. The Event
// name derives from the Service UID, the reason and a stable cause class, so a
// changing cause text updates one Event instead of creating a new one, and no
// Service annotation is written.
func (c *nodeLoadBalancerController) recordPublicNodeLocalHoldEvent(
	ctx context.Context,
	service *corev1.Service,
	reason string,
	cause error,
) error {
	if service == nil || cause == nil {
		return nil
	}
	message := cause.Error()
	if len(message) > 900 {
		message = message[:900] + "..."
	}
	now := metav1.Now()
	name := service.Name + "." + shortHash(string(service.UID)+"\x00"+reason+"\x00"+publicNodeLocalCauseClass(cause))
	client := c.provider.kubeClient.CoreV1().Events(service.Namespace)
	_, err := client.Create(ctx, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: service.Namespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1", Kind: "Service", Namespace: service.Namespace,
			Name: service.Name, UID: service.UID,
		},
		Reason:         reason,
		Message:        message,
		Source:         corev1.EventSource{Component: "inspace-cloud-controller-manager"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Type:           corev1.EventTypeWarning,
	}, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if existing.Message == message && now.Sub(existing.LastTimestamp.Time) < publicNodeLocalHoldEventRefresh {
		return nil
	}
	existing.Message = message
	existing.LastTimestamp = now
	existing.Count++
	_, err = client.Update(ctx, existing, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return err
}

func (c *nodeLoadBalancerController) cleanupPublicNodeLocal(ctx context.Context, key string, service *corev1.Service) error {
	if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
		return err
	}
	if err := c.deleteOwnedDatapathService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedDatapathServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if waiting, completed, err := c.resumeOwnedServiceFirewallDelete(ctx, service); err != nil || waiting {
		if waiting {
			c.requeuePublicNodeLocal(key)
		}
		return err
	} else if completed {
		service, err = c.getExactParentService(ctx, service)
		if err != nil {
			return err
		}
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	if len(owned) != 0 {
		if changed, err := c.clearFirewallAbsenceEvidence(
			ctx,
			service,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
		); err != nil || changed {
			return err
		}
	}
	if changed, err := c.preparePendingFirewallTeardown(ctx, service, owned); err != nil || changed {
		if changed {
			c.requeuePublicNodeLocal(key)
		}
		return err
	}
	for _, firewall := range owned {
		done, err := c.deleteOwnedServiceFirewall(ctx, service, firewall.UUID)
		if err != nil {
			return err
		}
		if !done {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}
	if len(owned) != 0 {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		if _, err := c.confirmPendingFirewallAbsent(ctx, service, metav1.Now().Time); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	// The pass that records the final spaced absence proof continues straight
	// to finalization; only an unfinished proof waits for the spacing delay.
	confirmedAbsent, _, err := c.recordFirewallAbsence(
		ctx,
		service,
		annotationNodeLoadBalancerCleanupFWAbsent,
		annotationNodeLoadBalancerCleanupFWChecked,
		time.Now().UTC(),
		time.Time{},
	)
	if err != nil {
		return err
	}
	if !confirmedAbsent {
		if c.queue != nil {
			c.queue.AddAfter(key, nodeLoadBalancerAbsenceConfirmationDelay)
		}
		return nil
	}
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp == nil && publicNodeLocalRequested(copy) {
			return false, errors.New("public-node-local: Service became active before finalization")
		}
		if len(copy.Status.LoadBalancer.Ingress) != 0 {
			return false, errors.New("public-node-local: public status remains during finalization")
		}
		if copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != "" ||
			copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" {
			return false, errors.New("public-node-local: refusing finalization while firewall deletion remains fenced")
		}
		changed := containsString(copy.Finalizers, publicNodeLocalFinalizer)
		copy.Finalizers = removeString(copy.Finalizers, publicNodeLocalFinalizer)
		for _, annotation := range []string{
			annotationPublicNodeLocalActivePool,
			annotationPublicNodeLocalActivePolicy,
			annotationPublicNodeLocalConflict,
			annotationNodeLoadBalancerFirewallUUID,
			annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
			annotationNodeLoadBalancerPendingFirewall,
			annotationNodeLoadBalancerPendingFWName,
			annotationNodeLoadBalancerPendingFWStarted,
			annotationNodeLoadBalancerPendingFWDelete,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
			annotationNodeLoadBalancerPreviousFirewall,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
			annotationNodeLoadBalancerWithdrawFWDetach,
			annotationNodeLoadBalancerWithdrawFWDetachAt,
			annotationPublicNodeLocalAssignPolicy,
			annotationPublicNodeLocalAssignVMs,
			annotationNodeLoadBalancerFWDeleteTarget,
			annotationNodeLoadBalancerFWDeleteIssued,
			annotationNodeLoadBalancerFirewallRelationRetired,
		} {
			if copy.Annotations[annotation] != "" {
				delete(copy.Annotations, annotation)
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

func publicNodeLocalStatusRemovesAddress(current, desired corev1.LoadBalancerStatus) bool {
	for _, existing := range current.Ingress {
		retained := false
		for _, wanted := range desired.Ingress {
			if reflect.DeepEqual(existing, wanted) {
				retained = true
				break
			}
		}
		if !retained {
			return true
		}
	}
	return false
}

func (c *nodeLoadBalancerController) requeuePublicNodeLocal(key string) {
	if c.queue != nil {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
	}
}

// errPublicNodeLocalHolding reports that a pass stopped on an error that is not
// verified intent, and that the last known good exposure was left in place.
type errPublicNodeLocalHolding struct {
	cause error
	// retryAfter is the requeue delay. Zero means the plain hold delay.
	retryAfter time.Duration
}

func (e *errPublicNodeLocalHolding) Error() string {
	return "public-node-local: holding the last known good exposure: " + e.cause.Error()
}

func (e *errPublicNodeLocalHolding) Unwrap() error { return e.cause }

// publicNodeLocalSiblingError marks a ledger or readiness fault of another
// Service's firewall found while auditing a shared VM.
type publicNodeLocalSiblingError struct {
	key   string
	cause error
}

func (e *publicNodeLocalSiblingError) Error() string { return e.cause.Error() }

func (e *publicNodeLocalSiblingError) Unwrap() error { return e.cause }

// publicNodeLocalHold is the in-memory record of a hold that repeats.
type publicNodeLocalHold struct {
	cause  string
	passes int
}

// nextPublicNodeLocalHoldDelay returns the requeue delay for a hold and how many
// consecutive passes ended in this same hold. The delay starts at the plain hold
// delay and doubles for every repeat up to publicNodeLocalHoldBackoffMax, so a
// state that never changes does not run a full VM audit every 10 seconds. A
// different cause starts over.
func (c *nodeLoadBalancerController) nextPublicNodeLocalHoldDelay(uid string, cause error) (time.Duration, int) {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	if c.holds == nil {
		c.holds = map[string]publicNodeLocalHold{}
	}
	hold := c.holds[uid]
	text := cause.Error()
	if hold.cause != text {
		hold = publicNodeLocalHold{cause: text}
	}
	hold.passes++
	c.holds[uid] = hold
	delay := nodeLoadBalancerRetry
	for repeat := 1; repeat < hold.passes && delay < publicNodeLocalHoldBackoffMax; repeat++ {
		delay *= 2
	}
	if delay > publicNodeLocalHoldBackoffMax {
		delay = publicNodeLocalHoldBackoffMax
	}
	return delay, hold.passes
}

func (c *nodeLoadBalancerController) resetPublicNodeLocalHold(uid string) {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	delete(c.holds, uid)
}
