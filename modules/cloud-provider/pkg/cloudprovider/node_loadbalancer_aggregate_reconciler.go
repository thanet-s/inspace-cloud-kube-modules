package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// sync reconciles the stable NodeLB design: one mutable public firewall per
// shard. The firewall is attached once to a Node and subsequently updated in
// place, so adding or removing a shared Service cannot flap an established VM.
func (c *nodeLoadBalancerController) sync(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	service, err := c.services.Services(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	service, err = c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: refresh exact parent Service: %w", err)
	}
	localRequested := publicNodeLocalRequested(service)
	hasLocalFinalizer := containsString(service.Finalizers, publicNodeLocalFinalizer)
	if hasLocalFinalizer && !localRequested {
		return c.syncPublicNodeLocal(ctx, key, service)
	}
	if hasLocalFinalizer || localRequested {
		// A mode transition must retire the old aggregate datapath before the
		// direct-node controller can attach a per-Service firewall. The two
		// ownership models are intentionally never active at the same time.
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			return c.cleanupAggregateService(ctx, service)
		}
		return c.syncPublicNodeLocal(ctx, key, service)
	}
	if service.DeletionTimestamp != nil || !isNodeLoadBalancerService(service) {
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			return c.cleanupAggregateService(ctx, service)
		}
		return nil
	}
	nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
	if err := c.validateAggregateClusterStateAnchor(ctx, nodeClassName); err != nil {
		return c.failAggregateClusterClosed(ctx, err)
	}
	if deleting, deletionErr := c.reconcileDeletingAggregateNodeClass(ctx, nodeClassName); deleting {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return errors.Join(deletionErr, c.failAggregateClusterClosed(ctx, deletionErr))
	}

	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	if _, err := parseNodeLoadBalancerService(service, defaults); err != nil {
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			return errors.Join(err, c.quarantineAggregateService(ctx, service))
		}
		return err
	}
	if shardName, ownershipErr := c.validateEstablishedAggregateShardAnchor(ctx, service); ownershipErr != nil {
		return c.failAggregateShardClosed(ctx, shardName, ownershipErr)
	}
	if previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]; previous != "" && service.Annotations[annotationNodeLoadBalancerDatapathActive] != previous {
		// A second edit can change the desired replacement while an already
		// closed previous shard is still retiring. Finish that durable cleanup
		// before planning/persisting another replacement; otherwise metadata
		// would deadlock at current=B, previous=A while the planner requests C.
		if service.Annotations[annotationNodeLoadBalancerDatapathStaged] == previous ||
			service.Annotations[annotationNodeLoadBalancerDatapathRestage] == previous {
			if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, true); err != nil {
				return err
			}
			service, err = c.getExactParentService(ctx, service)
			if err != nil {
				return err
			}
		}
		retired, retireErr := c.retireAggregatePreviousShard(ctx, service, previous)
		if retireErr != nil {
			return retireErr
		}
		if !retired {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
			return nil
		}
		service, err = c.getExactParentService(ctx, service)
		if err != nil {
			return err
		}
	}
	intent, plan, shard, err := c.planForService(ctx, service)
	if err != nil {
		return c.handleAggregatePlanningError(ctx, err)
	}
	if err := c.validateDatapathServiceName(ctx, service); err != nil {
		return err
	}
	if patched, err := c.ensureServiceMetadata(ctx, service, plan.Assignments[intent.ServiceID]); err != nil || patched {
		return err
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	currentPolicyHash, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		return errors.Join(err, c.quarantineAggregateService(ctx, service))
	}
	activeShard := service.Annotations[annotationNodeLoadBalancerDatapathActive]
	stagedShard := service.Annotations[annotationNodeLoadBalancerDatapathStaged]
	stagedPolicy := service.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy]
	restageShard := service.Annotations[annotationNodeLoadBalancerDatapathRestage]
	restagePolicy := service.Annotations[annotationNodeLoadBalancerDatapathRestagePolicy]
	stagingPairValid := (restageShard == "") == (restagePolicy == "")
	if activeShard != "" && activeShard != shard.Name {
		// A cross-shard move first closes and retires the old membership. The new
		// restage fence is persisted only after its own NodePool state anchor exists.
		if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, true); err != nil {
			return err
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	needsRestage := !stagingPairValid ||
		(stagedShard != "" && (stagedShard != shard.Name || stagedPolicy != currentPolicyHash)) ||
		(restageShard != "" && (restageShard != shard.Name || restagePolicy != currentPolicyHash)) ||
		(activeShard != "" && stagedShard == "" && restageShard == "")
	if needsRestage {
		if err := c.prepareAggregateServiceRestage(ctx, service, shard.Name, currentPolicyHash); err != nil {
			return err
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	firstBootstrap := activeShard == "" && stagedShard == "" && restageShard == ""
	if previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]; previous != "" && previous != shard.Name {
		retired, retireErr := c.retireAggregatePreviousShard(ctx, service, previous)
		if retireErr != nil {
			return retireErr
		}
		if !retired {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
			return nil
		}
		service, err = c.getExactParentService(ctx, service)
		if err != nil {
			return err
		}
	}

	deleting, deleteErr := c.reconcileDeletingAggregateNodePool(ctx, shard.Name)
	if deleting {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return errors.Join(deleteErr, c.failAggregateShardClosed(ctx, shard.Name, deleteErr))
	}
	if err := c.ensureNodeClass(ctx, nodeClassName); err != nil {
		return c.failAggregateClusterClosed(ctx, err)
	}
	if err := c.ensureNodePool(ctx, nodeClassName, shard); err != nil {
		return c.failAggregateShardClosed(ctx, shard.Name, err)
	}
	clusterNodes, err := c.authorizedNodesForCluster(ctx)
	if err != nil {
		return c.failAggregateClusterClosed(ctx, err)
	}
	icmpFirewall, icmpReady, err := c.ensureClusterICMPFirewall(ctx, nodeClassName, clusterNodes)
	if err != nil {
		return c.failAggregateClusterClosed(ctx, err)
	}
	if icmpFirewall == nil {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return c.failAggregateClusterClosed(ctx, nil)
	}
	if !icmpReady {
		// Keep nodes that were already advertised and still carry the exact ICMP
		// assignment. A new unadvertised VM may be attached without flapping every
		// established shard, while a ready VM whose assignment disappeared is
		// withdrawn before a later pass may repair it. Stop this pass so an attach
		// can never become advertise in the same crash window.
		fenceErr := c.fenceAggregateClusterICMPAssignmentGap(ctx, clusterNodes, *icmpFirewall)
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return fenceErr
	}
	if firstBootstrap {
		// First bootstrap follows the same closed restaging protocol as an edit,
		// but only after the durable NodePool state anchor and cluster ICMP policy
		// exist. The child remains status-empty throughout this pass.
		if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
			return err
		}
		if err := c.prepareAggregateServiceRestage(ctx, service, shard.Name, currentPolicyHash); err != nil {
			return err
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if service.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard.Name {
		// Recreate or repair a restaging child only while it is functionally
		// closed. This also recovers safely if the child was deleted mid-update.
		if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, false); err != nil {
			return err
		}
		if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
			return err
		}
	}

	state, policyErr := c.reconcileShardFirewallPolicy(ctx, shard.Name)
	if policyErr != nil && (state.Firewall == nil || state.AppliedHash == "") {
		return c.failAggregateShardClosed(ctx, shard.Name, policyErr)
	}
	if state.MutationIssued {
		// A cloud create/PUT must be followed by a fresh authoritative List before
		// any eligibility or Service status decision. In particular, an in-place
		// expansion may already be visible while the durable applied ledger still
		// names the old policy; established siblings remain untouched in this gap.
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return policyErr
	}
	if state.Firewall != nil && state.AppliedHash != "" && !state.AssignmentsReady {
		assignmentsReady, refreshed, assignmentErr := c.ensureShardFirewallAssignments(ctx, shard.Name, *state.Firewall)
		if refreshed != nil {
			state.Firewall = refreshed
		}
		state.AssignmentsReady = assignmentsReady
		policyErr = errors.Join(policyErr, assignmentErr)
	}
	// A staged/restaging Service always requires the aggregate firewall. Never
	// mark a Node eligible merely because the shared ICMP firewall is attached.
	requireFirewall := state.DesiredHash != "" || state.AppliedHash != "" ||
		service.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard.Name ||
		service.Annotations[annotationNodeLoadBalancerDatapathStaged] == shard.Name
	if requireFirewall && !state.AssignmentsReady {
		if state.Firewall == nil || !validNodeLoadBalancerShardFirewallPolicyHash(state.AppliedHash) {
			return c.failAggregateShardClosed(ctx, shard.Name, policyErr)
		}
		// Preserve already-protected siblings while holding every newly attached
		// VM closed until a later authoritative reconciliation. If an advertised
		// VM lost this assignment, only that shard's datapath is withdrawn.
		fenceErr := c.fenceAggregateShardFirewallAssignmentGap(ctx, shard.Name, *state.Firewall)
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return errors.Join(policyErr, fenceErr)
	}
	if err := c.reconcileAggregateShardNodeEligibility(ctx, shard.Name, state.Firewall, state.AppliedHash, requireFirewall); err != nil {
		return c.failAggregateShardClosed(ctx, shard.Name, errors.Join(policyErr, err))
	}
	addresses, err := c.readyShardAddresses(ctx, shard.Name)
	if err != nil {
		return c.failAggregateShardClosed(ctx, shard.Name, errors.Join(policyErr, err))
	}

	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return errors.Join(policyErr, err)
	}
	activeShard = service.Annotations[annotationNodeLoadBalancerDatapathActive]
	stagedShard = service.Annotations[annotationNodeLoadBalancerDatapathStaged]
	restageShard = service.Annotations[annotationNodeLoadBalancerDatapathRestage]
	if restageShard == shard.Name && (!state.covers(service) || !state.AssignmentsReady) {
		if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, false); err != nil {
			return errors.Join(policyErr, err)
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return policyErr
	}
	if restageShard == shard.Name && activeShard == "" {
		if len(addresses) < int(shard.NodesPerShard) {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
			return policyErr
		}
		if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
			return errors.Join(policyErr, err)
		}
		if _, err := c.authorizeDatapath(ctx, service, shard.Name, intent); err != nil {
			return errors.Join(policyErr, err)
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return policyErr
	}
	if restageShard == shard.Name && stagedShard == "" {
		if len(addresses) < int(shard.NodesPerShard) {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
			return policyErr
		}
		if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
			return errors.Join(policyErr, err)
		}
		service, err = c.publishDatapathStatus(ctx, service, shard.Name, intent, addresses)
		if err != nil {
			return errors.Join(policyErr, err)
		}
		if err := c.markAggregateDatapathStaged(ctx, service, shard.Name, currentPolicyHash); err != nil {
			return errors.Join(policyErr, err)
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return policyErr
	}

	// During an in-place policy expansion, already-applied siblings remain
	// published from the old exact ledger. A new or edited member stays private
	// until the aggregate PUT and assignment readback cover its current policy.
	if !state.covers(service) || !state.AssignmentsReady {
		if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, false); err != nil {
			return errors.Join(policyErr, err)
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return policyErr
	}
	if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
		return errors.Join(policyErr, err)
	}
	service, err = c.publishDatapathStatus(ctx, service, shard.Name, intent, addresses)
	if err != nil {
		return errors.Join(policyErr, err)
	}
	service, err = c.publishPublicProxyStatus(ctx, service, shard.Name, intent, addresses)
	if err != nil {
		return errors.Join(policyErr, err)
	}
	converged, err := c.datapathStatusesMatch(ctx, service, shard.Name, addresses)
	if err != nil || !converged {
		return errors.Join(policyErr, err, errors.New("node load balancer: aggregate shard datapath status failed exact readback"))
	}
	if len(addresses) < int(shard.NodesPerShard) {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
	}
	return policyErr
}

// validateAggregateClusterStateAnchor prevents a lost generated NodeClass from
// being treated as a fresh bootstrap while its cluster ICMP firewall ledger may
// still own paid cloud state. Every finalized Service receives this handoff;
// therefore one surviving unproven marker is enough to require the exact live
// NodeClass and its state finalizer before any create can run.
func (c *nodeLoadBalancerController) validateAggregateClusterStateAnchor(
	ctx context.Context,
	name string,
) error {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: list Services for cluster state anchor: %w", err)
	}
	required := false
	for index := range services.Items {
		service := &services.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		if service.Annotations[annotationNodeLoadBalancerClusterStateMaterial] == "true" &&
			service.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "true" {
			required = true
			break
		}
	}
	if !required {
		return nil
	}
	nodeClass, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: get materialized cluster state anchor %s: %w", name, err)
	}
	labels := nodeClass.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		!containsString(nodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return fmt.Errorf("node load balancer: materialized cluster state anchor %s lost exact ownership", name)
	}
	return nil
}

// handleAggregatePlanningError mutates state only when the planner attached
// authoritative provenance to the failure. Cluster/API failures remain
// mutation-free, an exact Service fault quarantines only that Service, and a
// cross-Service port conflict closes the affected shard.
func (c *nodeLoadBalancerController) handleAggregatePlanningError(ctx context.Context, planningErr error) error {
	var serviceFault *nodeLoadBalancerPlanningServiceError
	if errors.As(planningErr, &serviceFault) && serviceFault.Service != nil {
		current, currentErr := c.getExactParentService(ctx, serviceFault.Service)
		if currentErr != nil {
			return errors.Join(planningErr, currentErr)
		}
		// Planning is based on an authoritative live List, but a user may repair
		// the Service or its child immediately afterward. Re-run the complete
		// read-only plan and mutate only when it attributes the current failure to
		// the same UID again; stale informer/API observations can never withdraw a
		// newly healthy sibling.
		_, _, _, auditErr := c.planForService(ctx, current)
		var confirmed *nodeLoadBalancerPlanningServiceError
		if !errors.As(auditErr, &confirmed) || confirmed.Service == nil ||
			confirmed.Service.Namespace != current.Namespace || confirmed.Service.Name != current.Name ||
			confirmed.Service.UID != current.UID {
			if auditErr == nil {
				auditErr = errors.New("node load balancer: planning Service fault was repaired before quarantine")
			}
			return errors.Join(planningErr, auditErr)
		}
		return errors.Join(planningErr, c.quarantineAggregateService(ctx, current))
	}
	var shardFault *nodeLoadBalancerPlanningShardError
	if errors.As(planningErr, &shardFault) {
		return c.failAggregateShardClosed(ctx, shardFault.Shard, planningErr)
	}
	return planningErr
}

func (c *nodeLoadBalancerController) validateEstablishedAggregateShardAnchor(
	ctx context.Context,
	service *corev1.Service,
) (string, error) {
	if service == nil {
		return "", nil
	}
	materialized, err := aggregateUnprovenMaterializedShards(service)
	if err != nil {
		return "", err
	}
	explicit := map[string]struct{}{}
	for _, candidate := range []string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
		service.Annotations[annotationNodeLoadBalancerDatapathStaged],
		service.Annotations[annotationNodeLoadBalancerDatapathRestage],
	} {
		if isManagedNodeLoadBalancerShardName(candidate) {
			explicit[candidate] = struct{}{}
		}
	}
	for _, candidate := range materialized {
		if _, ok := explicit[candidate]; !ok {
			return candidate, fmt.Errorf(
				"node load balancer: materialized shard %s lost every explicit Service reference",
				candidate,
			)
		}
	}
	shard := service.Annotations[annotationNodeLoadBalancerShard]
	anchorShard := shard
	if active := service.Annotations[annotationNodeLoadBalancerDatapathActive]; active != "" {
		anchorShard = active
	} else if restaging := service.Annotations[annotationNodeLoadBalancerDatapathRestage]; restaging != "" {
		anchorShard = restaging
	} else if staged := service.Annotations[annotationNodeLoadBalancerDatapathStaged]; staged != "" {
		anchorShard = staged
	}
	established := service.Annotations[annotationNodeLoadBalancerDatapathActive] != "" ||
		service.Annotations[annotationNodeLoadBalancerDatapathStaged] != "" ||
		service.Annotations[annotationNodeLoadBalancerDatapathRestage] != "" ||
		len(service.Status.LoadBalancer.Ingress) != 0 ||
		(aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], shard) &&
			!aggregateShardCleanupWasProven(service.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard))
	if !established {
		return shard, nil
	}
	if !isManagedNodeLoadBalancerShardName(anchorShard) {
		return anchorShard, fmt.Errorf("node load balancer: established Service has invalid state-anchor shard %q", anchorShard)
	}
	pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, anchorShard, metav1.GetOptions{})
	if err != nil {
		return anchorShard, fmt.Errorf("node load balancer: get established shard anchor %s: %w", anchorShard, err)
	}
	labels := pool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != anchorShard {
		return anchorShard, fmt.Errorf("node load balancer: established shard %s lacks exact state-anchor ownership", anchorShard)
	}
	if !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		if pool.GetDeletionTimestamp() != nil {
			return anchorShard, fmt.Errorf("node load balancer: deleting established shard %s lost its state finalizer", anchorShard)
		}
		updated := pool.DeepCopy()
		updated.SetFinalizers(append(updated.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
		if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return anchorShard, fmt.Errorf("node load balancer: backfill established shard %s state finalizer: %w", anchorShard, err)
		}
	}
	verified, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, anchorShard, metav1.GetOptions{})
	if err != nil {
		return anchorShard, fmt.Errorf("node load balancer: read back established shard %s state finalizer: %w", anchorShard, err)
	}
	verifiedLabels := verified.GetLabels()
	if verifiedLabels[nodeLoadBalancerManagedLabel] != "true" ||
		verifiedLabels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		verifiedLabels[nodeLoadBalancerShardLabel] != anchorShard ||
		!containsString(verified.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return anchorShard, fmt.Errorf("node load balancer: established shard %s failed exact state-anchor readback", anchorShard)
	}
	if err := c.markAggregateShardStateMaterializedForReferences(ctx, anchorShard); err != nil {
		return anchorShard, err
	}
	return anchorShard, nil
}

// reconcileDeletingAggregateNodeClass turns an external deletion request into
// a fail-closed cluster reset. The NodeClass finalizer retains the shared ICMP
// transaction ledger until every shard is drained and cloud absence is proven.
func (c *nodeLoadBalancerController) reconcileDeletingAggregateNodeClass(
	ctx context.Context,
	name string,
) (bool, error) {
	resource := c.provider.dynamicClient.Resource(nodeClassGVR)
	nodeClass, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if nodeClass.GetDeletionTimestamp() == nil {
		return false, nil
	}
	labels := nodeClass.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		!containsString(nodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return true, fmt.Errorf("node load balancer: deleting NodeClass %s lost its exact cluster-state identity", name)
	}
	waiting, err := c.cleanupRemainingClusterNodeLoadBalancerCapacity(ctx)
	if err != nil || waiting {
		return true, err
	}
	done, err := c.cleanupClusterICMPFirewall(ctx, name)
	if err != nil || !done {
		return true, err
	}
	if err := c.markAggregateClusterCleanupProvenForReferences(ctx); err != nil {
		return true, err
	}
	return true, c.removeManagedNodeClassStateFinalizer(ctx, name)
}

// reconcileDeletingAggregateNodePool drains a user-initiated NodePool deletion
// through the same durable firewall cleanup as normal last-owner teardown. The
// CCM finalizer permanently retains an unresolved create ledger; for an exact
// observed resource, it remains until spaced absence reads prove cleanup.
func (c *nodeLoadBalancerController) reconcileDeletingAggregateNodePool(
	ctx context.Context,
	shard string,
) (bool, error) {
	pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pool.GetDeletionTimestamp() == nil {
		return false, nil
	}
	labels := pool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return true, fmt.Errorf("node load balancer: deleting NodePool %s lost its exact state-anchor identity", shard)
	}
	// A user or another controller may have started deletion with background
	// propagation. Reissue the exact UID-fenced delete as foreground before
	// waiting for capacity: blockOwnerDeletion NodeClaims otherwise cannot be
	// collected while our durable state finalizer retains the NodePool.
	if err := c.deleteManagedNodePool(ctx, shard); err != nil {
		return true, err
	}
	absent, err := c.managedShardCapacityAbsent(ctx, shard)
	if err != nil || !absent {
		return true, err
	}
	cloudAbsent, err := c.deleteAggregateShardFirewall(ctx, shard)
	if err != nil || !cloudAbsent {
		return true, err
	}
	if err := c.resetAggregateShardAfterAnchorDeletion(ctx, shard); err != nil {
		return true, err
	}
	if err := c.markAggregateShardCleanupProvenForReferences(ctx, shard); err != nil {
		return true, err
	}
	return true, c.removeManagedNodePoolStateFinalizer(ctx, shard)
}

func (c *nodeLoadBalancerController) resetAggregateShardAfterAnchorDeletion(ctx context.Context, shard string) error {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range services.Items {
		service := &services.Items[index]
		if service.DeletionTimestamp != nil || !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		if service.Annotations[annotationNodeLoadBalancerShard] == shard ||
			service.Annotations[annotationNodeLoadBalancerDatapathActive] == shard ||
			service.Annotations[annotationNodeLoadBalancerDatapathStaged] == shard ||
			service.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard {
			result = errors.Join(result, c.clearAggregateServiceDatapath(ctx, service, true))
		}
	}
	return result
}

func (c *nodeLoadBalancerController) markAggregateDatapathStaged(
	ctx context.Context,
	service *corev1.Service,
	shard, policyHash string,
) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerDatapathActive] != shard {
			return false, errors.New("node load balancer: datapath authorization changed before staging")
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if copy.Annotations[annotationNodeLoadBalancerDatapathRestage] != shard ||
			copy.Annotations[annotationNodeLoadBalancerDatapathRestagePolicy] != policyHash {
			return false, errors.New("node load balancer: restaging policy changed before datapath publication")
		}
		copy.Annotations[annotationNodeLoadBalancerDatapathStaged] = shard
		copy.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy] = policyHash
		delete(copy.Annotations, annotationNodeLoadBalancerDatapathRestage)
		delete(copy.Annotations, annotationNodeLoadBalancerDatapathRestagePolicy)
		return true, nil
	})
	return err
}

// prepareAggregateServiceRestage closes the functional child before it records
// the replacement policy. The restage annotations then keep the exact new rule
// in the aggregate ledger while the private VIP remains empty.
func (c *nodeLoadBalancerController) prepareAggregateServiceRestage(
	ctx context.Context,
	service *corev1.Service,
	shard, policyHash string,
) error {
	if !isManagedNodeLoadBalancerShardName(shard) || len(policyHash) != 64 {
		return errors.New("node load balancer: invalid aggregate restage identity")
	}
	if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, false); err != nil {
		return err
	}
	if _, err := c.ensureDatapathService(ctx, service, shard); err != nil {
		return err
	}
	if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, true); err != nil {
		return err
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) ||
			copy.Annotations[annotationNodeLoadBalancerShard] != shard {
			return false, errors.New("node load balancer: Service changed before restage fence persistence")
		}
		if len(copy.Status.LoadBalancer.Ingress) != 0 {
			return false, errors.New("node load balancer: public status remains before restage fence persistence")
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if copy.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard &&
			copy.Annotations[annotationNodeLoadBalancerDatapathRestagePolicy] == policyHash {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerDatapathRestage] = shard
		copy.Annotations[annotationNodeLoadBalancerDatapathRestagePolicy] = policyHash
		return true, nil
	})
	return err
}

// clearAggregateServiceDatapath withdraws Cilium and informational status but
// intentionally never mutates a shard firewall assignment.
func (c *nodeLoadBalancerController) clearAggregateServiceDatapath(
	ctx context.Context,
	service *corev1.Service,
	clearMarkers bool,
) error {
	if service == nil {
		return nil
	}
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	child, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx,
		nodeLoadBalancerDatapathName(current),
		metav1.GetOptions{},
	)
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(child, current) {
			return fmt.Errorf("node load balancer: refusing to withdraw foreign datapath Service %s/%s", child.Namespace, child.Name)
		}
		if len(child.Status.LoadBalancer.Ingress) != 0 {
			copy := child.DeepCopy()
			copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
			if _, err := c.provider.kubeClient.CoreV1().Services(child.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("node load balancer: clear aggregate datapath status: %w", err)
			}
		}
		verified, readErr := c.provider.kubeClient.CoreV1().Services(child.Namespace).Get(ctx, child.Name, metav1.GetOptions{})
		if readErr != nil {
			return fmt.Errorf("node load balancer: read back aggregate datapath withdrawal: %w", readErr)
		}
		if !nodeLoadBalancerDatapathOwnedByService(verified, current) || len(verified.Status.LoadBalancer.Ingress) != 0 {
			return errors.New("node load balancer: aggregate datapath withdrawal did not read back exactly")
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	// Parent status is informational. Clear it only after the functional Cilium
	// child has read back empty, so a crash never reports closed while traffic is
	// still live.
	if err := c.clearServiceLoadBalancerStatus(ctx, current); err != nil {
		return err
	}
	current, err = c.getExactParentService(ctx, current)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(current.Status.LoadBalancer.Ingress) != 0 {
		return errors.New("node load balancer: public status withdrawal did not read back exactly")
	}
	if !clearMarkers {
		return nil
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, annotation := range []string{
			annotationNodeLoadBalancerDatapathActive,
			annotationNodeLoadBalancerDatapathStaged,
			annotationNodeLoadBalancerDatapathStagedPolicy,
			annotationNodeLoadBalancerDatapathRestage,
			annotationNodeLoadBalancerDatapathRestagePolicy,
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

// clearAggregateServiceDatapathFailClosed is the top-level withdrawal fence.
// If the functional child changes ownership (or any other withdrawal readback
// fails), its public status cannot be mutated safely. Remove eligibility from
// every referenced shard first so the foreign/stale child cannot remain a live
// route while reconciliation retries. Internal shard-withdrawal loops call the
// raw helper directly to avoid recursive fail-close attempts.
func (c *nodeLoadBalancerController) clearAggregateServiceDatapathFailClosed(
	ctx context.Context,
	service *corev1.Service,
	clearMarkers bool,
) error {
	err := c.clearAggregateServiceDatapath(ctx, service, clearMarkers)
	if err == nil {
		return nil
	}
	return errors.Join(err, c.failAggregateServiceReferencedShards(ctx, service))
}

func (c *nodeLoadBalancerController) withdrawAggregateShardStatuses(ctx context.Context, shard string) error {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range services.Items {
		service := &services.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		if aggregateServiceReferencesShard(service, shard) {
			result = errors.Join(result, c.clearAggregateServiceDatapath(ctx, service, false))
		}
	}
	return result
}

func (c *nodeLoadBalancerController) failAggregateServiceReferencedShards(
	ctx context.Context,
	service *corev1.Service,
) error {
	seen := map[string]struct{}{}
	materialized, markerErr := aggregateUnprovenMaterializedShards(service)
	result := markerErr
	shards := append([]string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
		service.Annotations[annotationNodeLoadBalancerDatapathStaged],
		service.Annotations[annotationNodeLoadBalancerDatapathRestage],
	}, materialized...)
	for _, shard := range shards {
		if !isManagedNodeLoadBalancerShardName(shard) {
			continue
		}
		if _, duplicate := seen[shard]; duplicate {
			continue
		}
		seen[shard] = struct{}{}
		result = errors.Join(result, c.failAggregateShardClosed(ctx, shard, nil))
	}
	return result
}

func (c *nodeLoadBalancerController) failAggregateShardClosed(ctx context.Context, shard string, cause error) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return cause
	}
	nodes, nodeErr := c.rawNodesForShard(ctx, shard)
	if nodeErr == nil {
		nodeErr = c.setShardNodesReady(ctx, nodes, nil)
	}
	return errors.Join(cause, nodeErr, c.withdrawAggregateShardStatuses(ctx, shard))
}

func (c *nodeLoadBalancerController) failAggregateClusterClosed(ctx context.Context, cause error) error {
	nodes, nodeErr := c.rawNodesForCluster(ctx)
	if nodeErr == nil {
		nodeErr = c.setShardNodesReady(ctx, nodes, nil)
	}
	services, listErr := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	result := errors.Join(cause, nodeErr, listErr)
	if listErr == nil {
		for index := range services.Items {
			service := &services.Items[index]
			if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
				result = errors.Join(result, c.clearAggregateServiceDatapath(ctx, service, false))
			}
		}
	}
	return result
}

// fenceAggregateClusterICMPAssignmentGap preserves only nodes that were
// already advertised and are covered by the pre-mutation ICMP snapshot. It
// never promotes a new node. Established shards therefore remain live while a
// surge/replacement VM is attached, but an externally detached ready VM is
// removed from Cilium eligibility and its shard statuses are withdrawn.
func (c *nodeLoadBalancerController) fenceAggregateClusterICMPAssignmentGap(
	ctx context.Context,
	authorized []*corev1.Node,
	firewall inspace.Firewall,
) error {
	raw, err := c.rawNodesForCluster(ctx)
	if err != nil {
		return err
	}
	authorizedByName := make(map[string]*corev1.Node, len(authorized))
	for _, node := range authorized {
		authorizedByName[node.Name] = node
	}
	keep := make(map[string]bool, len(raw))
	affectedShards := map[string]struct{}{}
	for _, node := range raw {
		wasReady := node.Labels[nodeLoadBalancerReadyLabel] == "true"
		candidate := authorizedByName[node.Name]
		eligible := false
		if wasReady && candidate != nil && candidate.Spec.ProviderID == node.Spec.ProviderID {
			if vmUUID, ok := nodeLoadBalancerVMUUID(candidate); ok {
				eligible = firewallAssignedToVM(firewall, vmUUID)
			}
		}
		keep[node.Name] = eligible
		if wasReady && !eligible {
			if shard := node.Labels[nodeLoadBalancerNodeShardLabel]; isManagedNodeLoadBalancerShardName(shard) {
				affectedShards[shard] = struct{}{}
			}
		}
	}
	result := c.setShardNodesReady(ctx, raw, keep)
	shards := make([]string, 0, len(affectedShards))
	for shard := range affectedShards {
		shards = append(shards, shard)
	}
	sort.Strings(shards)
	for _, shard := range shards {
		result = errors.Join(result, c.withdrawAggregateShardStatuses(ctx, shard))
	}
	return result
}

// fenceAggregateShardFirewallAssignmentGap is the per-shard counterpart of
// the cluster ICMP fence. The supplied firewall is the authoritative snapshot
// observed before any attach in this pass, so a fresh VM cannot be advertised
// from the mutation's immediate read-your-write response.
func (c *nodeLoadBalancerController) fenceAggregateShardFirewallAssignmentGap(
	ctx context.Context,
	shard string,
	firewall inspace.Firewall,
) error {
	raw, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return err
	}
	authorized, err := c.authorizedNodeLoadBalancerNodes(ctx, raw, shard)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, raw, nil), c.withdrawAggregateShardStatuses(ctx, shard))
	}
	authorizedByName := make(map[string]*corev1.Node, len(authorized))
	for _, node := range authorized {
		authorizedByName[node.Name] = node
	}
	keep := make(map[string]bool, len(raw))
	affected := false
	for _, node := range raw {
		wasReady := node.Labels[nodeLoadBalancerReadyLabel] == "true"
		candidate := authorizedByName[node.Name]
		eligible := false
		if wasReady && candidate != nil && candidate.Spec.ProviderID == node.Spec.ProviderID {
			if vmUUID, ok := nodeLoadBalancerVMUUID(candidate); ok {
				eligible = firewallAssignedToVM(firewall, vmUUID)
			}
		}
		keep[node.Name] = eligible
		affected = affected || (wasReady && !eligible)
	}
	result := c.setShardNodesReady(ctx, raw, keep)
	if affected {
		result = errors.Join(result, c.withdrawAggregateShardStatuses(ctx, shard))
	}
	return result
}

func (c *nodeLoadBalancerController) quarantineAggregateService(ctx context.Context, service *corev1.Service) error {
	shardSet := map[string]struct{}{}
	materialized, markerErr := aggregateUnprovenMaterializedShards(service)
	if markerErr != nil {
		return errors.Join(markerErr, c.clearAggregateServiceDatapathFailClosed(ctx, service, true))
	}
	shardsToAdd := append([]string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
		service.Annotations[annotationNodeLoadBalancerDatapathStaged],
		service.Annotations[annotationNodeLoadBalancerDatapathRestage],
	}, materialized...)
	for _, shard := range shardsToAdd {
		if isManagedNodeLoadBalancerShardName(shard) {
			shardSet[shard] = struct{}{}
		}
	}
	if err := c.clearAggregateServiceDatapathFailClosed(ctx, service, true); err != nil {
		return err
	}
	if err := c.deleteOwnedDatapathService(ctx, service); err != nil {
		return errors.Join(err, c.failAggregateServiceReferencedShards(ctx, service))
	}
	var result error
	shards := make([]string, 0, len(shardSet))
	for shard := range shardSet {
		shards = append(shards, shard)
	}
	sort.Strings(shards)
	for _, shard := range shards {
		other, ownerErr := c.aggregateShardHasOtherOwner(ctx, service, shard)
		if ownerErr != nil {
			result = errors.Join(result, ownerErr)
			continue
		}
		if other {
			state, reconcileErr := c.reconcileShardFirewallPolicy(ctx, shard)
			if reconcileErr == nil && ledgerContainsNodeLoadBalancerService(state.AppliedLedger, string(service.UID)) {
				reconcileErr = errors.New("node load balancer: invalid Service remains in aggregate firewall ledger")
			}
			result = errors.Join(result, reconcileErr)
			continue
		}
		current, exactErr := c.getExactParentService(ctx, service)
		if exactErr == nil && aggregateShardCleanupWasProven(current.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
			continue
		}
		if exactErr != nil && !apierrors.IsNotFound(exactErr) {
			result = errors.Join(result, exactErr)
			continue
		}
		if _, getErr := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); apierrors.IsNotFound(getErr) {
			result = errors.Join(result, fmt.Errorf(
				"node load balancer: quarantined shard %s disappeared without persisted firewall-cleanup proof",
				shard,
			))
			continue
		} else if getErr != nil {
			result = errors.Join(result, getErr)
			continue
		}
		nodes, nodeErr := c.rawNodesForShard(ctx, shard)
		if nodeErr == nil {
			nodeErr = c.setShardNodesReady(ctx, nodes, nil)
		}
		if nodeErr != nil {
			result = errors.Join(result, nodeErr)
			continue
		}
		if deleteErr := c.deleteManagedNodePool(ctx, shard); deleteErr != nil {
			result = errors.Join(result, deleteErr)
			continue
		}
		absent, absentErr := c.managedShardCapacityAbsent(ctx, shard)
		if absentErr != nil || !absent {
			result = errors.Join(result, absentErr)
			continue
		}
		firewallAbsent, firewallErr := c.deleteAggregateShardFirewall(ctx, shard)
		if firewallErr != nil || !firewallAbsent {
			result = errors.Join(result, firewallErr)
			continue
		}
		if proofErr := c.markAggregateShardCleanupProvenForReferences(ctx, shard); proofErr != nil {
			result = errors.Join(result, proofErr)
			continue
		}
		if finalizerErr := c.removeManagedNodePoolStateFinalizer(ctx, shard); finalizerErr != nil {
			result = errors.Join(result, finalizerErr)
		}
	}
	return result
}

func ledgerContainsNodeLoadBalancerService(encoded, uid string) bool {
	members, err := parseNodeLoadBalancerShardFirewallLedger(encoded)
	return err == nil && members[uid] != ""
}

func (c *nodeLoadBalancerController) markAggregateShardCleanupProven(
	ctx context.Context,
	service *corev1.Service,
	shard string,
) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return fmt.Errorf("node load balancer: invalid proven-cleanup shard %q", shard)
	}
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		encoded := copy.Annotations[annotationNodeLoadBalancerShardCleanupProven]
		if aggregateShardCleanupWasProven(encoded, shard) {
			return false, nil
		}
		proofs := strings.FieldsFunc(encoded, func(r rune) bool { return r == ',' })
		proofs = append(proofs, shard)
		sort.Strings(proofs)
		copy.Annotations[annotationNodeLoadBalancerShardCleanupProven] = strings.Join(proofs, ",")
		return true, nil
	})
	return err
}

func (c *nodeLoadBalancerController) markAggregateShardStateMaterialized(
	ctx context.Context,
	service *corev1.Service,
	shard string,
) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return fmt.Errorf("node load balancer: invalid materialized shard %q", shard)
	}
	updated, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		encoded := copy.Annotations[annotationNodeLoadBalancerShardStateMaterial]
		changed := false
		if !aggregateShardSetContains(encoded, shard) {
			copy.Annotations[annotationNodeLoadBalancerShardStateMaterial] = appendAggregateShardSet(encoded, shard)
			changed = true
		}
		// A live exact anchor supersedes any cleanup proof left from an earlier
		// incarnation of the same deterministic shard name.
		if aggregateShardCleanupWasProven(copy.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
			clearAggregateShardCleanupProof(copy.Annotations, shard)
			changed = true
		}
		return changed, nil
	})
	if err != nil {
		return err
	}
	verified, err := c.getExactParentService(ctx, updated)
	if err != nil {
		return err
	}
	if !aggregateShardStateWasMaterialized(verified.Annotations[annotationNodeLoadBalancerShardStateMaterial], shard) ||
		aggregateShardCleanupWasProven(verified.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
		return fmt.Errorf("node load balancer: shard %s materialization handoff failed exact Service readback", shard)
	}
	return nil
}

func aggregateShardCleanupWasProven(encoded, shard string) bool {
	return aggregateShardSetContains(encoded, shard)
}

func aggregateShardStateWasMaterialized(encoded, shard string) bool {
	return aggregateShardSetContains(encoded, shard)
}

func aggregateUnprovenMaterializedShards(service *corev1.Service) ([]string, error) {
	if service == nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, shard := range strings.Split(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], ",") {
		if shard == "" {
			continue
		}
		if !isManagedNodeLoadBalancerShardName(shard) {
			return nil, fmt.Errorf("node load balancer: invalid materialized shard identity %q", shard)
		}
		if aggregateShardCleanupWasProven(service.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
			continue
		}
		if _, duplicate := seen[shard]; duplicate {
			continue
		}
		seen[shard] = struct{}{}
		result = append(result, shard)
	}
	sort.Strings(result)
	return result, nil
}

func aggregateShardSetContains(encoded, shard string) bool {
	for _, candidate := range strings.Split(encoded, ",") {
		if candidate == shard {
			return true
		}
	}
	return false
}

func appendAggregateShardSet(encoded, shard string) string {
	values := make([]string, 0)
	for _, candidate := range strings.Split(encoded, ",") {
		if candidate != "" && candidate != shard {
			values = append(values, candidate)
		}
	}
	values = append(values, shard)
	sort.Strings(values)
	return strings.Join(values, ",")
}

func clearAggregateShardCleanupProof(annotations map[string]string, shard string) {
	clearAggregateShardSet(annotations, annotationNodeLoadBalancerShardCleanupProven, shard)
}

func clearAggregateShardMaterialization(annotations map[string]string, shard string) {
	clearAggregateShardSet(annotations, annotationNodeLoadBalancerShardStateMaterial, shard)
}

func clearAggregateShardSet(annotations map[string]string, key, shard string) {
	retained := make([]string, 0)
	for _, candidate := range strings.Split(annotations[key], ",") {
		if candidate != "" && candidate != shard {
			retained = append(retained, candidate)
		}
	}
	if len(retained) == 0 {
		delete(annotations, key)
		return
	}
	sort.Strings(retained)
	annotations[key] = strings.Join(retained, ",")
}

func (c *nodeLoadBalancerController) markAggregateClusterCleanupProvenForReferences(ctx context.Context) error {
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range list.Items {
		service := &list.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		_, _, updateErr := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations == nil {
				copy.Annotations = map[string]string{}
			}
			if copy.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "true" {
				return false, nil
			}
			copy.Annotations[annotationNodeLoadBalancerClusterCleanupProven] = "true"
			return true, nil
		})
		result = errors.Join(result, updateErr)
	}
	return result
}

func (c *nodeLoadBalancerController) markAggregateClusterStateMaterializedForReferences(ctx context.Context) error {
	if c == nil || c.provider == nil || c.provider.kubeClient == nil {
		return nil
	}
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range list.Items {
		service := &list.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		_, _, updateErr := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations == nil {
				copy.Annotations = map[string]string{}
			}
			if copy.Annotations[annotationNodeLoadBalancerClusterStateMaterial] == "true" {
				return false, nil
			}
			copy.Annotations[annotationNodeLoadBalancerClusterStateMaterial] = "true"
			return true, nil
		})
		result = errors.Join(result, updateErr)
	}
	return result
}

func (c *nodeLoadBalancerController) clearAggregateClusterCleanupProofs(ctx context.Context) error {
	if c == nil || c.provider == nil || c.provider.kubeClient == nil {
		// Narrow helper/unit fixtures may exercise NodeClass rendering without a
		// Kubernetes client. The real controller constructor requires one.
		return nil
	}
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range list.Items {
		service := &list.Items[index]
		if service.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "" {
			continue
		}
		_, _, updateErr := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "" {
				return false, nil
			}
			delete(copy.Annotations, annotationNodeLoadBalancerClusterCleanupProven)
			return true, nil
		})
		result = errors.Join(result, updateErr)
	}
	return result
}

func (c *nodeLoadBalancerController) aggregateShardHasOtherOwner(
	ctx context.Context,
	exclude *corev1.Service,
	shard string,
) (bool, error) {
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for index := range list.Items {
		service := &list.Items[index]
		if exclude != nil && service.Namespace == exclude.Namespace && service.Name == exclude.Name {
			continue
		}
		if service.DeletionTimestamp != nil || !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		if !aggregateServiceReferencesShard(service, shard) {
			continue
		}
		defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
		if _, parseErr := parseNodeLoadBalancerService(service, defaults); parseErr != nil {
			quarantined, quarantineErr := c.invalidServiceIsQuarantined(ctx, service)
			if quarantineErr != nil {
				return false, quarantineErr
			}
			if quarantined {
				// A malformed peer whose functional child and public status are
				// already absent must not keep paid shard capacity forever.
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

func aggregateServiceReferencesShard(service *corev1.Service, shard string) bool {
	if service == nil || !isManagedNodeLoadBalancerShardName(shard) {
		return false
	}
	for _, value := range []string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
		service.Annotations[annotationNodeLoadBalancerDatapathStaged],
		service.Annotations[annotationNodeLoadBalancerDatapathRestage],
	} {
		if value == shard {
			return true
		}
	}
	return aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], shard) &&
		!aggregateShardCleanupWasProven(service.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard)
}

// markAggregateShardCleanupProvenForReferences persists the cloud-absence
// handoff on every surviving Service that can retry this shard. The NodePool
// finalizer is removed only after all such durable recovery anchors exist.
func (c *nodeLoadBalancerController) markAggregateShardCleanupProvenForReferences(
	ctx context.Context,
	shard string,
) error {
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range list.Items {
		service := &list.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) ||
			!aggregateServiceReferencesShard(service, shard) {
			continue
		}
		result = errors.Join(result, c.markAggregateShardCleanupProven(ctx, service, shard))
	}
	return result
}

// markAggregateShardStateMaterializedForReferences records that a NodePool
// anchor existed before any datapath or deletion transition. If that anchor is
// later force-removed, a status-empty Service can no longer be mistaken for a
// prospective shard that never owned paid cloud state.
func (c *nodeLoadBalancerController) markAggregateShardStateMaterializedForReferences(
	ctx context.Context,
	shard string,
) error {
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var result error
	for index := range list.Items {
		service := &list.Items[index]
		if !containsString(service.Finalizers, nodeLoadBalancerFinalizer) ||
			!aggregateServiceReferencesShard(service, shard) {
			continue
		}
		result = errors.Join(result, c.markAggregateShardStateMaterialized(ctx, service, shard))
	}
	return result
}

func (c *nodeLoadBalancerController) deleteAggregateShardFirewall(ctx context.Context, shard string) (bool, error) {
	pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, fmt.Errorf("node load balancer: shard state anchor %s disappeared before firewall cleanup", shard)
	}
	if err != nil {
		return false, err
	}
	labels := pool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) ||
		pool.GetDeletionTimestamp() == nil {
		return false, fmt.Errorf("node load balancer: shard state anchor %s is not an exactly owned deleting NodePool", shard)
	}
	ownerUID := pool.GetUID()
	if ownerUID == "" {
		return false, fmt.Errorf("node load balancer: shard state anchor %s has an empty UID", shard)
	}
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.shardFirewallRelationOwnerForUID(shard, ownerUID),
		nil,
	)
	if err != nil || !converged {
		return false, err
	}
	annotations, err := nodeLoadBalancerShardFirewallAnnotations(pool)
	if err != nil {
		return false, err
	}
	deleteTarget, deleteIssuedAt, err := nodeLoadBalancerFirewallDeleteReceipt(
		annotations,
		annotationNodeLoadBalancerShardFWDeleteTarget,
		annotationNodeLoadBalancerShardFWDeleteIssued,
		annotationNodeLoadBalancerShardFWCleanupAbsent,
		annotationNodeLoadBalancerShardFWCleanupCheck,
	)
	if err != nil {
		return false, fmt.Errorf("node load balancer: parse shard firewall delete receipt: %w", err)
	}
	name, err := inspace.NodeLoadBalancerShardFirewallName(c.provider.config.ClusterID, shard)
	if err != nil {
		return false, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var byName, byAppliedUUID, byPendingUUID, byCleanupUUID, byDeleteUUID *inspace.Firewall
	appliedUUID := annotations[annotationNodeLoadBalancerShardFirewallUUID]
	pendingUUID := annotations[annotationNodeLoadBalancerShardFWPendingUUID]
	cleanupUUID := annotations[annotationNodeLoadBalancerShardFWCleanupSeen]
	for index := range items {
		item := items[index]
		if item.EffectiveName() == name {
			if byName != nil {
				return false, fmt.Errorf("node load balancer: multiple shard firewalls use cleanup name %q", name)
			}
			copy := item
			byName = &copy
		}
		if appliedUUID != "" && item.UUID == appliedUUID {
			copy := item
			byAppliedUUID = &copy
		}
		if pendingUUID != "" && item.UUID == pendingUUID {
			copy := item
			byPendingUUID = &copy
		}
		if cleanupUUID != "" && item.UUID == cleanupUUID {
			copy := item
			byCleanupUUID = &copy
		}
		if deleteTarget != "" && item.UUID == deleteTarget {
			if byDeleteUUID != nil {
				return false, fmt.Errorf("node load balancer: shard firewall delete target UUID %s appears multiple times", deleteTarget)
			}
			copy := item
			byDeleteUUID = &copy
		}
	}
	if appliedUUID != "" && byName != nil && byName.UUID != appliedUUID {
		return false, fmt.Errorf("node load balancer: cleanup name %q resolves to UUID %s, expected applied UUID %s", name, byName.UUID, appliedUUID)
	}
	if pendingUUID != "" && byName != nil && byName.UUID != pendingUUID && appliedUUID == "" {
		return false, fmt.Errorf("node load balancer: cleanup name %q resolves to UUID %s, expected pending UUID %s", name, byName.UUID, pendingUUID)
	}
	if byAppliedUUID != nil && byAppliedUUID.EffectiveName() != name {
		return false, fmt.Errorf("node load balancer: applied cleanup UUID %s lost stable name %q", appliedUUID, name)
	}
	if byPendingUUID != nil && byPendingUUID.EffectiveName() != name {
		return false, fmt.Errorf("node load balancer: pending cleanup UUID %s lost stable name %q", pendingUUID, name)
	}
	if cleanupUUID != "" && byName != nil && byName.UUID != cleanupUUID {
		return false, fmt.Errorf("node load balancer: cleanup name %q resolves to UUID %s, expected observed UUID %s", name, byName.UUID, cleanupUUID)
	}
	if deleteTarget != "" && byName != nil && byName.UUID != deleteTarget {
		return false, fmt.Errorf("node load balancer: cleanup name %q resolves to UUID %s, expected delete target UUID %s", name, byName.UUID, deleteTarget)
	}
	if byCleanupUUID != nil && byCleanupUUID.EffectiveName() != name {
		return false, fmt.Errorf("node load balancer: cleanup-observed UUID %s lost stable name %q", cleanupUUID, name)
	}
	if cleanupUUID != "" && pendingUUID != "" && cleanupUUID != pendingUUID && appliedUUID == "" {
		return false, errors.New("node load balancer: pending and cleanup-observed shard firewall UUIDs conflict")
	}
	for role, persisted := range map[string]string{
		"applied": appliedUUID, "pending": pendingUUID, "cleanup-observed": cleanupUUID,
	} {
		if deleteTarget != "" && persisted != "" && deleteTarget != persisted {
			return false, fmt.Errorf("node load balancer: shard firewall delete target %s conflicts with %s UUID %s", deleteTarget, role, persisted)
		}
	}
	firewall := byName
	if deleteTarget != "" {
		firewall = byDeleteUUID
	} else if appliedUUID != "" {
		firewall = byAppliedUUID
	} else if cleanupUUID != "" {
		firewall = byCleanupUUID
	} else if pendingUUID != "" {
		firewall = byPendingUUID
	}
	if firewall == nil {
		if issued := annotations[annotationNodeLoadBalancerShardFWIssuedAt]; issued != "" && appliedUUID == "" && cleanupUUID == "" && deleteTarget == "" {
			// Empty list responses cannot prove that a paid POST which crossed the
			// request boundary will never commit later. Retain the exact NodePool
			// ledger/finalizer until the stable-name firewall becomes observable or
			// an operator resolves the attempt after cloud-side proof.
			return false, fmt.Errorf(
				"node load balancer: shard firewall create issued at %s remains ambiguous during cleanup; retaining the NodePool finalizer until the original firewall is observable or manually resolved",
				issued,
			)
		}
		if deleteTarget == "" {
			candidate := appliedUUID
			if candidate == "" {
				candidate = cleanupUUID
			}
			if candidate == "" {
				candidate = pendingUUID
			}
			if candidate != "" {
				_, changed, stageErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
					if existing := values[annotationNodeLoadBalancerShardFWDeleteTarget]; existing != "" {
						if existing != candidate {
							return false, fmt.Errorf("node load balancer: concurrent shard firewall delete targets %s, not %s", existing, candidate)
						}
						return false, nil
					}
					values[annotationNodeLoadBalancerShardFWDeleteTarget] = candidate
					delete(values, annotationNodeLoadBalancerShardFWDeleteIssued)
					delete(values, annotationNodeLoadBalancerShardFWCleanupAbsent)
					delete(values, annotationNodeLoadBalancerShardFWCleanupCheck)
					return true, nil
				})
				if stageErr != nil {
					return false, fmt.Errorf("node load balancer: persist shard firewall delete intent: %w", stageErr)
				}
				if changed {
					deleteTarget = candidate
					deleteIssuedAt = ""
				} else {
					return false, nil
				}
			}
		}
		notBefore := time.Time{}
		if issued := annotations[annotationNodeLoadBalancerShardFWIssuedAt]; issued != "" {
			issuedAt, parseErr := time.Parse(time.RFC3339Nano, issued)
			if parseErr != nil {
				return false, fmt.Errorf("node load balancer: parse shard firewall cleanup mutation fence: %w", parseErr)
			}
			notBefore = issuedAt.Add(nodeLoadBalancerShardFirewallMutationTimeout)
		}
		confirmed, _, confirmErr := c.recordManagedNodePoolFirewallAbsenceForUID(
			ctx, shard, ownerUID,
			annotationNodeLoadBalancerShardFWCleanupAbsent,
			annotationNodeLoadBalancerShardFWCleanupCheck,
			time.Now().UTC(), notBefore,
		)
		if confirmErr != nil || !confirmed {
			return false, confirmErr
		}
		_, _, clearErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
			if values[annotationNodeLoadBalancerShardFirewallUUID] != appliedUUID ||
				values[annotationNodeLoadBalancerShardFWPendingUUID] != pendingUUID ||
				values[annotationNodeLoadBalancerShardFWCleanupSeen] != cleanupUUID ||
				values[annotationNodeLoadBalancerShardFWIssuedAt] != annotations[annotationNodeLoadBalancerShardFWIssuedAt] ||
				values[annotationNodeLoadBalancerShardFWDeleteTarget] != deleteTarget ||
				values[annotationNodeLoadBalancerShardFWDeleteIssued] != deleteIssuedAt {
				return false, errors.New("node load balancer: shard firewall cleanup identity changed during absence proof")
			}
			if deleteTarget != "" {
				count, parseErr := strconv.Atoi(values[annotationNodeLoadBalancerShardFWCleanupAbsent])
				if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
					return false, errors.New("node load balancer: shard firewall delete absence is no longer confirmed")
				}
			}
			for _, key := range []string{
				annotationNodeLoadBalancerShardFirewallUUID,
				annotationNodeLoadBalancerShardFirewallHash,
				annotationNodeLoadBalancerShardFirewallLedger,
				annotationNodeLoadBalancerShardFWPendingHash,
				annotationNodeLoadBalancerShardFWPendingLedger,
				annotationNodeLoadBalancerShardFWPendingAt,
				annotationNodeLoadBalancerShardFWIssuedAt,
				annotationNodeLoadBalancerShardFWPendingUUID,
				annotationNodeLoadBalancerShardFWAbsent,
				annotationNodeLoadBalancerShardFWAbsentChecked,
				annotationNodeLoadBalancerShardFWCreateAbsent,
				annotationNodeLoadBalancerShardFWCreateChecked,
				annotationNodeLoadBalancerShardFWCleanupAbsent,
				annotationNodeLoadBalancerShardFWCleanupCheck,
				annotationNodeLoadBalancerShardFWCleanupSeen,
				annotationNodeLoadBalancerShardFWDeleteTarget,
				annotationNodeLoadBalancerShardFWDeleteIssued,
				annotationNodeLoadBalancerFirewallRelationIssued,
				annotationNodeLoadBalancerFirewallRelationOwnerUID,
			} {
				delete(values, key)
			}
			return true, nil
		})
		if clearErr != nil {
			return false, clearErr
		}
		return true, nil
	}
	if _, clearErr := c.clearManagedNodePoolFirewallAbsenceForUID(
		ctx, shard, ownerUID,
		annotationNodeLoadBalancerShardFWCleanupAbsent,
		annotationNodeLoadBalancerShardFWCleanupCheck,
	); clearErr != nil {
		return false, clearErr
	}
	if deleteTarget != "" {
		changed, clearErr := c.clearManagedNodePoolFirewallAbsenceForUID(
			ctx, shard, ownerUID,
			annotationNodeLoadBalancerShardFWCleanupAbsent,
			annotationNodeLoadBalancerShardFWCleanupCheck,
		)
		if clearErr != nil || changed {
			return false, clearErr
		}
	}
	hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(firewall.Rules)
	if err != nil {
		return false, err
	}
	if err := inspace.ValidateNodeLoadBalancerShardFirewall(
		*firewall,
		c.provider.config.ClusterID,
		shard,
		c.provider.config.BillingAccountID,
		hash,
	); err != nil {
		return false, fmt.Errorf("node load balancer: refuse foreign shard firewall cleanup: %w", err)
	}
	if appliedUUID == "" && cleanupUUID == "" {
		// Persist the exact resource observed after an issued create before any
		// destructive cleanup. If the controller crashes after DELETE, this
		// receipt distinguishes an observed/deleted resource from a POST that may
		// still commit for the first time later.
		_, _, persistErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
			if values[annotationNodeLoadBalancerShardFirewallUUID] != appliedUUID ||
				values[annotationNodeLoadBalancerShardFWPendingUUID] != pendingUUID ||
				values[annotationNodeLoadBalancerShardFWIssuedAt] != annotations[annotationNodeLoadBalancerShardFWIssuedAt] {
				return false, errors.New("node load balancer: shard firewall cleanup identity changed before observation handoff")
			}
			if existing := values[annotationNodeLoadBalancerShardFWCleanupSeen]; existing != "" && existing != firewall.UUID {
				return false, errors.New("node load balancer: shard firewall cleanup observation changed concurrently")
			}
			values[annotationNodeLoadBalancerShardFWCleanupSeen] = firewall.UUID
			delete(values, annotationNodeLoadBalancerShardFWCleanupAbsent)
			delete(values, annotationNodeLoadBalancerShardFWCleanupCheck)
			return true, nil
		})
		return false, persistErr
	}
	assignments, assignmentErr := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
	if assignmentErr != nil {
		return false, assignmentErr
	}
	if len(assignments) != 0 {
		for _, vmUUID := range assignments {
			converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				c.shardFirewallRelationOwnerForUID(shard, ownerUID),
				&nodeLoadBalancerFirewallRelationFence{
					operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
				},
			)
			if relationErr != nil || !converged {
				return false, relationErr
			}
		}
		return false, nil
	}
	if deleteIssuedAt != "" {
		// The exact delete receipt is intentionally read-only after dispatch.
		// A lagging list response must never authorize a second DELETE.
		return false, nil
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, winner, issueErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
		storedTarget, storedIssued, parseErr := nodeLoadBalancerFirewallDeleteReceipt(
			values,
			annotationNodeLoadBalancerShardFWDeleteTarget,
			annotationNodeLoadBalancerShardFWDeleteIssued,
			annotationNodeLoadBalancerShardFWCleanupAbsent,
			annotationNodeLoadBalancerShardFWCleanupCheck,
		)
		if parseErr != nil {
			return false, parseErr
		}
		if storedTarget != "" && storedTarget != firewall.UUID {
			return false, fmt.Errorf("node load balancer: concurrent shard firewall delete targets %s, not %s", storedTarget, firewall.UUID)
		}
		if storedIssued != "" {
			return false, nil
		}
		values[annotationNodeLoadBalancerShardFWDeleteTarget] = firewall.UUID
		values[annotationNodeLoadBalancerShardFWDeleteIssued] = issuedAt
		delete(values, annotationNodeLoadBalancerShardFWCleanupAbsent)
		delete(values, annotationNodeLoadBalancerShardFWCleanupCheck)
		return true, nil
	})
	if issueErr != nil {
		return false, fmt.Errorf("node load balancer: persist shard firewall delete-issued receipt: %w", issueErr)
	}
	if !winner {
		return false, nil
	}
	rejectUndispatched := func(rejection error) (bool, error) {
		return false, errors.Join(
			rejection,
			c.resetShardFirewallDeleteAfterProvenNonDispatch(ctx, shard, ownerUID, firewall.UUID, issuedAt),
		)
	}
	authorizedPool, authorityErr := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if authorityErr != nil {
		return rejectUndispatched(fmt.Errorf("node load balancer: re-read shard owner after firewall delete issue: %w", authorityErr))
	}
	authorizedAnnotations, authorityErr := nodeLoadBalancerShardFirewallAnnotations(authorizedPool)
	if authorityErr != nil {
		return rejectUndispatched(authorityErr)
	}
	authorizedLabels := authorizedPool.GetLabels()
	if authorizedPool.GetUID() != ownerUID ||
		authorizedLabels[nodeLoadBalancerManagedLabel] != "true" ||
		authorizedLabels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		authorizedLabels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(authorizedPool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) ||
		authorizedAnnotations[annotationNodeLoadBalancerShardFirewallUUID] != appliedUUID ||
		authorizedAnnotations[annotationNodeLoadBalancerShardFWPendingUUID] != pendingUUID ||
		authorizedAnnotations[annotationNodeLoadBalancerShardFWCleanupSeen] != cleanupUUID ||
		authorizedAnnotations[annotationNodeLoadBalancerShardFWDeleteTarget] != firewall.UUID ||
		authorizedAnnotations[annotationNodeLoadBalancerShardFWDeleteIssued] != issuedAt {
		return rejectUndispatched(errors.New("node load balancer: shard firewall delete authority changed after issue"))
	}
	authorizedFirewall, authorityErr := c.exactNodeLoadBalancerFirewallFresh(ctx, firewall.UUID)
	if authorityErr != nil {
		return rejectUndispatched(fmt.Errorf("node load balancer: re-read shard firewall after delete issue: %w", authorityErr))
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(*firewall, *authorizedFirewall) {
		return rejectUndispatched(errors.New("node load balancer: shard firewall changed after delete issue"))
	}
	authorizedHash, authorityErr := inspace.NodeLoadBalancerShardFirewallSpecHash(authorizedFirewall.Rules)
	if authorityErr != nil {
		return rejectUndispatched(authorityErr)
	}
	if authorityErr := inspace.ValidateNodeLoadBalancerShardFirewall(
		*authorizedFirewall,
		c.provider.config.ClusterID,
		shard,
		c.provider.config.BillingAccountID,
		authorizedHash,
	); authorityErr != nil {
		return rejectUndispatched(fmt.Errorf("node load balancer: shard firewall lost exact ownership after delete issue: %w", authorityErr))
	}
	postIssueAssignments, authorityErr := nodeLoadBalancerFirewallAssignmentVMs(*authorizedFirewall)
	if authorityErr != nil {
		return rejectUndispatched(authorityErr)
	}
	if len(postIssueAssignments) != 0 {
		return rejectUndispatched(errors.New("node load balancer: shard firewall gained assignments after delete issue"))
	}
	deleteErr := c.provider.api.DeleteFirewall(ctx, c.provider.config.Location, firewall.UUID)
	if nodeLoadBalancerMutationKnownPreDispatch(deleteErr) {
		return false, errors.Join(
			deleteErr,
			c.resetShardFirewallDeleteAfterProvenNonDispatch(ctx, shard, ownerUID, firewall.UUID, issuedAt),
		)
	}
	if deleteErr != nil {
		return false, deleteErr
	}
	return false, nil
}

func (c *nodeLoadBalancerController) resetShardFirewallDeleteAfterProvenNonDispatch(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	uuid, issuedAt string,
) error {
	if ownerUID == "" || !validNodeLoadBalancerCloudUUID(uuid) || issuedAt == "" {
		return errors.New("node load balancer: incomplete shard firewall delete receipt for pre-dispatch reset")
	}
	if _, err := time.Parse(time.RFC3339Nano, issuedAt); err != nil {
		return fmt.Errorf("node load balancer: invalid shard firewall delete issue timestamp: %w", err)
	}
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	updated, changed, err := c.updateManagedNodePoolAnnotationsForUID(resetCtx, shard, ownerUID, func(values map[string]string) (bool, error) {
		if values[annotationNodeLoadBalancerShardFWDeleteTarget] != uuid ||
			values[annotationNodeLoadBalancerShardFWDeleteIssued] != issuedAt {
			return false, errors.New("node load balancer: shard firewall delete receipt changed before pre-dispatch reset")
		}
		delete(values, annotationNodeLoadBalancerShardFWDeleteIssued)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: reset proven non-dispatched shard firewall delete receipt: %w", err)
	}
	if !changed || updated == nil {
		return errors.New("node load balancer: proven non-dispatched shard firewall delete receipt was not reset")
	}
	annotations := updated.GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFWDeleteTarget] != uuid ||
		annotations[annotationNodeLoadBalancerShardFWDeleteIssued] != "" {
		return errors.New("node load balancer: shard firewall delete receipt reset changed its staged target")
	}
	return nil
}

// ensureAggregateCleanupShardAnchors completes the durable NodePool-to-Service
// state handoff before cleanup withdraws a datapath or requests capacity
// deletion. A force-removed finalizer is repaired only while the NodePool is
// still live, then proved by a fresh GET. A missing NodePool is safe only when
// the Service proves cloud cleanup, or when metadata never progressed beyond
// the prospective pre-capacity assignment window.
func (c *nodeLoadBalancerController) ensureAggregateCleanupShardAnchors(
	ctx context.Context,
	service *corev1.Service,
	shards []string,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	resource := c.provider.dynamicClient.Resource(nodePoolGVR)
	for _, shard := range shards {
		pool, getErr := resource.Get(ctx, shard, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			proven := aggregateShardCleanupWasProven(current.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard)
			materialized := aggregateShardStateWasMaterialized(current.Annotations[annotationNodeLoadBalancerShardStateMaterial], shard)
			if proven || (!materialized && aggregateShardIsProspectiveOnly(current, shard)) {
				continue
			}
			return nil, fmt.Errorf("node load balancer: NodePool %s disappeared without a persisted firewall-cleanup proof", shard)
		}
		if getErr != nil {
			return nil, getErr
		}
		labels := pool.GetLabels()
		if labels[nodeLoadBalancerManagedLabel] != "true" ||
			labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
			labels[nodeLoadBalancerShardLabel] != shard {
			return nil, fmt.Errorf("node load balancer: cleanup shard %s lacks exact state-anchor ownership", shard)
		}
		if !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			if pool.GetDeletionTimestamp() != nil {
				return nil, fmt.Errorf("node load balancer: deleting cleanup shard %s lost its state finalizer", shard)
			}
			if _, _, err := c.updateManagedNodePoolAnnotations(ctx, shard, func(map[string]string) (bool, error) {
				return false, nil
			}); err != nil {
				return nil, err
			}
		}
		verified, err := resource.Get(ctx, shard, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("node load balancer: read back cleanup shard %s state anchor: %w", shard, err)
		}
		verifiedLabels := verified.GetLabels()
		if verifiedLabels[nodeLoadBalancerManagedLabel] != "true" ||
			verifiedLabels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
			verifiedLabels[nodeLoadBalancerShardLabel] != shard ||
			!containsString(verified.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			return nil, fmt.Errorf("node load balancer: cleanup shard %s failed exact state-anchor readback", shard)
		}
		if err := c.markAggregateShardStateMaterializedForReferences(ctx, shard); err != nil {
			return nil, err
		}
		current, err = c.getExactParentService(ctx, current)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (c *nodeLoadBalancerController) cleanupAggregateService(ctx context.Context, service *corev1.Service) error {
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	shardSet := map[string]struct{}{}
	materialized, markerErr := aggregateUnprovenMaterializedShards(current)
	if markerErr != nil {
		return markerErr
	}
	shardsToAdd := append([]string{
		current.Annotations[annotationNodeLoadBalancerShard],
		current.Annotations[annotationNodeLoadBalancerPreviousShard],
		current.Annotations[annotationNodeLoadBalancerDatapathActive],
		current.Annotations[annotationNodeLoadBalancerDatapathStaged],
		current.Annotations[annotationNodeLoadBalancerDatapathRestage],
	}, materialized...)
	for _, shard := range shardsToAdd {
		if isManagedNodeLoadBalancerShardName(shard) {
			shardSet[shard] = struct{}{}
		}
	}
	shards := make([]string, 0, len(shardSet))
	for shard := range shardSet {
		shards = append(shards, shard)
	}
	sort.Strings(shards)
	current, err = c.ensureAggregateCleanupShardAnchors(ctx, current, shards)
	if err != nil {
		return err
	}
	// Withdraw the deleting/class-changed Service before any cloud policy work.
	// The old active markers deliberately remain as a port reservation until the
	// aggregate ledger has excluded this UID. A failed or ambiguous firewall
	// List/PUT can therefore delay capacity cleanup, but can never leave the
	// removed Service publicly reachable while that retry is pending.
	if err := c.clearAggregateServiceDatapathFailClosed(ctx, current, false); err != nil {
		return err
	}
	for _, shard := range shards {
		other, err := c.aggregateShardHasOtherOwner(ctx, current, shard)
		if err != nil {
			return err
		}
		if other {
			state, reconcileErr := c.reconcileShardFirewallPolicy(ctx, shard)
			if reconcileErr != nil {
				return reconcileErr
			}
			if ledgerContainsNodeLoadBalancerService(state.AppliedLedger, string(current.UID)) || !state.PolicyReady {
				c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
				return nil
			}
			continue
		}
		if _, getErr := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); apierrors.IsNotFound(getErr) {
			if !aggregateShardStateWasMaterialized(current.Annotations[annotationNodeLoadBalancerShardStateMaterial], shard) &&
				aggregateShardIsProspectiveOnly(current, shard) {
				// Metadata assignment is persisted before paid capacity is created.
				// A delete in that handoff window may safely discard this shard: no
				// active/staged/restage/previous marker ever authorized capacity or
				// an aggregate firewall for it.
				continue
			}
			if !aggregateShardCleanupWasProven(current.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
				return fmt.Errorf("node load balancer: NodePool %s disappeared without a persisted firewall-cleanup proof", shard)
			}
			continue
		} else if getErr != nil {
			return getErr
		}
		if err := c.clearAggregateServiceDatapathFailClosed(ctx, current, true); err != nil {
			return err
		}
		nodes, err := c.rawNodesForShard(ctx, shard)
		if err != nil {
			return err
		}
		if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
			return err
		}
		if err := c.deleteManagedNodePool(ctx, shard); err != nil {
			return err
		}
		absent, err := c.managedShardCapacityAbsent(ctx, shard)
		if err != nil {
			return err
		}
		if !absent {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		}
		firewallAbsent, err := c.deleteAggregateShardFirewall(ctx, shard)
		if err != nil {
			return err
		}
		if !firewallAbsent {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		}
		if err := c.markAggregateShardCleanupProvenForReferences(ctx, shard); err != nil {
			return err
		}
		if err := c.removeManagedNodePoolStateFinalizer(ctx, shard); err != nil {
			return err
		}
	}

	if err := c.clearAggregateServiceDatapathFailClosed(ctx, current, true); err != nil {
		return err
	}
	if err := c.deleteOwnedDatapathService(ctx, current); err != nil {
		return errors.Join(err, c.failAggregateServiceReferencedShards(ctx, current))
	}
	absent, err := c.ownedDatapathServiceAbsent(ctx, current)
	if err != nil {
		return err
	}
	if !absent {
		c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
		return nil
	}
	otherOwners, err := c.otherNodeLoadBalancerServices(ctx, current)
	if err != nil {
		return err
	}
	if !otherOwners {
		waiting, err := c.cleanupRemainingClusterNodeLoadBalancerCapacity(ctx)
		if err != nil {
			return err
		}
		if waiting {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		}
		nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
		done, err := c.cleanupAggregateClusterState(ctx, current, nodeClassName)
		if err != nil {
			return err
		}
		if !done {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		}
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp == nil && isNodeLoadBalancerService(copy) && !publicNodeLocalRequested(copy) {
			return false, errors.New("node load balancer: Service became active before aggregate finalization")
		}
		if len(copy.Status.LoadBalancer.Ingress) != 0 {
			return false, errors.New("node load balancer: public status remains during aggregate finalization")
		}
		changed := containsString(copy.Finalizers, nodeLoadBalancerFinalizer)
		copy.Finalizers = removeString(copy.Finalizers, nodeLoadBalancerFinalizer)
		for _, key := range []string{
			annotationNodeLoadBalancerShard,
			annotationNodeLoadBalancerPreviousShard,
			annotationNodeLoadBalancerDatapathActive,
			annotationNodeLoadBalancerDatapathStaged,
			annotationNodeLoadBalancerDatapathStagedPolicy,
			annotationNodeLoadBalancerDatapathRestage,
			annotationNodeLoadBalancerDatapathRestagePolicy,
			annotationNodeLoadBalancerShardCleanupProven,
			annotationNodeLoadBalancerShardStateMaterial,
			annotationNodeLoadBalancerClusterCleanupProven,
			annotationNodeLoadBalancerClusterStateMaterial,
			annotationNodeLoadBalancerFirewallUUID,
			annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerPreviousFirewall,
		} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

func (c *nodeLoadBalancerController) cleanupAggregateClusterState(
	ctx context.Context,
	service *corev1.Service,
	nodeClassName string,
) (bool, error) {
	nodeClass, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		current, currentErr := c.getExactParentService(ctx, service)
		if apierrors.IsNotFound(currentErr) {
			return true, nil
		}
		if currentErr != nil {
			return false, currentErr
		}
		if current.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "true" {
			return true, nil
		}
		if current.Annotations[annotationNodeLoadBalancerClusterStateMaterial] != "true" {
			// The Service finalizer is persisted before the generated NodeClass is
			// created. Deletion in that prospective window owns no shared cloud
			// state and needs no impossible absence handoff.
			return true, nil
		}
		return false, errors.New("node load balancer: managed NodeClass disappeared without persisted cluster-firewall cleanup proof")
	}
	if err != nil {
		return false, err
	}
	labels := nodeClass.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID {
		return false, fmt.Errorf("node load balancer: managed NodeClass %s lacks exact cluster-state identity", nodeClassName)
	}
	if !containsString(nodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		if nodeClass.GetDeletionTimestamp() != nil {
			return false, fmt.Errorf("node load balancer: deleting managed NodeClass %s lost its cluster-state finalizer", nodeClassName)
		}
		updated := nodeClass.DeepCopy()
		updated.SetFinalizers(append(updated.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer))
		if _, err := c.provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return false, fmt.Errorf("node load balancer: backfill managed NodeClass %s cluster-state finalizer: %w", nodeClassName, err)
		}
		nodeClass, err = c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("node load balancer: read back managed NodeClass %s cluster-state finalizer: %w", nodeClassName, err)
		}
		labels = nodeClass.GetLabels()
		if labels[nodeLoadBalancerManagedLabel] != "true" ||
			labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
			!containsString(nodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
			return false, fmt.Errorf("node load balancer: managed NodeClass %s failed exact cluster-state readback", nodeClassName)
		}
	}
	if err := c.markAggregateClusterStateMaterializedForReferences(ctx); err != nil {
		return false, err
	}
	if nodeClass.GetDeletionTimestamp() != nil {
		current, currentErr := c.getExactParentService(ctx, service)
		if currentErr != nil {
			return false, currentErr
		}
		if current.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "true" {
			if err := c.removeManagedNodeClassStateFinalizer(ctx, nodeClassName); err != nil {
				return false, err
			}
			return false, nil
		}
	}
	done, err := c.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil || !done {
		return false, err
	}
	// Cloud absence is durable before either the delete request or finalizer
	// release. A crash after the API object disappears can recover from this
	// Service-side handoff without treating one empty cloud List as proof.
	if err := c.markAggregateClusterCleanupProvenForReferences(ctx); err != nil {
		return false, err
	}
	if nodeClass.GetDeletionTimestamp() == nil {
		if err := c.deleteManagedNodeClass(ctx, nodeClassName); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := c.removeManagedNodeClassStateFinalizer(ctx, nodeClassName); err != nil {
		return false, err
	}
	return false, nil
}

func aggregateShardIsProspectiveOnly(service *corev1.Service, shard string) bool {
	if service == nil || service.Annotations[annotationNodeLoadBalancerShard] != shard ||
		service.Annotations[annotationNodeLoadBalancerPreviousShard] == shard ||
		service.Annotations[annotationNodeLoadBalancerDatapathActive] == shard ||
		service.Annotations[annotationNodeLoadBalancerDatapathStaged] == shard ||
		service.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard {
		return false
	}
	active := service.Annotations[annotationNodeLoadBalancerDatapathActive]
	return len(service.Status.LoadBalancer.Ingress) == 0 ||
		(isManagedNodeLoadBalancerShardName(active) && active != shard)
}

// cleanupUnusedAggregateShard retires a previous migration only after the new
// shard is fully serving. The stable firewall name remains the cleanup anchor
// after the old NodePool has disappeared.
func (c *nodeLoadBalancerController) retireAggregatePreviousShard(
	ctx context.Context,
	service *corev1.Service,
	shard string,
) (bool, error) {
	other, err := c.aggregateShardHasOtherOwner(ctx, service, shard)
	if err != nil {
		return false, err
	}
	if other {
		state, reconcileErr := c.reconcileShardFirewallPolicy(ctx, shard)
		if reconcileErr != nil {
			return false, reconcileErr
		}
		if !state.PolicyReady || ledgerContainsNodeLoadBalancerService(state.AppliedLedger, string(service.UID)) {
			return false, nil
		}
		_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerPreviousShard] != shard {
				return false, nil
			}
			delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
			clearAggregateShardMaterialization(copy.Annotations, shard)
			return true, nil
		})
		return err == nil, err
	}
	if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		_, _, clearErr := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerPreviousShard] != shard ||
				!aggregateShardCleanupWasProven(copy.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
				return false, errors.New("node load balancer: previous shard disappeared without its persisted firewall-cleanup proof")
			}
			delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
			clearAggregateShardCleanupProof(copy.Annotations, shard)
			clearAggregateShardMaterialization(copy.Annotations, shard)
			return true, nil
		})
		return clearErr == nil, clearErr
	} else if err != nil {
		return false, err
	}
	nodes, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return false, err
	}
	if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
		return false, err
	}
	if err := c.deleteManagedNodePool(ctx, shard); err != nil {
		return false, err
	}
	absent, err := c.managedShardCapacityAbsent(ctx, shard)
	if err != nil || !absent {
		return false, err
	}
	firewallAbsent, err := c.deleteAggregateShardFirewall(ctx, shard)
	if err != nil || !firewallAbsent {
		return false, err
	}
	if err := c.markAggregateShardCleanupProvenForReferences(ctx, shard); err != nil {
		return false, err
	}
	if err := c.removeManagedNodePoolStateFinalizer(ctx, shard); err != nil {
		return false, err
	}
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPreviousShard] != shard {
			return false, nil
		}
		delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
		clearAggregateShardCleanupProof(copy.Annotations, shard)
		clearAggregateShardMaterialization(copy.Annotations, shard)
		return true, nil
	})
	return err == nil, err
}
