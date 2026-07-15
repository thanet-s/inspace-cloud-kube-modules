package cloudprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/informers"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	nodeLoadBalancerFinalizer                  = "service.inspace.cloud/node-lb"
	annotationNodeLoadBalancerFirewallUUID     = "service.inspace.cloud/node-lb-firewall-uuid"
	annotationNodeLoadBalancerFirewallHash     = "service.inspace.cloud/node-lb-firewall-hash"
	annotationNodeLoadBalancerFirewallAbsent   = "service.inspace.cloud/node-lb-firewall-absence-count"
	annotationNodeLoadBalancerFirewallChecked  = "service.inspace.cloud/node-lb-firewall-absence-checked-at"
	annotationNodeLoadBalancerPendingFirewall  = "service.inspace.cloud/node-lb-pending-firewall-uuid"
	annotationNodeLoadBalancerPendingFWName    = "service.inspace.cloud/node-lb-pending-firewall-name"
	annotationNodeLoadBalancerPendingFWStarted = "service.inspace.cloud/node-lb-pending-firewall-started-at"
	annotationNodeLoadBalancerPendingFWDelete  = "service.inspace.cloud/node-lb-pending-firewall-deleting"
	annotationNodeLoadBalancerPendingFWAbsent  = "service.inspace.cloud/node-lb-pending-firewall-absence-count"
	annotationNodeLoadBalancerPendingFWChecked = "service.inspace.cloud/node-lb-pending-firewall-absence-checked-at"
	annotationNodeLoadBalancerCleanupFWAbsent  = "service.inspace.cloud/node-lb-cleanup-firewall-absence-count"
	annotationNodeLoadBalancerCleanupFWChecked = "service.inspace.cloud/node-lb-cleanup-firewall-absence-checked-at"
	annotationNodeLoadBalancerPreviousFirewall = "service.inspace.cloud/node-lb-previous-firewall-uuid"
	annotationNodeLoadBalancerPreviousShard    = "service.inspace.cloud/node-lb-previous-shard"
	annotationCiliumNodeIPAMMatchLabels        = "io.cilium.nodeipam/match-node-labels"
	// The ready label is the final Cilium advertisement gate. Keep it under the
	// NodeRestriction-reserved prefix so a kubelet cannot self-advertise by
	// copying the otherwise user-visible NodeLoadBalancer identity labels.
	nodeLoadBalancerReadyLabel                = "inspace.cloud.node-restriction.kubernetes.io/ready"
	nodeLoadBalancerManagedLabel              = "inspace.cloud/node-lb-managed"
	nodeLoadBalancerClusterLabel              = "inspace.cloud/node-lb-cluster"
	nodeLoadBalancerProfileLabel              = "inspace.cloud/node-lb-profile"
	nodeLoadBalancerShadowLabel               = "inspace.cloud/node-lb-shadow"
	nodeLoadBalancerServiceUIDLabel           = "inspace.cloud/node-lb-service-uid"
	nodeLoadBalancerCiliumClass               = "io.cilium/node"
	karpenterNodePoolLabel                    = "karpenter.sh/nodepool"
	nodeLoadBalancerResync                    = 30 * time.Second
	nodeLoadBalancerRetry                     = 10 * time.Second
	nodeLoadBalancerAssignmentReadbackTimeout = 30 * time.Second
	nodeLoadBalancerAssignmentReadbackDelay   = 500 * time.Millisecond
	nodeLoadBalancerPendingCreateTimeout      = 5 * time.Minute
	nodeLoadBalancerAbsenceConfirmationDelay  = 30 * time.Second
	nodeLoadBalancerAbsenceConfirmations      = 3
)

var (
	nodePoolGVR  = schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodepools"}
	nodeClaimGVR = schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	nodeClassGVR = schema.GroupVersionResource{Group: "karpenter.inspace.cloud", Version: "v1alpha1", Resource: "inspacenodeclasses"}
)

type nodeLoadBalancerController struct {
	provider *Provider
	nodes    corelisters.NodeLister
	services corelisters.ServiceLister

	nodesSynced    cache.InformerSynced
	servicesSynced cache.InformerSynced
	queue          workqueue.TypedRateLimitingInterface[string]
}

func newNodeLoadBalancerController(provider *Provider, factory informers.SharedInformerFactory) (*nodeLoadBalancerController, error) {
	if provider == nil || factory == nil {
		return nil, errors.New("node load balancer: provider and informer factory are required")
	}
	if provider.kubeClient == nil || provider.dynamicClient == nil {
		return nil, errors.New("node load balancer: initialized Kubernetes clients are required")
	}
	nodes := factory.Core().V1().Nodes()
	services := factory.Core().V1().Services()
	controller := &nodeLoadBalancerController{
		provider: provider, nodes: nodes.Lister(), services: services.Lister(),
		nodesSynced: nodes.Informer().HasSynced, servicesSynced: services.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "inspace-node-load-balancers"},
		),
	}
	serviceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { controller.enqueueAll() },
		UpdateFunc: func(_, _ any) { controller.enqueueAll() },
		DeleteFunc: func(any) { controller.enqueueAll() },
	}
	nodeHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { controller.enqueueAll() },
		UpdateFunc: func(_, _ any) { controller.enqueueAll() },
		DeleteFunc: func(any) { controller.enqueueAll() },
	}
	if _, err := services.Informer().AddEventHandler(serviceHandler); err != nil {
		return nil, fmt.Errorf("node load balancer: register Service handler: %w", err)
	}
	if _, err := nodes.Informer().AddEventHandler(nodeHandler); err != nil {
		return nil, fmt.Errorf("node load balancer: register Node handler: %w", err)
	}
	return controller, nil
}

func (c *nodeLoadBalancerController) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()
	if stopCh == nil {
		panic("node load balancer: stop channel is required")
	}
	if !cache.WaitForCacheSync(stopCh, c.nodesSynced, c.servicesSynced) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stopCh
		cancel()
	}()
	c.enqueueAll()
	go func() {
		for c.processNext(ctx) {
		}
	}()
	ticker := time.NewTicker(nodeLoadBalancerResync)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.enqueueAll()
		}
	}
}

func (c *nodeLoadBalancerController) processNext(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)
	if err := c.sync(ctx, key); err != nil {
		klog.ErrorS(err, "failed to reconcile InSpace node load balancer", "service", key)
		c.queue.AddRateLimited(key)
		return true
	}
	c.queue.Forget(key)
	return true
}

func (c *nodeLoadBalancerController) enqueueAll() {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("node load balancer: list Services for enqueue: %w", err))
		return
	}
	for _, service := range services {
		if isNodeLoadBalancerService(service) || containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			c.queue.Add(service.Namespace + "/" + service.Name)
		}
	}
}

func isNodeLoadBalancerService(service *corev1.Service) bool {
	return service != nil && service.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		service.Spec.LoadBalancerClass != nil && *service.Spec.LoadBalancerClass == nodeLoadBalancerClass
}

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
	if service.DeletionTimestamp != nil || !isNodeLoadBalancerService(service) {
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			return c.cleanupService(ctx, service)
		}
		return nil
	}

	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	if _, err := parseNodeLoadBalancerService(service, defaults); err != nil {
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			if quarantineErr := c.quarantineInvalidService(ctx, service); quarantineErr != nil {
				return errors.Join(err, quarantineErr)
			}
		}
		return err
	}
	// Audit the currently advertised shard before any desired-state work. This
	// guarantees that ownership drift or a persistent create/update error later
	// in reconciliation cannot leave a previously ready public selector active.
	if err := c.auditAdvertisedServiceShard(ctx, service); err != nil {
		// The audit already removed the advertisement gate. Continue so the
		// normal desired-state path can repair a drifted NodeClass/NodePool;
		// unrepaired firewall or ownership errors are encountered again below.
		klog.ErrorS(err, "node load balancer advertised shard failed closed before desired-state repair", "service", key)
	}

	intent, plan, shard, err := c.planForService(ctx, service)
	if err != nil {
		return err
	}
	if err := c.validateShadowServiceName(ctx, service); err != nil {
		return err
	}
	if waiting, err := c.cleanupAbandonedReplacementShard(ctx, service, shard.Name); err != nil || waiting {
		if waiting {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
		}
		return err
	}
	if previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]; previous != "" && previous != shard.Name {
		if !isManagedNodeLoadBalancerShardName(previous) {
			return fmt.Errorf("node load balancer: previous shard %q is not a CCM-managed shard name", previous)
		}
		// A migration can spend minutes creating its replacement. Keep auditing
		// the still-advertised shard on every reconciliation so a Node that turns
		// NotReady (or loses its FIP/firewall) cannot retain the Cilium selector
		// merely because the Service's persisted assignment already points at the
		// replacement shard.
		if err := c.reconcileShardNodeEligibility(ctx, previous); err != nil {
			return err
		}
	}
	if patched, err := c.ensureServiceMetadata(ctx, service, plan.Assignments[intent.ServiceID]); err != nil || patched {
		return err
	}

	nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
	if err := c.ensureNodeClass(ctx, nodeClassName); err != nil {
		return err
	}
	clusterNodes, err := c.authorizedNodesForCluster(ctx)
	if err != nil {
		return c.failClusterNodeLoadBalancerClosed(ctx, err)
	}
	icmpFirewall, icmpAssignmentsReady, err := c.ensureClusterICMPFirewall(ctx, nodeClassName, clusterNodes)
	if err != nil {
		return c.failClusterNodeLoadBalancerClosed(ctx, err)
	}
	if icmpFirewall == nil || !icmpAssignmentsReady {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	firewall, previousUUID, _, err := c.ensureServiceFirewall(ctx, service, nil)
	if err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	if firewall == nil {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if patched, err := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); err != nil || patched {
		return err
	}
	if err := c.ensureNodePoolFailClosed(ctx, nodeClassName, shard); err != nil {
		return err
	}

	nodes, err := c.authorizedNodesForShard(ctx, shard.Name)
	if err != nil {
		return c.failNodeLoadBalancerShardClosed(ctx, shard.Name, err)
	}
	clusterNodes, err = c.authorizedNodesForCluster(ctx)
	if err != nil {
		return c.failClusterNodeLoadBalancerClosed(ctx, err)
	}
	icmpFirewall, icmpAssignmentsReady, err = c.ensureClusterICMPFirewall(ctx, nodeClassName, clusterNodes)
	if err != nil {
		return c.failClusterNodeLoadBalancerClosed(ctx, err)
	}
	firewall, previousUUID, assignmentsReady, err := c.ensureServiceFirewall(ctx, service, nodes)
	if err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	if icmpFirewall == nil || !icmpAssignmentsReady || firewall == nil || !assignmentsReady {
		if eligibilityErr := c.reconcileShardNodeEligibility(ctx, shard.Name); eligibilityErr != nil {
			return eligibilityErr
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if patched, err := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); err != nil || patched {
		return err
	}
	if err := c.reconcileShardNodeEligibility(ctx, shard.Name); err != nil {
		return err
	}
	readyNodes, readyExternalIPs, err := c.readyShardNodes(ctx, shard.Name)
	if err != nil {
		return err
	}
	shadowUsesShard, err := c.shadowServiceUsesShard(ctx, service, shard.Name)
	if err != nil {
		return err
	}
	if !shadowUsesShard && len(readyNodes) < int(shard.NodesPerShard) {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if _, err := c.ensureShadowService(ctx, service, shard.Name); err != nil {
		return err
	}
	converged, err := c.shadowStatusMatchesExternalIPs(ctx, service, shard.Name, readyExternalIPs)
	if err != nil {
		return err
	}
	if !converged {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if err := c.copyShadowStatus(ctx, service); err != nil {
		return err
	}
	service, err = c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: refresh Service after publishing shadow status: %w", err)
	}
	if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, readyNodes); err != nil {
		return err
	}
	if err := c.cleanupPreviousFirewall(ctx, service); err != nil {
		return err
	}
	if err := c.cleanupPreviousShard(ctx, service); err != nil {
		return err
	}
	if len(nodes) < int(shard.NodesPerShard) {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
	}
	return nil
}

func (c *nodeLoadBalancerController) auditAdvertisedServiceShard(ctx context.Context, service *corev1.Service) error {
	shard, active, err := c.activeShadowShard(ctx, service)
	if err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, "", err)
	}
	if !active {
		return nil
	}
	if err := c.reconcileShardNodeEligibility(ctx, shard); err != nil {
		return err
	}
	return nil
}

func (c *nodeLoadBalancerController) failNodeLoadBalancerShardClosed(ctx context.Context, shard string, cause error) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return cause
	}
	nodes, err := c.rawNodesForShard(shard)
	if err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, c.setShardNodesReady(ctx, nodes, nil))
}

func (c *nodeLoadBalancerController) failNodeLoadBalancerShardsClosed(
	ctx context.Context,
	service *corev1.Service,
	additionalShard string,
	cause error,
) error {
	shards := map[string]struct{}{}
	if isManagedNodeLoadBalancerShardName(additionalShard) {
		shards[additionalShard] = struct{}{}
	}
	if service != nil {
		for _, shard := range []string{
			service.Annotations[annotationNodeLoadBalancerShard],
			service.Annotations[annotationNodeLoadBalancerPreviousShard],
		} {
			if isManagedNodeLoadBalancerShardName(shard) {
				shards[shard] = struct{}{}
			}
		}
	}
	result := cause
	for shard := range shards {
		nodes, err := c.rawNodesForShard(shard)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		result = errors.Join(result, c.setShardNodesReady(ctx, nodes, nil))
	}
	return result
}

func (c *nodeLoadBalancerController) failClusterNodeLoadBalancerClosed(ctx context.Context, cause error) error {
	nodes, err := c.rawNodesForCluster()
	if err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, c.setShardNodesReady(ctx, nodes, nil))
}

func (c *nodeLoadBalancerController) cleanupAbandonedReplacementShard(
	ctx context.Context,
	service *corev1.Service,
	desiredShard string,
) (bool, error) {
	currentShard := service.Annotations[annotationNodeLoadBalancerShard]
	if currentShard == "" || currentShard == desiredShard {
		return false, nil
	}
	activeShard, active, err := c.activeShadowShard(ctx, service)
	if err != nil {
		return false, err
	}
	if active && activeShard == currentShard {
		return false, nil
	}
	remaining, err := c.servicesForShard(ctx, service, currentShard)
	if err != nil {
		return false, err
	}
	if len(remaining) != 0 {
		return false, nil
	}
	nodes, err := c.rawNodesForShard(currentShard)
	if err != nil {
		return false, err
	}
	if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
		return false, err
	}
	if err := c.deleteManagedNodePool(ctx, currentShard); err != nil {
		return false, err
	}
	if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, currentShard, metav1.GetOptions{}); err == nil {
		return true, nil
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("node load balancer: prove abandoned NodePool %s deletion: %w", currentShard, err)
	}
	nodes, err = c.rawNodesForShard(currentShard)
	if err != nil {
		return false, err
	}
	return len(nodes) != 0, nil
}

func (c *nodeLoadBalancerController) planForService(ctx context.Context, target *corev1.Service) (nodeLoadBalancerIntent, nodeLoadBalancerPlan, nodeLoadBalancerShardPlan, error) {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, err
	}
	reservations, err := c.activeShadowPortReservations(ctx, services)
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, err
	}
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	intents := make([]nodeLoadBalancerIntent, 0)
	var targetIntent nodeLoadBalancerIntent
	for _, service := range services {
		if !isNodeLoadBalancerService(service) || service.DeletionTimestamp != nil {
			continue
		}
		intent, parseErr := parseNodeLoadBalancerService(service, defaults)
		if parseErr != nil {
			if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
				if quarantineErr := c.quarantineInvalidService(ctx, service); quarantineErr != nil {
					return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, errors.Join(parseErr, quarantineErr)
				}
				quarantined, quarantineErr := c.invalidServiceIsQuarantined(ctx, service)
				if quarantineErr != nil {
					return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, errors.Join(parseErr, quarantineErr)
				}
				if !quarantined {
					c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
					return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, fmt.Errorf(
						"node load balancer: waiting for invalid Service %s/%s to become non-advertised: %w",
						service.Namespace, service.Name, parseErr,
					)
				}
			}
			// A never-established invalid Service owns no public dataplane. A
			// previously established one is omitted only after its shadow and
			// published status are authoritatively absent. Its retained shard and
			// firewall can then be recovered if the user fixes the Service without
			// letting malformed claims evict healthy Services.
			klog.ErrorS(parseErr, "quarantined invalid InSpace node load balancer Service", "service", service.Namespace+"/"+service.Name)
			continue
		}
		if intent.ExistingShard != "" {
			preserve, preserveErr := c.persistedShardAssignmentMatches(ctx, service, intent)
			if preserveErr != nil {
				return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, preserveErr
			}
			if !preserve {
				intent.ExistingShard = ""
			}
		}
		intents = append(intents, intent)
		if service.Namespace == target.Namespace && service.Name == target.Name {
			targetIntent = intent
		}
	}
	plan, err := planNodeLoadBalancerShardsWithReservations(intents, reservations)
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, err
	}
	shardName := plan.Assignments[targetIntent.ServiceID]
	for _, shard := range plan.Shards {
		if shard.Name == shardName {
			return targetIntent, plan, shard, nil
		}
	}
	return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, errors.New("node load balancer: planner returned no shard")
}

func (c *nodeLoadBalancerController) activeShadowPortReservations(
	ctx context.Context,
	services []*corev1.Service,
) (nodeLoadBalancerPortReservations, error) {
	reservations := make(nodeLoadBalancerPortReservations)
	for _, service := range services {
		if !isNodeLoadBalancerService(service) && !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
			ctx,
			nodeLoadBalancerShadowName(service),
			metav1.GetOptions{},
		)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("node load balancer: inspect active shadow reservation for %s/%s: %w", service.Namespace, service.Name, err)
		}
		if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
			return nil, fmt.Errorf("node load balancer: active shadow reservation for %s/%s lacks exact owner identity", service.Namespace, service.Name)
		}
		shard, valid := nodeLoadBalancerCiliumSelectorShard(
			shadow.Annotations[annotationCiliumNodeIPAMMatchLabels],
			c.provider.config.ClusterID,
		)
		if !valid {
			return nil, fmt.Errorf("node load balancer: active shadow reservation for %s/%s has a foreign node selector", service.Namespace, service.Name)
		}
		ports, err := nodeLoadBalancerPortClaims(shadow)
		if err != nil {
			return nil, fmt.Errorf("node load balancer: active shadow reservation for %s/%s has invalid ports: %w", service.Namespace, service.Name, err)
		}
		owner := string(service.UID)
		if owner == "" {
			return nil, fmt.Errorf("node load balancer: active shadow reservation for %s/%s has no Service UID", service.Namespace, service.Name)
		}
		if reservations[shard] == nil {
			reservations[shard] = make(map[nodeLoadBalancerPortClaim]string)
		}
		for _, port := range ports {
			if existing, conflict := reservations[shard][port]; conflict && existing != owner {
				return nil, fmt.Errorf(
					"node load balancer: active shadows %s and %s collide on shard %s %s/%d",
					existing, owner, shard, port.Protocol, port.Port,
				)
			}
			reservations[shard][port] = owner
		}
	}
	return reservations, nil
}

func (c *nodeLoadBalancerController) persistedShardAssignmentMatches(ctx context.Context, service *corev1.Service, intent nodeLoadBalancerIntent) (bool, error) {
	nodePool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, intent.ExistingShard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: get persisted NodePool %s: %w", intent.ExistingShard, err)
	}
	labels := nodePool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != intent.ExistingShard {
		return false, fmt.Errorf("node load balancer: persisted shard %s lacks exact cluster ownership", intent.ExistingShard)
	}
	if labels[nodeLoadBalancerProfileLabel] != nodeLoadBalancerIntentProfileHash(intent) {
		return false, nil
	}
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx,
		nodeLoadBalancerShadowName(service),
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: get persisted shadow Service for %s/%s: %w", service.Namespace, service.Name, err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return false, fmt.Errorf("node load balancer: persisted shadow Service for %s/%s lacks exact owner identity", service.Namespace, service.Name)
	}
	wantSelector := nodeLoadBalancerCiliumSelector(c.provider.config.ClusterID, intent.ExistingShard)
	if shadow.Annotations[annotationCiliumNodeIPAMMatchLabels] != wantSelector {
		previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]
		previousSelector := nodeLoadBalancerCiliumSelector(c.provider.config.ClusterID, previous)
		if previous == "" || shadow.Annotations[annotationCiliumNodeIPAMMatchLabels] != previousSelector {
			return false, fmt.Errorf("node load balancer: persisted shadow Service for %s/%s has a foreign shard selector", service.Namespace, service.Name)
		}
		// During a staged migration the persisted assignment already names the
		// replacement shard while the owned shadow intentionally continues to
		// advertise the previous shard. Preserve the replacement assignment only
		// while the public port claims are unchanged. An edited inactive Service
		// must not steal a port from a Service already active on the replacement.
	}
	shadowPorts, err := nodeLoadBalancerPortClaims(shadow)
	if err != nil {
		return false, fmt.Errorf("node load balancer: persisted shadow Service for %s/%s has invalid ports: %w", service.Namespace, service.Name, err)
	}
	return reflect.DeepEqual(shadowPorts, intent.Ports), nil
}

func (c *nodeLoadBalancerController) ensureServiceMetadata(ctx context.Context, service *corev1.Service, shard string) (bool, error) {
	copy := service.DeepCopy()
	changed := false
	if !containsString(copy.Finalizers, nodeLoadBalancerFinalizer) {
		copy.Finalizers = append(copy.Finalizers, nodeLoadBalancerFinalizer)
		changed = true
	}
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	if copy.Annotations[annotationNodeLoadBalancerShard] != shard {
		currentShard := copy.Annotations[annotationNodeLoadBalancerShard]
		previousShard := ""
		activeShard, active, err := c.activeShadowShard(ctx, service)
		if err != nil {
			return false, err
		}
		if active {
			previousShard = activeShard
			if activeShard == currentShard {
				// The shadow already cut over, but cleanup of older migration
				// metadata has not completed. Its current firewall is now the
				// dataplane identity that a new migration must preserve.
				if currentFirewall := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]; currentFirewall != "" {
					copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = currentFirewall
				}
			}
		}
		if previousShard != "" && previousShard != shard {
			copy.Annotations[annotationNodeLoadBalancerPreviousShard] = previousShard
		} else {
			delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
		}
		copy.Annotations[annotationNodeLoadBalancerShard] = shard
		changed = true
	}
	if !changed {
		return false, nil
	}
	_, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	return true, err
}

func nodeLoadBalancerCiliumSelector(cluster, shard string) string {
	return strings.Join([]string{
		nodeLoadBalancerNodeLabel + "=true",
		nodeLoadBalancerNodeClusterLabel + "=" + cluster,
		nodeLoadBalancerNodeShardLabel + "=" + shard,
		nodeLoadBalancerReadyLabel + "=true",
	}, ",")
}

func nodeLoadBalancerCiliumSelectorShard(selector, cluster string) (string, bool) {
	for _, part := range strings.Split(selector, ",") {
		if !strings.HasPrefix(part, nodeLoadBalancerNodeShardLabel+"=") {
			continue
		}
		shard := strings.TrimPrefix(part, nodeLoadBalancerNodeShardLabel+"=")
		if !isManagedNodeLoadBalancerShardName(shard) || selector != nodeLoadBalancerCiliumSelector(cluster, shard) {
			return "", false
		}
		return shard, true
	}
	return "", false
}

func (c *nodeLoadBalancerController) activeShadowShard(ctx context.Context, service *corev1.Service) (string, bool, error) {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("node load balancer: get active shadow Service for migration: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return "", false, fmt.Errorf("node load balancer: active shadow Service for %s/%s lacks exact owner identity", service.Namespace, service.Name)
	}
	shard, valid := nodeLoadBalancerCiliumSelectorShard(
		shadow.Annotations[annotationCiliumNodeIPAMMatchLabels],
		c.provider.config.ClusterID,
	)
	if !valid {
		return "", false, fmt.Errorf("node load balancer: active shadow Service for %s/%s has a foreign node selector", service.Namespace, service.Name)
	}
	return shard, true, nil
}

func managedNodeLoadBalancerName(clusterID, suffix string) string {
	base := strings.Trim(strings.ToLower(clusterID+"-"+suffix), "-")
	if len(base) <= 63 {
		return base
	}
	hash := shortNodeLoadBalancerHash(base)
	return strings.TrimRight(base[:54], "-") + "-" + hash
}

func shortNodeLoadBalancerHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

func (c *nodeLoadBalancerController) ensureNodeClass(ctx context.Context, name string) error {
	base, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(
		ctx, c.provider.config.NodeLoadBalancer.DefaultNodeClass, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("node load balancer: get base NodeClass %q: %w", c.provider.config.NodeLoadBalancer.DefaultNodeClass, err)
	}
	if err := c.validateBaseNodeClass(base); err != nil {
		return err
	}
	desired, err := renderNodeLoadBalancerNodeClass(base, name)
	if err != nil {
		return err
	}
	if err := markNodeLoadBalancerManaged(desired, c.provider.config.ClusterID, "", ""); err != nil {
		return err
	}
	return c.ensureDynamicObject(ctx, nodeClassGVR, desired)
}

func (c *nodeLoadBalancerController) validateBaseNodeClass(base *unstructured.Unstructured) error {
	if base == nil {
		return errors.New("node load balancer: base NodeClass is required")
	}
	stringFields := []struct {
		path []string
		want string
	}{
		{path: []string{"spec", "clusterName"}, want: c.provider.config.ClusterID},
		{path: []string{"spec", "location"}, want: c.provider.config.Location},
		{path: []string{"spec", "networkUUID"}, want: c.provider.config.NetworkUUID},
		{path: []string{"spec", "privateLoadBalancerPool", "start"}, want: c.provider.config.PrivateLoadBalancerPoolStart},
		{path: []string{"spec", "privateLoadBalancerPool", "stop"}, want: c.provider.config.PrivateLoadBalancerPoolStop},
		{path: []string{"spec", "rke2", "server"}, want: "https://" + c.provider.config.ControlPlaneVIP + ":9345"},
	}
	for _, field := range stringFields {
		got, found, err := unstructured.NestedString(base.Object, field.path...)
		if err != nil || !found || got != field.want {
			return fmt.Errorf("node load balancer: base NodeClass %s must equal CCM value %q, got %q", strings.Join(field.path, "."), field.want, got)
		}
	}
	billingAccountID, found, err := unstructured.NestedInt64(base.Object, "spec", "billingAccountID")
	if err != nil || !found || billingAccountID != c.provider.config.BillingAccountID {
		return fmt.Errorf("node load balancer: base NodeClass spec.billingAccountID must equal CCM billing account %d", c.provider.config.BillingAccountID)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensureNodePool(ctx context.Context, nodeClassName string, shard nodeLoadBalancerShardPlan) error {
	desired, err := renderNodeLoadBalancerNodePool(shard.Name, nodeClassName, shard)
	if err != nil {
		return err
	}
	if err := markNodeLoadBalancerManaged(desired, c.provider.config.ClusterID, shard.Name, nodeLoadBalancerShardProfileHash(shard)); err != nil {
		return err
	}
	return c.ensureDynamicObject(ctx, nodePoolGVR, desired)
}

func (c *nodeLoadBalancerController) ensureNodePoolFailClosed(
	ctx context.Context,
	nodeClassName string,
	shard nodeLoadBalancerShardPlan,
) error {
	if err := c.ensureNodePool(ctx, nodeClassName, shard); err != nil {
		return c.failNodeLoadBalancerShardClosed(ctx, shard.Name, err)
	}
	return nil
}

func markNodeLoadBalancerManaged(object *unstructured.Unstructured, cluster, shard, profile string) error {
	labels := object.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[nodeLoadBalancerManagedLabel] = "true"
	labels[nodeLoadBalancerClusterLabel] = cluster
	if shard != "" {
		labels[nodeLoadBalancerShardLabel] = shard
	}
	if profile != "" {
		labels[nodeLoadBalancerProfileLabel] = profile
	}
	object.SetLabels(labels)
	if shard != "" {
		templateLabels, _, err := unstructured.NestedStringMap(object.Object, "spec", "template", "metadata", "labels")
		if err != nil {
			return fmt.Errorf("node load balancer: read NodePool template labels: %w", err)
		}
		if templateLabels == nil {
			templateLabels = map[string]string{}
		}
		templateLabels[nodeLoadBalancerNodeClusterLabel] = cluster
		if err := unstructured.SetNestedStringMap(object.Object, templateLabels, "spec", "template", "metadata", "labels"); err != nil {
			return fmt.Errorf("node load balancer: set NodePool template cluster identity: %w", err)
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) ensureDynamicObject(ctx context.Context, gvr schema.GroupVersionResource, desired *unstructured.Unstructured) error {
	resource := c.provider.dynamicClient.Resource(gvr)
	existing, err := resource.Get(ctx, desired.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, createErr := resource.Create(ctx, desired, metav1.CreateOptions{})
		if createErr == nil {
			existing = created
			err = nil
		} else if !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("node load balancer: create %s %q: %w", desired.GetKind(), desired.GetName(), createErr)
		} else {
			existing, err = resource.Get(ctx, desired.GetName(), metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("node load balancer: read back concurrently created %s %q: %w", desired.GetKind(), desired.GetName(), err)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get %s %q: %w", desired.GetKind(), desired.GetName(), err)
	}
	if existing.GetLabels()[nodeLoadBalancerManagedLabel] != "true" ||
		existing.GetLabels()[nodeLoadBalancerClusterLabel] != desired.GetLabels()[nodeLoadBalancerClusterLabel] {
		return fmt.Errorf("node load balancer: refusing to adopt existing %s %q without exact cluster ownership labels", desired.GetKind(), desired.GetName())
	}
	if shard := desired.GetLabels()[nodeLoadBalancerShardLabel]; shard != "" && existing.GetLabels()[nodeLoadBalancerShardLabel] != shard {
		return fmt.Errorf("node load balancer: refusing to adopt existing %s %q with a different shard identity", desired.GetKind(), desired.GetName())
	}
	if existing.GetDeletionTimestamp() != nil {
		return fmt.Errorf("node load balancer: %s %q is still deleting", desired.GetKind(), desired.GetName())
	}
	desiredSpec, _, _ := unstructured.NestedFieldCopy(desired.Object, "spec")
	existingSpec, _, _ := unstructured.NestedFieldCopy(existing.Object, "spec")
	desiredLabels := desired.GetLabels()
	existingLabels := existing.GetLabels()
	labelsMatch := true
	for key, value := range desiredLabels {
		if existingLabels[key] != value {
			labelsMatch = false
			break
		}
	}
	if reflect.DeepEqual(existingSpec, desiredSpec) && labelsMatch {
		return nil
	}
	updated := existing.DeepCopy()
	if err := unstructured.SetNestedField(updated.Object, desiredSpec, "spec"); err != nil {
		return err
	}
	labels := updated.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range desiredLabels {
		labels[key] = value
	}
	updated.SetLabels(labels)
	if _, err := resource.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: update %s %q: %w", desired.GetKind(), desired.GetName(), err)
	}
	return nil
}

type desiredNodeLoadBalancerFirewall struct {
	Request inspace.CreateFirewallRequest
	Hash    string
}

func (c *nodeLoadBalancerController) desiredServiceFirewall(service *corev1.Service) (desiredNodeLoadBalancerFirewall, error) {
	serviceUID := string(service.UID)
	if serviceUID == "" {
		return desiredNodeLoadBalancerFirewall{}, errors.New("node load balancer: Service UID is required before creating a firewall")
	}
	if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
		return desiredNodeLoadBalancerFirewall{}, err
	}
	sources, err := canonicalNodeLoadBalancerSourceRanges(service.Spec.LoadBalancerSourceRanges)
	if err != nil {
		return desiredNodeLoadBalancerFirewall{}, err
	}
	ports, err := nodeLoadBalancerPortClaims(service)
	if err != nil {
		return desiredNodeLoadBalancerFirewall{}, err
	}
	rules := make([]inspace.FirewallRule, 0, len(ports))
	for _, port := range ports {
		start, stop := port.Port, port.Port
		rule := inspace.FirewallRule{
			Protocol: strings.ToLower(string(port.Protocol)), Direction: "inbound",
			PortStart: &start, PortEnd: &stop, EndpointSpecType: "any",
		}
		if len(sources) != 0 {
			rule.EndpointSpecType = "ip_prefixes"
			rule.EndpointSpec = append([]string(nil), sources...)
		}
		rules = append(rules, rule)
	}
	name, hash, err := inspace.NodeLoadBalancerServiceFirewallName(c.provider.config.ClusterID, serviceUID, rules)
	if err != nil {
		return desiredNodeLoadBalancerFirewall{}, err
	}
	return desiredNodeLoadBalancerFirewall{
		Request: inspace.CreateFirewallRequest{
			DisplayName: name, Description: "Managed InSpace node load balancer Service firewall", BillingAccountID: c.provider.config.BillingAccountID, Rules: rules,
		},
		Hash: hash,
	}, nil
}

func nodeLoadBalancerFirewallName(cluster, serviceUID, specHash string) string {
	return nodeLoadBalancerFirewallServicePrefix(cluster, serviceUID) + specHash
}

func nodeLoadBalancerFirewallServicePrefix(cluster, serviceUID string) string {
	return "inlb-" + shortNodeLoadBalancerHash(cluster) + "-" + serviceUID + "-"
}

func validateNodeLoadBalancerServiceUID(serviceUID string) error {
	if serviceUID == "" || serviceUID != strings.ToLower(serviceUID) || len(serviceUID) > 36 {
		return errors.New("node load balancer: Service UID must be a lowercase DNS label of at most 36 characters")
	}
	if messages := utilvalidation.IsDNS1123Label(serviceUID); len(messages) != 0 {
		return fmt.Errorf("node load balancer: Service UID %q is unsafe for firewall ownership: %s", serviceUID, strings.Join(messages, "; "))
	}
	return nil
}

func nodeLoadBalancerFirewallSpecHash(rules []inspace.FirewallRule) (string, error) {
	return inspace.NodeLoadBalancerServiceFirewallSpecHash(rules)
}

func canonicalNodeLoadBalancerSourceRanges(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("node load balancer: loadBalancerSourceRange %q must be an IPv4 CIDR", value)
		}
		canonical := prefix.Masked().String()
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			result = append(result, canonical)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (c *nodeLoadBalancerController) ensureServiceFirewall(ctx context.Context, service *corev1.Service, nodes []*corev1.Node) (*inspace.Firewall, string, bool, error) {
	desired, err := c.desiredServiceFirewall(service)
	if err != nil {
		return nil, "", false, err
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, "", false, fmt.Errorf("node load balancer: list firewalls: %w", err)
	}
	var firewall *inspace.Firewall
	var currentFirewallByUUID *inspace.Firewall
	var pendingFirewallByUUID *inspace.Firewall
	var pendingFirewallByName *inspace.Firewall
	pendingUUID := service.Annotations[annotationNodeLoadBalancerPendingFirewall]
	pendingName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	pendingStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	pendingDelete := service.Annotations[annotationNodeLoadBalancerPendingFWDelete] == "true"
	currentUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	currentHash := service.Annotations[annotationNodeLoadBalancerFirewallHash]
	if (currentUUID == "") != (currentHash == "") {
		return nil, "", false, errors.New("node load balancer: current firewall UUID and policy hash must be persisted together")
	}
	if pendingUUID != "" && pendingName == "" {
		return nil, "", false, errors.New("node load balancer: pending firewall UUID is missing its deterministic name")
	}
	if pendingName != "" && pendingStarted == "" {
		return nil, "", false, errors.New("node load balancer: pending firewall name is missing its create-attempt timestamp")
	}
	for i := range firewalls {
		if currentUUID != "" && firewalls[i].UUID == currentUUID {
			candidate := firewalls[i]
			currentFirewallByUUID = &candidate
		}
		if pendingUUID != "" && firewalls[i].UUID == pendingUUID {
			candidate := firewalls[i]
			pendingFirewallByUUID = &candidate
		}
		if pendingName != "" && firewalls[i].EffectiveName() == pendingName {
			if pendingFirewallByName != nil {
				return nil, "", false, fmt.Errorf("node load balancer: multiple firewalls use pending managed name %q", pendingName)
			}
			candidate := firewalls[i]
			pendingFirewallByName = &candidate
		}
		if firewalls[i].EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if firewall != nil {
			return nil, "", false, fmt.Errorf("node load balancer: multiple firewalls use managed name %q", desired.Request.DisplayName)
		}
		candidate := firewalls[i]
		if !nodeLoadBalancerFirewallMatches(candidate, desired) {
			return nil, "", false, fmt.Errorf("node load balancer: firewall name %q is occupied by a foreign or changed resource", desired.Request.DisplayName)
		}
		firewall = &candidate
	}
	if pendingName != "" {
		if pendingFirewallByUUID != nil && pendingFirewallByUUID.EffectiveName() != pendingName {
			return nil, "", false, fmt.Errorf("node load balancer: pending firewall %s does not use deterministic name %q", pendingUUID, pendingName)
		}
		if pendingFirewallByName != nil && pendingUUID != "" && pendingFirewallByName.UUID != pendingUUID {
			return nil, "", false, fmt.Errorf("node load balancer: pending firewall name %q resolved to unexpected UUID %s", pendingName, pendingFirewallByName.UUID)
		}
		pendingFirewall := pendingFirewallByName
		if pendingFirewall == nil {
			if _, confirmErr := c.confirmPendingFirewallAbsent(ctx, service, time.Now().UTC()); confirmErr != nil {
				return nil, "", false, confirmErr
			}
			// A successful create response is only a provisional handle. Do not
			// issue a second billable POST while its authoritative list readback
			// may still be converging. Confirmation and metadata clearing happen
			// in separate reconciliations before a replacement POST is allowed.
			return nil, "", false, nil
		}
		if !nodeLoadBalancerFirewallOwnedByService(*pendingFirewall, c.provider.config.ClusterID, string(service.UID), c.provider.config.BillingAccountID) {
			return nil, "", false, fmt.Errorf("node load balancer: pending firewall %q failed deterministic ownership readback", pendingName)
		}
		if patched, patchErr := c.ensurePendingFirewallMetadata(ctx, service, pendingFirewall.UUID, pendingName); patchErr != nil || patched {
			return nil, "", false, patchErr
		}
		if pendingDelete || pendingName != desired.Request.DisplayName {
			if patched, patchErr := c.ensurePendingFirewallDeletionMetadata(ctx, service); patchErr != nil || patched {
				return nil, "", false, patchErr
			}
			done, deleteErr := c.deleteOwnedServiceFirewall(ctx, service, pendingFirewall.UUID)
			if deleteErr != nil {
				return nil, "", false, deleteErr
			}
			_ = done // Absence still requires persisted, spaced list confirmations.
			return nil, "", false, nil
		}
		if patched, patchErr := c.promotePendingFirewallMetadata(ctx, service, pendingFirewall, desired.Hash); patchErr != nil || patched {
			return nil, "", false, patchErr
		}
	}
	if pendingName == "" && firewall == nil && currentUUID != "" && currentHash == desired.Hash {
		if currentFirewallByUUID != nil {
			return nil, "", false, fmt.Errorf("node load balancer: current firewall %s no longer matches its deterministic name and policy", currentUUID)
		}
		if _, confirmErr := c.confirmCurrentFirewallAbsent(ctx, service, time.Now().UTC()); confirmErr != nil {
			return nil, "", false, confirmErr
		}
		return nil, "", false, nil
	}
	if firewall != nil && (service.Annotations[annotationNodeLoadBalancerFirewallAbsent] != "" ||
		service.Annotations[annotationNodeLoadBalancerFirewallChecked] != "") {
		if patched, clearErr := c.clearFirewallAbsenceEvidence(
			ctx,
			service,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
		); clearErr != nil || patched {
			return nil, "", false, clearErr
		}
	}
	if firewall == nil {
		preparedService, err := c.ensurePendingFirewallCreateIntent(ctx, service, desired.Request.DisplayName)
		if err != nil {
			return nil, "", false, err
		}
		created, err := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
		if err != nil {
			if definitiveNodeLoadBalancerCreateFailure(err) {
				if _, clearErr := c.clearPendingFirewallMetadata(ctx, preparedService); clearErr != nil {
					return nil, "", false, errors.Join(fmt.Errorf("node load balancer: create Service firewall: %w", err), clearErr)
				}
			}
			return nil, "", false, fmt.Errorf("node load balancer: create Service firewall: %w", err)
		}
		if err := validateCreatedNodeLoadBalancerFirewall(created, desired); err != nil {
			return nil, "", false, fmt.Errorf("node load balancer: created firewall response: %w", err)
		}
		if _, err := c.ensurePendingFirewallMetadata(ctx, preparedService, created.UUID, desired.Request.DisplayName); err != nil {
			return nil, "", false, err
		}
		// InSpace may omit the name, description, billing account, and rules from
		// the POST response. Never assign from this provisional handle; the next
		// reconciliation must prove the deterministic name and exact policy via
		// ListFirewalls first.
		return nil, "", false, nil
	}

	ready := true
	for _, node := range nodes {
		if !nodeLoadBalancerNodeHealthy(node) {
			continue
		}
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			ready = false
			continue
		}
		if !firewallAssignedToVM(*firewall, vmUUID) {
			if err := c.provider.api.AssignFirewallToVM(ctx, c.provider.config.Location, firewall.UUID, vmUUID); err != nil {
				return nil, "", false, fmt.Errorf("node load balancer: assign firewall %s to VM %s: %w", firewall.UUID, vmUUID, err)
			}
			ready = false
		}
	}
	previousUUID := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	if previousUUID == "" && currentUUID != "" && currentUUID != firewall.UUID {
		previousUUID = currentUUID
	}
	return firewall, previousUUID, ready, nil
}

func definitiveNodeLoadBalancerCreateFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, inspace.ErrMutationBlocked) {
		return true
	}
	var apiErr *inspace.APIError
	return errors.As(err, &apiErr) && !apiErr.Retryable
}

func (c *nodeLoadBalancerController) ensurePendingFirewallCreateIntent(ctx context.Context, service *corev1.Service, name string) (*corev1.Service, error) {
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[annotationNodeLoadBalancerPendingFWName] = name
	copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] = time.Now().UTC().Format(time.RFC3339Nano)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFirewall)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWDelete)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: persist firewall create intent: %w", err)
	}
	return updated, nil
}

func (c *nodeLoadBalancerController) ensurePendingFirewallMetadata(ctx context.Context, service *corev1.Service, uuid, name string) (bool, error) {
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	if copy.Annotations[annotationNodeLoadBalancerPendingFirewall] == uuid &&
		copy.Annotations[annotationNodeLoadBalancerPendingFWName] == name &&
		copy.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
		copy.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
		return false, nil
	}
	copy.Annotations[annotationNodeLoadBalancerPendingFirewall] = uuid
	copy.Annotations[annotationNodeLoadBalancerPendingFWName] = name
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: persist provisional firewall identity: %w", err)
	}
	return true, nil
}

func (c *nodeLoadBalancerController) clearPendingFirewallMetadata(ctx context.Context, service *corev1.Service) (bool, error) {
	if service.Annotations[annotationNodeLoadBalancerPendingFirewall] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWName] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWStarted] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWDelete] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
		return false, nil
	}
	copy := service.DeepCopy()
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFirewall)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWName)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWStarted)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWDelete)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: clear provisional firewall identity: %w", err)
	}
	return true, nil
}

func (c *nodeLoadBalancerController) promotePendingFirewallMetadata(
	ctx context.Context,
	service *corev1.Service,
	firewall *inspace.Firewall,
	policyHash string,
) (bool, error) {
	if firewall == nil || firewall.UUID == "" || policyHash == "" {
		return false, errors.New("node load balancer: complete pending firewall identity is required for promotion")
	}
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	if current := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]; current != "" && current != firewall.UUID &&
		copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = current
	}
	copy.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewall.UUID
	copy.Annotations[annotationNodeLoadBalancerFirewallHash] = policyHash
	for _, key := range []string{
		annotationNodeLoadBalancerPendingFirewall,
		annotationNodeLoadBalancerPendingFWName,
		annotationNodeLoadBalancerPendingFWStarted,
		annotationNodeLoadBalancerPendingFWDelete,
		annotationNodeLoadBalancerPendingFWAbsent,
		annotationNodeLoadBalancerPendingFWChecked,
		annotationNodeLoadBalancerFirewallAbsent,
		annotationNodeLoadBalancerFirewallChecked,
	} {
		delete(copy.Annotations, key)
	}
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: atomically promote provisional firewall identity: %w", err)
	}
	return true, nil
}

func (c *nodeLoadBalancerController) ensurePendingFirewallDeletionMetadata(ctx context.Context, service *corev1.Service) (bool, error) {
	if service.Annotations[annotationNodeLoadBalancerPendingFWDelete] == "true" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
		service.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
		return false, nil
	}
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[annotationNodeLoadBalancerPendingFWDelete] = "true"
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
	delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: persist provisional firewall cleanup state: %w", err)
	}
	return true, nil
}

func (c *nodeLoadBalancerController) confirmPendingFirewallAbsent(ctx context.Context, service *corev1.Service, now time.Time) (bool, error) {
	started := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	if started == "" {
		return false, errors.New("node load balancer: pending firewall name is missing its create-attempt timestamp")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return false, fmt.Errorf("node load balancer: pending firewall create-attempt timestamp is invalid: %w", err)
	}
	confirmed, changed, err := c.recordFirewallAbsence(
		ctx,
		service,
		annotationNodeLoadBalancerPendingFWAbsent,
		annotationNodeLoadBalancerPendingFWChecked,
		now,
		startedAt.Add(nodeLoadBalancerPendingCreateTimeout),
	)
	if err != nil || changed || !confirmed {
		return false, err
	}
	// Clearing the intent is deliberately its own persisted reconciliation.
	// The next reconciliation performs a fresh authoritative list before it is
	// allowed to issue another billable create.
	_, err = c.clearPendingFirewallMetadata(ctx, service)
	return false, err
}

func (c *nodeLoadBalancerController) confirmCurrentFirewallAbsent(ctx context.Context, service *corev1.Service, now time.Time) (bool, error) {
	confirmed, changed, err := c.recordFirewallAbsence(
		ctx,
		service,
		annotationNodeLoadBalancerFirewallAbsent,
		annotationNodeLoadBalancerFirewallChecked,
		now,
		time.Time{},
	)
	if err != nil || changed || !confirmed {
		return false, err
	}
	copy := service.DeepCopy()
	delete(copy.Annotations, annotationNodeLoadBalancerFirewallUUID)
	delete(copy.Annotations, annotationNodeLoadBalancerFirewallHash)
	delete(copy.Annotations, annotationNodeLoadBalancerFirewallAbsent)
	delete(copy.Annotations, annotationNodeLoadBalancerFirewallChecked)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: clear repeatedly absent current firewall identity: %w", err)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) recordFirewallAbsence(
	ctx context.Context,
	service *corev1.Service,
	countAnnotation, checkedAnnotation string,
	now, notBefore time.Time,
) (confirmed, changed bool, err error) {
	if now.Before(notBefore) {
		return false, false, nil
	}
	count := 0
	if raw := service.Annotations[countAnnotation]; raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 0 || parsed > nodeLoadBalancerAbsenceConfirmations {
			return false, false, fmt.Errorf("node load balancer: invalid firewall absence count %q", raw)
		}
		count = parsed
	}
	if count >= nodeLoadBalancerAbsenceConfirmations {
		return true, false, nil
	}
	if raw := service.Annotations[checkedAnnotation]; raw != "" {
		checkedAt, parseErr := time.Parse(time.RFC3339Nano, raw)
		if parseErr != nil {
			return false, false, fmt.Errorf("node load balancer: invalid firewall absence timestamp: %w", parseErr)
		}
		if now.Before(checkedAt.Add(nodeLoadBalancerAbsenceConfirmationDelay)) {
			return false, false, nil
		}
	}
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[countAnnotation] = strconv.Itoa(count + 1)
	copy.Annotations[checkedAnnotation] = now.UTC().Format(time.RFC3339Nano)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, false, fmt.Errorf("node load balancer: persist firewall absence evidence: %w", err)
	}
	return false, true, nil
}

func (c *nodeLoadBalancerController) clearFirewallAbsenceEvidence(
	ctx context.Context,
	service *corev1.Service,
	countAnnotation, checkedAnnotation string,
) (bool, error) {
	if service.Annotations[countAnnotation] == "" && service.Annotations[checkedAnnotation] == "" {
		return false, nil
	}
	copy := service.DeepCopy()
	delete(copy.Annotations, countAnnotation)
	delete(copy.Annotations, checkedAnnotation)
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: clear firewall absence evidence: %w", err)
	}
	return true, nil
}

func nodeLoadBalancerFirewallMatches(firewall inspace.Firewall, desired desiredNodeLoadBalancerFirewall) bool {
	if (firewall.Description != "" && firewall.Description != desired.Request.Description) || firewall.BillingAccountID != desired.Request.BillingAccountID ||
		firewall.EffectiveName() != desired.Request.DisplayName || len(firewall.Rules) != len(desired.Request.Rules) {
		return false
	}
	gotRules := make(map[string]int, len(firewall.Rules))
	for _, rule := range firewall.Rules {
		gotRules[nodeLoadBalancerFirewallRuleKey(rule)]++
	}
	for _, rule := range desired.Request.Rules {
		key := nodeLoadBalancerFirewallRuleKey(rule)
		if gotRules[key] == 0 {
			return false
		}
		gotRules[key]--
	}
	return true
}

func validateCreatedNodeLoadBalancerFirewall(firewall *inspace.Firewall, desired desiredNodeLoadBalancerFirewall) error {
	if firewall == nil || firewall.UUID == "" {
		return errors.New("response has no firewall UUID")
	}
	if name := firewall.EffectiveName(); name != "" && name != desired.Request.DisplayName {
		return fmt.Errorf("name %q does not match %q", name, desired.Request.DisplayName)
	}
	if firewall.BillingAccountID != 0 && firewall.BillingAccountID != desired.Request.BillingAccountID {
		return errors.New("billing account does not match")
	}
	if firewall.Description != "" && firewall.Description != desired.Request.Description {
		return errors.New("description does not match")
	}
	return nil
}

func nodeLoadBalancerFirewallRuleKey(rule inspace.FirewallRule) string {
	start, stop := int32(0), int32(0)
	if rule.PortStart != nil {
		start = *rule.PortStart
	}
	if rule.PortEnd != nil {
		stop = *rule.PortEnd
	}
	endpoints := append([]string(nil), rule.EndpointSpec...)
	sort.Strings(endpoints)
	return strings.Join([]string{
		rule.Protocol, rule.Direction, strconv.FormatInt(int64(start), 10), strconv.FormatInt(int64(stop), 10),
		rule.EndpointSpecType, strings.Join(endpoints, ","),
	}, "|")
}

func firewallAssignedToVM(firewall inspace.Firewall, vmUUID string) bool {
	for _, resource := range firewall.ResourcesAssigned {
		if strings.EqualFold(resource.ResourceType, "vm") && resource.ResourceUUID == vmUUID {
			return true
		}
	}
	return false
}

func nodeLoadBalancerVMUUID(node *corev1.Node) (string, bool) {
	if node == nil || node.Spec.ProviderID == "" {
		return "", false
	}
	id, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil {
		return "", false
	}
	return id.UUID, true
}

func (c *nodeLoadBalancerController) ensureFirewallMetadata(ctx context.Context, service *corev1.Service, firewall *inspace.Firewall, previousUUID string) (bool, error) {
	desired, err := c.desiredServiceFirewall(service)
	if err != nil {
		return false, err
	}
	copy := service.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	changed := false
	for key, value := range map[string]string{
		annotationNodeLoadBalancerFirewallUUID: firewall.UUID,
		annotationNodeLoadBalancerFirewallHash: desired.Hash,
	} {
		if copy.Annotations[key] != value {
			copy.Annotations[key] = value
			changed = true
		}
	}
	if previousUUID != "" && previousUUID != firewall.UUID && copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = previousUUID
		changed = true
	}
	for _, key := range []string{annotationNodeLoadBalancerFirewallAbsent, annotationNodeLoadBalancerFirewallChecked} {
		if copy.Annotations[key] != "" {
			delete(copy.Annotations, key)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	_, err = c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	return true, err
}

func nodeLoadBalancerShadowName(service *corev1.Service) string {
	base := service.Name + "-node-lb"
	if len(base) <= 63 {
		return base
	}
	hash := shortNodeLoadBalancerHash(string(service.UID))
	prefix := strings.TrimRight(service.Name[:min(len(service.Name), 54)], "-")
	return prefix + "-" + hash
}

func (c *nodeLoadBalancerController) validateShadowServiceName(ctx context.Context, service *corev1.Service) error {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: preflight shadow Service name: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return fmt.Errorf("node load balancer: shadow Service name %s/%s is occupied by another owner", service.Namespace, shadow.Name)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensureShadowService(ctx context.Context, service *corev1.Service, shard string) (*corev1.Service, error) {
	name := nodeLoadBalancerShadowName(service)
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("node load balancer: get shadow Service: %w", err)
	}
	desired := desiredNodeLoadBalancerShadow(service, name, c.provider.config.ClusterID, shard)
	if apierrors.IsNotFound(err) {
		created, createErr := client.Create(ctx, desired, metav1.CreateOptions{})
		if createErr != nil {
			return nil, fmt.Errorf("node load balancer: create shadow Service: %w", createErr)
		}
		return created, nil
	}
	if !nodeLoadBalancerShadowOwnedByService(existing, service) {
		return nil, fmt.Errorf("node load balancer: shadow Service name %s/%s is occupied by another owner", service.Namespace, name)
	}
	desired.ResourceVersion = existing.ResourceVersion
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = append([]string(nil), existing.Spec.ClusterIPs...)
	desired.Spec.IPFamilies = append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
	desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	if reflect.DeepEqual(existing.Labels, desired.Labels) && reflect.DeepEqual(existing.Annotations, desired.Annotations) &&
		reflect.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) && reflect.DeepEqual(existing.Spec, desired.Spec) {
		return existing, nil
	}
	updated, err := client.Update(ctx, desired, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: update shadow Service: %w", err)
	}
	return updated, nil
}

func (c *nodeLoadBalancerController) quarantineInvalidService(ctx context.Context, service *corev1.Service) error {
	if err := c.deleteOwnedShadowService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedShadowServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	if changed, err := c.preparePendingFirewallTeardown(ctx, service, owned); err != nil || changed {
		if changed {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		}
		return err
	}
	for _, firewall := range owned {
		done, deleteErr := c.deleteOwnedServiceFirewall(ctx, service, firewall.UUID)
		if deleteErr != nil {
			return deleteErr
		}
		if !done {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		if _, err := c.confirmPendingFirewallAbsent(ctx, service, time.Now().UTC()); err != nil {
			return err
		}
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	if err := c.clearInvalidServiceFirewallMetadata(ctx, service); err != nil {
		return err
	}
	if err := c.clearServiceLoadBalancerStatus(ctx, service); err != nil {
		return err
	}
	return c.cleanupInvalidServiceShards(ctx, service)
}

func (c *nodeLoadBalancerController) cleanupInvalidServiceShards(ctx context.Context, service *corev1.Service) error {
	seen := map[string]struct{}{}
	for _, shard := range []string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
	} {
		if shard == "" {
			continue
		}
		if _, duplicate := seen[shard]; duplicate {
			continue
		}
		seen[shard] = struct{}{}
		remaining, err := c.servicesForShard(ctx, service, shard)
		if err != nil {
			return err
		}
		if len(remaining) != 0 {
			continue
		}
		nodes, err := c.rawNodesForShard(shard)
		if err != nil {
			return err
		}
		if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
			return err
		}
		if err := c.deleteManagedNodePool(ctx, shard); err != nil {
			return err
		}
		if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); err == nil {
			if c.queue != nil {
				c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			}
			return nil
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) preparePendingFirewallTeardown(
	ctx context.Context,
	service *corev1.Service,
	owned []inspace.Firewall,
) (bool, error) {
	pendingName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	pendingUUID := service.Annotations[annotationNodeLoadBalancerPendingFirewall]
	if pendingName == "" {
		if pendingUUID != "" || service.Annotations[annotationNodeLoadBalancerPendingFWStarted] != "" ||
			service.Annotations[annotationNodeLoadBalancerPendingFWDelete] != "" ||
			service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" ||
			service.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
			return false, errors.New("node load balancer: provisional firewall metadata is missing its deterministic name")
		}
		return false, nil
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWStarted] == "" {
		return false, errors.New("node load balancer: pending firewall name is missing its create-attempt timestamp")
	}
	var pending *inspace.Firewall
	for i := range owned {
		if pendingUUID != "" && owned[i].UUID == pendingUUID && owned[i].EffectiveName() != pendingName {
			return false, fmt.Errorf("node load balancer: pending firewall %s does not use deterministic name %q", pendingUUID, pendingName)
		}
		if owned[i].EffectiveName() != pendingName {
			continue
		}
		if pending != nil {
			return false, fmt.Errorf("node load balancer: multiple firewalls use pending managed name %q", pendingName)
		}
		candidate := owned[i]
		pending = &candidate
	}
	if pending != nil && pendingUUID != "" && pending.UUID != pendingUUID {
		return false, fmt.Errorf("node load balancer: pending firewall name %q resolved to unexpected UUID %s", pendingName, pending.UUID)
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWDelete] != "true" ||
		(pending != nil && (service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" ||
			service.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "")) {
		return c.ensurePendingFirewallDeletionMetadata(ctx, service)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) invalidServiceIsQuarantined(ctx context.Context, service *corev1.Service) (bool, error) {
	if _, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{}); err == nil {
		return false, nil
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("node load balancer: prove invalid shadow Service absence: %w", err)
	}
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: prove invalid Service status absence: %w", err)
	}
	if len(current.Status.LoadBalancer.Ingress) != 0 || current.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		return false, nil
	}
	owned, err := c.ownedServiceFirewalls(ctx, current)
	if err != nil {
		return false, err
	}
	return len(owned) == 0, nil
}

func (c *nodeLoadBalancerController) clearInvalidServiceFirewallMetadata(ctx context.Context, service *corev1.Service) error {
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	copy := current.DeepCopy()
	changed := false
	for _, key := range []string{
		annotationNodeLoadBalancerFirewallUUID,
		annotationNodeLoadBalancerFirewallHash,
		annotationNodeLoadBalancerFirewallAbsent,
		annotationNodeLoadBalancerFirewallChecked,
		annotationNodeLoadBalancerPreviousFirewall,
	} {
		if _, exists := copy.Annotations[key]; exists {
			delete(copy.Annotations, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: clear invalid Service firewall metadata: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) deleteOwnedShadowService(ctx context.Context, service *corev1.Service) error {
	name := nodeLoadBalancerShadowName(service)
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	shadow, err := client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get shadow Service before delete: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return fmt.Errorf("node load balancer: refusing to delete shadow Service %s/%s without exact owner identity", service.Namespace, name)
	}
	if err := client.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: delete shadow Service: %w", err)
	}
	return nil
}

func nodeLoadBalancerShadowOwnedByService(shadow, service *corev1.Service) bool {
	if shadow == nil || service == nil || shadow.Labels[nodeLoadBalancerShadowLabel] != "true" ||
		shadow.Labels[nodeLoadBalancerServiceUIDLabel] != string(service.UID) || len(shadow.OwnerReferences) != 1 {
		return false
	}
	reference := shadow.OwnerReferences[0]
	return reference.APIVersion == "v1" && reference.Kind == "Service" && reference.UID == service.UID &&
		reference.Name == service.Name && reference.Controller != nil && *reference.Controller &&
		reference.BlockOwnerDeletion != nil && *reference.BlockOwnerDeletion
}

func (c *nodeLoadBalancerController) ownedShadowServiceAbsent(ctx context.Context, service *corev1.Service) (bool, error) {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: prove shadow Service absence: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return false, fmt.Errorf("node load balancer: shadow Service name %s/%s is occupied by another owner", service.Namespace, shadow.Name)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) clearServiceLoadBalancerStatus(ctx context.Context, service *corev1.Service) error {
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(current.Status.LoadBalancer.Ingress) == 0 {
		return nil
	}
	copy := current.DeepCopy()
	copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: clear Service load balancer status: %w", err)
	}
	return nil
}

func desiredNodeLoadBalancerShadow(service *corev1.Service, name, cluster, shard string) *corev1.Service {
	ciliumClass := nodeLoadBalancerCiliumClass
	allocateNodePorts := false
	controller := true
	blockOwnerDeletion := true
	ports := append([]corev1.ServicePort(nil), service.Spec.Ports...)
	for i := range ports {
		ports[i].NodePort = 0
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: service.Namespace, Name: name,
			Labels: map[string]string{
				nodeLoadBalancerShadowLabel: "true", nodeLoadBalancerServiceUIDLabel: string(service.UID),
			},
			Annotations: map[string]string{
				annotationCiliumNodeIPAMMatchLabels: nodeLoadBalancerCiliumSelector(cluster, shard),
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, LoadBalancerClass: &ciliumClass,
			AllocateLoadBalancerNodePorts: &allocateNodePorts,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyCluster,
			Selector:                      copyStringMap(service.Spec.Selector),
			Ports:                         ports,
			SessionAffinity:               service.Spec.SessionAffinity,
			SessionAffinityConfig:         service.Spec.SessionAffinityConfig.DeepCopy(),
			PublishNotReadyAddresses:      service.Spec.PublishNotReadyAddresses,
			LoadBalancerSourceRanges:      append([]string(nil), service.Spec.LoadBalancerSourceRanges...),
			IPFamilyPolicy:                service.Spec.IPFamilyPolicy,
			IPFamilies:                    append([]corev1.IPFamily(nil), service.Spec.IPFamilies...),
			InternalTrafficPolicy:         service.Spec.InternalTrafficPolicy,
			TrafficDistribution:           service.Spec.TrafficDistribution,
		},
	}
}

func copyStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func (c *nodeLoadBalancerController) copyShadowStatus(ctx context.Context, service *corev1.Service) error {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if reflect.DeepEqual(service.Status.LoadBalancer, shadow.Status.LoadBalancer) {
		return nil
	}
	copy := service.DeepCopy()
	copy.Status.LoadBalancer = *shadow.Status.LoadBalancer.DeepCopy()
	if _, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: copy shadow status: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) shadowServiceUsesShard(ctx context.Context, service *corev1.Service, shard string) (bool, error) {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: get shadow Service for cutover: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return false, fmt.Errorf("node load balancer: shadow Service name %s/%s is occupied by another owner", service.Namespace, shadow.Name)
	}
	wantSelector := nodeLoadBalancerCiliumSelector(c.provider.config.ClusterID, shard)
	return shadow.Annotations[annotationCiliumNodeIPAMMatchLabels] == wantSelector, nil
}

func (c *nodeLoadBalancerController) readyShardNodes(ctx context.Context, shard string) ([]*corev1.Node, []string, error) {
	authorized, err := c.authorizedNodesForShard(ctx, shard)
	if err != nil {
		return nil, nil, err
	}
	nodes := make([]*corev1.Node, 0, len(authorized))
	externalIPs := make([]string, 0, len(authorized))
	seenIPs := map[string]struct{}{}
	for _, node := range authorized {
		if node.Labels[nodeLoadBalancerReadyLabel] != "true" || !nodeLoadBalancerNodeHealthy(node) {
			continue
		}
		externalIP, ok := nodeLoadBalancerNodeExternalIPv4(node)
		if !ok {
			continue
		}
		if _, duplicate := seenIPs[externalIP]; duplicate {
			return nil, nil, fmt.Errorf("node load balancer: shard %s has duplicate ExternalIP %s", shard, externalIP)
		}
		seenIPs[externalIP] = struct{}{}
		nodes = append(nodes, node)
		externalIPs = append(externalIPs, externalIP)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	sort.Strings(externalIPs)
	return nodes, externalIPs, nil
}

func (c *nodeLoadBalancerController) shadowStatusMatchesExternalIPs(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	expected []string,
) (bool, error) {
	shadow, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerShadowName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: get shadow Service status: %w", err)
	}
	if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
		return false, fmt.Errorf("node load balancer: shadow Service name %s/%s is occupied by another owner", service.Namespace, shadow.Name)
	}
	wantSelector := nodeLoadBalancerCiliumSelector(c.provider.config.ClusterID, shard)
	if shadow.Annotations[annotationCiliumNodeIPAMMatchLabels] != wantSelector {
		return false, nil
	}
	want := make(map[string]struct{}, len(expected))
	for _, value := range expected {
		want[value] = struct{}{}
	}
	got := make(map[string]struct{}, len(shadow.Status.LoadBalancer.Ingress))
	for _, ingress := range shadow.Status.LoadBalancer.Ingress {
		address, parseErr := netip.ParseAddr(ingress.IP)
		if parseErr != nil || !address.Is4() || ingress.IP != address.String() || ingress.Hostname != "" {
			return false, nil
		}
		if _, duplicate := got[ingress.IP]; duplicate {
			return false, nil
		}
		got[ingress.IP] = struct{}{}
	}
	return reflect.DeepEqual(got, want), nil
}

func (c *nodeLoadBalancerController) rawNodesForShard(shard string) ([]*corev1.Node, error) {
	return c.nodes.List(labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   shard,
	}))
}

func (c *nodeLoadBalancerController) rawNodesForCluster() ([]*corev1.Node, error) {
	return c.nodes.List(labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
	}))
}

// authorizedNodesForShard returns only Nodes whose kubelet-visible labels and
// provider ID are backed by Karpenter's API-owned identity chain. Callers that
// attach public firewalls or publish addresses must use this helper, never the
// raw label selector.
func (c *nodeLoadBalancerController) authorizedNodesForShard(ctx context.Context, shard string) ([]*corev1.Node, error) {
	raw, err := c.rawNodesForShard(shard)
	if err != nil {
		return nil, err
	}
	return c.authorizedNodeLoadBalancerNodes(ctx, raw, shard)
}

// authorizedNodesForCluster is the cluster-wide equivalent used for shared
// infrastructure that is attached to every managed Node load balancer VM.
func (c *nodeLoadBalancerController) authorizedNodesForCluster(ctx context.Context) ([]*corev1.Node, error) {
	raw, err := c.rawNodesForCluster()
	if err != nil {
		return nil, err
	}
	return c.authorizedNodeLoadBalancerNodes(ctx, raw, "")
}

func (c *nodeLoadBalancerController) authorizedNodeLoadBalancerNodes(
	ctx context.Context,
	raw []*corev1.Node,
	requiredShard string,
) ([]*corev1.Node, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if requiredShard != "" && !isManagedNodeLoadBalancerShardName(requiredShard) {
		return nil, fmt.Errorf("node load balancer: refusing to authorize invalid shard %q", requiredShard)
	}

	nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
	nodeClass, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("node load balancer: get generated NodeClass for Node authorization: %w", err)
	}
	if err := c.validateManagedNodeLoadBalancerNodeClass(nodeClass, nodeClassName); err != nil {
		return nil, err
	}
	claims, err := c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list NodeClaims for Node authorization: %w", err)
	}

	pools := map[string]*unstructured.Unstructured{}
	authorized := make([]*corev1.Node, 0, len(raw))
	for _, cached := range raw {
		current, getErr := c.provider.kubeClient.CoreV1().Nodes().Get(ctx, cached.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			continue
		}
		if getErr != nil {
			return nil, fmt.Errorf("node load balancer: read back Node %s for authorization: %w", cached.Name, getErr)
		}
		shard := current.Labels[nodeLoadBalancerNodeShardLabel]
		if current.Labels[nodeLoadBalancerNodeLabel] != "true" ||
			current.Labels[nodeLoadBalancerNodeClusterLabel] != c.provider.config.ClusterID ||
			(requiredShard != "" && shard != requiredShard) ||
			!isManagedNodeLoadBalancerShardName(shard) {
			continue
		}
		pool, loaded := pools[shard]
		if !loaded {
			pool, err = c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				pools[shard] = nil
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("node load balancer: get NodePool %s for Node authorization: %w", shard, err)
			}
			pools[shard] = pool
		}
		if pool == nil || !c.nodeLoadBalancerNodePoolAuthoritative(pool, shard, nodeClassName) {
			klog.InfoS("Ignoring Node without an authoritative Node load balancer NodePool", "node", current.Name, "shard", shard)
			continue
		}
		claim, reason := c.uniqueAuthoritativeNodeClaim(current, pool, nodeClassName, claims.Items)
		if claim == nil {
			klog.InfoS("Ignoring Node without an authoritative NodeClaim identity chain", "node", current.Name, "shard", shard, "reason", reason)
			continue
		}
		fipAuthorized, fipReason, fipErr := c.nodeLoadBalancerFloatingIPAuthoritative(ctx, current)
		if fipErr != nil {
			return nil, fipErr
		}
		if !fipAuthorized {
			klog.InfoS("Ignoring Node without an authoritative floating IPv4 assignment", "node", current.Name, "shard", shard, "reason", fipReason)
			continue
		}
		authorized = append(authorized, current.DeepCopy())
	}
	sort.Slice(authorized, func(i, j int) bool { return authorized[i].Name < authorized[j].Name })
	return authorized, nil
}

func (c *nodeLoadBalancerController) nodeLoadBalancerFloatingIPAuthoritative(
	ctx context.Context,
	node *corev1.Node,
) (bool, string, error) {
	identity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || identity.Location != c.provider.config.Location || identity.String() != node.Spec.ProviderID {
		return false, "Node providerID is invalid or non-canonical", nil
	}
	// Do not filter by billing account here. A second active FIP owned by a
	// different account still reaches the same VM-wide firewall surface and
	// must make the Node ineligible rather than being hidden by the API filter.
	items, err := c.provider.api.ListFloatingIPs(ctx, c.provider.config.Location, &inspace.FloatingIPFilters{VMUUID: identity.UUID})
	if err != nil {
		return false, "", fmt.Errorf("node load balancer: list floating IPs for VM %s: %w", identity.UUID, err)
	}
	assigned := make([]inspace.FloatingIP, 0, 1)
	for _, item := range items {
		if item.AssignedTo == identity.UUID && item.Enabled && !item.IsDeleted {
			assigned = append(assigned, item)
		}
	}
	if len(assigned) != 1 {
		return false, fmt.Sprintf("expected one floating IP assigned to VM %s, found %d", identity.UUID, len(assigned)), nil
	}
	item := assigned[0]
	if item.BillingAccountID != c.provider.config.BillingAccountID || !item.Enabled || item.IsDeleted || item.IsVirtual ||
		item.Type != "public" || item.AssignedToResourceType != "virtual_machine" {
		return false, "floating IP is not one active public assignment owned by the configured billing account", nil
	}
	address, parseErr := netip.ParseAddr(item.Address)
	if parseErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != item.Address {
		return false, "floating IP address is not canonical global IPv4", nil
	}
	externalIP, ok := nodeLoadBalancerNodeExternalIPv4(node)
	if !ok || externalIP != item.Address {
		return false, "Node ExternalIP does not match its authoritative InSpace floating IP assignment", nil
	}
	return true, "", nil
}

func (c *nodeLoadBalancerController) validateManagedNodeLoadBalancerNodeClass(
	nodeClass *unstructured.Unstructured,
	expectedName string,
) error {
	if nodeClass == nil || nodeClass.GetName() != expectedName || nodeClass.GetDeletionTimestamp() != nil ||
		nodeClass.GetLabels()[nodeLoadBalancerManagedLabel] != "true" ||
		nodeClass.GetLabels()[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID {
		return errors.New("node load balancer: generated NodeClass lacks exact controller ownership")
	}
	if err := c.validateBaseNodeClass(nodeClass); err != nil {
		return fmt.Errorf("node load balancer: generated NodeClass identity is invalid: %w", err)
	}
	profile, profileFound, profileErr := unstructured.NestedString(nodeClass.Object, "spec", "firewallProfile")
	disk, diskFound, diskErr := unstructured.NestedInt64(nodeClass.Object, "spec", "rootDiskGiB")
	reservePublicIPv4, reserveFound, reserveErr := unstructured.NestedBool(nodeClass.Object, "spec", "reservePublicIPv4")
	if profileErr != nil || !profileFound || profile != nodeLoadBalancerFirewallMode ||
		diskErr != nil || !diskFound || disk != 30 ||
		reserveErr != nil || !reserveFound || !reservePublicIPv4 {
		return errors.New("node load balancer: generated NodeClass does not match the hardened public Node load balancer contract")
	}
	for _, field := range []string{"sshUsername", "sshPublicKey", "additionalUserData"} {
		if _, found, fieldErr := unstructured.NestedFieldNoCopy(nodeClass.Object, "spec", field); fieldErr != nil || found {
			return fmt.Errorf("node load balancer: generated NodeClass must not expose spec.%s", field)
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) nodeLoadBalancerNodePoolAuthoritative(
	pool *unstructured.Unstructured,
	shard, nodeClassName string,
) bool {
	if pool == nil || pool.GetName() != shard || pool.GetUID() == "" || pool.GetDeletionTimestamp() != nil {
		return false
	}
	poolLabels := pool.GetLabels()
	if poolLabels[nodeLoadBalancerManagedLabel] != "true" ||
		poolLabels[nodeLoadBalancerLabel] != "true" ||
		poolLabels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		poolLabels[nodeLoadBalancerShardLabel] != shard ||
		poolLabels[nodeLoadBalancerModeLabel] == "" ||
		poolLabels[nodeLoadBalancerPoolLabel] == "" ||
		poolLabels[nodeLoadBalancerProfileLabel] == "" {
		return false
	}
	replicas, found, err := unstructured.NestedInt64(pool.Object, "spec", "replicas")
	if err != nil || !found || replicas < 1 || replicas > int64(^uint32(0)>>1) {
		return false
	}
	cpuValue, ok := exactNodeLoadBalancerRequirementValue(pool, "inspace.cloud/instance-cpu")
	if !ok {
		return false
	}
	cpu, err := strconv.ParseInt(cpuValue, 10, 32)
	if err != nil || cpu < 1 {
		return false
	}
	memoryValue, ok := exactNodeLoadBalancerRequirementValue(pool, "inspace.cloud/instance-memory")
	if !ok {
		return false
	}
	memoryMiB, err := strconv.ParseInt(memoryValue, 10, 64)
	if err != nil || memoryMiB < 1 {
		return false
	}
	desiredShard := nodeLoadBalancerShardPlan{
		Name: shard, Mode: poolLabels[nodeLoadBalancerModeLabel], Pool: poolLabels[nodeLoadBalancerPoolLabel],
		NodesPerShard: int32(replicas), CPU: int32(cpu), MemoryMiB: memoryMiB,
	}
	if poolLabels[nodeLoadBalancerProfileLabel] != nodeLoadBalancerShardProfileHash(desiredShard) {
		return false
	}
	desired, err := renderNodeLoadBalancerNodePool(shard, nodeClassName, desiredShard)
	if err != nil {
		return false
	}
	if err := markNodeLoadBalancerManaged(
		desired,
		c.provider.config.ClusterID,
		shard,
		nodeLoadBalancerShardProfileHash(desiredShard),
	); err != nil {
		return false
	}
	for key, value := range desired.GetLabels() {
		if poolLabels[key] != value {
			return false
		}
	}
	desiredSpec, desiredFound, desiredErr := unstructured.NestedFieldCopy(desired.Object, "spec")
	actualSpec, actualFound, actualErr := unstructured.NestedFieldCopy(pool.Object, "spec")
	return desiredErr == nil && actualErr == nil && desiredFound && actualFound && reflect.DeepEqual(actualSpec, desiredSpec)
}

func exactNodeLoadBalancerRequirementValue(pool *unstructured.Unstructured, key string) (string, bool) {
	requirements, found, err := unstructured.NestedSlice(pool.Object, "spec", "template", "spec", "requirements")
	if err != nil || !found {
		return "", false
	}
	value := ""
	matches := 0
	for _, raw := range requirements {
		requirement, ok := raw.(map[string]any)
		if !ok || requirement["key"] != key {
			continue
		}
		matches++
		operator, operatorOK := requirement["operator"].(string)
		values, valuesOK := requirement["values"].([]any)
		if !operatorOK || operator != string(corev1.NodeSelectorOpIn) || !valuesOK || len(values) != 1 {
			return "", false
		}
		value, ok = values[0].(string)
		if !ok || value == "" {
			return "", false
		}
	}
	return value, matches == 1
}

func (c *nodeLoadBalancerController) uniqueAuthoritativeNodeClaim(
	node *corev1.Node,
	pool *unstructured.Unstructured,
	nodeClassName string,
	claims []unstructured.Unstructured,
) (*unstructured.Unstructured, string) {
	providerIdentity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || providerIdentity.Location != c.provider.config.Location || providerIdentity.String() != node.Spec.ProviderID {
		return nil, "Node providerID is invalid or non-canonical"
	}
	shard := pool.GetName()
	matches := make([]*unstructured.Unstructured, 0, 1)
	for index := range claims {
		claim := &claims[index]
		claimProviderID, providerFound, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
		claimNodeName, nodeFound, nodeErr := unstructured.NestedString(claim.Object, "status", "nodeName")
		if providerErr != nil || nodeErr != nil {
			continue
		}
		if (providerFound && claimProviderID == node.Spec.ProviderID) || (nodeFound && claimNodeName == node.Name) {
			matches = append(matches, claim)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Sprintf("expected one matching NodeClaim, found %d", len(matches))
	}
	claim := matches[0]
	claimProviderID, providerFound, _ := unstructured.NestedString(claim.Object, "status", "providerID")
	claimNodeName, nodeFound, _ := unstructured.NestedString(claim.Object, "status", "nodeName")
	if !providerFound || !nodeFound || claimProviderID != node.Spec.ProviderID || claimNodeName != node.Name ||
		claim.GetUID() == "" || claim.GetDeletionTimestamp() != nil ||
		!strings.HasPrefix(claim.GetName(), shard+"-") || len(claim.GetName()) == len(shard)+1 {
		return nil, "NodeClaim status or generated identity does not match the Node"
	}
	claimLabels := claim.GetLabels()
	if claimLabels[karpenterNodePoolLabel] != shard ||
		claimLabels[nodeLoadBalancerNodeLabel] != "true" ||
		claimLabels[nodeLoadBalancerNodeClusterLabel] != c.provider.config.ClusterID ||
		claimLabels[nodeLoadBalancerNodeShardLabel] != shard ||
		node.Labels[karpenterNodePoolLabel] != shard {
		return nil, "NodeClaim labels do not match the managed NodePool"
	}
	if !nodeLoadBalancerNodeClassRefMatches(claim, []string{"spec", "nodeClassRef"}, nodeClassName) {
		return nil, "NodeClaim does not reference the generated NodeClass"
	}
	if !hasExactSingleNodeLoadBalancerOwnerReference(
		node.OwnerReferences, "karpenter.sh/v1", "NodeClaim", claim.GetName(), claim.GetUID(),
	) {
		return nil, "Node ownerReference does not match the unique NodeClaim"
	}
	if !hasExactSingleNodeLoadBalancerOwnerReference(
		claim.GetOwnerReferences(), "karpenter.sh/v1", "NodePool", pool.GetName(), pool.GetUID(),
	) {
		return nil, "NodeClaim ownerReference does not match the managed NodePool"
	}
	return claim, ""
}

func nodeLoadBalancerNodeClassRefMatches(object *unstructured.Unstructured, path []string, name string) bool {
	group, groupFound, groupErr := unstructured.NestedString(object.Object, append(path, "group")...)
	kind, kindFound, kindErr := unstructured.NestedString(object.Object, append(path, "kind")...)
	refName, nameFound, nameErr := unstructured.NestedString(object.Object, append(path, "name")...)
	return groupErr == nil && kindErr == nil && nameErr == nil && groupFound && kindFound && nameFound &&
		group == "karpenter.inspace.cloud" && kind == "InSpaceNodeClass" && refName == name
}

func hasExactSingleNodeLoadBalancerOwnerReference(
	references []metav1.OwnerReference,
	apiVersion, kind, name string,
	uid types.UID,
) bool {
	matchingKind := 0
	exact := false
	for _, reference := range references {
		if reference.APIVersion != apiVersion || reference.Kind != kind {
			continue
		}
		matchingKind++
		if reference.Name == name && reference.UID == uid && reference.BlockOwnerDeletion != nil && *reference.BlockOwnerDeletion {
			exact = true
		}
	}
	return matchingKind == 1 && exact
}

func (c *nodeLoadBalancerController) detachServiceFirewallFromOtherNodes(
	ctx context.Context,
	service *corev1.Service,
	firewall *inspace.Firewall,
	nodes []*corev1.Node,
) error {
	if firewall == nil {
		return errors.New("node load balancer: Service firewall is required for assignment cleanup")
	}
	desiredVMs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			return fmt.Errorf("node load balancer: selected shard Node %s has no valid InSpace provider identity", node.Name)
		}
		desiredVMs[vmUUID] = struct{}{}
	}
	staleVMs, err := staleNodeLoadBalancerFirewallAssignments(*firewall, desiredVMs)
	if err != nil || len(staleVMs) == 0 {
		return err
	}
	var mutationErr error
	for _, vmUUID := range staleVMs {
		if err := c.provider.api.UnassignFirewallFromVM(ctx, c.provider.config.Location, firewall.UUID, vmUUID); err != nil && !inspace.IsNotFound(err) {
			mutationErr = errors.Join(mutationErr, fmt.Errorf("unassign firewall %s from stale VM %s: %w", firewall.UUID, vmUUID, err))
		}
	}

	readbackCtx, cancel := context.WithTimeout(ctx, nodeLoadBalancerAssignmentReadbackTimeout)
	defer cancel()
	var lastObservation error
	for {
		firewalls, listErr := c.provider.api.ListFirewalls(readbackCtx, c.provider.config.Location)
		if listErr == nil {
			var current *inspace.Firewall
			for i := range firewalls {
				if firewalls[i].UUID == firewall.UUID {
					copy := firewalls[i]
					current = &copy
					break
				}
			}
			if current == nil {
				return fmt.Errorf("node load balancer: Service firewall %s disappeared during assignment cleanup", firewall.UUID)
			}
			if !nodeLoadBalancerFirewallOwnedByService(*current, c.provider.config.ClusterID, string(service.UID), c.provider.config.BillingAccountID) {
				return fmt.Errorf("node load balancer: Service firewall %s lost deterministic ownership during assignment cleanup", firewall.UUID)
			}
			remaining, assignmentErr := staleNodeLoadBalancerFirewallAssignments(*current, desiredVMs)
			if assignmentErr != nil {
				return assignmentErr
			}
			if len(remaining) == 0 {
				return nil
			}
			lastObservation = fmt.Errorf("firewall %s remains assigned to stale VMs %v", firewall.UUID, remaining)
		} else {
			lastObservation = fmt.Errorf("list firewalls for stale assignment readback: %w", listErr)
		}
		timer := time.NewTimer(nodeLoadBalancerAssignmentReadbackDelay)
		select {
		case <-readbackCtx.Done():
			timer.Stop()
			return fmt.Errorf("node load balancer: stale firewall assignment cleanup did not converge: %w", errors.Join(mutationErr, lastObservation, readbackCtx.Err()))
		case <-timer.C:
		}
	}
}

func staleNodeLoadBalancerFirewallAssignments(firewall inspace.Firewall, desiredVMs map[string]struct{}) ([]string, error) {
	stale := make([]string, 0)
	seen := make(map[string]struct{}, len(firewall.ResourcesAssigned))
	for _, resource := range firewall.ResourcesAssigned {
		if !strings.EqualFold(resource.ResourceType, "vm") || resource.ResourceUUID == "" {
			return nil, fmt.Errorf("node load balancer: firewall %s has unexpected assigned resource %#v", firewall.UUID, resource)
		}
		if _, duplicate := seen[resource.ResourceUUID]; duplicate {
			return nil, fmt.Errorf("node load balancer: firewall %s has duplicate VM assignment %s", firewall.UUID, resource.ResourceUUID)
		}
		seen[resource.ResourceUUID] = struct{}{}
		if _, desired := desiredVMs[resource.ResourceUUID]; !desired {
			stale = append(stale, resource.ResourceUUID)
		}
	}
	sort.Strings(stale)
	return stale, nil
}

func (c *nodeLoadBalancerController) reconcileShardNodeEligibility(ctx context.Context, shard string) error {
	rawNodes, err := c.rawNodesForShard(shard)
	if err != nil {
		return err
	}
	nodes, err := c.authorizedNodeLoadBalancerNodes(ctx, rawNodes, shard)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	services, err := c.services.List(labels.Everything())
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	type serviceFirewallCandidate struct {
		service *corev1.Service
		uuid    string
		hash    string
		active  bool
	}
	candidates := make([]serviceFirewallCandidate, 0)
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	for _, service := range services {
		if !isNodeLoadBalancerService(service) || service.DeletionTimestamp != nil {
			continue
		}
		current := service.Annotations[annotationNodeLoadBalancerShard] == shard
		previous := service.Annotations[annotationNodeLoadBalancerPreviousShard] == shard
		if !current && !previous {
			continue
		}
		if _, parseErr := parseNodeLoadBalancerService(service, defaults); parseErr != nil {
			continue
		}
		active, activeErr := c.shadowServiceUsesShard(ctx, service, shard)
		if activeErr != nil {
			return errors.Join(activeErr, c.setShardNodesReady(ctx, rawNodes, nil))
		}
		if previous && !current && !active {
			continue
		}
		uuid := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
		hash := service.Annotations[annotationNodeLoadBalancerFirewallHash]
		if previous && !current && active {
			if previousUUID := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]; previousUUID != "" {
				uuid = previousUUID
				// The deterministic firewall name binds the old policy hash to
				// authoritative readback. The Service stores only the new current
				// hash during a policy migration.
				hash = ""
			}
		}
		candidates = append(candidates, serviceFirewallCandidate{
			service: service,
			uuid:    uuid,
			hash:    hash,
			active:  active,
		})
	}
	if len(candidates) == 0 {
		return c.setShardNodesReady(ctx, rawNodes, nil)
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	byUUID := make(map[string]inspace.Firewall, len(firewalls))
	for _, firewall := range firewalls {
		byUUID[firewall.UUID] = firewall
	}
	icmpFirewall, err := c.currentClusterICMPFirewall(ctx, firewalls)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	if icmpFirewall == nil {
		return c.setShardNodesReady(ctx, rawNodes, nil)
	}
	serviceFirewalls := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.uuid == "" {
			if candidate.active {
				return c.setShardNodesReady(ctx, rawNodes, nil)
			}
			// A newly planned or migrating Service is not advertised by this
			// shard yet. Do not interrupt established shared Services while its
			// firewall is still being created and assigned.
			continue
		}
		firewall, exists := byUUID[candidate.uuid]
		valid := exists && nodeLoadBalancerFirewallOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			string(candidate.service.UID),
			c.provider.config.BillingAccountID,
		)
		if valid && candidate.hash != "" {
			hash, hashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
			valid = hashErr == nil && hash == candidate.hash
		}
		if candidate.active {
			if !valid {
				err := fmt.Errorf("node load balancer: active Service %s/%s has no exact current firewall", candidate.service.Namespace, candidate.service.Name)
				return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
			}
			serviceFirewalls = append(serviceFirewalls, candidate.uuid)
			continue
		}
		if valid && nodeLoadBalancerFirewallAssignedToAllHealthyNodes(firewall, nodes) {
			serviceFirewalls = append(serviceFirewalls, candidate.uuid)
		}
	}
	if len(serviceFirewalls) == 0 {
		return c.setShardNodesReady(ctx, rawNodes, nil)
	}
	ready := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		eligible := ok && nodeLoadBalancerNodeHealthy(node) && firewallAssignedToVM(*icmpFirewall, vmUUID)
		if eligible {
			for _, uuid := range serviceFirewalls {
				firewall, exists := byUUID[uuid]
				if !exists || !firewallAssignedToVM(firewall, vmUUID) {
					eligible = false
					break
				}
			}
		}
		ready[node.Name] = eligible
	}
	return c.setShardNodesReady(ctx, rawNodes, ready)
}

func nodeLoadBalancerFirewallAssignedToAllHealthyNodes(firewall inspace.Firewall, nodes []*corev1.Node) bool {
	for _, node := range nodes {
		if !nodeLoadBalancerNodeHealthy(node) {
			continue
		}
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok || !firewallAssignedToVM(firewall, vmUUID) {
			return false
		}
	}
	return true
}

func nodeLoadBalancerNodeHealthy(node *corev1.Node) bool {
	if node == nil || node.DeletionTimestamp != nil || node.Labels[nodeLoadBalancerNodeLabel] != "true" {
		return false
	}
	if _, excluded := node.Labels[corev1.LabelNodeExcludeBalancers]; excluded {
		return false
	}
	for _, taint := range node.Spec.Taints {
		if taint.Key == karpenterDisruptionTaint || taint.Key == clusterAutoscalerDeletionTaint {
			return false
		}
	}
	ready := false
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			ready = condition.Status == corev1.ConditionTrue
			break
		}
	}
	if !ready {
		return false
	}
	_, ok := nodeLoadBalancerNodeExternalIPv4(node)
	return ok
}

func nodeLoadBalancerNodeExternalIPv4(node *corev1.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	result := ""
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeExternalIP {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.String() != address.Address {
			continue
		}
		canonical := parsed.String()
		if result != "" && result != canonical {
			return "", false
		}
		result = canonical
	}
	return result, result != ""
}

func (c *nodeLoadBalancerController) setShardNodesReady(ctx context.Context, nodes []*corev1.Node, ready map[string]bool) error {
	for _, node := range nodes {
		current, err := c.provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("node load balancer: read back Node %s before readiness patch: %w", node.Name, err)
		}
		if current.Labels[nodeLoadBalancerNodeLabel] != "true" ||
			current.Labels[nodeLoadBalancerNodeClusterLabel] != c.provider.config.ClusterID ||
			current.Labels[nodeLoadBalancerNodeShardLabel] != node.Labels[nodeLoadBalancerNodeShardLabel] {
			continue
		}
		want := ready != nil && ready[node.Name] && nodeLoadBalancerNodeHealthy(current)
		if want {
			expectedVM, expectedOK := nodeLoadBalancerVMUUID(node)
			currentVM, currentOK := nodeLoadBalancerVMUUID(current)
			want = expectedOK && currentOK && expectedVM == currentVM
		}
		if want {
			fipAuthorized, _, fipErr := c.nodeLoadBalancerFloatingIPAuthoritative(ctx, current)
			if fipErr != nil {
				return fipErr
			}
			want = fipAuthorized
		}
		have := current.Labels[nodeLoadBalancerReadyLabel] == "true"
		if want == have {
			continue
		}
		value := any(nil)
		if want {
			value = "true"
		}
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{
			"resourceVersion": current.ResourceVersion,
			"labels":          map[string]any{nodeLoadBalancerReadyLabel: value},
		}})
		if _, err := c.provider.kubeClient.CoreV1().Nodes().Patch(ctx, current.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("node load balancer: patch readiness label on Node %s: %w", node.Name, err)
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) cleanupPreviousFirewall(ctx context.Context, service *corev1.Service) error {
	currentUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	for _, firewall := range owned {
		if firewall.UUID == currentUUID {
			continue
		}
		done, deleteErr := c.deleteOwnedServiceFirewall(ctx, service, firewall.UUID)
		if deleteErr != nil {
			return deleteErr
		}
		if !done {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
	}
	if service.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		return nil
	}
	copy := service.DeepCopy()
	delete(copy.Annotations, annotationNodeLoadBalancerPreviousFirewall)
	_, err = c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *nodeLoadBalancerController) cleanupPreviousShard(ctx context.Context, service *corev1.Service) error {
	previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]
	if previous == "" || previous == service.Annotations[annotationNodeLoadBalancerShard] {
		return nil
	}
	remaining, err := c.servicesForShard(ctx, service, previous)
	if err != nil {
		return err
	}
	if len(remaining) == 0 {
		nodes, err := c.rawNodesForShard(previous)
		if err != nil {
			return err
		}
		if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
			return err
		}
		if err := c.deleteManagedNodePool(ctx, previous); err != nil {
			return err
		}
		if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, previous, metav1.GetOptions{}); err == nil {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	copy := service.DeepCopy()
	delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
	_, err = c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *nodeLoadBalancerController) cleanupService(ctx context.Context, service *corev1.Service) error {
	if err := c.deleteOwnedShadowService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedShadowServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	ownedFirewalls, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	if changed, err := c.preparePendingFirewallTeardown(ctx, service, ownedFirewalls); err != nil || changed {
		if changed {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		}
		return err
	}
	if len(ownedFirewalls) != 0 {
		if changed, err := c.clearFirewallAbsenceEvidence(
			ctx,
			service,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
		); err != nil || changed {
			return err
		}
	}
	for _, firewall := range ownedFirewalls {
		done, deleteErr := c.deleteOwnedServiceFirewall(ctx, service, firewall.UUID)
		if deleteErr != nil {
			return deleteErr
		}
		if !done {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		if _, err := c.confirmPendingFirewallAbsent(ctx, service, time.Now().UTC()); err != nil {
			return err
		}
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	confirmedAbsent, changed, err := c.recordFirewallAbsence(
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
	if changed || !confirmedAbsent {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerAbsenceConfirmationDelay)
		return nil
	}
	if err := c.clearServiceLoadBalancerStatus(ctx, service); err != nil {
		return err
	}
	service, err = c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: refresh Service before finalization: %w", err)
	}

	seenShards := map[string]struct{}{}
	for _, shard := range []string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
	} {
		if shard == "" {
			continue
		}
		if _, duplicate := seenShards[shard]; duplicate {
			continue
		}
		seenShards[shard] = struct{}{}
		remaining, err := c.servicesForShard(ctx, service, shard)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			nodes, err := c.rawNodesForShard(shard)
			if err != nil {
				return err
			}
			if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
				return err
			}
			if err := c.deleteManagedNodePool(ctx, shard); err != nil {
				return err
			}
			if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); err == nil {
				c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
				return nil
			} else if !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	otherOwners, err := c.otherNodeLoadBalancerServices(ctx, service)
	if err != nil {
		return err
	}
	if !otherOwners {
		waiting, err := c.cleanupRemainingClusterNodeLoadBalancerCapacity(ctx)
		if err != nil {
			return err
		}
		if waiting {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
		nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
		done, err := c.cleanupClusterICMPFirewall(ctx, nodeClassName)
		if err != nil {
			return err
		}
		if !done {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
	}

	copy := service.DeepCopy()
	copy.Finalizers = removeString(copy.Finalizers, nodeLoadBalancerFinalizer)
	for _, key := range []string{
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
		annotationNodeLoadBalancerShard,
		annotationNodeLoadBalancerPreviousShard,
		annotationNodeLoadBalancerCleanupFWAbsent,
		annotationNodeLoadBalancerCleanupFWChecked,
	} {
		delete(copy.Annotations, key)
	}
	_, err = c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *nodeLoadBalancerController) otherNodeLoadBalancerServices(ctx context.Context, exclude *corev1.Service) (bool, error) {
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("node load balancer: list Services before cluster ICMP cleanup: %w", err)
	}
	for i := range list.Items {
		service := &list.Items[i]
		if exclude != nil && service.Namespace == exclude.Namespace && service.Name == exclude.Name {
			continue
		}
		// Only a persisted provider finalizer proves that this Service ever
		// acquired shared cloud state. An invalid or never-reconciled class-only
		// Service must not strand the last real owner's cluster ICMP firewall.
		if containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			return true, nil
		}
	}
	return false, nil
}

// cleanupRemainingClusterNodeLoadBalancerCapacity is the final shared-resource
// guard. The cluster ICMP firewall cannot disappear while any controller-owned
// NodePool, NodeClaim, or Node still exists, including capacity stranded by an
// interrupted Service migration.
func (c *nodeLoadBalancerController) cleanupRemainingClusterNodeLoadBalancerCapacity(ctx context.Context) (bool, error) {
	selector := labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerManagedLabel: "true",
		nodeLoadBalancerClusterLabel: c.provider.config.ClusterID,
	}).String()
	pools, err := c.provider.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, fmt.Errorf("node load balancer: list managed NodePools before cluster ICMP cleanup: %w", err)
	}
	if len(pools.Items) != 0 {
		for i := range pools.Items {
			name := pools.Items[i].GetName()
			if !isManagedNodeLoadBalancerShardName(name) || pools.Items[i].GetLabels()[nodeLoadBalancerShardLabel] != name {
				return false, fmt.Errorf("node load balancer: refusing cluster cleanup for malformed managed NodePool %q", name)
			}
			nodes, listErr := c.rawNodesForShard(name)
			if listErr != nil {
				return false, listErr
			}
			if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
				return false, err
			}
			if err := c.deleteManagedNodePool(ctx, name); err != nil {
				return false, err
			}
		}
		return true, nil
	}

	claims, err := c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("node load balancer: list NodeClaims before cluster ICMP cleanup: %w", err)
	}
	for i := range claims.Items {
		claimLabels := claims.Items[i].GetLabels()
		if claimLabels[nodeLoadBalancerNodeLabel] == "true" &&
			claimLabels[nodeLoadBalancerNodeClusterLabel] == c.provider.config.ClusterID {
			return true, nil
		}
	}

	nodeSelector := labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
	}).String()
	nodes, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: nodeSelector})
	if err != nil {
		return false, fmt.Errorf("node load balancer: list Nodes before cluster ICMP cleanup: %w", err)
	}
	return len(nodes.Items) != 0, nil
}

func (c *nodeLoadBalancerController) deleteManagedNodePool(ctx context.Context, name string) error {
	if !isManagedNodeLoadBalancerShardName(name) {
		return fmt.Errorf("node load balancer: refusing to delete invalid managed NodePool name %q", name)
	}
	resource := c.provider.dynamicClient.Resource(nodePoolGVR)
	nodePool, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get NodePool %s before delete: %w", name, err)
	}
	if nodePool.GetLabels()[nodeLoadBalancerManagedLabel] != "true" ||
		nodePool.GetLabels()[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		nodePool.GetLabels()[nodeLoadBalancerShardLabel] != name {
		return fmt.Errorf("node load balancer: refusing to delete NodePool %s without exact managed ownership labels", name)
	}
	if err := resource.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: delete NodePool %s: %w", name, err)
	}
	return nil
}

func (c *nodeLoadBalancerController) servicesForShard(ctx context.Context, exclude *corev1.Service, shard string) ([]*corev1.Service, error) {
	snapshot, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list live Services before shard cleanup: %w", err)
	}
	services := make([]*corev1.Service, 0, len(snapshot.Items))
	byKey := make(map[string]*corev1.Service, len(snapshot.Items))
	for index := range snapshot.Items {
		service := &snapshot.Items[index]
		services = append(services, service)
		byKey[service.Namespace+"/"+service.Name] = service
	}
	result := make([]*corev1.Service, 0)
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	for _, service := range services {
		if service.Namespace == exclude.Namespace && service.Name == exclude.Name {
			continue
		}
		if !isNodeLoadBalancerService(service) && !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		shadow := byKey[service.Namespace+"/"+nodeLoadBalancerShadowName(service)]
		if shadow != nil {
			if !nodeLoadBalancerShadowOwnedByService(shadow, service) {
				return nil, fmt.Errorf("node load balancer: shard shadow for %s/%s lacks exact owner identity", service.Namespace, service.Name)
			}
			activeShard, valid := nodeLoadBalancerCiliumSelectorShard(
				shadow.Annotations[annotationCiliumNodeIPAMMatchLabels],
				c.provider.config.ClusterID,
			)
			if !valid {
				return nil, fmt.Errorf("node load balancer: shard shadow for %s/%s has a foreign node selector", service.Namespace, service.Name)
			}
			if activeShard == shard {
				result = append(result, service)
				continue
			}
		}
		if service.DeletionTimestamp != nil || !isNodeLoadBalancerService(service) ||
			service.Annotations[annotationNodeLoadBalancerShard] != shard {
			continue
		}
		if _, err := parseNodeLoadBalancerService(service, defaults); err == nil {
			result = append(result, service)
		}
	}
	return result, nil
}

func (c *nodeLoadBalancerController) deleteOwnedServiceFirewall(ctx context.Context, service *corev1.Service, uuid string) (bool, error) {
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var firewall *inspace.Firewall
	for i := range firewalls {
		if firewalls[i].UUID == uuid {
			copy := firewalls[i]
			firewall = &copy
			break
		}
	}
	if firewall == nil {
		return true, nil
	}
	if !nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, string(service.UID), c.provider.config.BillingAccountID) {
		return false, fmt.Errorf("node load balancer: refusing to delete firewall %s without exact Service ownership", uuid)
	}
	if len(firewall.ResourcesAssigned) != 0 {
		for _, resource := range firewall.ResourcesAssigned {
			if !strings.EqualFold(resource.ResourceType, "vm") || resource.ResourceUUID == "" {
				return false, fmt.Errorf("node load balancer: firewall %s has unexpected assigned resource %#v", uuid, resource)
			}
			if err := c.provider.api.UnassignFirewallFromVM(ctx, c.provider.config.Location, uuid, resource.ResourceUUID); err != nil && !inspace.IsNotFound(err) {
				return false, fmt.Errorf("node load balancer: unassign firewall %s from VM %s: %w", uuid, resource.ResourceUUID, err)
			}
		}
		return false, nil
	}
	if err := c.provider.api.DeleteFirewall(ctx, c.provider.config.Location, uuid); err != nil && !inspace.IsNotFound(err) {
		return false, fmt.Errorf("node load balancer: delete firewall %s: %w", uuid, err)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) ownedServiceFirewalls(ctx context.Context, service *corev1.Service) ([]inspace.Firewall, error) {
	serviceUID := string(service.UID)
	if serviceUID == "" {
		return nil, errors.New("node load balancer: Service UID is required to discover owned firewalls")
	}
	if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
		return nil, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, err
	}
	prefix := nodeLoadBalancerFirewallServicePrefix(c.provider.config.ClusterID, serviceUID)
	result := make([]inspace.Firewall, 0)
	pendingUUID := service.Annotations[annotationNodeLoadBalancerPendingFirewall]
	pendingName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	pendingUUIDMatches := 0
	currentUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	currentHash := service.Annotations[annotationNodeLoadBalancerFirewallHash]
	previousUUID := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	identityMatches := map[string]int{}
	for _, firewall := range items {
		if pendingUUID != "" && firewall.UUID == pendingUUID {
			pendingUUIDMatches++
			if firewall.EffectiveName() != pendingName {
				return nil, fmt.Errorf("node load balancer: pending firewall %s does not use deterministic name %q", pendingUUID, pendingName)
			}
		}
		for role, uuid := range map[string]string{"current": currentUUID, "previous": previousUUID} {
			if uuid == "" || firewall.UUID != uuid {
				continue
			}
			identityMatches[role]++
			if !nodeLoadBalancerFirewallOwnedByService(firewall, c.provider.config.ClusterID, serviceUID, c.provider.config.BillingAccountID) {
				return nil, fmt.Errorf("node load balancer: %s firewall %s lost deterministic Service ownership", role, uuid)
			}
			if role == "current" {
				hash, hashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
				if hashErr != nil || hash != currentHash {
					return nil, fmt.Errorf("node load balancer: current firewall %s no longer matches persisted policy hash", uuid)
				}
			}
		}
		if !strings.HasPrefix(firewall.EffectiveName(), prefix) {
			continue
		}
		if !nodeLoadBalancerFirewallOwnedByService(firewall, c.provider.config.ClusterID, serviceUID, c.provider.config.BillingAccountID) {
			return nil, fmt.Errorf("node load balancer: ownership-shaped firewall %q has invalid billing or policy identity", firewall.EffectiveName())
		}
		result = append(result, firewall)
	}
	if pendingUUIDMatches > 1 {
		return nil, fmt.Errorf("node load balancer: pending firewall UUID %s appears multiple times", pendingUUID)
	}
	for role, count := range identityMatches {
		if count > 1 {
			return nil, fmt.Errorf("node load balancer: %s firewall UUID appears multiple times", role)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	return result, nil
}

func nodeLoadBalancerFirewallOwnedByService(firewall inspace.Firewall, cluster, serviceUID string, billingAccountID int64) bool {
	if cluster == "" || validateNodeLoadBalancerServiceUID(serviceUID) != nil || firewall.BillingAccountID != billingAccountID {
		return false
	}
	prefix := nodeLoadBalancerFirewallServicePrefix(cluster, serviceUID)
	name := firewall.EffectiveName()
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != 8 || !isLowerHex(suffix) {
		return false
	}
	hash, err := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
	return err == nil && hash == suffix
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func removeString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
