package cloudprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/informers"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	nodeLoadBalancerFinalizer                    = "service.inspace.cloud/node-lb"
	nodeLoadBalancerNodePoolFinalizer            = "inspace.cloud/node-lb-state"
	nodeLoadBalancerNodeClassFinalizer           = "inspace.cloud/node-lb-cluster-state"
	annotationNodeLoadBalancerFirewallUUID       = "service.inspace.cloud/node-lb-firewall-uuid"
	annotationNodeLoadBalancerFirewallHash       = "service.inspace.cloud/node-lb-firewall-hash"
	annotationNodeLoadBalancerFirewallAbsent     = "service.inspace.cloud/node-lb-firewall-absence-count"
	annotationNodeLoadBalancerFirewallChecked    = "service.inspace.cloud/node-lb-firewall-absence-checked-at"
	annotationNodeLoadBalancerPendingFirewall    = "service.inspace.cloud/node-lb-pending-firewall-uuid"
	annotationNodeLoadBalancerPendingFWName      = "service.inspace.cloud/node-lb-pending-firewall-name"
	annotationNodeLoadBalancerPendingFWStarted   = "service.inspace.cloud/node-lb-pending-firewall-started-at"
	annotationNodeLoadBalancerPendingFWIssued    = "service.inspace.cloud/node-lb-pending-firewall-issued-token"
	annotationNodeLoadBalancerPendingFWIssuedAt  = "service.inspace.cloud/node-lb-pending-firewall-issued-at"
	annotationNodeLoadBalancerPendingFWDelete    = "service.inspace.cloud/node-lb-pending-firewall-deleting"
	annotationNodeLoadBalancerPendingFWAbsent    = "service.inspace.cloud/node-lb-pending-firewall-absence-count"
	annotationNodeLoadBalancerPendingFWChecked   = "service.inspace.cloud/node-lb-pending-firewall-absence-checked-at"
	annotationNodeLoadBalancerCleanupFWAbsent    = "service.inspace.cloud/node-lb-cleanup-firewall-absence-count"
	annotationNodeLoadBalancerCleanupFWChecked   = "service.inspace.cloud/node-lb-cleanup-firewall-absence-checked-at"
	annotationNodeLoadBalancerWithdrawFWAbsent   = "service.inspace.cloud/node-lb-withdraw-firewall-absence-count"
	annotationNodeLoadBalancerWithdrawFWChecked  = "service.inspace.cloud/node-lb-withdraw-firewall-absence-checked-at"
	annotationNodeLoadBalancerWithdrawFWMissing  = "service.inspace.cloud/node-lb-withdraw-firewall-missing-set"
	annotationNodeLoadBalancerWithdrawFWDetach   = "service.inspace.cloud/node-lb-withdraw-firewall-detach-set"
	annotationNodeLoadBalancerWithdrawFWDetachAt = "service.inspace.cloud/node-lb-withdraw-firewall-detach-at"
	annotationNodeLoadBalancerFirewallAssigning  = "service.inspace.cloud/node-lb-firewall-assigning-uuid"
	annotationNodeLoadBalancerFirewallAssignAt   = "service.inspace.cloud/node-lb-firewall-assigning-started-at"
	annotationNodeLoadBalancerFWDeleteTarget     = "service.inspace.cloud/node-lb-firewall-delete-target-uuid"
	annotationNodeLoadBalancerFWDeleteIssued     = "service.inspace.cloud/node-lb-firewall-delete-issued-at"
	annotationNodeLoadBalancerPreviousFirewall   = "service.inspace.cloud/node-lb-previous-firewall-uuid"
	annotationNodeLoadBalancerPreviousShard      = "service.inspace.cloud/node-lb-previous-shard"
	annotationNodeLoadBalancerDatapathShard      = "service.inspace.cloud/node-lb-datapath-shard"
	annotationNodeLoadBalancerDatapathActive     = "service.inspace.cloud/node-lb-datapath-active-shard"
	// The ready label is the API-owned eligibility gate used to derive private
	// and public status pairs. Keep it protected so a kubelet cannot
	// self-advertise.
	nodeLoadBalancerReadyLabel               = "inspace.cloud.node-restriction.kubernetes.io/ready"
	nodeLoadBalancerManagedLabel             = "inspace.cloud/node-lb-managed"
	nodeLoadBalancerClusterLabel             = "inspace.cloud/node-lb-cluster"
	nodeLoadBalancerProfileLabel             = "inspace.cloud/node-lb-profile"
	nodeLoadBalancerDatapathLabel            = "inspace.cloud/node-lb-datapath"
	nodeLoadBalancerServiceIdentityLabel     = "inspace.cloud/node-lb-service-id"
	nodeLoadBalancerDatapathClass            = "inspace.cloud/node-datapath"
	karpenterNodePoolLabel                   = "karpenter.sh/nodepool"
	karpenterPublicIPv4Annotation            = "karpenter.inspace.cloud/public-ipv4"
	karpenterFloatingIPNameAnnotation        = "karpenter.inspace.cloud/floating-ip-name"
	karpenterBillingAccountAnnotation        = "karpenter.inspace.cloud/billing-account-id"
	karpenterNodeNameAnnotation              = "karpenter.inspace.cloud/node-name"
	nodeLoadBalancerResync                   = 30 * time.Second
	nodeLoadBalancerRetry                    = 10 * time.Second
	nodeLoadBalancerPendingCreateTimeout     = 5 * time.Minute
	nodeLoadBalancerAbsenceConfirmationDelay = 30 * time.Second
	nodeLoadBalancerAbsenceConfirmations     = 3
)

type nodeLoadBalancerAddress struct {
	Node        *corev1.Node
	PrivateIPv4 string
	PublicIPv4  string
}

type managedNodeLoadBalancerVMIdentity struct {
	VMUUID         string
	FloatingIPName string
	PublicIPv4     string
}

var (
	nodePoolGVR  = schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodepools"}
	nodeClaimGVR = schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodeclaims"}
	nodeClassGVR = schema.GroupVersionResource{Group: "karpenter.inspace.cloud", Version: "v1alpha1", Resource: "inspacenodeclasses"}
)

type nodeLoadBalancerController struct {
	provider       *Provider
	nodes          corelisters.NodeLister
	services       corelisters.ServiceLister
	endpointSlices discoverylisters.EndpointSliceLister
	// These two fields permit deterministic relationship-removal tests. The
	// production constructor always installs the real clock and convergence delay.
	firewallRelationNow         func() time.Time
	firewallRelationAbsentDelay time.Duration

	nodesSynced          cache.InformerSynced
	servicesSynced       cache.InformerSynced
	endpointSlicesSynced cache.InformerSynced
	queue                workqueue.TypedRateLimitingInterface[string]
}

// nodeLoadBalancerPlanningServiceError proves that a planning failure belongs
// to one exact parent Service. Aggregate reconciliation may quarantine that
// Service without withdrawing healthy siblings.
type nodeLoadBalancerPlanningServiceError struct {
	Service *corev1.Service
	Cause   error
}

func (err *nodeLoadBalancerPlanningServiceError) Error() string {
	if err == nil || err.Cause == nil {
		return "node load balancer: Service planning fault"
	}
	return err.Cause.Error()
}

func (err *nodeLoadBalancerPlanningServiceError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// nodeLoadBalancerPlanningShardError identifies a fault that cannot safely be
// assigned to one Service, such as two active children claiming one public
// port. The whole shard must close until the conflict is repaired.
type nodeLoadBalancerPlanningShardError struct {
	Shard string
	Cause error
}

func (err *nodeLoadBalancerPlanningShardError) Error() string {
	if err == nil || err.Cause == nil {
		return "node load balancer: shard planning fault"
	}
	return err.Cause.Error()
}

func (err *nodeLoadBalancerPlanningShardError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func planningServiceFault(service *corev1.Service, cause error) error {
	if service == nil {
		return cause
	}
	return &nodeLoadBalancerPlanningServiceError{Service: service.DeepCopy(), Cause: cause}
}

func planningShardFault(shard string, cause error) error {
	return &nodeLoadBalancerPlanningShardError{Shard: shard, Cause: cause}
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
	endpointSlices := factory.Discovery().V1().EndpointSlices()
	controller := &nodeLoadBalancerController{
		provider: provider, nodes: nodes.Lister(), services: services.Lister(), endpointSlices: endpointSlices.Lister(),
		firewallRelationNow: time.Now, firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
		nodesSynced: nodes.Informer().HasSynced, servicesSynced: services.Informer().HasSynced,
		endpointSlicesSynced: endpointSlices.Informer().HasSynced,
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
	if _, err := endpointSlices.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(object any) { controller.enqueueNodeLoadBalancerEndpointSlice(object) },
		UpdateFunc: func(oldObject, newObject any) {
			oldSlice, oldOK := oldObject.(*discoveryv1.EndpointSlice)
			newSlice, newOK := newObject.(*discoveryv1.EndpointSlice)
			if !oldOK || !newOK || reflect.DeepEqual(oldSlice, newSlice) {
				return
			}
			controller.enqueueNodeLoadBalancerEndpointSlice(oldSlice)
			controller.enqueueNodeLoadBalancerEndpointSlice(newSlice)
		},
		DeleteFunc: func(object any) { controller.enqueueNodeLoadBalancerEndpointSlice(object) },
	}); err != nil {
		return nil, fmt.Errorf("node load balancer: register EndpointSlice handler: %w", err)
	}
	return controller, nil
}

func (c *nodeLoadBalancerController) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()
	if stopCh == nil {
		panic("node load balancer: stop channel is required")
	}
	if !cache.WaitForCacheSync(stopCh, c.nodesSynced, c.servicesSynced, c.endpointSlicesSynced) {
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

func (c *nodeLoadBalancerController) enqueueNodeLoadBalancerEndpointSlice(object any) {
	endpointSlice, ok := object.(*discoveryv1.EndpointSlice)
	if !ok {
		if tombstone, tombstoneOK := object.(cache.DeletedFinalStateUnknown); tombstoneOK {
			endpointSlice, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		}
	}
	if !ok {
		return
	}
	if key := endpointSliceServiceKey(endpointSlice); key != "" {
		c.queue.Add(key)
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
		if isNodeLoadBalancerService(service) ||
			containsString(service.Finalizers, nodeLoadBalancerFinalizer) ||
			containsString(service.Finalizers, publicNodeLocalFinalizer) {
			c.queue.Add(service.Namespace + "/" + service.Name)
		}
	}
}

func isNodeLoadBalancerService(service *corev1.Service) bool {
	return service != nil && service.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		service.Spec.LoadBalancerClass != nil && *service.Spec.LoadBalancerClass == nodeLoadBalancerClass
}

// syncLegacyServiceFirewall is retained temporarily for focused compatibility
// tests while the stable controller uses the aggregate shard-firewall path.
// Per-Service firewalls existed only in pre-stable release candidates.
func (c *nodeLoadBalancerController) syncLegacyServiceFirewall(ctx context.Context, key string) error {
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
	if waiting, err := c.auditAdvertisedServiceShard(ctx, service); err != nil || waiting {
		// Repair starts on the next reconciliation. Continuing with the stale
		// object from before withdrawal could republish in the same pass.
		if waiting {
			c.queue.AddAfter(key, nodeLoadBalancerRetry)
		}
		return err
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return fmt.Errorf("node load balancer: refresh parent after advertised datapath audit: %w", err)
	}
	if handled, err := c.cleanupCompletedPreviousMigration(ctx, service); err != nil || handled {
		return err
	}

	intent, plan, shard, err := c.planForService(ctx, service)
	if err != nil {
		return err
	}
	if err := c.validateDatapathServiceName(ctx, service); err != nil {
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
	if service.Annotations[annotationNodeLoadBalancerDatapathActive] == "" {
		// A Service-specific firewall is the public activation gate. Keep a newly
		// staged firewall detached until the durable activation marker and the
		// generated Cilium Service's private VIP have both read back exactly.
		if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, nil); err != nil {
			return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
		}
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
	if icmpFirewall == nil || !icmpAssignmentsReady {
		if eligibilityErr := c.reconcileShardNodeEligibility(ctx, shard.Name); eligibilityErr != nil {
			return eligibilityErr
		}
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if err := c.reconcileShardNodeEligibility(ctx, shard.Name); err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	readyAddresses, err := c.readyShardAddresses(ctx, shard.Name)
	if err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	activeShard := service.Annotations[annotationNodeLoadBalancerDatapathActive]
	if activeShard != "" && activeShard != shard.Name {
		cause := fmt.Errorf("node load balancer: withdraw active shard %s before staging replacement %s", activeShard, shard.Name)
		return errors.Join(cause, c.withdrawServiceDatapath(ctx, service))
	}
	if activeShard != shard.Name && len(readyAddresses) < int(shard.NodesPerShard) {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
		return nil
	}
	if activeShard == shard.Name {
		// The advertised path was already audited above, including exact firewall
		// assignment readback. Continue only with non-datapath cleanup and capacity
		// repair; never tear down and restage an established activation gate here.
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
	if _, err := c.ensureDatapathService(ctx, service, shard.Name); err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	service, err = c.authorizeDatapath(ctx, service, shard.Name, intent)
	if err != nil {
		return c.failNodeLoadBalancerShardsClosed(ctx, service, shard.Name, err)
	}
	// Stop after storing the durable authorization. The next reconciliation's
	// advertised-path audit performs the remaining ordered transition:
	// private VIP -> exact firewall assignment -> public Proxy status.
	c.queue.AddAfter(key, nodeLoadBalancerRetry)
	return nil
}

func (c *nodeLoadBalancerController) cleanupCompletedPreviousMigration(
	ctx context.Context,
	service *corev1.Service,
) (bool, error) {
	previousShard := service.Annotations[annotationNodeLoadBalancerPreviousShard]
	previousFirewall := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	if previousShard == "" && previousFirewall == "" {
		return false, nil
	}
	activeShard := service.Annotations[annotationNodeLoadBalancerDatapathActive]
	currentShard := service.Annotations[annotationNodeLoadBalancerShard]
	if activeShard != "" && activeShard != currentShard {
		// The previous shard is still the established datapath while replacement
		// capacity is prepared. cleanupAbandonedReplacementShard serializes any
		// further edit without deleting that active identity.
		return false, nil
	}
	if previousFirewall != "" {
		if err := c.cleanupPreviousFirewall(ctx, service); err != nil {
			return true, err
		}
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return true, err
	}
	if current.Annotations[annotationNodeLoadBalancerPreviousShard] != "" {
		if err := c.cleanupPreviousShard(ctx, current); err != nil {
			return true, err
		}
	}
	c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
	return true, nil
}

func (c *nodeLoadBalancerController) auditAdvertisedServiceShard(ctx context.Context, service *corev1.Service) (bool, error) {
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	expected, err := parseNodeLoadBalancerService(service, defaults)
	if err != nil {
		return false, errors.Join(err, c.withdrawServiceDatapath(ctx, service))
	}
	datapath, shard, active, err := c.activeDatapathService(ctx, service)
	if err != nil {
		return false, c.failNodeLoadBalancerShardsClosed(ctx, service, "", err)
	}
	if !active {
		return false, c.auditUncommittedDatapath(ctx, service)
	}
	failClosed := func(cause error) (bool, error) {
		return false, c.failNodeLoadBalancerShardsClosed(ctx, service, shard, cause)
	}
	if err := c.reconcileShardNodeEligibility(ctx, shard); err != nil {
		return failClosed(err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return failClosed(errors.New("node load balancer: active generated Service lacks exact ownership"))
	}
	addresses, err := c.readyShardAddresses(ctx, shard)
	if err != nil {
		return failClosed(err)
	}
	readyNodes := make([]*corev1.Node, 0, len(addresses))
	for _, address := range addresses {
		readyNodes = append(readyNodes, address.Node)
	}

	// Resolve and validate the exact firewall while it is still detached from
	// any stale Nodes. A private Cilium VIP must exist before a new public edge
	// assignment is permitted, while stale assignments are closed before the
	// private frontend is changed.
	firewall, previousUUID, _, err := c.ensureServiceFirewall(ctx, service, nil)
	if err != nil {
		return failClosed(err)
	}
	if firewall == nil {
		return failClosed(errors.New("node load balancer: active Service firewall is absent from authoritative readback"))
	}
	if patched, metadataErr := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); metadataErr != nil {
		return failClosed(metadataErr)
	} else if patched {
		return c.waitForServiceFirewallGate(ctx, service)
	}
	if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, readyNodes); err != nil {
		return failClosed(err)
	}
	service, err = c.publishDatapathStatus(ctx, service, shard, expected, addresses)
	if err != nil {
		return failClosed(err)
	}

	assignmentsMatch, err := c.serviceFirewallAssignmentsMatch(ctx, service, firewall.UUID, readyNodes)
	if err != nil {
		return failClosed(err)
	}
	if !assignmentsMatch {
		var prepared bool
		service, prepared, err = c.ensureServiceFirewallAssignmentIntent(ctx, service, firewall.UUID)
		if err != nil {
			return failClosed(err)
		}
		if prepared {
			return c.waitForServiceFirewallGate(ctx, service)
		}
		firewall, previousUUID, assignmentsReady, assignmentErr := c.ensureServiceFirewall(ctx, service, readyNodes)
		if assignmentErr != nil {
			return failClosed(assignmentErr)
		}
		if firewall == nil || !assignmentsReady {
			return c.waitForServiceFirewallGate(ctx, service)
		}
		if patched, metadataErr := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); metadataErr != nil {
			return failClosed(metadataErr)
		} else if patched {
			return c.waitForServiceFirewallGate(ctx, service)
		}
		assignmentsMatch, err = c.serviceFirewallAssignmentsMatch(ctx, service, firewall.UUID, readyNodes)
		if err != nil {
			return failClosed(err)
		}
		if !assignmentsMatch {
			return c.waitForServiceFirewallGate(ctx, service)
		}
	}
	if service.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" {
		var cleared bool
		service, cleared, err = c.clearServiceFirewallAssignmentIntent(ctx, service, firewall.UUID)
		if err != nil {
			return failClosed(err)
		}
		if cleared {
			// Publication waits for a separate reconciliation after the assignment
			// fence is durably cleared.
			return c.waitForServiceFirewallGate(ctx, service)
		}
	}
	assignmentsMatch, err = c.serviceFirewallAssignmentsMatch(ctx, service, firewall.UUID, readyNodes)
	if err != nil {
		return failClosed(err)
	}
	if !assignmentsMatch {
		return failClosed(errors.New("node load balancer: Service firewall assignment changed before public status publication"))
	}
	if len(readyNodes) > 0 {
		if cleared, clearErr := c.clearServiceFirewallWithdrawalEvidenceAfterAssignment(ctx, service, firewall.UUID, readyNodes); clearErr != nil {
			return failClosed(clearErr)
		} else if cleared {
			// Withdrawal absence evidence is deliberately retained after the activation
			// marker is cleared so deletion and quarantine can consume the same proof.
			// Persist its reset after a positive, non-empty assignment readback, then
			// stop: the next reconciliation must re-prove the assignment before public
			// status returns. An empty desired/actual set is not positive recovery proof.
			return c.waitForServiceFirewallGate(ctx, service)
		}
	}
	service, err = c.publishPublicProxyStatus(ctx, service, shard, expected, addresses)
	if err != nil {
		return failClosed(err)
	}
	converged, err := c.datapathStatusesMatch(ctx, service, shard, addresses)
	if err != nil || !converged {
		cause := fmt.Errorf("node load balancer: active private VIP/public Proxy pair failed exact audit readback")
		return failClosed(errors.Join(cause, err))
	}
	return false, nil
}

func (c *nodeLoadBalancerController) waitForServiceFirewallGate(
	ctx context.Context,
	service *corev1.Service,
) (bool, error) {
	// status.loadBalancer is informational rather than the packet filter, but it
	// must never claim a public path while the real firewall gate is incomplete.
	return true, c.clearServiceLoadBalancerStatus(ctx, service)
}

func (c *nodeLoadBalancerController) auditUncommittedDatapath(ctx context.Context, service *corev1.Service) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx,
		nodeLoadBalancerDatapathName(current),
		metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		if len(current.Status.LoadBalancer.Ingress) == 0 {
			return nil
		}
		cause := errors.New("node load balancer: parent publishes a public address without an active or staged datapath")
		return errors.Join(cause, c.withdrawServiceDatapath(ctx, current))
	}
	if err != nil {
		return fmt.Errorf("node load balancer: inspect staged datapath Service: %w", err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, current) {
		cause := fmt.Errorf("node load balancer: staged datapath Service %s/%s lacks exact ownership", datapath.Namespace, datapath.Name)
		return errors.Join(cause, c.withdrawServiceDatapath(ctx, current))
	}
	shard := datapath.Annotations[annotationNodeLoadBalancerDatapathShard]
	if !isManagedNodeLoadBalancerShardName(shard) || !nodeLoadBalancerDatapathMatchesDesired(datapath, current, shard) {
		if len(current.Status.LoadBalancer.Ingress) == 0 && len(datapath.Status.LoadBalancer.Ingress) == 0 {
			// A completely unadvertised exact-owned child can be repaired safely by
			// the normal desired-state path.
			return nil
		}
		cause := fmt.Errorf("node load balancer: uncommitted datapath Service %s/%s is terminating or drifted", datapath.Namespace, datapath.Name)
		return errors.Join(cause, c.withdrawServiceDatapath(ctx, current))
	}
	if len(current.Status.LoadBalancer.Ingress) == 0 && len(datapath.Status.LoadBalancer.Ingress) == 0 {
		return nil
	}
	// The activation marker is persisted before the controller publishes any
	// private VIP. Any status without that durable authorization is therefore an
	// unsafe or foreign exposure and must be withdrawn rather than adopted.
	cause := fmt.Errorf("node load balancer: unmarked datapath Service %s/%s publishes a private VIP or public Proxy status", datapath.Namespace, datapath.Name)
	return errors.Join(cause, c.withdrawServiceDatapath(ctx, current))
}

func (c *nodeLoadBalancerController) failNodeLoadBalancerShardClosed(ctx context.Context, shard string, cause error) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return cause
	}
	nodes, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return errors.Join(cause, err, c.withdrawShardDatapaths(ctx, shard))
	}
	return errors.Join(cause, c.setShardNodesReady(ctx, nodes, nil), c.withdrawShardDatapaths(ctx, shard))
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
			service.Annotations[annotationNodeLoadBalancerDatapathActive],
		} {
			if isManagedNodeLoadBalancerShardName(shard) {
				shards[shard] = struct{}{}
			}
		}
	}
	result := cause
	result = errors.Join(result, c.withdrawServiceDatapath(ctx, service))
	for shard := range shards {
		nodes, err := c.rawNodesForShard(ctx, shard)
		if err != nil {
			result = errors.Join(result, err)
		} else {
			result = errors.Join(result, c.setShardNodesReady(ctx, nodes, nil))
		}
		result = errors.Join(result, c.withdrawShardDatapaths(ctx, shard))
	}
	return result
}

func (c *nodeLoadBalancerController) failClusterNodeLoadBalancerClosed(ctx context.Context, cause error) error {
	nodes, err := c.rawNodesForCluster(ctx)
	result := cause
	if err != nil {
		result = errors.Join(result, err)
	} else {
		result = errors.Join(result, c.setShardNodesReady(ctx, nodes, nil))
	}
	services, listErr := c.servicesForFailureWithdrawal(ctx)
	result = errors.Join(result, listErr)
	for _, service := range services {
		if isNodeLoadBalancerService(service) || containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			result = errors.Join(result, c.withdrawServiceDatapath(ctx, service))
		}
	}
	return result
}

func (c *nodeLoadBalancerController) withdrawShardDatapaths(ctx context.Context, shard string) error {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return nil
	}
	services, listErr := c.servicesForFailureWithdrawal(ctx)
	var result error = listErr
	for _, service := range services {
		if !isNodeLoadBalancerService(service) && !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		usesShard, inspectErr := c.serviceUsesShardForFailureWithdrawal(ctx, service, shard)
		result = errors.Join(result, inspectErr)
		if !usesShard {
			continue
		}
		result = errors.Join(result, c.withdrawServiceDatapath(ctx, service))
	}
	return result
}

func (c *nodeLoadBalancerController) servicesForFailureWithdrawal(ctx context.Context) ([]*corev1.Service, error) {
	live, liveErr := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if liveErr == nil {
		services := make([]*corev1.Service, 0, len(live.Items))
		for index := range live.Items {
			services = append(services, &live.Items[index])
		}
		return services, nil
	}
	if c.services == nil {
		return nil, fmt.Errorf("node load balancer: live Service List failed and no informer fallback is available: %w", liveErr)
	}
	cached, cacheErr := c.services.List(labels.Everything())
	if cacheErr != nil {
		return nil, errors.Join(
			fmt.Errorf("node load balancer: live Service List for withdrawal: %w", liveErr),
			fmt.Errorf("node load balancer: cached Service List for withdrawal: %w", cacheErr),
		)
	}
	return cached, fmt.Errorf("node load balancer: live Service List for withdrawal: %w", liveErr)
}

func (c *nodeLoadBalancerController) serviceUsesShardForFailureWithdrawal(
	ctx context.Context,
	service *corev1.Service,
	shard string,
) (bool, error) {
	if service == nil {
		return false, nil
	}
	for _, annotated := range []string{
		service.Annotations[annotationNodeLoadBalancerShard],
		service.Annotations[annotationNodeLoadBalancerPreviousShard],
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
	} {
		if annotated == shard {
			return true, nil
		}
	}
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if err == nil && nodeLoadBalancerDatapathOwnedByService(datapath, service) &&
		datapath.Annotations[annotationNodeLoadBalancerDatapathShard] == shard {
		return true, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("node load balancer: inspect datapath shard during withdrawal: %w", err)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) withdrawServiceDatapath(ctx context.Context, service *corev1.Service) error {
	if service == nil {
		return nil
	}
	// The public firewall is the functional edge. Detach and read it back before
	// touching either status so a crash cannot leave a FIP reaching a host port
	// after Cilium has removed the matching private VIP frontend.
	if err := c.detachOwnedServiceFirewallsForFailure(ctx, service); err != nil {
		return err
	}
	detached, err := c.serviceFirewallsDetached(ctx, service)
	if err != nil {
		return err
	}
	if !detached {
		return errors.New("node load balancer: waiting for exact Service firewall detachment readback")
	}
	if err := c.clearServiceLoadBalancerStatus(ctx, service); err != nil {
		return err
	}
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	generated, err := client.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(generated, service) {
			return fmt.Errorf("node load balancer: refusing to withdraw foreign datapath Service %s/%s", service.Namespace, generated.Name)
		} else if len(generated.Status.LoadBalancer.Ingress) != 0 {
			copy := generated.DeepCopy()
			copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
			if _, updateErr := client.UpdateStatus(ctx, copy, metav1.UpdateOptions{}); updateErr != nil {
				return fmt.Errorf("node load balancer: withdraw generated Service %s/%s status: %w", service.Namespace, generated.Name, updateErr)
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: get generated Service %s/%s for withdrawal: %w", service.Namespace, nodeLoadBalancerDatapathName(service), err)
	}
	withdrawn, err := c.serviceExposureWithdrawn(ctx, service)
	if err != nil {
		return err
	}
	if !withdrawn {
		return errors.New("node load balancer: refusing to clear datapath activation before exact withdrawal readback")
	}
	return c.clearDatapathActivation(ctx, service)
}

func (c *nodeLoadBalancerController) detachOwnedServiceFirewallsForFailure(ctx context.Context, service *corev1.Service) error {
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owner := c.serviceFirewallRelationOwner(current)
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, nil)
	if err != nil {
		return fmt.Errorf("node load balancer: resolve Service firewall relation before emergency withdrawal: %w", err)
	}
	if !converged {
		// Clearing an exact prior assignment/removal receipt is its own durable
		// transition. A fresh pass must rediscover the Service-owned firewalls
		// before it may authorize a different relationship mutation.
		return errors.New("node load balancer: waiting for prior Service firewall relation readback before emergency withdrawal")
	}
	owned, discoveryErr := c.serviceFirewallsForEmergencyDetach(ctx, current)
	assignments, assignmentSet, err := nodeLoadBalancerFirewallDetachAssignments(owned)
	if err != nil {
		return errors.Join(discoveryErr, err)
	}
	if len(assignments) == 0 {
		// Retain an existing fence until an exact positive assignment readback
		// proves recovery. A transient empty ListFirewalls response must not arm
		// the same detach again when the stale assignment reappears.
		return discoveryErr
	}

	// Retain the legacy withdrawal ledger as read-only-compatible evidence for
	// upgrades and diagnostics. It no longer authorizes cloud mutations: the
	// canonical Service relation fence below is the sole authority.
	now := time.Now().UTC()
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		storedSet := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach]
		storedAt := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt]
		if (storedSet == "") != (storedAt == "") {
			return false, errors.New("node load balancer: incomplete firewall withdrawal detach fence")
		}
		detachedAt := map[string]string{}
		if storedSet != "" {
			if err := validateNodeLoadBalancerFirewallDetachSet(storedSet); err != nil {
				return false, err
			}
			var parseErr error
			detachedAt, parseErr = parseNodeLoadBalancerFirewallDetachTimes(storedAt)
			if parseErr != nil {
				return false, parseErr
			}
			for _, pair := range strings.Split(storedSet, ",") {
				if detachedAt[pair] == "" {
					return false, fmt.Errorf("node load balancer: firewall withdrawal detach set has no timestamp for %s", pair)
				}
			}
		}
		nextDetachedAt := make(map[string]string, len(assignments))
		for _, assignment := range assignments {
			pair := assignment.firewallUUID + "/" + assignment.vmUUID
			encodedTime := detachedAt[pair]
			if encodedTime == "" {
				encodedTime = now.Format(time.RFC3339Nano)
			}
			nextDetachedAt[pair] = encodedTime
		}
		encodedTimes, marshalErr := json.Marshal(nextDetachedAt)
		if marshalErr != nil {
			return false, fmt.Errorf("node load balancer: encode firewall withdrawal evidence timestamps: %w", marshalErr)
		}
		changed := storedSet != assignmentSet || storedAt != string(encodedTimes)
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
		if !changed {
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = assignmentSet
		copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(encodedTimes)
		return true, nil
	})
	if err != nil {
		return errors.Join(discoveryErr, fmt.Errorf("node load balancer: persist firewall withdrawal evidence: %w", err))
	}

	// Mutate exactly one sorted relationship per pass. The relation helper
	// persists and reads back the canonical Service-owned issue, so a second VM
	// on this firewall cannot be touched until this removal is authoritatively
	// absent (or a local pre-dispatch block is durably retired).
	assignment := assignments[0]
	_, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		owner,
		&nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationUnassign,
			firewallUUID: assignment.firewallUUID,
			vmUUID:       assignment.vmUUID,
		},
	)
	if relationErr != nil {
		return errors.Join(discoveryErr, fmt.Errorf(
			"node load balancer: detach owned firewall %s from VM %s while failing closed: %w",
			assignment.firewallUUID,
			assignment.vmUUID,
			relationErr,
		))
	}
	return discoveryErr
}

type nodeLoadBalancerFirewallDetachAssignment struct {
	firewallUUID string
	vmUUID       string
}

func nodeLoadBalancerFirewallDetachAssignments(
	firewalls []inspace.Firewall,
) ([]nodeLoadBalancerFirewallDetachAssignment, string, error) {
	assignments := make([]nodeLoadBalancerFirewallDetachAssignment, 0)
	seen := map[string]struct{}{}
	for _, firewall := range firewalls {
		if !validNodeLoadBalancerCloudUUID(firewall.UUID) {
			return nil, "", fmt.Errorf("node load balancer: owned firewall has invalid UUID %q", firewall.UUID)
		}
		for _, resource := range firewall.ResourcesAssigned {
			if !strings.EqualFold(resource.ResourceType, "vm") || !validNodeLoadBalancerCloudUUID(resource.ResourceUUID) {
				return nil, "", fmt.Errorf("node load balancer: owned firewall %s has invalid assigned resource %#v", firewall.UUID, resource)
			}
			key := firewall.UUID + "/" + resource.ResourceUUID
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			assignments = append(assignments, nodeLoadBalancerFirewallDetachAssignment{
				firewallUUID: firewall.UUID,
				vmUUID:       resource.ResourceUUID,
			})
		}
	}
	sort.Slice(assignments, func(i, j int) bool {
		left := assignments[i].firewallUUID + "/" + assignments[i].vmUUID
		right := assignments[j].firewallUUID + "/" + assignments[j].vmUUID
		return left < right
	})
	encoded := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		encoded = append(encoded, assignment.firewallUUID+"/"+assignment.vmUUID)
	}
	return assignments, strings.Join(encoded, ","), nil
}

func validateNodeLoadBalancerFirewallDetachSet(encoded string) error {
	if encoded == "" {
		return errors.New("node load balancer: empty firewall withdrawal detach set")
	}
	previous := ""
	for _, item := range strings.Split(encoded, ",") {
		parts := strings.Split(item, "/")
		if len(parts) != 2 || !validNodeLoadBalancerCloudUUID(parts[0]) || !validNodeLoadBalancerCloudUUID(parts[1]) {
			return fmt.Errorf("node load balancer: invalid firewall withdrawal detach set %q", encoded)
		}
		if previous != "" && item <= previous {
			return fmt.Errorf("node load balancer: firewall withdrawal detach set is not strictly sorted: %q", encoded)
		}
		previous = item
	}
	return nil
}

func parseNodeLoadBalancerFirewallDetachTimes(encoded string) (map[string]string, error) {
	detachedAt := map[string]string{}
	if err := json.Unmarshal([]byte(encoded), &detachedAt); err != nil || len(detachedAt) == 0 {
		return nil, fmt.Errorf("node load balancer: invalid firewall withdrawal detach timestamps %q", encoded)
	}
	for pair, encodedTime := range detachedAt {
		if err := validateNodeLoadBalancerFirewallDetachSet(pair); err != nil || strings.Contains(pair, ",") {
			return nil, fmt.Errorf("node load balancer: invalid firewall withdrawal detach timestamp key %q", pair)
		}
		if _, err := time.Parse(time.RFC3339Nano, encodedTime); err != nil {
			return nil, fmt.Errorf("node load balancer: invalid firewall withdrawal detach timestamp for %s: %w", pair, err)
		}
	}
	return detachedAt, nil
}

func nodeLoadBalancerFirewallDetachSetFromTimes(detachedAt map[string]string) string {
	pairs := make([]string, 0, len(detachedAt))
	for pair := range detachedAt {
		pairs = append(pairs, pair)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func validNodeLoadBalancerCloudUUID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return false
	}
	_, err := hex.DecodeString(strings.Join(parts, ""))
	return err == nil
}

func (c *nodeLoadBalancerController) serviceDatapathWithdrawn(ctx context.Context, service *corev1.Service) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if current.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
		return false, nil
	}
	return c.serviceExposureWithdrawn(ctx, current)
}

func (c *nodeLoadBalancerController) serviceExposureWithdrawn(ctx context.Context, service *corev1.Service) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if len(current.Status.LoadBalancer.Ingress) != 0 {
		return false, nil
	}
	client := c.provider.kubeClient.CoreV1().Services(current.Namespace)
	generated, getErr := client.Get(ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{})
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return false, getErr
	}
	if getErr == nil {
		if !nodeLoadBalancerDatapathOwnedByService(generated, current) {
			return false, fmt.Errorf("node load balancer: cannot prove withdrawal while datapath Service %s/%s is foreign", current.Namespace, generated.Name)
		}
		if len(generated.Status.LoadBalancer.Ingress) != 0 {
			return false, nil
		}
	}
	return c.serviceFirewallsDetached(ctx, current)
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
	activeShard, active, err := c.activeDatapathShard(ctx, service)
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
	nodes, err := c.rawNodesForShard(ctx, currentShard)
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
	nodes, err = c.rawNodesForShard(ctx, currentShard)
	if err != nil {
		return false, err
	}
	return len(nodes) != 0, nil
}

func (c *nodeLoadBalancerController) planForService(ctx context.Context, target *corev1.Service) (nodeLoadBalancerIntent, nodeLoadBalancerPlan, nodeLoadBalancerShardPlan, error) {
	currentTarget, err := c.getExactParentService(ctx, target)
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, err
	}
	liveServices, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, fmt.Errorf(
			"node load balancer: list authoritative Services for planning: %w", err,
		)
	}
	services := make([]*corev1.Service, 0, len(liveServices.Items))
	for index := range liveServices.Items {
		services = append(services, &liveServices.Items[index])
	}
	targetFound := false
	for index, service := range services {
		if service.Namespace == currentTarget.Namespace && service.Name == currentTarget.Name {
			services[index] = currentTarget
			targetFound = true
			break
		}
	}
	if !targetFound {
		services = append(services, currentTarget)
	}
	target = currentTarget
	reservations, err := c.activeDatapathPortReservations(ctx, services)
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, err
	}
	// Reserve every occupied generated-name pattern, including foreign or
	// malformed NodePools. Existing valid assignments can still use their name,
	// but a new shard must deterministically advance to the next hash instead of
	// colliding forever with an object the CCM cannot mutate.
	occupiedPools, err := c.provider.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, fmt.Errorf("node load balancer: list occupied NodePool names: %w", err)
	}
	for index := range occupiedPools.Items {
		name := occupiedPools.Items[index].GetName()
		if !isManagedNodeLoadBalancerShardName(name) {
			continue
		}
		if _, exists := reservations[name]; !exists {
			reservations[name] = make(map[nodeLoadBalancerPortClaim]string)
		}
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
				quarantined, quarantineErr := c.invalidServiceIsQuarantined(ctx, service)
				if quarantineErr != nil {
					return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, planningServiceFault(
						service, errors.Join(parseErr, quarantineErr),
					)
				}
				if !quarantined {
					return nodeLoadBalancerIntent{}, nodeLoadBalancerPlan{}, nodeLoadBalancerShardPlan{}, planningServiceFault(service, fmt.Errorf(
						"node load balancer: waiting for invalid Service %s/%s to become non-advertised: %w",
						service.Namespace, service.Name, parseErr,
					))
				}
			}
			// A never-established invalid Service owns no public dataplane. A
			// previously established one is omitted only after its datapath and
			// published status are authoritatively absent. Its retained shard and
			// firewall can then be recovered if the user fixes the Service without
			// letting malformed claims evict healthy Services.
			klog.ErrorS(parseErr, "quarantined invalid InSpace node load balancer Service", "service", service.Namespace+"/"+service.Name)
			continue
		}
		if intent.Mode == nodeLoadBalancerModeLocal {
			// Direct-node Services own neither a generated NodePool nor an
			// aggregate shard port reservation.
			continue
		}
		if intent.ExistingShard != "" {
			preserve, preserveErr := c.persistedShardAssignmentMatches(ctx, service, intent, reservations)
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

func (c *nodeLoadBalancerController) activeDatapathPortReservations(
	ctx context.Context,
	services []*corev1.Service,
) (nodeLoadBalancerPortReservations, error) {
	reservations := make(nodeLoadBalancerPortReservations)
	for _, service := range services {
		if !isNodeLoadBalancerService(service) && !containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		datapath, shard, found, err := c.activeDatapathReservationService(ctx, service)
		if !found && err == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		ports, err := nodeLoadBalancerPortClaims(datapath)
		if err != nil {
			return nil, planningServiceFault(service, fmt.Errorf(
				"node load balancer: active datapath reservation for %s/%s has invalid ports: %w",
				service.Namespace, service.Name, err,
			))
		}
		owner := string(service.UID)
		if owner == "" {
			return nil, planningServiceFault(service, fmt.Errorf(
				"node load balancer: active datapath reservation for %s/%s has no Service UID",
				service.Namespace, service.Name,
			))
		}
		if reservations[shard] == nil {
			reservations[shard] = make(map[nodeLoadBalancerPortClaim]string)
		}
		for _, port := range ports {
			if existing, conflict := reservations[shard][port]; conflict && existing != owner {
				return nil, planningShardFault(shard, fmt.Errorf(
					"node load balancer: active datapaths %s and %s collide on shard %s %s/%d",
					existing, owner, shard, port.Protocol, port.Port,
				))
			}
			reservations[shard][port] = owner
		}
	}
	return reservations, nil
}

// activeDatapathReservationService validates the immutable ownership and
// routing identity of an active child, but deliberately reads the child's own
// ports instead of requiring its full spec to equal the live parent. A parent
// edit necessarily leaves the old child behind until the controller closes it;
// those old ports must remain reserved throughout that transition.
func (c *nodeLoadBalancerController) activeDatapathReservationService(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, string, bool, error) {
	if service == nil || service.UID == "" {
		return nil, "", false, planningServiceFault(service, errors.New("node load balancer: reservation parent Service identity is required"))
	}
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("node load balancer: read parent Service for active reservation: %w", err)
	}
	if current.UID != service.UID {
		// The informer entry belongs to a deleted generation. It owns no live
		// reservation for the replacement Service.
		return nil, "", false, nil
	}
	activeShard := current.Annotations[annotationNodeLoadBalancerDatapathActive]
	child, childErr := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if childErr != nil && !apierrors.IsNotFound(childErr) {
		return nil, "", false, fmt.Errorf("node load balancer: read active datapath reservation: %w", childErr)
	}
	if activeShard == "" {
		return nil, "", false, nil
	}
	if !isManagedNodeLoadBalancerShardName(activeShard) {
		return nil, activeShard, false, planningServiceFault(current, fmt.Errorf(
			"node load balancer: parent Service %s/%s has invalid active reservation shard %q",
			current.Namespace, current.Name, activeShard,
		))
	}
	if apierrors.IsNotFound(childErr) {
		return nil, activeShard, false, planningServiceFault(current, fmt.Errorf(
			"node load balancer: active datapath Service %s/%s is missing",
			current.Namespace, nodeLoadBalancerDatapathName(current),
		))
	}
	classOK := child.Spec.LoadBalancerClass != nil && *child.Spec.LoadBalancerClass == nodeLoadBalancerDatapathClass
	allocateOK := child.Spec.AllocateLoadBalancerNodePorts != nil && !*child.Spec.AllocateLoadBalancerNodePorts
	if child.DeletionTimestamp != nil || !nodeLoadBalancerDatapathOwnedByService(child, current) ||
		child.Annotations[annotationNodeLoadBalancerDatapathShard] != activeShard ||
		child.Spec.Type != corev1.ServiceTypeLoadBalancer || !classOK || !allocateOK ||
		child.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster {
		return nil, activeShard, false, planningServiceFault(current, fmt.Errorf(
			"node load balancer: active datapath Service %s/%s lost its immutable reservation identity",
			current.Namespace, child.Name,
		))
	}
	return child, activeShard, true, nil
}

func (c *nodeLoadBalancerController) persistedShardAssignmentMatches(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	reservations nodeLoadBalancerPortReservations,
) (bool, error) {
	nodePool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, intent.ExistingShard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], intent.ExistingShard) &&
			!aggregateShardCleanupWasProven(service.Annotations[annotationNodeLoadBalancerShardCleanupProven], intent.ExistingShard) {
			return false, planningShardFault(intent.ExistingShard, fmt.Errorf(
				"node load balancer: materialized persisted shard %s disappeared without cleanup proof",
				intent.ExistingShard,
			))
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: get persisted NodePool %s: %w", intent.ExistingShard, err)
	}
	labels := nodePool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != intent.ExistingShard {
		if aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], intent.ExistingShard) &&
			!aggregateShardCleanupWasProven(service.Annotations[annotationNodeLoadBalancerShardCleanupProven], intent.ExistingShard) {
			return false, planningShardFault(intent.ExistingShard, fmt.Errorf(
				"node load balancer: materialized persisted shard %s lost exact state-anchor ownership",
				intent.ExistingShard,
			))
		}
		if service.Annotations[annotationNodeLoadBalancerDatapathActive] != "" || len(service.Status.LoadBalancer.Ingress) != 0 {
			return false, planningShardFault(intent.ExistingShard, fmt.Errorf(
				"node load balancer: advertised persisted shard %s lacks exact cluster ownership",
				intent.ExistingShard,
			))
		}
		// An unadvertised stale assignment does not own the occupied NodePool.
		// Drop the assignment and let the reserved-name planner advance to a
		// collision-free shard rather than retrying the foreign object forever.
		return false, nil
	}
	if !containsString(nodePool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return false, planningShardFault(intent.ExistingShard, fmt.Errorf(
			"node load balancer: persisted shard %s lost its state finalizer",
			intent.ExistingShard,
		))
	}
	if labels[nodeLoadBalancerProfileLabel] != nodeLoadBalancerIntentProfileHash(intent) {
		return false, nil
	}
	datapath, activeShard, found, err := c.activeDatapathReservationService(ctx, service)
	if !found && err == nil {
		// A matching persisted NodePool is authoritative even before the first
		// datapath activation. Port conflicts are still checked against all active
		// reservations by the planner; dropping this assignment would churn names
		// merely because the child has not converged yet.
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if activeShard != intent.ExistingShard {
		previous := service.Annotations[annotationNodeLoadBalancerPreviousShard]
		if previous == "" || activeShard != previous {
			return false, planningServiceFault(service, fmt.Errorf(
				"node load balancer: persisted datapath Service for %s/%s has a foreign shard identity",
				service.Namespace, service.Name,
			))
		}
		// During a staged migration the persisted assignment already names the
		// replacement shard while the active datapath intentionally continues to
		// advertise the previous shard. Preserve the replacement assignment only
		// while the public port claims are unchanged. An edited inactive Service
		// must not steal a port from a Service already active on the replacement.
	}
	datapathPorts, err := nodeLoadBalancerPortClaims(datapath)
	if err != nil {
		return false, planningServiceFault(service, fmt.Errorf(
			"node load balancer: persisted datapath Service for %s/%s has invalid ports: %w",
			service.Namespace, service.Name, err,
		))
	}
	_ = datapathPorts // Validation above protects reservations; the live claims are already recorded.
	for _, port := range intent.Ports {
		if owner, occupied := reservations[intent.ExistingShard][port]; occupied && owner != intent.ServiceID {
			return false, nil
		}
	}
	return true, nil
}

func (c *nodeLoadBalancerController) ensureServiceMetadata(ctx context.Context, service *corev1.Service, shard string) (bool, error) {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return false, fmt.Errorf("node load balancer: refusing to persist invalid shard %q", shard)
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service intent changed before metadata persistence")
		}
		changed := false
		if !containsString(copy.Finalizers, nodeLoadBalancerFinalizer) {
			copy.Finalizers = append(copy.Finalizers, nodeLoadBalancerFinalizer)
			changed = true
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		cleanupProof := copy.Annotations[annotationNodeLoadBalancerShardCleanupProven]
		clearAggregateShardCleanupProof(copy.Annotations, shard)
		if copy.Annotations[annotationNodeLoadBalancerShardCleanupProven] != cleanupProof {
			// A proof belongs only to the retired generation of this shard. It
			// must never authorize cleanup recovery after live ownership resumes.
			// Reset its matching materialization handoff at the same time; the
			// exact NodePool ensure will establish a new generation and re-add it.
			clearAggregateShardMaterialization(copy.Annotations, shard)
			changed = true
		}
		if copy.Annotations[annotationNodeLoadBalancerShard] == shard {
			return changed, nil
		}
		currentShard := copy.Annotations[annotationNodeLoadBalancerShard]
		existingPrevious := copy.Annotations[annotationNodeLoadBalancerPreviousShard]
		previousShard := ""
		_, activeShard, active, activeErr := c.activeDatapathReservationService(ctx, copy)
		if activeErr != nil {
			return false, activeErr
		}
		if existingPrevious != "" && (!active || activeShard != existingPrevious || activeShard == currentShard) {
			return false, fmt.Errorf(
				"node load balancer: previous shard %s must finish cleanup before assigning %s",
				existingPrevious,
				shard,
			)
		}
		if active {
			previousShard = activeShard
			if activeShard == currentShard {
				// The datapath already cut over, but cleanup of older migration
				// metadata has not completed. Its current firewall is now the
				// dataplane identity that a new migration must preserve.
				if currentFirewall := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]; currentFirewall != "" {
					if previousFirewall := copy.Annotations[annotationNodeLoadBalancerPreviousFirewall]; previousFirewall != "" && previousFirewall != currentFirewall {
						return false, fmt.Errorf(
							"node load balancer: previous firewall %s must finish cleanup before preserving %s",
							previousFirewall,
							currentFirewall,
						)
					}
					copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = currentFirewall
				}
			}
		}
		if previousShard == "" && currentShard != "" && currentShard != shard {
			pool, poolErr := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, currentShard, metav1.GetOptions{})
			materialized := aggregateShardStateWasMaterialized(copy.Annotations[annotationNodeLoadBalancerShardStateMaterial], currentShard)
			cleanupProven := aggregateShardCleanupWasProven(copy.Annotations[annotationNodeLoadBalancerShardCleanupProven], currentShard)
			switch {
			case apierrors.IsNotFound(poolErr):
				if materialized && !cleanupProven {
					return false, fmt.Errorf("node load balancer: prior materialized shard %s disappeared without cleanup proof", currentShard)
				}
				// The old value was either only a prospective metadata assignment,
				// or its paid state was durably proven absent. Retire any completed
				// handoff before assigning the replacement.
				if cleanupProven {
					clearAggregateShardCleanupProof(copy.Annotations, currentShard)
					clearAggregateShardMaterialization(copy.Annotations, currentShard)
					changed = true
				}
			case poolErr != nil:
				return false, fmt.Errorf("node load balancer: inspect prior shard anchor %s before reassignment: %w", currentShard, poolErr)
			default:
				labels := pool.GetLabels()
				exact := labels[nodeLoadBalancerManagedLabel] == "true" &&
					labels[nodeLoadBalancerClusterLabel] == c.provider.config.ClusterID &&
					labels[nodeLoadBalancerShardLabel] == currentShard
				if !exact && materialized && !cleanupProven {
					return false, fmt.Errorf("node load balancer: prior materialized shard %s lost exact state-anchor ownership", currentShard)
				}
				if exact && !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
					return false, fmt.Errorf("node load balancer: prior materialized shard %s lost its state finalizer", currentShard)
				}
				if exact {
					if !materialized {
						copy.Annotations[annotationNodeLoadBalancerShardStateMaterial] = appendAggregateShardSet(
							copy.Annotations[annotationNodeLoadBalancerShardStateMaterial], currentShard,
						)
						changed = true
					}
					if cleanupProven {
						clearAggregateShardCleanupProof(copy.Annotations, currentShard)
						changed = true
					}
					// Even before datapath activation, a created NodePool may already
					// own a billed VM. Preserve it as previous until full aggregate
					// firewall/capacity cleanup proves retirement.
					previousShard = currentShard
				} else if cleanupProven {
					clearAggregateShardCleanupProof(copy.Annotations, currentShard)
					clearAggregateShardMaterialization(copy.Annotations, currentShard)
					changed = true
				}
			}
		}
		if previousShard != "" && previousShard != shard {
			copy.Annotations[annotationNodeLoadBalancerPreviousShard] = previousShard
		} else {
			delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
		}
		copy.Annotations[annotationNodeLoadBalancerShard] = shard
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: persist Service metadata: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) activeDatapathShard(ctx context.Context, service *corev1.Service) (string, bool, error) {
	_, shard, found, err := c.activeDatapathService(ctx, service)
	return shard, found, err
}

func (c *nodeLoadBalancerController) activeDatapathService(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, string, bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, "", false, fmt.Errorf("node load balancer: get exact parent before active datapath lookup: %w", err)
	}
	client := c.provider.kubeClient.CoreV1().Services(current.Namespace)
	activeShard := current.Annotations[annotationNodeLoadBalancerDatapathActive]
	datapath, datapathErr := client.Get(ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{})
	if datapathErr != nil && !apierrors.IsNotFound(datapathErr) {
		return nil, "", false, fmt.Errorf("node load balancer: get active datapath Service: %w", datapathErr)
	}
	if datapathErr == nil && !nodeLoadBalancerDatapathOwnedByService(datapath, current) {
		return nil, "", false, fmt.Errorf("node load balancer: datapath Service %s/%s lacks exact owner identity", current.Namespace, datapath.Name)
	}
	if activeShard != "" {
		if !isManagedNodeLoadBalancerShardName(activeShard) {
			return nil, "", false, fmt.Errorf("node load balancer: parent Service %s/%s has invalid active datapath shard %q", current.Namespace, current.Name, activeShard)
		}
		if apierrors.IsNotFound(datapathErr) {
			return nil, "", false, fmt.Errorf("node load balancer: active datapath Service %s/%s is missing", current.Namespace, nodeLoadBalancerDatapathName(current))
		}
		if !nodeLoadBalancerDatapathMatchesDesired(datapath, current, activeShard) {
			return nil, "", false, fmt.Errorf("node load balancer: active datapath Service %s/%s drifted from its exact parent contract", current.Namespace, datapath.Name)
		}
		return datapath, activeShard, true, nil
	}
	// An exact-owned child without the durable marker is staged only. It does
	// not reserve established capacity or become authoritative until both
	// private VIP and public Proxy statuses pass exact readback.
	return nil, "", false, nil
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
	if err := c.ensureDynamicObject(ctx, nodeClassGVR, desired); err != nil {
		return err
	}
	current, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: read back managed NodeClass %s: %w", name, err)
	}
	if current.GetDeletionTimestamp() != nil ||
		current.GetLabels()[nodeLoadBalancerManagedLabel] != "true" ||
		current.GetLabels()[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		!containsString(current.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return fmt.Errorf("node load balancer: generated NodeClass %s lacks exact cluster-state identity", name)
	}
	if err := c.markAggregateClusterStateMaterializedForReferences(ctx); err != nil {
		return err
	}
	return c.clearAggregateClusterCleanupProofs(ctx)
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
	if err := c.ensureDynamicObject(ctx, nodePoolGVR, desired); err != nil {
		return err
	}
	current, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: read back managed NodePool %s: %w", shard.Name, err)
	}
	if err := c.validateEnsuredNodeLoadBalancerNodePool(current, desired, shard.Name); err != nil {
		return err
	}
	// Persist the Service-side handoff only after the exact API readback proves
	// that the NodePool finalizer really exists. This marker prevents a later
	// force-removal of that anchor from being mistaken for a never-materialized
	// prospective shard during Service deletion.
	return c.markAggregateShardStateMaterializedForReferences(ctx, shard.Name)
}

func (c *nodeLoadBalancerController) validateEnsuredNodeLoadBalancerNodePool(
	current, desired *unstructured.Unstructured,
	shard string,
) error {
	if current == nil || desired == nil || current.GetName() != shard || current.GetDeletionTimestamp() != nil {
		return fmt.Errorf("node load balancer: generated NodePool %s is absent, renamed, or deleting after ensure", shard)
	}
	currentLabels := current.GetLabels()
	for key, value := range desired.GetLabels() {
		if currentLabels[key] != value {
			return fmt.Errorf("node load balancer: generated NodePool %s lost exact label %s=%q", shard, key, value)
		}
	}
	if !containsString(current.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return fmt.Errorf("node load balancer: generated NodePool %s lacks the durable shard-state finalizer after ensure", shard)
	}
	desiredSpec, desiredFound, desiredErr := unstructured.NestedFieldCopy(desired.Object, "spec")
	currentSpec, currentFound, currentErr := unstructured.NestedFieldCopy(current.Object, "spec")
	if desiredErr != nil || currentErr != nil || !desiredFound || !currentFound || !reflect.DeepEqual(currentSpec, desiredSpec) {
		return fmt.Errorf("node load balancer: generated NodePool %s failed exact spec readback", shard)
	}
	return nil
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
	finalizers := object.GetFinalizers()
	if shard == "" {
		if !containsString(finalizers, nodeLoadBalancerNodeClassFinalizer) {
			object.SetFinalizers(append(finalizers, nodeLoadBalancerNodeClassFinalizer))
		}
	} else {
		if !containsString(finalizers, nodeLoadBalancerNodePoolFinalizer) {
			object.SetFinalizers(append(finalizers, nodeLoadBalancerNodePoolFinalizer))
		}
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
	desiredFinalizers := desired.GetFinalizers()
	existingFinalizers := existing.GetFinalizers()
	finalizersMatch := true
	for _, finalizer := range desiredFinalizers {
		if !containsString(existingFinalizers, finalizer) {
			finalizersMatch = false
			break
		}
	}
	if reflect.DeepEqual(existingSpec, desiredSpec) && labelsMatch && finalizersMatch {
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
	finalizers := updated.GetFinalizers()
	for _, finalizer := range desiredFinalizers {
		if !containsString(finalizers, finalizer) {
			finalizers = append(finalizers, finalizer)
		}
	}
	updated.SetFinalizers(finalizers)
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
	if waiting, completed, resumeErr := c.resumeOwnedServiceFirewallDelete(ctx, service); resumeErr != nil || waiting || completed {
		return nil, "", false, resumeErr
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, "", false, fmt.Errorf("node load balancer: list firewalls: %w", err)
	}
	if nodes != nil {
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.serviceFirewallRelationOwner(service),
			nil,
		)
		if relationErr != nil {
			return nil, "", false, relationErr
		}
		if !converged {
			return nil, "", false, nil
		}
	}
	var firewall *inspace.Firewall
	var currentFirewallByUUID *inspace.Firewall
	var pendingFirewallByUUID *inspace.Firewall
	var pendingFirewallByName *inspace.Firewall
	pendingUUID := service.Annotations[annotationNodeLoadBalancerPendingFirewall]
	pendingName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	pendingStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	pendingIssued := service.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	pendingIssuedAt := service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
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
	if (pendingIssued == "") != (pendingIssuedAt == "") {
		return nil, "", false, errors.New("node load balancer: pending firewall create-issued token and timestamp must be persisted together")
	}
	if pendingIssued != "" {
		if pendingName == "" || pendingStarted == "" {
			return nil, "", false, errors.New("node load balancer: firewall create-issued fence lacks its immutable pending identity")
		}
		if err := validateNodeLoadBalancerFirewallCreateIssued(pendingIssued, pendingIssuedAt); err != nil {
			return nil, "", false, err
		}
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
			if pendingIssued != "" {
				return nil, "", false, fmt.Errorf(
					"node load balancer: Service firewall create attempt %s issued at %s remains ambiguous; waiting for deterministic-name adoption or operator resolution",
					pendingIssued,
					pendingIssuedAt,
				)
			}
			startedAt, parseErr := time.Parse(time.RFC3339Nano, pendingStarted)
			if parseErr != nil {
				return nil, "", false, fmt.Errorf("node load balancer: invalid pending firewall create timestamp: %w", parseErr)
			}
			if !time.Now().UTC().Before(startedAt.Add(nodeLoadBalancerPendingCreateTimeout)) ||
				service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" ||
				service.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
				if _, confirmErr := c.confirmPendingFirewallAbsent(ctx, service, time.Now().UTC()); confirmErr != nil {
					return nil, "", false, confirmErr
				}
				return nil, "", false, nil
			}
			issuedService, issued, issueErr := c.ensurePendingFirewallCreateIssued(ctx, service)
			if issueErr != nil {
				return nil, "", false, issueErr
			}
			if !issued {
				return nil, "", false, nil
			}
			if createErr := c.createServiceFirewallFromIssuedIntent(ctx, issuedService, desired); createErr != nil {
				return nil, "", false, createErr
			}
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
		if service.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
			// An active path may have an ambiguous or eventually-consistent assignment.
			// Never clear its durable firewall identity or create a replacement from a
			// transiently absent List response; fail-closed withdrawal owns that proof.
			return nil, "", false, nil
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
		preparedService, prepared, err := c.ensurePendingFirewallCreateIntent(ctx, service, desired.Request.DisplayName)
		if err != nil {
			return nil, "", false, err
		}
		if !prepared {
			return nil, "", false, nil
		}
		issuedService, issued, issueErr := c.ensurePendingFirewallCreateIssued(ctx, preparedService)
		if issueErr != nil {
			return nil, "", false, issueErr
		}
		if !issued {
			return nil, "", false, nil
		}
		if createErr := c.createServiceFirewallFromIssuedIntent(ctx, issuedService, desired); createErr != nil {
			return nil, "", false, createErr
		}
		return nil, "", false, nil
	}

	ready := true
	assignments, err := nodeLoadBalancerFirewallVMAssignments(*firewall)
	if err != nil {
		return nil, "", false, err
	}
	for _, node := range nodes {
		if !nodeLoadBalancerNodeHealthy(node) {
			continue
		}
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			ready = false
			continue
		}
		if _, assigned := assignments[strings.ToLower(vmUUID)]; !assigned {
			if err := c.validateServiceFirewallAssignmentMutation(ctx, service, *firewall, node); err != nil {
				return nil, "", false, fmt.Errorf("node load balancer: refuse firewall assignment to VM %s: %w", vmUUID, err)
			}
			converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				c.serviceFirewallRelationOwner(service),
				&nodeLoadBalancerFirewallRelationFence{
					operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
				},
			)
			if relationErr != nil {
				return nil, "", false, fmt.Errorf("node load balancer: assign firewall %s to VM %s: %w", firewall.UUID, vmUUID, relationErr)
			}
			ready = false
			if !converged {
				break
			}
		}
	}
	previousUUID := service.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	if previousUUID == "" && currentUUID != "" && currentUUID != firewall.UUID {
		previousUUID = currentUUID
	}
	return firewall, previousUUID, ready, nil
}

func (c *nodeLoadBalancerController) validateServiceFirewallAssignmentMutation(
	ctx context.Context,
	service *corev1.Service,
	firewall inspace.Firewall,
	target *corev1.Node,
) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	if current.DeletionTimestamp != nil || !isNodeLoadBalancerService(current) {
		return errors.New("parent Service is deleting or no longer requests the Node load balancer")
	}
	activeShard := current.Annotations[annotationNodeLoadBalancerDatapathActive]
	if !isManagedNodeLoadBalancerShardName(activeShard) {
		return errors.New("parent Service has no valid active datapath")
	}
	assigningUUID := current.Annotations[annotationNodeLoadBalancerFirewallAssigning]
	assigningStarted := current.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
	if assigningUUID != firewall.UUID || assigningStarted == "" ||
		assigningUUID != service.Annotations[annotationNodeLoadBalancerFirewallAssigning] ||
		assigningStarted != service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] {
		return errors.New("durable firewall assignment authorization changed")
	}
	if _, err := time.Parse(time.RFC3339Nano, assigningStarted); err != nil {
		return fmt.Errorf("firewall assignment authorization timestamp is invalid: %w", err)
	}
	desired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return err
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewall.UUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
		!nodeLoadBalancerFirewallMatches(firewall, desired) {
		return errors.New("current firewall identity or policy no longer matches the live Service")
	}
	expected, err := parseNodeLoadBalancerService(
		current,
		nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard},
	)
	if err != nil {
		return err
	}
	client := c.provider.kubeClient.CoreV1().Services(current.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read private VIP contract before firewall assignment: %w", err)
	}
	if err := c.validatePlannedDatapathContract(current, datapath, activeShard, expected, true); err != nil {
		return err
	}
	if len(current.Status.LoadBalancer.Ingress) != 0 {
		return errors.New("public Proxy status is not empty while the firewall assignment gate is pending")
	}
	addresses, err := c.readyShardAddresses(ctx, activeShard)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(datapath.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, false)) {
		return errors.New("private VIP status no longer matches the authorized ready Nodes")
	}
	targetVM, targetOK := nodeLoadBalancerVMUUID(target)
	foundTarget := false
	for _, address := range addresses {
		vmUUID, ok := nodeLoadBalancerVMUUID(address.Node)
		if ok && targetOK && address.Node.Name == target.Name && vmUUID == targetVM {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		return fmt.Errorf("target Node %s is no longer an authorized ready member of shard %s", target.Name, activeShard)
	}
	return nil
}

// nodeLoadBalancerMutationKnownPreDispatch identifies the only error that
// proves the cloud request never left this process. Every HTTP response and
// transport error is post-dispatch ambiguous and must retain its issued
// receipt until exact desired-state readback resolves it.
func nodeLoadBalancerMutationKnownPreDispatch(err error) bool {
	return errors.Is(err, inspace.ErrMutationBlocked)
}

func newNodeLoadBalancerFirewallCreateIssuedToken() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("node load balancer: generate firewall create-issued token: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func validateNodeLoadBalancerFirewallCreateIssued(token, issuedAt string) error {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 16 {
		return fmt.Errorf("node load balancer: invalid firewall create-issued token %q", token)
	}
	if _, err := time.Parse(time.RFC3339Nano, issuedAt); err != nil {
		return fmt.Errorf("node load balancer: invalid firewall create-issued timestamp: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensurePendingFirewallCreateIssued(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, bool, error) {
	name := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	started := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	if name == "" || started == "" {
		return nil, false, errors.New("node load balancer: complete pending firewall identity is required before create issuance")
	}
	token, err := newNodeLoadBalancerFirewallCreateIssuedToken()
	if err != nil {
		return nil, false, err
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	updated, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWName] != name ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != started ||
			copy.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWDelete] != "" {
			return false, errors.New("node load balancer: pending firewall identity changed before create issuance")
		}
		desired, desiredErr := c.desiredServiceFirewall(copy)
		if desiredErr != nil || desired.Request.DisplayName != name {
			return false, errors.Join(desiredErr, errors.New("node load balancer: Service firewall policy changed before create issuance"))
		}
		existingToken := copy.Annotations[annotationNodeLoadBalancerPendingFWIssued]
		existingAt := copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
		if existingToken != "" || existingAt != "" {
			if existingToken == "" || existingAt == "" {
				return false, errors.New("node load balancer: incomplete firewall create-issued fence")
			}
			if validateErr := validateNodeLoadBalancerFirewallCreateIssued(existingToken, existingAt); validateErr != nil {
				return false, validateErr
			}
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] = token
		copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] = issuedAt
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: persist Service firewall create-issued fence: %w", err)
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) createServiceFirewallFromIssuedIntent(
	ctx context.Context,
	service *corev1.Service,
	desired desiredNodeLoadBalancerFirewall,
) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return fmt.Errorf("node load balancer: revalidate issued firewall create attempt: %w", err)
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return err
	}
	token := service.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	issuedAt := service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
	if err := validateNodeLoadBalancerFirewallCreateIssued(token, issuedAt); err != nil {
		return err
	}
	if current.DeletionTimestamp != nil || !isNodeLoadBalancerService(current) ||
		current.Annotations[annotationNodeLoadBalancerPendingFWName] != desired.Request.DisplayName ||
		current.Annotations[annotationNodeLoadBalancerPendingFWStarted] != service.Annotations[annotationNodeLoadBalancerPendingFWStarted] ||
		current.Annotations[annotationNodeLoadBalancerPendingFWIssued] != token ||
		current.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != issuedAt ||
		currentDesired.Hash != desired.Hash || currentDesired.Request.DisplayName != desired.Request.DisplayName {
		return errors.New("node load balancer: firewall create-issued attempt became stale before the cloud API call")
	}
	observed, absent, err := c.exactNodeLoadBalancerFirewallNameFresh(ctx, desired.Request.DisplayName)
	if err != nil {
		return fmt.Errorf("node load balancer: authorize Service firewall create after issue: %w", err)
	}
	if !absent {
		if observed == nil || !validNodeLoadBalancerCloudUUID(observed.UUID) ||
			!nodeLoadBalancerFirewallOwnedByService(
				*observed,
				c.provider.config.ClusterID,
				string(current.UID),
				c.provider.config.BillingAccountID,
			) || !nodeLoadBalancerFirewallMatches(*observed, desired) {
			return fmt.Errorf(
				"node load balancer: deterministic Service firewall name %q became foreign after create issue",
				desired.Request.DisplayName,
			)
		}
		committed, recoveryErr := c.resolveServiceFirewallCreateReadback(ctx, current, desired)
		if recoveryErr != nil {
			return recoveryErr
		}
		if !committed {
			return errors.New("node load balancer: observed Service firewall was not durably promoted")
		}
		return nil
	}
	created, err := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
	if err != nil {
		createErr := fmt.Errorf("node load balancer: create Service firewall: %w", err)
		if nodeLoadBalancerMutationKnownPreDispatch(err) {
			_, clearErr := c.clearPendingFirewallMetadata(ctx, current)
			return errors.Join(createErr, clearErr)
		}
		committed, recoveryErr := c.resolveServiceFirewallCreateReadback(ctx, current, desired)
		if recoveryErr != nil {
			return errors.Join(createErr, recoveryErr)
		}
		if committed {
			return nil
		}
		return createErr
	}
	if err := validateCreatedNodeLoadBalancerFirewall(created, desired); err != nil {
		responseErr := fmt.Errorf("node load balancer: created firewall response: %w", err)
		committed, recoveryErr := c.resolveServiceFirewallCreateReadback(ctx, current, desired)
		if recoveryErr != nil {
			return errors.Join(responseErr, recoveryErr)
		}
		if committed {
			return nil
		}
		return responseErr
	}
	// The response is only a provisional handle. Deterministic-name ownership,
	// exact policy, and UUID are adopted exclusively from a later unfiltered
	// ListFirewalls readback.
	committed, recoveryErr := c.resolveServiceFirewallCreateReadback(ctx, current, desired)
	if recoveryErr != nil {
		return recoveryErr
	}
	if !committed {
		return errors.New("node load balancer: Service firewall create response lacks authoritative readback")
	}
	return nil
}

// resolveServiceFirewallCreateReadback performs a new authoritative read after
// an HTTP error or a malformed success response. The issued
// receipt is transitioned only when that read proves the exact intended
// firewall exists. Absence, foreign, duplicate, or unreadable state leaves the
// receipt intact because a dispatched request can still commit later.
func (c *nodeLoadBalancerController) resolveServiceFirewallCreateReadback(
	ctx context.Context,
	service *corev1.Service,
	desired desiredNodeLoadBalancerFirewall,
) (bool, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read back Service firewall after create response: %w", err)
	}
	var observed *inspace.Firewall
	for index := range items {
		item := items[index]
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if observed != nil {
			return false, fmt.Errorf("node load balancer: multiple firewalls use managed name %q after create response", desired.Request.DisplayName)
		}
		copy := item
		observed = &copy
	}
	if observed != nil {
		if !validNodeLoadBalancerCloudUUID(observed.UUID) || !nodeLoadBalancerFirewallOwnedByService(
			*observed,
			c.provider.config.ClusterID,
			string(service.UID),
			c.provider.config.BillingAccountID,
		) || !nodeLoadBalancerFirewallMatches(*observed, desired) {
			return false, fmt.Errorf("node load balancer: managed Service firewall name %q resolved to a foreign or third-state resource after create response", desired.Request.DisplayName)
		}
		if _, err := c.ensurePendingFirewallMetadata(ctx, service, observed.UUID, desired.Request.DisplayName); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, fmt.Errorf("node load balancer: Service firewall create outcome remains ambiguous after exact name absence readback")
}

func (c *nodeLoadBalancerController) ensurePendingFirewallCreateIntent(ctx context.Context, service *corev1.Service, name string) (*corev1.Service, bool, error) {
	started := time.Now().UTC().Format(time.RFC3339Nano)
	updated, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service intent changed before firewall create")
		}
		desired, desiredErr := c.desiredServiceFirewall(copy)
		if desiredErr != nil {
			return false, desiredErr
		}
		if desired.Request.DisplayName != name {
			return false, errors.New("node load balancer: firewall create intent is stale for the current Service spec")
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if pendingName := copy.Annotations[annotationNodeLoadBalancerPendingFWName]; pendingName != "" {
			if pendingName == name && copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != "" {
				return false, nil
			}
			return false, fmt.Errorf("node load balancer: another firewall create attempt %q is already pending", pendingName)
		}
		copy.Annotations[annotationNodeLoadBalancerPendingFWName] = name
		copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] = started
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFirewall)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssued)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssuedAt)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWDelete)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: persist firewall create intent: %w", err)
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) ensurePendingFirewallMetadata(ctx context.Context, service *corev1.Service, uuid, name string) (bool, error) {
	if uuid == "" || name == "" {
		return false, errors.New("node load balancer: complete provisional firewall identity is required")
	}
	expectedStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	expectedIssued := service.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	expectedIssuedAt := service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPendingFWName] != name ||
			expectedStarted == "" || copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != expectedStarted ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] != expectedIssued ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != expectedIssuedAt {
			return false, errors.New("node load balancer: provisional firewall create attempt changed before identity persistence")
		}
		if copy.Annotations[annotationNodeLoadBalancerPendingFirewall] == uuid &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerPendingFirewall] = uuid
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssued)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssuedAt)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: persist provisional firewall identity: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) clearPendingFirewallMetadata(ctx context.Context, service *corev1.Service) (bool, error) {
	expectedName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	expectedStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	expectedIssued := service.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	expectedIssuedAt := service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPendingFWName] != expectedName ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != expectedStarted ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] != expectedIssued ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != expectedIssuedAt {
			return false, errors.New("node load balancer: provisional firewall create attempt changed before metadata clear")
		}
		if copy.Annotations[annotationNodeLoadBalancerPendingFirewall] == "" && expectedName == "" && expectedStarted == "" &&
			expectedIssued == "" && expectedIssuedAt == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWDelete] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
			return false, nil
		}
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFirewall)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWName)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWStarted)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssued)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWIssuedAt)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWDelete)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: clear provisional firewall identity: %w", err)
	}
	return changed, nil
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
	expectedName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	expectedStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service intent changed before firewall promotion")
		}
		if expectedName == "" || expectedStarted == "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWName] != expectedName ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != expectedStarted ||
			copy.Annotations[annotationNodeLoadBalancerPendingFirewall] != firewall.UUID {
			return false, errors.New("node load balancer: provisional firewall create attempt changed before promotion")
		}
		desired, desiredErr := c.desiredServiceFirewall(copy)
		if desiredErr != nil {
			return false, desiredErr
		}
		if desired.Hash != policyHash || desired.Request.DisplayName != expectedName || !nodeLoadBalancerFirewallMatches(*firewall, desired) {
			return false, errors.New("node load balancer: provisional firewall no longer matches the current Service policy")
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
			annotationNodeLoadBalancerPendingFWIssued,
			annotationNodeLoadBalancerPendingFWIssuedAt,
			annotationNodeLoadBalancerPendingFWDelete,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
		} {
			delete(copy.Annotations, key)
		}
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: atomically promote provisional firewall identity: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) ensurePendingFirewallDeletionMetadata(ctx context.Context, service *corev1.Service) (bool, error) {
	expectedName := service.Annotations[annotationNodeLoadBalancerPendingFWName]
	expectedStarted := service.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if expectedName == "" || expectedStarted == "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWName] != expectedName ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != expectedStarted {
			return false, errors.New("node load balancer: provisional firewall create attempt changed before cleanup")
		}
		if copy.Annotations[annotationNodeLoadBalancerPendingFWDelete] == "true" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWAbsent] == "" &&
			copy.Annotations[annotationNodeLoadBalancerPendingFWChecked] == "" {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerPendingFWDelete] = "true"
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerPendingFWChecked)
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: persist provisional firewall cleanup state: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) confirmPendingFirewallAbsent(ctx context.Context, service *corev1.Service, now time.Time) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, err
	}
	if issued := current.Annotations[annotationNodeLoadBalancerPendingFWIssued]; issued != "" ||
		current.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != "" {
		return false, fmt.Errorf(
			"node load balancer: firewall create-issued attempt %s cannot be cleared by absence confirmation; deterministic-name adoption or operator resolution is required",
			issued,
		)
	}
	started := current.Annotations[annotationNodeLoadBalancerPendingFWStarted]
	if started == "" {
		return false, errors.New("node load balancer: pending firewall name is missing its create-attempt timestamp")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return false, fmt.Errorf("node load balancer: pending firewall create-attempt timestamp is invalid: %w", err)
	}
	confirmed, changed, err := c.recordFirewallAbsence(
		ctx,
		current,
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
	current, err = c.getExactParentService(ctx, current)
	if err != nil {
		return false, err
	}
	_, err = c.clearPendingFirewallMetadata(ctx, current)
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
	expectedUUID := service.Annotations[annotationNodeLoadBalancerFirewallUUID]
	expectedHash := service.Annotations[annotationNodeLoadBalancerFirewallHash]
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != expectedUUID ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != expectedHash {
			return false, errors.New("node load balancer: current firewall identity changed during absence confirmation")
		}
		count, parseErr := strconv.Atoi(copy.Annotations[annotationNodeLoadBalancerFirewallAbsent])
		if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
			return false, errors.New("node load balancer: current firewall absence is no longer confirmed")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallUUID)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallHash)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallChecked)
		return true, nil
	})
	if err != nil {
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
	confirmed = false
	_, changed, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		count := 0
		if raw := copy.Annotations[countAnnotation]; raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 0 || parsed > nodeLoadBalancerAbsenceConfirmations {
				return false, fmt.Errorf("node load balancer: invalid firewall absence count %q", raw)
			}
			count = parsed
		}
		if count >= nodeLoadBalancerAbsenceConfirmations {
			confirmed = true
			return false, nil
		}
		if raw := copy.Annotations[checkedAnnotation]; raw != "" {
			checkedAt, parseErr := time.Parse(time.RFC3339Nano, raw)
			if parseErr != nil {
				return false, fmt.Errorf("node load balancer: invalid firewall absence timestamp: %w", parseErr)
			}
			if now.Before(checkedAt.Add(nodeLoadBalancerAbsenceConfirmationDelay)) {
				return false, nil
			}
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		next := count + 1
		copy.Annotations[countAnnotation] = strconv.Itoa(next)
		copy.Annotations[checkedAnnotation] = now.UTC().Format(time.RFC3339Nano)
		confirmed = next >= nodeLoadBalancerAbsenceConfirmations
		return true, nil
	})
	if err != nil {
		return false, false, fmt.Errorf("node load balancer: persist firewall absence evidence: %w", err)
	}
	return confirmed, changed, nil
}

func (c *nodeLoadBalancerController) clearFirewallAbsenceEvidence(
	ctx context.Context,
	service *corev1.Service,
	countAnnotation, checkedAnnotation string,
) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[countAnnotation] == "" && copy.Annotations[checkedAnnotation] == "" {
			return false, nil
		}
		delete(copy.Annotations, countAnnotation)
		delete(copy.Annotations, checkedAnnotation)
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: clear firewall absence evidence: %w", err)
	}
	return changed, nil
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
	if firewall == nil || !validNodeLoadBalancerCloudUUID(firewall.UUID) {
		return errors.New("response has no valid firewall UUID")
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
	assignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
	if err != nil {
		return false
	}
	_, assigned := assignments[strings.ToLower(vmUUID)]
	return assigned
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
	if firewall == nil || firewall.UUID == "" {
		return false, errors.New("node load balancer: complete firewall identity is required")
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service intent changed before firewall metadata persistence")
		}
		desired, desiredErr := c.desiredServiceFirewall(copy)
		if desiredErr != nil {
			return false, desiredErr
		}
		if !nodeLoadBalancerFirewallMatches(*firewall, desired) {
			return false, errors.New("node load balancer: firewall no longer matches the current Service policy")
		}
		if assigning := copy.Annotations[annotationNodeLoadBalancerFirewallAssigning]; assigning != "" && assigning != firewall.UUID {
			return false, fmt.Errorf("node load balancer: unresolved firewall assignment fence still binds UUID %s", assigning)
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		currentBefore := copy.Annotations[annotationNodeLoadBalancerFirewallUUID]
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
		observedPrevious := previousUUID
		if currentBefore != "" && currentBefore != firewall.UUID {
			observedPrevious = currentBefore
		}
		if observedPrevious != "" && observedPrevious != firewall.UUID && copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
			copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] = observedPrevious
			changed = true
		}
		for _, key := range []string{annotationNodeLoadBalancerFirewallAbsent, annotationNodeLoadBalancerFirewallChecked} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: persist firewall metadata: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) ensureServiceFirewallAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	firewallUUID string,
) (*corev1.Service, bool, error) {
	if firewallUUID == "" {
		return nil, false, errors.New("node load balancer: firewall UUID is required before assignment authorization")
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, false, err
	}
	activeShard := current.Annotations[annotationNodeLoadBalancerDatapathActive]
	if !isManagedNodeLoadBalancerShardName(activeShard) || current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID {
		return nil, false, errors.New("node load balancer: firewall assignment is not bound to the active datapath identity")
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx,
		nodeLoadBalancerDatapathName(current),
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: inspect private VIP before firewall assignment authorization: %w", err)
	}
	if !nodeLoadBalancerDatapathMatchesDesired(datapath, current, activeShard) || len(datapath.Status.LoadBalancer.Ingress) == 0 {
		return nil, false, errors.New("node load balancer: exact private VIP must exist before firewall assignment authorization")
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	updated, changed, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerDatapathActive] != activeShard ||
			copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
			!nodeLoadBalancerDatapathMatchesDesired(datapath, copy, activeShard) {
			return false, errors.New("node load balancer: datapath changed before firewall assignment authorization")
		}
		existingUUID := copy.Annotations[annotationNodeLoadBalancerFirewallAssigning]
		existingStarted := copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		if existingUUID != "" || existingStarted != "" {
			if existingUUID != firewallUUID || existingStarted == "" {
				return false, errors.New("node load balancer: another or incomplete firewall assignment attempt is already pending")
			}
			if _, parseErr := time.Parse(time.RFC3339Nano, existingStarted); parseErr != nil {
				return false, fmt.Errorf("node load balancer: firewall assignment timestamp is invalid: %w", parseErr)
			}
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
		copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = started
		return true, nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: persist firewall assignment authorization: %w", err)
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) clearServiceFirewallAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	firewallUUID string,
) (*corev1.Service, bool, error) {
	updated, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		assigning := copy.Annotations[annotationNodeLoadBalancerFirewallAssigning]
		started := copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		if assigning == "" && started == "" {
			return false, nil
		}
		if assigning != firewallUUID || started == "" || copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID {
			return false, errors.New("node load balancer: firewall assignment authorization changed before exact readback")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssigning)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssignAt)
		return true, nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: clear firewall assignment authorization: %w", err)
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) serviceFirewallAssignmentsMatch(
	ctx context.Context,
	service *corev1.Service,
	firewallUUID string,
	nodes []*corev1.Node,
) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, err
	}
	if firewallUUID == "" || current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID {
		return false, errors.New("node load balancer: firewall assignment readback is not bound to current metadata")
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		return false, nil
	}
	expectedHash := current.Annotations[annotationNodeLoadBalancerFirewallHash]
	if expectedHash == "" {
		return false, errors.New("node load balancer: firewall assignment readback is missing the policy hash")
	}
	desiredVMs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok || !nodeLoadBalancerNodeHealthy(node) {
			return false, fmt.Errorf("node load balancer: selected Node %s is not eligible for firewall assignment", node.Name)
		}
		desiredVMs[vmUUID] = struct{}{}
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, fmt.Errorf("node load balancer: list firewalls for assignment readback: %w", err)
	}
	matches := 0
	for _, firewall := range items {
		if firewall.UUID != firewallUUID {
			continue
		}
		matches++
		if !nodeLoadBalancerFirewallOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			string(current.UID),
			c.provider.config.BillingAccountID,
		) {
			return false, errors.New("node load balancer: current firewall lost exact policy ownership during assignment readback")
		}
		hash, hashErr := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
		if hashErr != nil || hash != expectedHash {
			return false, errors.New("node load balancer: current firewall policy changed during assignment readback")
		}
		assigned, assignmentErr := staleNodeLoadBalancerFirewallAssignments(firewall, desiredVMs)
		if assignmentErr != nil {
			return false, assignmentErr
		}
		normalizedAssignments, assignmentErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignmentErr != nil {
			return false, assignmentErr
		}
		if len(assigned) != 0 || len(normalizedAssignments) != len(desiredVMs) {
			return false, nil
		}
	}
	if matches > 1 {
		return false, fmt.Errorf("node load balancer: firewall UUID %s appears multiple times during assignment readback", firewallUUID)
	}
	return matches == 1, nil
}

func nodeLoadBalancerDatapathName(service *corev1.Service) string {
	return "inlb-dp-" + nodeLoadBalancerServiceIdentity(service)
}

// nodeLoadBalancerServiceIdentity is independent of Kubernetes namespace/name
// length limits while still binding every generated object to the exact parent
// identity. Fifty-two hex characters retain 208 bits of SHA-256 and keep the
// canonical Service name at 60 DNS-label characters.
func nodeLoadBalancerServiceIdentity(service *corev1.Service) string {
	identity := "nil-service"
	if service != nil {
		identity = service.Namespace + "\x00" + service.Name + "\x00" + string(service.UID)
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])[:52]
}

func (c *nodeLoadBalancerController) validateDatapathServiceName(ctx context.Context, service *corev1.Service) error {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	name := nodeLoadBalancerDatapathName(service)
	generated, err := client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: preflight datapath Service name %s/%s: %w", service.Namespace, name, err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(generated, service) {
		return fmt.Errorf("node load balancer: datapath Service name %s/%s is occupied by another owner", service.Namespace, name)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensureDatapathService(ctx context.Context, service *corev1.Service, shard string) (*corev1.Service, error) {
	name := nodeLoadBalancerDatapathName(service)
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("node load balancer: get datapath Service: %w", err)
	}
	desired := desiredNodeLoadBalancerDatapath(service, name, shard)
	if apierrors.IsNotFound(err) {
		created, createErr := client.Create(ctx, desired, metav1.CreateOptions{})
		if createErr != nil {
			return nil, fmt.Errorf("node load balancer: create datapath Service: %w", createErr)
		}
		return created, nil
	}
	if !nodeLoadBalancerDatapathOwnedByService(existing, service) {
		return nil, fmt.Errorf("node load balancer: datapath Service name %s/%s is occupied by another owner", service.Namespace, name)
	}
	if existing.Spec.LoadBalancerClass == nil || *existing.Spec.LoadBalancerClass != nodeLoadBalancerDatapathClass {
		if err := deleteServiceWithUIDPrecondition(ctx, client, existing); err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("node load balancer: replace exact-owned datapath Service with immutable class drift: %w", err)
		}
		return nil, fmt.Errorf("node load balancer: deleted exact-owned datapath Service %s/%s with immutable class drift", service.Namespace, name)
	}
	desired = normalizedDesiredNodeLoadBalancerDatapath(desired, existing)
	if reflect.DeepEqual(existing.Labels, desired.Labels) && reflect.DeepEqual(existing.Annotations, desired.Annotations) &&
		reflect.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) && reflect.DeepEqual(existing.Spec, desired.Spec) {
		return existing, nil
	}
	updated, err := client.Update(ctx, desired, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: update datapath Service: %w", err)
	}
	return updated, nil
}

func normalizedDesiredNodeLoadBalancerDatapath(desired, existing *corev1.Service) *corev1.Service {
	copy := desired.DeepCopy()
	copy.ResourceVersion = existing.ResourceVersion
	copy.Spec.ClusterIP = existing.Spec.ClusterIP
	copy.Spec.ClusterIPs = append([]string(nil), existing.Spec.ClusterIPs...)
	copy.Spec.IPFamilies = append([]corev1.IPFamily(nil), existing.Spec.IPFamilies...)
	copy.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	return copy
}

func nodeLoadBalancerDatapathMatchesDesired(datapath, service *corev1.Service, shard string) bool {
	if datapath == nil || service == nil || datapath.DeletionTimestamp != nil ||
		datapath.Namespace != service.Namespace || datapath.Name != nodeLoadBalancerDatapathName(service) ||
		!nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return false
	}
	desired := normalizedDesiredNodeLoadBalancerDatapath(
		desiredNodeLoadBalancerDatapath(service, datapath.Name, shard),
		datapath,
	)
	return reflect.DeepEqual(datapath.Labels, desired.Labels) &&
		reflect.DeepEqual(datapath.Annotations, desired.Annotations) &&
		reflect.DeepEqual(datapath.OwnerReferences, desired.OwnerReferences) &&
		reflect.DeepEqual(datapath.Spec, desired.Spec)
}

func deleteServiceWithUIDPrecondition(
	ctx context.Context,
	client corev1client.ServiceInterface,
	service *corev1.Service,
) error {
	if service == nil || service.UID == "" {
		return errors.New("node load balancer: generated Service UID is required for deletion")
	}
	uid := service.UID
	return client.Delete(ctx, service.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	})
}

func (c *nodeLoadBalancerController) quarantineInvalidService(ctx context.Context, service *corev1.Service) error {
	if err := c.withdrawServiceDatapath(ctx, service); err != nil {
		return err
	}
	withdrawn, err := c.serviceDatapathWithdrawn(ctx, service)
	if err != nil {
		return err
	}
	if !withdrawn {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	if err := c.deleteOwnedDatapathService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedDatapathServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	if waiting, completed, err := c.resumeOwnedServiceFirewallDelete(ctx, service); err != nil || waiting {
		if waiting {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
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
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
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
	pendingIssued := service.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	pendingIssuedAt := service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt]
	if pendingName == "" {
		if pendingUUID != "" || service.Annotations[annotationNodeLoadBalancerPendingFWStarted] != "" ||
			pendingIssued != "" || pendingIssuedAt != "" ||
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
	if (pendingIssued == "") != (pendingIssuedAt == "") {
		return false, errors.New("node load balancer: incomplete pending firewall create-issued fence during teardown")
	}
	if pendingIssued != "" {
		if err := validateNodeLoadBalancerFirewallCreateIssued(pendingIssued, pendingIssuedAt); err != nil {
			return false, err
		}
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
	if pending != nil && (pendingUUID == "" || pendingIssued != "") {
		return c.ensurePendingFirewallMetadata(ctx, service, pending.UUID, pendingName)
	}
	if pending == nil && pendingIssued != "" {
		return false, fmt.Errorf(
			"node load balancer: Service firewall create attempt %s issued at %s remains ambiguous during teardown; retaining the Service finalizer until deterministic-name adoption or operator resolution",
			pendingIssued,
			pendingIssuedAt,
		)
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWDelete] != "true" ||
		(pending != nil && (service.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" ||
			service.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "")) {
		return c.ensurePendingFirewallDeletionMetadata(ctx, service)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) invalidServiceIsQuarantined(ctx context.Context, service *corev1.Service) (bool, error) {
	absent, err := c.ownedDatapathServiceAbsent(ctx, service)
	if err != nil {
		return false, err
	}
	if !absent {
		return false, nil
	}
	current, err := c.getExactParentService(ctx, service)
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
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, key := range []string{
			annotationNodeLoadBalancerFirewallUUID,
			annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
			annotationNodeLoadBalancerPreviousFirewall,
			annotationNodeLoadBalancerFirewallRelationIssued,
		} {
			if _, exists := copy.Annotations[key]; exists {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: clear invalid Service firewall metadata: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) deleteOwnedDatapathService(ctx context.Context, service *corev1.Service) error {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	name := nodeLoadBalancerDatapathName(service)
	datapath, err := client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get datapath Service %s/%s before delete: %w", service.Namespace, name, err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return fmt.Errorf("node load balancer: refusing to delete datapath Service %s/%s without exact owner identity", service.Namespace, name)
	}
	if err := deleteServiceWithUIDPrecondition(ctx, client, datapath); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: delete datapath Service %s/%s: %w", service.Namespace, name, err)
	}
	return nil
}

func nodeLoadBalancerGeneratedServiceOwnedByService(generated, service *corev1.Service, ownershipLabel string) bool {
	if generated == nil || service == nil || service.UID == "" || generated.Namespace != service.Namespace ||
		generated.Labels[ownershipLabel] != "true" || len(generated.OwnerReferences) != 1 {
		return false
	}
	reference := generated.OwnerReferences[0]
	return reference.APIVersion == "v1" && reference.Kind == "Service" && reference.UID == service.UID &&
		reference.Name == service.Name && reference.Controller != nil && *reference.Controller &&
		reference.BlockOwnerDeletion != nil && *reference.BlockOwnerDeletion
}

func nodeLoadBalancerDatapathOwnedByService(datapath, service *corev1.Service) bool {
	return nodeLoadBalancerGeneratedServiceOwnedByService(datapath, service, nodeLoadBalancerDatapathLabel) &&
		datapath.Labels[nodeLoadBalancerServiceIdentityLabel] == nodeLoadBalancerServiceIdentity(service)
}

func (c *nodeLoadBalancerController) ownedDatapathServiceAbsent(ctx context.Context, service *corev1.Service) (bool, error) {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	name := nodeLoadBalancerDatapathName(service)
	datapath, err := client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: prove datapath Service %s/%s absence: %w", service.Namespace, name, err)
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return false, fmt.Errorf("node load balancer: datapath Service name %s/%s is occupied by another owner", service.Namespace, name)
	}
	return false, nil
}

func (c *nodeLoadBalancerController) clearServiceLoadBalancerStatus(ctx context.Context, service *corev1.Service) error {
	_, _, err := c.updateExactParentStatus(ctx, service, corev1.LoadBalancerStatus{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: clear Service load balancer status: %w", err)
	}
	return nil
}

func desiredNodeLoadBalancerDatapath(service *corev1.Service, name, shard string) *corev1.Service {
	datapathClass := nodeLoadBalancerDatapathClass
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
				nodeLoadBalancerDatapathLabel: "true", nodeLoadBalancerServiceIdentityLabel: nodeLoadBalancerServiceIdentity(service),
			},
			Annotations: map[string]string{
				annotationNodeLoadBalancerDatapathShard: shard,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, LoadBalancerClass: &datapathClass,
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

func (c *nodeLoadBalancerController) getExactParentService(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, error) {
	if service == nil || service.UID == "" {
		return nil, errors.New("node load balancer: parent Service UID is required")
	}
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if current.UID != service.UID {
		return nil, fmt.Errorf(
			"node load balancer: parent Service %s/%s identity changed from UID %s to %s",
			service.Namespace, service.Name, service.UID, current.UID,
		)
	}
	return current, nil
}

func (c *nodeLoadBalancerController) validatePlannedDatapathContract(
	service, datapath *corev1.Service,
	shard string,
	expected nodeLoadBalancerIntent,
	requireAuthorization bool,
) error {
	if service == nil || service.DeletionTimestamp != nil || !isNodeLoadBalancerService(service) {
		return errors.New("node load balancer: parent Service is deleting or no longer requests the NodeLB class")
	}
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	currentIntent, err := parseNodeLoadBalancerService(service, defaults)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentIntent, expected) {
		return fmt.Errorf("node load balancer: parent Service intent changed while reconciling shard %s", shard)
	}
	if currentIntent.ExistingShard != shard && service.Annotations[annotationNodeLoadBalancerPreviousShard] != shard {
		return fmt.Errorf("node load balancer: parent Service records shard %q, not %q", currentIntent.ExistingShard, shard)
	}
	activeShard := service.Annotations[annotationNodeLoadBalancerDatapathActive]
	if requireAuthorization {
		if activeShard != shard {
			return fmt.Errorf("node load balancer: parent Service has no activation authorization for shard %s", shard)
		}
	} else if activeShard != "" && activeShard != shard {
		return fmt.Errorf("node load balancer: parent Service authorizes shard %s, not %s", activeShard, shard)
	}
	if !nodeLoadBalancerDatapathMatchesDesired(datapath, service, shard) {
		return fmt.Errorf("node load balancer: datapath is terminating, foreign, or drifted for shard %s", shard)
	}
	return nil
}

// updateExactParentService performs controller-owned metadata mutations only
// after a live UID check. The resourceVersion from that live read lets the API
// server reject a same-name replacement racing the update.
func (c *nodeLoadBalancerController) updateExactParentService(
	ctx context.Context,
	service *corev1.Service,
	mutate func(*corev1.Service) (bool, error),
) (*corev1.Service, bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, false, err
	}
	copy := current.DeepCopy()
	if mutate == nil {
		return current, false, nil
	}
	changed, err := mutate(copy)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return current, false, nil
	}
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, err
	}
	if updated.UID != service.UID {
		return nil, false, fmt.Errorf(
			"node load balancer: parent Service %s/%s identity changed during metadata update",
			service.Namespace, service.Name,
		)
	}
	if !mapsEqualStringString(updated.Annotations, copy.Annotations) ||
		!slices.Equal(updated.Finalizers, copy.Finalizers) {
		return nil, false, fmt.Errorf(
			"node load balancer: parent Service %s/%s metadata update did not retain the exact controller receipt",
			service.Namespace, service.Name,
		)
	}
	verified, err := c.getExactParentService(ctx, updated)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: read back parent Service metadata update: %w", err)
	}
	if !mapsEqualStringString(verified.Annotations, copy.Annotations) ||
		!slices.Equal(verified.Finalizers, copy.Finalizers) {
		return nil, false, fmt.Errorf(
			"node load balancer: parent Service %s/%s did not store the exact controller receipt",
			service.Namespace, service.Name,
		)
	}
	return verified, true, nil
}

func (c *nodeLoadBalancerController) updateExactParentStatus(
	ctx context.Context,
	service *corev1.Service,
	status corev1.LoadBalancerStatus,
) (*corev1.Service, bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, false, err
	}
	if reflect.DeepEqual(current.Status.LoadBalancer, status) {
		return current, false, nil
	}
	copy := current.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, err
	}
	if updated.UID != service.UID {
		return nil, false, fmt.Errorf(
			"node load balancer: parent Service %s/%s identity changed during status update",
			service.Namespace, service.Name,
		)
	}
	return updated, true, nil
}

func (c *nodeLoadBalancerController) datapathServiceUsesShard(ctx context.Context, service *corev1.Service, shard string) (bool, error) {
	_, activeShard, found, err := c.activeDatapathService(ctx, service)
	return found && activeShard == shard, err
}

func (c *nodeLoadBalancerController) readyShardAddresses(ctx context.Context, shard string) ([]nodeLoadBalancerAddress, error) {
	authorized, err := c.authorizedNodesForShard(ctx, shard)
	if err != nil {
		return nil, err
	}
	addresses := make([]nodeLoadBalancerAddress, 0, len(authorized))
	seenPrivate := map[string]struct{}{}
	seenPublic := map[string]struct{}{}
	for _, node := range authorized {
		if node.Labels[nodeLoadBalancerReadyLabel] != "true" || !nodeLoadBalancerNodeHealthy(node) {
			continue
		}
		privateIP, privateOK := nodeLoadBalancerNodeInternalIPv4(node)
		publicIP, publicOK := nodeLoadBalancerNodeExternalIPv4(node)
		if !privateOK || !publicOK {
			continue
		}
		if _, duplicate := seenPrivate[privateIP]; duplicate {
			return nil, fmt.Errorf("node load balancer: shard %s has duplicate private IPv4 %s", shard, privateIP)
		}
		if _, duplicate := seenPublic[publicIP]; duplicate {
			return nil, fmt.Errorf("node load balancer: shard %s has duplicate public IPv4 %s", shard, publicIP)
		}
		seenPrivate[privateIP] = struct{}{}
		seenPublic[publicIP] = struct{}{}
		addresses = append(addresses, nodeLoadBalancerAddress{Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP})
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Node.Name < addresses[j].Node.Name })
	return addresses, nil
}

func nodeLoadBalancerStatus(addresses []nodeLoadBalancerAddress, public bool) corev1.LoadBalancerStatus {
	mode := corev1.LoadBalancerIPModeVIP
	if public {
		mode = corev1.LoadBalancerIPModeProxy
	}
	status := corev1.LoadBalancerStatus{}
	for _, address := range addresses {
		ip := address.PrivateIPv4
		if public {
			ip = address.PublicIPv4
		}
		status.Ingress = append(status.Ingress, corev1.LoadBalancerIngress{IP: ip, IPMode: &mode})
	}
	return status
}

func (c *nodeLoadBalancerController) publishDatapathStatus(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	expected nodeLoadBalancerIntent,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	client := c.provider.kubeClient.CoreV1().Services(current.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("node load balancer: datapath Service %s/%s disappeared before private VIP publication", current.Namespace, nodeLoadBalancerDatapathName(current))
	}
	if err != nil {
		return nil, fmt.Errorf("node load balancer: get datapath Service status: %w", err)
	}
	if err := c.validatePlannedDatapathContract(current, datapath, shard, expected, true); err != nil {
		return nil, fmt.Errorf("node load balancer: refuse private VIP publication: %w", err)
	}
	desired := nodeLoadBalancerStatus(addresses, false)
	if !reflect.DeepEqual(datapath.Status.LoadBalancer, desired) {
		copy := datapath.DeepCopy()
		copy.Status.LoadBalancer = desired
		updated, updateErr := client.UpdateStatus(ctx, copy, metav1.UpdateOptions{})
		if updateErr != nil {
			return nil, fmt.Errorf("node load balancer: publish private VIP datapath status: %w", updateErr)
		}
		if updated.UID != datapath.UID {
			return nil, fmt.Errorf("node load balancer: datapath Service identity changed during private VIP publication")
		}
	}
	verifiedParent, err := c.getExactParentService(ctx, current)
	if err != nil {
		return nil, err
	}
	verifiedDatapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(verifiedParent), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: read back datapath after private VIP publication: %w", err)
	}
	if err := c.validatePlannedDatapathContract(verifiedParent, verifiedDatapath, shard, expected, true); err != nil {
		return nil, fmt.Errorf("node load balancer: private VIP publication lost its parent contract: %w", err)
	}
	if !reflect.DeepEqual(verifiedDatapath.Status.LoadBalancer, desired) {
		return nil, fmt.Errorf("node load balancer: private VIP publication did not read back exactly")
	}
	return verifiedParent, nil
}

func (c *nodeLoadBalancerController) publishPublicProxyStatus(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	expected nodeLoadBalancerIntent,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	client := c.provider.kubeClient.CoreV1().Services(current.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: inspect datapath before public Proxy publication: %w", err)
	}
	if err := c.validatePlannedDatapathContract(current, datapath, shard, expected, true); err != nil {
		return nil, fmt.Errorf("node load balancer: refuse public Proxy publication: %w", err)
	}
	desired := nodeLoadBalancerStatus(addresses, true)
	if !reflect.DeepEqual(current.Status.LoadBalancer, desired) {
		copy := current.DeepCopy()
		copy.Status.LoadBalancer = desired
		updated, updateErr := client.UpdateStatus(ctx, copy, metav1.UpdateOptions{})
		if updateErr != nil {
			return nil, fmt.Errorf("node load balancer: publish public Proxy status: %w", updateErr)
		}
		if updated.UID != service.UID {
			return nil, fmt.Errorf("node load balancer: parent Service identity changed during public Proxy publication")
		}
		current = updated
	}
	verified, err := c.getExactParentService(ctx, current)
	if err != nil {
		return nil, err
	}
	datapath, err = client.Get(ctx, nodeLoadBalancerDatapathName(verified), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: read back datapath after public Proxy publication: %w", err)
	}
	if err := c.validatePlannedDatapathContract(verified, datapath, shard, expected, true); err != nil {
		return nil, fmt.Errorf("node load balancer: public Proxy publication lost its parent contract: %w", err)
	}
	if !reflect.DeepEqual(verified.Status.LoadBalancer, desired) {
		return nil, fmt.Errorf("node load balancer: public Proxy publication did not read back exactly")
	}
	return verified, nil
}

func (c *nodeLoadBalancerController) datapathStatusesMatch(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	addresses []nodeLoadBalancerAddress,
) (bool, error) {
	privateMatches, err := c.datapathStatusMatches(ctx, service, shard, addresses)
	if err != nil || !privateMatches {
		return privateMatches, err
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, fmt.Errorf("node load balancer: verify public Service status: %w", err)
	}
	return reflect.DeepEqual(current.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, true)), nil
}

func (c *nodeLoadBalancerController) datapathStatusMatches(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	addresses []nodeLoadBalancerAddress,
) (bool, error) {
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("node load balancer: verify datapath Service status: %w", err)
	}
	if !nodeLoadBalancerDatapathMatchesDesired(datapath, service, shard) {
		return false, nil
	}
	return reflect.DeepEqual(datapath.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, false)), nil
}

func (c *nodeLoadBalancerController) authorizeDatapath(
	ctx context.Context,
	service *corev1.Service,
	shard string,
	expected nodeLoadBalancerIntent,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx,
		nodeLoadBalancerDatapathName(current),
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("node load balancer: inspect datapath before activation authorization: %w", err)
	}
	if err := c.validatePlannedDatapathContract(current, datapath, shard, expected, false); err != nil {
		return nil, fmt.Errorf("node load balancer: refuse datapath activation authorization: %w", err)
	}
	activeShard := current.Annotations[annotationNodeLoadBalancerDatapathActive]
	if activeShard == "" && len(datapath.Status.LoadBalancer.Ingress) != 0 {
		return nil, fmt.Errorf("node load balancer: refusing to authorize shard %s after an unmarked private VIP was published", shard)
	}
	updated, _, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if err := c.validatePlannedDatapathContract(copy, datapath, shard, expected, false); err != nil {
			return false, err
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if copy.Annotations[annotationNodeLoadBalancerDatapathActive] == shard {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerDatapathActive] = shard
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: persist datapath activation authorization: %w", err)
	}
	verified, err := c.getExactParentService(ctx, updated)
	if err != nil {
		return nil, err
	}
	if verified.Annotations[annotationNodeLoadBalancerDatapathActive] != shard {
		return nil, fmt.Errorf("node load balancer: datapath activation authorization for shard %s was not stored exactly", shard)
	}
	datapath, err = c.provider.kubeClient.CoreV1().Services(verified.Namespace).Get(
		ctx,
		nodeLoadBalancerDatapathName(verified),
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("node load balancer: re-read datapath after activation authorization: %w", err)
	}
	if err := c.validatePlannedDatapathContract(verified, datapath, shard, expected, true); err != nil {
		return nil, fmt.Errorf("node load balancer: datapath changed while authorizing shard %s: %w", shard, err)
	}
	return verified, nil
}

func (c *nodeLoadBalancerController) clearDatapathActivation(ctx context.Context, service *corev1.Service) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, key := range []string{
			annotationNodeLoadBalancerDatapathActive,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
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
	if err != nil {
		return fmt.Errorf("node load balancer: clear active datapath marker: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) clearServiceFirewallWithdrawalEvidenceAfterAssignment(
	ctx context.Context,
	service *corev1.Service,
	firewallUUID string,
	nodes []*corev1.Node,
) (bool, error) {
	if firewallUUID == "" || len(nodes) == 0 {
		return false, errors.New("node load balancer: firewall UUID and assigned Nodes are required before clearing withdrawal evidence")
	}
	provedPairs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok || !nodeLoadBalancerNodeHealthy(node) {
			return false, fmt.Errorf("node load balancer: Node %s is not eligible withdrawal recovery proof", node.Name)
		}
		pair := firewallUUID + "/" + vmUUID
		if _, duplicate := provedPairs[pair]; duplicate {
			return false, fmt.Errorf("node load balancer: duplicate withdrawal recovery assignment %s", pair)
		}
		provedPairs[pair] = struct{}{}
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service changed before withdrawal evidence reset")
		}
		if copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
			!isManagedNodeLoadBalancerShardName(copy.Annotations[annotationNodeLoadBalancerDatapathActive]) {
			return false, errors.New("node load balancer: positive firewall assignment readback lost its active Service identity")
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
			return false, errors.New("node load balancer: incomplete firewall withdrawal detach fence during recovery")
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
		for _, pair := range strings.Split(storedSet, ",") {
			if detachedAt[pair] == "" {
				return false, fmt.Errorf("node load balancer: firewall withdrawal detach set has no timestamp for %s", pair)
			}
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
				return false, fmt.Errorf("node load balancer: encode retained firewall withdrawal detach timestamps: %w", marshalErr)
			}
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = nodeLoadBalancerFirewallDetachSetFromTimes(detachedAt)
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(encodedTimes)
		}
		return changed, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: clear withdrawal evidence after exact firewall assignment readback: %w", err)
	}
	return changed, nil
}

func (c *nodeLoadBalancerController) rawNodesForShard(ctx context.Context, shard string) ([]*corev1.Node, error) {
	selector := labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   shard,
	}).String()
	list, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list live Nodes for shard %s: %w", shard, err)
	}
	result := make([]*corev1.Node, 0, len(list.Items))
	for index := range list.Items {
		result = append(result, &list.Items[index])
	}
	return result, nil
}

func (c *nodeLoadBalancerController) rawNodesForCluster(ctx context.Context) ([]*corev1.Node, error) {
	selector := labels.SelectorFromSet(labels.Set{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
	}).String()
	list, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list live cluster Nodes: %w", err)
	}
	result := make([]*corev1.Node, 0, len(list.Items))
	for index := range list.Items {
		result = append(result, &list.Items[index])
	}
	return result, nil
}

// authorizedNodesForShard returns only Nodes whose kubelet-visible labels and
// provider ID are backed by Karpenter's API-owned identity chain. Callers that
// attach public firewalls or publish addresses must use this helper, never the
// raw label selector.
func (c *nodeLoadBalancerController) authorizedNodesForShard(ctx context.Context, shard string) ([]*corev1.Node, error) {
	raw, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return nil, err
	}
	return c.authorizedNodeLoadBalancerNodes(ctx, raw, shard)
}

// authorizedNodesForCluster is the cluster-wide equivalent used for shared
// infrastructure that is attached to every managed Node load balancer VM.
func (c *nodeLoadBalancerController) authorizedNodesForCluster(ctx context.Context) ([]*corev1.Node, error) {
	raw, err := c.rawNodesForCluster(ctx)
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
	baseFirewallUUID, err := c.trustedNodeLoadBalancerBaseFirewall(ctx, nodeClass)
	if err != nil {
		return nil, fmt.Errorf("node load balancer: validate generated NodeClass security base: %w", err)
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
		authoritative := pool != nil && c.nodeLoadBalancerNodePoolAuthoritative(pool, shard, nodeClassName)
		if !authoritative {
			klog.InfoS("Ignoring Node without an authoritative Node load balancer NodePool", "node", current.Name, "shard", shard)
			continue
		}
		claim, reason := c.uniqueAuthoritativeNodeClaim(current, pool, nodeClassName, claims.Items)
		if claim == nil {
			klog.InfoS("Ignoring Node without an authoritative NodeClaim identity chain", "node", current.Name, "shard", shard, "reason", reason)
			continue
		}
		vmIdentity, vmReason, vmErr := c.managedNodeLoadBalancerVMIdentityAuthoritative(
			ctx, current, pool, claim, nodeClass, baseFirewallUUID,
		)
		if vmErr != nil {
			return nil, vmErr
		}
		if vmIdentity == nil {
			klog.InfoS("Ignoring Node without authoritative managed VM ownership", "node", current.Name, "shard", shard, "reason", vmReason)
			continue
		}
		fipAuthorized, fipReason, fipErr := c.nodeLoadBalancerFloatingIPAuthoritative(ctx, current, *vmIdentity)
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

func (c *nodeLoadBalancerController) managedNodeLoadBalancerVMIdentityAuthoritative(
	ctx context.Context,
	node *corev1.Node,
	pool, claim, nodeClass *unstructured.Unstructured,
	baseFirewallUUID string,
) (*managedNodeLoadBalancerVMIdentity, string, error) {
	identity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || identity.Location != c.provider.config.Location || identity.String() != node.Spec.ProviderID {
		return nil, "Node providerID is invalid or non-canonical", nil
	}
	vm, err := c.provider.api.GetVM(ctx, identity.Location, identity.UUID)
	if err != nil {
		return nil, "", fmt.Errorf("node load balancer: read canonical VM %s for Node %s: %w", identity.UUID, node.Name, err)
	}
	if vm == nil || vm.UUID != identity.UUID {
		return nil, "canonical VM UUID does not exactly match the Node providerID", nil
	}
	if vm.BillingAccountID != c.provider.config.BillingAccountID {
		return nil, "canonical VM billing account does not match the configured account", nil
	}
	// The VM detail endpoint may omit this redundant field. A non-empty value is
	// contradictory unless it matches; authoritative attachment is always proved
	// below from the exact VPC object and its unique VM membership.
	if vm.NetworkUUID != "" && vm.NetworkUUID != c.provider.config.NetworkUUID {
		return nil, "canonical VM network does not match the configured VPC", nil
	}
	network, err := c.provider.api.GetNetwork(ctx, identity.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return nil, "", fmt.Errorf("node load balancer: read canonical VPC membership for Node %s: %w", node.Name, err)
	}
	if network == nil || network.UUID != c.provider.config.NetworkUUID {
		return nil, "canonical VPC UUID does not exactly match the configured VPC", nil
	}
	memberships := 0
	exactMembership := false
	for _, vmUUID := range network.VMUUIDs {
		if strings.EqualFold(vmUUID, identity.UUID) {
			memberships++
			exactMembership = exactMembership || vmUUID == identity.UUID
		}
	}
	if memberships != 1 || !exactMembership {
		return nil, fmt.Sprintf("expected exactly one canonical VPC membership, found %d", memberships), nil
	}
	if err := c.auditManagedNodeLoadBalancerBaseFirewall(
		ctx,
		identity.UUID,
		baseFirewallUUID,
		network.Subnet,
	); err != nil {
		return nil, "", fmt.Errorf("node load balancer: audit managed VM base firewall authority: %w", err)
	}

	if pool == nil || claim == nil || nodeClass == nil || !validNodeLoadBalancerCloudUUID(baseFirewallUUID) {
		return nil, "managed Kubernetes ownership chain is incomplete", nil
	}
	var ownership publicNodeLocalVMOwnership
	if vm.Description == "" || json.Unmarshal([]byte(vm.Description), &ownership) != nil {
		return nil, "canonical VM has no decodable Karpenter ownership record", nil
	}
	shard := pool.GetName()
	if ownership.Schema != "karpenter.inspace.cloud/v3" ||
		ownership.Cluster != c.provider.config.ClusterID ||
		ownership.NodePool != shard || ownership.NodeClaim != claim.GetName() ||
		ownership.VMName == "" || ownership.VMName != vm.Name || ownership.VMName != node.Name ||
		ownership.FirewallProfile != nodeLoadBalancerFirewallMode || ownership.FirewallUUID != baseFirewallUUID ||
		ownership.NetworkUUID != c.provider.config.NetworkUUID || ownership.BillingAccountID != c.provider.config.BillingAccountID {
		return nil, "Karpenter v3 VM ownership record does not match the managed Node chain", nil
	}
	classFirewallUUID, found, fieldErr := unstructured.NestedString(nodeClass.Object, "spec", "firewallUUID")
	if fieldErr != nil || !found || classFirewallUUID != baseFirewallUUID {
		return nil, "managed NodeClass no longer references the trusted base firewall", nil
	}

	expectedFloatingIPName := managedNodeLoadBalancerFloatingIPName(c.provider.config.ClusterID, claim.GetName())
	annotations := claim.GetAnnotations()
	publicIPv4 := annotations[karpenterPublicIPv4Annotation]
	parsedPublicIPv4, parseErr := netip.ParseAddr(publicIPv4)
	if parseErr != nil || !parsedPublicIPv4.Is4() || !parsedPublicIPv4.IsGlobalUnicast() || parsedPublicIPv4.IsPrivate() || parsedPublicIPv4.String() != publicIPv4 {
		return nil, "NodeClaim has no canonical public IPv4 launch identity", nil
	}
	if ownership.FloatingIPName != expectedFloatingIPName ||
		annotations[karpenterFloatingIPNameAnnotation] != expectedFloatingIPName ||
		annotations[karpenterBillingAccountAnnotation] != strconv.FormatInt(c.provider.config.BillingAccountID, 10) ||
		annotations[karpenterNodeNameAnnotation] != node.Name ||
		(ownership.PublicIPv4 != "" && ownership.PublicIPv4 != publicIPv4) {
		return nil, "durable VM/NodeClaim floating-IP identity does not match the deterministic launch identity", nil
	}
	return &managedNodeLoadBalancerVMIdentity{
		VMUUID: identity.UUID, FloatingIPName: expectedFloatingIPName, PublicIPv4: publicIPv4,
	}, "", nil
}

func managedNodeLoadBalancerFloatingIPName(clusterName, nodeClaimName string) string {
	base := sanitizeManagedNodeLoadBalancerName(nodeClaimName)
	if !strings.HasPrefix(base, "inspace-e2e-") {
		base = "karpenter-" + base
	}
	suffix := nodeLoadBalancerHash(clusterName + "\x00" + nodeClaimName)[:10]
	const maxBase = 63 - 1 - 10
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + "-" + suffix
}

func sanitizeManagedNodeLoadBalancerName(value string) string {
	var result strings.Builder
	for _, character := range strings.ToLower(value) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			result.WriteRune(character)
		} else {
			result.WriteByte('-')
		}
	}
	return strings.Trim(result.String(), "-")
}

func (c *nodeLoadBalancerController) nodeLoadBalancerFloatingIPAuthoritative(
	ctx context.Context,
	node *corev1.Node,
	durable managedNodeLoadBalancerVMIdentity,
) (bool, string, error) {
	identity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || identity.Location != c.provider.config.Location || identity.String() != node.Spec.ProviderID || identity.UUID != durable.VMUUID {
		return false, "Node providerID is invalid or non-canonical", nil
	}
	internalIP, ok := nodeLoadBalancerNodeInternalIPv4(node)
	if !ok {
		return false, "Node has no canonical private InternalIP", nil
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
		if strings.EqualFold(item.AssignedTo, identity.UUID) && item.Enabled && !item.IsDeleted {
			assigned = append(assigned, item)
		}
	}
	if len(assigned) != 1 {
		return false, fmt.Sprintf("expected one floating IP assigned to VM %s, found %d", identity.UUID, len(assigned)), nil
	}
	item := assigned[0]
	if item.Name != durable.FloatingIPName || item.Address != durable.PublicIPv4 || item.AssignedTo != identity.UUID ||
		item.BillingAccountID != c.provider.config.BillingAccountID || !item.Enabled || item.IsDeleted || item.IsVirtual ||
		item.Type != "public" || item.AssignedToResourceType != "virtual_machine" {
		return false, "floating IP does not match the exact durable Karpenter launch identity", nil
	}
	if item.AssignedToPrivateIP != internalIP {
		return false, "floating IP DNAT private IPv4 does not match the Node InternalIP", nil
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
	if !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
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
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.serviceFirewallRelationOwner(service),
		nil,
	)
	if err != nil {
		return err
	}
	if !converged {
		return errors.New("node load balancer: waiting for durable Service firewall relation readback")
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
	for _, vmUUID := range staleVMs {
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.serviceFirewallRelationOwner(service),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if relationErr != nil {
			return fmt.Errorf("node load balancer: unassign firewall %s from stale VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		if !converged {
			// The exact relation was removed and authoritatively read back, but a
			// later pass must consume a fresh firewall snapshot before publication.
			return nil
		}
	}
	return nil
}

func staleNodeLoadBalancerFirewallAssignments(firewall inspace.Firewall, desiredVMs map[string]struct{}) ([]string, error) {
	stale := make([]string, 0)
	assignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
	if err != nil {
		return nil, err
	}
	for vmUUID := range assignments {
		if _, desired := desiredVMs[vmUUID]; !desired {
			stale = append(stale, vmUUID)
		}
	}
	sort.Strings(stale)
	return stale, nil
}

func (c *nodeLoadBalancerController) reconcileShardNodeEligibility(ctx context.Context, shard string) error {
	rawNodes, err := c.rawNodesForShard(ctx, shard)
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
	shardInUse := false
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
		if current {
			shardInUse = true
			break
		}
		active, activeErr := c.datapathServiceUsesShard(ctx, service, shard)
		if activeErr != nil {
			return errors.Join(activeErr, c.setShardNodesReady(ctx, rawNodes, nil))
		}
		if previous && active {
			shardInUse = true
			break
		}
	}
	if !shardInUse {
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
	ready := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		eligible := ok && nodeLoadBalancerNodeHealthy(node) && firewallAssignedToVM(*icmpFirewall, vmUUID)
		ready[node.Name] = eligible
	}
	return c.setShardNodesReady(ctx, rawNodes, ready)
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
	_, internalOK := nodeLoadBalancerNodeInternalIPv4(node)
	_, externalOK := nodeLoadBalancerNodeExternalIPv4(node)
	return internalOK && externalOK
}

func nodeLoadBalancerNodeInternalIPv4(node *corev1.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	result := ""
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || !parsed.IsPrivate() || parsed.String() != address.Address {
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
			shard := current.Labels[nodeLoadBalancerNodeShardLabel]
			authorized, authorizationErr := c.authorizedNodeLoadBalancerNodes(ctx, []*corev1.Node{current}, shard)
			if authorizationErr != nil {
				return authorizationErr
			}
			want = len(authorized) == 1 && authorized[0].Name == current.Name && authorized[0].Spec.ProviderID == current.Spec.ProviderID
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
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	if waiting, completed, resumeErr := c.resumeOwnedServiceFirewallDelete(ctx, current); resumeErr != nil || waiting {
		if waiting {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
		}
		return resumeErr
	} else if completed {
		current, err = c.getExactParentService(ctx, current)
		if err != nil {
			return err
		}
	}
	currentUUID := current.Annotations[annotationNodeLoadBalancerFirewallUUID]
	previousUUID := current.Annotations[annotationNodeLoadBalancerPreviousFirewall]
	owned, err := c.ownedServiceFirewalls(ctx, current)
	if err != nil {
		return err
	}
	for _, firewall := range owned {
		if firewall.UUID == currentUUID {
			continue
		}
		latest, latestErr := c.getExactParentService(ctx, current)
		if latestErr != nil {
			return latestErr
		}
		if firewall.UUID == latest.Annotations[annotationNodeLoadBalancerFirewallUUID] ||
			firewall.UUID == latest.Annotations[annotationNodeLoadBalancerPendingFirewall] {
			continue
		}
		done, deleteErr := c.deleteOwnedServiceFirewall(ctx, latest, firewall.UUID)
		if deleteErr != nil {
			return deleteErr
		}
		if !done {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		}
	}
	if previousUUID == "" {
		return nil
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPreviousFirewall] != previousUUID {
			return false, errors.New("node load balancer: previous firewall identity changed during cleanup")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerPreviousFirewall)
		return true, nil
	})
	return err
}

func (c *nodeLoadBalancerController) cleanupPreviousShard(ctx context.Context, service *corev1.Service) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	previous := current.Annotations[annotationNodeLoadBalancerPreviousShard]
	if previous == "" {
		return nil
	}
	if previous == current.Annotations[annotationNodeLoadBalancerShard] {
		_, _, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerPreviousShard] != previous ||
				copy.Annotations[annotationNodeLoadBalancerShard] != previous {
				return false, errors.New("node load balancer: duplicate previous shard identity changed before metadata clear")
			}
			delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
			return true, nil
		})
		return err
	}
	remaining, err := c.servicesForShard(ctx, current, previous)
	if err != nil {
		return err
	}
	if len(remaining) == 0 {
		nodes, err := c.rawNodesForShard(ctx, previous)
		if err != nil {
			return err
		}
		if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
			return err
		}
		latest, latestErr := c.getExactParentService(ctx, current)
		if latestErr != nil {
			return latestErr
		}
		if latest.Annotations[annotationNodeLoadBalancerPreviousShard] != previous ||
			latest.Annotations[annotationNodeLoadBalancerShard] == previous ||
			latest.Annotations[annotationNodeLoadBalancerDatapathActive] == previous {
			return errors.New("node load balancer: previous shard identity changed during cleanup")
		}
		if err := c.deleteManagedNodePool(ctx, previous); err != nil {
			return err
		}
		if _, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, previous, metav1.GetOptions{}); err == nil {
			c.queue.AddAfter(current.Namespace+"/"+current.Name, nodeLoadBalancerRetry)
			return nil
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerPreviousShard] != previous {
			return false, errors.New("node load balancer: previous shard identity changed before metadata clear")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerPreviousShard)
		return true, nil
	})
	return err
}

func (c *nodeLoadBalancerController) cleanupService(ctx context.Context, service *corev1.Service) error {
	if err := c.withdrawServiceDatapath(ctx, service); err != nil {
		return err
	}
	withdrawn, err := c.serviceDatapathWithdrawn(ctx, service)
	if err != nil {
		return err
	}
	if !withdrawn {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	if err := c.deleteOwnedDatapathService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedDatapathServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		return nil
	}
	if waiting, completed, err := c.resumeOwnedServiceFirewallDelete(ctx, service); err != nil || waiting {
		if waiting {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
		}
		return err
	} else if completed {
		service, err = c.getExactParentService(ctx, service)
		if err != nil {
			return err
		}
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
	service, err = c.getExactParentService(ctx, service)
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
		service.Annotations[annotationNodeLoadBalancerDatapathActive],
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
		// Legacy per-Service reconciler compatibility: releases before the
		// aggregate design never created a cluster NodeClass/ICMP anchor. The
		// active aggregate sync uses cleanupAggregateClusterState and never takes
		// this unanchored path.
		done := false
		if _, getErr := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{}); apierrors.IsNotFound(getErr) {
			done = true
		} else if getErr != nil {
			return getErr
		} else {
			done, err = c.cleanupClusterICMPFirewall(ctx, nodeClassName)
		}
		if err != nil {
			return err
		}
		if !done {
			c.queue.AddAfter(service.Namespace+"/"+service.Name, nodeLoadBalancerRetry)
			return nil
		}
	}

	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp == nil && isNodeLoadBalancerService(copy) {
			return false, errors.New("node load balancer: parent Service became active again before finalization")
		}
		if len(copy.Status.LoadBalancer.Ingress) != 0 || copy.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
			return false, errors.New("node load balancer: refusing finalization while the datapath remains advertised")
		}
		if copy.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWName] != "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWStarted] != "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" ||
			copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != "" {
			return false, errors.New("node load balancer: refusing finalization while firewall creation remains pending")
		}
		if copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != "" ||
			copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" {
			return false, errors.New("node load balancer: refusing finalization while firewall deletion remains fenced")
		}
		if copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] != "" ||
			copy.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
			return false, errors.New("node load balancer: refusing finalization while firewall assignment remains fenced")
		}
		changed := containsString(copy.Finalizers, nodeLoadBalancerFinalizer)
		copy.Finalizers = removeString(copy.Finalizers, nodeLoadBalancerFinalizer)
		for _, key := range []string{
			annotationNodeLoadBalancerFirewallUUID,
			annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
			annotationNodeLoadBalancerPendingFirewall,
			annotationNodeLoadBalancerPendingFWName,
			annotationNodeLoadBalancerPendingFWStarted,
			annotationNodeLoadBalancerPendingFWIssued,
			annotationNodeLoadBalancerPendingFWIssuedAt,
			annotationNodeLoadBalancerPendingFWDelete,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
			annotationNodeLoadBalancerPreviousFirewall,
			annotationNodeLoadBalancerShard,
			annotationNodeLoadBalancerPreviousShard,
			annotationNodeLoadBalancerDatapathActive,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
			annotationNodeLoadBalancerWithdrawFWDetach,
			annotationNodeLoadBalancerWithdrawFWDetachAt,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
			annotationNodeLoadBalancerFirewallRelationIssued,
			annotationNodeLoadBalancerFWDeleteTarget,
			annotationNodeLoadBalancerFWDeleteIssued,
		} {
			if _, exists := copy.Annotations[key]; exists {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
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
			pool := &pools.Items[i]
			name := pool.GetName()
			if !isManagedNodeLoadBalancerShardName(name) || pool.GetLabels()[nodeLoadBalancerShardLabel] != name {
				return false, fmt.Errorf("node load balancer: refusing cluster cleanup for malformed managed NodePool %q", name)
			}
			if !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
				if pool.GetDeletionTimestamp() != nil {
					return false, fmt.Errorf("node load balancer: deleting orphan NodePool %s lost its shard-state finalizer", name)
				}
				if _, _, err := c.updateManagedNodePoolAnnotations(ctx, name, func(map[string]string) (bool, error) {
					return false, nil
				}); err != nil {
					return false, err
				}
				return true, nil
			}
			nodes, listErr := c.rawNodesForShard(ctx, name)
			if listErr != nil {
				return false, listErr
			}
			if err := c.setShardNodesReady(ctx, nodes, nil); err != nil {
				return false, err
			}
			if err := c.deleteManagedNodePool(ctx, name); err != nil {
				return false, err
			}
			absent, err := c.managedShardCapacityAbsent(ctx, name)
			if err != nil {
				return false, err
			}
			if !absent {
				continue
			}
			firewallAbsent, err := c.deleteAggregateShardFirewall(ctx, name)
			if err != nil {
				return false, err
			}
			if !firewallAbsent {
				continue
			}
			if err := c.resetAggregateShardAfterAnchorDeletion(ctx, name); err != nil {
				return false, err
			}
			if err := c.markAggregateShardCleanupProvenForReferences(ctx, name); err != nil {
				return false, err
			}
			if err := c.removeManagedNodePoolStateFinalizer(ctx, name); err != nil {
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
	if !containsString(nodePool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return fmt.Errorf("node load balancer: refusing to delete NodePool %s without the durable shard-state finalizer", name)
	}
	uid := nodePool.GetUID()
	if uid == "" {
		return fmt.Errorf("node load balancer: refusing to delete NodePool %s without an observed UID", name)
	}
	if nodePool.GetDeletionTimestamp() != nil {
		// Do not repeat an in-flight foreground request, and never re-add its
		// foregroundDeletion finalizer after Kubernetes has drained the owned
		// NodeClaims. Nodes are still checked separately before CCM releases its
		// state finalizer, but they are not direct blockOwnerDeletion dependents
		// whose collection benefits from another NodePool DELETE.
		if containsString(nodePool.GetFinalizers(), metav1.FinalizerDeleteDependents) {
			return nil
		}
		claimsRemain, claimsErr := c.managedShardNodeClaimsRemain(ctx, name)
		if claimsErr != nil {
			return fmt.Errorf("node load balancer: list NodeClaims before foreground NodePool deletion: %w", claimsErr)
		}
		if !claimsRemain {
			return nil
		}
	}
	// The CCM state finalizer deliberately keeps the NodePool as the durable
	// aggregate-firewall anchor until its capacity and cloud policy are gone.
	// Foreground deletion lets Kubernetes delete blockOwnerDeletion NodeClaims
	// while that anchor remains. Background deletion would wait for this finalizer
	// before starting garbage collection, creating a circular wait with
	// managedShardCapacityAbsent.
	propagation := metav1.DeletePropagationForeground
	if err := resource.Delete(ctx, name, metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: &uid},
		PropagationPolicy: &propagation,
	}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: delete NodePool %s: %w", name, err)
	}
	return nil
}

// removeManagedNodePoolStateFinalizer releases the CCM's durable shard-state anchor
// only after deletion has started and every other controller has finished its
// NodePool teardown. Cloud firewall cleanup must be proved separately by the
// caller before invoking this helper.
func (c *nodeLoadBalancerController) removeManagedNodePoolStateFinalizer(ctx context.Context, name string) error {
	if !isManagedNodeLoadBalancerShardName(name) {
		return fmt.Errorf("node load balancer: refusing to finalize invalid managed NodePool name %q", name)
	}
	resource := c.provider.dynamicClient.Resource(nodePoolGVR)
	nodePool, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get NodePool %s before finalizer removal: %w", name, err)
	}
	labels := nodePool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != name {
		return fmt.Errorf("node load balancer: refusing to finalize NodePool %s without exact managed ownership labels", name)
	}
	if nodePool.GetDeletionTimestamp() == nil {
		return fmt.Errorf("node load balancer: refusing to remove the state finalizer from live NodePool %s", name)
	}
	finalizers := nodePool.GetFinalizers()
	if !containsString(finalizers, nodeLoadBalancerNodePoolFinalizer) {
		return nil
	}
	if len(finalizers) != 1 {
		return fmt.Errorf("node load balancer: refusing to remove the state finalizer from NodePool %s while other finalizers remain", name)
	}
	updated := nodePool.DeepCopy()
	updated.SetFinalizers(removeString(finalizers, nodeLoadBalancerNodePoolFinalizer))
	if _, err := resource.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: remove state finalizer from NodePool %s: %w", name, err)
	}
	return nil
}

func (c *nodeLoadBalancerController) deleteManagedNodeClass(ctx context.Context, name string) error {
	if name != managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb") {
		return fmt.Errorf("node load balancer: refusing to delete unexpected managed NodeClass %q", name)
	}
	resource := c.provider.dynamicClient.Resource(nodeClassGVR)
	object, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get NodeClass %s before delete: %w", name, err)
	}
	labels := object.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		!containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return fmt.Errorf("node load balancer: refusing to delete NodeClass %s without exact cluster-state identity", name)
	}
	uid := object.GetUID()
	if uid == "" {
		return fmt.Errorf("node load balancer: refusing to delete NodeClass %s without an observed UID", name)
	}
	if err := resource.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("node load balancer: delete NodeClass %s: %w", name, err)
	}
	return nil
}

func (c *nodeLoadBalancerController) removeManagedNodeClassStateFinalizer(ctx context.Context, name string) error {
	resource := c.provider.dynamicClient.Resource(nodeClassGVR)
	object, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: get NodeClass %s before finalizer removal: %w", name, err)
	}
	labels := object.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		object.GetDeletionTimestamp() == nil ||
		!containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return fmt.Errorf("node load balancer: refusing to finalize NodeClass %s without exact deleting cluster-state identity", name)
	}
	updated := object.DeepCopy()
	updated.SetFinalizers(removeString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer))
	if _, err := resource.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("node load balancer: remove cluster-state finalizer from NodeClass %s: %w", name, err)
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
		datapath := byKey[service.Namespace+"/"+nodeLoadBalancerDatapathName(service)]
		if datapath != nil {
			activeShard := datapath.Annotations[annotationNodeLoadBalancerDatapathShard]
			valid := nodeLoadBalancerDatapathOwnedByService(datapath, service) && isManagedNodeLoadBalancerShardName(activeShard)
			if !valid {
				return nil, fmt.Errorf("node load balancer: generated datapath for %s/%s lacks exact ownership or shard identity", service.Namespace, service.Name)
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

func (c *nodeLoadBalancerController) resumeOwnedServiceFirewallDelete(ctx context.Context, service *corev1.Service) (waiting, completed bool, err error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, false, err
	}
	target, _, err := nodeLoadBalancerFirewallDeleteReceipt(
		current.Annotations,
		annotationNodeLoadBalancerFWDeleteTarget,
		annotationNodeLoadBalancerFWDeleteIssued,
		annotationNodeLoadBalancerCleanupFWAbsent,
		annotationNodeLoadBalancerCleanupFWChecked,
	)
	if err != nil {
		return false, false, fmt.Errorf("node load balancer: parse Service firewall delete receipt: %w", err)
	}
	if target == "" {
		return false, false, nil
	}
	done, err := c.deleteOwnedServiceFirewall(ctx, current, target)
	return !done, done, err
}

func (c *nodeLoadBalancerController) deleteOwnedServiceFirewall(ctx context.Context, service *corev1.Service, uuid string) (bool, error) {
	if !validNodeLoadBalancerCloudUUID(uuid) {
		return false, fmt.Errorf("node load balancer: invalid Service firewall cleanup UUID %q", uuid)
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, err
	}
	if !containsString(current.Finalizers, nodeLoadBalancerFinalizer) &&
		!containsString(current.Finalizers, publicNodeLocalFinalizer) {
		return false, errors.New("node load balancer: refusing Service firewall cleanup without the durable provider finalizer")
	}
	target, issuedAt, err := nodeLoadBalancerFirewallDeleteReceipt(
		current.Annotations,
		annotationNodeLoadBalancerFWDeleteTarget,
		annotationNodeLoadBalancerFWDeleteIssued,
		annotationNodeLoadBalancerCleanupFWAbsent,
		annotationNodeLoadBalancerCleanupFWChecked,
	)
	if err != nil {
		return false, fmt.Errorf("node load balancer: parse Service firewall delete receipt: %w", err)
	}
	if target != "" && target != uuid {
		return false, fmt.Errorf("node load balancer: Service firewall delete receipt targets %s, not %s", target, uuid)
	}
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.serviceFirewallRelationOwner(current),
		nil,
	)
	if err != nil || !converged {
		return false, err
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var firewall *inspace.Firewall
	for i := range firewalls {
		if firewalls[i].UUID == uuid {
			if firewall != nil {
				return false, fmt.Errorf("node load balancer: firewall UUID %s appears multiple times during cleanup", uuid)
			}
			copy := firewalls[i]
			firewall = &copy
			break
		}
	}
	if firewall == nil {
		if target == "" {
			updated, changed, stageErr := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
				if !containsString(copy.Finalizers, nodeLoadBalancerFinalizer) &&
					!containsString(copy.Finalizers, publicNodeLocalFinalizer) {
					return false, errors.New("node load balancer: Service lost its provider finalizer before firewall delete intent persistence")
				}
				if existing := copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget]; existing != "" {
					if existing != uuid {
						return false, fmt.Errorf("node load balancer: concurrent Service firewall delete targets %s, not %s", existing, uuid)
					}
					return false, nil
				}
				copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] = uuid
				delete(copy.Annotations, annotationNodeLoadBalancerFWDeleteIssued)
				delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWAbsent)
				delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWChecked)
				return true, nil
			})
			if stageErr != nil {
				return false, fmt.Errorf("node load balancer: persist Service firewall delete intent: %w", stageErr)
			}
			if !changed {
				return false, nil
			}
			current = updated
			target = uuid
		}
		confirmed, changed, confirmErr := c.recordFirewallAbsence(
			ctx,
			current,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
			c.nodeLoadBalancerFirewallRelationTime(),
			time.Time{},
		)
		if confirmErr != nil || changed || !confirmed {
			return false, confirmErr
		}
		cleared, _, clearErr := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
			storedTarget, storedIssued, parseErr := nodeLoadBalancerFirewallDeleteReceipt(
				copy.Annotations,
				annotationNodeLoadBalancerFWDeleteTarget,
				annotationNodeLoadBalancerFWDeleteIssued,
				annotationNodeLoadBalancerCleanupFWAbsent,
				annotationNodeLoadBalancerCleanupFWChecked,
			)
			if parseErr != nil {
				return false, parseErr
			}
			if storedTarget != uuid || storedIssued != issuedAt {
				return false, errors.New("node load balancer: Service firewall delete receipt changed during absence proof")
			}
			count, parseErr := strconv.Atoi(copy.Annotations[annotationNodeLoadBalancerCleanupFWAbsent])
			if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
				return false, errors.New("node load balancer: Service firewall delete absence is no longer confirmed")
			}
			clearServiceFirewallDeleteState(copy.Annotations, uuid)
			return true, nil
		})
		if clearErr != nil {
			return false, fmt.Errorf("node load balancer: clear proven-absent Service firewall delete receipt: %w", clearErr)
		}
		return cleared != nil, nil
	}
	if !nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, string(current.UID), c.provider.config.BillingAccountID) {
		return false, fmt.Errorf("node load balancer: refusing to delete firewall %s without exact Service ownership", uuid)
	}
	if target != "" && (current.Annotations[annotationNodeLoadBalancerCleanupFWAbsent] != "" ||
		current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "") {
		updated, changed, clearErr := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != uuid ||
				copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != issuedAt {
				return false, errors.New("node load balancer: Service firewall delete receipt changed before visibility reset")
			}
			changed := copy.Annotations[annotationNodeLoadBalancerCleanupFWAbsent] != "" ||
				copy.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != ""
			delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWAbsent)
			delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWChecked)
			return changed, nil
		})
		if clearErr != nil || changed {
			return false, clearErr
		}
		current = updated
	}
	assignments, assignmentErr := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
	if assignmentErr != nil {
		return false, assignmentErr
	}
	if len(assignments) != 0 {
		for _, vmUUID := range assignments {
			converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				c.serviceFirewallRelationOwner(current),
				&nodeLoadBalancerFirewallRelationFence{
					operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: uuid, vmUUID: vmUUID,
				},
			)
			if relationErr != nil || !converged {
				return false, errors.Join(
					relationErr,
					fmt.Errorf("node load balancer: waiting to unassign firewall %s from VM %s", uuid, vmUUID),
				)
			}
		}
		return false, nil
	}
	if issuedAt != "" {
		// A durable issued receipt is immutable after the request boundary. Even
		// exact visibility can be stale and must never authorize a replay.
		return false, nil
	}
	issuedAt = c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	issuedService, winner, issueErr := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		storedTarget, storedIssued, parseErr := nodeLoadBalancerFirewallDeleteReceipt(
			copy.Annotations,
			annotationNodeLoadBalancerFWDeleteTarget,
			annotationNodeLoadBalancerFWDeleteIssued,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
		)
		if parseErr != nil {
			return false, parseErr
		}
		if storedTarget != "" && storedTarget != uuid {
			return false, fmt.Errorf("node load balancer: concurrent Service firewall delete targets %s, not %s", storedTarget, uuid)
		}
		if storedIssued != "" {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] = uuid
		copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] = issuedAt
		delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWAbsent)
		delete(copy.Annotations, annotationNodeLoadBalancerCleanupFWChecked)
		return true, nil
	})
	if issueErr != nil {
		return false, fmt.Errorf("node load balancer: persist Service firewall delete-issued receipt: %w", issueErr)
	}
	if !winner {
		return false, nil
	}
	authorizedService, authorityErr := c.getExactParentService(ctx, issuedService)
	if authorityErr != nil {
		return false, fmt.Errorf("node load balancer: re-read Service owner after firewall delete issue: %w", authorityErr)
	}
	if authorizedService.UID != issuedService.UID ||
		authorizedService.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != uuid ||
		authorizedService.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != issuedAt {
		return false, errors.New("node load balancer: Service firewall delete authority changed after issue")
	}
	authorizedFirewall, authorityErr := c.exactNodeLoadBalancerFirewallFresh(ctx, uuid)
	if authorityErr != nil {
		return false, fmt.Errorf("node load balancer: re-read Service firewall after delete issue: %w", authorityErr)
	}
	if !nodeLoadBalancerFirewallAuthorityUnchanged(*firewall, *authorizedFirewall) ||
		!nodeLoadBalancerFirewallOwnedByService(
			*authorizedFirewall,
			c.provider.config.ClusterID,
			string(authorizedService.UID),
			c.provider.config.BillingAccountID,
		) {
		return false, errors.New("node load balancer: Service firewall lost exact ownership or stable policy after delete issue")
	}
	postIssueAssignments, authorityErr := nodeLoadBalancerFirewallAssignmentVMs(*authorizedFirewall)
	if authorityErr != nil {
		return false, authorityErr
	}
	if len(postIssueAssignments) != 0 {
		return false, errors.New("node load balancer: Service firewall gained assignments after delete issue")
	}
	deleteErr := c.provider.api.DeleteFirewall(ctx, c.provider.config.Location, uuid)
	if nodeLoadBalancerMutationKnownPreDispatch(deleteErr) {
		_, _, resetErr := c.updateExactParentService(ctx, issuedService, func(copy *corev1.Service) (bool, error) {
			if copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != uuid ||
				copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != issuedAt {
				return false, errors.New("node load balancer: Service firewall delete receipt changed before pre-dispatch rejection")
			}
			delete(copy.Annotations, annotationNodeLoadBalancerFWDeleteIssued)
			return true, nil
		})
		return false, errors.Join(fmt.Errorf("node load balancer: delete firewall %s: %w", uuid, deleteErr), resetErr)
	}
	if deleteErr != nil {
		return false, fmt.Errorf("node load balancer: delete firewall %s: %w", uuid, deleteErr)
	}
	return false, nil
}

// nodeLoadBalancerFirewallDeleteReceipt validates the exact durable state used
// by all NodeLB firewall DELETE paths. A target without issuedAt is a staged
// upgrade/absence intent. Once issuedAt exists it is immutable until repeated,
// spaced exact-UUID absence is persisted on the same Kubernetes owner.
func nodeLoadBalancerFirewallDeleteReceipt(
	annotations map[string]string,
	targetKey, issuedKey, absentKey, checkedKey string,
) (target, issuedAt string, err error) {
	target = annotations[targetKey]
	issuedAt = annotations[issuedKey]
	absent := annotations[absentKey]
	checked := annotations[checkedKey]
	if target == "" {
		if issuedAt != "" {
			return "", "", errors.New("firewall delete-issued timestamp lacks an exact target UUID")
		}
		// Cleanup absence annotations predate delete receipts and are also used
		// by the surrounding finalizer convergence proof. They are intentionally
		// ignored until an exact delete target has been staged.
		return "", "", nil
	}
	if target != "" && !validNodeLoadBalancerCloudUUID(target) {
		return "", "", fmt.Errorf("invalid firewall delete target UUID %q", target)
	}
	if issuedAt != "" {
		if _, parseErr := time.Parse(time.RFC3339Nano, issuedAt); parseErr != nil {
			return "", "", fmt.Errorf("invalid firewall delete-issued timestamp: %w", parseErr)
		}
	}
	if (absent == "") != (checked == "") {
		return "", "", errors.New("incomplete firewall delete absence evidence")
	}
	if absent != "" {
		count, parseErr := strconv.Atoi(absent)
		if parseErr != nil || count < 1 || count > nodeLoadBalancerAbsenceConfirmations {
			return "", "", fmt.Errorf("invalid firewall delete absence count %q", absent)
		}
		if _, parseErr := time.Parse(time.RFC3339Nano, checked); parseErr != nil {
			return "", "", fmt.Errorf("invalid firewall delete absence timestamp: %w", parseErr)
		}
	}
	return target, issuedAt, nil
}

func clearServiceFirewallDeleteState(annotations map[string]string, uuid string) {
	if annotations[annotationNodeLoadBalancerFirewallUUID] == uuid {
		delete(annotations, annotationNodeLoadBalancerFirewallUUID)
		delete(annotations, annotationNodeLoadBalancerFirewallHash)
		delete(annotations, annotationNodeLoadBalancerFirewallAbsent)
		delete(annotations, annotationNodeLoadBalancerFirewallChecked)
	}
	if annotations[annotationNodeLoadBalancerPreviousFirewall] == uuid {
		delete(annotations, annotationNodeLoadBalancerPreviousFirewall)
	}
	if annotations[annotationNodeLoadBalancerPendingFirewall] == uuid {
		for _, key := range []string{
			annotationNodeLoadBalancerPendingFirewall,
			annotationNodeLoadBalancerPendingFWName,
			annotationNodeLoadBalancerPendingFWStarted,
			annotationNodeLoadBalancerPendingFWIssued,
			annotationNodeLoadBalancerPendingFWIssuedAt,
			annotationNodeLoadBalancerPendingFWDelete,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
		} {
			delete(annotations, key)
		}
	}
	for _, key := range []string{
		annotationNodeLoadBalancerFWDeleteTarget,
		annotationNodeLoadBalancerFWDeleteIssued,
	} {
		delete(annotations, key)
	}
}

func (c *nodeLoadBalancerController) serviceFirewallsForEmergencyDetach(
	ctx context.Context,
	service *corev1.Service,
) ([]inspace.Firewall, error) {
	serviceUID := string(service.UID)
	if serviceUID == "" {
		return nil, errors.New("node load balancer: Service UID is required to discover emergency firewall identities")
	}
	if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
		return nil, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list firewalls for emergency detach: %w", err)
	}
	persisted := nodeLoadBalancerPersistedFirewallUUIDs(service)
	result := make([]inspace.Firewall, 0)
	seen := map[string]int{}
	var resultErr error
	for _, firewall := range items {
		_, exactPersisted := persisted[firewall.UUID]
		strictOwned := nodeLoadBalancerFirewallOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			serviceUID,
			c.provider.config.BillingAccountID,
		)
		if !exactPersisted && !strictOwned {
			continue
		}
		seen[firewall.UUID]++
		if seen[firewall.UUID] > 1 {
			resultErr = errors.Join(resultErr, fmt.Errorf("node load balancer: firewall UUID %s appears multiple times during emergency detach", firewall.UUID))
			continue
		}
		if exactPersisted && !nodeLoadBalancerFirewallIdentityOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			serviceUID,
			c.provider.config.BillingAccountID,
		) {
			resultErr = errors.Join(resultErr, fmt.Errorf("node load balancer: persisted firewall %s lost deterministic Service identity", firewall.UUID))
			continue
		}
		result = append(result, firewall)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	return result, resultErr
}

func nodeLoadBalancerPersistedFirewallUUIDs(service *corev1.Service) map[string]struct{} {
	result := map[string]struct{}{}
	if service == nil {
		return result
	}
	for _, key := range []string{
		annotationNodeLoadBalancerFirewallUUID,
		annotationNodeLoadBalancerPreviousFirewall,
		annotationNodeLoadBalancerPendingFirewall,
		annotationNodeLoadBalancerFirewallAssigning,
	} {
		if uuid := service.Annotations[key]; uuid != "" {
			result[uuid] = struct{}{}
		}
	}
	return result
}

func (c *nodeLoadBalancerController) serviceFirewallsDetached(
	ctx context.Context,
	service *corev1.Service,
) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	items, discoveryErr := c.serviceFirewallsForEmergencyDetach(ctx, current)
	if discoveryErr != nil {
		return false, discoveryErr
	}
	observed := make(map[string]struct{}, len(items))
	for _, firewall := range items {
		observed[firewall.UUID] = struct{}{}
		for _, resource := range firewall.ResourcesAssigned {
			if !strings.EqualFold(resource.ResourceType, "vm") || resource.ResourceUUID == "" {
				return false, fmt.Errorf("node load balancer: firewall %s has invalid assigned resource %#v", firewall.UUID, resource)
			}
			if resetErr := c.resetServiceFirewallWithdrawalEvidence(ctx, current); resetErr != nil {
				return false, resetErr
			}
			return false, nil
		}
	}
	missing := make([]string, 0)
	for uuid := range nodeLoadBalancerPersistedFirewallUUIDs(current) {
		if _, found := observed[uuid]; !found {
			missing = append(missing, uuid)
		}
	}
	sort.Strings(missing)
	notBefore := time.Time{}
	assigningUUID := current.Annotations[annotationNodeLoadBalancerFirewallAssigning]
	assigningStarted := current.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
	if assigningUUID != "" || assigningStarted != "" {
		if assigningUUID == "" || assigningStarted == "" {
			return false, errors.New("node load balancer: incomplete firewall assignment authorization during withdrawal")
		}
		startedAt, parseErr := time.Parse(time.RFC3339Nano, assigningStarted)
		if parseErr != nil {
			return false, fmt.Errorf("node load balancer: invalid firewall assignment timestamp during withdrawal: %w", parseErr)
		}
		if _, persisted := nodeLoadBalancerPersistedFirewallUUIDs(current)[assigningUUID]; !persisted {
			return false, errors.New("node load balancer: firewall assignment authorization is not a persisted Service firewall identity")
		}
		notBefore = startedAt.Add(nodeLoadBalancerPendingCreateTimeout)
		missing = append(missing, "fenced:"+assigningUUID)
		sort.Strings(missing)
	}
	if len(missing) == 0 {
		if clearErr := c.resetServiceFirewallWithdrawalEvidence(ctx, current); clearErr != nil {
			return false, clearErr
		}
		return true, nil
	}
	return c.confirmMissingServiceFirewallsForWithdrawal(ctx, current, missing, notBefore)
}

func (c *nodeLoadBalancerController) resetServiceFirewallWithdrawalEvidence(
	ctx context.Context,
	service *corev1.Service,
) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
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
		return changed, nil
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node load balancer: reset firewall withdrawal absence evidence: %w", err)
	}
	return nil
}

func (c *nodeLoadBalancerController) confirmMissingServiceFirewallsForWithdrawal(
	ctx context.Context,
	service *corev1.Service,
	missing []string,
	notBefore time.Time,
) (bool, error) {
	now := time.Now().UTC()
	if now.Before(notBefore) {
		return false, nil
	}
	missingSet := strings.Join(missing, ",")
	confirmed := false
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerWithdrawFWMissing] != missingSet {
			if copy.Annotations == nil {
				copy.Annotations = map[string]string{}
			}
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWMissing] = missingSet
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] = "1"
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWChecked] = now.Format(time.RFC3339Nano)
			return true, nil
		}
		count, parseErr := strconv.Atoi(copy.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent])
		if parseErr != nil || count < 1 || count > nodeLoadBalancerAbsenceConfirmations {
			return false, fmt.Errorf("node load balancer: invalid withdrawal firewall absence count %q", copy.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent])
		}
		if count >= nodeLoadBalancerAbsenceConfirmations {
			confirmed = true
			return false, nil
		}
		checkedAt, parseErr := time.Parse(time.RFC3339Nano, copy.Annotations[annotationNodeLoadBalancerWithdrawFWChecked])
		if parseErr != nil {
			return false, fmt.Errorf("node load balancer: invalid withdrawal firewall absence timestamp: %w", parseErr)
		}
		if now.Before(checkedAt.Add(nodeLoadBalancerAbsenceConfirmationDelay)) {
			return false, nil
		}
		copy.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] = strconv.Itoa(count + 1)
		copy.Annotations[annotationNodeLoadBalancerWithdrawFWChecked] = now.Format(time.RFC3339Nano)
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("node load balancer: persist firewall withdrawal absence evidence: %w", err)
	}
	return confirmed, nil
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
	if !nodeLoadBalancerFirewallIdentityOwnedByService(firewall, cluster, serviceUID, billingAccountID) {
		return false
	}
	prefix := nodeLoadBalancerFirewallServicePrefix(cluster, serviceUID)
	name := firewall.EffectiveName()
	suffix := strings.TrimPrefix(name, prefix)
	hash, err := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
	return err == nil && hash == suffix
}

func nodeLoadBalancerFirewallIdentityOwnedByService(
	firewall inspace.Firewall,
	cluster, serviceUID string,
	billingAccountID int64,
) bool {
	if cluster == "" || validateNodeLoadBalancerServiceUID(serviceUID) != nil || firewall.BillingAccountID != billingAccountID {
		return false
	}
	prefix := nodeLoadBalancerFirewallServicePrefix(cluster, serviceUID)
	name := firewall.EffectiveName()
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	return len(suffix) == 8 && isLowerHex(suffix)
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
