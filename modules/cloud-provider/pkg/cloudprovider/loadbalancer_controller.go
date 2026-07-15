package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	loadBalancerTargetFullResync = 5 * time.Minute
	loadBalancerTargetFixedRetry = 30 * time.Second
	loadBalancerTargetMaxRetries = 12
)

// loadBalancerTargetController closes gaps in the standard Kubernetes Service
// controller. The standard controller neither watches EndpointSlices nor
// triggers host updates when Node Ready changes, and it ignores label-only
// Service updates. These signals are required when an InSpace NLB has no native
// backend health check and Local traffic policy must target only nodes that
// currently host a serving endpoint.
type loadBalancerTargetController struct {
	provider *Provider

	nodes          corelisters.NodeLister
	services       corelisters.ServiceLister
	endpointSlices discoverylisters.EndpointSliceLister

	nodesSynced          cache.InformerSynced
	servicesSynced       cache.InformerSynced
	endpointSlicesSynced cache.InformerSynced

	queue workqueue.TypedRateLimitingInterface[string]
}

func newLoadBalancerTargetController(provider *Provider, factory informers.SharedInformerFactory) (*loadBalancerTargetController, error) {
	if provider == nil || factory == nil {
		return nil, fmt.Errorf("provider and informer factory are required")
	}
	if provider.kubeClient == nil {
		return nil, fmt.Errorf("initialized Kubernetes client is required")
	}
	nodes := factory.Core().V1().Nodes()
	services := factory.Core().V1().Services()
	endpointSlices := factory.Discovery().V1().EndpointSlices()
	controller := &loadBalancerTargetController{
		provider:             provider,
		nodes:                nodes.Lister(),
		services:             services.Lister(),
		endpointSlices:       endpointSlices.Lister(),
		nodesSynced:          nodes.Informer().HasSynced,
		servicesSynced:       services.Informer().HasSynced,
		endpointSlicesSynced: endpointSlices.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "inspace-load-balancer-targets"},
		),
	}
	if _, err := endpointSlices.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.onEndpointSliceAdd,
		UpdateFunc: func(oldObject, newObject any) {
			controller.onEndpointSliceUpdate(oldObject, newObject)
		},
		DeleteFunc: controller.onEndpointSliceDelete,
	}); err != nil {
		return nil, fmt.Errorf("register EndpointSlice handler: %w", err)
	}
	if _, err := nodes.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.onNodeAdd,
		UpdateFunc: func(oldObject, newObject any) {
			controller.onNodeUpdate(oldObject, newObject)
		},
		DeleteFunc: controller.onNodeDelete,
	}); err != nil {
		return nil, fmt.Errorf("register Node handler: %w", err)
	}
	if _, err := services.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.onServiceAdd,
		UpdateFunc: func(oldObject, newObject any) {
			controller.onServiceUpdate(oldObject, newObject)
		},
	}); err != nil {
		return nil, fmt.Errorf("register Service handler: %w", err)
	}
	return controller, nil
}

func (c *loadBalancerTargetController) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()
	if stopCh == nil {
		panic("cloudprovider: load-balancer target controller requires a stop channel")
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
	c.enqueueAllRelevantServices()
	go func() {
		for c.processNext(ctx) {
		}
	}()

	ticker := time.NewTicker(loadBalancerTargetFullResync)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.enqueueAllRelevantServices()
		}
	}
}

func (c *loadBalancerTargetController) processNext(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)
	if err := c.sync(ctx, key); err != nil {
		c.requeueAfterError(key, err, c.queue.NumRequeues(key))
		return true
	}
	c.queue.Forget(key)
	return true
}

func (c *loadBalancerTargetController) requeueAfterError(key string, err error, requeues int) {
	if requeues < loadBalancerTargetMaxRetries {
		klog.ErrorS(err, "failed to reconcile InSpace load-balancer targets", "service", key)
		c.queue.AddRateLimited(key)
		return
	}
	// Retain the rate-limiter failure state and schedule a bounded retry. A
	// transient cloud or API failure must not leave a dead target until the
	// five-minute safety resync happens to run. A later success calls Forget.
	c.queue.AddAfter(key, loadBalancerTargetFixedRetry)
	runtime.HandleError(fmt.Errorf("reconcile InSpace load-balancer targets for %s after %d retries; retrying in %s: %w", key, loadBalancerTargetMaxRetries, loadBalancerTargetFixedRetry, err))
}

func (c *loadBalancerTargetController) sync(ctx context.Context, key string) error {
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
	patched, malformed, err := c.reconcilePublicIntentAnnotation(ctx, service)
	if err != nil || malformed || patched {
		return err
	}
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nil
	}
	if service.Spec.LoadBalancerClass != nil {
		return nil
	}
	public, err := explicitPublicRequested(service)
	if err != nil || !public {
		return err
	}
	nodes, err := c.nodes.List(labels.Everything())
	if err != nil {
		return err
	}
	return c.provider.reconcileLoadBalancerTargets(ctx, service, nodes)
}

// reconcilePublicIntentAnnotation mirrors the two public opt-in markers into
// one provider-private annotation. Kubernetes' stock Service controller reacts
// to annotation changes but not label-only changes, so this metadata-only nudge
// makes label-only opt-in and removal flow through its normal finalizer,
// EnsureLoadBalancer, and status lifecycle.
func (c *loadBalancerTargetController) reconcilePublicIntentAnnotation(ctx context.Context, service *corev1.Service) (patched, malformed bool, err error) {
	if service == nil || service.UID == "" {
		return false, false, errors.New("public load-balancer intent reconciliation requires a Service UID")
	}
	current, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		return false, false, err
	}
	if current.UID != service.UID {
		return false, false, fmt.Errorf("Service %s/%s identity changed before public intent reconciliation", service.Namespace, service.Name)
	}
	annotationRequested, err := publicAnnotationRequested(current)
	if err != nil {
		// The provider's standard reconciliation reports the malformed public
		// annotation. Do not rewrite user intent or create a patch loop here.
		return false, true, nil
	}
	desired := current.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		current.Spec.LoadBalancerClass == nil &&
		current.Labels[LabelLoadBalancerScope] == LoadBalancerScopePublic &&
		annotationRequested
	currentValue, exists := current.Annotations[annotationLoadBalancerReconcile]
	if (desired && exists && currentValue == "true") || (!desired && !exists) {
		return false, false, nil
	}
	copy := current.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	if desired {
		copy.Annotations[annotationLoadBalancerReconcile] = "true"
	} else {
		delete(copy.Annotations, annotationLoadBalancerReconcile)
	}
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return false, false, fmt.Errorf("update public load-balancer intent annotation on Service %s/%s: %w", service.Namespace, service.Name, err)
	}
	if updated.UID != service.UID {
		return false, false, fmt.Errorf("Service %s/%s identity changed during public intent reconciliation", service.Namespace, service.Name)
	}
	return true, false, nil
}

func (c *loadBalancerTargetController) onEndpointSliceAdd(object any) {
	if endpointSlice, ok := object.(*discoveryv1.EndpointSlice); ok {
		c.enqueueEndpointSliceService(endpointSlice)
	}
}

func (c *loadBalancerTargetController) onEndpointSliceUpdate(oldObject, newObject any) {
	oldSlice, oldOK := oldObject.(*discoveryv1.EndpointSlice)
	newSlice, newOK := newObject.(*discoveryv1.EndpointSlice)
	if !oldOK || !newOK {
		return
	}
	oldKey := endpointSliceServiceKey(oldSlice)
	newKey := endpointSliceServiceKey(newSlice)
	if oldKey == newKey && reflect.DeepEqual(readyEndpointNodes(oldSlice), readyEndpointNodes(newSlice)) {
		return
	}
	if oldKey != "" {
		c.queue.Add(oldKey)
	}
	if newKey != "" {
		c.queue.Add(newKey)
	}
}

func (c *loadBalancerTargetController) onEndpointSliceDelete(object any) {
	endpointSlice, ok := object.(*discoveryv1.EndpointSlice)
	if !ok {
		tombstone, tombstoneOK := object.(cache.DeletedFinalStateUnknown)
		if !tombstoneOK {
			return
		}
		endpointSlice, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		if !ok {
			return
		}
	}
	c.enqueueEndpointSliceService(endpointSlice)
}

func (c *loadBalancerTargetController) enqueueEndpointSliceService(endpointSlice *discoveryv1.EndpointSlice) {
	if key := endpointSliceServiceKey(endpointSlice); key != "" {
		c.queue.Add(key)
	}
}

func endpointSliceServiceKey(endpointSlice *discoveryv1.EndpointSlice) string {
	if endpointSlice == nil {
		return ""
	}
	name := endpointSlice.Labels[discoveryv1.LabelServiceName]
	if endpointSlice.Namespace == "" || name == "" {
		return ""
	}
	return endpointSlice.Namespace + "/" + name
}

func readyEndpointNodes(endpointSlice *discoveryv1.EndpointSlice) map[string]struct{} {
	result := make(map[string]struct{})
	if endpointSlice == nil {
		return result
	}
	for _, endpoint := range endpointSlice.Endpoints {
		if endpoint.NodeName == nil || (endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready) ||
			(endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
			continue
		}
		result[*endpoint.NodeName] = struct{}{}
	}
	return result
}

func (c *loadBalancerTargetController) onServiceAdd(object any) {
	service, ok := object.(*corev1.Service)
	if ok && serviceRelevantToIntentController(service) {
		c.enqueueService(service)
	}
}

func (c *loadBalancerTargetController) onServiceUpdate(oldObject, newObject any) {
	oldService, oldOK := oldObject.(*corev1.Service)
	newService, newOK := newObject.(*corev1.Service)
	if !oldOK || !newOK || serviceIntentStateFor(oldService) == serviceIntentStateFor(newService) {
		return
	}
	if serviceRelevantToIntentController(oldService) || serviceRelevantToIntentController(newService) {
		c.enqueueService(newService)
	}
}

func (c *loadBalancerTargetController) enqueueService(service *corev1.Service) {
	key, err := cache.MetaNamespaceKeyFunc(service)
	if err == nil {
		c.queue.Add(key)
	}
}

type serviceIntentState struct {
	serviceType             corev1.ServiceType
	loadBalancerClass       string
	loadBalancerClassExists bool
	publicLabel             string
	publicLabelExists       bool
	publicAnnotation        string
	publicAnnotationExists  bool
	reconcileAnnotation     string
	reconcileExists         bool
}

func serviceIntentStateFor(service *corev1.Service) serviceIntentState {
	if service == nil {
		return serviceIntentState{}
	}
	state := serviceIntentState{serviceType: service.Spec.Type}
	if service.Spec.LoadBalancerClass != nil {
		state.loadBalancerClassExists = true
		state.loadBalancerClass = *service.Spec.LoadBalancerClass
	}
	state.publicLabel, state.publicLabelExists = service.Labels[LabelLoadBalancerScope]
	state.publicAnnotation, state.publicAnnotationExists = service.Annotations[AnnotationPublicLoadBalancer]
	state.reconcileAnnotation, state.reconcileExists = service.Annotations[annotationLoadBalancerReconcile]
	return state
}

func serviceRelevantToIntentController(service *corev1.Service) bool {
	if service == nil {
		return false
	}
	_, publicAnnotationExists := service.Annotations[AnnotationPublicLoadBalancer]
	_, reconcileExists := service.Annotations[annotationLoadBalancerReconcile]
	return service.Labels[LabelLoadBalancerScope] == LoadBalancerScopePublic || publicAnnotationExists || reconcileExists
}

func (c *loadBalancerTargetController) onNodeAdd(object any) {
	if _, ok := object.(*corev1.Node); ok {
		c.enqueueAllPublicServices()
	}
}

func (c *loadBalancerTargetController) onNodeUpdate(oldObject, newObject any) {
	oldNode, oldOK := oldObject.(*corev1.Node)
	newNode, newOK := newObject.(*corev1.Node)
	if !oldOK || !newOK || nodeTargetStateEqual(oldNode, newNode) {
		return
	}
	c.enqueueAllPublicServices()
}

func (c *loadBalancerTargetController) onNodeDelete(object any) {
	if _, ok := object.(*corev1.Node); !ok {
		tombstone, tombstoneOK := object.(cache.DeletedFinalStateUnknown)
		if !tombstoneOK {
			return
		}
		if _, ok = tombstone.Obj.(*corev1.Node); !ok {
			return
		}
	}
	c.enqueueAllPublicServices()
}

type nodeTargetState struct {
	providerID   string
	ready        corev1.ConditionStatus
	deleting     bool
	excluded     bool
	controlPlane bool
	disrupted    bool
}

func nodeTargetStateEqual(left, right *corev1.Node) bool {
	return targetStateForNode(left) == targetStateForNode(right)
}

func targetStateForNode(node *corev1.Node) nodeTargetState {
	if node == nil {
		return nodeTargetState{}
	}
	state := nodeTargetState{
		providerID:   node.Spec.ProviderID,
		deleting:     !node.DeletionTimestamp.IsZero(),
		excluded:     nodeExcludedFromLoadBalancers(node),
		controlPlane: nodeHasControlPlaneRole(node),
	}
	for _, taint := range node.Spec.Taints {
		if taint.Key == clusterAutoscalerDeletionTaint || taint.Key == karpenterDisruptionTaint {
			state.disrupted = true
			break
		}
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			state.ready = condition.Status
			break
		}
	}
	return state
}

func (c *loadBalancerTargetController) enqueueAllPublicServices() {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("list Services for InSpace load-balancer target reconciliation: %w", err))
		return
	}
	for _, service := range services {
		if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		public, err := explicitPublicRequested(service)
		if err != nil || !public {
			continue
		}
		key, err := cache.MetaNamespaceKeyFunc(service)
		if err == nil {
			c.queue.Add(key)
		}
	}
}

func (c *loadBalancerTargetController) enqueueAllRelevantServices() {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("list Services for InSpace load-balancer intent reconciliation: %w", err))
		return
	}
	for _, service := range services {
		if serviceRelevantToIntentController(service) {
			c.enqueueService(service)
		}
	}
}
