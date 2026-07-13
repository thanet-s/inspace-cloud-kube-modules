package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	testVMUUIDB = "cccccccc-3333-4333-8444-dddddddddddd"
	testVMUUIDC = "dddddddd-4444-4444-8555-eeeeeeeeeeee"
)

func TestProviderInformerWiringStartsOnlyAfterInitialize(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	client := fake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, 0)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("SetInformers() before Initialize did not fail startup")
			}
		}()
		provider.SetInformers(factory)
	}()

	stopCh := make(chan struct{})
	provider.Initialize(staticControllerClientBuilder{client: client}, stopCh)
	provider.SetInformers(factory)
	if provider.endpointSliceLister == nil || provider.endpointSlicesSynced == nil {
		t.Fatal("SetInformers() did not wire EndpointSlice targeting")
	}
	close(stopCh)
}

func TestTargetControllerRetainsBoundedRetryAfterRateLimitExhaustion(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Unix(1_700_000_000, 0))
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.DefaultTypedControllerRateLimiter[string](),
		workqueue.TypedRateLimitingQueueConfig[string]{Clock: fakeClock},
	)
	defer queue.ShutDown()
	controller := &loadBalancerTargetController{queue: queue}
	controller.requeueAfterError("default/web", errors.New("transient API failure"), loadBalancerTargetMaxRetries)
	if queue.Len() != 0 {
		t.Fatalf("fixed retry became ready immediately: queue length=%d", queue.Len())
	}
	fakeClock.Step(loadBalancerTargetFixedRetry - time.Second)
	time.Sleep(time.Millisecond)
	if queue.Len() != 0 {
		t.Fatalf("fixed retry became ready early: queue length=%d", queue.Len())
	}
	fakeClock.Step(time.Second)
	deadline := time.Now().Add(time.Second)
	for queue.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if queue.Len() != 1 {
		t.Fatalf("fixed retry was lost after exhaustion: queue length=%d", queue.Len())
	}
	key, shutdown := queue.Get()
	if shutdown || key != "default/web" {
		t.Fatalf("fixed retry item = %q, shutdown=%t", key, shutdown)
	}
	queue.Done(key)
}

func TestPublicIntentAnnotationNudgesStockServiceControllerOnLabelTransitions(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*corev1.Service)
		wantTrigger bool
	}{
		{
			name: "label-only public opt-in adds trigger",
			mutate: func(service *corev1.Service) {
				service.Spec.Type = corev1.ServiceTypeLoadBalancer
			},
			wantTrigger: true,
		},
		{
			name: "label-only public removal removes trigger",
			mutate: func(service *corev1.Service) {
				service.Spec.Type = corev1.ServiceTypeLoadBalancer
				delete(service.Labels, LabelLoadBalancerScope)
				markPublicIntentMirrored(service)
			},
		},
		{
			name: "classed service removes trigger",
			mutate: func(service *corev1.Service) {
				service.Spec.Type = corev1.ServiceTypeLoadBalancer
				class := "example.com/other"
				service.Spec.LoadBalancerClass = &class
				markPublicIntentMirrored(service)
			},
		},
		{
			name: "non LoadBalancer removes trigger",
			mutate: func(service *corev1.Service) {
				service.Spec.Type = corev1.ServiceTypeClusterIP
				markPublicIntentMirrored(service)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			service.ResourceVersion = "17"
			test.mutate(service)
			client := fake.NewSimpleClientset(service.DeepCopy())
			provider := newTestProvider(t, &fakeAPI{})
			provider.kubeClient = client
			fixture := newTargetControllerFixture(t, provider)
			fixture.addService(t, service)

			if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
				t.Fatal(err)
			}
			actions := client.Actions()
			if len(actions) != 1 {
				t.Fatalf("Kubernetes actions = %#v, want one merge patch", actions)
			}
			patchAction, ok := actions[0].(k8stesting.PatchAction)
			if !ok || patchAction.GetPatchType() != types.MergePatchType {
				t.Fatalf("action = %#v, want merge patch", actions[0])
			}
			var patch map[string]any
			if err := json.Unmarshal(patchAction.GetPatch(), &patch); err != nil {
				t.Fatal(err)
			}
			metadata, _ := patch["metadata"].(map[string]any)
			if metadata["resourceVersion"] != service.ResourceVersion {
				t.Fatalf("patch resourceVersion = %#v, want %q", metadata["resourceVersion"], service.ResourceVersion)
			}
			annotations, _ := metadata["annotations"].(map[string]any)
			value, present := annotations[annotationLoadBalancerReconcile]
			if test.wantTrigger {
				if !present || value != "true" {
					t.Fatalf("trigger patch = %#v, want true", annotations)
				}
			} else if !present || value != nil {
				t.Fatalf("trigger patch = %#v, want explicit null removal", annotations)
			}
			if _, mutated := service.Annotations[annotationLoadBalancerReconcile]; mutated != !test.wantTrigger {
				t.Fatalf("informer object was mutated: annotations=%v", service.Annotations)
			}

			client.ClearActions()
			updated, err := client.CoreV1().Services("default").Get(context.Background(), "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, exists := updated.Annotations[annotationLoadBalancerReconcile]
			if test.wantTrigger {
				if !exists || got != "true" {
					t.Fatalf("stored trigger = %q, exists=%t", got, exists)
				}
			} else if exists {
				t.Fatalf("stored trigger was not removed: %v", updated.Annotations)
			}
		})
	}
}

func TestPublicIntentAnnotationIgnoresMalformedUserAnnotation(t *testing.T) {
	service := testService()
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	service.ResourceVersion = "19"
	service.Annotations[AnnotationPublicLoadBalancer] = "yes"
	markPublicIntentMirrored(service)
	client := fake.NewSimpleClientset(service.DeepCopy())
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = client
	fixture := newTargetControllerFixture(t, provider)
	fixture.addService(t, service)

	if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
		t.Fatal(err)
	}
	if actions := client.Actions(); len(actions) != 0 {
		t.Fatalf("malformed annotation caused Kubernetes mutations: %#v", actions)
	}
}

func TestPublicIntentAnnotationDoesNotPatchLoopAfterInformerObservesTrigger(t *testing.T) {
	service := testService()
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	service.ResourceVersion = "23"
	client := fake.NewSimpleClientset(service.DeepCopy())
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = client
	fixture := newTargetControllerFixture(t, provider)
	fixture.addService(t, service)

	if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Services("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.serviceIndexer.Update(updated); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
		t.Fatal(err)
	}
	if actions := client.Actions(); len(actions) != 0 {
		t.Fatalf("already mirrored intent caused a patch loop: %#v", actions)
	}
}

func TestLocalTargetsUseOnlyReadyNonTerminatingEndpointNodes(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	endpointIndexer := newNamespacedIndexer()
	provider.endpointSliceLister = discoverylisters.NewEndpointSliceLister(endpointIndexer)
	provider.endpointSlicesSynced = func() bool { return true }
	service := testService()
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal

	if err := endpointIndexer.Add(testEndpointSlice("default", "web", "web-a",
		endpointForNode("worker-a", true, false),
		endpointForNode("worker-b", false, false),
		endpointForNode("worker-c", true, true),
		endpointWithUnknownReadiness("worker-d"),
		endpointForNode("worker-a", true, false),
	)); err != nil {
		t.Fatal(err)
	}
	if err := endpointIndexer.Add(testEndpointSlice("default", "other", "other-a",
		endpointForNode("worker-b", true, false),
	)); err != nil {
		t.Fatal(err)
	}
	notReady := readyNode("worker-e", "inspace://bkk01/"+testVMUUIDB)
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	if err := endpointIndexer.Add(testEndpointSlice("default", "web", "web-b",
		endpointForNode("worker-e", true, false),
	)); err != nil {
		t.Fatal(err)
	}

	targets, err := provider.targetUUIDs(service, []*corev1.Node{
		readyNode("worker-a", "inspace://bkk01/"+testVMUUID),
		readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB),
		readyNode("worker-c", "inspace://bkk01/"+testVMUUIDC),
		readyNode("worker-d", "inspace://bkk01/99999999-1111-4222-8333-444444444444"),
		notReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantTargets := map[string]struct{}{testVMUUID: {}, "99999999-1111-4222-8333-444444444444": {}}
	if len(targets) != len(wantTargets) {
		t.Fatalf("Local targets = %v, want %v", targets, wantTargets)
	}
	for _, target := range targets {
		if _, exists := wantTargets[target]; !exists {
			t.Fatalf("unexpected Local target %q in %v", target, targets)
		}
	}
}

func TestLocalTargetsFailClosedUntilEndpointSliceCacheIsSynced(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	service := testService()
	service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	nodes := []*corev1.Node{readyNode("worker-a", "inspace://bkk01/"+testVMUUID)}

	if _, err := provider.targetUUIDs(service, nodes); err == nil || !strings.Contains(err.Error(), "synchronized EndpointSlice informer") {
		t.Fatalf("targetUUIDs() without informer error = %v", err)
	}
	provider.endpointSliceLister = discoverylisters.NewEndpointSliceLister(newNamespacedIndexer())
	provider.endpointSlicesSynced = func() bool { return false }
	if _, err := provider.targetUUIDs(service, nodes); err == nil || !strings.Contains(err.Error(), "synchronized EndpointSlice informer") {
		t.Fatalf("targetUUIDs() with unsynced informer error = %v", err)
	}
}

func TestReadyEndpointNodesInterpretsNilReadyAsReadyAndRejectsTermination(t *testing.T) {
	readyUnknownTerminationNode := "ready-unknown-termination"
	endpointSlice := testEndpointSlice("default", "web", "web-a",
		discoveryv1.Endpoint{
			NodeName: &readyUnknownTerminationNode, Addresses: []string{"10.0.0.20"},
			Conditions: discoveryv1.EndpointConditions{Ready: boolPointer(true)},
		},
		endpointForNode("ready", true, false),
		endpointForNode("unready", false, false),
		endpointForNode("terminating", true, true),
		endpointWithUnknownReadiness("unknown"),
		discoveryv1.Endpoint{
			NodeName: nil, Addresses: []string{"10.0.0.21"},
			Conditions: discoveryv1.EndpointConditions{Ready: boolPointer(true)},
		},
	)
	nodes := readyEndpointNodes(endpointSlice)
	if len(nodes) != 3 {
		t.Fatalf("ready endpoint nodes = %v", nodes)
	}
	for _, name := range []string{readyUnknownTerminationNode, "ready", "unknown"} {
		if _, exists := nodes[name]; !exists {
			t.Fatalf("ready endpoint node %q missing from %v", name, nodes)
		}
	}
}

func TestClusterTargetsOnlyReadyEligibleNodes(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	service := testService()
	ready := readyNode("worker-a", "inspace://bkk01/"+testVMUUID)
	notReady := readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB)
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	deleting := readyNode("worker-c", "inspace://bkk01/"+testVMUUIDC)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	excluded := readyNode("worker-d", "inspace://bkk01/99999999-1111-4222-8333-444444444444")
	excluded.Labels = map[string]string{corev1.LabelNodeExcludeBalancers: "true"}
	disrupted := readyNode("worker-e", "inspace://bkk01/88888888-1111-4222-8333-444444444444")
	disrupted.Spec.Taints = []corev1.Taint{{Key: karpenterDisruptionTaint, Effect: corev1.TaintEffectNoSchedule}}
	uninitialized := readyNode("worker-f", "")

	targets, err := provider.targetUUIDs(service, []*corev1.Node{ready, notReady, deleting, excluded, disrupted, uninitialized})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != testVMUUID {
		t.Fatalf("Cluster targets = %v, want only eligible Ready node %s", targets, testVMUUID)
	}
}

func TestLoadBalancerNodeEligibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*corev1.Node)
		want   bool
	}{
		{name: "ready", want: true},
		{name: "not ready", mutate: func(node *corev1.Node) { node.Status.Conditions[0].Status = corev1.ConditionFalse }},
		{name: "unknown", mutate: func(node *corev1.Node) { node.Status.Conditions[0].Status = corev1.ConditionUnknown }},
		{name: "missing condition", mutate: func(node *corev1.Node) { node.Status.Conditions = nil }},
		{name: "deleting", mutate: func(node *corev1.Node) { now := metav1.Now(); node.DeletionTimestamp = &now }},
		{name: "excluded", mutate: func(node *corev1.Node) {
			node.Labels = map[string]string{corev1.LabelNodeExcludeBalancers: "true"}
		}},
		{name: "malformed exclusion", mutate: func(node *corev1.Node) {
			node.Labels = map[string]string{corev1.LabelNodeExcludeBalancers: "invalid"}
		}},
		{name: "explicit inclusion", want: true, mutate: func(node *corev1.Node) {
			node.Labels = map[string]string{corev1.LabelNodeExcludeBalancers: "false"}
		}},
		{name: "cluster autoscaler deletion", mutate: func(node *corev1.Node) {
			node.Spec.Taints = []corev1.Taint{{Key: clusterAutoscalerDeletionTaint}}
		}},
		{name: "Karpenter disruption", mutate: func(node *corev1.Node) {
			node.Spec.Taints = []corev1.Taint{{Key: karpenterDisruptionTaint}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := readyNode("worker-a", "inspace://bkk01/"+testVMUUID)
			if test.mutate != nil {
				test.mutate(node)
			}
			if got := loadBalancerNodeEligible(node); got != test.want {
				t.Fatalf("loadBalancerNodeEligible() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestEnsureLocalLoadBalancerCreatesOnlyExactLocalTargets(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	endpointIndexer := newNamespacedIndexer()
	provider.endpointSliceLister = discoverylisters.NewEndpointSliceLister(endpointIndexer)
	provider.endpointSlicesSynced = func() bool { return true }
	service := testService()
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	if err := endpointIndexer.Add(testEndpointSlice("default", "web", "web-a",
		endpointForNode("worker-b", true, false),
	)); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{
		readyNode("worker-a", "inspace://bkk01/"+testVMUUID),
		readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB),
	}); err != nil {
		t.Fatal(err)
	}
	if len(api.creates) != 1 || len(api.creates[0].Targets) != 1 || api.creates[0].Targets[0].TargetUUID != testVMUUIDB {
		t.Fatalf("created Local targets = %#v", api.creates)
	}
}

func TestTargetControllerReconcilesEndpointMovementReadinessAndTermination(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint discoveryv1.Endpoint
		wantAdd  []string
		wantDrop []string
	}{
		{
			name: "Pod moves to another node", endpoint: endpointForNode("worker-b", true, false),
			wantAdd: []string{testVMUUIDB}, wantDrop: []string{testVMUUID},
		},
		{
			name: "endpoint becomes unready", endpoint: endpointForNode("worker-a", false, false),
			wantDrop: []string{testVMUUID},
		},
		{
			name: "endpoint starts terminating", endpoint: endpointForNode("worker-a", true, true),
			wantDrop: []string{testVMUUID},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			fixture := newTargetControllerFixture(t, provider)
			service := testService()
			service.Spec.Type = corev1.ServiceTypeLoadBalancer
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			markPublicIntentMirrored(service)
			fixture.addService(t, service)
			fixture.addNode(t, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			fixture.addNode(t, readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB))
			fixture.addEndpointSlice(t, testEndpointSlice("default", "web", "web-a", test.endpoint))
			setOwnedLoadBalancer(api, provider, service, []string{testVMUUID})

			if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
				t.Fatal(err)
			}
			if !reflectStrings(api.addedTargets, test.wantAdd) || !reflectStrings(api.removedTargets, test.wantDrop) {
				t.Fatalf("target changes add=%v drop=%v, want add=%v drop=%v", api.addedTargets, api.removedTargets, test.wantAdd, test.wantDrop)
			}
		})
	}
}

func TestTargetControllerReconcilesNodeReadyAddAndDelete(t *testing.T) {
	for _, test := range []struct {
		name           string
		nodes          []*corev1.Node
		currentTargets []string
		wantAdd        []string
		wantDrop       []string
	}{
		{
			name: "Ready becomes false",
			nodes: func() []*corev1.Node {
				a := readyNode("worker-a", "inspace://bkk01/"+testVMUUID)
				b := readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB)
				b.Status.Conditions[0].Status = corev1.ConditionFalse
				return []*corev1.Node{a, b}
			}(),
			currentTargets: []string{testVMUUID, testVMUUIDB}, wantDrop: []string{testVMUUIDB},
		},
		{
			name: "new Ready Karpenter node",
			nodes: []*corev1.Node{
				readyNode("worker-a", "inspace://bkk01/"+testVMUUID),
				readyNode("worker-b", "inspace://bkk01/"+testVMUUIDB),
			},
			currentTargets: []string{testVMUUID}, wantAdd: []string{testVMUUIDB},
		},
		{
			name: "deleted Karpenter node",
			nodes: []*corev1.Node{
				readyNode("worker-a", "inspace://bkk01/"+testVMUUID),
			},
			currentTargets: []string{testVMUUID, testVMUUIDB}, wantDrop: []string{testVMUUIDB},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			fixture := newTargetControllerFixture(t, provider)
			service := testService()
			service.Spec.Type = corev1.ServiceTypeLoadBalancer
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
			markPublicIntentMirrored(service)
			fixture.addService(t, service)
			for _, node := range test.nodes {
				fixture.addNode(t, node)
			}
			setOwnedLoadBalancer(api, provider, service, test.currentTargets)

			if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
				t.Fatal(err)
			}
			if !reflectStrings(api.addedTargets, test.wantAdd) || !reflectStrings(api.removedTargets, test.wantDrop) {
				t.Fatalf("target changes add=%v drop=%v, want add=%v drop=%v", api.addedTargets, api.removedTargets, test.wantAdd, test.wantDrop)
			}
		})
	}
}

func TestTargetControllerSkipsInvalidNodeIdentityAndStillRemovesStaleTargets(t *testing.T) {
	for _, test := range []struct {
		name       string
		providerID string
	}{
		{name: "malformed provider ID", providerID: "foreign://broken"},
		{name: "cross-location provider ID", providerID: "inspace://jkt01/" + testVMUUIDB},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			fixture := newTargetControllerFixture(t, provider)
			service := testService()
			service.Spec.Type = corev1.ServiceTypeLoadBalancer
			markPublicIntentMirrored(service)
			fixture.addService(t, service)
			fixture.addNode(t, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			fixture.addNode(t, readyNode("worker-invalid", test.providerID))
			setOwnedLoadBalancer(api, provider, service, []string{testVMUUIDB, testVMUUIDC})

			if err := fixture.controller.sync(context.Background(), "default/web"); err != nil {
				t.Fatal(err)
			}
			if !reflectStrings(api.addedTargets, []string{testVMUUID}) ||
				!reflectStrings(api.removedTargets, []string{testVMUUIDB, testVMUUIDC}) {
				t.Fatalf("target changes add=%v drop=%v", api.addedTargets, api.removedTargets)
			}
		})
	}
}

func TestTargetControllerEventFiltering(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	fixture := newTargetControllerFixture(t, provider)
	public := testService()
	public.Spec.Type = corev1.ServiceTypeLoadBalancer
	private := testService().DeepCopy()
	private.Name = "private"
	private.UID = "private"
	private.Labels[LabelLoadBalancerScope] = LoadBalancerScopePrivate
	delete(private.Annotations, AnnotationPublicLoadBalancer)
	fixture.addService(t, public)
	fixture.addService(t, private)
	fixture.controller.onServiceAdd(public)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	labelRemoved := public.DeepCopy()
	delete(labelRemoved.Labels, LabelLoadBalancerScope)
	fixture.controller.onServiceUpdate(public, labelRemoved)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	fixture.controller.onServiceUpdate(labelRemoved, public)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	unrelatedServiceUpdate := public.DeepCopy()
	unrelatedServiceUpdate.Labels["example.com/unrelated"] = "changed"
	unrelatedServiceUpdate.Annotations["example.com/unrelated"] = "changed"
	unrelatedServiceUpdate.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.20"}}
	fixture.controller.onServiceUpdate(public, unrelatedServiceUpdate)
	assertQueuedKeys(t, fixture.controller.queue)

	mirroredPublic := public.DeepCopy()
	markPublicIntentMirrored(mirroredPublic)
	fixture.controller.onServiceUpdate(public, mirroredPublic)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	oldNode := readyNode("worker-a", "inspace://bkk01/"+testVMUUID)
	newNode := oldNode.DeepCopy()
	newNode.Status.Conditions[0].Status = corev1.ConditionFalse
	fixture.controller.onNodeUpdate(oldNode, newNode)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	unchanged := oldNode.DeepCopy()
	unchanged.Status.Conditions[0].LastHeartbeatTime = metav1.Now()
	fixture.controller.onNodeUpdate(oldNode, unchanged)
	assertQueuedKeys(t, fixture.controller.queue)

	fixture.controller.onNodeAdd(oldNode)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	fixture.controller.onNodeDelete(oldNode)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	fixture.controller.onNodeDelete(cache.DeletedFinalStateUnknown{Key: oldNode.Name, Obj: oldNode})
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	oldSlice := testEndpointSlice("default", "web", "web-a", endpointForNode("worker-a", true, false))
	fixture.controller.onEndpointSliceAdd(oldSlice)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	addressOnly := oldSlice.DeepCopy()
	addressOnly.Endpoints[0].Addresses = []string{"10.0.0.99"}
	fixture.controller.onEndpointSliceUpdate(oldSlice, addressOnly)
	assertQueuedKeys(t, fixture.controller.queue)

	terminating := oldSlice.DeepCopy()
	terminating.Endpoints[0].Conditions.Terminating = boolPointer(true)
	fixture.controller.onEndpointSliceUpdate(oldSlice, terminating)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	unready := oldSlice.DeepCopy()
	unready.Endpoints[0].Conditions.Ready = boolPointer(false)
	fixture.controller.onEndpointSliceUpdate(unready, oldSlice)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")

	fixture.controller.onEndpointSliceDelete(oldSlice)
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
	fixture.controller.onEndpointSliceDelete(cache.DeletedFinalStateUnknown{Key: "default/web-a", Obj: oldSlice})
	assertQueuedKeys(t, fixture.controller.queue, "default/web")
}

func TestTargetControllerFullResyncHealsEitherPublicMarkerOrTrigger(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	fixture := newTargetControllerFixture(t, provider)
	valid := testService()
	valid.Spec.Type = corev1.ServiceTypeLoadBalancer
	labelOnly := testService().DeepCopy()
	labelOnly.Name = "label-only"
	delete(labelOnly.Annotations, AnnotationPublicLoadBalancer)
	staleTrigger := testService().DeepCopy()
	staleTrigger.Name = "stale-trigger"
	delete(staleTrigger.Labels, LabelLoadBalancerScope)
	delete(staleTrigger.Annotations, AnnotationPublicLoadBalancer)
	markPublicIntentMirrored(staleTrigger)
	private := testService().DeepCopy()
	private.Name = "private"
	private.Labels[LabelLoadBalancerScope] = LoadBalancerScopePrivate
	delete(private.Annotations, AnnotationPublicLoadBalancer)
	for _, service := range []*corev1.Service{valid, labelOnly, staleTrigger, private} {
		fixture.addService(t, service)
	}

	fixture.controller.enqueueAllRelevantServices()
	assertQueuedKeySet(t, fixture.controller.queue,
		"default/web", "default/label-only", "default/stale-trigger",
	)
}

type targetControllerFixture struct {
	controller      *loadBalancerTargetController
	nodeIndexer     cache.Indexer
	serviceIndexer  cache.Indexer
	endpointIndexer cache.Indexer
}

func newTargetControllerFixture(t *testing.T, provider *Provider) *targetControllerFixture {
	t.Helper()
	if provider.kubeClient == nil {
		provider.kubeClient = fake.NewSimpleClientset()
	}
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	serviceIndexer := newNamespacedIndexer()
	endpointIndexer := newNamespacedIndexer()
	controller := &loadBalancerTargetController{
		provider:       provider,
		nodes:          corelisters.NewNodeLister(nodeIndexer),
		services:       corelisters.NewServiceLister(serviceIndexer),
		endpointSlices: discoverylisters.NewEndpointSliceLister(endpointIndexer),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	provider.endpointSliceLister = controller.endpointSlices
	provider.endpointSlicesSynced = func() bool { return true }
	return &targetControllerFixture{
		controller: controller, nodeIndexer: nodeIndexer,
		serviceIndexer: serviceIndexer, endpointIndexer: endpointIndexer,
	}
}

type staticControllerClientBuilder struct {
	client kubernetes.Interface
	err    error
}

func (b staticControllerClientBuilder) Config(string) (*rest.Config, error) {
	return &rest.Config{}, b.err
}

func (b staticControllerClientBuilder) ConfigOrDie(string) *rest.Config { return &rest.Config{} }

func (b staticControllerClientBuilder) Client(string) (kubernetes.Interface, error) {
	return b.client, b.err
}

func (b staticControllerClientBuilder) ClientOrDie(string) kubernetes.Interface { return b.client }

func (f *targetControllerFixture) addNode(t *testing.T, node *corev1.Node) {
	t.Helper()
	if err := f.nodeIndexer.Add(node); err != nil {
		t.Fatal(err)
	}
}

func (f *targetControllerFixture) addService(t *testing.T, service *corev1.Service) {
	t.Helper()
	if err := f.serviceIndexer.Add(service); err != nil {
		t.Fatal(err)
	}
}

func (f *targetControllerFixture) addEndpointSlice(t *testing.T, endpointSlice *discoveryv1.EndpointSlice) {
	t.Helper()
	if err := f.endpointIndexer.Add(endpointSlice); err != nil {
		t.Fatal(err)
	}
}

func newNamespacedIndexer() cache.Indexer {
	return cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
}

func testEndpointSlice(namespace, service, name string, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			Labels: map[string]string{discoveryv1.LabelServiceName: service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
}

func endpointForNode(node string, ready, terminating bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		NodeName:  &node,
		Addresses: []string{"10.0.0.20"},
		Conditions: discoveryv1.EndpointConditions{
			Ready: boolPointer(ready), Terminating: boolPointer(terminating),
		},
	}
}

func endpointWithUnknownReadiness(node string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{NodeName: &node, Addresses: []string{"10.0.0.21"}}
}

func boolPointer(value bool) *bool { return &value }

func markPublicIntentMirrored(service *corev1.Service) {
	if service.Annotations == nil {
		service.Annotations = make(map[string]string)
	}
	service.Annotations[annotationLoadBalancerReconcile] = "true"
}

func setOwnedLoadBalancer(api *fakeAPI, provider *Provider, service *corev1.Service, targets []string) {
	cloudTargets := make([]inspace.LoadBalancerTarget, 0, len(targets))
	for _, uuid := range targets {
		cloudTargets = append(cloudTargets, inspace.LoadBalancerTarget{TargetUUID: uuid, TargetType: "vm"})
	}
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service),
		NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
		Targets: cloudTargets, ForwardingRules: serviceRules(service),
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20",
		BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer", AssignedToPrivateIP: "10.0.0.50",
	}}
}

func reflectStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func assertQueuedKeys(t *testing.T, queue workqueue.TypedRateLimitingInterface[string], want ...string) {
	t.Helper()
	if queue.Len() != len(want) {
		t.Fatalf("queue length = %d, want %d", queue.Len(), len(want))
	}
	for _, expected := range want {
		key, shutdown := queue.Get()
		if shutdown {
			t.Fatal("queue unexpectedly shut down")
		}
		queue.Done(key)
		queue.Forget(key)
		if key != expected {
			t.Fatalf("queued key = %q, want %q", key, expected)
		}
	}
}

func assertQueuedKeySet(t *testing.T, queue workqueue.TypedRateLimitingInterface[string], want ...string) {
	t.Helper()
	wanted := make(map[string]struct{}, len(want))
	for _, key := range want {
		wanted[key] = struct{}{}
	}
	if queue.Len() != len(wanted) {
		t.Fatalf("queue length = %d, want %d", queue.Len(), len(wanted))
	}
	for len(wanted) > 0 {
		key, shutdown := queue.Get()
		if shutdown {
			t.Fatal("queue unexpectedly shut down")
		}
		queue.Done(key)
		queue.Forget(key)
		if _, exists := wanted[key]; !exists {
			t.Fatalf("unexpected queued key %q, want %v", key, wanted)
		}
		delete(wanted, key)
	}
}
