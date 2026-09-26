package cloudprovider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func trafficDistributionValue(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}

// TestNodeLoadBalancerDatapathDefaultsTrafficDistributionToPreferSameNode
// proves that the generated Cilium child keeps traffic on the receiving LB
// node when the user left spec.trafficDistribution empty, while an explicit
// parent preference is copied unchanged.
func TestNodeLoadBalancerDatapathDefaultsTrafficDistributionToPreferSameNode(t *testing.T) {
	for name, test := range map[string]struct {
		parent *string
		want   string
	}{
		"omitted":          {parent: nil, want: corev1.ServiceTrafficDistributionPreferSameNode},
		"explicit empty":   {parent: new(string), want: corev1.ServiceTrafficDistributionPreferSameNode},
		"prefer close":     {parent: ptrTo(corev1.ServiceTrafficDistributionPreferClose), want: corev1.ServiceTrafficDistributionPreferClose},
		"prefer same zone": {parent: ptrTo(corev1.ServiceTrafficDistributionPreferSameZone), want: corev1.ServiceTrafficDistributionPreferSameZone},
		"prefer same node": {parent: ptrTo(corev1.ServiceTrafficDistributionPreferSameNode), want: corev1.ServiceTrafficDistributionPreferSameNode},
	} {
		t.Run(name, func(t *testing.T) {
			service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
			service.Spec.TrafficDistribution = test.parent
			before := trafficDistributionValue(service.Spec.TrafficDistribution)
			datapath := desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), "inlb-0123abcd")
			if got := trafficDistributionValue(datapath.Spec.TrafficDistribution); got != test.want {
				t.Fatalf("child trafficDistribution = %s, want %s", got, test.want)
			}
			if datapath.Spec.TrafficDistribution == service.Spec.TrafficDistribution {
				t.Fatal("child trafficDistribution aliases the parent Service pointer")
			}
			if after := trafficDistributionValue(service.Spec.TrafficDistribution); after != before {
				t.Fatalf("rendering the child mutated the parent trafficDistribution from %s to %s", before, after)
			}
		})
	}
}

func ptrTo(value string) *string {
	return &value
}

// TestNodeLoadBalancerDatapathDriftIncludesTrafficDistribution proves that a
// child written by an older controller (no trafficDistribution) is recognized
// as drifted and converges through the ordinary in-place update.
func TestNodeLoadBalancerDatapathDriftIncludesTrafficDistribution(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "11111111-1111-4111-8111-111111111111", corev1.ProtocolTCP, 443)
	const shard = "inlb-0123abcd"
	legacy := desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), shard)
	legacy.Spec.TrafficDistribution = nil
	if nodeLoadBalancerDatapathMatchesDesired(legacy, service, shard) {
		t.Fatal("a child without the PreferSameNode default is not detected as drift")
	}

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	client := kubefake.NewSimpleClientset(service.DeepCopy(), legacy.DeepCopy())
	provider.kubeClient = client
	controller := &nodeLoadBalancerController{provider: provider}
	updated, err := controller.ensureDatapathService(ctx, service, shard)
	if err != nil {
		t.Fatal(err)
	}
	if got := trafficDistributionValue(updated.Spec.TrafficDistribution); got != corev1.ServiceTrafficDistributionPreferSameNode {
		t.Fatalf("converged child trafficDistribution = %s", got)
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, legacy.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	requireNoServiceDeleteOrCreate(t, client)
	if !nodeLoadBalancerDatapathMatchesDesired(stored, service, shard) {
		t.Fatalf("stored child still drifts after convergence: %#v", stored.Spec)
	}
}

// TestNodeLoadBalancerAggregateSyncConvergesLegacyChildTrafficDistribution
// drives the real sync entrypoint for an established, published Service whose
// child predates the PreferSameNode default. The child must be updated in
// place without ever withdrawing the parent's public status or detaching the
// shard firewall.
func TestNodeLoadBalancerAggregateSyncConvergesLegacyChildTrafficDistribution(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService(
		"aggregate-legacy",
		"33333333-3333-4333-8333-333333333333",
		corev1.ProtocolTCP,
		80,
	)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	client := kubefake.NewSimpleClientset(service.DeepCopy())
	provider.kubeClient = client
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())

	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
		nodes:    corelisters.NewNodeLister(nodeIndexer),
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()
	fixture := aggregateSyncFixture{
		ctx: ctx, provider: provider, controller: controller,
		serviceIndexer: serviceIndexer, nodeIndexer: nodeIndexer,
	}
	key := service.Namespace + "/" + service.Name
	fixture.syncUntil(t, []string{key}, 24, func() bool {
		return fixture.service(t, service.Name).Annotations[annotationNodeLoadBalancerShard] != ""
	}, nil)
	shard := fixture.service(t, service.Name).Annotations[annotationNodeLoadBalancerShard]
	node := readyNode("aggregate-legacy-lb-0", "inspace://bkk01/aaaaaaaa-1111-4222-8333-cccccccccccc")
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   shard,
	}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	if _, err := provider.kubeClient.CoreV1().Nodes().Create(ctx, node.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	fixture.syncUntil(t, []string{key}, 48, func() bool {
		return fixture.servicePublished(t, service.Name) && fixture.shardPolicyStable(t, shard, 1)
	}, nil)

	// Simulate a child created by a controller release that copied an empty
	// parent trafficDistribution verbatim.
	children := provider.kubeClient.CoreV1().Services(service.Namespace)
	child, err := children.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child.Spec.TrafficDistribution = nil
	if _, err := children.Update(ctx, child, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	fixture.refreshListers(t)
	client.ClearActions()
	assignmentsBefore := len(api.assignedFirewalls)

	fixture.syncUntil(t, []string{key}, 16, func() bool {
		current, getErr := children.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		return trafficDistributionValue(current.Spec.TrafficDistribution) == corev1.ServiceTrafficDistributionPreferSameNode &&
			fixture.servicePublished(t, service.Name)
	}, func() {
		if !fixture.servicePublished(t, service.Name) {
			current := fixture.service(t, service.Name)
			t.Fatalf("legacy child convergence withdrew the published Service: annotations=%#v status=%#v",
				current.Annotations, current.Status.LoadBalancer)
		}
	})
	requireNoServiceDeleteOrCreate(t, client)
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("legacy child convergence detached a firewall: %#v", api.unassignedFirewalls)
	}
	if got := len(api.assignedFirewalls); got != assignmentsBefore {
		t.Fatalf("legacy child convergence reattached a firewall: before=%d after=%d", assignmentsBefore, got)
	}
}

// requireNoServiceDeleteOrCreate proves a child was repaired by an in-place
// update rather than a delete/recreate that would briefly remove its frontend.
func requireNoServiceDeleteOrCreate(t *testing.T, client *kubefake.Clientset) {
	t.Helper()
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "services" && (action.GetVerb() == "delete" || action.GetVerb() == "create") {
			t.Fatalf("trafficDistribution convergence issued a Service %s: %#v", action.GetVerb(), action)
		}
	}
}
