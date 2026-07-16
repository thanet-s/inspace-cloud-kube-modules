package cloudprovider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// TestNodeLoadBalancerAggregateSyncExpandsEstablishedSharedShardInPlace drives
// the real controller sync entrypoint through first-Service publication and a
// later non-conflicting shared sibling. It deliberately refreshes the listers
// from the fake API server after every sync, matching informer observation
// boundaries instead of directly invoking the aggregate-firewall helpers.
func TestNodeLoadBalancerAggregateSyncExpandsEstablishedSharedShardInPlace(t *testing.T) {
	ctx := context.Background()
	first := nodeLoadBalancerTestService(
		"aggregate-first",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(first.DeepCopy())
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())

	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(first.DeepCopy()); err != nil {
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
	firstKey := first.Namespace + "/" + first.Name
	fixture.syncUntil(t, []string{firstKey}, 24, func() bool {
		stored := fixture.service(t, first.Name)
		shard := stored.Annotations[annotationNodeLoadBalancerShard]
		if shard == "" {
			return false
		}
		_, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		return err == nil
	}, nil)

	storedFirst := fixture.service(t, first.Name)
	shard := storedFirst.Annotations[annotationNodeLoadBalancerShard]
	const vmUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	node := readyNode("aggregate-lb-0", "inspace://bkk01/"+vmUUID)
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

	fixture.syncUntil(t, []string{firstKey}, 48, func() bool {
		return fixture.servicePublished(t, first.Name) && fixture.shardPolicyStable(t, shard, 1)
	}, nil)

	poolBefore, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	poolUIDBefore := poolBefore.GetUID()
	if poolUIDBefore == "" {
		t.Fatal("established NodePool has no identity")
	}
	firewallUUID := poolBefore.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID]
	if firewallUUID == "" {
		t.Fatal("established NodePool has no stable shard firewall UUID")
	}
	if got := fixture.countShardFirewalls(t, shard); got != 1 {
		t.Fatalf("established shard firewalls = %d, want 1", got)
	}
	if got := fixture.firewallRuleCount(t, firewallUUID); got != 1 {
		t.Fatalf("established shard firewall rule count = %d, want 1", got)
	}
	assignmentsBefore := len(api.assignedFirewalls)
	updatesBefore := len(api.updatedFirewalls)
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("first-Service activation detached a firewall: %#v", api.unassignedFirewalls)
	}

	sibling := nodeLoadBalancerTestService(
		"aggregate-sibling",
		"22222222-2222-4222-8222-222222222222",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := provider.kubeClient.CoreV1().Services(sibling.Namespace).Create(
		ctx, sibling.DeepCopy(), metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := serviceIndexer.Add(sibling.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	siblingKey := sibling.Namespace + "/" + sibling.Name
	fixture.syncUntil(t, []string{siblingKey, firstKey}, 64, func() bool {
		storedSibling := fixture.service(t, sibling.Name)
		return storedSibling.Annotations[annotationNodeLoadBalancerShard] == shard &&
			fixture.servicePublished(t, sibling.Name) &&
			fixture.shardPolicyStable(t, shard, 2)
	}, func() {
		// An aggregate expansion is allowed to keep the new sibling private,
		// but must never withdraw the already-covered Service.
		if !fixture.servicePublished(t, first.Name) {
			current := fixture.service(t, first.Name)
			t.Fatalf("established Service lost public status during sibling expansion: annotations=%#v status=%#v", current.Annotations, current.Status.LoadBalancer)
		}
	})

	poolAfter, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if poolAfter.GetUID() != poolUIDBefore {
		t.Fatalf("NodePool identity changed from %q to %q", poolUIDBefore, poolAfter.GetUID())
	}
	if got := poolAfter.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID]; got != firewallUUID {
		t.Fatalf("shard firewall identity changed from %q to %q", firewallUUID, got)
	}
	pools, err := provider.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pools.Items) != 1 || pools.Items[0].GetName() != shard {
		t.Fatalf("shared expansion created replacement capacity: %#v", pools.Items)
	}
	nodes, err := provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes.Items) != 1 || nodes.Items[0].Spec.ProviderID != node.Spec.ProviderID {
		t.Fatalf("shared expansion changed VM identity: %#v", nodes.Items)
	}
	if got := fixture.countShardFirewalls(t, shard); got != 1 {
		t.Fatalf("shared expansion left %d shard firewalls, want 1", got)
	}
	if got := fixture.firewallRuleCount(t, firewallUUID); got != 2 {
		t.Fatalf("expanded shard firewall rule count = %d, want 2", got)
	}
	if got := len(api.updatedFirewalls) - updatesBefore; got != 1 {
		t.Fatalf("aggregate expansion PUT count = %d, want exactly 1", got)
	}
	updatedRules := aggregateTestRulesByKey(api.updatedFirewalls[len(api.updatedFirewalls)-1].Rules)
	if len(updatedRules) != 2 || updatedRules["tcp/80"].UUID == "" || updatedRules["tcp/443"].UUID != "" {
		t.Fatalf("aggregate PUT did not retain the old rule and add the sibling rule in place: %#v", updatedRules)
	}
	if got := len(api.assignedFirewalls); got != assignmentsBefore {
		t.Fatalf("shared expansion reattached the stable firewall: before=%d after=%d calls=%#v", assignmentsBefore, got, api.assignedFirewalls)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("shared expansion detached a firewall: %#v", api.unassignedFirewalls)
	}
	if !fixture.servicePublished(t, first.Name) || !fixture.servicePublished(t, sibling.Name) {
		t.Fatal("one or both shared Services are not published after aggregate convergence")
	}
}

type aggregateSyncFixture struct {
	ctx            context.Context
	provider       *Provider
	controller     *nodeLoadBalancerController
	serviceIndexer cache.Indexer
	nodeIndexer    cache.Indexer
}

func (f *aggregateSyncFixture) syncUntil(
	t *testing.T,
	keys []string,
	limit int,
	converged func() bool,
	afterEach func(),
) {
	t.Helper()
	for attempt := 0; attempt < limit; attempt++ {
		for _, key := range keys {
			if err := f.controller.sync(f.ctx, key); err != nil {
				t.Fatalf("sync %s attempt %d: %v", key, attempt, err)
			}
			f.refreshListers(t)
			if afterEach != nil {
				afterEach()
			}
			if converged() {
				return
			}
		}
	}
	t.Fatalf("controller did not converge after %d attempts for keys %#v", limit, keys)
}

func (f *aggregateSyncFixture) refreshListers(t *testing.T) {
	t.Helper()
	services, err := f.provider.kubeClient.CoreV1().Services("").List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range services.Items {
		if err := f.serviceIndexer.Update(services.Items[index].DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := f.provider.kubeClient.CoreV1().Nodes().List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range nodes.Items {
		if err := f.nodeIndexer.Update(nodes.Items[index].DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *aggregateSyncFixture) service(t *testing.T, name string) *corev1.Service {
	t.Helper()
	service, err := f.provider.kubeClient.CoreV1().Services("default").Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (f *aggregateSyncFixture) servicePublished(t *testing.T, name string) bool {
	t.Helper()
	service := f.service(t, name)
	return len(service.Status.LoadBalancer.Ingress) == 1 &&
		service.Status.LoadBalancer.Ingress[0].IP == "203.0.113.10" &&
		service.Status.LoadBalancer.Ingress[0].IPMode != nil &&
		*service.Status.LoadBalancer.Ingress[0].IPMode == corev1.LoadBalancerIPModeProxy
}

func (f *aggregateSyncFixture) shardPolicyStable(t *testing.T, shard string, wantMembers int) bool {
	t.Helper()
	pool, err := f.provider.dynamicClient.Resource(nodePoolGVR).Get(f.ctx, shard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFirewallUUID] == "" ||
		annotations[annotationNodeLoadBalancerShardFirewallHash] == "" ||
		annotations[annotationNodeLoadBalancerShardFWPendingHash] != "" {
		return false
	}
	ledger, err := parseNodeLoadBalancerShardFirewallLedger(annotations[annotationNodeLoadBalancerShardFirewallLedger])
	if err != nil {
		return false
	}
	return len(ledger) == wantMembers
}

func (f *aggregateSyncFixture) countShardFirewalls(t *testing.T, shard string) int {
	t.Helper()
	name, err := inspace.NodeLoadBalancerShardFirewallName(f.provider.config.ClusterID, shard)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, firewall := range f.provider.api.(*fakeAPI).firewalls {
		if firewall.EffectiveName() == name {
			count++
		}
	}
	return count
}

func (f *aggregateSyncFixture) firewallRuleCount(t *testing.T, uuid string) int {
	t.Helper()
	for _, firewall := range f.provider.api.(*fakeAPI).firewalls {
		if firewall.UUID == uuid {
			return len(firewall.Rules)
		}
	}
	t.Fatalf("firewall %s is absent", uuid)
	return 0
}
