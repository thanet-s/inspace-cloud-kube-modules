package cloudprovider

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestManagedNodeClassEnsureAddsAndPreservesClusterStateFinalizer(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset()
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	desired := managedNodeClassAnchorFixture(t, provider, nil, false)
	if !containsString(desired.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		t.Fatalf("managed desired NodeClass finalizers = %#v", desired.GetFinalizers())
	}

	stored := desired.DeepCopy()
	stored.SetFinalizers([]string{"karpenter.inspace.cloud/termination"})
	client := newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass(), stored)
	provider.dynamicClient = client
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.ensureNodeClass(ctx, nodeClassName); err != nil {
		t.Fatal(err)
	}
	got, err := client.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(got.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) ||
		!containsString(got.GetFinalizers(), "karpenter.inspace.cloud/termination") {
		t.Fatalf("ensure replaced or omitted NodeClass finalizers: %#v", got.GetFinalizers())
	}

	updates := nodeClassAnchorActionCount(client, "update", nodeClassGVR.Resource)
	if updates != 1 {
		t.Fatalf("first ensure NodeClass updates = %d, want 1", updates)
	}
	if err := controller.ensureNodeClass(ctx, nodeClassName); err != nil {
		t.Fatal(err)
	}
	if got := nodeClassAnchorActionCount(client, "update", nodeClassGVR.Resource); got != updates {
		t.Fatalf("idempotent NodeClass ensure issued another update: before=%d after=%d", updates, got)
	}
}

func TestDeletingManagedNodeClassRetainsCurrentOrPendingLedgerWithoutRecreate(t *testing.T) {
	const firewallUUID = "11111111-1111-4111-8111-111111111111"
	tests := map[string]struct {
		annotations map[string]string
		cloudExists bool
		wantDeletes int
		wantErr     string
	}{
		"current": {
			annotations: map[string]string{annotationNodeLoadBalancerICMPFirewallUUID: firewallUUID},
			cloudExists: true,
			wantDeletes: 1,
		},
		"pending": {
			annotations: map[string]string{
				annotationNodeLoadBalancerICMPPendingUUID:    firewallUUID,
				annotationNodeLoadBalancerICMPPendingName:    "desired",
				annotationNodeLoadBalancerICMPPendingStarted: time.Now().UTC().Format(time.RFC3339Nano),
				annotationNodeLoadBalancerICMPCreateIssued:   time.Now().UTC().Format(time.RFC3339Nano),
			},
			wantErr: "remains ambiguous during cleanup",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
				Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
			}
			provider.kubeClient = kubefake.NewSimpleClientset()
			desired, err := desiredNodeLoadBalancerClusterICMPFirewall(
				provider.config.ClusterID,
				provider.config.BillingAccountID,
			)
			if err != nil {
				t.Fatal(err)
			}
			annotations := make(map[string]string, len(test.annotations))
			for key, value := range test.annotations {
				if key == annotationNodeLoadBalancerICMPPendingName && value == "desired" {
					value = desired.Request.DisplayName
				}
				annotations[key] = value
			}
			if test.cloudExists {
				api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, firewallUUID)}
			}
			nodeClass := managedNodeClassAnchorFixture(t, provider, annotations, true)
			provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
				nodeLoadBalancerSafetyBaseNodeClass(), nodeClass,
			)
			controller := &nodeLoadBalancerController{provider: provider}
			nodeClassName := nodeClass.GetName()

			deleting, err := controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
			if !deleting || (test.wantErr == "" && err != nil) || (test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr))) {
				t.Fatalf("deleting NodeClass reconcile = deleting %t, err=%v", deleting, err)
			}
			stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("deleting NodeClass state anchor disappeared: %v", err)
			}
			if stored.GetUID() != nodeClass.GetUID() ||
				!containsString(stored.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
				t.Fatalf("deleting NodeClass lost durable identity: uid=%q finalizers=%#v", stored.GetUID(), stored.GetFinalizers())
			}
			for key, want := range annotations {
				if got := stored.GetAnnotations()[key]; got != want {
					t.Fatalf("deleting NodeClass ledger %s = %q, want %q", key, got, want)
				}
			}
			if got := len(api.deletedFirewalls); got != test.wantDeletes {
				t.Fatalf("deleting NodeClass firewall deletes = %d, want %d (%#v)", got, test.wantDeletes, api.deletedFirewalls)
			}
			if err := controller.ensureNodeClass(ctx, nodeClassName); err == nil || !strings.Contains(err.Error(), "still deleting") {
				t.Fatalf("ensure accepted deleting NodeClass: %v", err)
			}
			if len(api.createdFirewalls) != 0 {
				t.Fatalf("deleting NodeClass ledger caused duplicate firewall creates: %#v", api.createdFirewalls)
			}
			deleting, err = controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
			if !deleting || (test.wantErr == "" && err != nil) || (test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr))) {
				t.Fatalf("restarted deletion reconcile = deleting %t, err=%v", deleting, err)
			}
			if len(api.createdFirewalls) != 0 || len(api.deletedFirewalls) != test.wantDeletes {
				t.Fatalf(
					"restarted deletion duplicated cloud mutation: creates=%#v deletes=%#v",
					api.createdFirewalls,
					api.deletedFirewalls,
				)
			}
			stored, err = provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if err != nil || stored.GetUID() != nodeClass.GetUID() {
				t.Fatalf("ensure replaced deleting NodeClass: uid=%q err=%v", stored.GetUID(), err)
			}
		})
	}
}

func TestExternalNodeClassDeletionDrainsShardAndProvesClusterCleanupBeforeFinalizing(t *testing.T) {
	ctx := context.Background()
	const (
		shard             = "inlb-89abcdef"
		shardFirewallUUID = "22222222-2222-4222-8222-222222222222"
		icmpFirewallUUID  = "33333333-3333-4333-8333-333333333333"
	)
	service := nodeLoadBalancerTestService(
		"nodeclass-delete-owner",
		"44444444-4444-4444-8444-444444444444",
		corev1.ProtocolTCP,
		443,
	)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = shard

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())

	plan := nodeLoadBalancerShardPlan{
		Name: shard, Claims: []string{string(service.UID)},
		Ports: nodeLoadBalancerPortClaimsOrFatal(t, service),
	}
	policy, err := desiredNodeLoadBalancerShardFirewall(
		provider.config.ClusterID,
		provider.config.BillingAccountID,
		plan,
		[]*corev1.Service{service},
	)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(policy)
	if err != nil {
		t.Fatal(err)
	}
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared,
		nodeLoadBalancerDefaultPool,
		1,
		nodeLoadBalancerDefaultCPU,
		nodeLoadBalancerDefaultMemoryMiB,
	)
	pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1)
	pool.SetAnnotations(map[string]string{
		annotationNodeLoadBalancerShardFirewallUUID:   shardFirewallUUID,
		annotationNodeLoadBalancerShardFirewallHash:   policy.Hash,
		annotationNodeLoadBalancerShardFirewallLedger: ledger,
	})
	desiredICMP, err := desiredNodeLoadBalancerClusterICMPFirewall(
		provider.config.ClusterID,
		provider.config.BillingAccountID,
	)
	if err != nil {
		t.Fatal(err)
	}
	nodeClass := managedNodeClassAnchorFixture(t, provider, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: icmpFirewallUUID,
	}, true)
	api.firewalls = []inspace.Firewall{
		aggregateTestFirewall(policy, shardFirewallUUID),
		clusterICMPSafetyFirewall(desiredICMP, icmpFirewallUUID),
	}
	dynamicClient := newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyBaseNodeClass(), nodeClass, pool,
	)
	preserveFinalizedDynamicDeletion(t, dynamicClient, nodePoolGVR)
	provider.dynamicClient = dynamicClient
	emptyNodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	controller := &nodeLoadBalancerController{
		provider: provider,
		nodes:    corelisters.NewNodeLister(emptyNodeIndexer),
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()
	nodeClassName := nodeClass.GetName()
	proofObservedBeforeFinalizerRemoval := observeClusterProofBeforeNodeClassFinalizerRemoval(
		t, dynamicClient, provider, service.Namespace, service.Name,
	)

	deleting, err := controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
	if err != nil || !deleting {
		t.Fatalf("initial external deletion reconcile = deleting %t, err=%v", deleting, err)
	}
	if len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != shardFirewallUUID {
		t.Fatalf("external deletion did not start with shard firewall drain: %#v", api.deletedFirewalls)
	}
	requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)

	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			ageDynamicAnchorAnnotation(
				t, ctx, dynamicClient, nodePoolGVR, shard,
				annotationNodeLoadBalancerShardFWCleanupCheck,
			)
		}
		deleting, err = controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
		if err != nil || !deleting {
			t.Fatalf("shard absence confirmation %d = deleting %t, err=%v", confirmation, deleting, err)
		}
		storedPool, getErr := dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if confirmation < nodeLoadBalancerAbsenceConfirmations {
			if !containsString(storedPool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
				t.Fatalf("shard anchor finalized after only %d confirmations", confirmation)
			}
		} else if containsString(storedPool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			t.Fatalf("shard anchor retained after durable absence: %#v", storedPool.GetFinalizers())
		}
		requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)
	}
	storedService := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if !aggregateShardCleanupWasProven(storedService.Annotations[annotationNodeLoadBalancerShardCleanupProven], shard) {
		t.Fatalf("shard cleanup handoff was not persisted: %#v", storedService.Annotations)
	}
	if storedService.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "" {
		t.Fatalf("cluster cleanup was claimed before ICMP cleanup: %#v", storedService.Annotations)
	}
	if err := dynamicClient.Tracker().Delete(nodePoolGVR, "", shard); err != nil {
		t.Fatal(err)
	}

	deleting, err = controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
	if err != nil || !deleting {
		t.Fatalf("cluster ICMP delete reconcile = deleting %t, err=%v", deleting, err)
	}
	if len(api.deletedFirewalls) != 2 || api.deletedFirewalls[1] != icmpFirewallUUID {
		t.Fatalf("cluster ICMP firewall was not deleted after capacity drain: %#v", api.deletedFirewalls)
	}
	requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)

	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			ageDynamicAnchorAnnotation(
				t, ctx, dynamicClient, nodeClassGVR, nodeClassName,
				annotationNodeLoadBalancerICMPCleanupChecked,
			)
		}
		deleting, err = controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
		if err != nil || !deleting {
			t.Fatalf("ICMP absence confirmation %d = deleting %t, err=%v", confirmation, deleting, err)
		}
		requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)
	}

	deleting, err = controller.reconcileDeletingAggregateNodeClass(ctx, nodeClassName)
	if err != nil || !deleting {
		t.Fatalf("proven cluster cleanup reconcile = deleting %t, err=%v", deleting, err)
	}
	requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, false)
	storedService = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if storedService.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "true" {
		t.Fatalf("cluster cleanup handoff is absent: %#v", storedService.Annotations)
	}
	if !*proofObservedBeforeFinalizerRemoval {
		t.Fatal("NodeClass finalizer was removed before Service cluster-cleanup proof was observable")
	}
	if len(api.createdFirewalls) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("external deletion recreated or retained cloud firewalls: creates=%#v firewalls=%#v", api.createdFirewalls, api.firewalls)
	}
}

func TestAggregateClusterCleanupRejectsMissingNodeClassWithoutServiceProof(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService(
		"missing-nodeclass",
		"55555555-5555-4555-8555-555555555555",
		corev1.ProtocolTCP,
		443,
	)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerClusterStateMaterial] = "true"
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt

	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	controller := &nodeLoadBalancerController{provider: provider}

	done, err := controller.cleanupAggregateClusterState(
		ctx,
		service,
		managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb"),
	)
	if err == nil || done || !strings.Contains(err.Error(), "without persisted cluster-firewall cleanup proof") {
		t.Fatalf("missing NodeClass cleanup = done %t, err=%v", done, err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) ||
		stored.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "" {
		t.Fatalf("missing NodeClass finalized or fabricated proof: %#v", stored.ObjectMeta)
	}
}

func TestLastAggregateServiceDeletesAndFinalizesManagedNodeClassSafely(t *testing.T) {
	ctx := context.Background()
	const icmpFirewallUUID = "66666666-6666-4666-8666-666666666666"
	service := nodeLoadBalancerTestService(
		"last-nodeclass-owner",
		"77777777-7777-4777-8777-777777777777",
		corev1.ProtocolTCP,
		443,
	)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	desiredICMP, err := desiredNodeLoadBalancerClusterICMPFirewall(
		provider.config.ClusterID,
		provider.config.BillingAccountID,
	)
	if err != nil {
		t.Fatal(err)
	}
	nodeClass := managedNodeClassAnchorFixture(t, provider, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: icmpFirewallUUID,
	}, false)
	api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desiredICMP, icmpFirewallUUID)}
	dynamicClient := newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyBaseNodeClass(), nodeClass,
	)
	preserveFinalizedDynamicDeletion(t, dynamicClient, nodeClassGVR)
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{
		provider: provider,
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()
	nodeClassName := nodeClass.GetName()
	proofObservedBeforeFinalizerRemoval := observeClusterProofBeforeNodeClassFinalizerRemoval(
		t, dynamicClient, provider, service.Namespace, service.Name,
	)

	if err := controller.cleanupAggregateService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != icmpFirewallUUID {
		t.Fatalf("last owner did not delete cluster ICMP firewall first: %#v", api.deletedFirewalls)
	}
	requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)
	requireServiceFinalizer(t, ctx, provider, service.Namespace, service.Name, true)

	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			ageDynamicAnchorAnnotation(
				t, ctx, dynamicClient, nodeClassGVR, nodeClassName,
				annotationNodeLoadBalancerICMPCleanupChecked,
			)
		}
		current := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if err := controller.cleanupAggregateService(ctx, current); err != nil {
			t.Fatalf("last owner ICMP absence confirmation %d: %v", confirmation, err)
		}
		requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, true)
		requireServiceFinalizer(t, ctx, provider, service.Namespace, service.Name, true)
	}

	current := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if err := controller.cleanupAggregateService(ctx, current); err != nil {
		t.Fatalf("last owner proven cluster cleanup: %v", err)
	}
	storedNodeClass, err := dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if storedNodeClass.GetDeletionTimestamp() == nil ||
		!containsString(storedNodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		t.Fatalf("normal cleanup did not retain deleting NodeClass handoff: %#v", storedNodeClass.Object["metadata"])
	}
	current = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if current.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "true" {
		t.Fatalf("normal cleanup deleted NodeClass before persisting Service proof: %#v", current.Annotations)
	}

	if err := controller.cleanupAggregateService(ctx, current); err != nil {
		t.Fatalf("normal NodeClass finalizer release: %v", err)
	}
	requireManagedNodeClassFinalizer(t, ctx, provider, nodeClassName, false)
	if !*proofObservedBeforeFinalizerRemoval {
		t.Fatal("normal cleanup removed NodeClass finalizer before Service proof was observable")
	}
	if err := dynamicClient.Tracker().Delete(nodeClassGVR, "", nodeClassName); err != nil {
		t.Fatal(err)
	}
	current = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if err := controller.cleanupAggregateService(ctx, current); err != nil {
		t.Fatalf("last owner finalization after NodeClass disappearance: %v", err)
	}
	requireServiceFinalizer(t, ctx, provider, service.Namespace, service.Name, false)
	current = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if current.Annotations[annotationNodeLoadBalancerClusterCleanupProven] != "" {
		t.Fatalf("finalized Service retained cluster-cleanup proof: %#v", current.Annotations)
	}
	if _, err := dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("managed NodeClass survived finalization: %v", err)
	}
	if len(api.createdFirewalls) != 0 || len(api.deletedFirewalls) != 1 {
		t.Fatalf("normal cleanup duplicated cloud mutation: creates=%#v deletes=%#v", api.createdFirewalls, api.deletedFirewalls)
	}
}

func TestAggregateCleanupBackfillsLegacyLiveNodeClassStateAnchor(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService(
		"legacy-nodeclass-cleanup",
		"78787878-7878-4787-8787-787878787878",
		corev1.ProtocolTCP,
		8443,
	)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	nodeClass := managedNodeClassAnchorFixture(t, provider, nil, false)
	nodeClass.SetFinalizers(removeString(nodeClass.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer))
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyBaseNodeClass(), nodeClass,
	)
	controller := &nodeLoadBalancerController{provider: provider}

	done, err := controller.cleanupAggregateClusterState(ctx, service, nodeClass.GetName())
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("legacy NodeClass cleanup completed before cloud absence proof")
	}
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClass.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(stored.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		t.Fatalf("legacy live NodeClass finalizer was not backfilled: %#v", stored.GetFinalizers())
	}
	current := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if current.Annotations[annotationNodeLoadBalancerClusterStateMaterial] != "true" {
		t.Fatalf("legacy NodeClass backfill lacked Service materialization handoff: %#v", current.Annotations)
	}
}

func managedNodeClassAnchorFixture(
	t *testing.T,
	provider *Provider,
	annotations map[string]string,
	deleting bool,
) *unstructured.Unstructured {
	t.Helper()
	name := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	object, err := renderNodeLoadBalancerNodeClass(nodeLoadBalancerSafetyBaseNodeClass(), name)
	if err != nil {
		t.Fatal(err)
	}
	if err := markNodeLoadBalancerManaged(object, provider.config.ClusterID, "", ""); err != nil {
		t.Fatal(err)
	}
	object.SetUID(types.UID("nodeclass-" + shortNodeLoadBalancerHash(name)))
	if annotations != nil {
		copy := make(map[string]string, len(annotations))
		for key, value := range annotations {
			copy[key] = value
		}
		object.SetAnnotations(copy)
	}
	if deleting {
		now := metav1.Now()
		object.SetDeletionTimestamp(&now)
	}
	return object
}

func preserveFinalizedDynamicDeletion(
	t *testing.T,
	client *dynamicfake.FakeDynamicClient,
	gvr schema.GroupVersionResource,
) {
	t.Helper()
	client.PrependReactor("delete", gvr.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteAction, ok := action.(k8stesting.DeleteAction)
		if !ok {
			return false, nil, nil
		}
		object, getErr := client.Tracker().Get(gvr, action.GetNamespace(), deleteAction.GetName())
		if apierrors.IsNotFound(getErr) {
			return true, nil, nil
		}
		if getErr != nil {
			return true, nil, getErr
		}
		anchor, ok := object.(*unstructured.Unstructured)
		if !ok || len(anchor.GetFinalizers()) == 0 {
			return false, nil, nil
		}
		copy := anchor.DeepCopy()
		if copy.GetDeletionTimestamp() == nil {
			now := metav1.Now()
			copy.SetDeletionTimestamp(&now)
		}
		return true, nil, client.Tracker().Update(gvr, copy, action.GetNamespace())
	})
}

func observeClusterProofBeforeNodeClassFinalizerRemoval(
	t *testing.T,
	client *dynamicfake.FakeDynamicClient,
	provider *Provider,
	namespace, name string,
) *bool {
	t.Helper()
	observed := false
	client.PrependReactor("update", nodeClassGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := update.GetObject().(*unstructured.Unstructured)
		if !ok || containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
			return false, nil, nil
		}
		service, getErr := provider.kubeClient.CoreV1().Services(namespace).Get(
			context.Background(), name, metav1.GetOptions{},
		)
		if getErr == nil && service.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "true" {
			observed = true
		}
		return false, nil, nil
	})
	return &observed
}

func ageDynamicAnchorAnnotation(
	t *testing.T,
	ctx context.Context,
	client *dynamicfake.FakeDynamicClient,
	gvr schema.GroupVersionResource,
	name, annotation string,
) {
	t.Helper()
	object, err := client.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	values := object.GetAnnotations()
	if values == nil {
		values = map[string]string{}
	}
	values[annotation] = time.Now().Add(-2 * nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano)
	object.SetAnnotations(values)
	if _, err := client.Resource(gvr).Update(ctx, object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func requireManagedNodeClassFinalizer(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	name string,
	want bool,
) {
	t.Helper()
	object, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer); got != want {
		t.Fatalf("NodeClass cluster-state finalizer present = %t, want %t; finalizers=%#v", got, want, object.GetFinalizers())
	}
}

func requireServiceFinalizer(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	namespace, name string,
	want bool,
) {
	t.Helper()
	service := getNodeLoadBalancerTestService(t, ctx, provider, namespace, name)
	if got := containsString(service.Finalizers, nodeLoadBalancerFinalizer); got != want {
		t.Fatalf("Service Node-LB finalizer present = %t, want %t; finalizers=%#v", got, want, service.Finalizers)
	}
}

func nodeClassAnchorActionCount(client *dynamicfake.FakeDynamicClient, verb, resource string) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == verb && action.GetResource().Resource == resource {
			count++
		}
	}
	return count
}
