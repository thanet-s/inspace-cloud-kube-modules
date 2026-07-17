package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestRetainedShardVMIdentitiesSkipsFreshClaimWithoutProviderID(t *testing.T) {
	const (
		shard        = "inlb-89abcdef"
		validVMUUID  = "11111111-2222-4333-8444-555555555555"
		validClaimID = "nodeclaim-valid"
		freshClaimID = "nodeclaim-fresh"
	)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared,
		nodeLoadBalancerDefaultPool,
		1,
		nodeLoadBalancerDefaultCPU,
		nodeLoadBalancerDefaultMemoryMiB,
	)
	pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1)
	valid := retainedIdentityTestNodeClaim(
		shard, provider.config.ClusterID, nodeClassName, pool,
		shard+"-valid", validClaimID, "inspace://bkk01/"+validVMUUID,
	)
	fresh := retainedIdentityTestNodeClaim(
		shard, provider.config.ClusterID, nodeClassName, pool,
		shard+"-fresh", freshClaimID, "",
	)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool, valid, fresh)
	controller := &nodeLoadBalancerController{provider: provider}

	identities, err := controller.retainedShardVMIdentities(context.Background(), shard)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{}{validVMUUID: {}}
	if !reflect.DeepEqual(identities, want) {
		t.Fatalf("retained VM identities = %#v, want %#v", identities, want)
	}

	malformed := retainedIdentityTestNodeClaim(
		shard, provider.config.ClusterID, nodeClassName, pool,
		shard+"-malformed", "nodeclaim-malformed", "inspace://bkk01/not-a-uuid",
	)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool, valid, fresh, malformed)
	identities, err = controller.retainedShardVMIdentities(context.Background(), shard)
	if err == nil || !strings.Contains(err.Error(), "invalid retention providerID") {
		t.Fatalf("malformed present providerID error = %v", err)
	}
	if identities != nil {
		t.Fatalf("malformed present providerID returned partial identities: %#v", identities)
	}
}

func TestAggregateStatusEmptyMaterializedShardCannotBeReassignedAfterAnchorLoss(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-materialized-anchor-loss",
		"81818181-8181-4181-8181-818181818181",
		corev1.ProtocolTCP,
		9443,
	))
	defer harness.controller.queue.ShutDown()
	service := harness.service(t)
	if len(service.Status.LoadBalancer.Ingress) != 0 ||
		!aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], harness.shard) {
		t.Fatalf("fixture is not status-empty materialized state: status=%#v annotations=%#v", service.Status.LoadBalancer, service.Annotations)
	}
	dynamicClient, ok := harness.provider.dynamicClient.(interface {
		Tracker() k8stesting.ObjectTracker
	})
	if !ok {
		t.Fatalf("test dynamic client has no tracker: %T", harness.provider.dynamicClient)
	}
	if err := dynamicClient.Tracker().Delete(nodePoolGVR, "", harness.shard); err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	if _, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)

	err := harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "get established shard anchor") {
		t.Fatalf("missing materialized shard anchor error = %v", err)
	}
	current := harness.service(t)
	if current.Annotations[annotationNodeLoadBalancerShard] != harness.shard ||
		current.Annotations[annotationNodeLoadBalancerPreviousShard] != "" ||
		!aggregateShardStateWasMaterialized(current.Annotations[annotationNodeLoadBalancerShardStateMaterial], harness.shard) {
		t.Fatalf("anchor loss rewrote the last durable shard reference: %#v", current.Annotations)
	}
}

func TestAggregateMarkerOnlyShardReferenceFailsClosedBeforeReassignment(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-marker-only-shard",
		"81818181-8181-4181-8282-818181818181",
		corev1.ProtocolTCP,
		9543,
	))
	defer harness.controller.queue.ShutDown()
	service := harness.service(t)
	if !aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], harness.shard) {
		t.Fatalf("fixture lacks materialized shard marker: %#v", service.Annotations)
	}
	delete(service.Annotations, annotationNodeLoadBalancerShard)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	if _, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)
	poolsBefore, err := harness.provider.dynamicClient.Resource(nodePoolGVR).List(harness.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "lost every explicit Service reference") {
		t.Fatalf("marker-only shard drift error = %v", err)
	}
	current := harness.service(t)
	if current.Annotations[annotationNodeLoadBalancerShard] != "" ||
		!aggregateServiceReferencesShard(current, harness.shard) {
		t.Fatalf("marker-only durable reference was rewritten or ignored: %#v", current.Annotations)
	}
	poolsAfter, err := harness.provider.dynamicClient.Resource(nodePoolGVR).List(harness.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(poolsAfter.Items) != len(poolsBefore.Items) {
		t.Fatalf("marker-only drift created replacement capacity: pools before=%d after=%d", len(poolsBefore.Items), len(poolsAfter.Items))
	}
}

func TestAggregateDeletionCleansMarkerOnlyMaterializedShard(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-marker-only-delete",
		"81818181-8181-4181-8383-818181818181",
		corev1.ProtocolTCP,
		9643,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)
	service := harness.service(t)
	for _, key := range []string{
		annotationNodeLoadBalancerShard,
		annotationNodeLoadBalancerPreviousShard,
		annotationNodeLoadBalancerDatapathActive,
		annotationNodeLoadBalancerDatapathStaged,
		annotationNodeLoadBalancerDatapathRestage,
	} {
		delete(service.Annotations, key)
	}
	if !aggregateServiceReferencesShard(service, harness.shard) {
		t.Fatalf("materialized marker is not a durable cleanup reference: %#v", service.Annotations)
	}
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
	if _, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	// Keep an unrelated finalized owner so only the marker-derived shard loop,
	// not last-owner cluster sweeping, can select the lost explicit reference.
	survivor := nodeLoadBalancerTestService(
		"aggregate-marker-only-survivor",
		"86868686-8686-4686-8686-868686868686",
		corev1.ProtocolTCP,
		9743,
	)
	survivor.Finalizers = []string{nodeLoadBalancerFinalizer}
	if _, err := harness.provider.kubeClient.CoreV1().Services(survivor.Namespace).Create(
		harness.ctx, survivor, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)

	if err := harness.controller.sync(harness.ctx, harness.key); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, harness.shard, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("marker-only deleting Service did not select its materialized NodePool for teardown: %v", err)
	}
	current := harness.service(t)
	if !containsString(current.Finalizers, nodeLoadBalancerFinalizer) || len(current.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("marker-only cleanup crossed capacity fence or left status live: finalizers=%#v status=%#v", current.Finalizers, current.Status.LoadBalancer)
	}
}

func TestAggregateMaterializedClusterCannotRecreateMissingNodeClassLedger(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-nodeclass-anchor-loss",
		"82828282-8282-4282-8282-828282828282",
		corev1.ProtocolTCP,
		10443,
	))
	defer harness.controller.queue.ShutDown()
	service := harness.service(t)
	if service.Annotations[annotationNodeLoadBalancerClusterStateMaterial] != "true" ||
		service.Annotations[annotationNodeLoadBalancerClusterCleanupProven] == "true" {
		t.Fatalf("fixture lacks unproven cluster materialization handoff: %#v", service.Annotations)
	}
	dynamicClient, ok := harness.provider.dynamicClient.(interface {
		Tracker() k8stesting.ObjectTracker
	})
	if !ok {
		t.Fatalf("test dynamic client has no tracker: %T", harness.provider.dynamicClient)
	}
	nodeClassName := managedNodeLoadBalancerName(harness.provider.config.ClusterID, "node-lb")
	if err := dynamicClient.Tracker().Delete(nodeClassGVR, "", nodeClassName); err != nil {
		t.Fatal(err)
	}
	createsBefore := len(harness.api.createdFirewalls)

	err := harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "get materialized cluster state anchor") {
		t.Fatalf("missing materialized NodeClass anchor error = %v", err)
	}
	if _, getErr := harness.provider.dynamicClient.Resource(nodeClassGVR).Get(
		harness.ctx, nodeClassName, metav1.GetOptions{},
	); getErr == nil {
		t.Fatal("missing materialized NodeClass was recreated with an empty cloud ledger")
	}
	if len(harness.api.createdFirewalls) != createsBefore {
		t.Fatalf("missing NodeClass ledger triggered a duplicate firewall create: before=%d after=%d", createsBefore, len(harness.api.createdFirewalls))
	}
}

func TestAggregateNewShardICMPAttachPreservesEstablishedShard(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-established-a",
		"83838383-8383-4383-8383-838383838383",
		corev1.ProtocolTCP,
		11443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	serviceB := nodeLoadBalancerTestService(
		"aggregate-new-b",
		"84848484-8484-4484-8484-848484848484",
		corev1.ProtocolTCP,
		12443,
	)
	serviceB.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	serviceB.Annotations[annotationNodeLoadBalancerCPU] = "1"
	serviceB.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	if _, err := harness.provider.kubeClient.CoreV1().Services(serviceB.Namespace).Create(
		harness.ctx, serviceB.DeepCopy(), metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Add(serviceB.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	keyB := serviceB.Namespace + "/" + serviceB.Name
	var shardB string
	harness.fixture.syncUntil(t, []string{keyB}, 32, func() bool {
		stored := harness.fixture.service(t, serviceB.Name)
		shardB = stored.Annotations[annotationNodeLoadBalancerShard]
		if !isManagedNodeLoadBalancerShardName(shardB) || shardB == harness.shard {
			return false
		}
		_, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(harness.ctx, shardB, metav1.GetOptions{})
		return err == nil
	}, nil)

	const vmB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	nodeB := aggregateAddSafetyNode(
		t, harness, shardB, "aggregate-new-b-node", vmB,
		"10.0.0.21", "203.0.113.11", false,
	)
	assignmentsBefore := len(harness.api.assignedFirewalls)
	if err := harness.controller.sync(harness.ctx, keyB); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)
	if len(harness.api.assignedFirewalls) != assignmentsBefore+1 {
		t.Fatalf("new shard ICMP attach count = %d, want 1", len(harness.api.assignedFirewalls)-assignmentsBefore)
	}
	if !harness.fixture.servicePublished(t, harness.serviceName) {
		t.Fatal("new shard ICMP attachment withdrew the established shard Service")
	}
	nodeA, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if nodeA.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatalf("new shard ICMP attachment closed established Node A: %#v", nodeA.Labels)
	}
	storedB, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, nodeB.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if storedB.Labels[nodeLoadBalancerReadyLabel] == "true" || len(harness.fixture.service(t, serviceB.Name).Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("new shard was advertised in the ICMP attach pass: node=%#v status=%#v", storedB.Labels, harness.fixture.service(t, serviceB.Name).Status.LoadBalancer)
	}
}

func TestAggregateSameShardSurgeAttachPreservesEstablishedSibling(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-surge-a",
		"85858585-8585-4585-8585-858585858585",
		corev1.ProtocolTCP,
		13443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)
	shardFirewall := harness.aggregateFirewall(t)

	const surgeVM = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	surge := aggregateAddSafetyNode(
		t, harness, harness.shard, "aggregate-surge-new", surgeVM,
		"10.0.0.22", "203.0.113.12", true,
	)
	assignmentsBefore := len(harness.api.assignedFirewalls)
	if err := harness.controller.sync(harness.ctx, harness.key); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)
	if len(harness.api.assignedFirewalls) != assignmentsBefore+1 ||
		harness.api.assignedFirewalls[len(harness.api.assignedFirewalls)-1] != shardFirewall.UUID+"/"+surgeVM {
		t.Fatalf("surge shard-firewall attachment = %#v", harness.api.assignedFirewalls[assignmentsBefore:])
	}
	if !harness.fixture.servicePublished(t, harness.serviceName) {
		t.Fatal("same-shard surge attachment withdrew the established Service")
	}
	nodeA, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	storedSurge, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, surge.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if nodeA.Labels[nodeLoadBalancerReadyLabel] != "true" || storedSurge.Labels[nodeLoadBalancerReadyLabel] == "true" {
		t.Fatalf("surge assignment fence labels: established=%#v surge=%#v", nodeA.Labels, storedSurge.Labels)
	}
}

func TestAggregateForeignEstablishedChildFailsShardClosedWithoutMutatingChild(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-foreign-child",
		"91919191-9191-4191-8191-919191919191",
		corev1.ProtocolTCP,
		443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	parent := harness.service(t)
	childClient := harness.provider.kubeClient.CoreV1().Services(parent.Namespace)
	child, err := childClient.Get(harness.ctx, nodeLoadBalancerDatapathName(parent), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(child.OwnerReferences) != 1 {
		t.Fatalf("established child owner references = %#v", child.OwnerReferences)
	}
	foreign := child.DeepCopy()
	foreign.OwnerReferences[0].UID = types.UID("foreign-service-generation")
	foreign, err = childClient.Update(harness.ctx, foreign, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	foreignSnapshot := foreign.DeepCopy()
	// Safety-critical node discovery must not depend on informer freshness. Drop
	// the established Node from the cache while leaving it live in the API.
	if cached, exists, cacheErr := harness.fixture.nodeIndexer.GetByKey(harness.nodeName); cacheErr != nil {
		t.Fatal(cacheErr)
	} else if !exists {
		t.Fatalf("established Node %s was not present in the test informer", harness.nodeName)
	} else if cacheErr := harness.fixture.nodeIndexer.Delete(cached); cacheErr != nil {
		t.Fatal(cacheErr)
	}
	if cachedNodes, cacheErr := harness.controller.nodes.List(labels.Everything()); cacheErr != nil {
		t.Fatal(cacheErr)
	} else if len(cachedNodes) != 0 {
		t.Fatalf("test informer still exposes Nodes: %#v", cachedNodes)
	}
	actionClient, ok := harness.provider.kubeClient.(interface{ Actions() []k8stesting.Action })
	if !ok {
		t.Fatalf("test Kubernetes client does not expose action history: %T", harness.provider.kubeClient)
	}
	actionsBefore := len(actionClient.Actions())

	err = harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "immutable reservation identity") ||
		!strings.Contains(err.Error(), "refusing to withdraw foreign datapath Service") {
		t.Fatalf("foreign established child quarantine error = %v", err)
	}

	for _, action := range actionClient.Actions()[actionsBefore:] {
		if action.GetResource().Resource != "services" {
			continue
		}
		switch action.GetVerb() {
		case "create", "update", "patch", "delete", "deletecollection":
			t.Fatalf("foreign child failure issued a Service mutation: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	stored, err := childClient.Get(harness.ctx, foreign.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("foreign child was deleted: %v", err)
	}
	if !reflect.DeepEqual(stored, foreignSnapshot) {
		t.Fatalf("foreign child was mutated\n got: %#v\nwant: %#v", stored, foreignSnapshot)
	}

	node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(
		harness.ctx, harness.nodeName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ready := node.Labels[nodeLoadBalancerReadyLabel]; ready {
		t.Fatalf("foreign established child retained shard readiness: %#v", node.Labels)
	}
}

func TestAggregateDeletingSoleOwnerWithForeignChildRetainsPaidStateFailClosed(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-delete-foreign-child",
		"92929292-9292-4292-8292-929292929292",
		corev1.ProtocolTCP,
		8443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	foreign := makeAggregateReviewGapChildForeign(t, harness)
	parent := harness.service(t)
	deletingAt := metav1.Now()
	parent.DeletionTimestamp = &deletingAt
	parent, err := harness.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		harness.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Update(parent.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	poolBefore, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, harness.shard, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	firewallsBefore := append([]inspace.Firewall(nil), harness.api.firewalls...)
	unassignmentsBefore := append([]string(nil), harness.api.unassignedFirewalls...)
	deletionsBefore := append([]string(nil), harness.api.deletedFirewalls...)
	actionClient := aggregateReviewGapActionClient(t, harness)
	actionsBefore := len(actionClient.Actions())

	err = harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "refusing to withdraw foreign datapath Service") {
		t.Fatalf("foreign child deletion error = %v", err)
	}
	assertAggregateReviewGapForeignChildUntouched(t, harness, foreign, actionClient.Actions()[actionsBefore:])

	node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(
		harness.ctx, harness.nodeName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ready := node.Labels[nodeLoadBalancerReadyLabel]; ready {
		t.Fatalf("deleting foreign-child owner retained shard readiness: %#v", node.Labels)
	}
	storedParent, err := harness.provider.kubeClient.CoreV1().Services(parent.Namespace).Get(
		harness.ctx, parent.Name, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(storedParent.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("foreign child failure prematurely removed the parent finalizer: %#v", storedParent.Finalizers)
	}
	poolAfter, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, harness.shard, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("foreign child failure deleted the paid NodePool anchor: %v", err)
	}
	if poolAfter.GetDeletionTimestamp() != nil || poolAfter.GetUID() != poolBefore.GetUID() {
		t.Fatalf("foreign child failure started paid NodePool deletion: before=%#v after=%#v", poolBefore.Object, poolAfter.Object)
	}
	if !reflect.DeepEqual(harness.api.firewalls, firewallsBefore) ||
		!reflect.DeepEqual(harness.api.unassignedFirewalls, unassignmentsBefore) ||
		!reflect.DeepEqual(harness.api.deletedFirewalls, deletionsBefore) {
		t.Fatalf(
			"foreign child failure mutated paid firewall state: firewalls=%#v unassign=%#v delete=%#v",
			harness.api.firewalls, harness.api.unassignedFirewalls, harness.api.deletedFirewalls,
		)
	}
}

func TestPrepareAggregateServiceRestageChildOwnershipRaceFailsShardClosed(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-restage-child-race",
		"93939393-9393-4393-8393-939393939393",
		corev1.ProtocolTCP,
		9443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	parent := harness.service(t)
	parent.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	parent, err := harness.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		harness.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Update(parent.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	policyHash, err := desiredNodeLoadBalancerServicePolicyHash(parent)
	if err != nil {
		t.Fatal(err)
	}

	// Model the child changing owner after planning validated the parent but
	// immediately before prepareAggregateServiceRestage enters its first clear.
	foreign := makeAggregateReviewGapChildForeign(t, harness)
	actionClient := aggregateReviewGapActionClient(t, harness)
	actionsBefore := len(actionClient.Actions())
	err = harness.controller.prepareAggregateServiceRestage(
		harness.ctx, parent, harness.shard, policyHash,
	)
	if err == nil || !strings.Contains(err.Error(), "refusing to withdraw foreign datapath Service") {
		t.Fatalf("restage ownership race error = %v", err)
	}
	assertAggregateReviewGapForeignChildUntouched(t, harness, foreign, actionClient.Actions()[actionsBefore:])
	node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(
		harness.ctx, harness.nodeName, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ready := node.Labels[nodeLoadBalancerReadyLabel]; ready {
		t.Fatalf("restage ownership race retained shard readiness: %#v", node.Labels)
	}
}

func makeAggregateReviewGapChildForeign(
	t *testing.T,
	harness *aggregateSafetySyncHarness,
) *corev1.Service {
	t.Helper()
	parent := harness.service(t)
	client := harness.provider.kubeClient.CoreV1().Services(parent.Namespace)
	child, err := client.Get(harness.ctx, nodeLoadBalancerDatapathName(parent), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(child.OwnerReferences) != 1 {
		t.Fatalf("established child owner references = %#v", child.OwnerReferences)
	}
	foreign := child.DeepCopy()
	foreign.OwnerReferences[0].UID = types.UID("foreign-service-generation")
	foreign, err = client.Update(harness.ctx, foreign, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return foreign.DeepCopy()
}

func aggregateReviewGapActionClient(
	t *testing.T,
	harness *aggregateSafetySyncHarness,
) interface{ Actions() []k8stesting.Action } {
	t.Helper()
	actionClient, ok := harness.provider.kubeClient.(interface{ Actions() []k8stesting.Action })
	if !ok {
		t.Fatalf("test Kubernetes client does not expose action history: %T", harness.provider.kubeClient)
	}
	return actionClient
}

func assertAggregateReviewGapForeignChildUntouched(
	t *testing.T,
	harness *aggregateSafetySyncHarness,
	want *corev1.Service,
	actions []k8stesting.Action,
) {
	t.Helper()
	for _, action := range actions {
		if action.GetResource().Resource != "services" {
			continue
		}
		switch action.GetVerb() {
		case "create", "update", "patch", "delete", "deletecollection":
			t.Fatalf("foreign child failure issued a Service mutation: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	stored, err := harness.provider.kubeClient.CoreV1().Services(want.Namespace).Get(
		harness.ctx, want.Name, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("foreign child was deleted: %v", err)
	}
	if !reflect.DeepEqual(stored, want) {
		t.Fatalf("foreign child was mutated\n got: %#v\nwant: %#v", stored, want)
	}
}

func TestAggregateDeletingSharedServiceWithdrawsBeforeFirewallListFailure(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-delete-first",
		"92929292-9292-4292-8292-929292929292",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)

	sibling := nodeLoadBalancerTestService(
		"aggregate-delete-sibling",
		"93939393-9393-4393-8393-939393939393",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := harness.provider.kubeClient.CoreV1().Services(sibling.Namespace).Create(
		harness.ctx, sibling.DeepCopy(), metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Add(sibling.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	siblingKey := sibling.Namespace + "/" + sibling.Name
	harness.fixture.syncUntil(t, []string{siblingKey, harness.key}, 64, func() bool {
		stored := aggregateSafetyService(t, harness.ctx, harness.provider, sibling.Name)
		return stored.Annotations[annotationNodeLoadBalancerShard] == harness.shard &&
			harness.fixture.servicePublished(t, sibling.Name) &&
			harness.fixture.shardPolicyStable(t, harness.shard, 2)
	}, nil)

	deleting := harness.service(t)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting, err := harness.provider.kubeClient.CoreV1().Services(deleting.Namespace).Update(
		harness.ctx, deleting, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Update(deleting.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	firewallsBefore := append([]inspace.Firewall(nil), harness.api.firewalls...)
	listErr := errors.New("injected aggregate firewall List failure")
	harness.provider.api = &aggregateListFirewallsErrorAPI{fakeAPI: harness.api, err: listErr}

	err = harness.controller.sync(harness.ctx, harness.key)
	if !errors.Is(err, listErr) {
		t.Fatalf("deleting shared Service sync error = %v, want injected List failure", err)
	}
	removed := harness.service(t)
	if len(removed.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("deleting Service remained publicly advertised: %#v", removed.Status.LoadBalancer)
	}
	if !containsString(removed.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatal("deleting Service finalized before aggregate policy cleanup")
	}
	child, childErr := harness.provider.kubeClient.CoreV1().Services(removed.Namespace).Get(
		harness.ctx, nodeLoadBalancerDatapathName(removed), metav1.GetOptions{},
	)
	if childErr != nil {
		t.Fatalf("deleting Service child was removed before policy cleanup: %v", childErr)
	}
	if len(child.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("deleting Service child remained functionally advertised: %#v", child.Status.LoadBalancer)
	}
	if removed.Annotations[annotationNodeLoadBalancerDatapathActive] != harness.shard {
		t.Fatalf("deleting Service lost its active reservation before policy cleanup: %#v", removed.Annotations)
	}
	if !harness.fixture.servicePublished(t, sibling.Name) {
		t.Fatal("healthy shared sibling was withdrawn by deleting member's cloud List failure")
	}
	node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatalf("healthy shared shard was closed despite successful member withdrawal: %#v", node.Labels)
	}
	if !reflect.DeepEqual(harness.api.firewalls, firewallsBefore) {
		t.Fatalf("failed firewall List mutated aggregate cloud state\n got: %#v\nwant: %#v", harness.api.firewalls, firewallsBefore)
	}
}

type aggregateListFirewallsErrorAPI struct {
	*fakeAPI
	err error
}

func (a *aggregateListFirewallsErrorAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	return nil, a.err
}

func aggregateAddSafetyNode(
	t *testing.T,
	harness *aggregateSafetySyncHarness,
	shard, name, vmUUID, internalIP, externalIP string,
	assignICMP bool,
) *corev1.Node {
	t.Helper()
	pool, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(harness.ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pool.GetUID() == "" {
		copy := pool.DeepCopy()
		copy.SetUID(types.UID("nodepool-" + shard))
		pool, err = harness.provider.dynamicClient.Resource(nodePoolGVR).Update(harness.ctx, copy, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	claimName := shard + "-" + name + "-claim"
	claimUID := types.UID("nodeclaim-" + name)
	blockOwnerDeletion := true
	node := readyNode(name, "inspace://bkk01/"+vmUUID)
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: internalIP},
		{Type: corev1.NodeExternalIP, Address: externalIP},
	}
	if node.Labels == nil {
		node.Labels = map[string]string{}
	}
	node.Labels[karpenterNodePoolLabel] = shard
	node.Labels[nodeLoadBalancerNodeLabel] = "true"
	node.Labels[nodeLoadBalancerNodeClusterLabel] = harness.provider.config.ClusterID
	node.Labels[nodeLoadBalancerNodeShardLabel] = shard
	node.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "karpenter.sh/v1", Kind: "NodeClaim", Name: claimName, UID: claimUID,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}}
	nodeClassName := managedNodeLoadBalancerName(harness.provider.config.ClusterID, "node-lb")
	nodeClass, err := harness.provider.dynamicClient.Resource(nodeClassGVR).Get(harness.ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	baseFirewallUUID, found, err := unstructured.NestedString(nodeClass.Object, "spec", "firewallUUID")
	if err != nil || !found {
		t.Fatalf("managed NodeClass has no base firewall UUID: found=%v err=%v", found, err)
	}
	floatingIPName := managedNodeLoadBalancerFloatingIPName(harness.provider.config.ClusterID, claimName)
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodeClaim",
		"metadata": map[string]any{
			"name": claimName, "uid": string(claimUID),
			"annotations": map[string]any{
				karpenterPublicIPv4Annotation:     externalIP,
				karpenterFloatingIPNameAnnotation: floatingIPName,
				karpenterBillingAccountAnnotation: strconv.FormatInt(harness.provider.config.BillingAccountID, 10),
				karpenterNodeNameAnnotation:       node.Name,
			},
			"labels": map[string]any{
				karpenterNodePoolLabel:           shard,
				nodeLoadBalancerNodeLabel:        "true",
				nodeLoadBalancerNodeClusterLabel: harness.provider.config.ClusterID,
				nodeLoadBalancerNodeShardLabel:   shard,
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion": "karpenter.sh/v1", "kind": "NodePool", "name": shard,
				"uid": string(pool.GetUID()), "blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]any{"nodeClassRef": map[string]any{
			"group": "karpenter.inspace.cloud", "kind": "InSpaceNodeClass", "name": nodeClassName,
		}},
		"status": map[string]any{"providerID": node.Spec.ProviderID, "nodeName": node.Name},
	}}
	if _, err := harness.provider.dynamicClient.Resource(nodeClaimGVR).Create(harness.ctx, claim, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ownership, err := json.Marshal(publicNodeLocalVMOwnership{
		Schema: "karpenter.inspace.cloud/v3", Cluster: harness.provider.config.ClusterID,
		NodePool: shard, NodeClaim: claimName, VMName: node.Name,
		FirewallProfile: nodeLoadBalancerFirewallMode, FirewallUUID: baseFirewallUUID,
		NetworkUUID: harness.provider.config.NetworkUUID, BillingAccountID: harness.provider.config.BillingAccountID,
		FloatingIPName: floatingIPName,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.api.vms = append(harness.api.vms, inspace.VM{
		UUID: vmUUID, Name: node.Name, Description: string(ownership), Status: "running",
		BillingAccountID: harness.provider.config.BillingAccountID, NetworkUUID: harness.provider.config.NetworkUUID,
		PrivateIPv4: internalIP,
	})
	harness.api.floatingIPs = append(harness.api.floatingIPs, inspace.FloatingIP{
		Name: floatingIPName, Address: externalIP,
		BillingAccountID: harness.provider.config.BillingAccountID, Type: "public", Enabled: true,
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: internalIP,
	})
	baseFound := false
	for index := range harness.api.firewalls {
		if harness.api.firewalls[index].UUID != baseFirewallUUID {
			continue
		}
		harness.api.firewalls[index].ResourcesAssigned = append(
			harness.api.firewalls[index].ResourcesAssigned,
			inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID},
		)
		baseFound = true
		break
	}
	if !baseFound {
		t.Fatalf("base firewall %s not found", baseFirewallUUID)
	}
	if assignICMP {
		icmpUUID := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
		found := false
		for index := range harness.api.firewalls {
			if harness.api.firewalls[index].UUID != icmpUUID {
				continue
			}
			harness.api.firewalls[index].ResourcesAssigned = append(
				harness.api.firewalls[index].ResourcesAssigned,
				inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID},
			)
			found = true
			break
		}
		if !found {
			t.Fatalf("cluster ICMP firewall %s not found", icmpUUID)
		}
	}
	if _, err := harness.provider.kubeClient.CoreV1().Nodes().Create(harness.ctx, node.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	return node
}

func retainedIdentityTestNodeClaim(
	shard, cluster, nodeClassName string,
	pool *unstructured.Unstructured,
	name, uid, providerID string,
) *unstructured.Unstructured {
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1",
		"kind":       "NodeClaim",
		"metadata": map[string]any{
			"name": name,
			"uid":  uid,
			"labels": map[string]any{
				karpenterNodePoolLabel:           shard,
				nodeLoadBalancerNodeLabel:        "true",
				nodeLoadBalancerNodeClusterLabel: cluster,
				nodeLoadBalancerNodeShardLabel:   shard,
			},
			"ownerReferences": []any{map[string]any{
				"apiVersion":         "karpenter.sh/v1",
				"kind":               "NodePool",
				"name":               shard,
				"uid":                string(pool.GetUID()),
				"blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]any{"nodeClassRef": map[string]any{
			"group": "karpenter.inspace.cloud",
			"kind":  "InSpaceNodeClass",
			"name":  nodeClassName,
		}},
	}}
	if providerID != "" {
		claim.Object["status"] = map[string]any{"providerID": providerID}
	}
	return claim
}
