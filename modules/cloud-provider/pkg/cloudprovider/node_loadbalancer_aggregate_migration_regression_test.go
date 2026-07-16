package cloudprovider

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// These regressions drive the controller's sync entrypoint through complete
// cross-shard handoffs. The dynamic fake deliberately models apiserver
// finalizer semantics so a disappearing fake object cannot hide a stranded
// firewall transaction ledger.

func TestAggregateActiveServiceEditMigratesAcrossShards(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-active-migration",
		"10101010-1010-4010-8010-101010101010",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	driver := newAggregateMigrationDriver(t, harness)
	oldShard := harness.shard
	oldFirewall := harness.aggregateFirewall(t).UUID

	service := harness.service(t)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	service.Spec.Ports[0].Port = 8080
	driver.updateService(t, service)

	// The first pass must persist the replacement while the exact old child is
	// still the active reservation. This is the preflight boundary which used
	// to validate the prospective shard and deadlock before A could be closed.
	driver.sync(t)
	migrating := harness.service(t)
	newShard := migrating.Annotations[annotationNodeLoadBalancerShard]
	if !isManagedNodeLoadBalancerShardName(newShard) || newShard == oldShard {
		t.Fatalf("active edit did not assign a replacement shard: old=%q new=%q annotations=%#v", oldShard, newShard, migrating.Annotations)
	}
	if migrating.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard ||
		migrating.Annotations[annotationNodeLoadBalancerDatapathActive] != oldShard {
		t.Fatalf("active migration lost the old serving checkpoint: %#v", migrating.Annotations)
	}
	if len(migrating.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("metadata persistence withdrew the serving Service early: %#v", migrating.Status.LoadBalancer)
	}
	child, err := harness.provider.kubeClient.CoreV1().Services(migrating.Namespace).Get(
		harness.ctx, nodeLoadBalancerDatapathName(migrating), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if child.Spec.Ports[0].Port != 80 {
		t.Fatalf("active reservation was rewritten before close: port=%d", child.Spec.Ports[0].Port)
	}

	driver.convergeShard(t, newShard, oldShard, "203.0.113.31")
	driver.requireRetiredShard(t, oldShard, oldFirewall)
	driver.requireActiveShard(t, newShard, 8080, "203.0.113.31")
}

func TestAggregateMigrationChurnRetiresAThenSkipsProspectiveBForC(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-migration-churn",
		"20202020-2020-4020-8020-202020202020",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)
	driver := newAggregateMigrationDriver(t, harness)

	oldShard := harness.shard
	oldFirewall := harness.aggregateFirewall(t).UUID
	service := harness.service(t)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	service.Spec.Ports[0].Port = 8080
	driver.updateService(t, service)
	driver.sync(t)

	checkpoint := harness.service(t)
	prospectiveB := checkpoint.Annotations[annotationNodeLoadBalancerShard]
	if prospectiveB == "" || prospectiveB == oldShard ||
		checkpoint.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard {
		t.Fatalf("A to B checkpoint was not persisted: %#v", checkpoint.Annotations)
	}

	// Close A, but deliberately edit the desired profile again before A's
	// durable firewall/capacity retirement has completed.
	for attempt := 0; attempt < 12; attempt++ {
		driver.sync(t)
		checkpoint = harness.service(t)
		if checkpoint.Annotations[annotationNodeLoadBalancerDatapathActive] == "" {
			break
		}
	}
	if checkpoint.Annotations[annotationNodeLoadBalancerDatapathActive] != "" ||
		checkpoint.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard {
		t.Fatalf("A was not closed at the churn boundary: %#v", checkpoint.Annotations)
	}
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, prospectiveB, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("prospective B materialized before A retirement: %v", err)
	}

	checkpoint.Annotations[annotationNodeLoadBalancerCPU] = "4"
	checkpoint.Annotations[annotationNodeLoadBalancerMemory] = "8Gi"
	checkpoint.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeShared
	checkpoint.Annotations[annotationNodeLoadBalancerPool] = "churn-c"
	delete(checkpoint.Annotations, annotationNodeLoadBalancerCPU)
	delete(checkpoint.Annotations, annotationNodeLoadBalancerMemory)
	checkpoint.Spec.Ports[0].Port = 8081
	driver.updateService(t, checkpoint)

	var desiredC string
	for attempt := 0; attempt < 160; attempt++ {
		driver.prepare(t)
		if err := harness.controller.sync(harness.ctx, harness.key); err != nil {
			t.Fatalf("churn sync attempt %d: %v", attempt, err)
		}
		harness.fixture.refreshListers(t)
		driver.finish(t)
		current := harness.service(t)
		candidate := current.Annotations[annotationNodeLoadBalancerShard]
		if candidate != "" && candidate != oldShard && candidate != prospectiveB {
			desiredC = candidate
		}
		if desiredC != "" {
			driver.provisionShardIfReady(t, desiredC, "203.0.113.32")
			if driver.shardConverged(t, desiredC, oldShard, "203.0.113.32") {
				break
			}
		}
	}
	if desiredC == "" {
		t.Fatal("second edit never assigned replacement C")
	}
	if desiredC == prospectiveB {
		t.Fatalf("second edit reused stale prospective B %q", prospectiveB)
	}
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, prospectiveB, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("abandoned prospective B materialized: %v", err)
	}
	if got := harness.fixture.countShardFirewalls(t, prospectiveB); got != 0 {
		t.Fatalf("abandoned prospective B acquired %d aggregate firewalls", got)
	}
	driver.requireRetiredShard(t, oldShard, oldFirewall)
	driver.requireActiveShard(t, desiredC, 8081, "203.0.113.32")
}

func TestAggregatePreActivationMaterializedShardIsRetiredBeforeReplacement(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-preactivation-migration",
		"30303030-3030-4030-8030-303030303030",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()
	driver := newAggregateMigrationDriver(t, harness)
	oldShard := harness.shard

	// Materialize A's aggregate firewall, but stop on the mutation pass before
	// any functional child or parent status is allowed to become public.
	var oldFirewall string
	for attempt := 0; attempt < 32; attempt++ {
		driver.sync(t)
		for _, firewall := range harness.api.firewalls {
			name, err := inspace.NodeLoadBalancerShardFirewallName(harness.provider.config.ClusterID, oldShard)
			if err != nil {
				t.Fatal(err)
			}
			if firewall.EffectiveName() == name {
				oldFirewall = firewall.UUID
				break
			}
		}
		if oldFirewall != "" {
			break
		}
	}
	if oldFirewall == "" {
		t.Fatal("pre-activation shard never materialized its aggregate firewall")
	}
	if published := harness.service(t).Status.LoadBalancer.Ingress; len(published) != 0 {
		t.Fatalf("test crossed the pre-activation boundary: %#v", published)
	}

	service := harness.service(t)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	driver.updateService(t, service)
	driver.sync(t)

	migrating := harness.service(t)
	newShard := migrating.Annotations[annotationNodeLoadBalancerShard]
	if newShard == "" || newShard == oldShard ||
		migrating.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard ||
		migrating.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
		t.Fatalf("materialized pre-activation A was not checkpointed for cleanup: %#v", migrating.Annotations)
	}

	driver.convergeShard(t, newShard, oldShard, "203.0.113.33")
	driver.requireRetiredShard(t, oldShard, oldFirewall)
	driver.requireActiveShard(t, newShard, 80, "203.0.113.33")
}

func TestAggregateLastOwnerSyncSweepsOrphanShardFirewallAndReleasesAnchor(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-orphan-sweep",
		"40404040-4040-4040-8040-404040404040",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)
	driver := newAggregateMigrationDriver(t, harness)

	const (
		orphanShard    = "inlb-deadbeef"
		orphanFirewall = "50505050-5050-4050-8050-505050505050"
		orphanVM       = "60606060-6060-4060-8060-606060606060"
	)
	orphanService := aggregateTestService(
		"orphan-ledger-member",
		"70707070-7070-4070-8070-707070707070",
		corev1.ProtocolTCP,
		9443,
	)
	orphanPlan := nodeLoadBalancerShardPlan{
		Name: orphanShard, Claims: []string{string(orphanService.UID)},
		Ports: nodeLoadBalancerPortClaimsOrFatal(t, orphanService),
	}
	orphanPolicy, err := desiredNodeLoadBalancerShardFirewall(
		harness.provider.config.ClusterID,
		harness.provider.config.BillingAccountID,
		orphanPlan,
		[]*corev1.Service{orphanService},
	)
	if err != nil {
		t.Fatal(err)
	}
	orphanLedger, err := nodeLoadBalancerShardFirewallPolicyLedger(orphanPolicy)
	if err != nil {
		t.Fatal(err)
	}
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1,
		nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB,
	)
	orphanPool := nodeLoadBalancerSafetyNodePool(orphanShard, harness.provider.config.ClusterID, profile, 1)
	orphanPool.SetUID(types.UID("nodepool-" + orphanShard))
	annotations := orphanPool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerShardFirewallUUID] = orphanFirewall
	annotations[annotationNodeLoadBalancerShardFirewallHash] = orphanPolicy.Hash
	annotations[annotationNodeLoadBalancerShardFirewallLedger] = orphanLedger
	orphanPool.SetAnnotations(annotations)
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Create(
		harness.ctx, orphanPool, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	orphanCloudFirewall := aggregateTestFirewall(orphanPolicy, orphanFirewall)
	orphanCloudFirewall.ResourcesAssigned = []inspace.FirewallResource{{
		ResourceType: "vm", ResourceUUID: orphanVM,
	}}
	harness.api.firewalls = append(harness.api.firewalls, orphanCloudFirewall)

	service := harness.service(t)
	now := metav1.Now()
	service.DeletionTimestamp = &now
	driver.updateService(t, service)

	finalized := false
	for attempt := 0; attempt < 240; attempt++ {
		driver.prepare(t)
		if err := harness.controller.sync(harness.ctx, harness.key); err != nil {
			t.Fatalf("orphan sweep sync attempt %d: %v", attempt, err)
		}
		harness.fixture.refreshListers(t)
		driver.finish(t)
		current, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
			harness.ctx, service.Name, metav1.GetOptions{},
		)
		if err != nil {
			t.Fatal(err)
		}
		if !containsString(current.Finalizers, nodeLoadBalancerFinalizer) {
			finalized = true
			break
		}
	}
	if !finalized {
		current := harness.service(t)
		t.Fatalf("last owner never finalized after orphan sweep: %#v", current.ObjectMeta)
	}
	if !driver.releasedFinalizers[orphanShard] {
		t.Fatalf("orphan shard %s never released its durable state finalizer", orphanShard)
	}
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, orphanShard, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan NodePool survived finalizer release: %v", err)
	}
	for _, firewall := range harness.api.firewalls {
		if firewall.UUID == orphanFirewall {
			t.Fatalf("orphan aggregate firewall survived sweep: %#v", firewall)
		}
	}
	if !containsString(harness.api.unassignedFirewalls, orphanFirewall+"/"+orphanVM) {
		t.Fatalf("orphan aggregate firewall assignment was not drained: %#v", harness.api.unassignedFirewalls)
	}
	if !containsString(harness.api.deletedFirewalls, orphanFirewall) {
		t.Fatalf("orphan aggregate firewall was not deleted: %#v", harness.api.deletedFirewalls)
	}
}

type aggregateMigrationDriver struct {
	harness *aggregateSafetySyncHarness
	dynamic interface {
		PrependReactor(string, string, k8stesting.ReactionFunc)
		Tracker() k8stesting.ObjectTracker
	}
	provisioned        map[string]bool
	releasedFinalizers map[string]bool
	nextNode           int
}

func newAggregateMigrationDriver(t *testing.T, harness *aggregateSafetySyncHarness) *aggregateMigrationDriver {
	t.Helper()
	dynamic, ok := harness.provider.dynamicClient.(interface {
		PrependReactor(string, string, k8stesting.ReactionFunc)
		Tracker() k8stesting.ObjectTracker
	})
	if !ok {
		t.Fatalf("test dynamic client does not expose reactors and tracker: %T", harness.provider.dynamicClient)
	}
	driver := &aggregateMigrationDriver{
		harness: harness, dynamic: dynamic,
		provisioned:        map[string]bool{harness.shard: true},
		releasedFinalizers: make(map[string]bool),
		nextNode:           31,
	}
	nodeClassName := managedNodeLoadBalancerName(harness.provider.config.ClusterID, "node-lb")
	if nodeClass, err := harness.provider.dynamicClient.Resource(nodeClassGVR).Get(
		harness.ctx, nodeClassName, metav1.GetOptions{},
	); err == nil && nodeClass.GetUID() == "" {
		nodeClass.SetUID(types.UID("nodeclass-" + shortNodeLoadBalancerHash(nodeClassName)))
		if _, err := harness.provider.dynamicClient.Resource(nodeClassGVR).Update(
			harness.ctx, nodeClass, metav1.UpdateOptions{},
		); err != nil {
			t.Fatal(err)
		}
	} else if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	dynamic.PrependReactor("delete", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteAction, ok := action.(k8stesting.DeleteAction)
		if !ok {
			return false, nil, nil
		}
		object, err := dynamic.Tracker().Get(nodePoolGVR, "", deleteAction.GetName())
		if apierrors.IsNotFound(err) {
			return true, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		pool, ok := object.(*unstructured.Unstructured)
		if !ok {
			return true, nil, fmt.Errorf("NodePool tracker object has type %T", object)
		}
		if len(pool.GetFinalizers()) == 0 {
			return true, nil, dynamic.Tracker().Delete(nodePoolGVR, "", pool.GetName())
		}
		copy := pool.DeepCopy()
		if copy.GetDeletionTimestamp() == nil {
			now := metav1.Now()
			copy.SetDeletionTimestamp(&now)
		}
		return true, nil, dynamic.Tracker().Update(nodePoolGVR, copy, "")
	})
	dynamic.PrependReactor("update", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateAction, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		pool, ok := updateAction.GetObject().(*unstructured.Unstructured)
		if !ok || pool.GetDeletionTimestamp() == nil || len(pool.GetFinalizers()) != 0 {
			return false, nil, nil
		}
		driver.releasedFinalizers[pool.GetName()] = true
		if err := dynamic.Tracker().Delete(nodePoolGVR, "", pool.GetName()); err != nil && !apierrors.IsNotFound(err) {
			return true, nil, err
		}
		return true, pool.DeepCopy(), nil
	})
	return driver
}

func (d *aggregateMigrationDriver) updateService(t *testing.T, service *corev1.Service) {
	t.Helper()
	updated, err := d.harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		d.harness.ctx, service, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.harness.serviceIndexer.Update(updated.DeepCopy()); err != nil {
		t.Fatal(err)
	}
}

func (d *aggregateMigrationDriver) sync(t *testing.T) {
	t.Helper()
	d.prepare(t)
	if err := d.harness.controller.sync(d.harness.ctx, d.harness.key); err != nil {
		t.Fatal(err)
	}
	d.harness.fixture.refreshListers(t)
	d.finish(t)
}

func (d *aggregateMigrationDriver) prepare(t *testing.T) {
	t.Helper()
	d.ageCleanupEvidence(t)
	d.removeDeletingCapacity(t)
}

func (d *aggregateMigrationDriver) finish(t *testing.T) {
	t.Helper()
	d.observeAndReapFinalizedPools(t)
	d.harness.fixture.refreshListers(t)
}

func (d *aggregateMigrationDriver) ageCleanupEvidence(t *testing.T) {
	t.Helper()
	ctx := d.harness.ctx
	pools, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range pools.Items {
		pool := &pools.Items[index]
		annotations := pool.GetAnnotations()
		changed := false
		if pool.GetDeletionTimestamp() != nil && annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			annotations[annotationNodeLoadBalancerShardFWIssuedAt] = time.Now().Add(
				-nodeLoadBalancerShardFirewallMutationTimeout - 2*nodeLoadBalancerAbsenceConfirmationDelay,
			).UTC().Format(time.RFC3339Nano)
			changed = true
		}
		if annotations[annotationNodeLoadBalancerShardFWCleanupCheck] != "" {
			annotations[annotationNodeLoadBalancerShardFWCleanupCheck] = time.Now().Add(
				-2 * nodeLoadBalancerAbsenceConfirmationDelay,
			).UTC().Format(time.RFC3339Nano)
			changed = true
		}
		if !changed {
			continue
		}
		pool.SetAnnotations(annotations)
		if _, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).Update(
			ctx, pool, metav1.UpdateOptions{},
		); err != nil {
			t.Fatal(err)
		}
	}
	nodeClassName := managedNodeLoadBalancerName(d.harness.provider.config.ClusterID, "node-lb")
	nodeClass, err := d.harness.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	annotations := nodeClass.GetAnnotations()
	if annotations[annotationNodeLoadBalancerICMPCleanupChecked] == "" {
		return
	}
	annotations[annotationNodeLoadBalancerICMPCleanupChecked] = time.Now().Add(
		-2 * nodeLoadBalancerAbsenceConfirmationDelay,
	).UTC().Format(time.RFC3339Nano)
	nodeClass.SetAnnotations(annotations)
	if _, err := d.harness.provider.dynamicClient.Resource(nodeClassGVR).Update(
		ctx, nodeClass, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
}

func (d *aggregateMigrationDriver) removeDeletingCapacity(t *testing.T) {
	t.Helper()
	ctx := d.harness.ctx
	pools, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range pools.Items {
		pool := &pools.Items[index]
		if pool.GetDeletionTimestamp() == nil {
			continue
		}
		shard := pool.GetName()
		claims, err := d.harness.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for claimIndex := range claims.Items {
			claim := &claims.Items[claimIndex]
			if claim.GetLabels()[karpenterNodePoolLabel] != shard {
				continue
			}
			if err := d.harness.provider.dynamicClient.Resource(nodeClaimGVR).Delete(
				ctx, claim.GetName(), metav1.DeleteOptions{},
			); err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
		}
		nodes, err := d.harness.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for nodeIndex := range nodes.Items {
			node := &nodes.Items[nodeIndex]
			if node.Labels[nodeLoadBalancerNodeShardLabel] != shard {
				continue
			}
			if err := d.harness.provider.kubeClient.CoreV1().Nodes().Delete(
				ctx, node.Name, metav1.DeleteOptions{},
			); err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			if err := d.harness.fixture.nodeIndexer.Delete(node); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (d *aggregateMigrationDriver) observeAndReapFinalizedPools(t *testing.T) {
	t.Helper()
	pools, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).List(d.harness.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range pools.Items {
		pool := &pools.Items[index]
		if pool.GetDeletionTimestamp() == nil || containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			continue
		}
		d.releasedFinalizers[pool.GetName()] = true
		if err := d.dynamic.Tracker().Delete(nodePoolGVR, "", pool.GetName()); err != nil && !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
}

func (d *aggregateMigrationDriver) provisionShardIfReady(t *testing.T, shard, externalIP string) {
	t.Helper()
	if d.provisioned[shard] {
		return
	}
	pool, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		d.harness.ctx, shard, metav1.GetOptions{},
	)
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if pool.GetDeletionTimestamp() != nil {
		return
	}
	d.nextNode++
	vmUUID := fmt.Sprintf("%08d-1111-4111-8111-%012d", d.nextNode, d.nextNode)
	node := readyNode("aggregate-migration-"+shortNodeLoadBalancerHash(shard), "inspace://bkk01/"+vmUUID)
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: fmt.Sprintf("10.0.0.%d", d.nextNode)},
		{Type: corev1.NodeExternalIP, Address: externalIP},
	}
	installNodeLoadBalancerSafetyIdentity(t, d.harness.provider, node, shard)
	if _, err := d.harness.provider.kubeClient.CoreV1().Nodes().Create(
		d.harness.ctx, node.DeepCopy(), metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := d.harness.fixture.nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	d.provisioned[shard] = true
	d.harness.fixture.refreshListers(t)
}

func (d *aggregateMigrationDriver) convergeShard(t *testing.T, shard, retiredShard, externalIP string) {
	t.Helper()
	for attempt := 0; attempt < 160; attempt++ {
		d.prepare(t)
		if err := d.harness.controller.sync(d.harness.ctx, d.harness.key); err != nil {
			t.Fatalf("migration to %s sync attempt %d: %v", shard, attempt, err)
		}
		d.harness.fixture.refreshListers(t)
		d.finish(t)
		d.provisionShardIfReady(t, shard, externalIP)
		if d.shardConverged(t, shard, retiredShard, externalIP) {
			return
		}
	}
	service := d.harness.service(t)
	pools, _ := d.harness.provider.dynamicClient.Resource(nodePoolGVR).List(d.harness.ctx, metav1.ListOptions{})
	poolNames := make([]string, 0, len(pools.Items))
	for index := range pools.Items {
		poolNames = append(poolNames, fmt.Sprintf("%s(deleting=%t,finalizers=%v,annotations=%v)", pools.Items[index].GetName(), pools.Items[index].GetDeletionTimestamp() != nil, pools.Items[index].GetFinalizers(), pools.Items[index].GetAnnotations()))
	}
	claims, _ := d.harness.provider.dynamicClient.Resource(nodeClaimGVR).List(d.harness.ctx, metav1.ListOptions{})
	nodes, _ := d.harness.provider.kubeClient.CoreV1().Nodes().List(d.harness.ctx, metav1.ListOptions{})
	t.Fatalf("migration to %s did not converge: annotations=%#v status=%#v pools=%v claims=%#v nodes=%#v firewalls=%#v", shard, service.Annotations, service.Status.LoadBalancer, poolNames, claims.Items, nodes.Items, d.harness.api.firewalls)
}

func (d *aggregateMigrationDriver) shardConverged(t *testing.T, shard, retiredShard, externalIP string) bool {
	t.Helper()
	service := d.harness.service(t)
	if service.Annotations[annotationNodeLoadBalancerShard] != shard ||
		service.Annotations[annotationNodeLoadBalancerDatapathActive] != shard ||
		service.Annotations[annotationNodeLoadBalancerPreviousShard] != "" ||
		service.Annotations[annotationNodeLoadBalancerDatapathRestage] != "" ||
		len(service.Status.LoadBalancer.Ingress) != 1 ||
		service.Status.LoadBalancer.Ingress[0].IP != externalIP ||
		!d.harness.fixture.shardPolicyStable(t, shard, 1) {
		return false
	}
	if retiredShard != "" {
		if _, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
			d.harness.ctx, retiredShard, metav1.GetOptions{},
		); !apierrors.IsNotFound(err) {
			return false
		}
	}
	return true
}

func (d *aggregateMigrationDriver) requireRetiredShard(t *testing.T, shard, firewallUUID string) {
	t.Helper()
	if _, err := d.harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		d.harness.ctx, shard, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("retired NodePool %s remains: %v", shard, err)
	}
	if !d.releasedFinalizers[shard] {
		t.Fatalf("retired NodePool %s never released its state finalizer", shard)
	}
	wantName, err := inspace.NodeLoadBalancerShardFirewallName(d.harness.provider.config.ClusterID, shard)
	if err != nil {
		t.Fatal(err)
	}
	for _, firewall := range d.harness.api.firewalls {
		if firewall.EffectiveName() == wantName {
			t.Fatalf("retired shard firewall remains: %#v", firewall)
		}
	}
	if !containsString(d.harness.api.deletedFirewalls, firewallUUID) {
		t.Fatalf("retired shard firewall %s was never deleted: %#v", firewallUUID, d.harness.api.deletedFirewalls)
	}
}

func (d *aggregateMigrationDriver) requireActiveShard(t *testing.T, shard string, port int32, externalIP string) {
	t.Helper()
	service := d.harness.service(t)
	if service.Annotations[annotationNodeLoadBalancerShard] != shard ||
		service.Annotations[annotationNodeLoadBalancerDatapathActive] != shard ||
		service.Annotations[annotationNodeLoadBalancerPreviousShard] != "" ||
		len(service.Status.LoadBalancer.Ingress) != 1 ||
		service.Status.LoadBalancer.Ingress[0].IP != externalIP {
		t.Fatalf("Service did not cut over exactly to %s: annotations=%#v status=%#v", shard, service.Annotations, service.Status.LoadBalancer)
	}
	child, err := d.harness.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		d.harness.ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Spec.Ports) != 1 || child.Spec.Ports[0].Port != port ||
		child.Annotations[annotationNodeLoadBalancerDatapathShard] != shard ||
		len(child.Status.LoadBalancer.Ingress) != 1 ||
		child.Status.LoadBalancer.Ingress[0].IP == externalIP {
		t.Fatalf("functional child did not cut over exactly: annotations=%#v spec=%#v status=%#v", child.Annotations, child.Spec, child.Status.LoadBalancer)
	}
}
