package cloudprovider

import (
	"context"
	"errors"
	"strconv"
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
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

func TestNodeLoadBalancerProfileChangeDoesNotPreserveOldShard(t *testing.T) {
	ctx := context.Background()
	const oldShard = "inlb-0123abcd"

	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Annotations[annotationNodeLoadBalancerShard] = oldShard
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"

	oldProfile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	nodePool := nodeLoadBalancerSafetyNodePool(oldShard, "unit-test-cluster", oldProfile, 1)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme(), nodePool)
	provider.kubeClient = kubefake.NewSimpleClientset(
		service.DeepCopy(),
		desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), provider.config.ClusterID, oldShard),
	)

	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service); err != nil {
		t.Fatal(err)
	}
	if err := serviceIndexer.Add(desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", oldShard)); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	if intent.ExistingShard != "" {
		t.Fatalf("profile-changed Service retained old shard %q", intent.ExistingShard)
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == oldShard {
		t.Fatalf("profile-changed Service assignment = %q, want a new shard", got)
	}
}

func TestNodeLoadBalancerDefaultUpgradeMigratesLegacyUnderMinimumShard(t *testing.T) {
	ctx := context.Background()
	const oldShard = "inlb-0123abcd"

	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Annotations[annotationNodeLoadBalancerShard] = oldShard
	nodePool := nodeLoadBalancerSafetyLegacyNodePool(oldShard, "unit-test-cluster", nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1)

	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme(), nodePool)
	provider.kubeClient = kubefake.NewSimpleClientset(
		service.DeepCopy(),
		desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), provider.config.ClusterID, oldShard),
	)
	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service); err != nil {
		t.Fatal(err)
	}
	if err := serviceIndexer.Add(desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), provider.config.ClusterID, oldShard)); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	if intent.ExistingShard != "" {
		t.Fatalf("upgraded Service retained legacy under-minimum shard %q", intent.ExistingShard)
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == oldShard {
		t.Fatalf("upgraded Service assignment = %q, want a guarded replacement shard", got)
	}
}

func TestNodeLoadBalancerChangedPortCannotEvictStableSharedClaim(t *testing.T) {
	ctx := context.Background()
	const oldShard = "inlb-0123abcd"

	changed := nodeLoadBalancerTestService("changed", "changed-uid", corev1.ProtocolTCP, 443)
	changed.Annotations[annotationNodeLoadBalancerShard] = oldShard
	stable := nodeLoadBalancerTestService("stable", "stable-uid", corev1.ProtocolTCP, 443)
	stable.Annotations[annotationNodeLoadBalancerShard] = oldShard
	changedBeforeEdit := changed.DeepCopy()
	changedBeforeEdit.Spec.Ports[0].Port = 80

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	nodePool := nodeLoadBalancerSafetyNodePool(oldShard, "unit-test-cluster", profile, 1)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme(), nodePool)
	provider.kubeClient = kubefake.NewSimpleClientset(
		changed.DeepCopy(), stable.DeepCopy(),
		desiredNodeLoadBalancerShadow(changedBeforeEdit, nodeLoadBalancerShadowName(changed), provider.config.ClusterID, oldShard),
		desiredNodeLoadBalancerShadow(stable, nodeLoadBalancerShadowName(stable), provider.config.ClusterID, oldShard),
	)

	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		changed,
		stable,
		desiredNodeLoadBalancerShadow(changedBeforeEdit, nodeLoadBalancerShadowName(changed), "unit-test-cluster", oldShard),
		desiredNodeLoadBalancerShadow(stable, nodeLoadBalancerShadowName(stable), "unit-test-cluster", oldShard),
	} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Assignments[string(stable.UID)] != oldShard {
		t.Fatalf("stable Service moved from %q to %q", oldShard, plan.Assignments[string(stable.UID)])
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == oldShard {
		t.Fatalf("changed Service assignment = %q, want a new conflict-free shard", got)
	}
}

func TestNodeLoadBalancerInactiveMigratingPortEditCannotEvictActiveReplacementClaim(t *testing.T) {
	ctx := context.Background()
	const (
		oldShard         = "inlb-0123abcd"
		replacementShard = "inlb-89abcdef"
	)

	staged := nodeLoadBalancerTestService("staged", "a-staged-uid", corev1.ProtocolTCP, 443)
	staged.Annotations[annotationNodeLoadBalancerShard] = replacementShard
	staged.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
	stagedBeforeEdit := staged.DeepCopy()
	stagedBeforeEdit.Spec.Ports[0].Port = 80
	active := nodeLoadBalancerTestService("active", "z-active-uid", corev1.ProtocolTCP, 443)
	active.Annotations[annotationNodeLoadBalancerShard] = replacementShard

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(
		runtime.NewScheme(),
		nodeLoadBalancerSafetyNodePool(replacementShard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		staged.DeepCopy(), active.DeepCopy(),
		desiredNodeLoadBalancerShadow(stagedBeforeEdit, nodeLoadBalancerShadowName(staged), provider.config.ClusterID, oldShard),
		desiredNodeLoadBalancerShadow(active, nodeLoadBalancerShadowName(active), provider.config.ClusterID, replacementShard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		staged,
		active,
		desiredNodeLoadBalancerShadow(stagedBeforeEdit, nodeLoadBalancerShadowName(staged), provider.config.ClusterID, oldShard),
		desiredNodeLoadBalancerShadow(active, nodeLoadBalancerShadowName(active), provider.config.ClusterID, replacementShard),
	} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, staged)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Assignments[string(active.UID)]; got != replacementShard {
		t.Fatalf("active Service was evicted from replacement shard: got %q", got)
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == replacementShard {
		t.Fatalf("inactive port-edited Service assignment = %q, want a conflict-free shard", got)
	}
}

func TestNodeLoadBalancerSimultaneousPortSwapReservesBothLiveShadows(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	a := nodeLoadBalancerTestService("a", "a-service-uid", corev1.ProtocolTCP, 443)
	a.Annotations[annotationNodeLoadBalancerShard] = shard
	aBeforeSwap := a.DeepCopy()
	aBeforeSwap.Spec.Ports[0].Port = 80
	x := nodeLoadBalancerTestService("x", "x-service-uid", corev1.ProtocolTCP, 80)
	x.Annotations[annotationNodeLoadBalancerShard] = shard
	xBeforeSwap := x.DeepCopy()
	xBeforeSwap.Spec.Ports[0].Port = 443

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(
		runtime.NewScheme(),
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		a.DeepCopy(), x.DeepCopy(),
		desiredNodeLoadBalancerShadow(aBeforeSwap, nodeLoadBalancerShadowName(a), provider.config.ClusterID, shard),
		desiredNodeLoadBalancerShadow(xBeforeSwap, nodeLoadBalancerShadowName(x), provider.config.ClusterID, shard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		a,
		x,
		desiredNodeLoadBalancerShadow(aBeforeSwap, nodeLoadBalancerShadowName(a), provider.config.ClusterID, shard),
		desiredNodeLoadBalancerShadow(xBeforeSwap, nodeLoadBalancerShadowName(x), provider.config.ClusterID, shard),
	} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	_, plan, _, err := controller.planForService(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	aShard := plan.Assignments[string(a.UID)]
	xShard := plan.Assignments[string(x.UID)]
	if aShard == "" || xShard == "" || aShard == shard || xShard == shard {
		t.Fatalf("live-shadow port swap reused unsafe shard: A=%q X=%q", aShard, xShard)
	}
	if aShard != xShard {
		t.Fatalf("conflict-free swapped claims did not share their safe replacement: A=%q X=%q", aShard, xShard)
	}
}

func TestNodeLoadBalancerDeletingPeerShadowReservesItsPortUntilCleanup(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	a := nodeLoadBalancerTestService("a", "a-service-uid", corev1.ProtocolTCP, 443)
	a.Annotations[annotationNodeLoadBalancerShard] = shard
	aBeforeEdit := a.DeepCopy()
	aBeforeEdit.Spec.Ports[0].Port = 80
	deleting := nodeLoadBalancerTestService("deleting", "z-deleting-uid", corev1.ProtocolTCP, 443)
	deleting.Finalizers = []string{nodeLoadBalancerFinalizer}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting.Annotations[annotationNodeLoadBalancerShard] = shard

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(
		runtime.NewScheme(),
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		a.DeepCopy(), deleting.DeepCopy(),
		desiredNodeLoadBalancerShadow(aBeforeEdit, nodeLoadBalancerShadowName(a), provider.config.ClusterID, shard),
		desiredNodeLoadBalancerShadow(deleting, nodeLoadBalancerShadowName(deleting), provider.config.ClusterID, shard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		a,
		deleting,
		desiredNodeLoadBalancerShadow(aBeforeEdit, nodeLoadBalancerShadowName(a), provider.config.ClusterID, shard),
		desiredNodeLoadBalancerShadow(deleting, nodeLoadBalancerShadowName(deleting), provider.config.ClusterID, shard),
	} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == shard {
		t.Fatalf("Service claimed deleting peer's still-live port on shard %s: %q", shard, got)
	}
}

func TestNodeLoadBalancerPlannerReadsLiveShadowWhenInformerIsStale(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	target := nodeLoadBalancerTestService("target", "a-target-uid", corev1.ProtocolTCP, 443)
	stable := nodeLoadBalancerTestService("stable", "m-stable-uid", corev1.ProtocolTCP, 80)
	stable.Annotations[annotationNodeLoadBalancerShard] = shard
	deleting := nodeLoadBalancerTestService("deleting", "z-deleting-uid", corev1.ProtocolTCP, 443)
	deleting.Finalizers = []string{nodeLoadBalancerFinalizer}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting.Annotations[annotationNodeLoadBalancerShard] = shard
	stableShadow := desiredNodeLoadBalancerShadow(stable, nodeLoadBalancerShadowName(stable), "unit-test-cluster", shard)
	deletingShadow := desiredNodeLoadBalancerShadow(deleting, nodeLoadBalancerShadowName(deleting), "unit-test-cluster", shard)

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = fake.NewSimpleDynamicClient(
		runtime.NewScheme(),
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	// The authoritative API already contains the deleting peer shadow, while
	// the deliberately stale informer below has not observed it yet.
	provider.kubeClient = kubefake.NewSimpleClientset(
		target.DeepCopy(), stable.DeepCopy(), deleting.DeepCopy(), stableShadow.DeepCopy(), deletingShadow.DeepCopy(),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{target, stable, deleting, stableShadow} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Assignments[intent.ServiceID]; got == "" || got == shard {
		t.Fatalf("stale informer let target claim live shadow port on %s: %q", shard, got)
	}
}

func TestNodeLoadBalancerRejectsForeignClusterNodePoolUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"

	foreign := nodeLoadBalancerSafetyNodePool(shard, "foreign-cluster", "11111111", 1)
	provider := newTestProvider(t, &fakeAPI{})
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme(), foreign)
	controller := &nodeLoadBalancerController{provider: provider}

	desired := foreign.DeepCopy()
	desired.SetLabels(map[string]string{
		nodeLoadBalancerManagedLabel: "true",
		nodeLoadBalancerClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerShardLabel:   shard,
		nodeLoadBalancerProfileLabel: "22222222",
	})
	if err := unstructured.SetNestedField(desired.Object, int64(2), "spec", "replicas"); err != nil {
		t.Fatal(err)
	}
	if err := controller.ensureDynamicObject(ctx, nodePoolGVR, desired); err == nil || !strings.Contains(err.Error(), "exact cluster ownership") {
		t.Fatalf("foreign NodePool update error = %v", err)
	}

	stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replicas, _, _ := unstructured.NestedInt64(stored.Object, "spec", "replicas"); replicas != 1 {
		t.Fatalf("foreign NodePool was updated to %d replicas", replicas)
	}

	if err := controller.deleteManagedNodePool(ctx, shard); err == nil || !strings.Contains(err.Error(), "exact managed ownership") {
		t.Fatalf("foreign NodePool delete error = %v", err)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign NodePool was deleted: %v", err)
	}
}

func TestNodeLoadBalancerDefaultedNodePoolReadbackIsIdempotent(t *testing.T) {
	ctx := context.Background()
	const shardName = "inlb-89abcdef"
	shard := nodeLoadBalancerShardPlan{
		Name: shardName, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: 1, CPU: nodeLoadBalancerDefaultCPU, MemoryMiB: nodeLoadBalancerDefaultMemoryMiB,
	}
	desired, err := renderNodeLoadBalancerNodePool(shardName, "unit-test-node-lb", shard)
	if err != nil {
		t.Fatal(err)
	}
	if err := markNodeLoadBalancerManaged(desired, "unit-test-cluster", shardName, nodeLoadBalancerShardProfileHash(shard)); err != nil {
		t.Fatal(err)
	}
	// This is the exact shape returned after the Karpenter CRD has applied its
	// defaults. Reconciliation must be a read-only GET, not a perpetual UPDATE.
	stored := desired.DeepCopy()
	stored.SetResourceVersion("1")
	dynamicClient := fake.NewSimpleDynamicClient(runtime.NewScheme(), stored)
	provider := newTestProvider(t, &fakeAPI{})
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.ensureDynamicObject(ctx, nodePoolGVR, desired); err != nil {
		t.Fatal(err)
	}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "update" {
			t.Fatalf("defaulted NodePool readback caused an UPDATE: %#v", action)
		}
	}
}

func TestNodeLoadBalancerNodePoolAuthorizationRequiresFullHardenedProfile(t *testing.T) {
	const shard = "inlb-89abcdef"
	provider := newTestProvider(t, &fakeAPI{})
	controller := &nodeLoadBalancerController{provider: provider}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	baseline := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1)
	if !controller.nodeLoadBalancerNodePoolAuthoritative(baseline, shard, nodeClassName) {
		t.Fatal("exact rendered NodePool was not authoritative")
	}
	withUnrelatedMetadata := baseline.DeepCopy()
	labels := withUnrelatedMetadata.GetLabels()
	labels["example.com/operator-note"] = "preserved"
	withUnrelatedMetadata.SetLabels(labels)
	if !controller.nodeLoadBalancerNodePoolAuthoritative(withUnrelatedMetadata, shard, nodeClassName) {
		t.Fatal("unrelated metadata made the exact desired NodePool non-authoritative")
	}

	tests := map[string]func(*testing.T, *unstructured.Unstructured){
		"missing isolation taint": func(t *testing.T, pool *unstructured.Unstructured) {
			t.Helper()
			unstructured.RemoveNestedField(pool.Object, "spec", "template", "spec", "taints")
		},
		"changed CPU requirement": func(t *testing.T, pool *unstructured.Unstructured) {
			t.Helper()
			requirements, found, err := unstructured.NestedSlice(pool.Object, "spec", "template", "spec", "requirements")
			if err != nil || !found {
				t.Fatalf("read requirements: found=%t err=%v", found, err)
			}
			for _, raw := range requirements {
				requirement := raw.(map[string]any)
				if requirement["key"] == "inspace.cloud/instance-cpu" {
					requirement["values"] = []any{"4"}
				}
			}
			if err := unstructured.SetNestedSlice(pool.Object, requirements, "spec", "template", "spec", "requirements"); err != nil {
				t.Fatal(err)
			}
		},
		"changed disruption policy": func(t *testing.T, pool *unstructured.Unstructured) {
			t.Helper()
			if err := unstructured.SetNestedField(pool.Object, "WhenEmpty", "spec", "disruption", "consolidationPolicy"); err != nil {
				t.Fatal(err)
			}
		},
		"changed expiry": func(t *testing.T, pool *unstructured.Unstructured) {
			t.Helper()
			if err := unstructured.SetNestedField(pool.Object, "Never", "spec", "template", "spec", "expireAfter"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pool := baseline.DeepCopy()
			mutate(t, pool)
			if controller.nodeLoadBalancerNodePoolAuthoritative(pool, shard, nodeClassName) {
				t.Fatal("drifted NodePool remained authoritative")
			}
		})
	}
}

func TestNodeLoadBalancerLegacyNodePoolAuthorizationIsExactAndMigrationOnly(t *testing.T) {
	const shard = "inlb-89abcdef"
	provider := newTestProvider(t, &fakeAPI{})
	controller := &nodeLoadBalancerController{provider: provider}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	legacyPlan := nodeLoadBalancerShardPlan{
		Name: shard, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: 1, CPU: 1, MemoryMiB: 2048,
	}
	baseline := nodeLoadBalancerSafetyLegacyNodePool(
		shard,
		provider.config.ClusterID,
		legacyPlan.Mode,
		legacyPlan.Pool,
		int64(legacyPlan.NodesPerShard),
	)
	if controller.nodeLoadBalancerNodePoolAuthoritative(baseline, shard, nodeClassName) {
		t.Fatal("normal authorization accepted the legacy under-minimum NodePool")
	}
	if !controller.legacyNodeLoadBalancerNodePoolAuthoritative(baseline, shard, nodeClassName, legacyPlan) {
		t.Fatal("exact legacy NodePool was not accepted by the migration-only predicate")
	}
	if _, err := renderNodeLoadBalancerNodePool(shard, nodeClassName, legacyPlan); err == nil {
		t.Fatal("normal renderer accepted the legacy under-minimum shape")
	}

	tests := map[string]func(*testing.T, *unstructured.Unstructured, *nodeLoadBalancerShardPlan){
		"wrong profile": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			labels := pool.GetLabels()
			labels[nodeLoadBalancerProfileLabel] = "foreign-profile"
			pool.SetLabels(labels)
		},
		"foreign cluster ownership": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			labels := pool.GetLabels()
			labels[nodeLoadBalancerClusterLabel] = "foreign-cluster"
			pool.SetLabels(labels)
		},
		"missing isolation taint": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			unstructured.RemoveNestedField(pool.Object, "spec", "template", "spec", "taints")
		},
		"changed disruption policy": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			if err := unstructured.SetNestedField(pool.Object, "WhenEmpty", "spec", "disruption", "consolidationPolicy"); err != nil {
				t.Fatal(err)
			}
		},
		"wrong CPU": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			setNodeLoadBalancerSafetyRequirement(t, pool, "inspace.cloud/instance-cpu", "2")
		},
		"wrong memory": func(t *testing.T, pool *unstructured.Unstructured, _ *nodeLoadBalancerShardPlan) {
			setNodeLoadBalancerSafetyRequirement(t, pool, "inspace.cloud/instance-memory", "4096")
		},
		"mismatched expected mode": func(_ *testing.T, _ *unstructured.Unstructured, expected *nodeLoadBalancerShardPlan) {
			expected.Mode = nodeLoadBalancerModeDedicated
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pool := baseline.DeepCopy()
			expected := legacyPlan
			mutate(t, pool, &expected)
			if controller.legacyNodeLoadBalancerNodePoolAuthoritative(pool, shard, nodeClassName, expected) {
				t.Fatal("drifted legacy NodePool remained authoritative")
			}
		})
	}
}

func TestNodeLoadBalancerForeignShadowNameFailsBeforeFinalizerOrCapacity(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	foreignOwner := nodeLoadBalancerTestService("foreign", "foreign-uid", corev1.ProtocolTCP, 8443)
	foreignShadow := desiredNodeLoadBalancerShadow(foreignOwner, nodeLoadBalancerShadowName(service), "unit-test-cluster", "inlb-0123abcd")
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), foreignShadow.DeepCopy())
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{service, foreignShadow} {
		if err := serviceIndexer.Add(object.DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
		nodes:    corelisters.NewNodeLister(newNamespacedIndexer()),
	}
	err := controller.sync(ctx, service.Namespace+"/"+service.Name)
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("foreign shadow preflight error = %v", err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if containsString(stored.Finalizers, nodeLoadBalancerFinalizer) || stored.Annotations[annotationNodeLoadBalancerShard] != "" {
		t.Fatalf("foreign shadow caused managed metadata before preflight: %#v", stored.ObjectMeta)
	}
}

func TestNodeLoadBalancerInvalidFinalizedServiceQuarantine(t *testing.T) {
	t.Run("deletes exact shadow and clears status", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerSafetyInvalidFinalizedService("web", "web-uid")
		shadow := desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", "inlb-0123abcd")
		unrelatedOwner := nodeLoadBalancerTestService("other", "other-uid", corev1.ProtocolTCP, 8443)
		unrelated := desiredNodeLoadBalancerShadow(unrelatedOwner, nodeLoadBalancerShadowName(unrelatedOwner), "unit-test-cluster", "inlb-89abcdef")

		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow, unrelated)
		serviceIndexer := newNamespacedIndexer()
		if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		controller := &nodeLoadBalancerController{
			provider: provider,
			services: corelisters.NewServiceLister(serviceIndexer),
		}

		if err := controller.sync(ctx, "default/web"); err == nil {
			t.Fatal("invalid finalized Service reconciled without an error")
		}
		if _, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, shadow.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("owned shadow still exists: %v", err)
		}
		if _, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, unrelated.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("unrelated shadow was deleted: %v", err)
		}
		stored, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored.Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("invalid Service retained load-balancer status: %#v", stored.Status.LoadBalancer)
		}
	})

	t.Run("refuses foreign shadow", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerSafetyInvalidFinalizedService("web", "web-uid")
		shadow := desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", "inlb-0123abcd")
		shadow.Labels[nodeLoadBalancerServiceUIDLabel] = "foreign-uid"
		shadow.OwnerReferences[0].UID = types.UID("foreign-uid")

		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow)
		serviceIndexer := newNamespacedIndexer()
		if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		controller := &nodeLoadBalancerController{
			provider: provider,
			services: corelisters.NewServiceLister(serviceIndexer),
		}

		err := controller.sync(ctx, "default/web")
		if err == nil || !strings.Contains(err.Error(), "refusing to delete shadow Service") {
			t.Fatalf("foreign shadow quarantine error = %v", err)
		}
		if _, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, shadow.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("foreign shadow was deleted: %v", err)
		}
		stored, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored.Status.LoadBalancer.Ingress) != 1 {
			t.Fatalf("status changed despite foreign-shadow refusal: %#v", stored.Status.LoadBalancer)
		}
	})
}

func TestNodeLoadBalancerQuarantinedInvalidPeerDoesNotBlockHealthyPlanning(t *testing.T) {
	ctx := context.Background()
	healthy := nodeLoadBalancerTestService("healthy", "healthy-uid", corev1.ProtocolTCP, 443)
	invalid := nodeLoadBalancerSafetyInvalidFinalizedService("invalid", "invalid-uid")
	invalid.Status.LoadBalancer = corev1.LoadBalancerStatus{}

	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(healthy.DeepCopy(), invalid.DeepCopy())
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme())
	serviceIndexer := newNamespacedIndexer()
	for _, service := range []*corev1.Service{healthy, invalid} {
		if err := serviceIndexer.Add(service); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, plan, _, err := controller.planForService(ctx, healthy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Assignments[intent.ServiceID] == "" {
		t.Fatalf("healthy Service was not assigned: %#v", plan)
	}
	if _, exists := plan.Assignments[string(invalid.UID)]; exists {
		t.Fatalf("invalid Service remained in the shard plan: %#v", plan.Assignments)
	}
}

func TestNodeLoadBalancerQuarantineDeletesSoleInvalidServiceNodePool(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	service := nodeLoadBalancerSafetyInvalidFinalizedService("invalid", "invalid-uid")
	service.Annotations[annotationNodeLoadBalancerShard] = shard
	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	provider.dynamicClient = fake.NewSimpleDynamicClient(runtime.NewScheme(), nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1))
	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
		nodes:    corelisters.NewNodeLister(newNamespacedIndexer()),
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()

	if err := controller.quarantineInvalidService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("sole invalid Service retained billable NodePool: %v", err)
	}
}

func TestNodeLoadBalancerCleanupDiscoversUnannotatedOwnedFirewallToAbsence(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	if service.Annotations[annotationNodeLoadBalancerFirewallUUID] != "" || service.Annotations[annotationNodeLoadBalancerFirewallHash] != "" {
		t.Fatal("test Service unexpectedly has firewall identity annotations")
	}

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{
		provider: provider,
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()

	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const firewallUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	const vmUUID = "cccccccc-1111-4222-8333-dddddddddddd"
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}}

	if err := controller.cleanupService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if len(api.unassignedFirewalls) != 1 || api.unassignedFirewalls[0] != firewallUUID+"/"+vmUUID || len(api.deletedFirewalls) != 0 {
		t.Fatalf("unassign phase: unassigned=%#v deleted=%#v", api.unassignedFirewalls, api.deletedFirewalls)
	}

	if err := controller.cleanupService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != firewallUUID || len(api.firewalls) != 0 {
		t.Fatalf("delete phase: deleted=%#v firewalls=%#v", api.deletedFirewalls, api.firewalls)
	}

	stored := service
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if confirmation > 1 {
			stored = ageNodeLoadBalancerAbsenceEvidence(
				t, ctx, provider, stored, annotationNodeLoadBalancerCleanupFWChecked,
			)
		}
		if err := controller.cleanupService(ctx, stored); err != nil {
			t.Fatal(err)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if got := stored.Annotations[annotationNodeLoadBalancerCleanupFWAbsent]; got != strconv.Itoa(confirmation) {
			t.Fatalf("cleanup absence confirmation %d = %q", confirmation, got)
		}
		if !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
			t.Fatalf("finalizer cleared after only %d absence confirmations", confirmation)
		}
	}
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("finalizer remained after firewall absence was proved: %#v", stored.Finalizers)
	}
}

func TestNodeLoadBalancerCleanupDeletesCurrentAndPreviousMigrationShards(t *testing.T) {
	ctx := context.Background()
	const (
		currentShard  = "inlb-89abcdef"
		previousShard = "inlb-0123abcd"
	)
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = currentShard
	service.Annotations[annotationNodeLoadBalancerPreviousShard] = previousShard
	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)

	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyNodePool(currentShard, provider.config.ClusterID, profile, 1),
		nodeLoadBalancerSafetyNodePool(previousShard, provider.config.ClusterID, profile, 1),
	)
	controller := &nodeLoadBalancerController{
		provider: provider,
		nodes:    corelisters.NewNodeLister(newNamespacedIndexer()),
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()

	stored := service
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if confirmation > 1 {
			stored = ageNodeLoadBalancerAbsenceEvidence(
				t, ctx, provider, stored, annotationNodeLoadBalancerCleanupFWChecked,
			)
		}
		if err := controller.cleanupService(ctx, stored); err != nil {
			t.Fatal(err)
		}
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	for _, shard := range []string{currentShard, previousShard} {
		if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("migration shard %s remains after finalization: %v", shard, err)
		}
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("finalizer remains after both migration shards were removed: %#v", stored.Finalizers)
	}
}

func TestNodeLoadBalancerDeterministicFirewallIdentity(t *testing.T) {
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	provider := newTestProvider(t, &fakeAPI{})
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}

	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb",
		DisplayName:      desired.Request.DisplayName,
		Description:      "", // InSpace may omit Description from ListFirewalls.
		BillingAccountID: desired.Request.BillingAccountID,
		Rules:            desired.Request.Rules,
	}
	if !nodeLoadBalancerFirewallMatches(firewall, desired) {
		t.Fatal("exact deterministic firewall with omitted Description was rejected")
	}
	if !nodeLoadBalancerFirewallOwnedByService(firewall, provider.config.ClusterID, string(service.UID), provider.config.BillingAccountID) {
		t.Fatal("exact deterministic firewall was not recognized as Service-owned")
	}

	policyDrift := firewall
	policyDrift.Rules = append([]inspace.FirewallRule(nil), firewall.Rules...)
	changedPort := *policyDrift.Rules[0].PortStart + 1
	policyDrift.Rules[0].PortStart = &changedPort
	policyDrift.Rules[0].PortEnd = &changedPort
	if nodeLoadBalancerFirewallMatches(policyDrift, desired) ||
		nodeLoadBalancerFirewallOwnedByService(policyDrift, provider.config.ClusterID, string(service.UID), provider.config.BillingAccountID) {
		t.Fatal("firewall policy drift retained deterministic ownership")
	}

	hashDrift := firewall
	driftHash := "00000000"
	if driftHash == desired.Hash {
		driftHash = "11111111"
	}
	hashDrift.DisplayName = nodeLoadBalancerFirewallServicePrefix(provider.config.ClusterID, string(service.UID)) + driftHash
	if nodeLoadBalancerFirewallMatches(hashDrift, desired) ||
		nodeLoadBalancerFirewallOwnedByService(hashDrift, provider.config.ClusterID, string(service.UID), provider.config.BillingAccountID) {
		t.Fatal("firewall name/hash drift retained deterministic ownership")
	}
}

func TestNodeLoadBalancerPendingFirewallPreventsDuplicateCreateDuringDelayedReadback(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	if firewall, _, ready, err := controller.ensureServiceFirewall(ctx, service, nil); err != nil || firewall != nil || ready {
		t.Fatalf("initial firewall create = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("initial create count = %d", len(api.createdFirewalls))
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Annotations[annotationNodeLoadBalancerPendingFirewall] == "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWName] == "" {
		t.Fatalf("pending identity was not persisted: %#v", stored.Annotations)
	}

	// Simulate an eventually consistent ListFirewalls response immediately
	// after a successful POST. The pending identity must suppress another POST.
	api.firewalls = nil
	if firewall, _, ready, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil || firewall != nil || ready {
		t.Fatalf("delayed readback = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("delayed readback issued %d creates, want exactly one", len(api.createdFirewalls))
	}
}

func TestNodeLoadBalancerClusterICMPPendingPreventsDuplicateCreateDuringDelayedReadback(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())
	controller := &nodeLoadBalancerController{provider: provider}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	if err := controller.ensureNodeClass(ctx, nodeClassName); err != nil {
		t.Fatal(err)
	}

	if firewall, ready, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err != nil || firewall != nil || ready {
		t.Fatalf("initial cluster ICMP create = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("initial cluster ICMP create count = %d", len(api.createdFirewalls))
	}
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := nodeClass.GetAnnotations()
	if annotations[annotationNodeLoadBalancerICMPPendingUUID] == "" ||
		annotations[annotationNodeLoadBalancerICMPPendingName] == "" ||
		annotations[annotationNodeLoadBalancerICMPPendingStarted] == "" {
		t.Fatalf("cluster ICMP pending identity was not persisted: %#v", annotations)
	}

	// Simulate an eventually consistent list after the POST. Durable NodeClass
	// intent must suppress a duplicate create, including after controller restart.
	api.firewalls = nil
	restarted := &nodeLoadBalancerController{provider: provider}
	if firewall, ready, err := restarted.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err != nil || firewall != nil || ready {
		t.Fatalf("delayed cluster ICMP readback = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("delayed cluster ICMP readback issued %d creates, want one", len(api.createdFirewalls))
	}
}

func TestNodeLoadBalancerExpiredPendingCreateRecoversWithoutPermanentStall(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerPendingFWName] = desired.Request.DisplayName
	service.Annotations[annotationNodeLoadBalancerPendingFWStarted] = time.Now().Add(-nodeLoadBalancerPendingCreateTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())

	stored := service
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			stored = ageNodeLoadBalancerAbsenceEvidence(
				t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked,
			)
		}
		if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
			t.Fatal(err)
		}
		if len(api.createdFirewalls) != 0 {
			t.Fatalf("expired intent created after only %d absence confirmations", confirmation)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if got := stored.Annotations[annotationNodeLoadBalancerPendingFWAbsent]; got != strconv.Itoa(confirmation) {
			t.Fatalf("pending absence confirmation %d = %q", confirmation, got)
		}
	}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		t.Fatalf("confirmed pending intent remains: %#v", stored.Annotations)
	}
	if len(api.createdFirewalls) != 0 {
		t.Fatalf("metadata-clearing reconciliation issued a create: %d", len(api.createdFirewalls))
	}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("recovered create count = %d, want one", len(api.createdFirewalls))
	}
}

func TestNodeLoadBalancerPendingFirewallVisibilityResetsAbsenceProofWithoutDuplicateCreate(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerPendingFWName] = desired.Request.DisplayName
	service.Annotations[annotationNodeLoadBalancerPendingFWStarted] = time.Now().Add(-nodeLoadBalancerPendingCreateTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())

	stored := service
	for confirmation := 1; confirmation <= 2; confirmation++ {
		if confirmation > 1 {
			stored = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked)
		}
		if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
			t.Fatal(err)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	}
	const firewallUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}

	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFirewall] != firewallUUID ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
		t.Fatalf("visible firewall did not reset provisional absence evidence: %#v", stored.Annotations)
	}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	firewall, _, ready, err := controller.ensureServiceFirewall(ctx, stored, nil)
	if err != nil || firewall == nil || firewall.UUID != firewallUUID || !ready {
		t.Fatalf("adopted firewall = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 0 {
		t.Fatalf("late visibility caused %d duplicate creates", len(api.createdFirewalls))
	}
}

func TestNodeLoadBalancerCurrentFirewallTransientOmissionCannotCreateDuplicate(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const firewallUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	stored := service
	for confirmation := 1; confirmation <= 2; confirmation++ {
		if confirmation > 1 {
			stored = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerFirewallChecked)
		}
		if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
			t.Fatal(err)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if len(api.createdFirewalls) != 0 {
			t.Fatalf("transient omission caused a create after %d observations", confirmation)
		}
	}
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallAbsent] != "" ||
		stored.Annotations[annotationNodeLoadBalancerFirewallChecked] != "" {
		t.Fatalf("current firewall visibility did not reset absence evidence: %#v", stored.Annotations)
	}
	firewall, _, ready, err := controller.ensureServiceFirewall(ctx, stored, nil)
	if err != nil || firewall == nil || firewall.UUID != firewallUUID || !ready {
		t.Fatalf("recovered current firewall = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 0 {
		t.Fatalf("transient omission caused %d duplicate creates", len(api.createdFirewalls))
	}
}

func TestNodeLoadBalancerCleanupRetainsFinalizerUntilLatePendingFirewallIsDeleted(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{
		provider: provider,
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerPendingFWName] = desired.Request.DisplayName
	service.Annotations[annotationNodeLoadBalancerPendingFWStarted] = time.Now().Add(-nodeLoadBalancerPendingCreateTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())

	if err := controller.cleanupService(ctx, service); err != nil {
		t.Fatal(err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWDelete] != "true" || !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("cleanup did not persist deletion intent and retain finalizer: %#v", stored.ObjectMeta)
	}
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	stored = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked)
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "2" {
		t.Fatalf("pending absence evidence = %#v", stored.Annotations)
	}

	const firewallUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWAbsent] != "" || !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("late firewall did not reset absence evidence while retaining finalizer: %#v", stored.ObjectMeta)
	}
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != firewallUUID || len(api.firewalls) != 0 {
		t.Fatalf("late firewall cleanup: deleted=%#v remaining=%#v", api.deletedFirewalls, api.firewalls)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatal("finalizer cleared in the same reconciliation that deleted the late firewall")
	}
}

func TestNodeLoadBalancerMigrationKeepsOldDataplaneUntilReplacementStatusConverges(t *testing.T) {
	ctx := context.Background()
	const (
		oldShard = "inlb-0123abcd"
		newShard = "inlb-89abcdef"
		oldVM    = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		newVM    = "cccccccc-1111-4222-8333-dddddddddddd"
		oldIP    = "203.0.113.10"
		newIP    = "203.0.113.20"
	)
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = newShard
	service.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: oldIP}}
	shadow := desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", oldShard)
	shadow.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: oldIP}}
	oldNode := readyNode("lb-old", "inspace://bkk01/"+oldVM)
	oldNode.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   oldShard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	oldNode.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: oldIP}}

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const firewallUUID = "eeeeeeee-1111-4222-8333-ffffffffffff"
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: oldVM}},
	}}
	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	base := nodeLoadBalancerSafetyBaseNodeClass()
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		base,
		nodeLoadBalancerSafetyLegacyNodePool(oldShard, provider.config.ClusterID, nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1),
		nodeLoadBalancerSafetyNodePool(newShard, provider.config.ClusterID, profile, 1),
	)
	installNodeLoadBalancerSafetyIdentity(t, provider, oldNode, oldShard)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow.DeepCopy(), oldNode.DeepCopy())
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{service.DeepCopy(), shadow.DeepCopy()} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(oldNode.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller.services = corelisters.NewServiceLister(serviceIndexer)
	controller.nodes = corelisters.NewNodeLister(nodeIndexer)
	controller.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer controller.queue.ShutDown()
	legacyShards, err := controller.legacyNodeLoadBalancerMigrationShards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacyPlan, allowed := legacyShards[oldShard]
	if !allowed {
		t.Fatalf("active old shard was not identified as a legacy migration: %#v", legacyShards)
	}
	legacyPool, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, oldShard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !controller.legacyNodeLoadBalancerNodePoolAuthoritative(
		legacyPool,
		oldShard,
		managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb"),
		legacyPlan,
	) {
		desiredLegacy, renderErr := renderLegacyNodeLoadBalancerNodePoolForAuthorization(oldShard, managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb"), legacyPlan)
		if renderErr != nil {
			t.Fatal(renderErr)
		}
		if markErr := markNodeLoadBalancerManaged(desiredLegacy, provider.config.ClusterID, oldShard, nodeLoadBalancerShardProfileHash(legacyPlan)); markErr != nil {
			t.Fatal(markErr)
		}
		t.Fatalf("active old NodePool was not authoritative for migration: plan=%#v actual=%#v desired=%#v", legacyPlan, legacyPool.Object, desiredLegacy.Object)
	}

	if err := controller.sync(ctx, service.Namespace+"/"+service.Name); err != nil {
		t.Fatal(err)
	}
	storedShadow := getNodeLoadBalancerTestService(t, ctx, provider, shadow.Namespace, shadow.Name)
	oldSelector := nodeLoadBalancerCiliumSelector("unit-test-cluster", oldShard)
	if storedShadow.Annotations[annotationCiliumNodeIPAMMatchLabels] != oldSelector ||
		len(storedShadow.Status.LoadBalancer.Ingress) != 1 || storedShadow.Status.LoadBalancer.Ingress[0].IP != oldIP {
		t.Fatalf("old shadow was cut over without replacement capacity: %#v", storedShadow)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, oldShard, metav1.GetOptions{}); err != nil {
		t.Fatalf("old NodePool was deleted before cutover: %v", err)
	}
	storedOldNode, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, oldNode.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if storedOldNode.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatal("legacy Node lost its Cilium readiness label before replacement capacity converged")
	}
	if !firewallAssignedToVM(*nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, firewallUUID), oldVM) {
		t.Fatal("Service firewall detached from the legacy Node before replacement capacity converged")
	}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	icmpUUID := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
	if icmpUUID == "" || !firewallAssignedToVM(*nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, icmpUUID), oldVM) {
		t.Fatal("cluster ICMP firewall detached from the legacy Node before replacement capacity converged")
	}

	newNode := readyNode("lb-new", "inspace://bkk01/"+newVM)
	newNode.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   newShard,
	}
	newNode.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: newIP}}
	installNodeLoadBalancerSafetyIdentity(t, provider, newNode, newShard)
	if _, err := provider.kubeClient.CoreV1().Nodes().Create(ctx, newNode.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := nodeIndexer.Add(newNode.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := controller.sync(ctx, service.Namespace+"/"+service.Name); err != nil {
			t.Fatalf("migration sync %d: %v", i, err)
		}
		storedService := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if err := serviceIndexer.Update(storedService); err != nil {
			t.Fatal(err)
		}
		storedShadow = getNodeLoadBalancerTestService(t, ctx, provider, shadow.Namespace, shadow.Name)
		newSelector := nodeLoadBalancerCiliumSelector("unit-test-cluster", newShard)
		if storedShadow.Annotations[annotationCiliumNodeIPAMMatchLabels] == newSelector &&
			(len(storedShadow.Status.LoadBalancer.Ingress) != 1 || storedShadow.Status.LoadBalancer.Ingress[0].IP != newIP) {
			storedShadow.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: newIP}}
			storedShadow, err = provider.kubeClient.CoreV1().Services(storedShadow.Namespace).UpdateStatus(ctx, storedShadow, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := serviceIndexer.Update(storedShadow); err != nil {
			t.Fatal(err)
		}
		storedNode, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, newNode.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := nodeIndexer.Update(storedNode); err != nil {
			t.Fatal(err)
		}
	}
	storedService := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if len(storedService.Status.LoadBalancer.Ingress) != 1 || storedService.Status.LoadBalancer.Ingress[0].IP != newIP {
		t.Fatalf("replacement status was not published: %#v", storedService.Status.LoadBalancer)
	}
	if storedService.Annotations[annotationNodeLoadBalancerPreviousShard] != "" {
		t.Fatalf("previous shard metadata remains after cutover: %#v", storedService.Annotations)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, oldShard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old NodePool remains after converged cutover: %v", err)
	}
	storedOldNode, err = provider.kubeClient.CoreV1().Nodes().Get(ctx, oldNode.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := storedOldNode.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("legacy Node retained its Cilium readiness label after cutover")
	}
	serviceFirewall := nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, firewallUUID)
	if firewallAssignedToVM(*serviceFirewall, oldVM) || !firewallAssignedToVM(*serviceFirewall, newVM) {
		t.Fatalf("post-cutover firewall assignments = %#v", serviceFirewall.ResourcesAssigned)
	}
	icmpFirewall := nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, icmpUUID)
	if firewallAssignedToVM(*icmpFirewall, oldVM) || !firewallAssignedToVM(*icmpFirewall, newVM) {
		t.Fatalf("post-cutover ICMP firewall assignments = %#v", icmpFirewall.ResourcesAssigned)
	}
}

func TestNodeLoadBalancerPreviousShardCleanupKeepsMigratingPeerDataplane(t *testing.T) {
	ctx := context.Background()
	const (
		oldShard = "inlb-0123abcd"
		newShard = "inlb-89abcdef"
	)
	exclude := nodeLoadBalancerTestService("finished", "finished-uid", corev1.ProtocolTCP, 443)
	peer := nodeLoadBalancerTestService("peer", "peer-uid", corev1.ProtocolTCP, 8443)
	peer.Annotations[annotationNodeLoadBalancerShard] = newShard
	peer.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
	shadow := desiredNodeLoadBalancerShadow(peer, nodeLoadBalancerShadowName(peer), "unit-test-cluster", oldShard)

	serviceIndexer := newNamespacedIndexer()
	// Keep the informer deliberately behind the authoritative API: cleanup must
	// still retain the live previous-shard shadow.
	for _, object := range []*corev1.Service{exclude, peer} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(exclude.DeepCopy(), peer.DeepCopy(), shadow.DeepCopy())
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	remaining, err := controller.servicesForShard(ctx, exclude, oldShard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].UID != peer.UID {
		t.Fatalf("active previous-shard peers = %#v, want %s", remaining, peer.UID)
	}

	shadow = desiredNodeLoadBalancerShadow(peer, nodeLoadBalancerShadowName(peer), "unit-test-cluster", newShard)
	currentShadow, err := provider.kubeClient.CoreV1().Services(shadow.Namespace).Get(ctx, shadow.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shadow.ResourceVersion = currentShadow.ResourceVersion
	if _, err := provider.kubeClient.CoreV1().Services(shadow.Namespace).Update(ctx, shadow, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	remaining, err = controller.servicesForShard(ctx, exclude, oldShard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("cut-over peer still retained old shard: %#v", remaining)
	}
}

func TestNodeLoadBalancerShardCleanupKeepsDeletingPeerUntilItsShadowIsGone(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	exclude := nodeLoadBalancerTestService("finished", "finished-uid", corev1.ProtocolTCP, 80)
	peer := nodeLoadBalancerTestService("deleting", "deleting-uid", corev1.ProtocolTCP, 443)
	peer.Finalizers = []string{nodeLoadBalancerFinalizer}
	peer.Annotations[annotationNodeLoadBalancerShard] = shard
	now := metav1.Now()
	peer.DeletionTimestamp = &now
	shadow := desiredNodeLoadBalancerShadow(peer, nodeLoadBalancerShadowName(peer), "unit-test-cluster", shard)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(exclude.DeepCopy(), peer.DeepCopy(), shadow.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	remaining, err := controller.servicesForShard(ctx, exclude, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].UID != peer.UID {
		t.Fatalf("deleting peer with live shadow was not retained: %#v", remaining)
	}
	if err := provider.kubeClient.CoreV1().Services(shadow.Namespace).Delete(ctx, shadow.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	remaining, err = controller.servicesForShard(ctx, exclude, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("deleting peer retained shard after shadow removal: %#v", remaining)
	}
}

func TestNodeLoadBalancerRepeatedMigrationDeletesAbandonedShardAndPreservesActiveIdentities(t *testing.T) {
	ctx := context.Background()
	const (
		activeShard       = "inlb-0123abcd"
		abandonedShard    = "inlb-4567abcd"
		desiredShard      = "inlb-89abcdef"
		activeFirewall    = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		abandonedFirewall = "cccccccc-1111-4222-8333-dddddddddddd"
		desiredFirewall   = "eeeeeeee-1111-4222-8333-ffffffffffff"
	)
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = abandonedShard
	service.Annotations[annotationNodeLoadBalancerPreviousShard] = activeShard
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = abandonedFirewall
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = "bbbbbbbb"
	service.Annotations[annotationNodeLoadBalancerPreviousFirewall] = activeFirewall
	shadow := desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", activeShard)

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow.DeepCopy())
	provider.dynamicClient = fake.NewSimpleDynamicClient(
		runtime.NewScheme(),
		nodeLoadBalancerSafetyNodePool(abandonedShard, provider.config.ClusterID, profile, 1),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{service.DeepCopy(), shadow.DeepCopy()} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
		nodes:    corelisters.NewNodeLister(newNamespacedIndexer()),
	}

	waiting, err := controller.cleanupAbandonedReplacementShard(ctx, service, desiredShard)
	if err != nil || waiting {
		t.Fatalf("abandoned shard cleanup = waiting %t, err %v", waiting, err)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, abandonedShard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("abandoned intermediate NodePool remains: %v", err)
	}
	if patched, err := controller.ensureServiceMetadata(ctx, service, desiredShard); err != nil || !patched {
		t.Fatalf("reassign repeated migration = patched %t, err %v", patched, err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerShard] != desiredShard ||
		stored.Annotations[annotationNodeLoadBalancerPreviousShard] != activeShard ||
		stored.Annotations[annotationNodeLoadBalancerPreviousFirewall] != activeFirewall {
		t.Fatalf("repeated migration lost active identities: %#v", stored.Annotations)
	}
	storedShadow := getNodeLoadBalancerTestService(t, ctx, provider, shadow.Namespace, shadow.Name)
	if storedShadow.Annotations[annotationCiliumNodeIPAMMatchLabels] != nodeLoadBalancerCiliumSelector(provider.config.ClusterID, activeShard) {
		t.Fatalf("active shadow changed during abandoned-shard cleanup: %#v", storedShadow.Annotations)
	}
	if _, err := controller.promotePendingFirewallMetadata(ctx, stored, &inspace.Firewall{UUID: desiredFirewall}, "dddddddd"); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallUUID] != desiredFirewall ||
		stored.Annotations[annotationNodeLoadBalancerPreviousFirewall] != activeFirewall {
		t.Fatalf("firewall promotion lost active previous firewall: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerMigrationAuditsActivePreviousShardWithPreviousFirewall(t *testing.T) {
	ctx := context.Background()
	const (
		oldShard        = "inlb-0123abcd"
		newShard        = "inlb-89abcdef"
		oldFirewall     = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		currentFirewall = "cccccccc-1111-4222-8333-dddddddddddd"
		vmUUID          = "eeeeeeee-1111-4222-8333-ffffffffffff"
	)
	service := nodeLoadBalancerTestService("peer", "peer-uid", corev1.ProtocolTCP, 443)
	service.Annotations[annotationNodeLoadBalancerShard] = newShard
	service.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
	oldService := service.DeepCopy()
	oldService.Spec.Ports[0].Port = 80
	shadow := desiredNodeLoadBalancerShadow(oldService, nodeLoadBalancerShadowName(service), "unit-test-cluster", oldShard)

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	controller := &nodeLoadBalancerController{provider: provider}
	currentDesired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	oldDesired, err := controller.desiredServiceFirewall(oldService)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = currentFirewall
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = currentDesired.Hash
	service.Annotations[annotationNodeLoadBalancerPreviousFirewall] = oldFirewall
	api.firewalls = []inspace.Firewall{
		{
			UUID: oldFirewall, DisplayName: oldDesired.Request.DisplayName,
			BillingAccountID: oldDesired.Request.BillingAccountID, Rules: oldDesired.Request.Rules,
			ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
		},
		{
			UUID: currentFirewall, DisplayName: currentDesired.Request.DisplayName,
			BillingAccountID: currentDesired.Request.BillingAccountID, Rules: currentDesired.Request.Rules,
		},
	}
	node := readyNode("lb-old", "inspace://bkk01/"+vmUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   oldShard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, oldShard)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow.DeepCopy(), node.DeepCopy())

	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{service.DeepCopy(), shadow.DeepCopy()} {
		if err := serviceIndexer.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller.services = corelisters.NewServiceLister(serviceIndexer)
	controller.nodes = corelisters.NewNodeLister(nodeIndexer)

	if err := controller.reconcileShardNodeEligibility(ctx, oldShard); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatal("active previous shard was disabled even though its old firewall remained assigned")
	}

	for index := range stored.Status.Conditions {
		if stored.Status.Conditions[index].Type == corev1.NodeReady {
			stored.Status.Conditions[index].Status = corev1.ConditionFalse
		}
	}
	stored, err = provider.kubeClient.CoreV1().Nodes().UpdateStatus(ctx, stored, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeIndexer.Update(stored.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if err := controller.reconcileShardNodeEligibility(ctx, oldShard); err != nil {
		t.Fatal(err)
	}
	stored, err = provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("NotReady node retained its previous-shard Cilium eligibility")
	}
}

func TestNodeLoadBalancerPendingSharedServiceDoesNotInterruptActiveShard(t *testing.T) {
	ctx := context.Background()
	const (
		shard  = "inlb-0123abcd"
		vmUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	)
	stable := nodeLoadBalancerTestService("stable", "stable-uid", corev1.ProtocolTCP, 443)
	stable.Annotations[annotationNodeLoadBalancerShard] = shard
	pending := nodeLoadBalancerTestService("pending", "pending-uid", corev1.ProtocolTCP, 8443)
	pending.Annotations[annotationNodeLoadBalancerShard] = shard
	shadow := desiredNodeLoadBalancerShadow(stable, nodeLoadBalancerShadowName(stable), "unit-test-cluster", shard)
	node := readyNode("lb-0", "inspace://bkk01/"+vmUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(stable)
	if err != nil {
		t.Fatal(err)
	}
	const firewallUUID = "eeeeeeee-1111-4222-8333-ffffffffffff"
	stable.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	stable.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	provider.kubeClient = kubefake.NewSimpleClientset(stable.DeepCopy(), pending.DeepCopy(), shadow.DeepCopy(), node.DeepCopy())
	serviceIndexer := newNamespacedIndexer()
	for _, service := range []*corev1.Service{stable, pending, shadow} {
		if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller.services = corelisters.NewServiceLister(serviceIndexer)
	controller.nodes = corelisters.NewNodeLister(nodeIndexer)

	if err := controller.reconcileShardNodeEligibility(ctx, shard); err != nil {
		t.Fatal(err)
	}
	storedNode, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if storedNode.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatalf("pending shared Service interrupted active shard: %#v", storedNode.Labels)
	}
}

func TestNodeLoadBalancerEstablishedShardFailsClosedOnAuthoritativeDrift(t *testing.T) {
	tests := map[string]struct {
		mutate    func(*testing.T, *nodeLoadBalancerFailClosedFixture)
		wantError bool
	}{
		"Service firewall policy drift": {
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				t.Helper()
				firewall := fixture.firewall(t, fixture.serviceFirewallUUID)
				port := int32(8443)
				firewall.Rules[0].PortStart = &port
				firewall.Rules[0].PortEnd = &port
			},
			wantError: true,
		},
		"duplicate managed Service firewall row": {
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				t.Helper()
				duplicate := *fixture.firewall(t, fixture.serviceFirewallUUID)
				duplicate.UUID = "77777777-1111-4222-8333-444444444444"
				fixture.api.firewalls = append(fixture.api.firewalls, duplicate)
			},
			wantError: true,
		},
		"NodePool ownership drift": {
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				t.Helper()
				pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
					fixture.ctx, fixture.shard, metav1.GetOptions{},
				)
				if err != nil {
					t.Fatal(err)
				}
				labels := pool.GetLabels()
				labels[nodeLoadBalancerClusterLabel] = "foreign-cluster"
				pool.SetLabels(labels)
				if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
					fixture.ctx, pool, metav1.UpdateOptions{},
				); err != nil {
					t.Fatal(err)
				}
			},
			wantError: true,
		},
		"cluster ICMP firewall policy drift": {
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				t.Helper()
				firewall := fixture.firewall(t, fixture.icmpFirewallUUID)
				firewall.Rules[0].EndpointSpecType = "ip_prefixes"
				firewall.Rules[0].EndpointSpec = []string{"203.0.113.0/24"}
			},
			wantError: true,
		},
		"cluster ICMP firewall missing": {
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				t.Helper()
				kept := fixture.api.firewalls[:0]
				for _, firewall := range fixture.api.firewalls {
					if firewall.UUID != fixture.icmpFirewallUUID {
						kept = append(kept, firewall)
					}
				}
				fixture.api.firewalls = kept
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newNodeLoadBalancerFailClosedFixture(t)
			defer fixture.controller.queue.ShutDown()
			test.mutate(t, fixture)

			err := fixture.controller.sync(fixture.ctx, fixture.service.Namespace+"/"+fixture.service.Name)
			if test.wantError && err == nil {
				t.Fatal("authoritative drift reconciled without an error")
			}
			current, getErr := fixture.provider.kubeClient.CoreV1().Nodes().Get(
				fixture.ctx, fixture.node.Name, metav1.GetOptions{},
			)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if _, advertised := current.Labels[nodeLoadBalancerReadyLabel]; advertised {
				t.Fatalf("authoritative drift retained the protected Cilium ready label: error=%v labels=%#v", err, current.Labels)
			}
		})
	}
}

func TestNodeLoadBalancerNodePoolRepairErrorFailsShardClosed(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()

	pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
		fixture.ctx,
		fixture.shard,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	unstructured.RemoveNestedField(pool.Object, "spec", "template", "spec", "taints")
	if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
		fixture.ctx,
		pool,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	dynamicClient, ok := fixture.provider.dynamicClient.(*fake.FakeDynamicClient)
	if !ok {
		t.Fatalf("dynamic client type = %T", fixture.provider.dynamicClient)
	}
	injected := errors.New("injected NodePool repair failure")
	dynamicClient.PrependReactor("update", "nodepools", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	shard := nodeLoadBalancerShardPlan{
		Name: fixture.shard, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: 1, CPU: nodeLoadBalancerDefaultCPU, MemoryMiB: nodeLoadBalancerDefaultMemoryMiB,
	}
	err = fixture.controller.ensureNodePoolFailClosed(
		fixture.ctx,
		managedNodeLoadBalancerName(fixture.provider.config.ClusterID, "node-lb"),
		shard,
	)
	if !errors.Is(err, injected) {
		t.Fatalf("sync error = %v, want injected NodePool repair failure", err)
	}
	current, err := fixture.provider.kubeClient.CoreV1().Nodes().Get(
		fixture.ctx,
		fixture.node.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, advertised := current.Labels[nodeLoadBalancerReadyLabel]; advertised {
		t.Fatalf("failed NodePool repair retained protected ready label: %#v", current.Labels)
	}
}

func TestNodeLoadBalancerInvalidUnfinalizedServiceDoesNotOwnSharedCleanup(t *testing.T) {
	ctx := context.Background()
	lastOwner := nodeLoadBalancerTestService("last", "last-owner-uid", corev1.ProtocolTCP, 443)
	lastOwner.Finalizers = []string{nodeLoadBalancerFinalizer}
	invalid := nodeLoadBalancerTestService("invalid", "invalid-owner-uid", corev1.ProtocolTCP, 8443)
	invalid.Annotations[annotationNodeLoadBalancerMode] = "invalid"

	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(lastOwner.DeepCopy(), invalid.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	otherOwner, err := controller.otherNodeLoadBalancerServices(ctx, lastOwner)
	if err != nil {
		t.Fatal(err)
	}
	if otherOwner {
		t.Fatal("invalid class-only Service without the provider finalizer claimed shared cloud ownership")
	}

	peer := nodeLoadBalancerTestService("peer", "peer-owner-uid", corev1.ProtocolTCP, 9443)
	peer.Finalizers = []string{nodeLoadBalancerFinalizer}
	if _, err := provider.kubeClient.CoreV1().Services(peer.Namespace).Create(ctx, peer, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	otherOwner, err = controller.otherNodeLoadBalancerServices(ctx, lastOwner)
	if err != nil {
		t.Fatal(err)
	}
	if !otherOwner {
		t.Fatal("finalized peer Service was not recognized as a shared cloud owner")
	}
}

func TestNodeLoadBalancerLastOwnerCleansSharedICMPDespiteInvalidUnfinalizedService(t *testing.T) {
	ctx := context.Background()
	lastOwner := nodeLoadBalancerTestService("last", "last-owner-uid", corev1.ProtocolTCP, 443)
	lastOwner.Finalizers = []string{nodeLoadBalancerFinalizer}
	lastOwner.Annotations[annotationNodeLoadBalancerCleanupFWAbsent] = strconv.Itoa(nodeLoadBalancerAbsenceConfirmations)
	invalid := nodeLoadBalancerTestService("invalid", "invalid-owner-uid", corev1.ProtocolTCP, 8443)
	invalid.Annotations[annotationNodeLoadBalancerMode] = "invalid"

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := renderNodeLoadBalancerNodeClass(nodeLoadBalancerSafetyBaseNodeClass(), nodeClassName)
	if err != nil {
		t.Fatal(err)
	}
	if err := markNodeLoadBalancerManaged(nodeClass, provider.config.ClusterID, "", ""); err != nil {
		t.Fatal(err)
	}
	desiredICMP, err := desiredNodeLoadBalancerClusterICMPFirewall(provider.config.ClusterID, provider.config.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	const icmpUUID = "99999999-1111-4222-8333-444444444444"
	nodeClass.SetAnnotations(map[string]string{annotationNodeLoadBalancerICMPFirewallUUID: icmpUUID})
	api.firewalls = []inspace.Firewall{{
		UUID: icmpUUID, DisplayName: desiredICMP.Request.DisplayName,
		Description: desiredICMP.Request.Description, BillingAccountID: desiredICMP.Request.BillingAccountID,
		Rules: append([]inspace.FirewallRule(nil), desiredICMP.Request.Rules...),
	}}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeClass)
	provider.kubeClient = kubefake.NewSimpleClientset(lastOwner.DeepCopy(), invalid.DeepCopy())
	controller := &nodeLoadBalancerController{
		provider: provider,
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()

	if err := controller.cleanupService(ctx, lastOwner); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != icmpUUID {
		t.Fatalf("last owner did not delete the shared ICMP firewall: %#v", api.deletedFirewalls)
	}
	stored, err := provider.kubeClient.CoreV1().Services(lastOwner.Namespace).Get(ctx, lastOwner.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatal("last owner finalized before shared ICMP absence was proven")
	}

	storedNodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := storedNodeClass.GetAnnotations()
	annotations[annotationNodeLoadBalancerICMPCleanupAbsent] = strconv.Itoa(nodeLoadBalancerAbsenceConfirmations)
	storedNodeClass.SetAnnotations(annotations)
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, storedNodeClass, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := controller.cleanupService(ctx, stored); err != nil {
		t.Fatal(err)
	}
	stored, err = provider.kubeClient.CoreV1().Services(lastOwner.Namespace).Get(ctx, lastOwner.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatal("last owner retained its finalizer after shared ICMP absence was proven")
	}
	invalidStored, err := provider.kubeClient.CoreV1().Services(invalid.Namespace).Get(ctx, invalid.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(invalidStored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatal("cleanup adopted the invalid class-only Service")
	}
}

type nodeLoadBalancerFailClosedFixture struct {
	ctx                 context.Context
	shard               string
	serviceFirewallUUID string
	icmpFirewallUUID    string
	api                 *fakeAPI
	provider            *Provider
	controller          *nodeLoadBalancerController
	service             *corev1.Service
	node                *corev1.Node
	serviceIndexer      cache.Indexer
	nodeIndexer         cache.Indexer
}

func newNodeLoadBalancerFailClosedFixture(t *testing.T) *nodeLoadBalancerFailClosedFixture {
	t.Helper()
	ctx := context.Background()
	const (
		shard               = "inlb-0123abcd"
		vmUUID              = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		serviceFirewallUUID = "eeeeeeee-1111-4222-8333-ffffffffffff"
	)
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = shard
	shadow := desiredNodeLoadBalancerShadow(service, nodeLoadBalancerShadowName(service), "unit-test-cluster", shard)
	node := readyNode("lb-0", "inspace://bkk01/"+vmUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}

	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = serviceFirewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	api.firewalls = []inspace.Firewall{{
		UUID: serviceFirewallUUID, DisplayName: desired.Request.DisplayName,
		Description: desired.Request.Description, BillingAccountID: desired.Request.BillingAccountID,
		Rules:             append([]inspace.FirewallRule(nil), desired.Request.Rules...),
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)

	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), shadow.DeepCopy(), node.DeepCopy())
	serviceIndexer := newNamespacedIndexer()
	for _, item := range []*corev1.Service{service, shadow} {
		if err := serviceIndexer.Add(item.DeepCopy()); err != nil {
			t.Fatal(err)
		}
	}
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller.services = corelisters.NewServiceLister(serviceIndexer)
	controller.nodes = corelisters.NewNodeLister(nodeIndexer)
	controller.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	icmpUUID := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
	if icmpUUID == "" {
		t.Fatal("fixture generated NodeClass has no cluster ICMP firewall identity")
	}

	return &nodeLoadBalancerFailClosedFixture{
		ctx: ctx, shard: shard, serviceFirewallUUID: serviceFirewallUUID, icmpFirewallUUID: icmpUUID,
		api: api, provider: provider, controller: controller, service: service, node: node,
		serviceIndexer: serviceIndexer, nodeIndexer: nodeIndexer,
	}
}

func (f *nodeLoadBalancerFailClosedFixture) firewall(t *testing.T, uuid string) *inspace.Firewall {
	t.Helper()
	for index := range f.api.firewalls {
		if f.api.firewalls[index].UUID == uuid {
			return &f.api.firewalls[index]
		}
	}
	t.Fatalf("fixture firewall %s is absent", uuid)
	return nil
}

func (f *nodeLoadBalancerFailClosedFixture) replaceNodePoolWithLegacyDefault(t *testing.T) {
	t.Helper()
	resource := f.provider.dynamicClient.Resource(nodePoolGVR)
	current, err := resource.Get(f.ctx, f.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	legacy := nodeLoadBalancerSafetyLegacyNodePool(
		f.shard,
		f.provider.config.ClusterID,
		nodeLoadBalancerModeShared,
		nodeLoadBalancerDefaultPool,
		1,
	)
	legacy.SetUID(current.GetUID())
	legacy.SetResourceVersion(current.GetResourceVersion())
	if _, err := resource.Update(f.ctx, legacy, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func getNodeLoadBalancerTestService(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	namespace, name string,
) *corev1.Service {
	t.Helper()
	service, err := provider.kubeClient.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func ageNodeLoadBalancerAbsenceEvidence(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	service *corev1.Service,
	checkedAnnotation string,
) *corev1.Service {
	t.Helper()
	copy := service.DeepCopy()
	copy.Annotations[checkedAnnotation] = time.Now().Add(-nodeLoadBalancerAbsenceConfirmationDelay - time.Second).UTC().Format(time.RFC3339Nano)
	updated, err := provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func TestNodeLoadBalancerRawShardSelectorRequiresAllVisibleIdentityLabels(t *testing.T) {
	good := readyNode("lb", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	good.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   "inlb-0123abcd",
	}
	spoofed := readyNode("private-worker", "inspace://bkk01/cccccccc-1111-4222-8333-dddddddddddd")
	spoofed.Labels = map[string]string{nodeLoadBalancerNodeShardLabel: "inlb-0123abcd"}
	wrongCluster := readyNode("foreign-lb", "inspace://bkk01/eeeeeeee-1111-4222-8333-ffffffffffff")
	wrongCluster.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "foreign-cluster",
		nodeLoadBalancerNodeShardLabel:   "inlb-0123abcd",
	}
	indexer := newNamespacedIndexer()
	for _, node := range []*corev1.Node{good, spoofed, wrongCluster} {
		if err := indexer.Add(node); err != nil {
			t.Fatal(err)
		}
	}
	provider := newTestProvider(t, &fakeAPI{})
	controller := &nodeLoadBalancerController{provider: provider, nodes: corelisters.NewNodeLister(indexer)}
	nodes, err := controller.rawNodesForShard("inlb-0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != good.Name {
		t.Fatalf("selected nodes = %#v, want only %s", nodes, good.Name)
	}
}

func TestNodeLoadBalancerAuthorizesExactNodeClaimNodePoolNodeClassAndFIPChain(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	node := readyNode("lb-0", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	provider.kubeClient = kubefake.NewSimpleClientset(node.DeepCopy())
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{provider: provider, nodes: corelisters.NewNodeLister(nodeIndexer)}

	authorized, err := controller.authorizedNodesForShard(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 1 || authorized[0].Name != node.Name {
		t.Fatalf("authorized shard Nodes = %#v", authorized)
	}
	clusterAuthorized, err := controller.authorizedNodesForCluster(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusterAuthorized) != 1 || clusterAuthorized[0].Name != node.Name {
		t.Fatalf("authorized cluster Nodes = %#v", clusterAuthorized)
	}
	ready, externalIPs, err := controller.readyShardNodes(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 1 || len(externalIPs) != 1 || externalIPs[0] != "203.0.113.10" {
		t.Fatalf("ready Nodes = %#v, external IPs = %#v", ready, externalIPs)
	}
	current, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.11"}}
	if _, err := provider.kubeClient.CoreV1().Nodes().UpdateStatus(ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := controller.setShardNodesReady(ctx, authorized, map[string]bool{node.Name: true}); err != nil {
		t.Fatal(err)
	}
	current, err = provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := current.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("readiness boundary retained advertisement after ExternalIP diverged from authoritative FIP")
	}
}

func TestNodeLoadBalancerLegacyAuthorizationRequiresActiveOmittedSizingService(t *testing.T) {
	assertRejected := func(t *testing.T, mutate func(*testing.T, *nodeLoadBalancerFailClosedFixture)) {
		t.Helper()
		fixture := newNodeLoadBalancerFailClosedFixture(t)
		defer fixture.controller.queue.ShutDown()
		fixture.replaceNodePoolWithLegacyDefault(t)
		mutate(t, fixture)
		authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
		if err != nil {
			t.Fatal(err)
		}
		if len(authorized) != 0 {
			t.Fatalf("legacy Node remained authorized: %#v", authorized)
		}
	}

	fixture := newNodeLoadBalancerFailClosedFixture(t)
	fixture.replaceNodePoolWithLegacyDefault(t)
	authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 1 || authorized[0].Name != fixture.node.Name {
		t.Fatalf("active legacy shard authorization = %#v", authorized)
	}
	clusterAuthorized, err := fixture.controller.authorizedNodesForCluster(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusterAuthorized) != 1 || clusterAuthorized[0].Name != fixture.node.Name {
		t.Fatalf("cluster-wide active legacy shard authorization = %#v", clusterAuthorized)
	}
	fixture.controller.queue.ShutDown()

	t.Run("missing provider finalizer", func(t *testing.T) {
		assertRejected(t, func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
			service := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name)
			service.Finalizers = nil
			if _, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).Update(fixture.ctx, service, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("missing shadow", func(t *testing.T) {
		assertRejected(t, func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
			if err := fixture.provider.kubeClient.CoreV1().Services(fixture.service.Namespace).Delete(
				fixture.ctx,
				nodeLoadBalancerShadowName(fixture.service),
				metav1.DeleteOptions{},
			); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("foreign shadow ownership", func(t *testing.T) {
		assertRejected(t, func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
			shadow := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerShadowName(fixture.service))
			shadow.Labels[nodeLoadBalancerServiceUIDLabel] = "foreign-uid"
			if _, err := fixture.provider.kubeClient.CoreV1().Services(shadow.Namespace).Update(fixture.ctx, shadow, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("explicit legacy sizing", func(t *testing.T) {
		assertRejected(t, func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
			service := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name)
			service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
			service.Annotations[annotationNodeLoadBalancerCPU] = "1"
			service.Annotations[annotationNodeLoadBalancerMemory] = "2Gi"
			if _, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).Update(fixture.ctx, service, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("previous shard no longer active", func(t *testing.T) {
		assertRejected(t, func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
			const replacement = "inlb-deadbeef"
			service := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name)
			service.Annotations[annotationNodeLoadBalancerPreviousShard] = fixture.shard
			service.Annotations[annotationNodeLoadBalancerShard] = replacement
			if _, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).Update(fixture.ctx, service, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			shadow := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerShadowName(fixture.service))
			shadow.Annotations[annotationCiliumNodeIPAMMatchLabels] = nodeLoadBalancerCiliumSelector(fixture.provider.config.ClusterID, replacement)
			if _, err := fixture.provider.kubeClient.CoreV1().Services(shadow.Namespace).Update(fixture.ctx, shadow, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	})
}

func TestNodeLoadBalancerLegacyNodeEventEligibilityPreservesThenDrops(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	fixture.replaceNodePoolWithLegacyDefault(t)

	if err := fixture.controller.reconcileShardNodeEligibility(fixture.ctx, fixture.shard); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.provider.kubeClient.CoreV1().Nodes().Get(fixture.ctx, fixture.node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Labels[nodeLoadBalancerReadyLabel] != "true" {
		t.Fatal("active legacy shard lost its Cilium readiness label")
	}
	if err := fixture.nodeIndexer.Update(stored.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	service := getNodeLoadBalancerTestService(t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "1"
	service.Annotations[annotationNodeLoadBalancerMemory] = "2Gi"
	updated, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).Update(fixture.ctx, service, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.serviceIndexer.Update(updated.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.controller.reconcileShardNodeEligibility(fixture.ctx, fixture.shard); err != nil {
		t.Fatal(err)
	}
	stored, err = fixture.provider.kubeClient.CoreV1().Nodes().Get(fixture.ctx, fixture.node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("inactive explicit legacy shape retained its Cilium readiness label")
	}
}

func TestNodeLoadBalancerExactLabelAndProviderIDSpoofCannotAttachFirewallOrAdvertise(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	legitimate := readyNode("lb-real", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	legitimate.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
	}
	legitimate.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	installNodeLoadBalancerSafetyIdentity(t, provider, legitimate, shard)

	spoofed := readyNode("private-worker", "inspace://bkk01/cccccccc-1111-4222-8333-dddddddddddd")
	spoofed.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
		karpenterNodePoolLabel:           shard,
	}
	// Even copying the real NodeClaim owner reference cannot satisfy the
	// authoritative status.providerID/status.nodeName pair.
	spoofed.OwnerReferences = append([]metav1.OwnerReference(nil), legitimate.OwnerReferences...)
	spoofed.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.99"}}
	provider.kubeClient = kubefake.NewSimpleClientset(spoofed.DeepCopy())
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(spoofed.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	serviceIndexer := newNamespacedIndexer()
	controller := &nodeLoadBalancerController{
		provider: provider,
		nodes:    corelisters.NewNodeLister(nodeIndexer),
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	authorized, err := controller.authorizedNodesForShard(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 0 {
		t.Fatalf("spoofed Node was authorized: %#v", authorized)
	}
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	api.firewalls = []inspace.Firewall{{
		UUID: "eeeeeeee-1111-4222-8333-ffffffffffff", DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, service, authorized); err != nil {
		t.Fatal(err)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("spoofed Node received a public firewall: %#v", api.assignedFirewalls)
	}
	ready, externalIPs, err := controller.readyShardNodes(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 0 || len(externalIPs) != 0 {
		t.Fatalf("spoofed Node was advertised: Nodes=%#v IPs=%#v", ready, externalIPs)
	}
	if err := controller.reconcileShardNodeEligibility(ctx, shard); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, spoofed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("spoofed Node retained the protected Cilium readiness label")
	}
}

func TestNodeLoadBalancerRejectsNodeWhenFIPDoesNotMatchExternalIP(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	node := readyNode("lb-0", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
	}
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}}
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	api.floatingIPs[0].Address = "203.0.113.11"
	provider.kubeClient = kubefake.NewSimpleClientset(node.DeepCopy())
	nodeIndexer := newNamespacedIndexer()
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{provider: provider, nodes: corelisters.NewNodeLister(nodeIndexer)}
	authorized, err := controller.authorizedNodesForShard(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 0 {
		t.Fatalf("Node with mismatched authoritative FIP was authorized: %#v", authorized)
	}
	api.floatingIPs[0].Address = "203.0.113.10"
	duplicate := api.floatingIPs[0]
	duplicate.Address = "203.0.113.11"
	duplicate.BillingAccountID = provider.config.BillingAccountID + 1
	api.floatingIPs = append(api.floatingIPs, duplicate)
	authorized, err = controller.authorizedNodesForShard(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 0 {
		t.Fatalf("Node with a second active cross-account FIP was authorized: %#v", authorized)
	}
}

func TestNodeLoadBalancerDetachesStaleFirewallAssignmentWithReadback(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const currentVM = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	const staleVM = "cccccccc-1111-4222-8333-dddddddddddd"
	api.firewalls = []inspace.Firewall{{
		UUID: "eeeeeeee-1111-4222-8333-ffffffffffff", DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: currentVM},
			{ResourceType: "vm", ResourceUUID: staleVM},
		},
	}}
	node := readyNode("lb", "inspace://bkk01/"+currentVM)
	if err := controller.detachServiceFirewallFromOtherNodes(ctx, service, &api.firewalls[0], []*corev1.Node{node}); err != nil {
		t.Fatal(err)
	}
	if len(api.unassignedFirewalls) != 1 || !strings.HasSuffix(api.unassignedFirewalls[0], "/"+staleVM) {
		t.Fatalf("stale unassignments = %#v", api.unassignedFirewalls)
	}
	if !firewallAssignedToVM(api.firewalls[0], currentVM) || firewallAssignedToVM(api.firewalls[0], staleVM) {
		t.Fatalf("post-cleanup assignments = %#v", api.firewalls[0].ResourcesAssigned)
	}
}

func nodeLoadBalancerSafetyNodePool(name, cluster, profile string, replicas int64) *unstructured.Unstructured {
	shard := nodeLoadBalancerShardPlan{
		Name: name, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: int32(replicas), CPU: nodeLoadBalancerDefaultCPU, MemoryMiB: nodeLoadBalancerDefaultMemoryMiB,
	}
	pool, err := renderNodeLoadBalancerNodePool(name, managedNodeLoadBalancerName(cluster, "node-lb"), shard)
	if err != nil {
		panic(err)
	}
	if err := markNodeLoadBalancerManaged(pool, cluster, name, profile); err != nil {
		panic(err)
	}
	pool.SetUID(types.UID("nodepool-" + name))
	return pool
}

func nodeLoadBalancerSafetyLegacyNodePool(name, cluster, mode, poolName string, replicas int64) *unstructured.Unstructured {
	shard := nodeLoadBalancerShardPlan{
		Name: name, Mode: mode, Pool: poolName,
		NodesPerShard: int32(replicas), CPU: 1, MemoryMiB: 2048,
	}
	pool, err := renderLegacyNodeLoadBalancerNodePoolForAuthorization(name, managedNodeLoadBalancerName(cluster, "node-lb"), shard)
	if err != nil {
		panic(err)
	}
	if err := markNodeLoadBalancerManaged(pool, cluster, name, nodeLoadBalancerShardProfileHash(shard)); err != nil {
		panic(err)
	}
	pool.SetUID(types.UID("nodepool-" + name))
	return pool
}

func setNodeLoadBalancerSafetyRequirement(t *testing.T, pool *unstructured.Unstructured, key, value string) {
	t.Helper()
	requirements, found, err := unstructured.NestedSlice(pool.Object, "spec", "template", "spec", "requirements")
	if err != nil || !found {
		t.Fatalf("read NodePool requirements: found=%t err=%v", found, err)
	}
	updated := false
	for _, raw := range requirements {
		requirement, ok := raw.(map[string]any)
		if !ok || requirement["key"] != key {
			continue
		}
		requirement["values"] = []any{value}
		updated = true
	}
	if !updated {
		t.Fatalf("NodePool requirement %q is absent", key)
	}
	if err := unstructured.SetNestedSlice(pool.Object, requirements, "spec", "template", "spec", "requirements"); err != nil {
		t.Fatal(err)
	}
}

func nodeLoadBalancerSafetyFirewallByUUID(t *testing.T, firewalls []inspace.Firewall, uuid string) *inspace.Firewall {
	t.Helper()
	for index := range firewalls {
		if firewalls[index].UUID == uuid {
			return &firewalls[index]
		}
	}
	t.Fatalf("firewall %s is absent", uuid)
	return nil
}

func newNodeLoadBalancerTestDynamicClient(objects ...runtime.Object) *fake.FakeDynamicClient {
	return fake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			nodePoolGVR: "NodePoolList", nodeClaimGVR: "NodeClaimList",
		},
		objects...,
	)
}

func installNodeLoadBalancerSafetyIdentity(
	t *testing.T,
	provider *Provider,
	node *corev1.Node,
	shard string,
) {
	t.Helper()
	ctx := context.Background()
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		nodeClass, err = renderNodeLoadBalancerNodeClass(nodeLoadBalancerSafetyBaseNodeClass(), nodeClassName)
		if err != nil {
			t.Fatal(err)
		}
		if err := markNodeLoadBalancerManaged(nodeClass, provider.config.ClusterID, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, err = provider.dynamicClient.Resource(nodeClassGVR).Create(ctx, nodeClass, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}

	pool, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
		pool = nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1)
		if _, err = provider.dynamicClient.Resource(nodePoolGVR).Create(ctx, pool, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else {
		copy := pool.DeepCopy()
		if copy.GetUID() == "" {
			copy.SetUID(types.UID("nodepool-" + shard))
		}
		labels := copy.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[nodeLoadBalancerManagedLabel] = "true"
		labels[nodeLoadBalancerLabel] = "true"
		labels[nodeLoadBalancerClusterLabel] = provider.config.ClusterID
		labels[nodeLoadBalancerShardLabel] = shard
		if labels[nodeLoadBalancerProfileLabel] == "" {
			labels[nodeLoadBalancerProfileLabel] = "test-profile"
		}
		copy.SetLabels(labels)
		templateLabels, _, err := unstructured.NestedStringMap(copy.Object, "spec", "template", "metadata", "labels")
		if err != nil {
			t.Fatal(err)
		}
		if templateLabels == nil {
			templateLabels = map[string]string{}
		}
		templateLabels[nodeLoadBalancerNodeLabel] = "true"
		templateLabels[nodeLoadBalancerNodeClusterLabel] = provider.config.ClusterID
		templateLabels[nodeLoadBalancerNodeShardLabel] = shard
		if err := unstructured.SetNestedStringMap(copy.Object, templateLabels, "spec", "template", "metadata", "labels"); err != nil {
			t.Fatal(err)
		}
		if err := unstructured.SetNestedStringMap(copy.Object, map[string]string{
			"group": "karpenter.inspace.cloud", "kind": "InSpaceNodeClass", "name": nodeClassName,
		}, "spec", "template", "spec", "nodeClassRef"); err != nil {
			t.Fatal(err)
		}
		pool, err = provider.dynamicClient.Resource(nodePoolGVR).Update(ctx, copy, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	if node.Labels == nil {
		node.Labels = map[string]string{}
	}
	node.Labels[karpenterNodePoolLabel] = shard
	node.Labels[nodeLoadBalancerNodeLabel] = "true"
	node.Labels[nodeLoadBalancerNodeClusterLabel] = provider.config.ClusterID
	node.Labels[nodeLoadBalancerNodeShardLabel] = shard
	blockOwnerDeletion := true
	claimName := shard + "-claim"
	claimUID := types.UID("nodeclaim-" + shard)
	node.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "karpenter.sh/v1", Kind: "NodeClaim", Name: claimName, UID: claimUID,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}}
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodeClaim",
		"metadata": map[string]any{
			"name": claimName, "uid": string(claimUID),
			"labels": map[string]any{
				karpenterNodePoolLabel:           shard,
				nodeLoadBalancerNodeLabel:        "true",
				nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
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
	if _, err := provider.dynamicClient.Resource(nodeClaimGVR).Create(ctx, claim, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if api, ok := provider.api.(*fakeAPI); ok {
		identity, err := providerid.Parse(node.Spec.ProviderID)
		if err != nil {
			t.Fatal(err)
		}
		externalIP, ok := nodeLoadBalancerNodeExternalIPv4(node)
		if !ok {
			t.Fatalf("Node %s has no public ExternalIP for its test identity", node.Name)
		}
		found := false
		for _, item := range api.floatingIPs {
			if item.AssignedTo == identity.UUID {
				found = true
				break
			}
		}
		if !found {
			api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{
				Name: "karpenter-" + claimName, Address: externalIP,
				BillingAccountID: provider.config.BillingAccountID, Type: "public", Enabled: true,
				AssignedTo: identity.UUID, AssignedToResourceType: "virtual_machine",
			})
		}
		icmpDesired, err := desiredNodeLoadBalancerClusterICMPFirewall(provider.config.ClusterID, provider.config.BillingAccountID)
		if err != nil {
			t.Fatal(err)
		}
		const icmpUUID = "99999999-1111-4222-8333-444444444444"
		icmpIndex := -1
		for index := range api.firewalls {
			if api.firewalls[index].EffectiveName() == icmpDesired.Request.DisplayName {
				icmpIndex = index
				break
			}
		}
		if icmpIndex == -1 {
			api.firewalls = append(api.firewalls, inspace.Firewall{
				UUID: icmpUUID, DisplayName: icmpDesired.Request.DisplayName,
				Description: icmpDesired.Request.Description, BillingAccountID: icmpDesired.Request.BillingAccountID,
				Rules: append([]inspace.FirewallRule(nil), icmpDesired.Request.Rules...),
			})
			icmpIndex = len(api.firewalls) - 1
		}
		if !firewallAssignedToVM(api.firewalls[icmpIndex], identity.UUID) {
			api.firewalls[icmpIndex].ResourcesAssigned = append(
				api.firewalls[icmpIndex].ResourcesAssigned,
				inspace.FirewallResource{ResourceType: "vm", ResourceUUID: identity.UUID},
			)
		}
		storedNodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations := storedNodeClass.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[annotationNodeLoadBalancerICMPFirewallUUID] = api.firewalls[icmpIndex].UUID
		storedNodeClass.SetAnnotations(annotations)
		if _, err := provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, storedNodeClass, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func nodeLoadBalancerSafetyBaseNodeClass() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.inspace.cloud/v1alpha1", "kind": "InSpaceNodeClass",
		"metadata": map[string]any{"name": "workers"},
		"spec": map[string]any{
			"clusterName": "unit-test-cluster", "billingAccountID": int64(42), "location": "bkk01",
			"networkUUID": testNetworkUUID, "firewallUUID": "22222222-2222-4222-8222-222222222222",
			"privateLoadBalancerPool": map[string]any{"start": "10.0.0.200", "stop": "10.0.0.239"},
			"rke2":                    map[string]any{"server": "https://10.0.0.10:9345"},
			"rootDiskGiB":             int64(100), "reservePublicIPv4": true,
		},
	}}
}

func nodeLoadBalancerSafetyInvalidFinalizedService(name, uid string) *corev1.Service {
	service := nodeLoadBalancerTestService(name, uid, corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerMode] = "invalid"
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.10"}}
	return service
}
