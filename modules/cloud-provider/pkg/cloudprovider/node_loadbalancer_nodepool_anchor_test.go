package cloudprovider

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestManagedNodePoolEnsureAddsAndPreservesStateFinalizer(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	provider := newTestProvider(t, &fakeAPI{})
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared,
		nodeLoadBalancerDefaultPool,
		1,
		nodeLoadBalancerDefaultCPU,
		nodeLoadBalancerDefaultMemoryMiB,
	)
	desired := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1)
	if !containsString(desired.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		t.Fatalf("rendered managed NodePool finalizers = %#v", desired.GetFinalizers())
	}

	stored := desired.DeepCopy()
	stored.SetFinalizers([]string{"karpenter.sh/termination"})
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), stored)
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.ensureDynamicObject(ctx, nodePoolGVR, desired); err != nil {
		t.Fatal(err)
	}
	got, err := dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(got.GetFinalizers(), "karpenter.sh/termination") ||
		!containsString(got.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		t.Fatalf("ensure replaced or omitted NodePool finalizers: %#v", got.GetFinalizers())
	}

	updates := 0
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "update" && action.GetResource().Resource == nodePoolGVR.Resource {
			updates++
		}
	}
	if updates != 1 {
		t.Fatalf("first ensure update count = %d, want 1", updates)
	}
	actionCount := len(dynamicClient.Actions())
	if err := controller.ensureDynamicObject(ctx, nodePoolGVR, desired); err != nil {
		t.Fatal(err)
	}
	for _, action := range dynamicClient.Actions()[actionCount:] {
		if action.GetVerb() == "update" {
			t.Fatalf("idempotent ensure issued an update: %#v", action)
		}
	}
}

func TestManagedNodePoolAnnotationUpdateBackfillsStateFinalizer(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	provider := newTestProvider(t, &fakeAPI{})
	pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "0123abcd", 1)
	pool.SetFinalizers([]string{"karpenter.sh/termination"})
	provider.dynamicClient = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pool)
	controller := &nodeLoadBalancerController{provider: provider}

	updated, changed, err := controller.updateManagedNodePoolAnnotations(
		ctx,
		shard,
		func(map[string]string) (bool, error) { return false, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !containsString(updated.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) ||
		!containsString(updated.GetFinalizers(), "karpenter.sh/termination") {
		t.Fatalf("annotation update did not safely backfill the anchor: changed=%t finalizers=%#v", changed, updated.GetFinalizers())
	}
}

func TestEnsureNodePoolRequiresExactFinalizerReadback(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset()
	plan := nodeLoadBalancerShardPlan{
		Name: shard, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: 1, CPU: nodeLoadBalancerDefaultCPU, MemoryMiB: nodeLoadBalancerDefaultMemoryMiB,
	}
	desired, err := renderNodeLoadBalancerNodePool(shard, "generated-nodeclass", plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := markNodeLoadBalancerManaged(desired, provider.config.ClusterID, shard, nodeLoadBalancerShardProfileHash(plan)); err != nil {
		t.Fatal(err)
	}
	stored := desired.DeepCopy()
	stored.SetFinalizers(removeString(stored.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), stored)
	dynamicClient.PrependReactor("update", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		update := action.(k8stesting.UpdateAction)
		copy := update.GetObject().(*unstructured.Unstructured).DeepCopy()
		copy.SetFinalizers(removeString(copy.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
		if err := dynamicClient.Tracker().Update(nodePoolGVR, copy, ""); err != nil {
			return true, nil, err
		}
		return true, copy, nil
	})
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	err = controller.ensureNodePool(ctx, "generated-nodeclass", plan)
	if err == nil || !strings.Contains(err.Error(), "lacks the durable shard-state finalizer after ensure") {
		t.Fatalf("stripped ensure readback error = %v", err)
	}
}

func TestRemoveManagedNodePoolStateFinalizerRequiresExactDeletingOwnership(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"

	t.Run("rejects a live NodePool", func(t *testing.T) {
		provider := newTestProvider(t, &fakeAPI{})
		pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "0123abcd", 1)
		provider.dynamicClient = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pool)
		controller := &nodeLoadBalancerController{provider: provider}
		err := controller.removeManagedNodePoolStateFinalizer(ctx, shard)
		if err == nil || !strings.Contains(err.Error(), "live NodePool") {
			t.Fatalf("live NodePool finalizer removal error = %v", err)
		}
	})

	t.Run("rejects foreign ownership", func(t *testing.T) {
		provider := newTestProvider(t, &fakeAPI{})
		pool := deletingNodeLoadBalancerStateAnchorPool(
			nodeLoadBalancerSafetyNodePool(shard, "foreign-cluster", "0123abcd", 1),
		)
		provider.dynamicClient = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pool)
		controller := &nodeLoadBalancerController{provider: provider}
		err := controller.removeManagedNodePoolStateFinalizer(ctx, shard)
		if err == nil || !strings.Contains(err.Error(), "exact managed ownership") {
			t.Fatalf("foreign NodePool finalizer removal error = %v", err)
		}
	})

	t.Run("waits for other finalizers", func(t *testing.T) {
		provider := newTestProvider(t, &fakeAPI{})
		pool := deletingNodeLoadBalancerStateAnchorPool(
			nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "0123abcd", 1),
		)
		pool.SetFinalizers([]string{"karpenter.sh/termination", nodeLoadBalancerNodePoolFinalizer})
		provider.dynamicClient = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pool)
		controller := &nodeLoadBalancerController{provider: provider}
		err := controller.removeManagedNodePoolStateFinalizer(ctx, shard)
		if err == nil || !strings.Contains(err.Error(), "other finalizers remain") {
			t.Fatalf("multi-finalizer NodePool removal error = %v", err)
		}
	})

	t.Run("removes only the CCM anchor", func(t *testing.T) {
		provider := newTestProvider(t, &fakeAPI{})
		pool := deletingNodeLoadBalancerStateAnchorPool(
			nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "0123abcd", 1),
		)
		dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), pool)
		provider.dynamicClient = dynamicClient
		controller := &nodeLoadBalancerController{provider: provider}
		if err := controller.removeManagedNodePoolStateFinalizer(ctx, shard); err != nil {
			t.Fatal(err)
		}
		got, err := dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if containsString(got.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			t.Fatalf("CCM state finalizer remained: %#v", got.GetFinalizers())
		}
	})
}

func TestManagedShardCapacityAbsentIgnoresOnlyTheCCMStateAnchor(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"

	newController := func(t *testing.T, pool *unstructured.Unstructured, claims []*unstructured.Unstructured, nodes ...*corev1.Node) *nodeLoadBalancerController {
		t.Helper()
		provider := newTestProvider(t, &fakeAPI{})
		objects := make([]runtime.Object, 0, 1+len(claims))
		objects = append(objects, pool)
		for _, claim := range claims {
			objects = append(objects, claim)
		}
		provider.dynamicClient = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			runtime.NewScheme(),
			map[schema.GroupVersionResource]string{
				nodePoolGVR:  "NodePoolList",
				nodeClaimGVR: "NodeClaimList",
			},
			objects...,
		)
		kubeObjects := make([]runtime.Object, 0, len(nodes))
		for _, node := range nodes {
			kubeObjects = append(kubeObjects, node)
		}
		provider.kubeClient = kubefake.NewSimpleClientset(kubeObjects...)
		return &nodeLoadBalancerController{provider: provider}
	}

	newPool := func(t *testing.T, finalizers ...string) *unstructured.Unstructured {
		t.Helper()
		provider := newTestProvider(t, &fakeAPI{})
		pool := deletingNodeLoadBalancerStateAnchorPool(
			nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "0123abcd", 1),
		)
		pool.SetFinalizers(finalizers)
		return pool
	}

	t.Run("only anchor and no capacity is absent", func(t *testing.T) {
		controller := newController(t, newPool(t, nodeLoadBalancerNodePoolFinalizer), nil)
		absent, err := controller.managedShardCapacityAbsent(ctx, shard)
		if err != nil || !absent {
			t.Fatalf("capacity absent = %t, %v; want true", absent, err)
		}
	})

	t.Run("another finalizer still holds capacity", func(t *testing.T) {
		controller := newController(t, newPool(t, "karpenter.sh/termination", nodeLoadBalancerNodePoolFinalizer), nil)
		absent, err := controller.managedShardCapacityAbsent(ctx, shard)
		if err != nil || absent {
			t.Fatalf("capacity absent = %t, %v; want false", absent, err)
		}
	})

	t.Run("a managed NodeClaim still holds capacity", func(t *testing.T) {
		claim := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "karpenter.sh/v1",
			"kind":       "NodeClaim",
			"metadata": map[string]any{
				"name": "claim",
				"labels": map[string]any{
					karpenterNodePoolLabel:           shard,
					nodeLoadBalancerNodeLabel:        "true",
					nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
					nodeLoadBalancerNodeShardLabel:   shard,
				},
			},
		}}
		claim.SetUID(types.UID("claim-uid"))
		controller := newController(t, newPool(t, nodeLoadBalancerNodePoolFinalizer), []*unstructured.Unstructured{claim})
		absent, err := controller.managedShardCapacityAbsent(ctx, shard)
		if err != nil || absent {
			t.Fatalf("capacity absent = %t, %v; want false", absent, err)
		}
	})

	t.Run("a managed Node still holds capacity", func(t *testing.T) {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: "node",
			Labels: map[string]string{
				nodeLoadBalancerNodeLabel:        "true",
				nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
				nodeLoadBalancerNodeShardLabel:   shard,
			},
		}}
		controller := newController(t, newPool(t, nodeLoadBalancerNodePoolFinalizer), nil, node)
		absent, err := controller.managedShardCapacityAbsent(ctx, shard)
		if err != nil || absent {
			t.Fatalf("capacity absent = %t, %v; want false", absent, err)
		}
	})
}

func deletingNodeLoadBalancerStateAnchorPool(pool *unstructured.Unstructured) *unstructured.Unstructured {
	copy := pool.DeepCopy()
	now := metav1.Now()
	copy.SetDeletionTimestamp(&now)
	copy.SetFinalizers([]string{nodeLoadBalancerNodePoolFinalizer})
	return copy
}
