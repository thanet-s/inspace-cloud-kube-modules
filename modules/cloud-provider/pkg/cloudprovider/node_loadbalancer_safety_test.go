package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
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
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodePool)
	provider.kubeClient = kubefake.NewSimpleClientset(
		service.DeepCopy(),
		desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), oldShard),
	)

	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service); err != nil {
		t.Fatal(err)
	}
	if err := serviceIndexer.Add(desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), oldShard)); err != nil {
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

func TestNodeLoadBalancerChangedPortCannotEvictStableSharedClaim(t *testing.T) {
	ctx := context.Background()
	const oldShard = "inlb-0123abcd"

	changed := nodeLoadBalancerTestService("changed", "changed-uid", corev1.ProtocolTCP, 443)
	changed.Annotations[annotationNodeLoadBalancerShard] = oldShard
	stable := nodeLoadBalancerTestService("stable", "stable-uid", corev1.ProtocolTCP, 443)
	stable.Annotations[annotationNodeLoadBalancerShard] = oldShard
	nodeLoadBalancerSafetyMarkDatapathActive(stable, oldShard)
	changedBeforeEdit := changed.DeepCopy()
	changedBeforeEdit.Spec.Ports[0].Port = 80

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	nodePool := nodeLoadBalancerSafetyNodePool(oldShard, "unit-test-cluster", profile, 1)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodePool)
	provider.kubeClient = kubefake.NewSimpleClientset(
		changed.DeepCopy(), stable.DeepCopy(),
		desiredNodeLoadBalancerDatapath(changedBeforeEdit, nodeLoadBalancerDatapathName(changed), oldShard),
		desiredNodeLoadBalancerDatapath(stable, nodeLoadBalancerDatapathName(stable), oldShard),
	)

	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		changed,
		stable,
		desiredNodeLoadBalancerDatapath(changedBeforeEdit, nodeLoadBalancerDatapathName(changed), oldShard),
		desiredNodeLoadBalancerDatapath(stable, nodeLoadBalancerDatapathName(stable), oldShard),
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
	nodeLoadBalancerSafetyMarkDatapathActive(active, replacementShard)

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyNodePool(replacementShard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		staged.DeepCopy(), active.DeepCopy(),
		desiredNodeLoadBalancerDatapath(stagedBeforeEdit, nodeLoadBalancerDatapathName(staged), oldShard),
		desiredNodeLoadBalancerDatapath(active, nodeLoadBalancerDatapathName(active), replacementShard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		staged,
		active,
		desiredNodeLoadBalancerDatapath(stagedBeforeEdit, nodeLoadBalancerDatapathName(staged), oldShard),
		desiredNodeLoadBalancerDatapath(active, nodeLoadBalancerDatapathName(active), replacementShard),
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

func TestNodeLoadBalancerUncommittedPortSwapCanReusePersistedShard(t *testing.T) {
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
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		a.DeepCopy(), x.DeepCopy(),
		desiredNodeLoadBalancerDatapath(aBeforeSwap, nodeLoadBalancerDatapathName(a), shard),
		desiredNodeLoadBalancerDatapath(xBeforeSwap, nodeLoadBalancerDatapathName(x), shard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		a,
		x,
		desiredNodeLoadBalancerDatapath(aBeforeSwap, nodeLoadBalancerDatapathName(a), shard),
		desiredNodeLoadBalancerDatapath(xBeforeSwap, nodeLoadBalancerDatapathName(x), shard),
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
	if aShard != shard || xShard != shard {
		t.Fatalf("uncommitted, conflict-free port swap moved from persisted shard: A=%q X=%q", aShard, xShard)
	}
}

func TestNodeLoadBalancerDeletingPeerDatapathReservesItsPortUntilCleanup(t *testing.T) {
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
	nodeLoadBalancerSafetyMarkDatapathActive(deleting, shard)

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	provider.kubeClient = kubefake.NewSimpleClientset(
		a.DeepCopy(), deleting.DeepCopy(),
		desiredNodeLoadBalancerDatapath(aBeforeEdit, nodeLoadBalancerDatapathName(a), shard),
		desiredNodeLoadBalancerDatapath(deleting, nodeLoadBalancerDatapathName(deleting), shard),
	)
	serviceIndexer := newNamespacedIndexer()
	for _, object := range []*corev1.Service{
		a,
		deleting,
		desiredNodeLoadBalancerDatapath(aBeforeEdit, nodeLoadBalancerDatapathName(a), shard),
		desiredNodeLoadBalancerDatapath(deleting, nodeLoadBalancerDatapathName(deleting), shard),
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

func TestNodeLoadBalancerPlannerReadsLiveDatapathWhenInformerIsStale(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-89abcdef"
	target := nodeLoadBalancerTestService("target", "a-target-uid", corev1.ProtocolTCP, 443)
	stable := nodeLoadBalancerTestService("stable", "m-stable-uid", corev1.ProtocolTCP, 80)
	stable.Annotations[annotationNodeLoadBalancerShard] = shard
	nodeLoadBalancerSafetyMarkDatapathActive(stable, shard)
	deleting := nodeLoadBalancerTestService("deleting", "z-deleting-uid", corev1.ProtocolTCP, 443)
	deleting.Finalizers = []string{nodeLoadBalancerFinalizer}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting.Annotations[annotationNodeLoadBalancerShard] = shard
	nodeLoadBalancerSafetyMarkDatapathActive(deleting, shard)
	stableShadow := desiredNodeLoadBalancerDatapath(stable, nodeLoadBalancerDatapathName(stable), shard)
	deletingShadow := desiredNodeLoadBalancerDatapath(deleting, nodeLoadBalancerDatapathName(deleting), shard)

	profile := nodeLoadBalancerProfileHash(nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1, nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
		nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, profile, 1),
	)
	// The authoritative API already contains the deleting peer datapath, while
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
		t.Fatalf("stale informer let target claim live datapath port on %s: %q", shard, got)
	}
}

func TestNodeLoadBalancerPlannerSplicesLiveTargetIntent(t *testing.T) {
	ctx := context.Background()
	cached := nodeLoadBalancerTestService("target", "target-uid", corev1.ProtocolTCP, 443)
	live := cached.DeepCopy()
	live.Spec.Ports[0].Port = 8443

	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())
	provider.kubeClient = kubefake.NewSimpleClientset(live.DeepCopy())
	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(cached.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
	}

	intent, _, _, err := controller.planForService(ctx, cached)
	if err != nil {
		t.Fatal(err)
	}
	want := []nodeLoadBalancerPortClaim{{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 8443}}
	if !reflect.DeepEqual(intent.Ports, want) {
		t.Fatalf("planned target ports = %#v, want authoritative live %#v", intent.Ports, want)
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

func TestNodeLoadBalancerForeignDatapathNameFailsBeforeFinalizerOrCapacity(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	foreignOwner := nodeLoadBalancerTestService("foreign", "foreign-uid", corev1.ProtocolTCP, 8443)
	foreignShadow := desiredNodeLoadBalancerDatapath(foreignOwner, nodeLoadBalancerDatapathName(service), "inlb-0123abcd")
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
		t.Fatalf("foreign datapath preflight error = %v", err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if containsString(stored.Finalizers, nodeLoadBalancerFinalizer) || stored.Annotations[annotationNodeLoadBalancerShard] != "" {
		t.Fatalf("foreign datapath caused managed metadata before preflight: %#v", stored.ObjectMeta)
	}
}

func TestNodeLoadBalancerDatapathNameBindsExactParentIdentity(t *testing.T) {
	fixed := nodeLoadBalancerTestService("web", "12345678-1234-4234-8234-123456789abc", corev1.ProtocolTCP, 443)
	const fixedName = "inlb-dp-7eb63a7dd612a757e4f3b4ec4e2ab9fbf5c9e81cafb8de6fae13"
	if got := nodeLoadBalancerDatapathName(fixed); got != fixedName {
		t.Fatalf("canonical fixed-vector datapath name = %q, want %q", got, fixedName)
	}

	service := nodeLoadBalancerTestService(strings.Repeat("a", 63), strings.Repeat("1", 63), corev1.ProtocolTCP, 443)
	service.Namespace = strings.Repeat("n", 63)
	name := nodeLoadBalancerDatapathName(service)
	if len(name) != 60 || len(utilvalidation.IsDNS1123Label(name)) != 0 {
		t.Fatalf("canonical datapath name %q has invalid length or DNS syntax", name)
	}
	child := desiredNodeLoadBalancerDatapath(service, name, "inlb-0123abcd")
	if child.Namespace != service.Namespace || child.Name != name || !nodeLoadBalancerDatapathOwnedByService(child, service) {
		t.Fatalf("generated datapath does not retain exact parent identity: %#v", child.ObjectMeta)
	}

	otherNamespace := service.DeepCopy()
	otherNamespace.Namespace = strings.Repeat("m", 63)
	if nodeLoadBalancerDatapathName(otherNamespace) == name {
		t.Fatal("same-name Services in different namespaces collided")
	}
	otherUID := service.DeepCopy()
	otherUID.UID = types.UID(strings.Repeat("2", 63))
	if nodeLoadBalancerDatapathName(otherUID) == name {
		t.Fatal("same namespace/name replacement Service collided with the old UID")
	}
}

func TestNodeLoadBalancerActiveDatapathRequiresMarkerAndExactChild(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	baseService := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	baseChild := nodeLoadBalancerSafetyDatapath(baseService, shard)

	t.Run("exact child without marker is staged", func(t *testing.T) {
		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(baseService.DeepCopy(), baseChild.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}
		if _, _, active, err := controller.activeDatapathService(ctx, baseService); err != nil || active {
			t.Fatalf("unmarked datapath active=%t err=%v", active, err)
		}
	})

	mutations := map[string]func(*corev1.Service){
		"terminating": func(child *corev1.Service) {
			now := metav1.Now()
			child.DeletionTimestamp = &now
		},
		"selector drift": func(child *corev1.Service) { child.Spec.Selector = map[string]string{"app": "foreign"} },
		"port drift":     func(child *corev1.Service) { child.Spec.Ports[0].Port = 8443 },
		"source range drift": func(child *corev1.Service) {
			child.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"}
		},
		"class drift": func(child *corev1.Service) {
			class := "example.com/foreign"
			child.Spec.LoadBalancerClass = &class
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			service := baseService.DeepCopy()
			nodeLoadBalancerSafetyMarkDatapathActive(service, shard)
			child := baseChild.DeepCopy()
			mutate(child)
			provider := newTestProvider(t, &fakeAPI{})
			provider.kubeClient = kubefake.NewSimpleClientset(service, child)
			controller := &nodeLoadBalancerController{provider: provider}
			if _, _, active, err := controller.activeDatapathService(ctx, service); err == nil || active {
				t.Fatalf("drifted datapath active=%t err=%v", active, err)
			}
		})
	}

	t.Run("exact marked child is active", func(t *testing.T) {
		service := baseService.DeepCopy()
		nodeLoadBalancerSafetyMarkDatapathActive(service, shard)
		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(service, baseChild.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}
		child, gotShard, active, err := controller.activeDatapathService(ctx, service)
		if err != nil || !active || gotShard != shard || child.Name != baseChild.Name {
			t.Fatalf("exact datapath active=%t shard=%q child=%#v err=%v", active, gotShard, child, err)
		}
	})
}

func TestNodeLoadBalancerPrivateVIPPublicationRequiresPriorAuthorization(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	parent := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		fixture.service.Name,
	)
	delete(parent.Annotations, annotationNodeLoadBalancerDatapathActive)
	parent, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx,
		parent,
		metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defaults := nodeLoadBalancerDefaults{NodesPerShard: fixture.provider.config.NodeLoadBalancer.NodesPerShard}
	expected, err := parseNodeLoadBalancerService(parent, defaults)
	if err != nil {
		t.Fatal(err)
	}
	addresses := []nodeLoadBalancerAddress{{
		Node: fixture.node, PrivateIPv4: "10.0.0.20", PublicIPv4: "203.0.113.10",
	}}
	if _, err := fixture.controller.publishDatapathStatus(
		fixture.ctx,
		parent,
		fixture.shard,
		expected,
		addresses,
	); err == nil || !strings.Contains(err.Error(), "no activation authorization") {
		t.Fatalf("unmarked private VIP publication error = %v", err)
	}

	authorized, err := fixture.controller.authorizeDatapath(fixture.ctx, parent, fixture.shard, expected)
	if err != nil {
		t.Fatal(err)
	}
	clientset, ok := fixture.provider.kubeClient.(*kubefake.Clientset)
	if !ok {
		t.Fatalf("kube client type = %T", fixture.provider.kubeClient)
	}
	markerObserved := false
	childName := nodeLoadBalancerDatapathName(parent)
	clientset.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok || action.GetSubresource() != "status" {
			return false, nil, nil
		}
		child, ok := update.GetObject().(*corev1.Service)
		if !ok || child.Name != childName {
			return false, nil, nil
		}
		object, trackerErr := clientset.Tracker().Get(
			corev1.SchemeGroupVersion.WithResource("services"),
			parent.Namespace,
			parent.Name,
		)
		if trackerErr != nil {
			return true, nil, trackerErr
		}
		stored := object.(*corev1.Service)
		markerObserved = stored.Annotations[annotationNodeLoadBalancerDatapathActive] == fixture.shard
		return false, nil, nil
	})
	if _, err := fixture.controller.publishDatapathStatus(
		fixture.ctx,
		authorized,
		fixture.shard,
		expected,
		addresses,
	); err != nil {
		t.Fatal(err)
	}
	if !markerObserved {
		t.Fatal("private VIP status write happened before durable activation authorization")
	}
}

func TestNodeLoadBalancerAuthorizationRejectsSameUIDIntentRace(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	parent := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		fixture.service.Name,
	)
	delete(parent.Annotations, annotationNodeLoadBalancerDatapathActive)
	parent, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx,
		parent,
		metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defaults := nodeLoadBalancerDefaults{NodesPerShard: fixture.provider.config.NodeLoadBalancer.NodesPerShard}
	expected, err := parseNodeLoadBalancerService(parent, defaults)
	if err != nil {
		t.Fatal(err)
	}

	clientset := fixture.provider.kubeClient.(*kubefake.Clientset)
	parentGets := 0
	clientset.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		get, ok := action.(k8stesting.GetAction)
		if !ok || get.GetNamespace() != parent.Namespace || get.GetName() != parent.Name {
			return false, nil, nil
		}
		parentGets++
		if parentGets != 2 {
			return false, nil, nil
		}
		raced := parent.DeepCopy()
		raced.Spec.Ports[0].Port = 8443
		return true, raced, nil
	})

	if _, err := fixture.controller.authorizeDatapath(
		fixture.ctx,
		parent,
		fixture.shard,
		expected,
	); err == nil || !strings.Contains(err.Error(), "intent changed") {
		t.Fatalf("same-UID intent race authorization error = %v", err)
	}
	stored := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		parent.Namespace,
		parent.Name,
	)
	if stored.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
		t.Fatalf("same-UID intent race persisted activation: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerGeneratedServiceDeleteUsesUIDPrecondition(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	child := nodeLoadBalancerSafetyDatapath(service, "inlb-0123abcd")
	provider := newTestProvider(t, &fakeAPI{})
	client := kubefake.NewSimpleClientset(service.DeepCopy(), child.DeepCopy())
	provider.kubeClient = client
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.deleteOwnedDatapathService(ctx, service); err != nil {
		t.Fatal(err)
	}
	actions := client.Actions()
	if len(actions) != 2 || actions[0].GetVerb() != "get" || actions[1].GetVerb() != "delete" {
		t.Fatalf("generated Service deletion actions = %#v", actions)
	}
	deleteAction, ok := actions[1].(k8stesting.DeleteAction)
	if !ok || deleteAction.GetDeleteOptions().Preconditions == nil ||
		deleteAction.GetDeleteOptions().Preconditions.UID == nil ||
		*deleteAction.GetDeleteOptions().Preconditions.UID != child.UID {
		t.Fatalf("generated Service delete lacks exact UID precondition: %#v", actions[1])
	}
}

func TestNodeLoadBalancerNodePoolDeleteUsesUIDPreconditionAndForegroundPropagation(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	pool := nodeLoadBalancerSafetyNodePool(shard, "unit-test-cluster", "0123abcd", 1)
	provider := newTestProvider(t, &fakeAPI{})
	dynamicClient := fake.NewSimpleDynamicClient(runtime.NewScheme(), pool.DeepCopy())
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.deleteManagedNodePool(ctx, shard); err != nil {
		t.Fatal(err)
	}
	actions := dynamicClient.Actions()
	if len(actions) != 2 || actions[0].GetVerb() != "get" || actions[1].GetVerb() != "delete" {
		t.Fatalf("NodePool deletion actions = %#v", actions)
	}
	deleteAction, ok := actions[1].(k8stesting.DeleteAction)
	if !ok || deleteAction.GetDeleteOptions().Preconditions == nil ||
		deleteAction.GetDeleteOptions().Preconditions.UID == nil ||
		*deleteAction.GetDeleteOptions().Preconditions.UID != pool.GetUID() ||
		deleteAction.GetDeleteOptions().PropagationPolicy == nil ||
		*deleteAction.GetDeleteOptions().PropagationPolicy != metav1.DeletePropagationForeground {
		t.Fatalf("NodePool delete lacks exact UID/foreground contract: %#v", actions[1])
	}
}

func TestNodeLoadBalancerDeletingNodePoolIsUpgradedToForegroundPropagation(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	pool := nodeLoadBalancerSafetyNodePool(shard, "unit-test-cluster", "0123abcd", 1)
	deletingAt := metav1.Now()
	pool.SetDeletionTimestamp(&deletingAt)
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1",
		"kind":       "NodeClaim",
		"metadata": map[string]any{
			"name": "claim",
			"ownerReferences": []any{map[string]any{
				"apiVersion":         "karpenter.sh/v1",
				"kind":               "NodePool",
				"name":               shard,
				"uid":                string(pool.GetUID()),
				"blockOwnerDeletion": true,
			}},
			"labels": map[string]any{
				karpenterNodePoolLabel:           shard,
				nodeLoadBalancerNodeLabel:        "true",
				nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
				nodeLoadBalancerNodeShardLabel:   shard,
			},
		},
	}}
	claim.SetUID(types.UID("claim-uid"))
	provider := newTestProvider(t, &fakeAPI{})
	dynamicClient := newNodeLoadBalancerTestDynamicClient(pool.DeepCopy(), claim)
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	deleting, err := controller.reconcileDeletingAggregateNodePool(ctx, shard)
	if err != nil || !deleting {
		t.Fatalf("reconcile deleting NodePool = %t, %v; want true, nil", deleting, err)
	}
	var deleteAction k8stesting.DeleteAction
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "delete" && action.GetResource().Resource == nodePoolGVR.Resource {
			deleteAction = action.(k8stesting.DeleteAction)
			break
		}
	}
	if deleteAction == nil || deleteAction.GetDeleteOptions().Preconditions == nil ||
		deleteAction.GetDeleteOptions().Preconditions.UID == nil ||
		*deleteAction.GetDeleteOptions().Preconditions.UID != pool.GetUID() ||
		deleteAction.GetDeleteOptions().PropagationPolicy == nil ||
		*deleteAction.GetDeleteOptions().PropagationPolicy != metav1.DeletePropagationForeground {
		t.Fatalf("deleting NodePool was not upgraded with exact UID/foreground contract: %#v", dynamicClient.Actions())
	}
}

func TestNodeLoadBalancerDrainedDeletingNodePoolDoesNotReaddForegroundFinalizer(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	pool := nodeLoadBalancerSafetyNodePool(shard, "unit-test-cluster", "0123abcd", 1)
	deletingAt := metav1.Now()
	pool.SetDeletionTimestamp(&deletingAt)
	provider := newTestProvider(t, &fakeAPI{})
	dynamicClient := newNodeLoadBalancerTestDynamicClient(pool.DeepCopy())
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.deleteManagedNodePool(ctx, shard); err != nil {
		t.Fatal(err)
	}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "delete" && action.GetResource().Resource == nodePoolGVR.Resource {
			t.Fatalf("drained deleting NodePool received another foreground delete: %#v", dynamicClient.Actions())
		}
	}
}

func TestNodeLoadBalancerInFlightForegroundDeleteIsNotReissued(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	pool := nodeLoadBalancerSafetyNodePool(shard, "unit-test-cluster", "0123abcd", 1)
	deletingAt := metav1.Now()
	pool.SetDeletionTimestamp(&deletingAt)
	pool.SetFinalizers(append(pool.GetFinalizers(), metav1.FinalizerDeleteDependents))
	provider := newTestProvider(t, &fakeAPI{})
	dynamicClient := newNodeLoadBalancerTestDynamicClient(pool.DeepCopy())
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	if err := controller.deleteManagedNodePool(ctx, shard); err != nil {
		t.Fatal(err)
	}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "delete" && action.GetResource().Resource == nodePoolGVR.Resource {
			t.Fatalf("in-flight foreground NodePool delete was reissued: %#v", dynamicClient.Actions())
		}
	}
}

func TestNodeLoadBalancerParentReplacementRejectsMetadataAndStatusWrites(t *testing.T) {
	ctx := context.Background()
	old := nodeLoadBalancerTestService("web", "old-uid", corev1.ProtocolTCP, 443)
	replacement := old.DeepCopy()
	replacement.UID = types.UID("replacement-uid")
	replacement.Annotations = map[string]string{"user.example/keep": "true"}
	proxy := corev1.LoadBalancerIPModeProxy
	replacement.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.99", IPMode: &proxy}}
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(replacement.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	if _, err := controller.ensureServiceMetadata(ctx, old, "inlb-0123abcd"); err == nil {
		t.Fatal("metadata writer accepted a same-name replacement UID")
	}
	if err := controller.clearServiceLoadBalancerStatus(ctx, old); err == nil {
		t.Fatal("status writer accepted a same-name replacement UID")
	}
	if err := controller.clearInvalidServiceFirewallMetadata(ctx, old); err == nil {
		t.Fatal("invalid-Service cleanup accepted a same-name replacement UID")
	}
	stored, err := provider.kubeClient.CoreV1().Services(replacement.Namespace).Get(ctx, replacement.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.UID != replacement.UID || stored.Annotations["user.example/keep"] != "true" ||
		!reflect.DeepEqual(stored.Status.LoadBalancer, replacement.Status.LoadBalancer) ||
		containsString(stored.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("replacement Service was mutated: %#v", stored)
	}
}

func TestNodeLoadBalancerPlannerSkipsOccupiedForeignShardName(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	first := "inlb-" + nodeLoadBalancerHash("shared/" + nodeLoadBalancerDefaultPool + "/" + string(service.UID))[:8]
	service.Annotations[annotationNodeLoadBalancerShard] = first
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodePool", "metadata": map[string]any{"name": first},
	}}
	provider := newTestProvider(t, &fakeAPI{})
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(foreign)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	indexer := newNamespacedIndexer()
	if err := indexer.Add(service); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{provider: provider, services: corelisters.NewServiceLister(indexer)}
	intent, plan, _, err := controller.planForService(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	if assigned := plan.Assignments[intent.ServiceID]; assigned == "" || assigned == first {
		t.Fatalf("planner reused occupied foreign NodePool name %q", assigned)
	}
}

func TestNodeLoadBalancerInvalidFinalizedServiceQuarantine(t *testing.T) {
	t.Run("deletes exact datapath and clears status", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerSafetyInvalidFinalizedService("web", "web-uid")
		shadow := nodeLoadBalancerSafetyDatapath(service, "inlb-0123abcd")
		unrelatedOwner := nodeLoadBalancerTestService("other", "other-uid", corev1.ProtocolTCP, 8443)
		unrelated := desiredNodeLoadBalancerDatapath(unrelatedOwner, nodeLoadBalancerDatapathName(unrelatedOwner), "inlb-89abcdef")

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
			t.Fatalf("owned datapath still exists: %v", err)
		}
		if _, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, unrelated.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("unrelated datapath was deleted: %v", err)
		}
		stored, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored.Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("invalid Service retained load-balancer status: %#v", stored.Status.LoadBalancer)
		}
	})

	t.Run("refuses foreign datapath", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerSafetyInvalidFinalizedService("web", "web-uid")
		shadow := nodeLoadBalancerSafetyDatapath(service, "inlb-0123abcd")
		shadow.Labels[nodeLoadBalancerServiceIdentityLabel] = "foreign-identity"
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
		if err == nil || !strings.Contains(err.Error(), "refusing to withdraw foreign datapath Service") {
			t.Fatalf("foreign datapath quarantine error = %v", err)
		}
		if _, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, shadow.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("foreign datapath was deleted: %v", err)
		}
		stored, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored.Status.LoadBalancer.Ingress) == 0 {
			t.Fatalf("parent falsely reported closed while a foreign functional datapath could not be withdrawn: %#v", stored.Status.LoadBalancer)
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
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient()
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
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
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
	if len(api.unassignedFirewalls) != 1 || api.unassignedFirewalls[0] != firewallUUID+"/"+vmUUID ||
		len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != firewallUUID {
		t.Fatalf("unassign phase: unassigned=%#v deleted=%#v", api.unassignedFirewalls, api.deletedFirewalls)
	}

	if err := controller.cleanupService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedFirewalls) != 1 || len(api.firewalls) != 0 {
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

func TestNodeLoadBalancerDeletingServiceRetainsMissingFirewallProofUntilFinalization(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	deletingAt := metav1.Now()
	current.DeletionTimestamp = &deletingAt
	if _, err := fixture.provider.kubeClient.CoreV1().Services(current.Namespace).Update(
		fixture.ctx, current, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	// Keep another finalized owner so this focused test does not enter the
	// unrelated last-owner cluster ICMP teardown state machine.
	survivor := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Namespace: current.Namespace,
		Name:      "surviving-node-lb-owner",
		UID:       types.UID("surviving-node-lb-owner-uid"),
		Finalizers: []string{
			nodeLoadBalancerFinalizer,
		},
	}}
	if _, err := fixture.provider.kubeClient.CoreV1().Services(survivor.Namespace).Create(
		fixture.ctx, survivor, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	// Model the live failure: the Service still persists the exact UUID while the
	// authoritative firewall List no longer contains that resource.
	fixture.api.firewalls = nil

	cleanup := func() error {
		t.Helper()
		service := getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		return fixture.controller.cleanupService(fixture.ctx, service)
	}
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		err := cleanup()
		if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
			t.Fatalf("withdrawal absence confirmation %d error = %v", confirmation, err)
		}
		current = getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		if got := current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent]; got != strconv.Itoa(confirmation) {
			t.Fatalf("withdrawal absence confirmation %d = %q", confirmation, got)
		}
		if confirmation < nodeLoadBalancerAbsenceConfirmations {
			ageNodeLoadBalancerAbsenceEvidence(
				t,
				fixture.ctx,
				fixture.provider,
				current,
				annotationNodeLoadBalancerWithdrawFWChecked,
			)
		}
	}

	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if current.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
		t.Fatalf("completed withdrawal retained activation marker: %#v", current.Annotations)
	}
	if got := current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent]; got != strconv.Itoa(nodeLoadBalancerAbsenceConfirmations) {
		t.Fatalf("datapath deactivation discarded withdrawal proof: got %q", got)
	}
	if got := current.Annotations[annotationNodeLoadBalancerCleanupFWAbsent]; got != "1" {
		t.Fatalf("cleanup did not advance beyond withdrawal after retained proof: got %q", got)
	}
	if _, err := fixture.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		fixture.ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("generated datapath still exists after proven withdrawal: %v", err)
	}

	for confirmation := 2; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		current = ageNodeLoadBalancerAbsenceEvidence(
			t,
			fixture.ctx,
			fixture.provider,
			current,
			annotationNodeLoadBalancerCleanupFWChecked,
		)
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		current = getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		if got := current.Annotations[annotationNodeLoadBalancerCleanupFWAbsent]; got != strconv.Itoa(confirmation) {
			t.Fatalf("cleanup absence confirmation %d = %q", confirmation, got)
		}
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if containsString(current.Finalizers, nodeLoadBalancerFinalizer) {
		t.Fatalf("Service finalizer remained after both absence proofs converged: %#v", current.ObjectMeta)
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
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
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
	hidden := &nodeLoadBalancerHiddenPostCreateAPI{fakeAPI: api}
	provider.api = hidden

	if firewall, _, ready, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil || firewall != nil || ready ||
		!strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("initial firewall create = %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("initial create count = %d", len(api.createdFirewalls))
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWName] == "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] == "" {
		t.Fatalf("durable create-issued identity was not persisted: %#v", stored.Annotations)
	}

	// Simulate an eventually consistent ListFirewalls response immediately
	// after a successful POST. The pending identity must suppress another POST.
	api.firewalls = nil
	if firewall, _, ready, err := controller.ensureServiceFirewall(ctx, stored, nil); err == nil || firewall != nil || ready ||
		!strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("delayed readback did not fail closed = %#v, ready=%t, err=%v", firewall, ready, err)
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
	hidden := &nodeLoadBalancerHiddenPostCreateAPI{fakeAPI: api}
	provider.api = hidden
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	if err := controller.ensureNodeClass(ctx, nodeClassName); err != nil {
		t.Fatal(err)
	}

	if firewall, ready, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil || firewall != nil || ready ||
		!strings.Contains(err.Error(), "remains ambiguous") {
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
	if annotations[annotationNodeLoadBalancerICMPPendingUUID] != "" ||
		annotations[annotationNodeLoadBalancerICMPPendingName] == "" ||
		annotations[annotationNodeLoadBalancerICMPPendingStarted] == "" ||
		annotations[annotationNodeLoadBalancerICMPCreateIssued] == "" {
		t.Fatalf("cluster ICMP pending identity was not persisted: %#v", annotations)
	}

	// Simulate an eventually consistent list after the POST. Durable NodeClass
	// intent must suppress a duplicate create, including after controller restart.
	api.firewalls = nil
	restarted := &nodeLoadBalancerController{provider: provider}
	for attempt := 1; attempt <= nodeLoadBalancerAbsenceConfirmations+2; attempt++ {
		firewall, ready, err := restarted.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
		if err == nil || !strings.Contains(err.Error(), "remains ambiguous") || firewall != nil || ready {
			t.Fatalf("delayed cluster ICMP readback %d = %#v, ready=%t, err=%v", attempt, firewall, ready, err)
		}
		if len(api.createdFirewalls) != 1 {
			t.Fatalf("delayed cluster ICMP readback %d issued %d creates, want one", attempt, len(api.createdFirewalls))
		}
		stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
			t.Fatalf("delayed cluster ICMP readback %d cleared the durable issued fence", attempt)
		}
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
	shadow := desiredNodeLoadBalancerDatapath(peer, nodeLoadBalancerDatapathName(peer), oldShard)

	serviceIndexer := newNamespacedIndexer()
	// Keep the informer deliberately behind the authoritative API: cleanup must
	// still retain the live previous-shard datapath.
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

	shadow = desiredNodeLoadBalancerDatapath(peer, nodeLoadBalancerDatapathName(peer), newShard)
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

func TestNodeLoadBalancerShardCleanupKeepsDeletingPeerUntilItsDatapathIsGone(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	exclude := nodeLoadBalancerTestService("finished", "finished-uid", corev1.ProtocolTCP, 80)
	peer := nodeLoadBalancerTestService("deleting", "deleting-uid", corev1.ProtocolTCP, 443)
	peer.Finalizers = []string{nodeLoadBalancerFinalizer}
	peer.Annotations[annotationNodeLoadBalancerShard] = shard
	now := metav1.Now()
	peer.DeletionTimestamp = &now
	shadow := desiredNodeLoadBalancerDatapath(peer, nodeLoadBalancerDatapathName(peer), shard)
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(exclude.DeepCopy(), peer.DeepCopy(), shadow.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	remaining, err := controller.servicesForShard(ctx, exclude, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].UID != peer.UID {
		t.Fatalf("deleting peer with live datapath was not retained: %#v", remaining)
	}
	if err := provider.kubeClient.CoreV1().Services(shadow.Namespace).Delete(ctx, shadow.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	remaining, err = controller.servicesForShard(ctx, exclude, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("deleting peer retained shard after datapath removal: %#v", remaining)
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
	nodeLoadBalancerSafetyMarkDatapathActive(service, activeShard)
	shadow := desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), activeShard)

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
	if storedShadow.Annotations[annotationNodeLoadBalancerDatapathShard] != activeShard {
		t.Fatalf("active datapath changed during abandoned-shard cleanup: %#v", storedShadow.Annotations)
	}
	desired, err := controller.desiredServiceFirewall(stored)
	if err != nil {
		t.Fatal(err)
	}
	prepared, createdIntent, err := controller.ensurePendingFirewallCreateIntent(ctx, stored, desired.Request.DisplayName)
	if err != nil || !createdIntent {
		t.Fatalf("prepare replacement firewall = created %t, err %v", createdIntent, err)
	}
	if _, err := controller.ensurePendingFirewallMetadata(ctx, prepared, desiredFirewall, desired.Request.DisplayName); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	replacementFirewall := &inspace.Firewall{
		UUID: desiredFirewall, DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}
	if _, err := controller.promotePendingFirewallMetadata(ctx, stored, replacementFirewall, desired.Hash); err != nil {
		t.Fatal(err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallUUID] != desiredFirewall ||
		stored.Annotations[annotationNodeLoadBalancerPreviousFirewall] != activeFirewall {
		t.Fatalf("firewall promotion lost active previous firewall: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerSerializesCompletedMigrationBeforeThirdAssignment(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("current-active-%t", active), func(t *testing.T) {
			ctx := context.Background()
			const (
				oldShard     = "inlb-0123abcd"
				currentShard = "inlb-4567abcd"
				desiredShard = "inlb-89abcdef"
			)
			service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
			service.Finalizers = []string{nodeLoadBalancerFinalizer}
			service.Annotations[annotationNodeLoadBalancerShard] = currentShard
			service.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
			if active {
				nodeLoadBalancerSafetyMarkDatapathActive(service, currentShard)
			}
			child := nodeLoadBalancerSafetyDatapath(service, currentShard)
			profile := nodeLoadBalancerProfileHash(
				nodeLoadBalancerModeShared,
				nodeLoadBalancerDefaultPool,
				1,
				nodeLoadBalancerDefaultCPU,
				nodeLoadBalancerDefaultMemoryMiB,
			)

			provider := newTestProvider(t, &fakeAPI{})
			provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
			provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), child.DeepCopy())
			provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(
				nodeLoadBalancerSafetyBaseNodeClass(),
				nodeLoadBalancerSafetyNodePool(oldShard, provider.config.ClusterID, profile, 1),
				nodeLoadBalancerSafetyNodePool(currentShard, provider.config.ClusterID, profile, 1),
			)
			serviceIndexer := newNamespacedIndexer()
			for _, object := range []*corev1.Service{service.DeepCopy(), child.DeepCopy()} {
				if err := serviceIndexer.Add(object); err != nil {
					t.Fatal(err)
				}
			}
			controller := &nodeLoadBalancerController{
				provider: provider,
				services: corelisters.NewServiceLister(serviceIndexer),
				nodes:    corelisters.NewNodeLister(newNamespacedIndexer()),
				queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
			}
			defer controller.queue.ShutDown()

			handled, err := controller.cleanupCompletedPreviousMigration(ctx, service)
			if err != nil || !handled {
				t.Fatalf("completed migration cleanup = handled %t, err %v", handled, err)
			}
			if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, oldShard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatalf("older previous NodePool survived serialization: %v", err)
			}
			stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
			if stored.Annotations[annotationNodeLoadBalancerPreviousShard] != "" {
				t.Fatalf("older previous identity was not cleared after deletion: %#v", stored.Annotations)
			}

			if !active {
				waiting, err := controller.cleanupAbandonedReplacementShard(ctx, stored, desiredShard)
				if err != nil || waiting {
					t.Fatalf("inactive current shard cleanup = waiting %t, err %v", waiting, err)
				}
				if _, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, currentShard, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
					t.Fatalf("inactive intermediate NodePool survived serialization: %v", err)
				}
			}

			if patched, err := controller.ensureServiceMetadata(ctx, stored, desiredShard); err != nil || !patched {
				t.Fatalf("third assignment = patched %t, err %v", patched, err)
			}
			stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
			if stored.Annotations[annotationNodeLoadBalancerShard] != desiredShard {
				t.Fatalf("third assignment did not persist desired shard: %#v", stored.Annotations)
			}
			wantPrevious := ""
			if active {
				wantPrevious = currentShard
			}
			if stored.Annotations[annotationNodeLoadBalancerPreviousShard] != wantPrevious {
				t.Fatalf("third assignment previous shard = %q, want %q", stored.Annotations[annotationNodeLoadBalancerPreviousShard], wantPrevious)
			}
		})
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
	nodeLoadBalancerSafetyMarkDatapathActive(stable, shard)
	pending := nodeLoadBalancerTestService("pending", "pending-uid", corev1.ProtocolTCP, 8443)
	pending.Annotations[annotationNodeLoadBalancerShard] = shard
	shadow := desiredNodeLoadBalancerDatapath(stable, nodeLoadBalancerDatapathName(stable), shard)
	node := readyNode("lb-0", "inspace://bkk01/"+vmUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}

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
			fixture.installAggregateShardState(t)
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
				t.Fatalf("authoritative drift retained the protected datapath-ready label: error=%v labels=%#v", err, current.Labels)
			}
		})
	}
}

func (f *nodeLoadBalancerFailClosedFixture) installAggregateShardState(t *testing.T) {
	t.Helper()
	service, err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Get(
		f.ctx, f.service.Name, metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerDatapathStaged] = f.shard
	service.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy] = policyHash
	updated, err := f.provider.kubeClient.CoreV1().Services(service.Namespace).Update(f.ctx, service, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.serviceIndexer.Update(updated.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	f.service = updated.DeepCopy()

	plan := nodeLoadBalancerShardPlan{
		Name:   f.shard,
		Claims: []string{string(updated.UID)},
		Ports:  nodeLoadBalancerPortClaimsOrFatal(t, updated),
	}
	policy, err := desiredNodeLoadBalancerShardFirewall(
		f.provider.config.ClusterID,
		f.provider.config.BillingAccountID,
		plan,
		[]*corev1.Service{updated},
	)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(policy)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := aggregateTestFirewall(policy, f.serviceFirewallUUID)
	aggregate.ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"}}
	kept := make([]inspace.Firewall, 0, len(f.api.firewalls)+1)
	for _, firewall := range f.api.firewalls {
		if firewall.UUID != f.serviceFirewallUUID {
			kept = append(kept, firewall)
		}
	}
	f.api.firewalls = append(kept, aggregate)

	resource := f.provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(f.ctx, f.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerShardFirewallUUID] = aggregate.UUID
	annotations[annotationNodeLoadBalancerShardFirewallHash] = policy.Hash
	annotations[annotationNodeLoadBalancerShardFirewallLedger] = ledger
	pool.SetAnnotations(annotations)
	if _, err := resource.Update(f.ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
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

func TestNodeLoadBalancerWithdrawalClearsPrivateVIPAndPublicProxyStatuses(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	if err := fixture.controller.withdrawServiceDatapath(fixture.ctx, fixture.service); err != nil {
		t.Fatal(err)
	}
	nodeLoadBalancerAssertWithdrawn(t, fixture)
}

func TestNodeLoadBalancerFirewallAssignmentFollowsMarkerAndPrivateVIP(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = nil

	assignmentChecks := 0
	fixture.provider.api = &nodeLoadBalancerAssignmentOrderAPI{
		fakeAPI: fixture.api,
		beforeAssign: func(firewallUUID, vmUUID string) error {
			assignmentChecks++
			if firewallUUID != fixture.serviceFirewallUUID {
				return fmt.Errorf("unexpected firewall %s", firewallUUID)
			}
			wantVM, ok := nodeLoadBalancerVMUUID(fixture.node)
			if !ok || vmUUID != wantVM {
				return fmt.Errorf("unexpected VM %s", vmUUID)
			}
			parent := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
			)
			if parent.Annotations[annotationNodeLoadBalancerDatapathActive] != fixture.shard ||
				parent.Annotations[annotationNodeLoadBalancerFirewallAssigning] != fixture.serviceFirewallUUID ||
				parent.Annotations[annotationNodeLoadBalancerFirewallAssignAt] == "" {
				return fmt.Errorf("durable activation/assignment fence is absent: %#v", parent.Annotations)
			}
			if len(parent.Status.LoadBalancer.Ingress) != 0 {
				return fmt.Errorf("public status was published before firewall assignment: %#v", parent.Status.LoadBalancer)
			}
			child := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(parent),
			)
			if len(child.Status.LoadBalancer.Ingress) != 1 || child.Status.LoadBalancer.Ingress[0].IP != "10.0.0.20" ||
				child.Status.LoadBalancer.Ingress[0].IPMode == nil || *child.Status.LoadBalancer.Ingress[0].IPMode != corev1.LoadBalancerIPModeVIP {
				return fmt.Errorf("private VIP was not established before firewall assignment: %#v", child.Status.LoadBalancer)
			}
			return nil
		},
	}

	audit := func() bool {
		t.Helper()
		service := getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		waiting, err := fixture.controller.auditAdvertisedServiceShard(fixture.ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		return waiting
	}
	if !audit() {
		t.Fatal("first audit did not persist the assignment fence")
	}
	if assignmentChecks != 0 {
		t.Fatalf("firewall assignment ran before its persisted fence: %d calls", assignmentChecks)
	}
	if !audit() {
		t.Fatal("assignment audit did not wait for authoritative assignment readback")
	}
	if assignmentChecks != 1 {
		t.Fatalf("firewall assignment checks = %d, want 1", assignmentChecks)
	}
	if !audit() {
		t.Fatal("assignment readback did not durably clear its fence before publication")
	}
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if len(parent.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("public status was published in the fence-clear reconciliation: %#v", parent.Status.LoadBalancer)
	}
	if audit() {
		t.Fatal("fully converged firewall gate still reported waiting")
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	nodeLoadBalancerAssertStatusIngress(t, parent.Status.LoadBalancer, "203.0.113.10", corev1.LoadBalancerIPModeProxy)
}

func TestNodeLoadBalancerFirewallAssignmentRevalidatesLiveServiceImmediatelyBeforeMutation(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = nil

	child := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		nodeLoadBalancerDatapathName(fixture.service),
	)
	vip := corev1.LoadBalancerIPModeVIP
	child.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.20", IPMode: &vip}}
	if _, err := fixture.provider.kubeClient.CoreV1().Services(child.Namespace).UpdateStatus(
		fixture.ctx, child, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerFirewallAssigning] = fixture.serviceFirewallUUID
	parent.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	parent, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	mutated := false
	fixture.provider.api = &nodeLoadBalancerFirewallListHookAPI{
		fakeAPI: fixture.api,
		afterList: func() error {
			if mutated {
				return nil
			}
			mutated = true
			live := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
			)
			live.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"}
			_, updateErr := fixture.provider.kubeClient.CoreV1().Services(live.Namespace).Update(
				fixture.ctx, live, metav1.UpdateOptions{},
			)
			return updateErr
		},
	}
	_, _, _, err = fixture.controller.ensureServiceFirewall(
		fixture.ctx,
		parent,
		[]*corev1.Node{fixture.node},
	)
	if err == nil {
		t.Fatal("same-UID Service policy race reached cloud assignment")
	}
	if !mutated {
		t.Fatal("test did not inject the live Service race")
	}
	if len(fixture.api.assignedFirewalls) != 0 {
		t.Fatalf("stale firewall was assigned after a live Service change: %#v", fixture.api.assignedFirewalls)
	}
}

func TestNodeLoadBalancerNodeRemovalDetachesEdgeBeforeRemovingVIP(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	node := getNodeLoadBalancerTestNode(t, fixture.ctx, fixture.provider, fixture.node.Name)
	for index := range node.Status.Conditions {
		if node.Status.Conditions[index].Type == corev1.NodeReady {
			node.Status.Conditions[index].Status = corev1.ConditionFalse
		}
	}
	if _, err := fixture.provider.kubeClient.CoreV1().Nodes().UpdateStatus(fixture.ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	detachChecks := 0
	fixture.provider.api = &nodeLoadBalancerUnassignmentOrderAPI{
		fakeAPI: fixture.api,
		beforeUnassign: func(firewallUUID, _ string) error {
			if firewallUUID != fixture.serviceFirewallUUID {
				return nil
			}
			detachChecks++
			parent := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
			)
			child := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(parent),
			)
			if len(parent.Status.LoadBalancer.Ingress) != 1 || parent.Status.LoadBalancer.Ingress[0].IP != "203.0.113.10" {
				return fmt.Errorf("public status shrank before stale edge detach: %#v", parent.Status.LoadBalancer)
			}
			if len(child.Status.LoadBalancer.Ingress) != 1 || child.Status.LoadBalancer.Ingress[0].IP != "10.0.0.20" {
				return fmt.Errorf("private VIP shrank before stale edge detach: %#v", child.Status.LoadBalancer)
			}
			return nil
		},
	}
	service := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	waiting, err := fixture.controller.auditAdvertisedServiceShard(fixture.ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	if waiting {
		t.Fatal("node removal unexpectedly waited after exact edge detachment")
	}
	if detachChecks != 1 {
		t.Fatalf("stale edge detach checks = %d, want 1", detachChecks)
	}
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if len(parent.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("public status retained removed Node: %#v", parent.Status.LoadBalancer)
	}
	child := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(parent),
	)
	if len(child.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("private VIP retained removed Node: %#v", child.Status.LoadBalancer)
	}
}

func TestNodeLoadBalancerWithdrawalDetachesPersistedFirewallAfterPolicyDrift(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)
	port := int32(22)
	fixture.firewall(t, fixture.serviceFirewallUUID).Rules[0].PortStart = &port
	fixture.firewall(t, fixture.serviceFirewallUUID).Rules[0].PortEnd = &port

	if err := fixture.controller.withdrawServiceDatapath(fixture.ctx, fixture.service); err != nil {
		t.Fatal(err)
	}
	nodeLoadBalancerAssertWithdrawn(t, fixture)
}

func TestNodeLoadBalancerEmergencyWithdrawalSerializesMultipleVMAssignments(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	now := time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fixture.controller.firewallRelationNow = clock
	fixture.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)
	sticky := &nodeLoadBalancerStickyUnassignAPI{fakeAPI: fixture.api}
	fixture.provider.api = sticky
	const secondVM = "bbbbbbbb-2222-4333-8444-cccccccccccc"
	fixture.api.vms = append(fixture.api.vms, inspace.VM{
		UUID: secondVM, Name: "lb-1", Status: "running",
		BillingAccountID: fixture.provider.config.BillingAccountID,
		NetworkUUID:      fixture.provider.config.NetworkUUID,
	})
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = append(
		fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned,
		inspace.FirewallResource{ResourceType: "vm", ResourceUUID: secondVM},
	)

	withdraw := func(controller *nodeLoadBalancerController) error {
		t.Helper()
		current := getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		return controller.withdrawServiceDatapath(fixture.ctx, current)
	}
	wantWaiting := func(err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "firewall relation") {
			t.Fatalf("withdrawal error = %v, want canonical firewall relation wait", err)
		}
	}

	wantWaiting(withdraw(fixture.controller))
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	wantFirstPair := fixture.serviceFirewallUUID + "/" + vmUUID
	wantSecondPair := fixture.serviceFirewallUUID + "/" + secondVM
	if got := fixture.api.unassignedFirewalls; len(got) != 1 || got[0] != wantFirstPair {
		t.Fatalf("first withdrawal detach calls = %#v, want sorted first pair %q", got, wantFirstPair)
	}
	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	wantEvidenceSet := strings.Join([]string{wantFirstPair, wantSecondPair}, ",")
	if current.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != wantEvidenceSet ||
		current.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] == "" {
		t.Fatalf("withdrawal evidence was not persisted exactly: %#v", current.Annotations)
	}
	firstEvidenceAt := current.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt]

	wantWaiting(withdraw(fixture.controller))
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("same controller repeated a fenced detach %d times, want 1", got)
	}

	restarted := &nodeLoadBalancerController{
		provider: fixture.provider, firewallRelationNow: clock,
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("restarted controller repeated a fenced detach %d times, want 1", got)
	}

	// The old evidence timestamps are diagnostic only. Aging them must never
	// authorize another relationship mutation while the canonical issue remains.
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	agedDetachTimes, err := json.Marshal(map[string]string{
		wantFirstPair:  time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		wantSecondPair: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	current.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(agedDetachTimes)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(current.Namespace).Update(
		fixture.ctx, current, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("aged evidence authorized %d detach calls, want 1", got)
	}

	// Exact absence of the sorted first pair clears that canonical issue, but the
	// same pass must stop before it can authorize the second pair.
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = []inspace.FirewallResource{{
		ResourceType: "vm", ResourceUUID: secondVM,
	}}
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("first-absence pass dispatched another detach; calls = %d, want 1", got)
	}

	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("spaced issue-clear pass dispatched another detach; calls = %d, want 1", got)
	}
	wantWaiting(withdraw(restarted))
	if got := fixture.api.unassignedFirewalls; len(got) != 2 || got[1] != wantSecondPair {
		t.Fatalf("second sorted detach calls = %#v, want [%q %q]", got, wantFirstPair, wantSecondPair)
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if got := current.Annotations[annotationNodeLoadBalancerWithdrawFWDetach]; got != wantSecondPair {
		t.Fatalf("current withdrawal evidence = %q, want %q", got, wantSecondPair)
	}
	if got := current.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt]; got == firstEvidenceAt {
		t.Fatal("assignment-set evidence did not advance after exact first-pair absence")
	}

	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = nil
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 2 {
		t.Fatalf("second first-absence pass dispatched another detach; calls = %d, want 2", got)
	}
	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	wantWaiting(withdraw(restarted))
	if got := len(fixture.api.unassignedFirewalls); got != 2 {
		t.Fatalf("second spaced issue-clear pass dispatched another detach; calls = %d, want 2", got)
	}
	if err := withdraw(restarted); err != nil {
		t.Fatal(err)
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if len(current.Status.LoadBalancer.Ingress) != 0 ||
		current.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
		t.Fatalf("withdrawal did not converge after assignment cleared: annotations=%#v status=%#v", current.Annotations, current.Status.LoadBalancer)
	}
	child := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(current),
	)
	if len(child.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("private datapath remained published after assignment cleared: %#v", child.Status.LoadBalancer)
	}
	if got := len(fixture.api.unassignedFirewalls); got != 2 {
		t.Fatalf("assignment-clear convergence issued another detach; calls = %d, want 2", got)
	}
	if current.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != wantSecondPair ||
		current.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] == "" {
		t.Fatalf("withdrawal convergence cleared diagnostic evidence early: %#v", current.Annotations)
	}
}

func TestNodeLoadBalancerEmergencyWithdrawalResolvesPendingAssignBeforeDelete(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	fixture.controller.firewallRelationNow = func() time.Time { return now }
	fixture.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	copy := current.DeepCopy()
	copy.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] = nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: fixture.serviceFirewallUUID,
		vmUUID:       vmUUID,
		issueID:      strings.Repeat("a", 32),
		issuedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}.String()
	copy.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] = string(copy.UID)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(
		fixture.ctx, copy, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, current)
	if err == nil || !strings.Contains(err.Error(), "waiting for prior Service firewall relation readback") {
		t.Fatalf("pending assignment resolution error = %v, want a fresh-pass wait", err)
	}
	if got := len(fixture.api.unassignedFirewalls); got != 0 {
		t.Fatalf("assignment-fence resolution dispatched %d emergency DELETEs, want 0", got)
	}
	stored := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if got := stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued]; got != "" {
		t.Fatalf("converged assignment fence remains stored: %q", got)
	}

	if err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored); err == nil || !strings.Contains(err.Error(), "firewall relation") {
		t.Fatalf("first removal absence did not remain fenced: %v", err)
	}
	wantPair := fixture.serviceFirewallUUID + "/" + vmUUID
	if got := fixture.api.unassignedFirewalls; len(got) != 1 || got[0] != wantPair {
		t.Fatalf("post-resolution emergency DELETEs = %#v, want [%q]", got, wantPair)
	}
	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored); err == nil || !strings.Contains(err.Error(), "prior Service firewall relation readback") {
		t.Fatalf("spaced removal issue-clear error = %v, want fresh-pass wait", err)
	}
	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored); err != nil {
		t.Fatal(err)
	}
	if got := len(fixture.api.unassignedFirewalls); got != 1 {
		t.Fatalf("removal confirmation reissued %d DELETEs, want 1", got)
	}
}

func TestNodeLoadBalancerEmergencyWithdrawalCommitted500RestartDoesNotReissue(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	now := time.Date(2026, 7, 17, 5, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fixture.controller.firewallRelationNow = clock
	fixture.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	api := &nodeLoadBalancerCommittedHiddenUnassignAPI{
		fakeAPI:      fixture.api,
		firewallUUID: fixture.serviceFirewallUUID,
		vmUUID:       vmUUID,
		hiddenReads:  2,
	}
	fixture.provider.api = api

	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, current)
	if err == nil || !strings.Contains(err.Error(), "committed but response lost") {
		t.Fatalf("committed HTTP 500 error = %v, want ambiguous failure", err)
	}
	if api.calls != 1 {
		t.Fatalf("initial emergency DELETE calls = %d, want 1", api.calls)
	}
	stored := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" {
		t.Fatalf("ambiguous emergency DELETE lacks canonical issue: %#v", stored.Annotations)
	}

	restarted := &nodeLoadBalancerController{
		provider: fixture.provider, firewallRelationNow: clock,
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	err = restarted.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored)
	if err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("restart hidden-readback error = %v, want canonical pending state", err)
	}
	if api.calls != 1 {
		t.Fatalf("restart reissued committed emergency DELETE %d times, want 1", api.calls)
	}

	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	err = restarted.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored)
	if err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("first exact-absence observation error = %v, want durable pending state", err)
	}
	if api.calls != 1 {
		t.Fatalf("first exact-absence observation reissued emergency DELETE %d times, want 1", api.calls)
	}
	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	issued, parseErr := parseNodeLoadBalancerFirewallRelationFence(stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued])
	if parseErr != nil || issued.absenceObservedAt == "" {
		t.Fatalf("first exact absence did not persist canonical observation: %#v err=%v", issued, parseErr)
	}
	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	err = restarted.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored)
	if err == nil || !strings.Contains(err.Error(), "waiting for prior Service firewall relation readback") {
		t.Fatalf("spaced exact-absence issue-clear error = %v, want fresh-pass wait", err)
	}
	if api.calls != 1 {
		t.Fatalf("spaced exact-absence issue clear reissued emergency DELETE %d times, want 1", api.calls)
	}
	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("two authoritative absences did not clear canonical issue: %#v", stored.Annotations)
	}
	if err := restarted.detachOwnedServiceFirewallsForFailure(fixture.ctx, stored); err != nil {
		t.Fatal(err)
	}
	if api.calls != 1 {
		t.Fatalf("absence convergence reissued emergency DELETE %d times, want 1", api.calls)
	}
}

func TestNodeLoadBalancerWithdrawalDoesNotDispatchWhenDetachReceiptIsStripped(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	client, ok := fixture.provider.kubeClient.(*kubefake.Clientset)
	if !ok {
		t.Fatal("fixture does not use a fake Kubernetes clientset")
	}
	client.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		service, ok := update.GetObject().(*corev1.Service)
		if !ok || service.Name != fixture.service.Name || service.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] == "" {
			return false, nil, nil
		}
		stripped := service.DeepCopy()
		delete(stripped.Annotations, annotationNodeLoadBalancerWithdrawFWDetach)
		delete(stripped.Annotations, annotationNodeLoadBalancerWithdrawFWDetachAt)
		return true, stripped, nil
	})

	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	err := fixture.controller.detachOwnedServiceFirewallsForFailure(fixture.ctx, current)
	if err == nil || !strings.Contains(err.Error(), "exact controller receipt") {
		t.Fatalf("stripped emergency-detach receipt error = %v", err)
	}
	if len(fixture.api.unassignedFirewalls) != 0 {
		t.Fatalf("stripped emergency-detach receipt dispatched cloud mutation: %#v", fixture.api.unassignedFirewalls)
	}
}

func TestExactParentUpdateAcceptsAPIServerNilNormalizationOfEmptyFinalizers(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	client := fixture.provider.kubeClient.(*kubefake.Clientset)
	client.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		service, ok := update.GetObject().(*corev1.Service)
		if !ok || service.Name != fixture.service.Name || len(service.Finalizers) != 0 {
			return false, nil, nil
		}
		normalized := service.DeepCopy()
		normalized.Finalizers = nil
		if err := client.Tracker().Update(
			corev1.SchemeGroupVersion.WithResource("services"), normalized, normalized.Namespace,
		); err != nil {
			return true, nil, err
		}
		return true, normalized, nil
	})

	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	updated, changed, err := fixture.controller.updateExactParentService(fixture.ctx, current, func(copy *corev1.Service) (bool, error) {
		copy.Finalizers = removeString(copy.Finalizers, nodeLoadBalancerFinalizer)
		return true, nil
	})
	if err != nil || !changed || updated == nil || len(updated.Finalizers) != 0 {
		t.Fatalf("nil-normalized finalizer removal = updated %#v, changed=%t, err=%v", updated, changed, err)
	}
}

func TestClusterICMPDoesNotDispatchWhenIssuedReceiptIsStripped(t *testing.T) {
	ctx, api, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	dynamicClient, ok := provider.dynamicClient.(*fake.FakeDynamicClient)
	if !ok {
		t.Fatal("fixture does not use a fake dynamic client")
	}
	dynamicClient.PrependReactor("update", nodeClassGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := update.GetObject().(*unstructured.Unstructured)
		if !ok || object.GetName() != nodeClassName || object.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
			return false, nil, nil
		}
		stripped := object.DeepCopy()
		annotations := stripped.GetAnnotations()
		delete(annotations, annotationNodeLoadBalancerICMPCreateIssued)
		stripped.SetAnnotations(annotations)
		return true, stripped, nil
	})

	_, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
	if err == nil || !strings.Contains(err.Error(), "exact cluster ICMP firewall receipt") {
		t.Fatalf("stripped cluster ICMP receipt error = %v", err)
	}
	if len(api.createdFirewalls) != 0 {
		t.Fatalf("stripped cluster ICMP receipt dispatched %d firewall creates", len(api.createdFirewalls))
	}
}

func TestShardFirewallDoesNotDispatchWhenIssuedReceiptIsStripped(t *testing.T) {
	existing := aggregateTestService(
		"receipt-create",
		"71111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	fixture.reconcile(t) // persist create intent only
	dynamicClient := fixture.provider.dynamicClient.(*fake.FakeDynamicClient)
	stripIssued := func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := update.GetObject().(*unstructured.Unstructured)
		if !ok || object.GetName() != fixture.shard || object.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
			return false, nil, nil
		}
		stripped := object.DeepCopy()
		annotations := stripped.GetAnnotations()
		delete(annotations, annotationNodeLoadBalancerShardFWIssuedAt)
		stripped.SetAnnotations(annotations)
		return true, stripped, nil
	}
	dynamicClient.PrependReactor("update", nodePoolGVR.Resource, stripIssued)
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
		!strings.Contains(err.Error(), "exact shard firewall receipt") {
		t.Fatalf("stripped shard-create receipt error = %v", err)
	}
	if len(fixture.api.createdFirewalls) != 0 {
		t.Fatalf("stripped shard-create receipt dispatched %d firewall creates", len(fixture.api.createdFirewalls))
	}
}

func TestShardFirewallUpdateDoesNotDispatchWhenIssuedReceiptIsStripped(t *testing.T) {
	existing := aggregateTestService(
		"receipt-update",
		"72222222-2222-4222-8222-222222222222",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil {
		t.Fatalf("initial desired policy = %#v, %v", desired, err)
	}
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*desired, aggregateTestFirewallUUID)}
	fixture.reconcile(t) // adopt
	fixture.reconcile(t) // ready
	newMember := aggregateTestService(
		"receipt-update-new",
		"73333333-3333-4333-8333-333333333333",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(newMember.Namespace).Create(
		fixture.ctx, newMember, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	fixture.reconcile(t) // persist update intent only
	dynamicClient := fixture.provider.dynamicClient.(*fake.FakeDynamicClient)
	dynamicClient.PrependReactor("update", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := update.GetObject().(*unstructured.Unstructured)
		if !ok || object.GetName() != fixture.shard || object.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
			return false, nil, nil
		}
		stripped := object.DeepCopy()
		annotations := stripped.GetAnnotations()
		delete(annotations, annotationNodeLoadBalancerShardFWIssuedAt)
		stripped.SetAnnotations(annotations)
		return true, stripped, nil
	})
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
		!strings.Contains(err.Error(), "exact shard firewall receipt") {
		t.Fatalf("stripped shard-update receipt error = %v", err)
	}
	if len(fixture.api.updatedFirewalls) != 0 {
		t.Fatalf("stripped shard-update receipt dispatched %d firewall updates", len(fixture.api.updatedFirewalls))
	}
}

func TestNodeLoadBalancerWithdrawalDoesNotTrustTransientFirewallOmission(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerFirewallAssigning] = fixture.serviceFirewallUUID
	parent.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	parent, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	omitting := &nodeLoadBalancerFirewallOmissionAPI{fakeAPI: fixture.api, omitUUID: fixture.serviceFirewallUUID}
	fixture.provider.api = omitting
	err = fixture.controller.withdrawServiceDatapath(fixture.ctx, parent)
	if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
		t.Fatalf("withdrawal during transient omission error = %v", err)
	}
	if len(fixture.api.unassignedFirewalls) != 0 {
		t.Fatalf("hidden firewall unexpectedly reported a detachment: %#v", fixture.api.unassignedFirewalls)
	}
	stored := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if stored.Annotations[annotationNodeLoadBalancerDatapathActive] != fixture.shard ||
		len(stored.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("transient omission cleared durable/public state: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
	child := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(stored),
	)
	if len(child.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("transient omission cleared private VIP: %#v", child.Status.LoadBalancer)
	}

	omitting.omitUUID = ""
	err = fixture.controller.withdrawServiceDatapath(fixture.ctx, stored)
	if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
		t.Fatalf("late assignment became trusted immediately after visibility: %v", err)
	}
	if len(fixture.api.unassignedFirewalls) != 1 {
		t.Fatalf("visible late assignment was not detached exactly once: %#v", fixture.api.unassignedFirewalls)
	}
	stored = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	stored.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().Add(
		-nodeLoadBalancerPendingCreateTimeout - time.Minute,
	).UTC().Format(time.RFC3339Nano)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(stored.Namespace).Update(
		fixture.ctx, stored, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	withdraw := func() error {
		t.Helper()
		current := getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		return fixture.controller.withdrawServiceDatapath(fixture.ctx, current)
	}
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		err = withdraw()
		if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
			t.Fatalf("withdrawal confirmation %d error = %v", confirmation, err)
		}
		if confirmation < nodeLoadBalancerAbsenceConfirmations {
			current := getNodeLoadBalancerTestService(
				t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
			)
			ageNodeLoadBalancerAbsenceEvidence(
				t,
				fixture.ctx,
				fixture.provider,
				current,
				annotationNodeLoadBalancerWithdrawFWChecked,
			)
		}
	}
	if err := withdraw(); err != nil {
		t.Fatal(err)
	}
	nodeLoadBalancerAssertWithdrawn(t, fixture)
}

func TestNodeLoadBalancerLateAssignmentResetsConsecutiveWithdrawalProof(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = nil

	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerFirewallAssigning] = fixture.serviceFirewallUUID
	parent.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().Add(
		-nodeLoadBalancerPendingCreateTimeout - time.Minute,
	).UTC().Format(time.RFC3339Nano)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	withdraw := func() error {
		t.Helper()
		current := getNodeLoadBalancerTestService(
			t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
		)
		return fixture.controller.withdrawServiceDatapath(fixture.ctx, current)
	}
	if err := withdraw(); err == nil {
		t.Fatal("first empty assignment observation cleared the datapath")
	}
	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] != "1" {
		t.Fatalf("first proof count = %q, want 1", current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent])
	}
	ageNodeLoadBalancerAbsenceEvidence(
		t,
		fixture.ctx,
		fixture.provider,
		current,
		annotationNodeLoadBalancerWithdrawFWChecked,
	)
	if err := withdraw(); err == nil {
		t.Fatal("second empty assignment observation cleared the datapath")
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] != "2" {
		t.Fatalf("second proof count = %q, want 2", current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent])
	}

	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned = []inspace.FirewallResource{{
		ResourceType: "vm", ResourceUUID: vmUUID,
	}}
	if err := withdraw(); err == nil {
		t.Fatal("late assignment cleared the datapath after resetting proof")
	}
	current = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if current.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] != "1" {
		t.Fatalf("late assignment did not reset proof count: %#v", current.Annotations)
	}
	if current.Annotations[annotationNodeLoadBalancerDatapathActive] != fixture.shard ||
		len(current.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("late assignment cleared durable/public state: annotations=%#v status=%#v", current.Annotations, current.Status.LoadBalancer)
	}
	child := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, nodeLoadBalancerDatapathName(current),
	)
	if len(child.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("late assignment cleared private VIP before consecutive proof: %#v", child.Status.LoadBalancer)
	}
}

func TestNodeLoadBalancerRecoveryClearsRetainedWithdrawalProofBeforeRepublishing(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWMissing] = fixture.serviceFirewallUUID
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] = strconv.Itoa(nodeLoadBalancerAbsenceConfirmations)
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWChecked] = time.Now().Add(
		-nodeLoadBalancerAbsenceConfirmationDelay - time.Second,
	).UTC().Format(time.RFC3339Nano)
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	detachPair := fixture.serviceFirewallUUID + "/" + vmUUID
	detachTimes, marshalErr := json.Marshal(map[string]string{
		detachPair: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = detachPair
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(detachTimes)
	parent, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	waiting, err := fixture.controller.auditAdvertisedServiceShard(fixture.ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if !waiting {
		t.Fatal("proof reset did not force a separate assignment re-audit before publication")
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	for _, key := range []string{
		annotationNodeLoadBalancerWithdrawFWMissing,
		annotationNodeLoadBalancerWithdrawFWAbsent,
		annotationNodeLoadBalancerWithdrawFWChecked,
		annotationNodeLoadBalancerWithdrawFWDetach,
		annotationNodeLoadBalancerWithdrawFWDetachAt,
	} {
		if parent.Annotations[key] != "" {
			t.Fatalf("retained withdrawal proof key %s was not cleared after positive assignment readback: %#v", key, parent.Annotations)
		}
	}
	if len(parent.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("public status remained published during durable proof reset: %#v", parent.Status.LoadBalancer)
	}

	waiting, err = fixture.controller.auditAdvertisedServiceShard(fixture.ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if waiting {
		t.Fatal("exact assignment re-audit did not republish the recovered Service")
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	nodeLoadBalancerAssertStatusIngress(t, parent.Status.LoadBalancer, "203.0.113.10", corev1.LoadBalancerIPModeProxy)

	fixture.provider.api = &nodeLoadBalancerFirewallOmissionAPI{
		fakeAPI:  fixture.api,
		omitUUID: fixture.serviceFirewallUUID,
	}
	err = fixture.controller.withdrawServiceDatapath(fixture.ctx, parent)
	if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
		t.Fatalf("first post-recovery firewall omission reused stale proof: %v", err)
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if parent.Annotations[annotationNodeLoadBalancerWithdrawFWAbsent] != "1" ||
		parent.Annotations[annotationNodeLoadBalancerDatapathActive] != fixture.shard ||
		len(parent.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("first post-recovery omission was not treated as provisional: annotations=%#v status=%#v", parent.Annotations, parent.Status.LoadBalancer)
	}
}

func TestNodeLoadBalancerZeroReadyNodesRetainWithdrawalFence(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	detachPair := fixture.serviceFirewallUUID + "/" + vmUUID
	detachTimes, err := json.Marshal(map[string]string{
		detachPair: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = detachPair
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(detachTimes)
	parent, err = fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	node := fixture.node.DeepCopy()
	for index := range node.Status.Conditions {
		if node.Status.Conditions[index].Type == corev1.NodeReady {
			node.Status.Conditions[index].Status = corev1.ConditionFalse
		}
	}
	if _, err := fixture.provider.kubeClient.CoreV1().Nodes().UpdateStatus(
		fixture.ctx, node, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.nodeIndexer.Update(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	waiting, err := fixture.controller.auditAdvertisedServiceShard(fixture.ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if waiting {
		t.Fatal("zero-node audit unexpectedly entered an assignment gate")
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != detachPair ||
		parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] != string(detachTimes) {
		t.Fatalf("empty desired/actual assignment readback cleared the withdrawal fence: %#v", parent.Annotations)
	}
	if len(parent.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("zero-ready-node audit retained public status: %#v", parent.Status.LoadBalancer)
	}
	if assigned := fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned; len(assigned) != 0 {
		t.Fatalf("zero-ready-node audit retained firewall assignments: %#v", assigned)
	}
}

func TestNodeLoadBalancerRecoveryClearsOnlyPositivelyReadCurrentFirewallFence(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()

	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	const previousFirewallUUID = "dddddddd-3333-4444-8555-eeeeeeeeeeee"
	currentPair := fixture.serviceFirewallUUID + "/" + vmUUID
	previousPair := previousFirewallUUID + "/" + vmUUID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	detachTimes := map[string]string{currentPair: now, previousPair: now}
	encodedTimes, err := json.Marshal(detachTimes)
	if err != nil {
		t.Fatal(err)
	}
	parent := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	parent.Annotations[annotationNodeLoadBalancerPreviousFirewall] = previousFirewallUUID
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = nodeLoadBalancerFirewallDetachSetFromTimes(detachTimes)
	parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(encodedTimes)
	parent, err = fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
		fixture.ctx, parent, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	cleared, err := fixture.controller.clearServiceFirewallWithdrawalEvidenceAfterAssignment(
		fixture.ctx, parent, fixture.serviceFirewallUUID, []*corev1.Node{fixture.node},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !cleared {
		t.Fatal("positive current-firewall readback did not clear its withdrawal record")
	}
	parent = getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	if got := parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetach]; got != previousPair {
		t.Fatalf("recovery cleared or changed the previous-firewall fence: got %q, want %q", got, previousPair)
	}
	retained, err := parseNodeLoadBalancerFirewallDetachTimes(
		parent.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt],
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[previousPair] != now {
		t.Fatalf("recovery retained withdrawal timestamps = %#v, want only %s", retained, previousPair)
	}

	cleared, err = fixture.controller.clearServiceFirewallWithdrawalEvidenceAfterAssignment(
		fixture.ctx, parent, fixture.serviceFirewallUUID, []*corev1.Node{fixture.node},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cleared {
		t.Fatal("second current-firewall readback mutated an unrelated previous-firewall fence")
	}
}

func TestNodeLoadBalancerIncompleteWithdrawalRetainsActivationMarker(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	detachErr := errors.New("injected firewall detach failure")
	statusErr := errors.New("injected private VIP withdrawal failure")
	failingAPI := &nodeLoadBalancerFailingUnassignAPI{fakeAPI: fixture.api, err: detachErr}
	fixture.provider.api = failingAPI
	clientset, ok := fixture.provider.kubeClient.(*kubefake.Clientset)
	if !ok {
		t.Fatalf("kube client type = %T", fixture.provider.kubeClient)
	}
	childName := nodeLoadBalancerDatapathName(fixture.service)
	childStatusUpdates := 0
	clientset.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok || action.GetSubresource() != "status" {
			return false, nil, nil
		}
		service, ok := update.GetObject().(*corev1.Service)
		if !ok || service.Name != childName {
			return false, nil, nil
		}
		childStatusUpdates++
		return true, nil, statusErr
	})

	err := fixture.controller.withdrawServiceDatapath(fixture.ctx, fixture.service)
	if !errors.Is(err, detachErr) || errors.Is(err, statusErr) {
		t.Fatalf("withdrawal error = %v, want only the edge-detach failure", err)
	}
	if childStatusUpdates != 0 {
		t.Fatalf("private VIP withdrawal ran %d times before the firewall detached", childStatusUpdates)
	}
	current := getNodeLoadBalancerTestService(
		t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	err = fixture.controller.withdrawServiceDatapath(fixture.ctx, current)
	if err == nil || !strings.Contains(err.Error(), "firewall relation") {
		t.Fatalf("fenced withdrawal retry error = %v, want canonical relation readback wait", err)
	}
	if failingAPI.calls != 1 {
		t.Fatalf("failed cloud detach was retried %d times without authoritative absence, want 1", failingAPI.calls)
	}
	stored := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		fixture.service.Name,
	)
	if stored.Annotations[annotationNodeLoadBalancerDatapathActive] != fixture.shard {
		t.Fatalf("incomplete withdrawal cleared durable activation marker: %#v", stored.Annotations)
	}
	datapath := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		childName,
	)
	nodeLoadBalancerAssertStatusIngress(t, datapath.Status.LoadBalancer, "10.0.0.20", corev1.LoadBalancerIPModeVIP)
}

func TestNodeLoadBalancerForeignDatapathWithdrawalPreservesChildButWithdrawsParentAndFirewall(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	datapath := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		nodeLoadBalancerDatapathName(fixture.service),
	)
	datapath.Labels[nodeLoadBalancerServiceIdentityLabel] = "foreign-identity"
	datapath.OwnerReferences[0].UID = types.UID("foreign-uid")
	if _, err := fixture.provider.kubeClient.CoreV1().Services(datapath.Namespace).Update(
		fixture.ctx,
		datapath,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	err := fixture.controller.withdrawServiceDatapath(fixture.ctx, fixture.service)
	if err == nil || !strings.Contains(err.Error(), "refusing to withdraw foreign datapath Service") {
		t.Fatalf("foreign datapath withdrawal error = %v", err)
	}
	storedDatapath := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		nodeLoadBalancerDatapathName(fixture.service),
	)
	nodeLoadBalancerAssertStatusIngress(t, storedDatapath.Status.LoadBalancer, "10.0.0.20", corev1.LoadBalancerIPModeVIP)
	nodeLoadBalancerAssertParentAndFirewallWithdrawn(t, fixture)
}

func TestNodeLoadBalancerLiveNodeListFailureStillWithdrawsShardDatapaths(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	listErr := errors.New("injected live Node List failure")
	clientset, ok := fixture.provider.kubeClient.(*kubefake.Clientset)
	if !ok {
		t.Fatalf("kube client type = %T", fixture.provider.kubeClient)
	}
	clientset.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, listErr
	})
	cause := errors.New("injected shard failure")
	err := fixture.controller.failNodeLoadBalancerShardClosed(fixture.ctx, fixture.shard, cause)
	if !errors.Is(err, cause) || !errors.Is(err, listErr) {
		t.Fatalf("fail-closed error = %v, want both injected errors", err)
	}
	nodeLoadBalancerAssertWithdrawn(t, fixture)
}

func TestNodeLoadBalancerLiveServiceListFailureUsesInformerForWithdrawal(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	nodeLoadBalancerSeedAdvertisedStatuses(t, fixture)

	injected := errors.New("injected live Service List failure")
	clientset, ok := fixture.provider.kubeClient.(*kubefake.Clientset)
	if !ok {
		t.Fatalf("kube client type = %T", fixture.provider.kubeClient)
	}
	clientset.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, injected
	})

	err := fixture.controller.withdrawShardDatapaths(fixture.ctx, fixture.shard)
	if !errors.Is(err, injected) {
		t.Fatalf("withdrawal error = %v, want live List failure", err)
	}
	nodeLoadBalancerAssertWithdrawn(t, fixture)
}

func TestNodeLoadBalancerInterruptedActivationContract(t *testing.T) {
	tests := map[string]struct {
		seedParent bool
		seedChild  bool
		childIP    string
		wantError  bool
	}{
		"unadvertised staged child": {},
		"private VIP only": {
			seedChild: true,
			childIP:   "10.0.0.20",
			wantError: true,
		},
		"exact private VIP and public Proxy pair": {
			seedParent: true,
			seedChild:  true,
			childIP:    "10.0.0.20",
			wantError:  true,
		},
		"public Proxy without private VIP": {
			seedParent: true,
			wantError:  true,
		},
		"mismatched private VIP and public Proxy pair": {
			seedParent: true,
			seedChild:  true,
			childIP:    "10.0.0.99",
			wantError:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newNodeLoadBalancerFailClosedFixture(t)
			defer fixture.controller.queue.ShutDown()

			parent := getNodeLoadBalancerTestService(
				t,
				fixture.ctx,
				fixture.provider,
				fixture.service.Namespace,
				fixture.service.Name,
			)
			delete(parent.Annotations, annotationNodeLoadBalancerDatapathActive)
			if _, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).Update(
				fixture.ctx,
				parent,
				metav1.UpdateOptions{},
			); err != nil {
				t.Fatal(err)
			}

			if test.seedParent {
				proxy := corev1.LoadBalancerIPModeProxy
				parent = getNodeLoadBalancerTestService(
					t,
					fixture.ctx,
					fixture.provider,
					fixture.service.Namespace,
					fixture.service.Name,
				)
				parent.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
					IP: "203.0.113.10", IPMode: &proxy,
				}}
				if _, err := fixture.provider.kubeClient.CoreV1().Services(parent.Namespace).UpdateStatus(
					fixture.ctx,
					parent,
					metav1.UpdateOptions{},
				); err != nil {
					t.Fatal(err)
				}
			}

			if test.seedChild {
				vip := corev1.LoadBalancerIPModeVIP
				child := getNodeLoadBalancerTestService(
					t,
					fixture.ctx,
					fixture.provider,
					fixture.service.Namespace,
					nodeLoadBalancerDatapathName(fixture.service),
				)
				child.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
					IP: test.childIP, IPMode: &vip,
				}}
				if _, err := fixture.provider.kubeClient.CoreV1().Services(child.Namespace).UpdateStatus(
					fixture.ctx,
					child,
					metav1.UpdateOptions{},
				); err != nil {
					t.Fatal(err)
				}
			}

			err := fixture.controller.auditUncommittedDatapath(fixture.ctx, fixture.service)
			if test.wantError {
				if err == nil {
					t.Fatal("unsafe interrupted activation was accepted")
				}
				nodeLoadBalancerAssertWithdrawn(t, fixture)
				return
			}
			if err != nil {
				t.Fatalf("safe interrupted activation audit failed: %v", err)
			}
			stored := getNodeLoadBalancerTestService(
				t,
				fixture.ctx,
				fixture.provider,
				fixture.service.Namespace,
				fixture.service.Name,
			)
			if stored.Annotations[annotationNodeLoadBalancerDatapathActive] != "" {
				t.Fatalf("audit persisted activation marker unexpectedly: %#v", stored.Annotations)
			}
		})
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
	deletingAt := metav1.Now()
	lastOwner.DeletionTimestamp = &deletingAt
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
	annotations[annotationNodeLoadBalancerICMPCleanupChecked] = time.Now().Add(-nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano)
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

type nodeLoadBalancerFailingUnassignAPI struct {
	*fakeAPI
	err   error
	calls int
}

type nodeLoadBalancerAssignmentOrderAPI struct {
	*fakeAPI
	beforeAssign func(firewallUUID, vmUUID string) error
}

func (a *nodeLoadBalancerAssignmentOrderAPI) AssignFirewallToVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	if a.beforeAssign != nil {
		if err := a.beforeAssign(firewallUUID, vmUUID); err != nil {
			return err
		}
	}
	return a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

type nodeLoadBalancerUnassignmentOrderAPI struct {
	*fakeAPI
	beforeUnassign func(firewallUUID, vmUUID string) error
}

func (a *nodeLoadBalancerUnassignmentOrderAPI) UnassignFirewallFromVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	if a.beforeUnassign != nil {
		if err := a.beforeUnassign(firewallUUID, vmUUID); err != nil {
			return err
		}
	}
	return a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

type nodeLoadBalancerFirewallOmissionAPI struct {
	*fakeAPI
	omitUUID string
}

type nodeLoadBalancerFirewallListHookAPI struct {
	*fakeAPI
	afterList func() error
}

type nodeLoadBalancerHiddenPostCreateAPI struct {
	*fakeAPI
	hideLists int
}

func (a *nodeLoadBalancerHiddenPostCreateAPI) CreateFirewall(
	ctx context.Context,
	location string,
	request inspace.CreateFirewallRequest,
) (*inspace.Firewall, error) {
	created, err := a.fakeAPI.CreateFirewall(ctx, location, request)
	if err == nil {
		a.hideLists = 100
	}
	return created, err
}

func (a *nodeLoadBalancerHiddenPostCreateAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	if a.hideLists > 0 {
		a.hideLists--
		return nil, nil
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

type nodeLoadBalancerStickyUnassignAPI struct {
	*fakeAPI
}

type nodeLoadBalancerCommittedHiddenUnassignAPI struct {
	*fakeAPI
	firewallUUID string
	vmUUID       string
	hiddenReads  int
	committed    bool
	calls        int
}

func (a *nodeLoadBalancerStickyUnassignAPI) UnassignFirewallFromVM(
	_ context.Context,
	_, firewallUUID, vmUUID string,
) error {
	for _, firewall := range a.firewalls {
		if firewall.UUID != firewallUUID {
			continue
		}
		for _, resource := range firewall.ResourcesAssigned {
			if strings.EqualFold(resource.ResourceType, "vm") && resource.ResourceUUID == vmUUID {
				a.unassignedFirewalls = append(a.unassignedFirewalls, firewallUUID+"/"+vmUUID)
				return nil
			}
		}
		return &inspace.APIError{StatusCode: 404, Method: "DELETE", Path: "/firewall/vms", Message: "assignment not found"}
	}
	return &inspace.APIError{StatusCode: 404, Method: "DELETE", Path: "/firewall/vms", Message: "firewall not found"}
}

func (a *nodeLoadBalancerCommittedHiddenUnassignAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	result := cloneNodeLoadBalancerTestFirewalls(items)
	if !a.committed || a.hiddenReads == 0 {
		return result, nil
	}
	a.hiddenReads--
	for index := range result {
		if result[index].UUID != a.firewallUUID {
			continue
		}
		for _, relation := range result[index].ResourcesAssigned {
			if strings.EqualFold(relation.ResourceType, "vm") && relation.ResourceUUID == a.vmUUID {
				return result, nil
			}
		}
		result[index].ResourcesAssigned = append(result[index].ResourcesAssigned, inspace.FirewallResource{
			ResourceType: "vm", ResourceUUID: a.vmUUID,
		})
	}
	return result, nil
}

func (a *nodeLoadBalancerCommittedHiddenUnassignAPI) UnassignFirewallFromVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.calls++
	if err := a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID); err != nil {
		return err
	}
	a.committed = true
	return &inspace.APIError{
		StatusCode: 500,
		Method:     "DELETE",
		Path:       "/firewall/vms",
		Message:    "committed but response lost",
		Retryable:  true,
	}
}

func (a *nodeLoadBalancerFirewallListHookAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil || a.afterList == nil {
		return items, err
	}
	if hookErr := a.afterList(); hookErr != nil {
		return nil, hookErr
	}
	return items, nil
}

func (a *nodeLoadBalancerFirewallOmissionAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil || a.omitUUID == "" {
		return items, err
	}
	filtered := make([]inspace.Firewall, 0, len(items))
	for _, firewall := range items {
		if firewall.UUID != a.omitUUID {
			filtered = append(filtered, firewall)
		}
	}
	return filtered, nil
}

func (f *nodeLoadBalancerFailingUnassignAPI) UnassignFirewallFromVM(context.Context, string, string, string) error {
	f.calls++
	return f.err
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
	nodeLoadBalancerSafetyMarkDatapathActive(service, shard)
	shadow := nodeLoadBalancerSafetyDatapath(service, shard)
	node := readyNode("lb-0", "inspace://bkk01/"+vmUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}

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

func nodeLoadBalancerSeedAdvertisedStatuses(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
	t.Helper()
	proxy := corev1.LoadBalancerIPModeProxy
	service := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		fixture.service.Name,
	)
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
		IP: "203.0.113.10", IPMode: &proxy,
	}}
	if _, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).UpdateStatus(
		fixture.ctx,
		service,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	vip := corev1.LoadBalancerIPModeVIP
	datapath := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		nodeLoadBalancerDatapathName(fixture.service),
	)
	datapath.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{
		IP: "10.0.0.20", IPMode: &vip,
	}}
	if _, err := fixture.provider.kubeClient.CoreV1().Services(datapath.Namespace).UpdateStatus(
		fixture.ctx,
		datapath,
		metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
}

func nodeLoadBalancerAssertWithdrawn(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
	t.Helper()
	datapath := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		nodeLoadBalancerDatapathName(fixture.service),
	)
	if len(datapath.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("private VIP datapath status was not withdrawn: %#v", datapath.Status.LoadBalancer)
	}
	nodeLoadBalancerAssertParentAndFirewallWithdrawn(t, fixture)
}

func nodeLoadBalancerAssertParentAndFirewallWithdrawn(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
	t.Helper()
	service := getNodeLoadBalancerTestService(
		t,
		fixture.ctx,
		fixture.provider,
		fixture.service.Namespace,
		fixture.service.Name,
	)
	if len(service.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("public Proxy status was not withdrawn: %#v", service.Status.LoadBalancer)
	}
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatalf("fixture Node has no InSpace VM identity: %#v", fixture.node.Spec.ProviderID)
	}
	want := fixture.serviceFirewallUUID + "/" + vmUUID
	if len(fixture.api.unassignedFirewalls) != 1 || fixture.api.unassignedFirewalls[0] != want {
		t.Fatalf("fail-closed firewall detachments = %#v, want [%q]", fixture.api.unassignedFirewalls, want)
	}
	if assigned := fixture.firewall(t, fixture.serviceFirewallUUID).ResourcesAssigned; len(assigned) != 0 {
		t.Fatalf("exact-owned Service firewall remained assigned: %#v", assigned)
	}
	if !firewallAssignedToVM(*fixture.firewall(t, fixture.icmpFirewallUUID), vmUUID) {
		t.Fatal("fail-closed Service withdrawal detached the shared cluster ICMP firewall")
	}
}

func nodeLoadBalancerAssertStatusIngress(
	t *testing.T,
	status corev1.LoadBalancerStatus,
	wantIP string,
	wantMode corev1.LoadBalancerIPMode,
) {
	t.Helper()
	if len(status.Ingress) != 1 || status.Ingress[0].IP != wantIP ||
		status.Ingress[0].IPMode == nil || *status.Ingress[0].IPMode != wantMode {
		t.Fatalf("load balancer status = %#v, want %s with mode %s", status, wantIP, wantMode)
	}
}

type nodeLoadBalancerFailingNodeLister struct {
	err error
}

func (l nodeLoadBalancerFailingNodeLister) List(labels.Selector) ([]*corev1.Node, error) {
	return nil, l.err
}

func (l nodeLoadBalancerFailingNodeLister) Get(string) (*corev1.Node, error) {
	return nil, l.err
}

var _ corelisters.NodeLister = nodeLoadBalancerFailingNodeLister{}

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

func getNodeLoadBalancerTestNode(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	name string,
) *corev1.Node {
	t.Helper()
	node, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return node
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
	ctx := context.Background()
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
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset()
	for _, node := range []*corev1.Node{good, spoofed, wrongCluster} {
		if _, err := provider.kubeClient.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	controller := &nodeLoadBalancerController{provider: provider}
	nodes, err := controller.rawNodesForShard(ctx, "inlb-0123abcd")
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
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
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
	addresses, err := controller.readyShardAddresses(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0].Node.Name != node.Name ||
		addresses[0].PrivateIPv4 != "10.0.0.20" || addresses[0].PublicIPv4 != "203.0.113.10" {
		t.Fatalf("ready address pairs = %#v", addresses)
	}
	current, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.11"},
	}
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

func TestNodeLoadBalancerExactLabelAndProviderIDSpoofCannotAttachFirewallOrAdvertise(t *testing.T) {
	ctx := context.Background()
	const shard = "inlb-0123abcd"
	legitimate := readyNode("lb-real", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	legitimate.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: "unit-test-cluster",
		nodeLoadBalancerNodeShardLabel:   shard,
	}
	legitimate.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
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
	spoofed.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.99"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.99"},
	}
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
	if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Create(ctx, service.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
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
	addresses, err := controller.readyShardAddresses(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 0 {
		t.Fatalf("spoofed Node was advertised: %#v", addresses)
	}
	if err := controller.reconcileShardNodeEligibility(ctx, shard); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, spoofed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := stored.Labels[nodeLoadBalancerReadyLabel]; exists {
		t.Fatal("spoofed Node retained the protected datapath readiness label")
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
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
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
	api.floatingIPs[0].AssignedToPrivateIP = "10.0.0.99"
	authorized, err := controller.authorizedNodesForShard(ctx, shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 0 {
		t.Fatalf("Node with a mismatched FIP DNAT private IPv4 was authorized: %#v", authorized)
	}
	api.floatingIPs[0].AssignedToPrivateIP = "10.0.0.20"
	api.floatingIPs[0].Address = "203.0.113.11"
	authorized, err = controller.authorizedNodesForShard(ctx, shard)
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
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
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
	nextUID := 0
	seeded := make([]runtime.Object, 0, len(objects))
	for _, object := range objects {
		copy := object.DeepCopyObject()
		if resource, ok := copy.(*unstructured.Unstructured); ok && resource.GetUID() == "" {
			nextUID++
			resource.SetUID(types.UID(fmt.Sprintf("test-%s-%d", resource.GetName(), nextUID)))
		}
		seeded = append(seeded, copy)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			nodePoolGVR: "NodePoolList", nodeClaimGVR: "NodeClaimList",
		},
		seeded...,
	)
	client.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := createAction.GetObject().(*unstructured.Unstructured)
		if !ok || object.GetUID() != "" {
			return false, nil, nil
		}
		nextUID++
		object.SetUID(types.UID(fmt.Sprintf("test-%s-%d", object.GetName(), nextUID)))
		return false, nil, nil
	})
	return client
}

func installNodeLoadBalancerSafetyIdentity(
	t *testing.T,
	provider *Provider,
	node *corev1.Node,
	shard string,
) {
	t.Helper()
	ctx := context.Background()
	if provider.config.NodeLoadBalancer.DefaultNodeClass == "" {
		provider.config.NodeLoadBalancer.DefaultNodeClass = "workers"
	}
	baseNodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(
		ctx, provider.config.NodeLoadBalancer.DefaultNodeClass, metav1.GetOptions{},
	)
	baseNeedsCreate := apierrors.IsNotFound(err)
	if baseNeedsCreate {
		baseNodeClass = nodeLoadBalancerSafetyBaseNodeClass()
	} else if err != nil {
		t.Fatal(err)
	}
	baseFirewallUUID, found, err := unstructured.NestedString(baseNodeClass.Object, "spec", "firewallUUID")
	if err != nil || !found {
		t.Fatalf("test base NodeClass has no firewall UUID: found=%v err=%v", found, err)
	}
	if err := unstructured.SetNestedField(baseNodeClass.Object, baseFirewallUUID, "status", "firewallUUID"); err != nil {
		t.Fatal(err)
	}
	if baseNeedsCreate {
		if _, err := provider.dynamicClient.Resource(nodeClassGVR).Create(ctx, baseNodeClass, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	} else if _, err := provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, baseNodeClass, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		nodeClass, err = renderNodeLoadBalancerNodeClass(baseNodeClass, nodeClassName)
		if err != nil {
			t.Fatal(err)
		}
		if err := markNodeLoadBalancerManaged(nodeClass, provider.config.ClusterID, "", ""); err != nil {
			t.Fatal(err)
		}
		if err := unstructured.SetNestedField(nodeClass.Object, baseFirewallUUID, "status", "firewallUUID"); err != nil {
			t.Fatal(err)
		}
		if _, err = provider.dynamicClient.Resource(nodeClassGVR).Create(ctx, nodeClass, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else {
		if err := unstructured.SetNestedField(nodeClass.Object, baseFirewallUUID, "status", "firewallUUID"); err != nil {
			t.Fatal(err)
		}
		if nodeClass, err = provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, nodeClass, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
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
	floatingIPName := managedNodeLoadBalancerFloatingIPName(provider.config.ClusterID, claimName)
	externalIPForClaim, ok := nodeLoadBalancerNodeExternalIPv4(node)
	if !ok {
		t.Fatalf("Node %s has no public ExternalIP for its test identity", node.Name)
	}
	claimUID := types.UID("nodeclaim-" + shard)
	node.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "karpenter.sh/v1", Kind: "NodeClaim", Name: claimName, UID: claimUID,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}}
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodeClaim",
		"metadata": map[string]any{
			"name": claimName, "uid": string(claimUID),
			"annotations": map[string]any{
				karpenterPublicIPv4Annotation:     externalIPForClaim,
				karpenterFloatingIPNameAnnotation: floatingIPName,
				karpenterBillingAccountAnnotation: strconv.FormatInt(provider.config.BillingAccountID, 10),
				karpenterNodeNameAnnotation:       node.Name,
			},
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
		internalIP, ok := nodeLoadBalancerNodeInternalIPv4(node)
		if !ok {
			t.Fatalf("Node %s has no private InternalIP for its test identity", node.Name)
		}
		externalIP, ok := nodeLoadBalancerNodeExternalIPv4(node)
		if !ok {
			t.Fatalf("Node %s has no public ExternalIP for its test identity", node.Name)
		}
		ownership, err := json.Marshal(publicNodeLocalVMOwnership{
			Schema: "karpenter.inspace.cloud/v3", Cluster: provider.config.ClusterID,
			NodePool: shard, NodeClaim: claimName, VMName: node.Name,
			FirewallProfile: nodeLoadBalancerFirewallMode, FirewallUUID: baseFirewallUUID,
			NetworkUUID: provider.config.NetworkUUID, BillingAccountID: provider.config.BillingAccountID,
			FloatingIPName: floatingIPName,
		})
		if err != nil {
			t.Fatal(err)
		}
		vmFound := false
		for index := range api.vms {
			if api.vms[index].UUID != identity.UUID {
				continue
			}
			api.vms[index].Name = node.Name
			api.vms[index].Description = string(ownership)
			api.vms[index].BillingAccountID = provider.config.BillingAccountID
			api.vms[index].NetworkUUID = provider.config.NetworkUUID
			api.vms[index].PrivateIPv4 = internalIP
			vmFound = true
		}
		if !vmFound {
			api.vms = append(api.vms, inspace.VM{
				UUID: identity.UUID, Name: node.Name, Description: string(ownership), Status: "running",
				BillingAccountID: provider.config.BillingAccountID, NetworkUUID: provider.config.NetworkUUID,
				PrivateIPv4: internalIP,
			})
		}
		baseIndex := -1
		for index := range api.firewalls {
			if api.firewalls[index].UUID == baseFirewallUUID {
				baseIndex = index
				break
			}
		}
		if baseIndex == -1 {
			rules := make([]inspace.FirewallRule, 0, 6)
			for _, protocol := range []string{"tcp", "udp", "icmp"} {
				rules = append(rules,
					inspace.FirewallRule{
						Protocol: protocol, Direction: "inbound", EndpointSpecType: "ip_prefixes",
						EndpointSpec: []string{"10.0.0.0/24", "10.42.0.0/16"},
					},
					inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"},
				)
			}
			api.firewalls = append(api.firewalls, inspace.Firewall{
				UUID: baseFirewallUUID, DisplayName: "unit-test-default-node-firewall",
				BillingAccountID: provider.config.BillingAccountID, Rules: rules,
			})
			baseIndex = len(api.firewalls) - 1
		}
		if !firewallAssignedToVM(api.firewalls[baseIndex], identity.UUID) {
			api.firewalls[baseIndex].ResourcesAssigned = append(
				api.firewalls[baseIndex].ResourcesAssigned,
				inspace.FirewallResource{ResourceType: "vm", ResourceUUID: identity.UUID},
			)
		}
		found := false
		for index := range api.floatingIPs {
			if api.floatingIPs[index].AssignedTo == identity.UUID {
				api.floatingIPs[index].Name = floatingIPName
				api.floatingIPs[index].Address = externalIP
				api.floatingIPs[index].BillingAccountID = provider.config.BillingAccountID
				api.floatingIPs[index].AssignedToPrivateIP = internalIP
				found = true
				break
			}
		}
		if !found {
			api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{
				Name: floatingIPName, Address: externalIP,
				BillingAccountID: provider.config.BillingAccountID, Type: "public", Enabled: true,
				AssignedTo: identity.UUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: internalIP,
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

func nodeLoadBalancerSafetyMarkDatapathActive(service *corev1.Service, shard string) {
	if service.Annotations == nil {
		service.Annotations = map[string]string{}
	}
	service.Annotations[annotationNodeLoadBalancerDatapathActive] = shard
}

func nodeLoadBalancerSafetyDatapath(service *corev1.Service, shard string) *corev1.Service {
	datapath := desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), shard)
	datapath.UID = types.UID("datapath-" + shortNodeLoadBalancerHash(nodeLoadBalancerServiceIdentity(service)))
	return datapath
}

func nodeLoadBalancerSafetyInvalidFinalizedService(name, uid string) *corev1.Service {
	service := nodeLoadBalancerTestService(name, uid, corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerMode] = "invalid"
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.10"}}
	return service
}
