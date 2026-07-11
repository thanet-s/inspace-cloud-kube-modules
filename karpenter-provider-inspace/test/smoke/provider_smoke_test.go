package smoke_test

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/karpenter-provider-inspace/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/karpenter-provider-inspace/pkg/catalog"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/karpenter-provider-inspace/pkg/cloud/fake"
	"github.com/thanet-s/inspace-cloud-kube-modules/karpenter-provider-inspace/pkg/provider"
)

func TestFakeProvisioningLifecycleMakesNoNetworkCalls(t *testing.T) {
	ctx := context.Background()
	nodeClass := smokeNodeClass()
	resolver := provider.NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.K3sAgentTokenSecretName, inspacev1.K3sAgentTokenSecretKey, "test-only-token")
	cloud := cloudfake.New()
	cloudProvider, err := provider.New(cloud, resolver, provider.Options{ClusterName: "smoke-cluster", DefaultNodeClassName: nodeClass.Name})
	if err != nil {
		t.Fatal(err)
	}
	nodeClaim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "general-worker", UID: types.UID("nodeclaim-uid-1")},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
			Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
				{Key: karpv1.CapacityTypeLabelKey, Operator: corev1.NodeSelectorOpIn, Values: []string{karpv1.CapacityTypeOnDemand}},
			},
			Resources: karpv1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3"),
				corev1.ResourceMemory: resource.MustParse("5Gi"),
			}},
		},
	}

	created, err := cloudProvider.Create(ctx, nodeClaim)
	if err != nil {
		t.Fatal(err)
	}
	if created.Labels[corev1.LabelInstanceTypeStable] != "is-general-4c-8g" {
		t.Fatalf("unexpected selection %q", created.Labels[corev1.LabelInstanceTypeStable])
	}
	retried, err := cloudProvider.Create(ctx, nodeClaim)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("idempotent create changed provider ID: %s != %s", retried.Status.ProviderID, created.Status.ProviderID)
	}

	got, err := cloudProvider.Get(ctx, created.Status.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("providerID mismatch: %s != %s", got.Status.ProviderID, created.Status.ProviderID)
	}
	listed, err := cloudProvider.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("unexpected list result %#v, %v", listed, err)
	}

	id := strings.TrimPrefix(created.Status.ProviderID, "inspace://bkk01/")
	request, ok := cloud.Request(id)
	if !ok {
		t.Fatalf("fake did not retain create request for %s", id)
	}
	if !request.PublicIPv4 {
		t.Fatal("worker must request a public IPv4 address because InSpace has no managed NAT")
	}
	if request.HostPoolUUID != inspacev1.AMDEPYCHostPoolUUID {
		t.Fatalf("unexpected host pool UUID %q", request.HostPoolUUID)
	}
	if strings.Count(request.CloudInitJSON, "karpenter.sh/unregistered:NoExecute") != 1 {
		t.Fatalf("bootstrap must contain exactly one registration taint\n%s", request.CloudInitJSON)
	}

	if err := cloudProvider.Delete(ctx, created); err != nil {
		t.Fatal(err)
	}
	if _, err := cloudProvider.Get(ctx, created.Status.ProviderID); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("expected not-found after delete, got %v", err)
	}
	if err := cloudProvider.Delete(ctx, created); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("Karpenter delete convergence must return NodeClaimNotFound, got %v", err)
	}
}

func smokeNodeClass() *inspacev1.InSpaceNodeClass {
	nodeClass := &inspacev1.InSpaceNodeClass{
		ObjectMeta: metav1.ObjectMeta{Name: "smoke-amd"},
		Spec: inspacev1.InSpaceNodeClassSpec{
			ClusterName:       "smoke-cluster",
			BillingAccountID:  1,
			Location:          inspacev1.LocationBangkok,
			NetworkUUID:       "11111111-1111-4111-8111-111111111111",
			ReservePublicIPv4: true,
			FirewallUUID:      "22222222-2222-4222-8222-222222222222",
			ImageSelector:     inspacev1.ImageSelector{OSName: inspacev1.OSNameUbuntu, OSVersion: inspacev1.OSVersionUbuntu},
			HostPoolSelector:  inspacev1.HostPoolSelector{Class: inspacev1.HostClassAMDEPYC},
			RootDiskGiB:       40,
			K3s: inspacev1.K3sConfig{
				Version:        "v1.35.6+k3s1",
				Server:         "https://api.smoke.example:6443",
				TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.K3sAgentTokenSecretName, Key: inspacev1.K3sAgentTokenSecretKey},
			},
		},
	}
	nodeClass.Status.ObservedGeneration = nodeClass.Generation
	nodeClass.Status.ObservedSpecHash = provider.NodeClassHash(nodeClass)
	nodeClass.StatusConditions().SetTrue("Ready")
	return nodeClass
}
