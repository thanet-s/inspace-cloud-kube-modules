package provider

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

func TestDeleteMalformedProviderIDDoesNotReleaseFinalizer(t *testing.T) {
	nodeClass := providerNodeClass()
	provider, err := New(cloudfake.New(), NewStaticResolver(nodeClass), Options{ClusterName: nodeClass.Spec.ClusterName, DefaultNodeClassName: nodeClass.Name})
	if err != nil {
		t.Fatal(err)
	}
	err = provider.Delete(context.Background(), &karpv1.NodeClaim{Status: karpv1.NodeClaimStatus{ProviderID: "malformed"}})
	if err == nil || cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("malformed provider ID must be a retryable hard error, got %v", err)
	}
}

func TestGetInstanceTypesUsesNodeClassHostPool(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	resolver := NewStaticResolver(nodeClass)
	provider, err := New(cloudfake.New(), resolver, Options{ClusterName: nodeClass.Spec.ClusterName, DefaultNodeClassName: nodeClass.Name})
	if err != nil {
		t.Fatal(err)
	}
	nodePool := &karpv1.NodePool{Spec: karpv1.NodePoolSpec{Template: karpv1.NodeClaimTemplate{Spec: karpv1.NodeClaimTemplateSpec{
		NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
	}}}}
	instanceTypes, err := provider.GetInstanceTypes(ctx, nodePool)
	if err != nil {
		t.Fatal(err)
	}
	if len(instanceTypes) != 24 {
		t.Fatalf("expected 24 instance types, got %d", len(instanceTypes))
	}
}

func TestIsDriftedWhenNodeClassImageChanges(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	resolver := NewStaticResolver(nodeClass)
	provider, err := New(cloudfake.New(), resolver, Options{ClusterName: nodeClass.Spec.ClusterName, DefaultNodeClassName: nodeClass.Name})
	if err != nil {
		t.Fatal(err)
	}
	nodeClaim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationNodeClassHash: NodeClassHash(nodeClass)}},
		Spec:       karpv1.NodeClaimSpec{NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name}},
		Status:     karpv1.NodeClaimStatus{ImageID: nodeClass.Spec.ImageSelector.ID()},
	}
	if reason, err := provider.IsDrifted(ctx, nodeClaim); err != nil || reason != "" {
		t.Fatalf("fresh NodeClaim unexpectedly drifted: %q, %v", reason, err)
	}
	updated := nodeClass.DeepCopy()
	updated.Spec.ImageSelector.OSVersion = "24.10"
	resolver.SetNodeClass(updated)
	if reason, err := provider.IsDrifted(ctx, nodeClaim); err != nil || reason != DriftReasonNodeClass {
		t.Fatalf("expected %q, got %q, %v", DriftReasonNodeClass, reason, err)
	}
}

func providerNodeClass() *inspacev1.InSpaceNodeClass {
	return &inspacev1.InSpaceNodeClass{
		ObjectMeta: metav1.ObjectMeta{Name: "workers"},
		Spec: inspacev1.InSpaceNodeClassSpec{
			ClusterName:       "provider-test",
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
				Server:         "https://api.provider-test.example:6443",
				TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.K3sAgentTokenSecretName, Key: inspacev1.K3sAgentTokenSecretKey},
			},
		},
	}
}
