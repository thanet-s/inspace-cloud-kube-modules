package provider

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

func TestWorkerNodeNameUsesClusterAndKarpenterNodeClaimSuffix(t *testing.T) {
	nodeClaim := &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "general-a1b2c", UID: types.UID("stable-nodeclaim-uid"),
		Labels: map[string]string{karpv1.NodePoolLabelKey: "general"},
	}}
	got, err := workerNodeName("production", nodeClaim)
	if err != nil {
		t.Fatal(err)
	}
	if got != "production-karp-general-a1b2c" {
		t.Fatalf("workerNodeName() = %q", got)
	}
	nodeClaim.UID = types.UID("different-uid")
	if retry, err := workerNodeName("production", nodeClaim); err != nil || retry != got {
		t.Fatalf("worker name must be derived from visible NodeClaim identity, got %q, %v", retry, err)
	}
}

func TestWorkerNodeNameRejectsUnsafeOrUncorrelatedIdentity(t *testing.T) {
	tests := map[string]struct {
		cluster string
		claim   *karpv1.NodeClaim
	}{
		"missing NodePool label":            {cluster: "cluster", claim: &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{Name: "workers-abc"}}},
		"NodeClaim outside NodePool prefix": {cluster: "cluster", claim: &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{Name: "other-abc", Labels: map[string]string{karpv1.NodePoolLabelKey: "workers"}}}},
		"empty random suffix":               {cluster: "cluster", claim: &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{Name: "workers-", Labels: map[string]string{karpv1.NodePoolLabelKey: "workers"}}}},
		"hostname too long":                 {cluster: strings.Repeat("a", 40), claim: &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{Name: "workers-" + strings.Repeat("b", 20), Labels: map[string]string{karpv1.NodePoolLabelKey: "workers"}}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := workerNodeName(test.cluster, test.claim); err == nil {
				t.Fatalf("workerNodeName() = %q, want validation error", got)
			}
		})
	}
}

func TestNewRejectsClusterNameThatCannotBeAHostnameLabel(t *testing.T) {
	nodeClass := providerNodeClass()
	opts := providerOptions(nodeClass)
	opts.ClusterName = "cluster.example"
	if _, err := New(cloudfake.New(), NewStaticResolver(nodeClass), opts); err == nil || !strings.Contains(err.Error(), "DNS-1123 hostname label") {
		t.Fatalf("New() error = %v, want hostname-label validation", err)
	}
}

func TestCreateRejectsUnsafeWorkerNameBeforeCloudMutation(t *testing.T) {
	nodeClass := providerNodeClass()
	cloud := cloudfake.New()
	provider, err := New(cloud, NewStaticResolver(nodeClass), providerOptions(nodeClass))
	if err != nil {
		t.Fatal(err)
	}
	nodeClaim := &karpv1.NodeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "workers-" + strings.Repeat("a", 55), Labels: map[string]string{karpv1.NodePoolLabelKey: "workers"},
	}}
	if _, err := provider.Create(context.Background(), nodeClaim); err == nil {
		t.Fatal("Create() accepted an unsafe or uncorrelated worker name")
	}
	if vms, err := cloud.ListVMs(context.Background(), inspacev1.LocationBangkok, nodeClass.Spec.ClusterName); err != nil || len(vms) != 0 {
		t.Fatalf("invalid name reached cloud mutation: VMs=%#v, err=%v", vms, err)
	}
}

func TestDeleteMalformedProviderIDDoesNotReleaseFinalizer(t *testing.T) {
	nodeClass := providerNodeClass()
	provider, err := New(cloudfake.New(), NewStaticResolver(nodeClass), providerOptions(nodeClass))
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
	provider, err := New(cloudfake.New(), resolver, providerOptions(nodeClass))
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

func TestGetInstanceTypesRejectsNodeClassServicePoolDifferentFromController(t *testing.T) {
	nodeClass := providerNodeClass()
	provider, err := New(cloudfake.New(), NewStaticResolver(nodeClass), Options{
		ClusterName:             nodeClass.Spec.ClusterName,
		DefaultNodeClassName:    nodeClass.Name,
		NetworkUUID:             nodeClass.Spec.NetworkUUID,
		ControlPlaneVIP:         "10.0.0.10",
		PrivateLoadBalancerPool: inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.220", Stop: "10.0.0.235"},
	})
	if err != nil {
		t.Fatal(err)
	}
	nodePool := &karpv1.NodePool{Spec: karpv1.NodePoolSpec{Template: karpv1.NodeClaimTemplate{Spec: karpv1.NodeClaimTemplateSpec{
		NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
	}}}}
	if _, err := provider.GetInstanceTypes(context.Background(), nodePool); !cloudprovider.IsNodeClassNotReadyError(err) {
		t.Fatalf("GetInstanceTypes() error = %v, want NodeClassNotReady", err)
	}
}

func TestGetInstanceTypesRejectsNodeClassNetworkOrVIPDifferentFromController(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*inspacev1.InSpaceNodeClass)
	}{
		{name: "network", mutate: func(nodeClass *inspacev1.InSpaceNodeClass) {
			nodeClass.Spec.NetworkUUID = "33333333-3333-4333-8333-333333333333"
		}},
		{name: "control-plane VIP", mutate: func(nodeClass *inspacev1.InSpaceNodeClass) {
			nodeClass.Spec.RKE2.Server = "https://10.0.0.11:9345"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nodeClass := providerNodeClass()
			opts := providerOptions(nodeClass)
			test.mutate(nodeClass)
			provider, err := New(cloudfake.New(), NewStaticResolver(nodeClass), opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.GetInstanceTypes(context.Background(), nil); !cloudprovider.IsNodeClassNotReadyError(err) {
				t.Fatalf("GetInstanceTypes() error = %v, want NodeClassNotReady", err)
			}
		})
	}
}

func TestGetAndListRejectVMControllerNetworkContractDrift(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	cloud := cloudfake.New()
	vm, err := cloud.CreateVM(ctx, cloudapi.CreateVMRequest{
		IdempotencyKey: "drifted-worker", Name: "drifted-worker", ClusterName: nodeClass.Spec.ClusterName,
		NodeClaimName: "drifted-worker", Location: inspacev1.LocationBangkok,
		NetworkUUID: "33333333-3333-4333-8333-333333333333", ControlPlaneVIP: "10.0.0.11",
		PrivateLoadBalancerPoolStart: nodeClass.Spec.PrivateLoadBalancerPool.Start,
		PrivateLoadBalancerPoolStop:  nodeClass.Spec.PrivateLoadBalancerPool.Stop,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(cloud, NewStaticResolver(nodeClass), providerOptions(nodeClass))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get(ctx, "inspace://bkk01/"+vm.UUID); err == nil {
		t.Fatal("Get() accepted a VM recorded for another controller network/VIP")
	}
	if _, err := provider.List(ctx); err == nil {
		t.Fatal("List() accepted a VM recorded for another controller network/VIP")
	}
}

func TestIsDriftedWhenNodeClassImageChanges(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	resolver := NewStaticResolver(nodeClass)
	provider, err := New(cloudfake.New(), resolver, providerOptions(nodeClass))
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

func TestSSHAccessChangesNodeClassAndBootstrapHashes(t *testing.T) {
	nodeClass := providerNodeClass()
	nodeClassHash := NodeClassHash(nodeClass)
	bootstrapHash := BootstrapHash(nodeClass)

	nodeClass.Spec.SSHUsername = "inspacee2e"
	nodeClass.Spec.SSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea provider@example"
	if NodeClassHash(nodeClass) == nodeClassHash {
		t.Fatal("SSH access change did not change NodeClass hash")
	}
	if BootstrapHash(nodeClass) == bootstrapHash {
		t.Fatal("SSH access change did not change bootstrap hash")
	}
}

func TestRKE2ConfigChangesNodeClassAndBootstrapHashes(t *testing.T) {
	nodeClass := providerNodeClass()
	nodeClassHash := NodeClassHash(nodeClass)
	bootstrapHash := BootstrapHash(nodeClass)

	nodeClass.Spec.RKE2.Server = "https://10.0.0.11:9345"
	if NodeClassHash(nodeClass) == nodeClassHash {
		t.Fatal("RKE2 configuration change did not change NodeClass hash")
	}
	if BootstrapHash(nodeClass) == bootstrapHash {
		t.Fatal("RKE2 configuration change did not change bootstrap hash")
	}
}

func providerNodeClass() *inspacev1.InSpaceNodeClass {
	return &inspacev1.InSpaceNodeClass{
		ObjectMeta: metav1.ObjectMeta{Name: "workers"},
		Spec: inspacev1.InSpaceNodeClassSpec{
			ClusterName:             "provider-test",
			BillingAccountID:        1,
			Location:                inspacev1.LocationBangkok,
			NetworkUUID:             "11111111-1111-4111-8111-111111111111",
			PrivateLoadBalancerPool: inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"},
			ReservePublicIPv4:       true,
			FirewallUUID:            "22222222-2222-4222-8222-222222222222",
			ImageSelector:           inspacev1.ImageSelector{OSName: inspacev1.OSNameUbuntu, OSVersion: inspacev1.OSVersionUbuntu},
			HostPoolSelector:        inspacev1.HostPoolSelector{Class: inspacev1.HostClassAMDEPYC},
			RootDiskGiB:             40,
			RKE2: inspacev1.RKE2Config{
				Version:        "v1.35.6+rke2r1",
				Server:         "https://10.0.0.10:9345",
				TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.RKE2AgentTokenSecretName, Key: inspacev1.RKE2AgentTokenSecretKey},
			},
		},
	}
}

func providerOptions(nodeClass *inspacev1.InSpaceNodeClass) Options {
	vip, _ := nodeClass.Spec.RKE2.ServerVIP()
	return Options{
		ClusterName: nodeClass.Spec.ClusterName, DefaultNodeClassName: nodeClass.Name,
		NetworkUUID: nodeClass.Spec.NetworkUUID, ControlPlaneVIP: vip.String(),
		PrivateLoadBalancerPool: nodeClass.Spec.PrivateLoadBalancerPool,
	}
}
