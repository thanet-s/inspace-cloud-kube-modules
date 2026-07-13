package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/awslabs/operatorpkg/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"
	"sigs.k8s.io/karpenter/pkg/scheduling"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/providerid"
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

func TestDeleteThreadsDurableFloatingIPIdentityFromNodeClaimAnnotations(t *testing.T) {
	nodeClass := providerNodeClass()
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	provider, err := New(cloud, NewStaticResolver(nodeClass), providerOptions(nodeClass))
	if err != nil {
		t.Fatal(err)
	}
	vm, err := cloud.CreateVM(context.Background(), cloudapi.CreateVMRequest{
		IdempotencyKey: "delete-identity", Name: "cluster-karp-general-abc", ClusterName: nodeClass.Spec.ClusterName,
		NodeClaimName: "general-abc", Location: nodeClass.Spec.Location, BillingAccountID: 42,
		OSName: "ubuntu", OSVersion: "24.04", InstanceType: "is-general-2c-4g", VCPU: 2, MemoryGiB: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := nodeClaimFromVM(vm)
	if claim.Annotations[AnnotationBillingAccount] != "42" {
		t.Fatalf("NodeClaim billing annotation = %q, want 42", claim.Annotations[AnnotationBillingAccount])
	}
	if err := provider.Delete(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	want := cloudapi.DeleteVMIdentity{FloatingIPName: vm.FloatingIPName, PublicIPv4: vm.PublicIPv4, BillingAccountID: 42}
	if cloud.lastDeleteIdentity != want {
		t.Fatalf("DeleteVM identity = %#v, want %#v", cloud.lastDeleteIdentity, want)
	}
}

type recordingDeleteCloud struct {
	*cloudfake.Cloud
	lastDeleteIdentity cloudapi.DeleteVMIdentity
}

func (c *recordingDeleteCloud) DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string, identity cloudapi.DeleteVMIdentity) error {
	c.lastDeleteIdentity = identity
	return c.Cloud.DeleteVM(ctx, location, uuid, clusterName, nodeClaimName, identity)
}

func TestGetInstanceTypesAdvertisesBothHostClassesAndNumericCapacity(t *testing.T) {
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
	for _, instanceType := range instanceTypes {
		if len(instanceType.Offerings) != 2 {
			t.Fatalf("%s offerings=%d, want Intel and AMD", instanceType.Name, len(instanceType.Offerings))
		}
		if instanceType.Requirements.Get(catalog.LabelInstanceCPU) == nil || instanceType.Requirements.Get(catalog.LabelInstanceMemory) == nil {
			t.Fatalf("%s lacks numeric CPU/memory requirements", instanceType.Name)
		}
	}
}

func TestSelectInstanceTypeSupportsNumericBoundsAndHostClassOffering(t *testing.T) {
	instanceTypes, err := catalog.New(catalog.Options{Location: inspacev1.LocationBangkok, RootDiskGiB: 100})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		requirements []karpv1.NodeSelectorRequirementWithMinValues
		wantType     string
	}{
		{
			name: "exclusive CPU bounds",
			requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
				{Key: catalog.LabelInstanceCPU, Operator: corev1.NodeSelectorOpGt, Values: []string{"2"}},
				{Key: catalog.LabelInstanceCPU, Operator: corev1.NodeSelectorOpLt, Values: []string{"6"}},
				{Key: catalog.LabelHostClass, Operator: corev1.NodeSelectorOpIn, Values: []string{inspacev1.HostClassAMDEPYC}},
			},
			wantType: "is-general-4c-8g",
		},
		{
			name: "inclusive memory bounds",
			requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
				{Key: catalog.LabelInstanceMemory, Operator: karpv1.NodeSelectorOpGte, Values: []string{"8192"}},
				{Key: catalog.LabelInstanceMemory, Operator: karpv1.NodeSelectorOpLte, Values: []string{"8192"}},
				{Key: catalog.LabelHostClass, Operator: corev1.NodeSelectorOpIn, Values: []string{inspacev1.HostClassAMDEPYC}},
			},
			wantType: "is-general-4c-8g",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claim := &karpv1.NodeClaim{Spec: karpv1.NodeClaimSpec{Requirements: test.requirements}}
			instanceType, offering, err := selectInstanceType(claim, instanceTypes)
			if err != nil {
				t.Fatal(err)
			}
			if instanceType.Name != test.wantType {
				t.Fatalf("selected %s, want %s", instanceType.Name, test.wantType)
			}
			hostClass, hostPoolUUID, err := hostPoolForOffering(offering)
			if err != nil {
				t.Fatal(err)
			}
			if hostClass != inspacev1.HostClassAMDEPYC || hostPoolUUID != inspacev1.AMDEPYCHostPoolUUID {
				t.Fatalf("selected host class/pool=%s/%s", hostClass, hostPoolUUID)
			}
		})
	}
}

func TestSelectInstanceTypeAllowsMixedHostClassesInOneNodePool(t *testing.T) {
	instanceTypes, err := catalog.New(catalog.Options{Location: inspacev1.LocationBangkok, RootDiskGiB: 100})
	if err != nil {
		t.Fatal(err)
	}
	claim := &karpv1.NodeClaim{Spec: karpv1.NodeClaimSpec{Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
		{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
		{Key: catalog.LabelInstanceCPU, Operator: karpv1.NodeSelectorOpGte, Values: []string{"4"}},
		{Key: catalog.LabelHostClass, Operator: corev1.NodeSelectorOpIn, Values: []string{inspacev1.HostClassIntelScalable, inspacev1.HostClassAMDEPYC}},
	}}}
	instanceType, offering, err := selectInstanceType(claim, instanceTypes)
	if err != nil {
		t.Fatal(err)
	}
	if instanceType.Name != "is-general-4c-8g" {
		t.Fatalf("selected %s, want is-general-4c-8g", instanceType.Name)
	}
	hostClass, hostPoolUUID, err := hostPoolForOffering(offering)
	if err != nil {
		t.Fatal(err)
	}
	wantHostPoolUUID, supported := inspacev1.HostPoolUUIDForClass(hostClass)
	if !supported || hostPoolUUID != wantHostPoolUUID {
		t.Fatalf("mixed pool selected inconsistent host class/pool=%s/%s", hostClass, hostPoolUUID)
	}
}

func TestHostPoolForOfferingRejectsAmbiguousOrUnknownIdentity(t *testing.T) {
	tests := map[string]*cloudprovider.Offering{
		"nil":     nil,
		"missing": {Requirements: scheduling.NewRequirements()},
		"ambiguous": {Requirements: scheduling.NewRequirements(
			scheduling.NewRequirement(catalog.LabelHostClass, corev1.NodeSelectorOpIn, inspacev1.HostClassIntelScalable, inspacev1.HostClassAMDEPYC),
		)},
		"unknown": {Requirements: scheduling.NewRequirements(
			scheduling.NewRequirement(catalog.LabelHostClass, corev1.NodeSelectorOpIn, "future-host"),
		)},
	}
	for name, offering := range tests {
		t.Run(name, func(t *testing.T) {
			if hostClass, hostPoolUUID, err := hostPoolForOffering(offering); err == nil {
				t.Fatalf("resolved unsafe offering to %s/%s", hostClass, hostPoolUUID)
			}
		})
	}
}

func TestCreateAndReadbackPreserveOfferingAndNumericIdentity(t *testing.T) {
	ctx := context.Background()
	nodeClass := readyProviderNodeClass()
	resolver := NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "agent-token")
	cloud := cloudfake.New()
	provider, err := New(cloud, resolver, providerOptions(nodeClass))
	if err != nil {
		t.Fatal(err)
	}
	claim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "general-ab12c", UID: types.UID("claim-uid"), Labels: map[string]string{karpv1.NodePoolLabelKey: "general"}},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
			Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
				{Key: catalog.LabelHostClass, Operator: corev1.NodeSelectorOpIn, Values: []string{inspacev1.HostClassAMDEPYC}},
				{Key: catalog.LabelInstanceCPU, Operator: karpv1.NodeSelectorOpGte, Values: []string{"4"}},
				{Key: catalog.LabelInstanceMemory, Operator: karpv1.NodeSelectorOpGte, Values: []string{"8192"}},
			},
			Resources: karpv1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3")}},
		},
	}
	created, err := provider.Create(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	id, err := providerid.Parse(created.Status.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := cloud.Request(id.VMUUID)
	if !ok {
		t.Fatal("cloud did not record launch request")
	}
	if request.HostClass != inspacev1.HostClassAMDEPYC || request.HostPoolUUID != inspacev1.AMDEPYCHostPoolUUID || request.InstanceType != "is-general-4c-8g" {
		t.Fatalf("launch identity=%s/%s/%s", request.HostClass, request.HostPoolUUID, request.InstanceType)
	}
	assertCapacityLabels := func(t *testing.T, labels map[string]string) {
		t.Helper()
		want := map[string]string{
			catalog.LabelHostClass:      inspacev1.HostClassAMDEPYC,
			catalog.LabelInstanceCPU:    "4",
			catalog.LabelInstanceMemory: "8192",
			catalog.LabelFamily:         "general",
			catalog.LabelLocation:       inspacev1.LocationBangkok,
		}
		for key, value := range want {
			if labels[key] != value {
				t.Fatalf("label %s=%q, want %q", key, labels[key], value)
			}
		}
	}
	assertCapacityLabels(t, created.Labels)
	read, err := provider.Get(ctx, created.Status.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	assertCapacityLabels(t, read.Labels)
	listed, err := provider.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("List() returned %d NodeClaims", len(listed))
	}
	assertCapacityLabels(t, listed[0].Labels)
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
			RootDiskGiB:             40,
			RKE2: inspacev1.RKE2Config{
				Version:        "v1.35.6+rke2r1",
				Server:         "https://10.0.0.10:9345",
				TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.RKE2AgentTokenSecretName, Key: inspacev1.RKE2AgentTokenSecretKey},
			},
		},
	}
}

func readyProviderNodeClass() *inspacev1.InSpaceNodeClass {
	nodeClass := providerNodeClass()
	nodeClass.Generation = 1
	nodeClass.Status.ObservedGeneration = nodeClass.Generation
	nodeClass.Status.ObservedSpecHash = NodeClassHash(nodeClass)
	nodeClass.StatusConditions().SetTrueWithReason(status.ConditionReady, "NodeClassReady", "ready for provider test")
	return nodeClass
}

func providerOptions(nodeClass *inspacev1.InSpaceNodeClass) Options {
	vip, _ := nodeClass.Spec.RKE2.ServerVIP()
	return Options{
		ClusterName: nodeClass.Spec.ClusterName, DefaultNodeClassName: nodeClass.Name,
		NetworkUUID: nodeClass.Spec.NetworkUUID, ControlPlaneVIP: vip.String(),
		PrivateLoadBalancerPool: nodeClass.Spec.PrivateLoadBalancerPool,
	}
}
