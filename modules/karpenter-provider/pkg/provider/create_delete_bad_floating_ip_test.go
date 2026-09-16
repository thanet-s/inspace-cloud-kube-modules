package provider

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

func TestCreateDeletesAndRetriesWhenAssignedFloatingIPIsRecentlyBad(t *testing.T) {
	ctx := context.Background()
	nodeClass := readyProviderNodeClass()
	resolver := NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "agent-token")
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	badFloatingIPs := NewMemoryBadFloatingIPStore()
	// The fake cloud always assigns 203.0.113.10; pre-seed it as recently bad.
	if err := badFloatingIPs.RecordBad(ctx, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	opts := providerOptions(nodeClass)
	opts.BadFloatingIPs = badFloatingIPs
	provider, err := New(cloud, resolver, opts)
	if err != nil {
		t.Fatal(err)
	}
	claim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "general-abc", UID: types.UID("claim-uid"), Labels: map[string]string{karpv1.NodePoolLabelKey: "general"}},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
			Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: "In", Values: []string{"general"}},
				{Key: catalog.LabelHostClass, Operator: "In", Values: []string{inspacev1.HostClassAMDEPYC}},
			},
		},
	}
	_, err = provider.Create(ctx, claim)
	if err == nil {
		t.Fatal("Create() succeeded despite a known-bad floating IP; want a retryable error")
	}
	if cloud.lastDeleteIdentity.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("Create() did not delete the VM on the known-bad floating IP: lastDeleteIdentity=%#v", cloud.lastDeleteIdentity)
	}
}

func TestDeleteRecordsBadFloatingIPOnlyWhenNeverRegistered(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()

	run := func(t *testing.T, name string, registered bool) {
		t.Helper()
		cloud := cloudfake.New()
		badFloatingIPs := NewMemoryBadFloatingIPStore()
		opts := providerOptions(nodeClass)
		opts.BadFloatingIPs = badFloatingIPs
		provider, err := New(cloud, NewStaticResolver(nodeClass), opts)
		if err != nil {
			t.Fatal(err)
		}
		vm, err := cloud.CreateVM(ctx, cloudapi.CreateVMRequest{
			IdempotencyKey: name, Name: "cluster-karp-general-" + name, ClusterName: nodeClass.Spec.ClusterName,
			NodeClaimName: name, Location: nodeClass.Spec.Location, BillingAccountID: 42,
			OSName: "ubuntu", OSVersion: "24.04", InstanceType: "is-general-2c-4g", VCPU: 2, MemoryGiB: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		claim := nodeClaimFromVM(vm)
		if registered {
			claim.StatusConditions().SetTrue(karpv1.ConditionTypeRegistered)
		}
		_ = provider.Delete(ctx, claim)
		bad, err := badFloatingIPs.IsRecentlyBad(ctx, vm.PublicIPv4)
		if err != nil {
			t.Fatal(err)
		}
		if registered && bad {
			t.Fatalf("Delete() recorded a floating IP as bad for a NodeClaim that had registered a Node")
		}
		if !registered && !bad {
			t.Fatalf("Delete() did not record a floating IP as bad for a NodeClaim that never registered a Node")
		}
	}

	t.Run("never registered", func(t *testing.T) { run(t, "never-registered", false) })
	t.Run("registered", func(t *testing.T) { run(t, "registered", true) })
}
