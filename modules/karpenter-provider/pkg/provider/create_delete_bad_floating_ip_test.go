package provider

import (
	"context"
	"testing"
	"time"

	"github.com/awslabs/operatorpkg/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

// steppedBadFloatingIPStore is a memory store whose clock the test advances.
func steppedBadFloatingIPStore(now *time.Time) *memoryBadFloatingIPStore {
	return &memoryBadFloatingIPStore{bad: map[string]time.Time{}, clock: func() time.Time { return *now }}
}

func TestCreateDeletesAndRetriesWhenAssignedFloatingIPIsRecentlyBad(t *testing.T) {
	ctx := context.Background()
	nodeClass := readyProviderNodeClass()
	resolver := NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "agent-token")
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	badFloatingIPs := steppedBadFloatingIPStore(&now)
	// The fake cloud always assigns 203.0.113.10; pre-seed it as recently bad.
	if err := badFloatingIPs.RecordBad(ctx, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	recordedAt := now
	now = now.Add(10 * 24 * time.Hour)
	opts := providerOptions(nodeClass)
	opts.BadFloatingIPs = badFloatingIPs
	provider, err := New(cloud, resolver, opts)
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }
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
	// The durable create fence is already materialized for this NodeClaim, so a
	// plain retry of the same claim cannot launch again. Karpenter replaces a
	// claim immediately only for an insufficient-capacity launch error.
	if !cloudprovider.IsInsufficientCapacityError(err) {
		t.Fatalf("Create() error = %v, want an insufficient-capacity error so Karpenter replaces the NodeClaim", err)
	}
	if cloud.lastDeleteIdentity.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("Create() did not delete the VM on the known-bad floating IP: lastDeleteIdentity=%#v", cloud.lastDeleteIdentity)
	}
	if got := badFloatingIPs.bad["203.0.113.10"]; !got.Equal(recordedAt) {
		t.Fatalf("Create() refreshed the known-bad floating IP entry to %s, want the original %s", got, recordedAt)
	}
}

func TestDeleteRecordsBadFloatingIPOnlyAfterARegistrationTimeout(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	run := func(t *testing.T, name string, registered status.Condition, wantBad bool) {
		t.Helper()
		cloud := cloudfake.New()
		badFloatingIPs := steppedBadFloatingIPStore(&now)
		opts := providerOptions(nodeClass)
		opts.BadFloatingIPs = badFloatingIPs
		provider, err := New(cloud, NewStaticResolver(nodeClass), opts)
		if err != nil {
			t.Fatal(err)
		}
		provider.now = func() time.Time { return now }
		vm, err := cloud.CreateVM(ctx, cloudapi.CreateVMRequest{
			IdempotencyKey: name, Name: "cluster-karp-general-" + name, ClusterName: nodeClass.Spec.ClusterName,
			NodeClaimName: name, Location: nodeClass.Spec.Location, BillingAccountID: 42,
			OSName: "ubuntu", OSVersion: "24.04", InstanceType: "is-general-2c-4g", VCPU: 2, MemoryGiB: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		claim := nodeClaimFromVM(vm)
		if registered.Type != "" {
			claim.Status.Conditions = []status.Condition{registered}
		}
		_ = provider.Delete(ctx, claim)
		bad, err := badFloatingIPs.IsRecentlyBad(ctx, vm.PublicIPv4)
		if err != nil {
			t.Fatal(err)
		}
		if bad != wantBad {
			t.Fatalf("Delete() recorded floating IP as bad = %t, want %t", bad, wantBad)
		}
	}
	condition := func(value metav1.ConditionStatus, age time.Duration) status.Condition {
		return status.Condition{
			Type: karpv1.ConditionTypeRegistered, Status: value, Reason: "Test",
			LastTransitionTime: metav1.NewTime(now.Add(-age)),
		}
	}

	t.Run("never registered past the registration timeout", func(t *testing.T) {
		run(t, "timed-out", condition(metav1.ConditionUnknown, fastRegistrationTimeout+time.Minute), true)
	})
	t.Run("registered", func(t *testing.T) {
		run(t, "registered", condition(metav1.ConditionTrue, time.Hour), false)
	})
	// A claim removed before any registration timeout could have fired was
	// deleted for another reason, which says nothing about its floating IP.
	t.Run("deleted before the registration timeout", func(t *testing.T) {
		run(t, "early", condition(metav1.ConditionUnknown, time.Minute), false)
	})
	t.Run("registration never observed", func(t *testing.T) {
		run(t, "unobserved", status.Condition{}, false)
	})
}

func TestDeleteDoesNotRefreshAnExistingBadFloatingIPEntry(t *testing.T) {
	ctx := context.Background()
	nodeClass := providerNodeClass()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cloud := cloudfake.New()
	badFloatingIPs := steppedBadFloatingIPStore(&now)
	opts := providerOptions(nodeClass)
	opts.BadFloatingIPs = badFloatingIPs
	provider, err := New(cloud, NewStaticResolver(nodeClass), opts)
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }
	vm, err := cloud.CreateVM(ctx, cloudapi.CreateVMRequest{
		IdempotencyKey: "repeat", Name: "cluster-karp-general-repeat", ClusterName: nodeClass.Spec.ClusterName,
		NodeClaimName: "repeat", Location: nodeClass.Spec.Location, BillingAccountID: 42,
		OSName: "ubuntu", OSVersion: "24.04", InstanceType: "is-general-2c-4g", VCPU: 2, MemoryGiB: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := badFloatingIPs.RecordBad(ctx, vm.PublicIPv4); err != nil {
		t.Fatal(err)
	}
	recordedAt := now
	now = now.Add(20 * 24 * time.Hour)
	claim := nodeClaimFromVM(vm)
	claim.Status.Conditions = []status.Condition{{
		Type: karpv1.ConditionTypeRegistered, Status: metav1.ConditionUnknown, Reason: "Test",
		LastTransitionTime: metav1.NewTime(now.Add(-time.Hour)),
	}}
	_ = provider.Delete(ctx, claim)
	if got := badFloatingIPs.bad[vm.PublicIPv4]; !got.Equal(recordedAt) {
		t.Fatalf("Delete() refreshed the existing bad floating IP entry to %s, want the original %s", got, recordedAt)
	}
}
