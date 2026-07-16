package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestKubernetesCreateFenceTransitionsReservedIssuedMaterializedExactlyOnce(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	baseline := cloudapi.CreateInventory{
		VMs:          []string{"11111111-1111-4111-8111-111111111111"},
		PotentialVMs: []string{"11111111-1111-4111-8111-111111111111"},
		FloatingIPs:  []string{"address:203.0.113.9"},
	}

	fenced, reserved, allowLaunch, err := store.Ensure(ctx, claim, binding, cleanup, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !allowLaunch || reserved.Issued {
		t.Fatalf("initial fence = %#v, allow=%t; want reserved launch authority", reserved, allowLaunch)
	}
	record, err := decodeCreateFence(fenced.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceReserved || !containsString(fenced.Finalizers, CreateFenceFinalizer) {
		t.Fatalf("persisted reserved fence = %#v, err=%v, finalizers=%v", record, err, fenced.Finalizers)
	}
	reservedVM := &cloudapi.VM{
		UUID: "22222222-2222-4222-8222-222222222222", Name: cleanup.VMName,
		ClusterName: cleanup.ClusterName, NodeClaimName: cleanup.NodeClaimName, Location: cleanup.Location,
		BillingAccountID: cleanup.BillingAccountID, FloatingIPName: "fenced-public", PublicIPv4: "203.0.113.10",
	}
	if _, err := store.MarkMaterialized(ctx, fenced, binding, reserved.Token, reservedVM); err == nil {
		t.Fatal("MarkMaterialized() accepted reserved -> materialized without an issued CAS")
	}

	retryClaim, retryFence, exists, err := store.Get(ctx, fenced, binding, cleanup)
	if err != nil || !exists || retryFence.Issued {
		t.Fatalf("Get() = exists=%t fence=%#v err=%v, want reusable reserved preflight", exists, retryFence, err)
	}
	issuedClaim, err := store.Authorize(ctx, retryClaim, binding, retryFence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issuedClaim.Annotations[AnnotationCreateFence])
	if err != nil || issuedRecord.Phase != createFenceIssued || issuedRecord.IssuedAt == nil {
		t.Fatalf("issued readback = %#v, err=%v", issuedRecord, err)
	}
	if _, err := store.Authorize(ctx, issuedClaim, binding, retryFence.Token, cloudapi.CreateAuthorizationPost); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("second Authorize() error = %v, want immutable-attempt pending", err)
	}
	issuedClaim, err = store.RecordCreatedVM(ctx, issuedClaim, binding, retryFence.Token, issuedRecord.IssueID, reservedVM.UUID)
	if err != nil {
		t.Fatal(err)
	}

	vm := reservedVM
	materializedClaim, err := store.MarkMaterialized(ctx, issuedClaim, binding, retryFence.Token, vm)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := decodeCreateFence(materializedClaim.Annotations[AnnotationCreateFence])
	if err != nil || materialized.Phase != createFenceMaterialized || materialized.ObservedVMUUID != vm.UUID || materialized.IssuedAt == nil {
		t.Fatalf("materialized readback = %#v, err=%v", materialized, err)
	}
}

func TestKubernetesCreateFenceCanDurablyRejectOnlyIssuedAttempt(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRejected(ctx, fenced, binding, fence.Token, ""); err == nil {
		t.Fatal("MarkRejected() accepted a reserved attempt")
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.MarkRejected(ctx, issued, binding, fence.Token, issuedRecord.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(rejected.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceRejected || record.IssuedAt == nil || record.ObservedVMUUID != "" || record.CleanupVMUUID != "" {
		t.Fatalf("rejected fence = %#v, err=%v", record, err)
	}
}

func TestKubernetesCreateFenceRejectsIssuedAttemptAfterDeletionBegins(t *testing.T) {
	ctx := context.Background()
	claim := createFenceTestNodeClaim()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim).Build()
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	binding, cleanup := createFenceTestIdentity(claim)
	fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
	if err != nil {
		t.Fatal(err)
	}
	issuedRecord, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	if err := kubeClient.Delete(ctx, issued); err != nil {
		t.Fatal(err)
	}
	rejected, err := store.MarkRejected(ctx, issued, binding, fence.Token, issuedRecord.IssueID)
	if err != nil {
		t.Fatalf("MarkRejected() after deletion began = %v", err)
	}
	record, err := decodeCreateFence(rejected.Annotations[AnnotationCreateFence])
	if err != nil || record.Phase != createFenceRejected || rejected.DeletionTimestamp == nil {
		t.Fatalf("deleting rejected fence = %#v claim=%#v err=%v", record, rejected, err)
	}
}

func TestRollbackAndMaterializationAreMutuallyExclusiveForAnchoredVM(t *testing.T) {
	ctx := context.Background()
	for _, rollbackFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "rollback wins", false: "materialization wins"}[rollbackFirst], func(t *testing.T) {
			claim := createFenceTestNodeClaim()
			store := NewMemoryCreateFenceStore()
			binding, cleanup := createFenceTestIdentity(claim)
			fenced, fence, _, err := store.Ensure(ctx, claim, binding, cleanup, cloudapi.CreateInventory{})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := store.Authorize(ctx, fenced, binding, fence.Token, cloudapi.CreateAuthorizationPost)
			if err != nil {
				t.Fatal(err)
			}
			record, err := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
			if err != nil {
				t.Fatal(err)
			}
			vm := &cloudapi.VM{
				UUID: "22222222-2222-4222-8222-222222222222", Name: cleanup.VMName,
				ClusterName: cleanup.ClusterName, NodeClaimName: cleanup.NodeClaimName, Location: cleanup.Location,
				BillingAccountID: cleanup.BillingAccountID, FloatingIPName: "fenced-public", PublicIPv4: "203.0.113.10",
			}
			anchored, err := store.RecordCreatedVM(ctx, issued, binding, fence.Token, record.IssueID, vm.UUID)
			if err != nil {
				t.Fatal(err)
			}
			if rollbackFirst {
				rolledBack, err := store.ChooseRollback(ctx, anchored, binding, fence.Token, record.IssueID, vm.UUID, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.MarkMaterialized(ctx, rolledBack, binding, fence.Token, vm); err == nil {
					t.Fatal("MarkMaterialized() overwrote an irreversible rollback decision")
				}
				stored, err := decodeCreateFence(rolledBack.Annotations[AnnotationCreateFence])
				if err != nil || stored.RollbackAt == nil || !stored.DependentUnresolved {
					t.Fatalf("rollback state = %#v err=%v", stored, err)
				}
				return
			}
			materialized, err := store.MarkMaterialized(ctx, anchored, binding, fence.Token, vm)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ChooseRollback(ctx, materialized, binding, fence.Token, record.IssueID, vm.UUID, nil); err == nil {
				t.Fatal("ChooseRollback() overwrote a materialized VM")
			}
		})
	}
}

func TestCreateInventoryRejectsPotentialVMOutsideBoundedBaseline(t *testing.T) {
	err := validateCreateInventory(cloudapi.CreateInventory{
		VMs:          []string{"11111111-1111-4111-8111-111111111111"},
		PotentialVMs: []string{"22222222-2222-4222-8222-222222222222"},
	})
	if err == nil {
		t.Fatal("validateCreateInventory() accepted a potential VM absent from the complete baseline")
	}
}

func TestCreateInventoryEncodedBoundLeavesKubernetesAnnotationHeadroom(t *testing.T) {
	identities := make([]string, 800)
	for i := range identities {
		identities[i] = fmt.Sprintf("%04d-%s", i, strings.Repeat("x", 118))
	}
	if err := validateCreateInventory(cloudapi.CreateInventory{FloatingIPs: identities}); err == nil {
		t.Fatalf("validateCreateInventory() accepted an inventory larger than %d encoded bytes", cloudapi.MaxCreateInventoryEncodedBytes)
	}

	safe := cloudapi.CreateInventory{FloatingIPs: identities[:600]}
	if err := validateCreateInventory(safe); err != nil {
		t.Fatalf("safe inventory was rejected: %v", err)
	}
	claim := createFenceTestNodeClaim()
	binding, cleanup := createFenceTestIdentity(claim)
	record, err := newCreateFenceRecord(binding, cleanup, safe, time.Now(), func() (string, error) {
		return "11111111111111111111111111111111", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 128*1024 {
		t.Fatalf("maximum accepted fixture encoded fence is %d bytes, want at least 128 KiB of Kubernetes annotation headroom", len(encoded))
	}
}

func createFenceTestNodeClaim() *karpv1.NodeClaim {
	return &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "general-abc12", UID: types.UID("claim-uid"), Generation: 1,
			Labels:     map[string]string{karpv1.NodePoolLabelKey: "general"},
			Finalizers: []string{karpv1.TerminationFinalizer},
		},
		Spec: karpv1.NodeClaimSpec{NodeClassRef: &karpv1.NodeClassReference{Name: "workers"}},
	}
}

func createFenceTestIdentity(claim *karpv1.NodeClaim) (createFenceBinding, createFenceCleanupIdentity) {
	return createFenceBinding{
			NodeClaimUID: string(claim.UID), IdempotencyKeyHash: createFenceHash(string(claim.UID)),
			RequestHash: createFenceHash("request"), SpecHash: "spec", BootstrapHash: "bootstrap",
		}, createFenceCleanupIdentity{
			ClusterName: "cluster-a", Location: "bkk01", NetworkUUID: "11111111-1111-4111-8111-111111111111",
			ControlPlaneVIP: "10.0.0.10", PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.219",
			FirewallUUID: "33333333-3333-4333-8333-333333333333", FirewallProfile: inspacev1.FirewallProfilePrivateWorker,
			NodeClaimName: claim.Name,
			VMName:        "cluster-a-karp-general-abc12", BillingAccountID: 1, OwnershipKeyHash: cloudapi.OwnershipKeyHash(string(claim.UID)),
		}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
