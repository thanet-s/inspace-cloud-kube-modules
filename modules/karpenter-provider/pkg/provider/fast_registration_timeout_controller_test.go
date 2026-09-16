package provider

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	"github.com/awslabs/operatorpkg/status"
	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

func fastRegistrationTimeoutTestClaim(t *testing.T, registeredStatus metav1.ConditionStatus, registeredAt time.Time) *karpv1.NodeClaim {
	t.Helper()
	claim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "fast-timeout-claim", UID: types.UID("fast-timeout-uid")},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: "test-nodeclass"},
		},
	}
	if registeredStatus != "" {
		claim.Status.Conditions = []status.Condition{{
			Type: karpv1.ConditionTypeRegistered, Status: registeredStatus,
			LastTransitionTime: metav1.NewTime(registeredAt), Reason: "Test", Message: "test",
		}}
	}
	return claim
}

func fastRegistrationTimeoutClient(t *testing.T, claim *karpv1.NodeClaim) *fake.ClientBuilder {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(kubescheme.Scheme).WithObjects(claim)
}

func TestFastRegistrationTimeoutDeletesOnlyWhenSkipOSUpgradeAndTimedOut(t *testing.T) {
	ctx := context.Background()
	registeredAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name           string
		elapsed        time.Duration
		skipOSUpgrade  bool
		wantDeleted    bool
		wantRequeueGT0 bool
	}{
		{name: "timed out and skips OS upgrade", elapsed: 10 * time.Minute, skipOSUpgrade: true, wantDeleted: true},
		{name: "timed out but keeps OS upgrade", elapsed: 10 * time.Minute, skipOSUpgrade: false, wantDeleted: false},
		{name: "skips OS upgrade but not yet timed out", elapsed: 3 * time.Minute, skipOSUpgrade: true, wantDeleted: false, wantRequeueGT0: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			claim := fastRegistrationTimeoutTestClaim(t, metav1.ConditionFalse, registeredAt)
			kubeClient := fastRegistrationTimeoutClient(t, claim).Build()
			nodeClass := &inspacev1.InSpaceNodeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "test-nodeclass"},
				Spec:       inspacev1.InSpaceNodeClassSpec{RKE2: inspacev1.RKE2Config{SkipOSUpgrade: testCase.skipOSUpgrade}},
			}
			resolver := NewStaticResolver(nodeClass)
			controllerUnderTest, err := NewFastRegistrationTimeoutController(kubeClient, kubeClient, resolver)
			if err != nil {
				t.Fatal(err)
			}
			controllerUnderTest.clock = func() time.Time { return registeredAt.Add(testCase.elapsed) }

			result, err := controllerUnderTest.Reconcile(ctx, claim.DeepCopy())
			if err != nil {
				t.Fatal(err)
			}
			var readback karpv1.NodeClaim
			getErr := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback)
			deleted := getErr != nil
			if deleted != testCase.wantDeleted {
				t.Fatalf("deleted=%v, want %v (get error=%v)", deleted, testCase.wantDeleted, getErr)
			}
			if testCase.wantRequeueGT0 && result.RequeueAfter <= 0 {
				t.Fatalf("RequeueAfter=%v, want > 0", result.RequeueAfter)
			}
		})
	}
}

func TestFastRegistrationTimeoutIgnoresRegisteredOrDeletingClaims(t *testing.T) {
	ctx := context.Background()
	registeredAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nodeClass := &inspacev1.InSpaceNodeClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-nodeclass"},
		Spec:       inspacev1.InSpaceNodeClassSpec{RKE2: inspacev1.RKE2Config{SkipOSUpgrade: true}},
	}
	resolver := NewStaticResolver(nodeClass)

	t.Run("already registered", func(t *testing.T) {
		claim := fastRegistrationTimeoutTestClaim(t, metav1.ConditionTrue, registeredAt)
		kubeClient := fastRegistrationTimeoutClient(t, claim).Build()
		controllerUnderTest, err := NewFastRegistrationTimeoutController(kubeClient, kubeClient, resolver)
		if err != nil {
			t.Fatal(err)
		}
		controllerUnderTest.clock = func() time.Time { return registeredAt.Add(time.Hour) }
		if _, err := controllerUnderTest.Reconcile(ctx, claim.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		var readback karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); err != nil {
			t.Fatalf("registered NodeClaim was deleted: %v", err)
		}
	})

	t.Run("no Registered condition yet", func(t *testing.T) {
		claim := fastRegistrationTimeoutTestClaim(t, "", time.Time{})
		kubeClient := fastRegistrationTimeoutClient(t, claim).Build()
		controllerUnderTest, err := NewFastRegistrationTimeoutController(kubeClient, kubeClient, resolver)
		if err != nil {
			t.Fatal(err)
		}
		controllerUnderTest.clock = func() time.Time { return registeredAt.Add(time.Hour) }
		if _, err := controllerUnderTest.Reconcile(ctx, claim.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		var readback karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); err != nil {
			t.Fatalf("uninitialized NodeClaim was deleted: %v", err)
		}
	})

	t.Run("already deleting", func(t *testing.T) {
		claim := fastRegistrationTimeoutTestClaim(t, metav1.ConditionFalse, registeredAt)
		controllerutilFinalizer := "inspace.cloud/test-finalizer"
		claim.Finalizers = append(claim.Finalizers, controllerutilFinalizer)
		now := metav1.NewTime(registeredAt.Add(time.Hour))
		claim.DeletionTimestamp = &now
		kubeClient := fastRegistrationTimeoutClient(t, claim).Build()
		controllerUnderTest, err := NewFastRegistrationTimeoutController(kubeClient, kubeClient, resolver)
		if err != nil {
			t.Fatal(err)
		}
		controllerUnderTest.clock = func() time.Time { return registeredAt.Add(2 * time.Hour) }
		if _, err := controllerUnderTest.Reconcile(ctx, claim.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		var readback karpv1.NodeClaim
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); err != nil {
			t.Fatalf("already-deleting NodeClaim disappeared unexpectedly: %v", err)
		}
	})
}
