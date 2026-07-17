package nodeclass

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/awslabs/operatorpkg/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/provider"
)

type recordingValidator struct {
	calls            int
	billingAccountID int64
	controlPlaneVIP  string
	poolStart        string
	poolStop         string
	hostPoolUUIDs    []string
	failHostPool     string
}

func (v *recordingValidator) ValidateNodeClass(_ context.Context, _ string, billingAccountID int64, _, controlPlaneVIP, poolStart, poolStop, hostPoolUUID, _ string) error {
	v.calls++
	v.billingAccountID = billingAccountID
	v.controlPlaneVIP = controlPlaneVIP
	v.poolStart = poolStart
	v.poolStop = poolStop
	v.hostPoolUUIDs = append(v.hostPoolUUIDs, hostPoolUUID)
	if hostPoolUUID == v.failHostPool {
		return fmt.Errorf("host pool %s is unavailable", hostPoolUUID)
	}
	return nil
}

func TestReconcileMarksReadyAfterSecretAndBothHostPoolValidations(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := inspacev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	nodeClass := readyNodeClass()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: inspacev1.RKE2AgentTokenSecretName, Namespace: "karpenter"}, Data: map[string][]byte{inspacev1.RKE2AgentTokenSecretKey: []byte("secret")}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(nodeClass).WithObjects(nodeClass, secret).Build()
	resolver, err := provider.NewKubernetesResolver(kubeClient, "karpenter")
	if err != nil {
		t.Fatal(err)
	}
	validator := &recordingValidator{}
	controller, err := NewController(
		kubeClient, resolver, validator, "test-cluster", nodeClass.Spec.NetworkUUID, "10.0.0.10", nodeClass.Spec.PrivateLoadBalancerPool,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ReconcileByName(context.Background(), nodeClass.Name); err != nil {
		t.Fatal(err)
	}
	var got inspacev1.InSpaceNodeClass
	if err := kubeClient.Get(context.Background(), clientKey(nodeClass.Name), &got); err != nil {
		t.Fatal(err)
	}
	if !got.StatusConditions(status.WithObservedOnly()).IsTrue(status.ConditionReady) || got.Status.ObservedImageID != "ubuntu@24.04" || got.Status.ObservedSpecHash == "" {
		t.Fatalf("unexpected status %#v", got.Status)
	}
	wantHostPoolUUIDs := []string{inspacev1.IntelScalableHostPoolUUID, inspacev1.AMDEPYCHostPoolUUID}
	if !slices.Equal(got.Status.HostPoolUUIDs, wantHostPoolUUIDs) {
		t.Fatalf("status hostPoolUUIDs=%v, want %v", got.Status.HostPoolUUIDs, wantHostPoolUUIDs)
	}
	ready := got.StatusConditions(status.WithObservedOnly()).Get(status.ConditionReady)
	if ready == nil || ready.Message != "Private RKE2 supervisor VIP and Service pool, InSpace VPC, Cilium native-routing firewall, Intel and AMD host pools, and RKE2 token are ready" {
		t.Fatalf("Ready condition does not describe validated native-routing infrastructure: %#v", ready)
	}
	if validator.calls != 2 || validator.billingAccountID != nodeClass.Spec.BillingAccountID || validator.controlPlaneVIP != "10.0.0.10" || validator.poolStart != "10.0.0.200" || validator.poolStop != "10.0.0.219" || !slices.Equal(validator.hostPoolUUIDs, wantHostPoolUUIDs) {
		t.Fatalf("cloud validation calls=%d supervisorVIP=%q pool=%s-%s", validator.calls, validator.controlPlaneVIP, validator.poolStart, validator.poolStop)
	}
}

func TestReconcileFailsClosedWhenEitherMappedHostPoolIsUnavailable(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := inspacev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	nodeClass := readyNodeClass()
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(nodeClass).WithObjects(nodeClass).Build()
	resolver := provider.NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "agent-token")
	validator := &recordingValidator{failHostPool: inspacev1.AMDEPYCHostPoolUUID}
	controller, err := NewController(
		kubeClient, resolver, validator, "test-cluster", nodeClass.Spec.NetworkUUID, "10.0.0.10", nodeClass.Spec.PrivateLoadBalancerPool,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.ReconcileByName(context.Background(), nodeClass.Name)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != retryAfter {
		t.Fatalf("requeueAfter=%s, want %s", result.RequeueAfter, retryAfter)
	}
	var got inspacev1.InSpaceNodeClass
	if err := kubeClient.Get(context.Background(), clientKey(nodeClass.Name), &got); err != nil {
		t.Fatal(err)
	}
	ready := got.StatusConditions(status.WithObservedOnly()).Get(status.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || !strings.Contains(ready.Message, "validating amd-epyc host pool "+inspacev1.AMDEPYCHostPoolUUID) {
		t.Fatalf("Ready condition=%#v, want exact AMD mapping failure", ready)
	}
	if len(got.Status.HostPoolUUIDs) != 0 || got.Status.ObservedSpecHash != "" {
		t.Fatalf("failed readiness retained authoritative status: %#v", got.Status)
	}
	wantCalls := []string{inspacev1.IntelScalableHostPoolUUID, inspacev1.AMDEPYCHostPoolUUID}
	if !slices.Equal(validator.hostPoolUUIDs, wantCalls) {
		t.Fatalf("validated host pools=%v, want exact mapped sequence %v", validator.hostPoolUUIDs, wantCalls)
	}
}

func TestReconcileRejectsNodeClassServicePoolDifferentFromController(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := inspacev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	nodeClass := readyNodeClass()
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(nodeClass).WithObjects(nodeClass).Build()
	validator := &recordingValidator{}
	controller, err := NewController(
		kubeClient,
		provider.NewStaticResolver(nodeClass),
		validator,
		"test-cluster",
		nodeClass.Spec.NetworkUUID,
		"10.0.0.10",
		inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.220", Stop: "10.0.0.235"},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.ReconcileByName(context.Background(), nodeClass.Name)
	if err != nil {
		t.Fatal(err)
	}
	if result.Requeue || result.RequeueAfter != 0 {
		t.Fatalf("static controller-pool mismatch unexpectedly requeued: %#v", result)
	}
	var got inspacev1.InSpaceNodeClass
	if err := kubeClient.Get(context.Background(), clientKey(nodeClass.Name), &got); err != nil {
		t.Fatal(err)
	}
	ready := got.StatusConditions(status.WithObservedOnly()).Get(status.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || !strings.Contains(ready.Message, "does not match controller pool") {
		t.Fatalf("Ready condition = %#v, want controller-pool mismatch", ready)
	}
	if validator.calls != 0 {
		t.Fatalf("mismatched Service pool reached cloud validation: %d calls", validator.calls)
	}
}

func TestReconcileRejectsNodeClassNetworkOrControlPlaneVIPDifferentFromController(t *testing.T) {
	for _, test := range []struct {
		name              string
		controllerNetwork string
		controllerVIP     string
		wantMessage       string
	}{
		{name: "network", controllerNetwork: "33333333-3333-4333-8333-333333333333", controllerVIP: "10.0.0.10", wantMessage: "does not match controller network"},
		{name: "control-plane VIP", controllerNetwork: "11111111-1111-4111-8111-111111111111", controllerVIP: "10.0.0.11", wantMessage: "does not match controller control-plane VIP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := inspacev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			nodeClass := readyNodeClass()
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(nodeClass).WithObjects(nodeClass).Build()
			validator := &recordingValidator{}
			controller, err := NewController(
				kubeClient, provider.NewStaticResolver(nodeClass), validator, "test-cluster",
				test.controllerNetwork, test.controllerVIP, nodeClass.Spec.PrivateLoadBalancerPool,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.ReconcileByName(context.Background(), nodeClass.Name); err != nil {
				t.Fatal(err)
			}
			var got inspacev1.InSpaceNodeClass
			if err := kubeClient.Get(context.Background(), clientKey(nodeClass.Name), &got); err != nil {
				t.Fatal(err)
			}
			ready := got.StatusConditions(status.WithObservedOnly()).Get(status.ConditionReady)
			if ready == nil || ready.Status != metav1.ConditionFalse || !strings.Contains(ready.Message, test.wantMessage) {
				t.Fatalf("Ready condition = %#v, want %q", ready, test.wantMessage)
			}
			if validator.calls != 0 {
				t.Fatalf("mismatched controller identity reached cloud validation: %d calls", validator.calls)
			}
		})
	}
}

func readyNodeClass() *inspacev1.InSpaceNodeClass {
	return &inspacev1.InSpaceNodeClass{ObjectMeta: metav1.ObjectMeta{Name: "workers", Generation: 3}, Spec: inspacev1.InSpaceNodeClassSpec{
		ClusterName: "test-cluster", BillingAccountID: 1, Location: inspacev1.LocationBangkok,
		NetworkUUID:             "11111111-1111-4111-8111-111111111111",
		PrivateLoadBalancerPool: inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"},
		ReservePublicIPv4:       true,
		FirewallUUID:            "22222222-2222-4222-8222-222222222222",
		ImageSelector:           inspacev1.ImageSelector{OSName: inspacev1.OSNameUbuntu, OSVersion: inspacev1.OSVersionUbuntu},
		RootDiskGiB:             40,
		RKE2:                    inspacev1.RKE2Config{Version: "v1.35.6+rke2r1", Server: "https://10.0.0.10:9345", TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.RKE2AgentTokenSecretName, Key: inspacev1.RKE2AgentTokenSecretKey}},
		BootstrapCache:          inspacev1.BootstrapCacheSpec{DirectDownload: true},
	}}
}

func clientKey(name string) client.ObjectKey { return client.ObjectKey{Name: name} }
