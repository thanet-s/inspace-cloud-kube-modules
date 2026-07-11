package nodeclass

import (
	"context"
	"testing"

	"github.com/awslabs/operatorpkg/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/apis/v1alpha1"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/cloud/fake"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/provider"
)

func TestReconcileMarksReadyAfterSecretAndHostPoolValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := inspacev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	nodeClass := readyNodeClass()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: inspacev1.K3sAgentTokenSecretName, Namespace: "karpenter"}, Data: map[string][]byte{inspacev1.K3sAgentTokenSecretKey: []byte("secret")}}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(nodeClass).WithObjects(nodeClass, secret).Build()
	resolver, err := provider.NewKubernetesResolver(kubeClient, "karpenter")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(kubeClient, resolver, cloudfake.New(), "test-cluster")
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
}

func readyNodeClass() *inspacev1.InSpaceNodeClass {
	return &inspacev1.InSpaceNodeClass{ObjectMeta: metav1.ObjectMeta{Name: "workers", Generation: 3}, Spec: inspacev1.InSpaceNodeClassSpec{
		ClusterName: "test-cluster", BillingAccountID: 1, Location: inspacev1.LocationBangkok,
		NetworkUUID:       "11111111-1111-4111-8111-111111111111",
		ReservePublicIPv4: true,
		FirewallUUID:      "22222222-2222-4222-8222-222222222222",
		ImageSelector:     inspacev1.ImageSelector{OSName: inspacev1.OSNameUbuntu, OSVersion: inspacev1.OSVersionUbuntu},
		HostPoolSelector:  inspacev1.HostPoolSelector{Class: inspacev1.HostClassIntelScalable}, RootDiskGiB: 40,
		K3s: inspacev1.K3sConfig{Version: "v1.35.6+k3s1", Server: "https://api.test.example:6443", TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.K3sAgentTokenSecretName, Key: inspacev1.K3sAgentTokenSecretKey}},
	}}
}

func clientKey(name string) client.ObjectKey { return client.ObjectKey{Name: name} }
