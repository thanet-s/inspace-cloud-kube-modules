package provider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

func TestKubernetesResolverUsesOnlyFixedSecretNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = inspacev1.AddToScheme(scheme)
	nodeClass := providerNodeClass()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: nodeClass.Spec.RKE2.TokenSecretRef.Name, Namespace: "other"},
		Data:       map[string][]byte{nodeClass.Spec.RKE2.TokenSecretRef.Key: []byte("must-not-be-read")},
	}
	resolver, err := NewKubernetesResolver(fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodeClass, secret).Build(), "karpenter")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveAgentToken(context.Background(), nodeClass); err == nil {
		t.Fatal("resolver read a token outside its fixed namespace")
	}
}

func TestKubernetesResolverNeverReadsCloudAPISecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = inspacev1.AddToScheme(scheme)
	nodeClass := providerNodeClass()
	nodeClass.Spec.RKE2.TokenSecretRef = inspacev1.SecretKeySelector{Name: "inspace-api", Key: "token"}
	apiSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "inspace-api", Namespace: "karpenter"},
		Data:       map[string][]byte{"token": []byte("cloud-api-credential")},
	}
	resolver, err := NewKubernetesResolver(fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodeClass, apiSecret).Build(), "karpenter")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveAgentToken(context.Background(), nodeClass); err == nil {
		t.Fatal("resolver allowed the cloud API credential Secret as an RKE2 agent token")
	}
}

func TestKubernetesResolverReadsDedicatedRKE2Token(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = inspacev1.AddToScheme(scheme)
	nodeClass := providerNodeClass()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: inspacev1.RKE2AgentTokenSecretName, Namespace: "karpenter"},
		Data:       map[string][]byte{inspacev1.RKE2AgentTokenSecretKey: []byte("rke2-agent-token\n")},
	}
	resolver, err := NewKubernetesResolver(fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodeClass, secret).Build(), "karpenter")
	if err != nil {
		t.Fatal(err)
	}
	token, err := resolver.ResolveAgentToken(context.Background(), nodeClass)
	if err != nil {
		t.Fatal(err)
	}
	if token != "rke2-agent-token" {
		t.Fatalf("resolved token = %q", token)
	}
}
