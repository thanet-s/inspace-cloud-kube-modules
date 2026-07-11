package provider

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

// KubernetesResolver reads cluster-scoped NodeClasses and agent tokens from a
// single, controller-configured namespace. It intentionally does not let a
// NodeClass select arbitrary Secret namespaces.
type KubernetesResolver struct {
	client          client.Reader
	secretNamespace string
}

func NewKubernetesResolver(kubeClient client.Reader, secretNamespace string) (*KubernetesResolver, error) {
	if kubeClient == nil || secretNamespace == "" {
		return nil, fmt.Errorf("Kubernetes client and secret namespace are required")
	}
	return &KubernetesResolver{client: kubeClient, secretNamespace: secretNamespace}, nil
}

func (r *KubernetesResolver) GetNodeClass(ctx context.Context, name string) (*inspacev1.InSpaceNodeClass, error) {
	var nodeClass inspacev1.InSpaceNodeClass
	if err := r.client.Get(ctx, types.NamespacedName{Name: name}, &nodeClass); err != nil {
		return nil, fmt.Errorf("getting InSpaceNodeClass %q: %w", name, err)
	}
	return &nodeClass, nil
}

func (r *KubernetesResolver) ResolveAgentToken(ctx context.Context, nodeClass *inspacev1.InSpaceNodeClass) (string, error) {
	ref := nodeClass.Spec.K3s.TokenSecretRef
	if ref.Name != inspacev1.K3sAgentTokenSecretName || ref.Key != inspacev1.K3sAgentTokenSecretKey {
		return "", fmt.Errorf("agent token must use dedicated Secret %q key %q", inspacev1.K3sAgentTokenSecretName, inspacev1.K3sAgentTokenSecretKey)
	}
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: r.secretNamespace, Name: ref.Name}
	if err := r.client.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("getting K3s agent token Secret %s: %w", key.String(), err)
	}
	token := string(secret.Data[ref.Key])
	if token == "" {
		return "", fmt.Errorf("K3s agent token Secret %s has no non-empty %q key", key.String(), ref.Key)
	}
	return token, nil
}

// NodeClassResolver keeps Kubernetes API access and Secret access out of the
// core provider, which makes launch behavior deterministic and unit-testable.
type NodeClassResolver interface {
	GetNodeClass(context.Context, string) (*inspacev1.InSpaceNodeClass, error)
	ResolveAgentToken(context.Context, *inspacev1.InSpaceNodeClass) (string, error)
}

type StaticResolver struct {
	mu          sync.RWMutex
	nodeClasses map[string]*inspacev1.InSpaceNodeClass
	tokens      map[string]string
}

func NewStaticResolver(nodeClasses ...*inspacev1.InSpaceNodeClass) *StaticResolver {
	r := &StaticResolver{nodeClasses: map[string]*inspacev1.InSpaceNodeClass{}, tokens: map[string]string{}}
	for _, nodeClass := range nodeClasses {
		r.nodeClasses[nodeClass.Name] = nodeClass.DeepCopy()
	}
	return r
}

func (r *StaticResolver) SetNodeClass(nodeClass *inspacev1.InSpaceNodeClass) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodeClasses[nodeClass.Name] = nodeClass.DeepCopy()
}

func (r *StaticResolver) SetToken(name, key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[name+"/"+key] = value
}

func (r *StaticResolver) GetNodeClass(_ context.Context, name string) (*inspacev1.InSpaceNodeClass, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nodeClass, ok := r.nodeClasses[name]
	if !ok {
		return nil, fmt.Errorf("InSpaceNodeClass %q not found", name)
	}
	return nodeClass.DeepCopy(), nil
}

func (r *StaticResolver) ResolveAgentToken(_ context.Context, nodeClass *inspacev1.InSpaceNodeClass) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ref := nodeClass.Spec.K3s.TokenSecretRef
	if ref.Name != inspacev1.K3sAgentTokenSecretName || ref.Key != inspacev1.K3sAgentTokenSecretKey {
		return "", fmt.Errorf("agent token must use dedicated Secret %q key %q", inspacev1.K3sAgentTokenSecretName, inspacev1.K3sAgentTokenSecretKey)
	}
	token, ok := r.tokens[ref.Name+"/"+ref.Key]
	if !ok || token == "" {
		return "", fmt.Errorf("agent token Secret %q key %q not found", ref.Name, ref.Key)
	}
	return token, nil
}
