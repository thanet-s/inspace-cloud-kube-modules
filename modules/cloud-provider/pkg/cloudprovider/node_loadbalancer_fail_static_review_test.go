package cloudprovider

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The incumbent keeps its claim from the parent's own state. A child that is
// absent, unparsable or unreadable must hold, never lose.
func TestPublicNodeLocalIncumbencyDoesNotDependOnChildReadability(t *testing.T) {
	const childReadFailure = "child read failure"
	tests := []struct {
		name    string
		prepare func(*testing.T, *kubefake.Clientset, *corev1.Service)
	}{
		{name: "child absent", prepare: func(t *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			if err := kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("services"), child.Namespace, child.Name); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "child ports unparsable", prepare: func(t *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			broken := child.DeepCopy()
			broken.Spec.Ports = nil
			if err := kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("services"), broken, broken.Namespace); err != nil {
				t.Fatal(err)
			}
		}},
		{name: childReadFailure, prepare: func(_ *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.GetAction).GetName() == child.Name {
					return true, nil, errors.New("child read failed")
				}
				return false, nil, nil
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			incumbent := publicNodeLocalTestService("incumbent", "z-service-uid", "edge", corev1.ProtocolTCP, 443)
			incumbent.Annotations[annotationPublicNodeLocalActivePool] = "edge"
			incumbent.Annotations[annotationPublicNodeLocalActivePolicy] = "policy"
			child := desiredPublicNodeLocalDatapath(incumbent, "edge")
			newcomer := publicNodeLocalTestService("newcomer", "a-service-uid", "edge", corev1.ProtocolTCP, 443)
			provider := newTestProvider(t, &fakeAPI{})
			kube := kubefake.NewSimpleClientset(incumbent.DeepCopy(), newcomer.DeepCopy(), child)
			provider.kubeClient = kube
			controller := &nodeLoadBalancerController{provider: provider}
			test.prepare(t, kube, child)

			intent, err := parseNodeLoadBalancerService(incumbent, nodeLoadBalancerDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			// A child that cannot be read must never make the incumbent lose; it
			// either holds the claim or reports an error, and the parent state
			// alone already proves the claim here.
			loses, _, err := controller.publicNodeLocalPortConflict(context.Background(), incumbent, intent)
			if loses {
				t.Fatalf("the incumbent lost its claim to a lower-UID newcomer: %v", err)
			}
			// The newcomer still loses to the incumbent, whatever the child says.
			if test.name == childReadFailure {
				return
			}
			newcomerIntent, err := parseNodeLoadBalancerService(newcomer, nodeLoadBalancerDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			if loses, _, err := controller.publicNodeLocalPortConflict(context.Background(), newcomer, newcomerIntent); !loses {
				t.Fatalf("the newcomer won against the incumbent: %v", err)
			}
		})
	}
}
