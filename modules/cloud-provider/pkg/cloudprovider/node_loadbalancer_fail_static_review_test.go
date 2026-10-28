package cloudprovider

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

// A published Node that is verifiably excluded leaves the edge even while its
// local endpoint is still Ready. Only real ambiguity holds a Node.
func TestPublicNodeLocalVerifiedIneligiblePublishedNodeIsRemoved(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *publicNodeLocalTransientFixture)
		// foreign leaves only the public FIP to remove: the relation fence never
		// touches a VM of another billing account.
		foreign bool
	}{
		{name: "excluded from load balancers", mutate: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureNode(t, f, "edge-1", func(node *corev1.Node) {
				node.Labels[corev1.LabelNodeExcludeBalancers] = "true"
			})
		}},
		{name: "control-plane role", mutate: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureNode(t, f, "edge-1", func(node *corev1.Node) {
				node.Labels[nodeRoleControlPlaneLabel] = ""
			})
		}},
		{name: "billing account mismatch", foreign: true, mutate: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.api.vms[1].BillingAccountID = 99
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			_, _, priv1, pub1 := publicNodeLocalFixtureNode(0)
			_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
			test.mutate(t, f)
			done := false
			for pass := 0; pass < 40 && !done; pass++ {
				err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
				var holding *errPublicNodeLocalHolding
				if err != nil && !(test.foreign && errors.As(err, &holding)) {
					t.Fatalf("pass %d: %v", pass, err)
				}
				observed := observePublicNodeLocal(t, f)
				if !observed.fips[pub1] || !observed.vips[priv1] {
					t.Fatalf("pass %d: the remaining node left the edge: %#v", pass, observed)
				}
				done = !observed.fips[pub2]
				if !test.foreign {
					done = done && !observed.vips[priv2] && !observed.assigned[vm2]
				}
			}
			if !done {
				t.Fatalf("the ineligible published node stayed on the edge: %#v", observePublicNodeLocal(t, f))
			}
		})
	}
}

func updatePublicNodeLocalFixtureNode(t *testing.T, f *publicNodeLocalTransientFixture, name string, mutate func(*corev1.Node)) {
	t.Helper()
	node, err := f.provider.kubeClient.CoreV1().Nodes().Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mutate(node)
	if _, err := f.provider.kubeClient.CoreV1().Nodes().Update(f.ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// An InSpaceNodeClass that is no longer a public-node-local class is verified
// intent: the Node leaves. An absent class stays ambiguous and holds.
func TestPublicNodeLocalNodeClassWithoutProfileIsGone(t *testing.T) {
	f := newPublicNodeLocalAuditFixture(t)
	class, err := f.provider.dynamicClient.Resource(nodeClassGVR).Get(f.ctx, "edge-workers", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(class.Object, "default", "spec", "firewallProfile"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.provider.dynamicClient.Resource(nodeClassGVR).Update(f.ctx, class, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	verdict, err := f.verdict(t, nil)
	if err != nil || verdict.kind != publicNodeLocalNodeGone {
		t.Fatalf("verdict = %#v err=%v, want a gone node", verdict, err)
	}

	if err := f.provider.dynamicClient.Resource(nodeClassGVR).Delete(f.ctx, "edge-workers", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	verdict, err = f.verdict(t, nil)
	if verdict.kind == publicNodeLocalNodeGone || verdict.kind == publicNodeLocalNodeAuthorized {
		t.Fatalf("an absent class was treated as %#v (err=%v), want an ambiguous node", verdict, err)
	}
}
