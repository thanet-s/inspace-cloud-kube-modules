package cloudprovider

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
)

func TestVMFirewallAnchorCreateGetUpdateCAS(t *testing.T) {
	f := newVMFirewallFixture(t)
	if got, err := f.controller.getVMFirewallAnchor(f.ctx, vmTestVM); err != nil || got != nil {
		t.Fatalf("missing anchor = %v, %v; want nil, nil", got, err)
	}
	created, err := f.controller.createVMFirewallAnchor(f.ctx, vmTestVM)
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != vmFirewallAnchorName(vmTestVM) || created.Name != "inlb-vmfw-"+vmTestVM || created.Namespace != vmTestNamespace {
		t.Fatalf("anchor identity = %s/%s", created.Namespace, created.Name)
	}
	if created.Labels[vmFirewallAnchorLabel] != "true" || created.Labels[nodeLoadBalancerNodeClusterLabel] != "unit-test-cluster" ||
		len(created.Finalizers) != 1 || created.Finalizers[0] != vmFirewallAnchorFinalizer ||
		created.Annotations[annotationVMFirewallVM] != vmTestVM {
		t.Fatalf("anchor = %#v", created.ObjectMeta)
	}
	again, err := f.controller.createVMFirewallAnchor(f.ctx, vmTestVM)
	if err != nil || again.UID != created.UID {
		t.Fatalf("a second create must return the existing anchor: %v, %v", again, err)
	}
	if got := f.anchor(vmTestVM); got == nil || got.UID != created.UID {
		t.Fatalf("get = %#v", got)
	}
	listed, err := f.controller.listVMFirewallAnchors(f.ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %v, %v", listed, err)
	}

	// A concurrent writer wins the first update: the CAS conflicts and mutate
	// runs once more on the fresh object.
	conflicts := 0
	clientset := f.provider.kubeClient.(*kubefake.Clientset)
	clientset.PrependReactor("update", "configmaps", func(action kubetesting.Action) (bool, runtime.Object, error) {
		if conflicts == 0 {
			conflicts++
			other := created.DeepCopy()
			other.Annotations["concurrent"] = "writer"
			// Apply the other writer's change directly to the tracker.
			if err := clientset.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, other, vmTestNamespace); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, created.Name, errors.New("stale resourceVersion"))
		}
		return false, nil, nil
	})
	runs := 0
	updated, changed, err := f.controller.updateVMFirewallAnchor(f.ctx, created, func(cm *corev1.ConfigMap) (bool, error) {
		runs++
		cm.Annotations[annotationVMFirewallUUID] = "33333333-3333-4333-8333-333333333333"
		return true, nil
	})
	if err != nil || !changed {
		t.Fatalf("update = %v, %t, %v", updated, changed, err)
	}
	if runs != 2 {
		t.Fatalf("mutate ran %d times, want 2 (once per attempt)", runs)
	}
	if updated.Annotations["concurrent"] != "writer" || updated.Annotations[annotationVMFirewallUUID] == "" {
		t.Fatalf("the retry must build on the fresh object: %#v", updated.Annotations)
	}

	unchanged, changed, err := f.controller.updateVMFirewallAnchor(f.ctx, updated, func(*corev1.ConfigMap) (bool, error) { return false, nil })
	if err != nil || changed || unchanged == nil {
		t.Fatalf("no-op update = %v, %t, %v", unchanged, changed, err)
	}
	if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, updated, func(*corev1.ConfigMap) (bool, error) {
		return false, errors.New("refused")
	}); err == nil {
		t.Fatal("a mutate error must be returned")
	}
}

func TestVMFirewallAnchorRejectsForeignLabelsAndName(t *testing.T) {
	f := newVMFirewallFixture(t)
	good, err := f.controller.createVMFirewallAnchor(f.ctx, vmTestVM)
	if err != nil {
		t.Fatal(err)
	}
	clientset := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace)
	mutate := func(mutator func(*corev1.ConfigMap)) {
		t.Helper()
		cm := good.DeepCopy()
		mutator(cm)
		if _, err := clientset.Update(f.ctx, cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for name, mutator := range map[string]func(*corev1.ConfigMap){
		"foreign cluster":    func(cm *corev1.ConfigMap) { cm.Labels[nodeLoadBalancerNodeClusterLabel] = "other-cluster" },
		"missing anchor tag": func(cm *corev1.ConfigMap) { delete(cm.Labels, vmFirewallAnchorLabel) },
		"vm annotation":      func(cm *corev1.ConfigMap) { cm.Annotations[annotationVMFirewallVM] = vmTestOtherVM },
		"vm annotation gone": func(cm *corev1.ConfigMap) { delete(cm.Annotations, annotationVMFirewallVM) },
	} {
		t.Run(name, func(t *testing.T) {
			mutate(mutator)
			if _, err := f.controller.getVMFirewallAnchor(f.ctx, vmTestVM); !errors.Is(err, errVMFirewallLedgerCorrupt) {
				t.Fatalf("get error = %v, want errVMFirewallLedgerCorrupt", err)
			}
			mutate(func(cm *corev1.ConfigMap) {
				cm.Labels = good.DeepCopy().Labels
				cm.Annotations = good.DeepCopy().Annotations
			})
			if _, err := f.controller.getVMFirewallAnchor(f.ctx, vmTestVM); err != nil {
				t.Fatalf("restored anchor must read cleanly: %v", err)
			}
		})
	}
	t.Run("list skips other clusters", func(t *testing.T) {
		foreign := good.DeepCopy()
		foreign.Name = vmFirewallAnchorName(vmTestOtherVM)
		foreign.UID = "other"
		foreign.ResourceVersion = ""
		foreign.Labels[nodeLoadBalancerNodeClusterLabel] = "other-cluster"
		foreign.Annotations[annotationVMFirewallVM] = vmTestOtherVM
		if _, err := clientset.Create(f.ctx, foreign, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		listed, err := f.controller.listVMFirewallAnchors(f.ctx)
		if err != nil || len(listed) != 1 || listed[0].Name != good.Name {
			t.Fatalf("list = %v, %v", listed, err)
		}
	})
	t.Run("update refuses a replaced anchor after a conflict", func(t *testing.T) {
		kube := f.provider.kubeClient.(*kubefake.Clientset)
		kube.PrependReactor("update", "configmaps", func(kubetesting.Action) (bool, runtime.Object, error) {
			replaced := good.DeepCopy()
			replaced.UID = "replacement"
			if err := kube.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, replaced, vmTestNamespace); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, good.Name, errors.New("uid"))
		})
		original := good.DeepCopy()
		original.UID = "original"
		if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, original, func(cm *corev1.ConfigMap) (bool, error) {
			cm.Annotations["x"] = "y"
			return true, nil
		}); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("update of a replaced anchor error = %v", err)
		}
	})
}

func TestVMFirewallAnchorRequiresNamespace(t *testing.T) {
	f := newVMFirewallFixture(t)
	f.provider.config.NodeLoadBalancer.ControllerNamespace = ""
	if _, err := f.controller.getVMFirewallAnchor(f.ctx, vmTestVM); err == nil || err.Error() != "public-node-local: CCM namespace is not configured" {
		t.Fatalf("get error = %v", err)
	}
	if _, err := f.controller.createVMFirewallAnchor(f.ctx, vmTestVM); err == nil {
		t.Fatal("create without a namespace must fail")
	}
	if _, err := f.controller.listVMFirewallAnchors(f.ctx); err == nil {
		t.Fatal("list without a namespace must fail")
	}
	if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, &corev1.ConfigMap{}, func(*corev1.ConfigMap) (bool, error) { return true, nil }); err == nil {
		t.Fatal("update without a namespace must fail")
	}
}
