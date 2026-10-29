package cloudprovider

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func publicNodeLocalPerVMStateEventCount(t *testing.T, f *publicNodeLocalTransientFixture) int {
	t.Helper()
	events, err := f.provider.kubeClient.CoreV1().Events(f.service.Namespace).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events.Items {
		if event.Reason == publicNodeLocalReasonPerVMStatePresent {
			count++
		}
	}
	return count
}

// auditFixtureVM0 runs the Karpenter-node VM firewall audit against the first
// fixture VM. The fixture's Nodes are manual edge Nodes, whose authorization
// never reaches the audit, so the audit is called directly. The base firewall
// is added the way a Karpenter-backed public-node-local VM carries it.
func auditFixtureVM0(t *testing.T, f *publicNodeLocalTransientFixture) error {
	t.Helper()
	name, _, _, _ := publicNodeLocalFixtureNode(0)
	node, err := f.provider.kubeClient.CoreV1().Nodes().Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return f.controller.auditPublicNodeLocalVMFirewalls(
		f.ctx, node, "22222222-2222-4222-8222-222222222222", f.current(t),
	)
}

func TestPublicNodeLocalHoldsOnPerVMFirewallInPerServiceMode(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	f.api.firewalls = append(f.api.firewalls, publicNodeLocalTestBaseFirewall(vm0))
	if err := auditFixtureVM0(t, f); err != nil {
		t.Fatalf("audit before the per-VM firewall exists: %v", err)
	}
	fw := perVMTestFirewall(t, f.provider.config.ClusterID, vm0, "70000000-0000-4000-8000-000000000001", 443)
	f.api.firewalls = append(f.api.firewalls, fw)

	statusBefore := f.current(t).Status.DeepCopy()
	childBefore := trackedPublicNodeLocalDatapath(t, f).Status.DeepCopy()
	assignsBefore := len(f.api.assignedFirewalls)
	unassignsBefore := len(f.api.unassignedFirewalls)
	deletesBefore := len(f.api.deletedFirewalls)
	firewallsBefore := append(f.api.firewalls[:0:0], f.api.firewalls...)

	for pass := 0; pass < 20; pass++ {
		cause := auditFixtureVM0(t, f)
		var present *publicNodeLocalPerVMStatePresentError
		if !errors.As(cause, &present) || present.vmUUID != vm0 || present.firewallUUID != fw.UUID {
			t.Fatalf("pass %d: audit error = %v, want the per-VM state hold", pass, cause)
		}
		held := f.controller.holdOrFailPublicNodeLocal(f.ctx, f.current(t), cause)
		var holding *errPublicNodeLocalHolding
		if !errors.As(held, &holding) {
			t.Fatalf("pass %d: hold result = %v, want errPublicNodeLocalHolding", pass, held)
		}
	}

	if len(f.api.unassignedFirewalls) != unassignsBefore || len(f.api.deletedFirewalls) != deletesBefore ||
		len(f.api.assignedFirewalls) != assignsBefore {
		t.Fatalf("firewall mutated while holding: assigned=%v unassigned=%v deleted=%v",
			f.api.assignedFirewalls[assignsBefore:], f.api.unassignedFirewalls[unassignsBefore:], f.api.deletedFirewalls[deletesBefore:])
	}
	if !reflect.DeepEqual(f.api.firewalls, firewallsBefore) {
		t.Fatalf("firewalls changed while holding")
	}
	if got := f.current(t).Status; !reflect.DeepEqual(&got, statusBefore) {
		t.Fatalf("Service status changed: got %#v want %#v", got, *statusBefore)
	}
	if got := trackedPublicNodeLocalDatapath(t, f).Status; !reflect.DeepEqual(&got, childBefore) {
		t.Fatalf("datapath status changed: got %#v want %#v", got, *childBefore)
	}
	if publicNodeLocalPerVMStateEventCount(t, f) == 0 {
		t.Fatalf("no %s Event on the Service", publicNodeLocalReasonPerVMStatePresent)
	}
}

func TestPublicNodeLocalAuditRejectsForeignPerVMFirewall(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	_, vm1, _, _ := publicNodeLocalFixtureNode(1)
	f.api.firewalls = append(f.api.firewalls, publicNodeLocalTestBaseFirewall(vm0))
	// Named for VM 1 but attached to VM 0.
	fw := perVMTestFirewall(t, f.provider.config.ClusterID, vm1, "70000000-0000-4000-8000-000000000002", 443)
	fw.ResourcesAssigned[0].ResourceUUID = vm0
	f.api.firewalls = append(f.api.firewalls, fw)

	err := auditFixtureVM0(t, f)
	if err == nil || !strings.Contains(err.Error(), "unauthorized additional firewall") {
		t.Fatalf("foreign per-VM firewall error = %v, want unauthorized additional firewall", err)
	}
	var present *publicNodeLocalPerVMStatePresentError
	if errors.As(err, &present) {
		t.Fatalf("foreign per-VM firewall treated as own per-VM state: %v", err)
	}
}

func TestPublicNodeLocalNoConfigMapReadsWithoutPerVMState(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	f.api.firewalls = append(f.api.firewalls, publicNodeLocalTestBaseFirewall(vm0))
	kube := f.provider.kubeClient.(*kubefake.Clientset)
	touched := 0
	kube.PrependReactor("*", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		touched++
		return true, nil, errors.New("ConfigMaps must not be touched without per-VM state")
	})
	statusBefore := f.current(t).Status.DeepCopy()
	for pass := 0; pass < 10; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if err := auditFixtureVM0(t, f); err != nil {
			t.Fatalf("audit pass %d: %v", pass, err)
		}
	}
	if touched != 0 {
		t.Fatalf("ConfigMap API used %d times", touched)
	}
	if got := f.current(t).Status; !reflect.DeepEqual(&got, statusBefore) {
		t.Fatalf("status changed: %#v", got)
	}
}
