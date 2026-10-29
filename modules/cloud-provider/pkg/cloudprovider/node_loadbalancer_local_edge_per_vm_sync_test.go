package cloudprovider

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVMFirewallQueueKeyNeverParsesAsService(t *testing.T) {
	const vmUUID = "11111111-2222-4333-8444-555555555555"
	if _, ok := parseVMFirewallQueueKey("vmfw/" + vmUUID); ok {
		t.Fatal("a Service key in a namespace called vmfw must stay a Service key")
	}
	if got, ok := parseVMFirewallQueueKey(vmFirewallQueueKey(vmUUID)); !ok || got != vmUUID {
		t.Fatalf("parse(%q) = %q, %t", vmFirewallQueueKey(vmUUID), got, ok)
	}
	for _, key := range []string{"vmfw:", "vmfw:not-a-uuid", "vmfw:" + vmUUID + "x", "default/vmfw"} {
		if _, ok := parseVMFirewallQueueKey(key); ok {
			t.Fatalf("%q must not parse as a VM key", key)
		}
	}
	// The dispatch happens before the Service lister is touched: this controller
	// has no lister at all, and a Service Get would panic.
	f := newPerVMPublicNodeLocalFixture(t, 1)
	if err := f.controller.sync(f.ctx, vmFirewallQueueKey(vmUUID)); err != nil {
		t.Fatalf("sync of a VM key: %v", err)
	}
}

// A withdrawal closes the edge and proves it before the status goes.
func TestPerVMWithdrawProvesBeforeStatus(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	service := f.current(t)
	for pass := 0; pass < 80; pass++ {
		err := f.controller.withdrawPublicNodeLocal(f.ctx, service)
		current := f.current(t)
		open, listErr := f.controller.vmFirewallLedgersList(f.ctx, string(service.UID))
		if listErr != nil {
			t.Fatal(listErr)
		}
		if err != nil {
			// Still proving: the edge may be closing, but the status and the child
			// VIPs are untouched.
			if len(current.Status.LoadBalancer.Ingress) != 2 {
				t.Fatalf("pass %d: the status changed before the edge was proven closed: %#v", pass, current.Status)
			}
			if child := trackedPublicNodeLocalDatapath(t, f); len(child.Status.LoadBalancer.Ingress) != 2 {
				t.Fatalf("pass %d: the child VIPs changed before the edge was proven closed", pass)
			}
			continue
		}
		if open {
			// Only an anchor whose firewall is already detached and being deleted may
			// still list the Service when the withdrawal is proven.
			anchors, anchorErr := f.controller.listVMFirewallAnchors(f.ctx)
			if anchorErr != nil {
				t.Fatal(anchorErr)
			}
			for index := range anchors {
				view := vmFirewallAnchorView{cm: &anchors[index]}
				if len(view.memberKeys(string(service.UID))) != 0 && view.pendingOp() != string(vmFirewallOpDelete) {
					t.Fatalf("pass %d: the withdrawal finished while an anchor still lists the Service: %#v", pass, anchors[index].Annotations)
				}
			}
		}
		if len(current.Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("pass %d: the status was not cleared: %#v", pass, current.Status)
		}
		if child := trackedPublicNodeLocalDatapath(t, f); len(child.Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("pass %d: the child VIPs were not cleared", pass)
		}
		for i := 0; i < 2; i++ {
			_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
			if got := len(vmFirewallsOfVM(f, vmUUID)); got != 1 {
				t.Fatalf("VM %d still carries %d firewalls, want only the base", i, got)
			}
		}
		return
	}
	t.Fatal("the withdrawal never finished")
}

// A Service object that is gone, finalizer stripped by hand or not, loses its
// entries only after a second read, spaced by the confirmation delay.
func TestPerVMServiceGoneWithStrippedFinalizer(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	clock := useFakeClock(f, 10*time.Second)
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	if err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Delete(f.ctx, f.service.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	updatesBefore, deletesBefore := len(f.api.updatedFirewalls), len(f.api.deletedFirewalls)
	err := f.controller.syncVMFirewall(f.ctx, vm0)
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("the first read must only be recorded: %v", err)
	}
	if applied, _ := (vmFirewallAnchorView{cm: f.anchorOf(t, vm0)}).applied(); len(applied.Members) != 1 {
		t.Fatalf("an entry left on a single read: %#v", applied)
	}
	clock.advance(nodeLoadBalancerAbsenceConfirmationDelay / 2)
	if err := f.controller.syncVMFirewall(f.ctx, vm0); !errors.As(err, &pending) {
		t.Fatalf("a read that is not spaced enough must wait: %v", err)
	}
	clock.advance(nodeLoadBalancerAbsenceConfirmationDelay)
	for pass := 0; pass < 20; pass++ {
		_ = f.controller.syncVMFirewall(f.ctx, vm0)
		clock.advance(nodeLoadBalancerAbsenceConfirmationDelay)
		if f.anchorOf(t, vm0) == nil {
			break
		}
	}
	if f.anchorOf(t, vm0) != nil {
		t.Fatalf("the anchor of a gone Service was never collected: %#v", f.anchorOf(t, vm0).Annotations)
	}
	if len(f.api.updatedFirewalls) != updatesBefore || len(f.api.deletedFirewalls) != deletesBefore+1 {
		t.Fatalf("the last member leaves by delete: PUTs %d, deletes %d", len(f.api.updatedFirewalls)-updatesBefore, len(f.api.deletedFirewalls)-deletesBefore)
	}
}

func (f *publicNodeLocalFixtureT) anchorOf(t *testing.T, vmUUID string) *corev1.ConfigMap {
	t.Helper()
	anchor, err := f.controller.getVMFirewallAnchor(f.ctx, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

// A Node object that is deleted while its VM lives does not take the ledger
// with it: the anchor outlives the Node and the entry leaves through it.
func TestPerVMNodeDeletedVMAlive(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	name2, vm2, _, _ := publicNodeLocalFixtureNode(1)
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, "edge-0")
	if f.anchorOf(t, vm2) == nil {
		t.Fatal("the anchor must outlive its Node")
	}
	// The Service pass takes the entry off; the VM pass finishes the delete of
	// the emptied firewall and its anchor.
	f.controller.firewallRelationAbsentDelay = 0
	for pass := 0; pass < 80 && f.anchorOf(t, vm2) != nil; pass++ {
		stepPublicNodeLocal(t, f, pass)
		requireVMEdgeSafe(t, f)
		_ = f.controller.syncVMFirewall(f.ctx, vm2)
	}
	if f.anchorOf(t, vm2) != nil {
		t.Fatalf("the entry never left the VM whose Node was deleted: %#v", f.anchorOf(t, vm2).Annotations)
	}
	if got := len(vmFirewallsOfVM(f, vm2)); got != 1 {
		t.Fatalf("VM2 carries %d firewalls, want only the base", got)
	}
}

// A VM that is deleted takes its ledger off without a PUT, and the last entry
// deletes the firewall.
func TestPerVMVMDeletedLedgerOnly(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	f.controller.firewallRelationAbsentDelay = 0
	name2, vm2, _, _ := publicNodeLocalFixtureNode(1)
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.api.vms = f.api.vms[:1]
	f.api.floatingIPs = f.api.floatingIPs[:1]
	updatesBefore := len(f.api.updatedFirewalls)
	for pass := 0; pass < 30 && f.anchorOf(t, vm2) != nil; pass++ {
		_ = f.controller.syncVMFirewall(f.ctx, vm2)
	}
	if f.anchorOf(t, vm2) != nil {
		t.Fatalf("the anchor of a deleted VM was never collected: %#v", f.anchorOf(t, vm2).Annotations)
	}
	if len(f.api.updatedFirewalls) != updatesBefore {
		t.Fatal("a deleted VM needs no PUT")
	}
	if f.anchorOf(t, "11111111-2222-4333-8444-555555555555") == nil {
		t.Fatal("the other VM lost its anchor")
	}
}

// When the cloud shows every published VM gone but the Nodes are still there,
// the Service waits for a second spaced read: one odd answer removes nothing.
func TestPerVMMassNodeAbsenceStillRefused(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	f.api.vms = nil
	mutations := managedNodeLoadBalancerMutationSnapshot(f.api)
	for pass := 0; pass < 6; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		if got := managedNodeLoadBalancerMutationSnapshot(f.api); got != mutations {
			t.Fatalf("pass %d: the edge changed on a single cloud read", pass)
		}
		if len(f.api.unassignedFirewalls) != 0 || len(f.api.deletedFirewalls) != 0 || len(f.api.updatedFirewalls) != 0 {
			t.Fatalf("pass %d: a firewall was touched on a single cloud read", pass)
		}
		if len(f.current(t).Status.LoadBalancer.Ingress) != 2 {
			t.Fatalf("pass %d: the status changed: %#v", pass, f.current(t).Status)
		}
	}
}
