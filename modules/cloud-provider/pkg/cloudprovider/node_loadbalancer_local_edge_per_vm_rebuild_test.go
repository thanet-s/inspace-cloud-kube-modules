package cloudprovider

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A lost anchor is rebuilt by exact attribution, and the Service never notices:
// no PUT, no hold.
func TestPerVMAnchorDeletedRebuilds(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	before := f.anchorOf(t, vm0).Annotations[annotationVMFirewallApplied]
	if err := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace).Delete(f.ctx, vmFirewallAnchorName(vm0), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	updatesBefore := len(f.api.updatedFirewalls)
	if err := f.controller.syncVMFirewall(f.ctx, vm0); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	rebuilt := f.anchorOf(t, vm0)
	if rebuilt == nil || rebuilt.Annotations[annotationVMFirewallApplied] != before {
		t.Fatalf("the rebuilt ledger differs from the lost one:\n got %v\nwant %s", rebuilt, before)
	}
	if len(f.api.updatedFirewalls) != updatesBefore {
		t.Fatal("a rebuild must not mutate the cloud")
	}
	if len(f.eventsOf(t, vmFirewallLedgerRebuiltReason)) == 0 {
		t.Fatal("no PublicNodeLocalVMFirewallLedgerRebuilt Event")
	}
	for pass := 0; pass < 10; pass++ {
		stepPublicNodeLocal(t, f, pass)
		requireVMEdgeSafe(t, f)
	}
	if len(f.current(t).Status.LoadBalancer.Ingress) != 2 {
		t.Fatalf("the Service lost nodes: %#v", f.current(t).Status)
	}
}

// The delete of an emptied VM firewall is the VM pass's. A Service planning an
// edge change must not read it as an unresolved receipt of its own, or one
// anchor on its way out would hold the Service for as long as the delete takes.
func TestVMEdgeAssignedIgnoresAnAnchorThatIsBeingDeleted(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	member := f.member(service)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	f.setAnchor(vmTestVM, func(annotations map[string]string) {
		annotations[annotationVMFirewallPending] = annotations[annotationVMFirewallApplied]
		annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpDelete)
		annotations[annotationVMFirewallDeleteTarget] = vmTestFirewallUUID
	})
	items, err := f.provider.api.ListFirewalls(f.ctx, "bkk01")
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := f.controller.listVMFirewallAnchors(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	open, err := f.controller.vmEdgeAssigned(member.UID, member.Policy, items, anchors)
	if err != nil {
		t.Fatalf("a deleting anchor must not be reported as a pending receipt: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("nobody is open on a firewall that is being deleted: %v", open)
	}
}

// When two Services could own the same rule the ledger is not guessed: the VM
// holds, nothing is written and nothing is sent.
func TestPerVMAnchorDeletedAmbiguousAttributionHolds(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	twin := publicNodeLocalTestService("twin", "twin-service-uid", "edge", corev1.ProtocolTCP, 443)
	if _, err := f.provider.kubeClient.CoreV1().Services(twin.Namespace).Create(f.ctx, twin, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace).Delete(f.ctx, vmFirewallAnchorName(vm0), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	updatesBefore := len(f.api.updatedFirewalls)
	err := f.controller.syncVMFirewall(f.ctx, vm0)
	if err == nil || !errors.Is(err, errVMFirewallDrift) {
		t.Fatalf("an ambiguous attribution must hold: %v", err)
	}
	if f.anchorOf(t, vm0) != nil {
		t.Fatal("an anchor was written from a guess")
	}
	if len(f.api.updatedFirewalls) != updatesBefore {
		t.Fatal("the cloud was touched on a guess")
	}
}
