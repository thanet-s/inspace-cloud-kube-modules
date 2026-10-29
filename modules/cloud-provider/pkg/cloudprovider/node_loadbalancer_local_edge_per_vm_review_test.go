package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// A Service that is still on a per-Service firewall must not attach it to a VM
// that already carries a per-VM firewall: the audit would reject the VM for
// every Service on it.
func TestPerServiceAssignWaitsOnAVMThatCarriesAPerVMFirewall(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	name, vm0, privateIP, publicIP := publicNodeLocalFixtureNode(0)
	node, err := f.provider.kubeClient.CoreV1().Nodes().Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	old := publicNodeLocalTestService("old", "old-service-uid", "edge", corev1.ProtocolTCP, 8080)
	desired, err := f.controller.desiredServiceFirewall(old)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := parseNodeLoadBalancerService(old, nodeLoadBalancerDefaults{NodesPerShard: 1})
	if err != nil {
		t.Fatal(err)
	}
	address := nodeLoadBalancerAddress{Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP}
	assignsBefore := len(f.api.assignedFirewalls)
	_, err = perServiceEdge{c: f.controller}.Assign(f.ctx, old, intent, desired, edgeID{}, []nodeLoadBalancerAddress{address})
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if !errors.As(err, &pending) || !strings.Contains(err.Error(), vm0) {
		t.Fatalf("Assign next to a per-VM firewall = %v, want a wait naming the VM", err)
	}
	if len(f.api.assignedFirewalls) != assignsBefore {
		t.Fatal("a per-Service firewall was attached next to a per-VM firewall")
	}
	events, err := f.provider.kubeClient.CoreV1().Events("default").List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waiting := false
	for _, event := range events.Items {
		waiting = waiting || event.Reason == publicNodeLocalReasonVMFirewallMigrationWaiting
	}
	if !waiting {
		t.Fatal("no PublicNodeLocalVMFirewallMigrationWaiting Event")
	}
}

// The invariant is not vacuous: a Retire-like bug that takes the active entry
// off a published VM without authority makes it fail.
func TestVMEdgeInvariantCatchesAnEntryRemovedWithoutAuthority(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	if err := vmEdgeViolation(f); err != nil {
		t.Fatalf("a healthy published Service violates the invariant: %v", err)
	}
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	f.controller.firewallRelationAbsentDelay = 0
	anchor := f.anchorOf(t, vm0)
	applied, err := (vmFirewallAnchorView{cm: anchor}).applied()
	if err != nil || len(applied.Members) != 1 {
		t.Fatalf("applied = %#v, %v", applied, err)
	}
	key := applied.Members[0].key()
	allow := func(context.Context, *corev1.ConfigMap, *inspace.Firewall) error { return nil }
	for pass := 0; pass < 10 && len(vmFirewallsOfVM(f, vm0)) > 1; pass++ {
		_, _ = f.controller.vmFirewallStep(f.ctx, vm0, vmFirewallDelta{Remove: &key}, allow, nil)
	}
	if len(vmFirewallsOfVM(f, vm0)) != 1 {
		t.Fatal("the mutation did not take the firewall off the VM")
	}
	if err := vmEdgeViolation(f); err == nil {
		t.Fatal("the invariant passed with a published FIP on a VM without its rules")
	}
}

func TestVMEdgeInvariantRefusesAPublishedServiceWithNoPolicyAnywhere(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	if err := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace).Delete(f.ctx, vmFirewallAnchorName(vm0), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := vmEdgeViolation(f); err == nil || !strings.Contains(err.Error(), "no firewall or ledger records any policy") {
		t.Fatalf("a published Service with no recorded policy = %v", err)
	}
}

// Only a clean zero-row lookup, or a clean detached row, counts as closed.
func TestVMFirewallEntriesClosedNeedsACleanLookup(t *testing.T) {
	const uuid = "aaaaaaaa-0000-4000-8000-000000000001"
	const vm = "11111111-2222-4333-8444-555555555555"
	anchor := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		annotationVMFirewallVM: vm, annotationVMFirewallUUID: uuid, annotationVMFirewallPendingOp: string(vmFirewallOpDelete),
	}}}
	view := vmFirewallAnchorView{cm: anchor}
	attached := inspace.Firewall{UUID: uuid, ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vm}}}
	detached := inspace.Firewall{UUID: uuid, ResourcesAssigned: []inspace.FirewallResource{}}
	folded := inspace.Firewall{UUID: strings.ToUpper(uuid), ResourcesAssigned: []inspace.FirewallResource{}}
	malformed := inspace.Firewall{UUID: uuid}
	for _, test := range []struct {
		name  string
		items []inspace.Firewall
		want  bool
	}{
		{"absent", nil, true},
		{"detached", []inspace.Firewall{detached}, true},
		{"attached", []inspace.Firewall{attached}, false},
		{"case-folded duplicate rows", []inspace.Firewall{detached, folded}, false},
		{"row without assignments", []inspace.Firewall{malformed}, false},
	} {
		if got := vmFirewallEntriesClosed(view, test.items); got != test.want {
			t.Errorf("%s: closed = %t, want %t", test.name, got, test.want)
		}
	}
	anchor.Annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpUpdate)
	if vmFirewallEntriesClosed(view, nil) {
		t.Error("an anchor that is not deleting is never closed")
	}
}
