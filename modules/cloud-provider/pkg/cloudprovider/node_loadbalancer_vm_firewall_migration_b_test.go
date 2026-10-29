package cloudprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// newRelayMigrationCluster is the relay VM of th-live: RTMP production on 1935
// and RTMP staging on 1936 from one range, each on its own per-Service
// firewall. With the base firewall the VM carries three, the limit.
func newRelayMigrationCluster(t *testing.T, mode VMFirewallMigrationMode) *migrationCluster {
	t.Helper()
	m := newMigrationCluster(t, mgRelay)
	m.addService("relay-prod", "relay-prod-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 1935)}, []string{mgRelay.name})
	m.publish("relay-prod")
	m.addService("relay-staging", "relay-staging-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 1936)}, []string{mgRelay.name}, "203.0.113.0/24")
	m.publish("relay-staging")
	if got := len(m.firewallsOf(mgRelay)); got != 3 {
		t.Fatalf("the relay VM carries %d firewalls, want 3", got)
	}
	m.switchToPerVM(mode)
	return m
}

// The relay VM is full. The per-Service firewall of production is renamed into
// the per-VM firewall with the union of the rules in one PUT, with nothing
// attached; the staging firewall then leaves. The count goes 3, 3, 2 and never
// 4, and 1935 and 1936 are allowed between every two cloud calls.
func TestVMFirewallMigrationStrategyBRelay(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	prod := m.firewallOfService("relay-prod")
	staging := m.firewallOfService("relay-staging")
	attachesBefore := len(m.api.assignedFirewalls)
	m.trackCoverage()
	m.annotateNode(mgRelay.name, "true")

	m.runUntil(300, "the relay VM is done", m.phaseIs(mgRelay, vmFirewallMigrationPhaseDone))

	if plan := m.plan(mgRelay); plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != prod.UUID {
		t.Fatalf("plan = %#v, want strategy B adopting %s", plan, prod.UUID)
	}
	if got := m.history[mgRelay.uuid]; !reflect.DeepEqual(got, []int{3, 2}) {
		t.Fatalf("firewalls on the relay VM over time = %v, want [3 2]", got)
	}
	if len(m.api.assignedFirewalls) != attachesBefore {
		t.Fatalf("the migration of a full VM attached %v", m.api.assignedFirewalls[attachesBefore:])
	}
	if len(m.api.updatedFirewalls) != 1 || len(m.api.createdFirewalls) != 2 {
		t.Fatalf("puts=%d creates=%d, want exactly one PUT and no create", len(m.api.updatedFirewalls), len(m.api.createdFirewalls))
	}
	put := m.api.updatedFirewalls[0]
	wantName, nameErr := inspace.NodeLoadBalancerVMFirewallName(m.provider.config.ClusterID, mgRelay.uuid)
	if nameErr != nil {
		t.Fatal(nameErr)
	}
	if put.Name != wantName || len(put.Rules) != 2 {
		t.Fatalf("PUT = name %q with %d rules, want %q with 2", put.Name, len(put.Rules), wantName)
	}
	perVM := m.perVMFirewall(mgRelay)
	if perVM == nil || perVM.UUID != prod.UUID || !vmFirewallAttachedTo(*perVM, mgRelay.uuid) {
		t.Fatalf("per-VM firewall = %#v, want the renamed production firewall %s", perVM, prod.UUID)
	}
	if len(perVM.Rules) != 2 {
		t.Fatalf("per-VM firewall has %d rules", len(perVM.Rules))
	}
	for _, rule := range perVM.Rules {
		if *rule.PortStart == 1935 && rule.UUID != prod.Rules[0].UUID {
			t.Fatalf("the production rule changed its provider UUID from %s to %s", prod.Rules[0].UUID, rule.UUID)
		}
	}
	if left := m.firewallOfService("relay-staging"); left == nil || vmFirewallAttachedTo(*left, mgRelay.uuid) || left.UUID != staging.UUID {
		t.Fatalf("the staging firewall = %#v, want it detached", left)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

// ignoreRenameAPI accepts a PUT and ignores its name, as InSpace does with the
// name field: the rules change, the name stays.
type ignoreRenameAPI struct {
	API
	puts int
}

func (a *ignoreRenameAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	a.puts++
	items, err := a.API.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.UUID == uuid {
			request.Name, request.Description = item.EffectiveName(), item.Description
		}
	}
	return a.API.UpdateFirewall(ctx, location, uuid, request)
}

// A PUT whose answer is lost holds the VM until the request can no longer be in
// flight; a readback that still shows the old firewall then clears the receipt
// and the next pass issues the adopt again, once.
func TestVMFirewallMigrationStrategyBAmbiguousAdopt(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgRelay.name, "true")
	m.api.updateFirewallErr = vmTestTimeoutError()
	m.runUntil(20, "the adopt was issued", func() bool { return len(m.api.updatedFirewalls) == 1 })
	puts := len(m.api.updatedFirewalls)

	// Inside the retire window nothing is sent again.
	for pass := 0; pass < 4; pass++ {
		m.round()
	}
	if len(m.api.updatedFirewalls) != puts {
		t.Fatalf("PUTs went from %d to %d inside the retire window", puts, len(m.api.updatedFirewalls))
	}
	anchor := m.anchor(mgRelay)
	if anchor.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpAdopt) || anchor.Annotations[annotationVMFirewallAdoptUUID] == "" {
		t.Fatalf("the adopt receipt is gone: %#v", anchor.Annotations)
	}
	if prod := m.firewallOfService("relay-prod"); len(prod.Rules) != 1 {
		t.Fatalf("the adoptee changed although the PUT failed: %#v", prod.Rules)
	}

	// After the window a readback of the unchanged firewall retires the receipt;
	// the adopt is then issued once more and commits.
	m.api.updateFirewallErr = nil
	m.clock = m.clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + 1)
	m.runUntil(300, "the relay VM is done", m.phaseIs(mgRelay, vmFirewallMigrationPhaseDone))
	if len(m.api.updatedFirewalls) != puts+1 {
		t.Fatalf("PUTs = %d, want %d (one retry)", len(m.api.updatedFirewalls), puts+1)
	}
}

// A PUT that errors but lands inside the retire window commits by readback;
// nothing is sent again.
func TestVMFirewallMigrationStrategyBLateAdoptCommitsByReadback(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgRelay.name, "true")
	m.api.updateFirewallErr = vmTestTimeoutError()
	m.runUntil(20, "the adopt was issued", func() bool { return len(m.api.updatedFirewalls) == 1 })
	// The request lands late, from the cloud's side.
	m.api.updateFirewallErr = nil
	prod := m.firewallOfService("relay-prod")
	if _, err := m.api.UpdateFirewall(m.ctx, "bkk01", prod.UUID, m.api.updatedFirewalls[0]); err != nil {
		t.Fatal(err)
	}
	puts := len(m.api.updatedFirewalls)
	m.runUntil(300, "the relay VM is done", m.phaseIs(mgRelay, vmFirewallMigrationPhaseDone))
	if len(m.api.updatedFirewalls) != puts {
		t.Fatalf("a committed late adopt was sent again: %d -> %d", puts, len(m.api.updatedFirewalls))
	}
}

// A rename that is accepted and ignored (the name field instead of display_name)
// is not mistaken for an adopt: the VM holds and says so.
func TestVMFirewallMigrationStrategyBRenameThatDoesNotTakeHolds(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgRelay.name, "true")
	api := &ignoreRenameAPI{API: m.provider.api}
	m.provider.api = api
	for pass := 0; pass < 20 && api.puts == 0; pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		_ = m.controller.syncVMFirewall(m.ctx, mgRelay.uuid)
	}
	if api.puts != 1 {
		t.Fatalf("PUTs = %d", api.puts)
	}
	var last error
	for pass := 0; pass < 6; pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		last = m.controller.syncVMFirewall(m.ctx, mgRelay.uuid)
	}
	if !errors.Is(last, errVMFirewallDrift) {
		t.Fatalf("the VM pass = %v, want drift", last)
	}
	anchor := m.anchor(mgRelay)
	if anchor.Annotations[annotationVMFirewallAppliedHash] != "" || anchor.Annotations[annotationVMFirewallUUID] != "" {
		t.Fatalf("an unrenamed firewall was committed: %#v", anchor.Annotations)
	}
	drift := false
	events, err := m.kube.CoreV1().Events("default").List(m.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Items {
		drift = drift || event.Reason == vmFirewallDriftReason
	}
	if !drift {
		t.Fatal("no drift Event for a rename that did not take effect")
	}
	if left := m.firewallOfService("relay-staging"); !vmFirewallAttachedTo(*left, mgRelay.uuid) || !vmFirewallAttachedTo(*m.firewallOfService("relay-prod"), mgRelay.uuid) {
		t.Fatal("a firewall left the VM although the adopt never took effect")
	}
}

func TestVMFirewallMigrationBlockedWhenRenameUnsupported(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	previous := vmFirewallRenameSupportedForTest
	vmFirewallRenameSupportedForTest = false
	t.Cleanup(func() { vmFirewallRenameSupportedForTest = previous })
	m.annotateNode(mgRelay.name, "true")
	writes := m.writes()
	for pass := 0; pass < 4; pass++ {
		_ = m.controller.syncVMFirewall(m.ctx, mgRelay.uuid)
	}
	if m.anchor(mgRelay) != nil || m.writes() != writes {
		t.Fatal("a blocked VM was planned or mutated")
	}
	blocked := 0
	events, err := m.kube.CoreV1().Events("default").List(m.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Items {
		if event.Reason == publicNodeLocalReasonVMFirewallMigrationBlocked {
			blocked++
		}
	}
	if blocked == 0 {
		t.Fatal("no PublicNodeLocalVMFirewallMigrationBlocked Event")
	}
}
