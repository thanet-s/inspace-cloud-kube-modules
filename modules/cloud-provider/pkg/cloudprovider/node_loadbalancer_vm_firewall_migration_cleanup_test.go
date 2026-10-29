package cloudprovider

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// vmRound runs one pass of every VM and none of the Services.
func (m *migrationCluster) vmRound() map[string]error {
	m.t.Helper()
	errs := map[string]error{}
	m.clock = m.clock.Add(7 * time.Second)
	for _, vm := range m.vms {
		errs[vm.name] = m.controller.syncVMFirewall(m.ctx, vm.uuid)
	}
	return errs
}

func (m *migrationCluster) servicePerVM(name string) func() bool {
	return func() bool { return publicNodeLocalServicePerVM(m.service(name)) }
}

// setServiceAnnotation changes a Service as a user edit or another pass would.
func (m *migrationCluster) setServiceAnnotation(name, key, value string) {
	m.t.Helper()
	svc := m.service(name)
	svc.Annotations[key] = value
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Update(m.ctx, svc, metav1.UpdateOptions{}); err != nil {
		m.t.Fatal(err)
	}
}

func (m *migrationCluster) eventsWithReason(reason string) int {
	m.t.Helper()
	events, err := m.kube.CoreV1().Events(metav1.NamespaceAll).List(m.ctx, metav1.ListOptions{})
	if err != nil {
		m.t.Fatal(err)
	}
	count := 0
	for _, event := range events.Items {
		if event.Reason == reason {
			count++
		}
	}
	return count
}

// A Service gives up its own firewall only when no VM of it carries it any
// more, and is then flipped to the per-VM edge in one write that clears the
// per-Service state. The firewall of traefik-public is on both gateways: it is
// deleted after the second gateway, not the first.
func TestVMFirewallMigrationM6SetsFirewallMode(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	source := m.firewallOfService("traefik-public")
	m.trackCoverage()
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(300, "the first gateway is done", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseDone))
	for pass := 0; pass < 10; pass++ {
		m.round()
	}
	if len(m.api.deletedFirewalls) != 0 || publicNodeLocalServicePerVM(m.service("traefik-public")) {
		t.Fatalf("the Service firewall was given up while the second gateway still carries it: deleted=%v", m.api.deletedFirewalls)
	}
	if !vmFirewallAttachedTo(*m.firewallOfService("traefik-public"), mgGateway2.uuid) {
		t.Fatal("the Service firewall left the second gateway")
	}

	m.annotateNode(mgGateway2.name, "true")
	m.clock = m.clock.Add(time.Minute)
	m.runUntil(500, "the Service is on the per-VM firewall", m.servicePerVM("traefik-public"))

	if !reflect.DeepEqual(m.api.deletedFirewalls, []string{source.UUID}) {
		t.Fatalf("deleted firewalls = %v, want only %s", m.api.deletedFirewalls, source.UUID)
	}
	svc := m.service("traefik-public")
	for _, key := range []string{annotationNodeLoadBalancerFirewallUUID, annotationNodeLoadBalancerFirewallHash,
		annotationNodeLoadBalancerFirewallAbsent, annotationNodeLoadBalancerFirewallChecked,
		annotationNodeLoadBalancerFWDeleteTarget, annotationNodeLoadBalancerCleanupFWAbsent} {
		if svc.Annotations[key] != "" {
			t.Fatalf("%s=%q is still set: %#v", key, svc.Annotations[key], svc.Annotations)
		}
	}
	if svc.Annotations[annotationPublicNodeLocalActivePolicy] == "" || len(svc.Status.LoadBalancer.Ingress) != 2 {
		t.Fatalf("the Service lost its identity or its status: %#v %#v", svc.Annotations, svc.Status)
	}
	if _, perVM := m.controller.publicNodeLocalEdgeFor(svc).(perVMEdge); !perVM {
		t.Fatal("the flipped Service does not take the per-VM edge")
	}
	for _, vm := range []migrationVM{mgGateway1, mgGateway2} {
		if got := len(m.firewallsOf(vm)); got != 2 {
			t.Fatalf("%s carries %d firewalls, want the base and the per-VM firewall", vm.name, got)
		}
	}
	// From here the Service pass finds the Service steady on the per-VM edge: it
	// writes nothing to the cloud and keeps its status.
	writes := m.writes()
	for pass := 0; pass < 8; pass++ {
		m.round()
	}
	if m.writes() != writes || len(m.service("traefik-public").Status.LoadBalancer.Ingress) != 2 {
		t.Fatalf("the steady Service wrote %d times", m.writes()-writes)
	}
}

// The adoptee is the per-VM firewall now: only its annotations are cleared. The
// other firewall is deleted.
func TestVMFirewallMigrationM6NeverDeletesAdoptee(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	prod := m.firewallOfService("relay-prod")
	staging := m.firewallOfService("relay-staging")
	m.trackCoverage()
	m.annotateNode(mgRelay.name, "true")
	m.runUntil(600, "both Services are on the per-VM firewall", func() bool {
		return publicNodeLocalServicePerVM(m.service("relay-prod")) && publicNodeLocalServicePerVM(m.service("relay-staging"))
	})
	if !reflect.DeepEqual(m.api.deletedFirewalls, []string{staging.UUID}) {
		t.Fatalf("deleted firewalls = %v, want only the staging firewall %s", m.api.deletedFirewalls, staging.UUID)
	}
	perVM := m.perVMFirewall(mgRelay)
	if perVM == nil || perVM.UUID != prod.UUID {
		t.Fatalf("per-VM firewall = %#v, want the adoptee %s", perVM, prod.UUID)
	}
	for _, name := range []string{"relay-prod", "relay-staging"} {
		if uuid := m.service(name).Annotations[annotationNodeLoadBalancerFirewallUUID]; uuid != "" {
			t.Fatalf("%s still names firewall %s", name, uuid)
		}
	}
	if got := len(m.firewallsOf(mgRelay)); got != 2 {
		t.Fatalf("the relay VM carries %d firewalls", got)
	}
}

// A VM whose two firewalls are both shared with other VMs can not adopt either.
// It waits; a migration elsewhere detaches a shared firewall from that VM, which
// makes the firewall single-VM, and the deferred VM plans again.
func TestVMFirewallMigrationDeferredUnblocksAfterA(t *testing.T) {
	m := newMigrationCluster(t, mgGateway1, mgGateway2, mgRelay)
	m.addService("shared-a", "shared-a-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 80)}, []string{mgGateway1.name, mgGateway2.name})
	m.publish("shared-a")
	m.addService("shared-b", "shared-b-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 1935)}, []string{mgGateway1.name, mgRelay.name})
	m.publish("shared-b")
	if got := len(m.firewallsOf(mgGateway1)); got != 3 {
		t.Fatalf("the first gateway carries %d firewalls, want 3", got)
	}
	m.switchToPerVM(VMFirewallMigrationManual)
	m.trackCoverage()
	for _, vm := range m.vms {
		m.annotateNode(vm.name, "true")
	}

	// The full VM defers first.
	for pass := 0; pass < 3; pass++ {
		m.round()
	}
	if m.plan(mgGateway1) != nil {
		t.Fatalf("the full VM was planned with no firewall of its own to adopt: %#v", m.plan(mgGateway1))
	}
	if m.eventsWithReason(publicNodeLocalReasonVMFirewallMigrationWaiting) == 0 {
		t.Fatal("no Waiting Event for the deferred VM")
	}
	m.runUntil(1500, "every VM is done", func() bool {
		for _, vm := range m.vms {
			if plan := m.plan(vm); plan == nil || plan.Phase != vmFirewallMigrationPhaseDone {
				return false
			}
		}
		return true
	})
	plan := m.plan(mgGateway1)
	if plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee == "" {
		t.Fatalf("the full VM migrated with %#v, want an adopt", plan)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	for _, vm := range m.vms {
		if got := len(m.firewallsOf(vm)); got != 2 {
			t.Fatalf("%s carries %d firewalls at the end", vm.name, got)
		}
	}
}

// The abort of strategy A: a source changes after the per-VM firewall was
// created and attached, but before it was open. The per-Service firewalls never
// left, so the new firewall is detached and deleted, the record goes and the
// anchor with it.
func TestVMFirewallMigrationAbortBeforeCommitA(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	source := m.firewallOfService("traefik-public")
	m.trackCoverage()
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(200, "the per-VM firewall is attached", func() bool {
		firewall := m.perVMFirewall(mgGateway1)
		return firewall != nil && vmFirewallAttachedTo(*firewall, mgGateway1.uuid)
	})
	if plan := m.plan(mgGateway1); plan == nil || plan.Phase != vmFirewallMigrationPhasePlanned {
		t.Fatalf("plan = %#v, want it still planned", plan)
	}
	// The user edits the Service: a policy change is now in flight.
	m.setServiceAnnotation("traefik-public", annotationPublicNodeLocalTargetPolicy, "00000000")

	for pass := 0; pass < 200 && m.anchor(mgGateway1) != nil; pass++ {
		if err := m.vmRound()[mgGateway1.name]; !tolerableMigrationError(err) {
			t.Fatal(err)
		}
	}
	if m.anchor(mgGateway1) != nil {
		t.Fatalf("the abort never finished: %#v", m.anchor(mgGateway1).Annotations)
	}
	if m.perVMFirewall(mgGateway1) != nil {
		t.Fatal("the new firewall survived the abort")
	}
	if got := m.history[mgGateway1.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
		t.Fatalf("firewalls on the first gateway over time = %v, want [2 3 2]", got)
	}
	if left := m.firewallOfService("traefik-public"); left == nil || left.UUID != source.UUID ||
		!vmFirewallAttachedTo(*left, mgGateway1.uuid) || !vmFirewallAttachedTo(*left, mgGateway2.uuid) {
		t.Fatalf("the Service firewall was touched: %#v", left)
	}
	if len(m.api.deletedFirewalls) != 1 || len(m.api.updatedFirewalls) != 0 {
		t.Fatalf("deleted=%v puts=%d", m.api.deletedFirewalls, len(m.api.updatedFirewalls))
	}
}

// The abort of strategy B before the adopt landed: the receipt resolves as not
// committed, then the record goes. Nothing in the cloud changed.
func TestVMFirewallMigrationAbortBeforeCommitB(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	prod := m.firewallOfService("relay-prod")
	m.trackCoverage()
	attaches, detaches := len(m.api.assignedFirewalls), len(m.api.unassignedFirewalls)
	m.annotateNode(mgRelay.name, "true")
	m.api.updateFirewallErr = vmTestTimeoutError()
	for pass := 0; pass < 20 && len(m.api.updatedFirewalls) == 0; pass++ {
		_ = m.vmRound()
	}
	if len(m.api.updatedFirewalls) != 1 {
		t.Fatalf("PUTs = %d", len(m.api.updatedFirewalls))
	}
	m.api.updateFirewallErr = nil
	m.setServiceAnnotation("relay-staging", annotationPublicNodeLocalTargetPolicy, "00000000")
	m.clock = m.clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + 1)
	for pass := 0; pass < 100 && m.anchor(mgRelay) != nil; pass++ {
		_ = m.vmRound()
	}
	if m.anchor(mgRelay) != nil {
		t.Fatalf("the abort never finished: %#v", m.anchor(mgRelay).Annotations)
	}
	if len(m.api.updatedFirewalls) != 1 || len(m.api.deletedFirewalls) != 0 ||
		len(m.api.assignedFirewalls) != attaches || len(m.api.unassignedFirewalls) != detaches {
		t.Fatalf("the abort touched the cloud: puts=%d deleted=%v", len(m.api.updatedFirewalls), m.api.deletedFirewalls)
	}
	if got := m.firewallOfService("relay-prod"); got == nil || got.UUID != prod.UUID || got.EffectiveName() != prod.EffectiveName() || len(got.Rules) != 1 {
		t.Fatalf("the adoptee changed: %#v", got)
	}
	if got := len(m.firewallsOf(mgRelay)); got != 3 {
		t.Fatalf("the relay VM carries %d firewalls", got)
	}
}

// An adopt that committed can not be undone by an abort: the record is turned
// around into a reverse migration. It waits, touching nothing, while a Service
// is not steady, and when the Service is back it renames the firewall back under
// the name of the Service it came from.
func TestVMFirewallMigrationAbortAfterAdoptCommittedTurnsAround(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	prod := m.firewallOfService("relay-prod")
	m.trackCoverage()
	m.annotateNode(mgRelay.name, "true")
	for pass := 0; pass < 20 && len(m.api.updatedFirewalls) == 0; pass++ {
		_ = m.vmRound()
	}
	if len(m.api.updatedFirewalls) != 1 || m.perVMFirewall(mgRelay) == nil {
		t.Fatal("the adopt did not land")
	}
	m.setServiceAnnotation("relay-staging", annotationPublicNodeLocalTargetPolicy, "00000000")
	for pass := 0; pass < 6; pass++ {
		_ = m.vmRound()
	}
	plan := m.plan(mgRelay)
	if plan == nil || plan.Direction != vmFirewallMigrationDirectionReverse || plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != "relay-prod-uid" {
		t.Fatalf("plan = %#v, want a reverse adopt into relay-prod", plan)
	}
	if m.eventsWithReason(publicNodeLocalReasonVMFirewallMigrationWaiting) == 0 {
		t.Fatal("no Waiting Event")
	}
	// While the Service is not steady the reverse waits and writes nothing.
	for pass := 0; pass < 20 && plan.Phase != vmFirewallMigrationPhaseDetaching; pass++ {
		_ = m.vmRound()
		plan = m.plan(mgRelay)
	}
	writes, puts := m.writes(), len(m.api.updatedFirewalls)
	for pass := 0; pass < 10; pass++ {
		_ = m.vmRound()
	}
	if m.writes() != writes || m.anchor(mgRelay) == nil {
		t.Fatalf("the reverse moved while a Service was not steady: %d writes", m.writes()-writes)
	}
	m.setServiceAnnotation("relay-staging", annotationPublicNodeLocalTargetPolicy, "")
	for pass := 0; pass < 100 && m.anchor(mgRelay) != nil; pass++ {
		_ = m.vmRound()
	}
	if m.anchor(mgRelay) != nil {
		t.Fatalf("the reverse never finished: %#v", m.anchor(mgRelay).Annotations)
	}
	if got := len(m.api.updatedFirewalls) - puts; got != 1 {
		t.Fatalf("%d PUTs after the turn around, want the one rename back", got)
	}
	if got := m.firewallOfService("relay-prod"); got == nil || got.UUID != prod.UUID || got.EffectiveName() != prod.EffectiveName() || len(got.Rules) != 1 {
		t.Fatalf("relay-prod's firewall = %#v, want %s as it was", got, prod.EffectiveName())
	}
	if got := len(m.firewallsOf(mgRelay)); got != 3 || m.perVMFirewallsLeft() != 0 {
		t.Fatalf("the relay VM carries %d firewalls, per-VM firewalls %d", got, m.perVMFirewallsLeft())
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}
