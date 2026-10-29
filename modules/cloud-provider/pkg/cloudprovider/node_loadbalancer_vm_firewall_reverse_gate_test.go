package cloudprovider

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// reverseRound is one pass of every VM and Service that tolerates a block, as the
// work queue does with an error it retries.
func (m *migrationCluster) reverseRound() {
	m.t.Helper()
	m.clock = m.clock.Add(7 * time.Second)
	for _, vm := range m.vms {
		var blocked *errVMFirewallMigrationBlocked
		if err := m.controller.syncVMFirewall(m.ctx, vm.uuid); !tolerableMigrationError(err) && !errors.As(err, &blocked) {
			m.t.Fatalf("VM pass of %s: %v", vm.name, err)
		}
	}
	for _, name := range m.services {
		if err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name)); !tolerableMigrationError(err) {
			m.t.Fatalf("Service pass of %s: %v", name, err)
		}
	}
}

// reverseInFlight lists the VMs whose anchor carries a reverse plan.
func (m *migrationCluster) reverseInFlight() []string {
	m.t.Helper()
	var out []string
	for _, vm := range m.vms {
		if plan := m.plan(vm); plan != nil && plan.Direction == vmFirewallMigrationDirectionReverse {
			out = append(out, vm.name)
		}
	}
	return out
}

func (m *migrationCluster) isReversing(vm migrationVM) bool {
	plan := m.plan(vm)
	return plan != nil && plan.Direction == vmFirewallMigrationDirectionReverse
}

// A Node on hold is not reversed, at the start or in the middle; the others
// are. Removing the hold lets it finish.
func TestReverseMigrationHoldPausesAndResumes(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.trackCoverage()
	for _, vm := range m.vms {
		m.annotateNode(vm.name, "hold")
	}
	m.switchToPerService()
	writes := m.writes()
	for pass := 0; pass < 30; pass++ {
		m.reverseRound()
	}
	if m.writes() != writes || len(m.reverseInFlight()) != 0 || m.anchorsLeft() != 3 {
		t.Fatalf("a Node on hold was reversed: %d writes, in flight %v", m.writes()-writes, m.reverseInFlight())
	}

	// Release one gateway; hold it again in the middle of its reverse.
	m.annotateNode(mgGateway1.name, "true")
	for pass := 0; pass < 40 && !m.isReversing(mgGateway1); pass++ {
		m.reverseRound()
	}
	plan := m.plan(mgGateway1)
	if plan == nil || plan.Direction != vmFirewallMigrationDirectionReverse {
		t.Fatalf("the released Node was not planned: %#v", plan)
	}
	m.annotateNode(mgGateway1.name, "hold")
	phase, writes := plan.Phase, m.writes()
	for pass := 0; pass < 30; pass++ {
		m.reverseRound()
	}
	if got := m.plan(mgGateway1); got == nil || got.Phase != phase || m.writes() != writes {
		t.Fatalf("a reverse advanced on a Node on hold: %#v, %d writes", got, m.writes()-writes)
	}

	for _, vm := range m.vms {
		m.annotateNode(vm.name, "")
	}
	for pass := 0; pass < 1500 && !m.allReversed(); pass++ {
		m.reverseRound()
	}
	if !m.allReversed() {
		t.Fatal("the reverse never finished after the hold was lifted")
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

// VMs reverse one at a time, and the next waits four settle delays after the last
// one's anchor is gone.
func TestReverseMigrationOneAtATimeAndPaced(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.switchToPerService()
	var lastGone, firstPlanAfter time.Time
	anchors := m.anchorsLeft()
	gaps := []time.Duration{}
	for pass := 0; pass < 1500 && !m.allReversed(); pass++ {
		m.reverseRound()
		if inFlight := m.reverseInFlight(); len(inFlight) > 1 {
			t.Fatalf("VMs %v are reversing at the same time", inFlight)
		}
		left := m.anchorsLeft()
		if left < anchors {
			lastGone, firstPlanAfter = m.clock, time.Time{}
		}
		anchors = left
		if !lastGone.IsZero() && firstPlanAfter.IsZero() && len(m.reverseInFlight()) == 1 {
			firstPlanAfter = m.clock
			gaps = append(gaps, firstPlanAfter.Sub(lastGone))
		}
	}
	if !m.allReversed() {
		t.Fatal("the reverse never finished")
	}
	if len(gaps) < 2 {
		t.Fatalf("saw %d gaps between VMs, want 2", len(gaps))
	}
	for _, gap := range gaps {
		if gap < 4*m.provider.vmFirewallSettle() {
			t.Errorf("the next VM started %s after the last one, want at least %s", gap, 4*m.provider.vmFirewallSettle())
		}
	}
}

// Without the rename the way back still works where a slot is free: the gateways
// attach and retire; the relay VM, which needs a rename, is blocked with an Event
// and keeps its per-VM firewall.
func TestReverseMigrationWithoutRenameBlocksTheFullVM(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.trackCoverage()
	saved := vmFirewallRenameSupportedForTest
	vmFirewallRenameSupportedForTest = false
	t.Cleanup(func() { vmFirewallRenameSupportedForTest = saved })
	m.switchToPerService()
	for pass := 0; pass < 200; pass++ {
		m.reverseRound()
	}
	if m.anchor(mgGateway1) != nil || m.anchor(mgGateway2) != nil {
		t.Fatal("the gateways were not reversed")
	}
	if m.anchor(mgRelay) == nil || m.perVMFirewall(mgRelay) == nil || len(m.firewallsOf(mgRelay)) != 2 {
		t.Fatal("the relay VM changed without the rename")
	}
	if m.eventsWithReason(publicNodeLocalReasonVMFirewallMigrationBlocked) == 0 {
		t.Fatal("no Blocked Event for the relay VM")
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

// With a fourth slot the relay VM needs no rename: both Services attach their own
// firewall, settle, and the per-VM firewall is retired entry by entry.
func TestReverseMigrationWithAFourthSlotAttachesBothAndRetiresThePerVMFirewall(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.trackCoverage()
	m.provider.config.NodeLoadBalancer.MaxFirewallsPerVM = 4
	m.gate.limit = 4
	puts := len(m.api.updatedFirewalls)
	m.switchToPerService()
	m.runUntilReversed(1500)
	if got := m.history[mgRelay.uuid]; !reflect.DeepEqual(got, []int{2, 3, 4, 3}) {
		t.Errorf("relay firewalls over time = %v, want [2 3 4 3]", got)
	}
	// The retirement narrows the per-VM firewall once, between the two entries.
	if got := len(m.api.updatedFirewalls) - puts; got != 1 {
		t.Errorf("%d PUTs, want the one that drops the first entry", got)
	}
	if m.gate.maxObservedFirewallsPerVM > 4 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

func (m *migrationCluster) runUntilReversed(limit int) {
	m.t.Helper()
	for pass := 0; pass < limit && !m.allReversed(); pass++ {
		m.reverseRound()
	}
	if !m.allReversed() {
		m.t.Fatalf("the reverse migration never finished in %d rounds", limit)
	}
}

// A forward migration that has opened the per-VM firewall and not finished when the
// mode is turned off: the way back starts from where the cluster is, even with a
// source still attached.
func TestReverseMigrationTakesAForwardMigrationInFlightBack(t *testing.T) {
	m := newTHLiveCluster(t)
	m.trackCoverage()
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(400, "the first gateway is opened", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseOpened))
	if m.perVMFirewall(mgGateway1) == nil {
		t.Fatal("the per-VM firewall is not there")
	}
	m.switchToPerService()
	m.runUntilReversed(1500)
	if left := m.perVMFirewallsLeft(); left != 0 {
		t.Errorf("%d per-VM firewalls are left", left)
	}
	for _, name := range m.services {
		if publicNodeLocalServicePerVM(m.service(name)) {
			t.Errorf("%s is on the per-VM edge", name)
		}
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}
