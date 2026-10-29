package cloudprovider

import (
	"errors"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// markDeleting sets the deletion timestamp of a Service, as `kubectl delete` does
// on a Service that has a finalizer.
func (m *migrationCluster) markDeleting(name string) {
	m.t.Helper()
	svc := m.service(name)
	now := metav1.NewTime(m.clock)
	svc.DeletionTimestamp = &now
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Update(m.ctx, svc, metav1.UpdateOptions{}); err != nil {
		m.t.Fatal(err)
	}
}

func (m *migrationCluster) noPerVMState() bool {
	if m.anchorsLeft() != 0 || m.perVMFirewallsLeft() != 0 {
		return false
	}
	for _, name := range m.services {
		if publicNodeLocalServicePerVM(m.service(name)) {
			return false
		}
	}
	return true
}

// A Service that is deleted while the mode is off does not stall the way back: its
// entry leaves the per-VM firewall on that intent, it gets no firewall of its own,
// and its mark goes so its own cleanup can finish. The others are reversed as ever.
func TestReverseMigrationHandlesAServiceBeingDeleted(t *testing.T) {
	for name, deleting := range map[string]string{
		"a Service that would take the per-VM firewall by rename": "relay-staging",
		"the other Service of a full VM":                          "relay-prod",
		"the only Service of the gateways":                        "traefik-public",
	} {
		t.Run(name, func(t *testing.T) {
			m := newTHLiveCluster(t)
			migrateTHLiveForward(m)
			m.trackCoverage()
			// What a Service that is going away served need not stay covered.
			goingAway := map[string][]int32{"relay-staging": {1936}, "relay-prod": {1935}, "traefik-public": {80, 443}}[deleting]
			for vm, rules := range m.required {
				kept := rules[:0:0]
				for _, rule := range rules {
					drop := false
					for _, port := range goingAway {
						drop = drop || *rule.PortStart == port
					}
					if !drop {
						kept = append(kept, rule)
					}
				}
				m.required[vm] = kept
			}
			m.markDeleting(deleting)
			creates := len(m.api.createdFirewalls)
			m.switchToPerService()
			for pass := 0; pass < 1500 && !m.noPerVMState(); pass++ {
				m.reverseRound()
			}
			if !m.noPerVMState() {
				t.Fatalf("the reverse stalled on a Service being deleted: anchors %d", m.anchorsLeft())
			}
			if own := m.service(deleting).Annotations[annotationNodeLoadBalancerFirewallUUID]; own != "" && deleting == "traefik-public" {
				t.Errorf("%s got a firewall of its own: %s", deleting, own)
			}
			if deleting == "traefik-public" && len(m.api.createdFirewalls)-creates != 1 {
				t.Errorf("%d firewalls were created, want only the relay VM's: the gateways' only Service is going away", len(m.api.createdFirewalls)-creates)
			}
			for _, vm := range []migrationVM{mgGateway1, mgGateway2} {
				want := 2
				if got := len(m.firewallsOf(vm)); got != want && deleting != "traefik-public" {
					t.Errorf("%s carries %d firewalls, want %d", vm.name, got, want)
				}
			}
			if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
				t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
			}
		})
	}
}

// The pacing delay survives a restart of the controller between two VMs: it is
// remembered on the anchors that are left, not in memory.
func TestReverseMigrationPacingSurvivesARestart(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.switchToPerService()
	var lastGone time.Time
	var gaps []time.Duration
	anchors := m.anchorsLeft()
	for pass := 0; pass < 1500 && !m.allReversed(); pass++ {
		m.reverseRound()
		if left := m.anchorsLeft(); left < anchors {
			lastGone = m.clock
			m.restart() // the crash that forgets everything in memory
			anchors = left
			continue
		}
		if !lastGone.IsZero() && len(m.reverseInFlight()) == 1 {
			gaps = append(gaps, m.clock.Sub(lastGone))
			lastGone = time.Time{}
		}
	}
	if !m.allReversed() || len(gaps) < 2 {
		t.Fatalf("reversed %v, gaps %v", m.allReversed(), gaps)
	}
	for _, gap := range gaps {
		if gap < 4*m.provider.vmFirewallSettle() {
			t.Errorf("after a restart the next VM started %s after the last one, want at least %s", gap, 4*m.provider.vmFirewallSettle())
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
