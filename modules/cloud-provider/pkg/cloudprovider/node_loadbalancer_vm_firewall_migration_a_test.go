package cloudprovider

import (
	"reflect"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func (m *migrationCluster) phaseIs(vm migrationVM, phase string) func() bool {
	return func() bool {
		plan := m.plan(vm)
		return plan != nil && plan.Phase == phase
	}
}

// vmFirewallRulesOf returns the per-VM firewall of a VM in the fake cloud.
func (m *migrationCluster) perVMFirewall(vm migrationVM) *inspace.Firewall {
	name, err := inspace.NodeLoadBalancerVMFirewallName(m.provider.config.ClusterID, vm.uuid)
	if err != nil {
		m.t.Fatal(err)
	}
	for index := range m.api.firewalls {
		if m.api.firewalls[index].EffectiveName() == name {
			copied := m.api.firewalls[index]
			return &copied
		}
	}
	return nil
}

// The two gateways of th-live carry traefik-public on one per-Service firewall.
// VM one gets its per-VM firewall as a third firewall, then the Service
// firewall leaves it: 2, 3, 2. Every port that serves stays allowed between
// every two cloud calls, and the other gateway is not touched.
func TestVMFirewallMigrationStrategyAGatewayPair(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	source := m.firewallOfService("traefik-public")
	m.trackCoverage()
	m.annotateNode(mgGateway1.name, "true")

	m.runUntil(300, "the first gateway is done", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseDone))

	if got := m.history[mgGateway1.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
		t.Fatalf("firewalls on the first gateway over time = %v, want [2 3 2]", got)
	}
	if got := m.history[mgGateway2.uuid]; !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("the second gateway was touched: %v", got)
	}
	perVM := m.perVMFirewall(mgGateway1)
	if perVM == nil || !vmFirewallAttachedTo(*perVM, mgGateway1.uuid) || len(perVM.ResourcesAssigned) != 1 {
		t.Fatalf("per-VM firewall = %#v", perVM)
	}
	if len(perVM.Rules) != len(source.Rules) {
		t.Fatalf("per-VM firewall has %d rules, the Service firewall had %d", len(perVM.Rules), len(source.Rules))
	}
	if vmFirewallAttachedTo(*m.firewallOfService("traefik-public"), mgGateway1.uuid) {
		t.Fatal("the Service firewall is still on the first gateway")
	}
	if !vmFirewallAttachedTo(*m.firewallOfService("traefik-public"), mgGateway2.uuid) {
		t.Fatal("the Service firewall left the second gateway, which has not migrated")
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	// One create, one attach, one detach, and the Service never moved.
	if len(m.api.createdFirewalls) != 2 || len(m.api.updatedFirewalls) != 0 || len(m.api.deletedFirewalls) != 0 {
		t.Fatalf("creates=%d (traefik + per-VM) puts=%d deletes=%d", len(m.api.createdFirewalls), len(m.api.updatedFirewalls), len(m.api.deletedFirewalls))
	}
	svc := m.service("traefik-public")
	if len(svc.Status.LoadBalancer.Ingress) != 2 {
		t.Fatalf("status = %#v", svc.Status)
	}
}

func TestVMFirewallMigrationDetachWaitsForTheSettleDelay(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(100, "the per-VM firewall is open", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseOpened))
	detaches := len(m.api.unassignedFirewalls)
	// The settle delay counts from the attach read-back; a clock that stands
	// still must keep the source attached.
	for pass := 0; pass < 5; pass++ {
		for _, vm := range m.vms {
			_ = m.controller.syncVMFirewall(m.ctx, vm.uuid)
		}
	}
	if len(m.api.unassignedFirewalls) != detaches || m.plan(mgGateway1).Phase != vmFirewallMigrationPhaseOpened {
		t.Fatalf("a source left before the settle delay: phase %s", m.plan(mgGateway1).Phase)
	}
	m.runUntil(50, "the first gateway is done", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseDone))
}

func TestVMFirewallMigrationHoldPausesMidPhaseAndResumes(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.trackCoverage()
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(100, "the per-VM firewall is open", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseOpened))

	m.annotateNode(mgGateway1.name, "hold")
	before, writes := m.plan(mgGateway1).Phase, m.writes()
	for pass := 0; pass < 12; pass++ {
		m.round()
	}
	if m.plan(mgGateway1).Phase != before || m.writes() != writes {
		t.Fatalf("a Node on hold advanced: phase %s, %d writes", m.plan(mgGateway1).Phase, m.writes()-writes)
	}
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(100, "the first gateway is done", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseDone))
	if got := m.history[mgGateway1.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
		t.Fatalf("firewalls on the first gateway over time = %v", got)
	}
}
