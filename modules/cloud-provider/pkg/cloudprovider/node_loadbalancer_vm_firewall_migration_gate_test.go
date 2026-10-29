package cloudprovider

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func traefikPorts() []corev1.ServicePort {
	return []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 80), mgPort(corev1.ProtocolTCP, 443), mgPort(corev1.ProtocolUDP, 443)}
}

// newGatewayCluster is the two gateway VMs of th-live with traefik-public on
// both, published on its per-Service firewall.
func newGatewayCluster(t *testing.T, mode VMFirewallMigrationMode) *migrationCluster {
	t.Helper()
	m := newMigrationCluster(t, mgGateway1, mgGateway2)
	m.addService("traefik-public", "traefik-public-uid", traefikPorts(), []string{mgGateway1.name, mgGateway2.name})
	m.publish("traefik-public")
	m.switchToPerVM(mode)
	return m
}

func TestVMFirewallMigrationManualNeedsAnnotation(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	for pass := 0; pass < 3; pass++ {
		m.round()
	}
	if m.plan(mgGateway1) != nil || m.plan(mgGateway2) != nil || m.anchor(mgGateway1) != nil {
		t.Fatal("manual mode planned a VM that was not annotated")
	}
	writes := m.writes()

	m.annotateNode(mgGateway1.name, "true")
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	plan := m.plan(mgGateway1)
	if plan == nil || plan.Phase != vmFirewallMigrationPhasePlanned || plan.Strategy != vmFirewallMigrationStrategyHeadroom || len(plan.Sources) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	if want := m.service("traefik-public").Annotations[annotationNodeLoadBalancerFirewallUUID]; plan.Sources[0].Firewall != want {
		t.Fatalf("source = %s, want the traefik-public firewall %s", plan.Sources[0].Firewall, want)
	}
	if m.writes() != writes {
		t.Fatal("planning wrote to the cloud")
	}
	if m.plan(mgGateway2) != nil {
		t.Fatal("the VM without the annotation was planned")
	}
}

func TestVMFirewallMigrationAutoPlansWithoutAnnotation(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationAuto)
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	if m.plan(mgGateway1) == nil {
		t.Fatal("auto mode did not plan a VM")
	}
}

func TestVMFirewallMigrationHoldBlocksTheStart(t *testing.T) {
	for _, mode := range []VMFirewallMigrationMode{VMFirewallMigrationManual, VMFirewallMigrationAuto} {
		m := newGatewayCluster(t, mode)
		m.annotateNode(mgGateway1.name, "hold")
		m.annotateNode(mgGateway2.name, "hold")
		for pass := 0; pass < 3; pass++ {
			m.round()
		}
		if m.anchor(mgGateway1) != nil || m.anchor(mgGateway2) != nil {
			t.Fatalf("%s mode: a Node on hold was planned", mode)
		}
		m.annotateNode(mgGateway1.name, "true")
		m.round()
		if m.plan(mgGateway1) == nil {
			t.Fatalf("%s mode: the hold did not lift", mode)
		}
	}
}

func TestVMFirewallMigrationOneAtATimeAndPaced(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	m.annotateNode(mgGateway2.name, "true")
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	// The second VM waits while the first has a plan that is not done.
	err := m.controller.syncVMFirewall(m.ctx, mgGateway2.uuid)
	if err == nil || !strings.Contains(err.Error(), "one at a time") {
		t.Fatalf("second VM = %v, want it to wait for the first", err)
	}
	if m.anchor(mgGateway2) != nil {
		t.Fatal("two VMs migrate at once")
	}
	// The first finishes; the next waits four settle periods.
	anchor := m.anchor(mgGateway1)
	plan := *m.plan(mgGateway1)
	plan.Phase = vmFirewallMigrationPhaseDone
	plan.DoneAt = m.clock.Format(time.RFC3339Nano)
	raw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.controller.updateVMFirewallAnchor(m.ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		cm.Annotations[annotationVMFirewallMigration] = raw
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	err = m.controller.syncVMFirewall(m.ctx, mgGateway2.uuid)
	if err == nil || !strings.Contains(err.Error(), "next one waits") {
		t.Fatalf("second VM right after the first = %v, want the pacing wait", err)
	}
	m.clock = m.clock.Add(4*m.provider.vmFirewallSettle() - time.Second)
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway2.uuid); err == nil || m.anchor(mgGateway2) != nil {
		t.Fatalf("one second early: err=%v", err)
	}
	m.clock = m.clock.Add(2 * time.Second)
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway2.uuid); err != nil {
		t.Fatal(err)
	}
	if m.plan(mgGateway2) == nil {
		t.Fatal("the paced VM was not planned")
	}
}

// While a VM has a plan, the Services on it change nothing: not their status,
// their VIPs, their annotations or their firewalls, and a new Node does not
// add anything until the VM is done.
func TestServicesHoldWhileTheirVMMigrates(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	before := m.service("traefik-public")
	writes := m.writes()

	err := m.controller.syncPublicNodeLocal(m.ctx, m.key("traefik-public"), before)
	if err == nil || !tolerableMigrationError(err) || !strings.Contains(err.Error(), "moving to the per-VM firewall") {
		t.Fatalf("Service pass = %v, want a wait for the migration", err)
	}
	events, listErr := m.kube.CoreV1().Events("default").List(m.ctx, metav1.ListOptions{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	waiting := false
	for _, event := range events.Items {
		waiting = waiting || event.Reason == publicNodeLocalReasonVMFirewallMigrationWaiting
	}
	if !waiting {
		t.Fatal("no PublicNodeLocalVMFirewallMigrationWaiting Event on the held Service")
	}

	// A third Node appears and the Service now has an endpoint on it.
	m.vms = append(m.vms, mgRelay)
	extra := publicNodeLocalTestNode(mgRelay.name, mgRelay.uuid, mgRelay.private, mgRelay.public)
	if _, err := m.kube.CoreV1().Nodes().Create(m.ctx, extra, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	m.endpoints["traefik-public"] = append(m.endpoints["traefik-public"], mgRelay.name)
	m.refreshEndpoints()
	for pass := 0; pass < 3; pass++ {
		if err := m.controller.syncPublicNodeLocal(m.ctx, m.key("traefik-public"), m.service("traefik-public")); err == nil {
			t.Fatal("a held Service made progress")
		}
	}
	after := m.service("traefik-public")
	if m.writes() != writes {
		t.Fatalf("a held Service wrote to the cloud: %d -> %d", writes, m.writes())
	}
	if len(after.Status.LoadBalancer.Ingress) != len(before.Status.LoadBalancer.Ingress) ||
		after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("a held Service changed: %#v", after.Annotations)
	}
}

// A Service that is not a source of the migration is not held by it, but it
// does not attach its own firewall to a VM whose migration is in flight.
func TestAnAddOnAMigratingVMWaits(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	node, err := m.kube.CoreV1().Nodes().Get(m.ctx, mgGateway1.name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other := m.service("traefik-public")
	err = m.controller.waitForPerVMVM(m.ctx, other, []nodeLoadBalancerAddress{{Node: node}})
	if err == nil || !strings.Contains(err.Error(), "firewall migration in flight") {
		t.Fatalf("waitForPerVMVM = %v, want a wait", err)
	}
	// A finished migration no longer holds the VM; the per-VM edge may add.
	plan := *m.plan(mgGateway1)
	plan.Phase = vmFirewallMigrationPhaseDone
	plan.DoneAt = m.clock.Format(time.RFC3339Nano)
	raw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.controller.updateVMFirewallAnchor(m.ctx, m.anchor(mgGateway1), func(cm *corev1.ConfigMap) (bool, error) {
		cm.Annotations[annotationVMFirewallMigration] = raw
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.controller.waitForPerVMVM(m.ctx, other, []nodeLoadBalancerAddress{{Node: node}}); err != nil {
		t.Fatalf("waitForPerVMVM after done = %v", err)
	}
	items, err := m.api.ListFirewalls(m.ctx, "bkk01")
	if err != nil {
		t.Fatal(err)
	}
	if err := (perVMEdge{c: m.controller}).waitForUnmigratedVM(m.ctx, other, mgGateway2.uuid, items); err == nil {
		t.Fatal("a VM that still carries the per-Service firewall must hold a per-VM add")
	}
	if err := (perVMEdge{c: m.controller}).waitForUnmigratedVM(m.ctx, other, mgGateway1.uuid, nil); err != nil {
		t.Fatalf("a done migration must not hold a per-VM add: %v", err)
	}
}
