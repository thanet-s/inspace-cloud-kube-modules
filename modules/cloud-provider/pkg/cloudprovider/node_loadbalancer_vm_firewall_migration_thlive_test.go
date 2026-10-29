package cloudprovider

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// newTHLiveCluster is th-live as it runs on v1.1.9: traefik-public on the two
// gateways, the RTMP production Service on the relay VM and the RTMP staging
// Service on the relay VM, each on its own per-Service firewall, then the
// controller switched to the perVM mode.
func newTHLiveCluster(t *testing.T) *migrationCluster {
	t.Helper()
	gateway1, gateway2, relay := mgGateway1, mgGateway2, mgRelay
	gateway1.pool, gateway2.pool, relay.pool = "public-gateway", "public-gateway", "spe-relay-share"
	m := newMigrationCluster(t, gateway1, gateway2, relay)
	m.addService("traefik-public", "traefik-public-uid", traefikPorts(), []string{mgGateway1.name, mgGateway2.name})
	m.publish("traefik-public")
	m.addService("relay-prod", "relay-prod-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 1935)}, []string{mgRelay.name})
	m.publish("relay-prod")
	m.addService("relay-staging", "relay-staging-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 1936)}, []string{mgRelay.name}, "203.0.113.0/24")
	m.publish("relay-staging")
	for _, vm := range []migrationVM{mgGateway1, mgGateway2} {
		if got := len(m.firewallsOf(vm)); got != 2 {
			t.Fatalf("%s carries %d firewalls, want 2", vm.name, got)
		}
	}
	if got := len(m.firewallsOf(mgRelay)); got != 3 {
		t.Fatalf("the relay VM carries %d firewalls, want 3", got)
	}
	m.switchToPerVM(VMFirewallMigrationManual)
	return m
}

// statusSnapshot is what must not change during a migration: the public status
// of every Service and the VIPs of its datapath.
func (m *migrationCluster) statusSnapshot() map[string]string {
	m.t.Helper()
	out := map[string]string{}
	for _, name := range m.services {
		svc := m.service(name)
		ips := []string{}
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			ips = append(ips, ingress.IP)
		}
		sort.Strings(ips)
		vips := []string{}
		if child, err := m.kube.CoreV1().Services(svc.Namespace).Get(m.ctx, nodeLoadBalancerDatapathName(svc), metav1.GetOptions{}); err == nil {
			for _, ingress := range child.Status.LoadBalancer.Ingress {
				vips = append(vips, ingress.IP)
			}
		}
		sort.Strings(vips)
		out[name] = fmt.Sprintf("status=%v vips=%v", ips, vips)
	}
	return out
}

func (m *migrationCluster) allMigrated() bool {
	for _, vm := range m.vms {
		if plan := m.plan(vm); plan == nil || plan.Phase != vmFirewallMigrationPhaseDone {
			return false
		}
	}
	for _, name := range m.services {
		if !publicNodeLocalServicePerVM(m.service(name)) {
			return false
		}
	}
	return true
}

// The whole migration of th-live, in the order of the rollout: the gateways
// one at a time, then the relay VM. The gateways go 2, 3, 2; the relay VM, which
// is full, goes 3, 3, 2 by renaming a Service firewall and never attaches a
// fourth. Every port that serves is allowed between every two cloud calls
// (trackCoverage checks it after each one), and no Service changes its status
// or its VIPs at any point.
func TestVMFirewallMigrationTHLiveFixture(t *testing.T) {
	m := newTHLiveCluster(t)
	traefik := m.firewallOfService("traefik-public")
	prod := m.firewallOfService("relay-prod")
	staging := m.firewallOfService("relay-staging")
	if !(prod.UUID < staging.UUID) {
		t.Fatalf("the fixture must create the production firewall (%s) before the staging one (%s)", prod.UUID, staging.UUID)
	}
	m.trackCoverage()
	var relayPorts []int32
	for _, rule := range m.required[mgRelay.uuid] {
		relayPorts = append(relayPorts, *rule.PortStart)
	}
	sort.Slice(relayPorts, func(i, j int) bool { return relayPorts[i] < relayPorts[j] })
	if !reflect.DeepEqual(relayPorts, []int32{1935, 1936}) {
		t.Fatalf("the coverage the relay VM must keep = %v, want 1935 and 1936", relayPorts)
	}
	before := m.statusSnapshot()
	checkStatus := func() {
		t.Helper()
		if now := m.statusSnapshot(); !reflect.DeepEqual(now, before) {
			t.Fatalf("a Service changed its status or VIPs during the migration:\n before %v\n after  %v", before, now)
		}
	}

	for _, step := range []struct {
		vm migrationVM
	}{{mgGateway1}, {mgGateway2}, {mgRelay}} {
		m.annotateNode(step.vm.name, "true")
		m.runUntil(800, step.vm.name+" is done", m.phaseIs(step.vm, vmFirewallMigrationPhaseDone))
		checkStatus()
		if step.vm == mgGateway1 && len(m.api.deletedFirewalls) != 0 {
			t.Fatalf("a firewall was deleted after the first gateway: %v", m.api.deletedFirewalls)
		}
	}
	m.runUntil(800, "every Service is on the per-VM firewall", m.allMigrated)
	checkStatus()

	if got := m.history[mgGateway1.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
		t.Errorf("first gateway firewalls over time = %v, want [2 3 2]", got)
	}
	if got := m.history[mgGateway2.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
		t.Errorf("second gateway firewalls over time = %v, want [2 3 2]", got)
	}
	if got := m.history[mgRelay.uuid]; !reflect.DeepEqual(got, []int{3, 2}) {
		t.Errorf("relay firewalls over time = %v, want [3 2] (never 4)", got)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	deleted := append([]string(nil), m.api.deletedFirewalls...)
	sort.Strings(deleted)
	want := []string{traefik.UUID, staging.UUID}
	sort.Strings(want)
	if !reflect.DeepEqual(deleted, want) {
		t.Errorf("deleted firewalls = %v, want the gateway firewall %s and the staging firewall %s", deleted, traefik.UUID, staging.UUID)
	}
	if perVM := m.perVMFirewall(mgRelay); perVM == nil || perVM.UUID != prod.UUID {
		t.Errorf("relay per-VM firewall = %#v, want the renamed production firewall %s", perVM, prod.UUID)
	}
	for _, name := range m.services {
		if svc := m.service(name); !publicNodeLocalServicePerVM(svc) || svc.Annotations[annotationNodeLoadBalancerFirewallUUID] != "" {
			t.Errorf("%s: %#v", name, svc.Annotations)
		}
	}
	for _, vm := range m.vms {
		if got := len(m.firewallsOf(vm)); got != 2 {
			t.Errorf("%s carries %d firewalls at the end, want 2", vm.name, got)
		}
	}

	// R6: traefik-public-relay joins the relay VM on the per-VM edge. It is one
	// PUT of the relay VM's firewall, and the count stays at two.
	puts, creates := len(m.api.updatedFirewalls), len(m.api.createdFirewalls)
	m.addService("traefik-public-relay", "traefik-public-relay-uid", traefikPorts(), []string{mgRelay.name})
	m.runUntil(800, "traefik-public-relay is published", func() bool {
		svc := m.service("traefik-public-relay")
		return len(svc.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(svc)
	})
	if len(m.api.updatedFirewalls) != puts+1 || len(m.api.createdFirewalls) != creates {
		t.Errorf("R6: PUTs %d -> %d, creates %d -> %d, want exactly one PUT and no create",
			puts, len(m.api.updatedFirewalls), creates, len(m.api.createdFirewalls))
	}
	if got := len(m.firewallsOf(mgRelay)); got != 2 || m.gate.maxObservedFirewallsPerVM > 3 {
		t.Errorf("R6: relay carries %d firewalls (peak %d)", got, m.gate.maxObservedFirewallsPerVM)
	}
	if rules := len(m.perVMFirewall(mgRelay).Rules); rules != 5 {
		t.Errorf("R6: the relay firewall has %d rules, want 1935, 1936, 80, 443/tcp, 443/udp", rules)
	}
}

// migrationOutcome is what a finished migration must look like, whatever
// crashed on the way.
type migrationOutcome struct {
	firewalls map[string][]string // VM name -> sorted "name:rules" of its firewalls
	modes     map[string]string
	deleted   []string
	history   map[string][]int
	creates   int
	puts      int
	writes    int
	crashed   bool
}

func (m *migrationCluster) outcome(writes int) migrationOutcome {
	m.t.Helper()
	out := migrationOutcome{firewalls: map[string][]string{}, modes: map[string]string{}, history: map[string][]int{},
		creates: len(m.api.createdFirewalls), puts: len(m.api.updatedFirewalls), writes: writes}
	for _, vm := range m.vms {
		var rows []string
		for _, firewall := range m.firewallsOf(vm) {
			rows = append(rows, fmt.Sprintf("%s:%d", firewall.EffectiveName(), len(firewall.Rules)))
		}
		sort.Strings(rows)
		out.firewalls[vm.name] = rows
		out.history[vm.name] = m.history[vm.uuid]
	}
	for _, name := range m.services {
		out.modes[name] = m.service(name).Annotations[annotationPublicNodeLocalFirewallMode]
	}
	// Firewall UUIDs depend on creation order only, which a crash does not change.
	out.deleted = append(out.deleted, m.api.deletedFirewalls...)
	sort.Strings(out.deleted)
	return out
}
