package cloudprovider

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// switchToPerService turns the controller back into the default perService mode,
// as a restart with the flag removed does. The namespace of the anchors stays,
// as the chart sets it in every mode.
func (m *migrationCluster) switchToPerService() {
	m.t.Helper()
	m.provider.config.NodeLoadBalancer.LocalFirewallMode = PublicNodeLocalFirewallModePerService
	m.restart()
}

// migrateTHLiveForward is the forward migration of th-live, in rollout order, to
// its end state: three VMs on one per-VM firewall each, three Services on the
// per-VM edge.
func migrateTHLiveForward(m *migrationCluster) {
	m.t.Helper()
	for _, vm := range []migrationVM{mgGateway1, mgGateway2, mgRelay} {
		m.annotateNode(vm.name, "true")
		m.runUntil(800, vm.name+" is done", m.phaseIs(vm, vmFirewallMigrationPhaseDone))
	}
	m.runUntil(800, "every Service is on the per-VM firewall", m.allMigrated)
}

// anchorsLeft counts the VM firewall anchors of the cluster.
func (m *migrationCluster) anchorsLeft() int {
	m.t.Helper()
	list, err := m.kube.CoreV1().ConfigMaps(vmTestNamespace).List(m.ctx, metav1.ListOptions{})
	if err != nil {
		m.t.Fatal(err)
	}
	return len(list.Items)
}

// perVMFirewallsLeft counts the firewalls in the cloud that carry a per-VM name.
func (m *migrationCluster) perVMFirewallsLeft() int {
	count := 0
	for _, firewall := range m.api.firewalls {
		if _, ok := inspace.ParseNodeLoadBalancerVMFirewallName(m.provider.config.ClusterID, firewall.EffectiveName()); ok {
			count++
		}
	}
	return count
}

func (m *migrationCluster) allReversed() bool {
	if m.anchorsLeft() != 0 {
		return false
	}
	for _, name := range m.services {
		svc := m.service(name)
		if publicNodeLocalServicePerVM(svc) || svc.Annotations[annotationNodeLoadBalancerFirewallUUID] == "" {
			return false
		}
	}
	return true
}

// The reverse migration of th-live after the per-VM mode is turned off: the
// gateways (one Service on two VMs) take base plus the Service firewall; the
// relay VM (two Services, so one create and one rename) takes base plus two
// Service firewalls. No VM carries a fourth firewall at any call, every port
// that serves stays allowed between any two cloud calls, no Service changes its
// status or VIPs, and no per-VM state is left.
func TestReverseMigrationRunsWhenFlagOff(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	perVMOfRelay := m.perVMFirewall(mgRelay)
	if perVMOfRelay == nil || m.anchorsLeft() != 3 {
		t.Fatalf("the forward end state is not what the test starts from: anchors %d", m.anchorsLeft())
	}
	m.trackCoverage()
	before := m.statusSnapshot()
	creates, deletes := len(m.api.createdFirewalls), len(m.api.deletedFirewalls)

	m.switchToPerService()
	m.runUntil(1500, "every VM is reversed", m.allReversed)

	if now := m.statusSnapshot(); !reflect.DeepEqual(now, before) {
		t.Fatalf("a Service changed its status or VIPs during the reverse migration:\n before %v\n after  %v", before, now)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	if left := m.perVMFirewallsLeft(); left != 0 {
		t.Errorf("%d per-VM firewalls are left", left)
	}
	for _, name := range m.services {
		svc := m.service(name)
		if publicNodeLocalServicePerVM(svc) {
			t.Errorf("%s is still on the per-VM edge: %#v", name, svc.Annotations)
		}
		if firewall := m.firewallOfService(name); firewall == nil || firewall.EffectiveName() != nodeLoadBalancerFirewallName(
			m.provider.config.ClusterID, string(svc.UID), svc.Annotations[annotationNodeLoadBalancerFirewallHash]) {
			t.Errorf("%s: own firewall %#v", name, firewall)
		}
	}
	for _, vm := range []migrationVM{mgGateway1, mgGateway2} {
		if got := len(m.firewallsOf(vm)); got != 2 {
			t.Errorf("%s carries %d firewalls, want base and the Service firewall", vm.name, got)
		}
		if got := m.history[vm.uuid]; !reflect.DeepEqual(got, []int{2, 3, 2}) {
			t.Errorf("%s firewalls over time = %v, want [2 3 2]", vm.name, got)
		}
	}
	if got := len(m.firewallsOf(mgRelay)); got != 3 {
		t.Errorf("the relay VM carries %d firewalls, want base and two Service firewalls", got)
	}
	if got := m.history[mgRelay.uuid]; !reflect.DeepEqual(got, []int{2, 3}) {
		t.Errorf("relay firewalls over time = %v, want [2 3] (one attach, one rename, never 4)", got)
	}
	// The gateways share one firewall of traefik-public; the relay VM renamed its
	// per-VM firewall into one of the two Services' and created the other.
	if got := len(m.api.createdFirewalls) - creates; got != 2 {
		t.Errorf("%d firewalls were created, want traefik-public's and one relay Service's", got)
	}
	if got := len(m.api.deletedFirewalls) - deletes; got != 2 {
		t.Errorf("%d firewalls were deleted, want the two gateway per-VM firewalls", got)
	}
	// The Services serve on again as ordinary per-Service Services.
	for pass := 0; pass < 5; pass++ {
		m.round()
	}
	if now := m.statusSnapshot(); !reflect.DeepEqual(now, before) {
		t.Fatalf("a Service changed after the reverse migration:\n before %v\n after  %v", before, now)
	}
	if got := len(m.api.createdFirewalls) - creates; got != 2 {
		t.Errorf("the Services created %d firewalls after the reverse, want none more", got-2)
	}
	for _, vm := range m.vms {
		if got := len(m.firewallsOf(vm)); got > 3 {
			t.Errorf("%s carries %d firewalls", vm.name, got)
		}
	}
}

// A VM with three Services can not exist in the per-Service mode: base plus three
// firewalls is a fourth on a three-firewall VM. The reverse says so on every
// Service of the VM and changes nothing, for as long as it stays that way.
func TestReverseMigrationRefusesKThree(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.addService("traefik-public-relay", "traefik-public-relay-uid", traefikPorts(), []string{mgRelay.name})
	m.runUntil(800, "traefik-public-relay is published", func() bool {
		svc := m.service("traefik-public-relay")
		return len(svc.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(svc)
	})
	m.trackCoverage()
	before := m.statusSnapshot()
	writes := m.writes()

	m.switchToPerService()
	// A block is an error the work queue retries with backoff, like a hold.
	roundWithBlocks := func() {
		t.Helper()
		m.clock = m.clock.Add(7 * time.Second)
		for _, vm := range m.vms {
			var blocked *errVMFirewallMigrationBlocked
			if err := m.controller.syncVMFirewall(m.ctx, vm.uuid); !tolerableMigrationError(err) && !errors.As(err, &blocked) {
				t.Fatalf("VM pass of %s: %v", vm.name, err)
			}
		}
		for _, name := range m.services {
			if err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name)); !tolerableMigrationError(err) {
				t.Fatalf("Service pass of %s: %v", name, err)
			}
		}
	}
	for pass := 0; pass < 120; pass++ {
		roundWithBlocks()
	}
	// The two gateways have k=1 and go back; the relay VM stays as it is.
	if m.anchor(mgRelay) == nil || m.perVMFirewall(mgRelay) == nil {
		t.Fatal("the per-VM firewall of the VM with three Services was touched")
	}
	if plan := m.plan(mgRelay); plan != nil && plan.Direction == vmFirewallMigrationDirectionReverse {
		t.Fatalf("a reverse plan was recorded for k=3: %#v", plan)
	}
	if got := len(m.firewallsOf(mgRelay)); got != 2 {
		t.Errorf("the relay VM carries %d firewalls, want base and the per-VM firewall", got)
	}
	blocked := 0
	list, err := m.kube.CoreV1().Events(metav1.NamespaceAll).List(m.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range list.Items {
		if event.Reason == publicNodeLocalReasonVMFirewallMigrationBlocked && strings.Contains(event.Message, "k exceeds per-Service capacity") {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("no Blocked Event names the VM with three Services")
	}
	for _, name := range []string{"relay-prod", "relay-staging", "traefik-public-relay"} {
		if !publicNodeLocalServicePerVM(m.service(name)) {
			t.Errorf("%s left the per-VM edge", name)
		}
	}
	if now := m.statusSnapshot(); !reflect.DeepEqual(now, before) {
		t.Fatalf("a Service changed its status or VIPs:\n before %v\n after  %v", before, now)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	// traefik-public is on the gateways only, so it did not move with the relay VM held.
	_ = writes
	// Nothing more happens, ever: another stretch of passes writes nothing.
	steady := m.writes()
	for pass := 0; pass < 40; pass++ {
		roundWithBlocks()
	}
	if m.writes() != steady {
		t.Errorf("the held VM changed the cloud again: %d writes", m.writes()-steady)
	}
}

// The mode is turned off on a cluster that never migrated: the Service passes
// read no ConfigMap, write nothing, and the Services serve as they always did.
func TestPerServiceModeWithoutPerVMStateTouchesNoConfigMap(t *testing.T) {
	m := newTHLiveCluster(t)
	m.switchToPerService()
	configMapCalls := 0
	m.kube.PrependReactor("*", "configmaps", func(action kubetesting.Action) (bool, runtime.Object, error) {
		configMapCalls++
		return false, nil, nil
	})
	writes := m.writes()
	for pass := 0; pass < 10; pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		for _, name := range m.services {
			if err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name)); !tolerableMigrationError(err) {
				t.Fatalf("Service pass of %s: %v", name, err)
			}
		}
	}
	if configMapCalls != 0 {
		t.Errorf("%d ConfigMap calls in the perService mode without per-VM state", configMapCalls)
	}
	if m.writes() != writes {
		t.Errorf("%d cloud writes with nothing to do", m.writes()-writes)
	}
}
