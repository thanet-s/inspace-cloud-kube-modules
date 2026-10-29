package cloudprovider

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// deleteService deletes a Service the way the apiserver does: it gets a
// deletion timestamp, the Service pass withdraws and removes its finalizer, and
// only then is the object gone.
func (m *migrationCluster) deleteService(name string) {
	m.t.Helper()
	svc := m.service(name)
	now := metav1.Now()
	svc.DeletionTimestamp = &now
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Update(m.ctx, svc, metav1.UpdateOptions{}); err != nil {
		m.t.Fatal(err)
	}
	var last error
	for pass := 0; pass < 400; pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		m.ageCleanupAbsence(name)
		err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name))
		last = err
		if !tolerableMigrationError(err) {
			m.t.Fatalf("deleting %s: %v", name, err)
		}
		for _, vm := range m.vms {
			if vmErr := m.controller.syncVMFirewall(m.ctx, vm.uuid); !tolerableMigrationError(vmErr) {
				m.t.Fatalf("VM pass of %s while deleting %s: %v", vm.name, name, vmErr)
			}
		}
		if !containsString(m.service(name).Finalizers, publicNodeLocalFinalizer) {
			break
		}
	}
	if containsString(m.service(name).Finalizers, publicNodeLocalFinalizer) {
		m.t.Fatalf("%s kept its finalizer; last pass: %v; annotations %v", name, last, m.service(name).Annotations)
	}
	if err := m.kube.CoreV1().Services(svc.Namespace).Delete(m.ctx, name, metav1.DeleteOptions{}); err != nil {
		m.t.Fatal(err)
	}
	kept := m.services[:0]
	for _, known := range m.services {
		if known != name {
			kept = append(kept, known)
		}
	}
	m.services = kept
	m.refreshEndpoints()
}

// ageCleanupAbsence moves the last absent read of a deleting Service's cleanup
// back by the confirmation delay. The cleanup spaces those reads on the wall
// clock, which a test does not wait for.
func (m *migrationCluster) ageCleanupAbsence(name string) {
	m.t.Helper()
	svc := m.service(name)
	raw := svc.Annotations[annotationNodeLoadBalancerCleanupFWChecked]
	if raw == "" {
		return
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		m.t.Fatal(err)
	}
	svc.Annotations[annotationNodeLoadBalancerCleanupFWChecked] = at.Add(-nodeLoadBalancerAbsenceConfirmationDelay - time.Second).Format(time.RFC3339Nano)
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Update(m.ctx, svc, metav1.UpdateOptions{}); err != nil {
		m.t.Fatal(err)
	}
}

func rulePorts(firewall *inspace.Firewall) map[int32]bool {
	ports := map[int32]bool{}
	if firewall != nil {
		for _, rule := range firewall.Rules {
			ports[*rule.PortStart] = true
		}
	}
	return ports
}

// M1: a finished migration keeps its record for the pacing of the next VM, and
// that record must not take the VM out of its ordinary upkeep.
func TestVMFirewallMigrationDoneVMStaysUnderUpkeep(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(300, "the first gateway is done", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseDone))
	for pass := 0; pass < 3; pass++ {
		_ = m.vmRound()
	}
	if err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid); err != nil && !tolerableMigrationError(err) {
		t.Fatalf("steady done VM: %v", err)
	}
	// Someone edits the per-VM firewall behind the CCM's back: upkeep reports it.
	name := m.perVMFirewall(mgGateway1).EffectiveName()
	for index := range m.api.firewalls {
		if m.api.firewalls[index].EffectiveName() == name {
			port := int32(9999)
			m.api.firewalls[index].Rules = append(m.api.firewalls[index].Rules, inspace.FirewallRule{
				UUID: "dddddddd-0000-4000-8000-000000000001", Protocol: "tcp", Direction: "inbound",
				PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			})
		}
	}
	err := m.controller.syncVMFirewall(m.ctx, mgGateway1.uuid)
	if !errors.Is(err, errVMFirewallDrift) {
		t.Fatalf("done VM with a drifted firewall: %v, want drift", err)
	}
}

// M2: a Service deleted while its VM is being migrated takes its ports off the
// per-VM firewall, and only its own; the other Service on the VM keeps its.
func TestVMFirewallMigrationDeletedServiceLeavesThePerVMFirewall(t *testing.T) {
	m := newMigrationCluster(t, mgGateway1, mgGateway2)
	m.provider.config.NodeLoadBalancer.MaxFirewallsPerVM = 4
	m.gate.limit = 4
	m.addService("traefik-public", "traefik-public-uid", traefikPorts(), []string{mgGateway1.name, mgGateway2.name})
	m.publish("traefik-public")
	m.addService("other", "other-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 9000)}, []string{mgGateway1.name})
	m.publish("other")
	m.switchToPerVM(VMFirewallMigrationManual)
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(300, "the per-VM firewall is open", m.phaseIs(mgGateway1, vmFirewallMigrationPhaseOpened))

	m.deleteService("traefik-public")
	m.runUntil(600, "the first gateway is done and swept", func() bool {
		plan := m.plan(mgGateway1)
		ports := rulePorts(m.perVMFirewall(mgGateway1))
		return plan != nil && plan.Phase == vmFirewallMigrationPhaseDone && !ports[80] && !ports[443]
	})
	if ports := rulePorts(m.perVMFirewall(mgGateway1)); !ports[9000] || len(ports) != 1 {
		t.Fatalf("the per-VM firewall allows %v, want only the other Service's 9000", ports)
	}
	m.runUntil(600, "the other Service is on the per-VM firewall", m.servicePerVM("other"))
	if len(m.service("other").Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("the other Service lost its status: %#v", m.service("other").Status)
	}
	if m.gate.maxObservedFirewallsPerVM > 4 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

// L1: a rename changes display_name only. The adopted firewall keeps its old
// list name, and the per-VM firewall can still be updated.
func TestVMFirewallMigrationAdoptedFirewallStaysUpdatable(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	prod := m.firewallOfService("relay-prod")
	m.annotateNode(mgRelay.name, "true")
	m.runUntil(300, "the relay VM is done", m.phaseIs(mgRelay, vmFirewallMigrationPhaseDone))
	perVM := m.perVMFirewall(mgRelay)
	if perVM.Name != prod.Name || perVM.DisplayName == perVM.Name {
		t.Fatalf("name=%q display_name=%q: the fake must leave name alone on a rename", perVM.Name, perVM.DisplayName)
	}
	if perVM.Description != "" {
		t.Fatalf("the fake stored a description: %q", perVM.Description)
	}
	puts := len(m.api.updatedFirewalls)
	m.runUntil(600, "both Services are flipped", func() bool {
		return publicNodeLocalServicePerVM(m.service("relay-prod")) && publicNodeLocalServicePerVM(m.service("relay-staging"))
	})
	m.addService("late", "late-uid", []corev1.ServicePort{mgPort(corev1.ProtocolTCP, 8080)}, []string{mgRelay.name})
	m.runUntil(600, "the late Service is published", func() bool {
		svc := m.service("late")
		return len(svc.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(svc)
	})
	if len(m.api.updatedFirewalls) != puts+1 || !rulePorts(m.perVMFirewall(mgRelay))[8080] {
		t.Fatalf("PUTs %d -> %d: the adopted firewall was not updated", puts, len(m.api.updatedFirewalls))
	}
}

// L2: the Service whose firewall was renamed into the per-VM firewall is
// deleted before it flips. Its emergency detach does not touch the shared
// firewall; its entry leaves the ledger and the other Service keeps serving.
func TestVMFirewallMigrationDeletingTheAdopteeServiceFinishesSafely(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgRelay.name, "true")
	m.runUntil(300, "the adopt landed", func() bool { return m.perVMFirewall(mgRelay) != nil })
	if publicNodeLocalServicePerVM(m.service("relay-prod")) {
		t.Fatal("the Service flipped before the test deleted it")
	}
	perVMUUID := m.perVMFirewall(mgRelay).UUID
	m.deleteService("relay-prod")
	for _, unassigned := range m.api.unassignedFirewalls {
		if strings.HasPrefix(unassigned, perVMUUID+"/") {
			t.Fatalf("the shared per-VM firewall was detached: %v", m.api.unassignedFirewalls)
		}
	}
	m.runUntil(600, "the relay VM is done and swept", func() bool {
		plan := m.plan(mgRelay)
		return plan != nil && plan.Phase == vmFirewallMigrationPhaseDone && !rulePorts(m.perVMFirewall(mgRelay))[1935]
	})
	if ports := rulePorts(m.perVMFirewall(mgRelay)); !ports[1936] || len(ports) != 1 {
		t.Fatalf("the per-VM firewall allows %v, want only 1936", ports)
	}
	m.runUntil(600, "the staging Service is flipped", m.servicePerVM("relay-staging"))
	if got := len(m.firewallsOf(mgRelay)); got != 2 || m.gate.maxObservedFirewallsPerVM > 3 {
		t.Fatalf("relay carries %d firewalls (peak %d)", got, m.gate.maxObservedFirewallsPerVM)
	}
}

// Without the perVM mode (a rollback before the reverse migration exists) nobody
// can take the entry of a Service off the per-VM firewall, so deleting the
// Service whose firewall was adopted holds fail-closed instead of finalizing it
// with its port still open.
func TestVMFirewallMigrationDeletingTheAdopteeServiceHoldsInPerServiceMode(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.annotateNode(mgRelay.name, "true")
	m.runUntil(300, "the adopt landed", func() bool { return m.perVMFirewall(mgRelay) != nil })
	m.provider.config.NodeLoadBalancer.LocalFirewallMode = PublicNodeLocalFirewallModePerService
	m.restart()

	svc := m.service("relay-prod")
	now := metav1.Now()
	svc.DeletionTimestamp = &now
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Update(m.ctx, svc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	var last error
	for pass := 0; pass < 30; pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		last = m.controller.syncPublicNodeLocal(m.ctx, m.key("relay-prod"), m.service("relay-prod"))
	}
	if last == nil || !strings.Contains(last.Error(), "lost deterministic Service identity") {
		t.Fatalf("deletion pass = %v, want the fail-closed identity hold", last)
	}
	if !containsString(m.service("relay-prod").Finalizers, publicNodeLocalFinalizer) {
		t.Fatal("the Service was finalized with its port still open")
	}
	if perVM := m.perVMFirewall(mgRelay); perVM == nil || !rulePorts(perVM)[1935] || !vmFirewallAttachedTo(*perVM, mgRelay.uuid) {
		t.Fatal("the per-VM firewall no longer serves 1935")
	}
}

// L3: an abort takes an entry off the per-VM firewall only when its Service is
// gone or its own firewall is still on the VM to cover it.
func TestVMFirewallMigrationAbortKeepsAnEntryNothingElseCovers(t *testing.T) {
	m := newGatewayCluster(t, VMFirewallMigrationManual)
	source := m.firewallOfService("traefik-public")
	m.annotateNode(mgGateway1.name, "true")
	m.runUntil(200, "the per-VM firewall is attached", func() bool {
		firewall := m.perVMFirewall(mgGateway1)
		return firewall != nil && vmFirewallAttachedTo(*firewall, mgGateway1.uuid)
	})
	// The Service's own firewall is off the VM (some other actor detached it) and
	// the Service changed: the plan aborts, but the per-VM firewall is now the
	// only thing that serves the ports.
	if err := m.api.UnassignFirewallFromVM(m.ctx, "bkk01", source.UUID, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	m.setServiceAnnotation("traefik-public", annotationPublicNodeLocalTargetPolicy, "00000000")
	var last error
	for pass := 0; pass < 20; pass++ {
		last = m.vmRound()[mgGateway1.name]
	}
	if last == nil || !strings.Contains(last.Error(), "its entry stays") {
		t.Fatalf("the abort = %v, want it to hold", last)
	}
	if m.perVMFirewall(mgGateway1) == nil || !rulePorts(m.perVMFirewall(mgGateway1))[443] {
		t.Fatal("the abort narrowed the only firewall that serves the Service")
	}
	// Once the Service's own firewall covers the VM again the abort goes on.
	if err := m.api.AssignFirewallToVM(m.ctx, "bkk01", source.UUID, mgGateway1.uuid); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 200 && m.anchor(mgGateway1) != nil; pass++ {
		if err := m.vmRound()[mgGateway1.name]; !tolerableMigrationError(err) {
			t.Fatal(err)
		}
	}
	if m.anchor(mgGateway1) != nil || m.perVMFirewall(mgGateway1) != nil {
		t.Fatal("the abort did not finish after the Service's firewall came back")
	}
}
