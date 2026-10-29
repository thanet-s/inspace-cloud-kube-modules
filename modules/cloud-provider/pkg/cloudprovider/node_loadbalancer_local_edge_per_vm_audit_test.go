package cloudprovider

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func perVMFirewallIndexOfFixtureVM(t *testing.T, f *publicNodeLocalTransientFixture, vmUUID string) int {
	t.Helper()
	for index := range f.api.firewalls {
		if _, isVM := parseVMFirewallNameForTest(f, f.api.firewalls[index].EffectiveName()); isVM {
			for _, row := range f.api.firewalls[index].ResourcesAssigned {
				if row.ResourceUUID == vmUUID {
					return index
				}
			}
		}
	}
	t.Fatalf("VM %s has no per-VM firewall", vmUUID)
	return -1
}

func TestPerVMAuditAcceptsAnchoredFirewall(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	if err := auditFixtureVM0(t, f); err != nil {
		t.Fatalf("a per-VM firewall that matches its anchor must pass the audit: %v", err)
	}
}

func TestPerVMAuditRejectsHashMismatch(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	index := perVMFirewallIndexOfFixtureVM(t, f, vm0)
	port := int32(9999)
	f.api.firewalls[index].Rules = append(f.api.firewalls[index].Rules, inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	})
	err := auditFixtureVM0(t, f)
	if err == nil || !strings.Contains(err.Error(), "does not match its anchor") {
		t.Fatalf("audit of a drifted per-VM firewall = %v", err)
	}
}

func TestPerVMAuditRejectsSecondPerVMFirewall(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	index := perVMFirewallIndexOfFixtureVM(t, f, vm0)
	second := f.api.firewalls[index]
	second.UUID = "70000000-0000-4000-8000-0000000000aa"
	second.ResourcesAssigned = append([]inspace.FirewallResource(nil), second.ResourcesAssigned...)
	f.api.firewalls = append(f.api.firewalls, second)
	if err := auditFixtureVM0(t, f); err == nil {
		t.Fatal("a second per-VM firewall on a VM must be refused")
	}
}

func TestPerVMAuditHoldsAndQueuesAFirewallWithoutAnchor(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	if err := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace).Delete(f.ctx, vmFirewallAnchorName(vm0), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	err := auditFixtureVM0(t, f)
	if err == nil || !strings.Contains(err.Error(), "no anchor records") {
		t.Fatalf("audit without an anchor = %v", err)
	}
	if f.controller.queue.Len() == 0 {
		t.Fatal("the VM was not queued for its ledger rebuild")
	}
}

// Next to a per-VM firewall, a per-Service firewall is accepted only while the
// anchor's migration is retiring it.
func TestPerVMAuditAcceptsPlannedSourcesOnlyDuringMigration(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	other := publicNodeLocalTestService("other", "other-service-uid", "edge", corev1.ProtocolTCP, 8080)
	desired, err := f.controller.desiredServiceFirewall(other)
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.api.CreateFirewall(f.ctx, "bkk01", desired.Request)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.api.AssignFirewallToVM(f.ctx, "bkk01", created.UUID, vm0); err != nil {
		t.Fatal(err)
	}
	const unauthorized = "next to its per-VM firewall"
	if err := auditFixtureVM0(t, f); err == nil || !strings.Contains(err.Error(), unauthorized) {
		t.Fatalf("an unlisted per-Service firewall next to the per-VM one = %v", err)
	}
	setPlan := func(phase string) {
		anchor := f.anchorOf(t, vm0)
		plan := fmt.Sprintf(`{"phase":%q,"sources":[{"firewall":%q}]}`, phase, created.UUID)
		if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
			cm.Annotations[annotationVMFirewallMigration] = plan
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	setPlan("detaching")
	if err := auditFixtureVM0(t, f); err != nil && strings.Contains(err.Error(), unauthorized) {
		t.Fatalf("a firewall the migration retires must pass the gate: %v", err)
	}
	setPlan("done")
	if err := auditFixtureVM0(t, f); err == nil || !strings.Contains(err.Error(), unauthorized) {
		t.Fatalf("a per-Service firewall after the migration is done = %v", err)
	}
}
