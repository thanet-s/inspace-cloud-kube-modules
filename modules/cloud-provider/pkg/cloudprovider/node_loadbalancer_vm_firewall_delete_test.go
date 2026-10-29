package cloudprovider

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// deleteHookAPI runs a hook just before a DELETE reaches the fake cloud.
type deleteHookAPI struct {
	API
	before func(uuid string)
}

func (a *deleteHookAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	if a.before != nil {
		a.before(uuid)
	}
	return a.API.DeleteFirewall(ctx, location, uuid)
}

// stepUntil repeats a step until done reports true; a bounded wait advances the
// clock by its own retry time and one second.
func (f *vmFirewallFixture) stepUntil(vmUUID string, delta vmFirewallDelta, done func() bool) {
	f.t.Helper()
	for pass := 0; pass < 120; pass++ {
		if done() {
			return
		}
		if _, err := f.step(vmUUID, delta, nil); err != nil {
			var pending *nodeLoadBalancerFirewallRelationPendingError
			if !errors.As(err, &pending) {
				f.t.Fatalf("pass %d: %v", pass, err)
			}
			f.advance(pending.retryAfter + time.Second)
		}
	}
	f.t.Fatal("the condition was never reached")
}

func TestVMFirewallStepRemoveLastDetachesAndDeletes(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	member := f.member(service)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	rowsAtDelete := -1
	f.provider.api = &deleteHookAPI{API: f.gate, before: func(uuid string) {
		for _, fw := range f.api.firewalls {
			if fw.UUID == uuid {
				rowsAtDelete = len(fw.ResourcesAssigned)
			}
		}
	}}
	start := f.clock
	result := f.stepUntilConverged(vmTestVM, removeDelta(member))
	if !result.Converged {
		t.Fatal("removing the last member must converge")
	}
	if rowsAtDelete != 0 {
		t.Fatalf("the firewall still had %d assignments when it was deleted", rowsAtDelete)
	}
	if len(f.api.unassignedFirewalls) != 1 || len(f.api.deletedFirewalls) != 1 || len(f.api.updatedFirewalls) != 0 {
		t.Fatalf("unassigned=%v deleted=%v PUTs=%d: the last member's closure is the detach, never an empty PUT",
			f.api.unassignedFirewalls, f.api.deletedFirewalls, len(f.api.updatedFirewalls))
	}
	if f.anchor(vmTestVM) != nil {
		t.Fatal("the anchor must be deleted last")
	}
	if f.vmFirewall(vmTestVM) != nil || f.firewallCount(vmTestVM) != 1 {
		t.Fatalf("firewalls on the VM = %d, want only the base firewall", f.firewallCount(vmTestVM))
	}
	if elapsed := f.clock.Sub(start); elapsed < 2*nodeLoadBalancerAbsenceConfirmationDelay {
		t.Fatalf("only %s passed: three absent reads need two confirmation delays", elapsed)
	}
}

func TestVMFirewallDeleteVisibilityResetsAbsence(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	member := f.member(service)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	var removed inspace.Firewall
	for _, fw := range f.api.firewalls {
		if fw.UUID == vmTestFirewallUUID {
			removed = fw
		}
	}
	f.stepUntil(vmTestVM, removeDelta(member), func() bool { return len(f.api.deletedFirewalls) == 1 })
	count := func() int {
		raw := f.anchor(vmTestVM).Annotations[annotationVMFirewallAbsenceCount]
		n, _ := strconv.Atoi(raw)
		return n
	}
	f.stepUntil(vmTestVM, removeDelta(member), func() bool { return count() == 2 })

	// The listing shows the firewall again: the count starts over, and the
	// DELETE is not sent a second time inside the retire delay.
	removed.ResourcesAssigned = nil
	f.api.firewalls = append(f.api.firewalls, removed)
	f.advance(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	if _, err := f.step(vmTestVM, removeDelta(member), nil); err != nil {
		var pending *nodeLoadBalancerFirewallRelationPendingError
		if !errors.As(err, &pending) {
			t.Fatal(err)
		}
	}
	if count() != 0 || len(f.api.deletedFirewalls) != 1 {
		t.Fatalf("absence count = %d, DELETEs = %d: visibility must reset the count and not re-send", count(), len(f.api.deletedFirewalls))
	}
	// It disappears again: three fresh absent reads are needed.
	f.api.firewalls = f.api.firewalls[:len(f.api.firewalls)-1]
	f.stepUntil(vmTestVM, removeDelta(member), func() bool { return count() == 1 })
	f.stepUntil(vmTestVM, removeDelta(member), func() bool { return count() == 2 })
	if f.anchor(vmTestVM) == nil {
		t.Fatal("two reads after the reset must not finish the delete")
	}
	f.stepUntilConverged(vmTestVM, removeDelta(member))
	if f.anchor(vmTestVM) != nil || len(f.api.deletedFirewalls) != 1 {
		t.Fatal("the delete must finish after three fresh reads without another DELETE")
	}
}

func TestVMFirewallRepairIsSingleUse(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1), f.member(s2))
	// A console edit.
	port := int32(22)
	for index := range f.api.firewalls {
		if f.api.firewalls[index].UUID == vmTestFirewallUUID {
			f.api.firewalls[index].Rules[0].PortStart = &port
			f.api.firewalls[index].Rules[0].PortEnd = &port
		}
	}
	if _, err := f.step(vmTestVM, addDelta(f.member(s1)), nil); !errors.Is(err, errVMFirewallDrift) {
		t.Fatalf("error = %v, want drift", err)
	}
	if err := f.controller.repairVMFirewall(f.ctx, f.anchor(vmTestVM)); err == nil {
		t.Fatal("a repair without the annotation must be refused")
	}
	if len(f.api.updatedFirewalls) != 0 {
		t.Fatal("no repair was requested, so no PUT may be made")
	}
	f.setAnchor(vmTestVM, func(a map[string]string) { a[annotationVMFirewallRepair] = "yes" })
	if err := f.controller.repairVMFirewall(f.ctx, f.anchor(vmTestVM)); err != nil {
		t.Fatal(err)
	}
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("PUTs = %d, want exactly the repair", len(f.api.updatedFirewalls))
	}
	if got := ruleSummary(f.api.updatedFirewalls[0].Rules); !reflect.DeepEqual(got, []string{"tcp/1935/any/", "tcp/1936/any/"}) {
		t.Fatalf("the repair PUT carries merged(applied): %v", got)
	}
	annotations := f.anchor(vmTestVM).Annotations
	if annotations[annotationVMFirewallRepair] != "" {
		t.Fatal("the repair annotation must go in the commit")
	}
	f.requireNoReceipt(vmTestVM)
	if err := f.controller.repairVMFirewall(f.ctx, f.anchor(vmTestVM)); err == nil {
		t.Fatal("the repair is single use")
	}
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatal("a second repair attempt must not PUT")
	}
	if result, err := f.step(vmTestVM, addDelta(f.member(s1)), nil); err != nil || !result.Converged {
		t.Fatalf("the repaired VM must converge: %v, %v", result, err)
	}
}

func TestVMFirewallRebuildByAttribution(t *testing.T) {
	setup := func(t *testing.T, extra func(*vmFirewallFixture)) (*vmFirewallFixture, inspace.Firewall) {
		f := newVMFirewallFixture(t)
		s1 := f.addService("svc-a", 1935)
		s2 := f.addService("svc-b", 1936)
		s2.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
		if _, err := f.provider.kubeClient.CoreV1().Services(s2.Namespace).Update(f.ctx, s2, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1), f.member(s2))
		// The anchor is lost together with its finalizer.
		cms := f.provider.kubeClient.CoreV1().ConfigMaps(vmTestNamespace)
		anchor := f.anchor(vmTestVM)
		anchor.Finalizers = nil
		if _, err := cms.Update(f.ctx, anchor, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := cms.Delete(f.ctx, anchor.Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if extra != nil {
			extra(f)
		}
		return f, *f.vmFirewall(vmTestVM)
	}
	services := func(f *vmFirewallFixture) []corev1.Service {
		out := []corev1.Service{}
		for _, s := range f.members(f.ctx) {
			out = append(out, *s)
		}
		return out
	}
	t.Run("exact attribution writes the ledger", func(t *testing.T) {
		f, fw := setup(t, nil)
		if err := f.controller.rebuildVMFirewallAnchor(f.ctx, vmTestVM, fw, services(f)); err != nil {
			t.Fatal(err)
		}
		view := vmFirewallAnchorView{cm: f.anchor(vmTestVM)}
		applied, err := view.applied()
		if err != nil || len(applied.Members) != 2 || view.uuid() != vmTestFirewallUUID {
			t.Fatalf("applied = %#v uuid=%q err=%v", applied, view.uuid(), err)
		}
		hash, _ := inspace.NodeLoadBalancerVMFirewallSpecHash(fw.Rules)
		if view.appliedHash() != hash {
			t.Fatalf("applied-hash %q, firewall %q", view.appliedHash(), hash)
		}
		if got := f.eventsFor("PublicNodeLocalVMFirewallLedgerRebuilt"); len(got) != 2 {
			t.Fatalf("LedgerRebuilt Events = %d, want one per member", len(got))
		}
		if len(f.api.updatedFirewalls)+len(f.api.createdFirewalls) != 0 {
			t.Fatal("a rebuild must never mutate the cloud")
		}
		if result, err := f.step(vmTestVM, addDelta(f.member(f.members(f.ctx)[0])), nil); err != nil || !result.Converged {
			t.Fatalf("a rebuilt VM must converge without a PUT: %v, %v", result, err)
		}
	})
	t.Run("two possible owners of one rule hold", func(t *testing.T) {
		f, fw := setup(t, func(f *vmFirewallFixture) { f.addService("svc-c", 1935) })
		err := f.controller.rebuildVMFirewallAnchor(f.ctx, vmTestVM, fw, services(f))
		if !errors.Is(err, errVMFirewallDrift) {
			t.Fatalf("error = %v, want a hold", err)
		}
		if f.anchor(vmTestVM) != nil || len(f.api.updatedFirewalls) != 0 {
			t.Fatal("an ambiguous attribution must write nothing")
		}
	})
	t.Run("a rule nobody owns holds", func(t *testing.T) {
		f, fw := setup(t, func(f *vmFirewallFixture) {
			port := int32(22)
			for index := range f.api.firewalls {
				if f.api.firewalls[index].UUID == vmTestFirewallUUID {
					f.api.firewalls[index].Rules = append(f.api.firewalls[index].Rules, inspace.FirewallRule{
						Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
					})
				}
			}
		})
		err := f.controller.rebuildVMFirewallAnchor(f.ctx, vmTestVM, *f.vmFirewall(vmTestVM), services(f))
		_ = fw
		if !errors.Is(err, errVMFirewallDrift) {
			t.Fatalf("error = %v, want a hold", err)
		}
		if f.anchor(vmTestVM) != nil {
			t.Fatal("an unowned rule must write nothing")
		}
		if len(f.eventsFor(vmFirewallDriftReason)) == 0 {
			t.Fatal("a hold must be visible as an Event")
		}
	})
}

func TestVMFirewallOrphanGC(t *testing.T) {
	orphan := func(f *vmFirewallFixture, attached bool) inspace.Firewall {
		name, _ := inspace.NodeLoadBalancerVMFirewallName(vmTestCluster, vmTestVM)
		fw := perVMTestFirewall(t, vmTestCluster, vmTestVM, vmTestFirewallUUID, 1935)
		fw.DisplayName, fw.Name = name, name
		if !attached {
			fw.ResourcesAssigned = nil
		}
		f.api.firewalls = append(f.api.firewalls, fw)
		// The caller works from a listing, as the Service pass does.
		items, err := f.api.ListFirewalls(f.ctx, "bkk01")
		if err != nil {
			t.Fatal(err)
		}
		for _, listed := range items {
			if listed.UUID == fw.UUID {
				return listed
			}
		}
		t.Fatal("orphan not listed")
		return fw
	}
	t.Run("a firewall of a vanished VM is deleted after two spaced reads", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		f.addService("svc-a", 1935)
		fw := orphan(f, false)
		f.api.vms = f.api.vms[1:] // the VM is gone
		if err := f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members); err != nil {
			var pending *nodeLoadBalancerFirewallRelationPendingError
			if !errors.As(err, &pending) {
				t.Fatal(err)
			}
		}
		if len(f.api.deletedFirewalls) != 0 {
			t.Fatal("one absent read must not delete")
		}
		f.advance(nodeLoadBalancerAbsenceConfirmationDelay / 2)
		_ = f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members)
		if len(f.api.deletedFirewalls) != 0 {
			t.Fatal("two unspaced reads must not delete")
		}
		f.advance(nodeLoadBalancerAbsenceConfirmationDelay)
		if err := f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members); err != nil {
			t.Fatal(err)
		}
		if len(f.api.deletedFirewalls) != 1 || f.vmFirewall(vmTestVM) != nil {
			t.Fatalf("deleted = %v", f.api.deletedFirewalls)
		}
	})
	t.Run("a live VM keeps its orphan", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		fw := orphan(f, false)
		for i := 0; i < 3; i++ {
			f.advance(time.Minute)
			_ = f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members)
		}
		if len(f.api.deletedFirewalls) != 0 {
			t.Fatal("an orphan of a live VM is never deleted")
		}
	})
	t.Run("an attached orphan holds with an Event", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		f.addService("svc-a", 1935)
		fw := orphan(f, true)
		f.api.vms = f.api.vms[1:]
		f.advance(time.Hour)
		err := f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members)
		if !errors.Is(err, errVMFirewallDrift) {
			t.Fatalf("error = %v, want a hold", err)
		}
		if len(f.api.deletedFirewalls) != 0 || len(f.api.unassignedFirewalls) != 0 {
			t.Fatal("an attached orphan must be neither detached nor deleted")
		}
		if len(f.eventsFor(vmFirewallDriftReason)) != 1 {
			t.Fatalf("Events = %d", len(f.eventsFor(vmFirewallDriftReason)))
		}
	})
	t.Run("an orphan with an anchor is not an orphan", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		s := f.addService("svc-a", 1935)
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, f.member(s))
		f.api.vms = f.api.vms[1:]
		fw := *f.vmFirewall(vmTestVM)
		for i := 0; i < 3; i++ {
			f.advance(time.Minute)
			_ = f.controller.collectOrphanVMFirewall(f.ctx, fw, f.members)
		}
		if len(f.api.deletedFirewalls) != 0 {
			t.Fatal("a firewall with an anchor is deleted only through its ledger")
		}
	})
}

func TestVMFirewallLedgerOnlyRemovalOnAbsentVM(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	m1, m2 := f.member(s1), f.member(s2)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, m1, m2)
	k1 := m1.key()
	ledgerOnly := func(k vmFirewallMemberKey) vmFirewallDelta { return vmFirewallDelta{Remove: &k, LedgerOnly: true} }

	// A live VM never takes a ledger-only removal: it could still be reached.
	if _, err := f.step(vmTestVM, ledgerOnly(k1), nil); err == nil {
		t.Fatal("a ledger-only removal needs a VM that is gone")
	}
	f.api.vms = f.api.vms[1:]
	if _, err := f.step(vmTestVM, ledgerOnly(k1), nil); err != nil {
		t.Fatal(err)
	}
	applied, err := vmFirewallAnchorView{cm: f.anchor(vmTestVM)}.applied()
	if err != nil || len(applied.Members) != 1 || applied.Members[0].UID != "svc-b" {
		t.Fatalf("applied = %#v, %v", applied, err)
	}
	if len(f.api.updatedFirewalls) != 0 {
		t.Fatal("a ledger-only removal must make no PUT")
	}
	// The authority callback still has the last word.
	deny := func(context.Context, *corev1.ConfigMap, *inspace.Firewall) error { return errors.New("not proven") }
	k2 := m2.key()
	if _, err := f.step(vmTestVM, ledgerOnly(k2), deny); err == nil {
		t.Fatal("authority must be consulted")
	}
	f.stepUntil(vmTestVM, ledgerOnly(k2), func() bool { return f.anchor(vmTestVM) == nil })
	if len(f.api.deletedFirewalls) != 1 || len(f.api.updatedFirewalls) != 0 {
		t.Fatalf("deleted=%v PUTs=%d: the last removal deletes the firewall", f.api.deletedFirewalls, len(f.api.updatedFirewalls))
	}
}

func TestServiceFirewallDeletePathRefusesVMFirewallName(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := nodeLoadBalancerTestService("edge", "edge-service-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	if _, err := f.provider.kubeClient.CoreV1().Services(service.Namespace).Create(f.ctx, service, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	owned := perVMTestFirewall(t, vmTestCluster, vmTestVM, vmTestFirewallUUID, 1935)
	owned.ResourcesAssigned = nil
	f.api.firewalls = append(f.api.firewalls, owned)

	done, err := f.controller.deleteOwnedServiceFirewall(f.ctx, service, vmTestFirewallUUID)
	if err == nil || done {
		t.Fatalf("done=%t err=%v: the Service delete path must refuse a per-VM firewall", done, err)
	}
	if len(f.api.deletedFirewalls) != 0 {
		t.Fatalf("a per-VM firewall was deleted through the Service path: %v", f.api.deletedFirewalls)
	}
}
