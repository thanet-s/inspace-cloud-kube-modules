package cloudprovider

import (
	"context"
	"errors"
	"testing"
	"time"
)

const vmTestFirewallUUID = "33333333-3333-4333-8333-333333333333"

// assignHookAPI runs a hook just before an attach reaches the fake cloud.
type assignHookAPI struct {
	API
	before func()
}

func (a *assignHookAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if a.before != nil {
		a.before()
	}
	return a.API.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func vmTestAssignFence() *nodeLoadBalancerFirewallRelationFence {
	return &nodeLoadBalancerFirewallRelationFence{
		operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: vmTestFirewallUUID, vmUUID: vmTestVM,
	}
}

func vmTestUnassignFence() *nodeLoadBalancerFirewallRelationFence {
	return &nodeLoadBalancerFirewallRelationFence{
		operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: vmTestFirewallUUID, vmUUID: vmTestVM,
	}
}

func TestVMFirewallRelationOwnerAttachesThroughFence(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, f.member(service))
	owner := f.controller.vmFirewallRelationOwner(vmTestVM, f.members)

	var duringAttach map[string]string
	f.provider.api = &assignHookAPI{API: f.gate, before: func() { duringAttach = f.anchor(vmTestVM).Annotations }}
	_, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestAssignFence())
	if err != nil {
		t.Fatal(err)
	}
	if duringAttach[annotationNodeLoadBalancerFirewallRelationIssued] == "" || duringAttach[annotationNodeLoadBalancerFirewallRelationOwnerUID] != string(f.anchor(vmTestVM).UID) {
		t.Fatalf("the relation receipt must be on the anchor before the attach: %#v", duringAttach)
	}
	if len(f.api.assignedFirewalls) != 1 || f.api.assignedFirewalls[0] != vmTestFirewallUUID+"/"+vmTestVM {
		t.Fatalf("assigned = %v", f.api.assignedFirewalls)
	}
	after := f.anchor(vmTestVM).Annotations
	if after[annotationNodeLoadBalancerFirewallRelationIssued] != "" || after[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		t.Fatalf("the receipt must clear after the readback: %#v", after)
	}
	if after[annotationVMFirewallApplied] == "" || after[annotationVMFirewallUUID] != vmTestFirewallUUID {
		t.Fatalf("the relation write must keep the other anchor state: %#v", after)
	}
	f.provider.api = f.gate
	converged, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestAssignFence())
	if err != nil || !converged {
		t.Fatalf("converged = %t, %v", converged, err)
	}
	if f.firewallCount(vmTestVM) != 2 {
		t.Fatalf("firewalls on the VM = %d, want base + per-VM", f.firewallCount(vmTestVM))
	}
}

func TestVMFirewallRelationOwnerKeepsConcurrentAnchorChanges(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, f.member(service))
	owner := f.controller.vmFirewallRelationOwner(vmTestVM, f.members)
	// Another writer touches an unrelated key between the read and the write.
	f.provider.api = &assignHookAPI{API: f.gate, before: func() {
		f.setAnchor(vmTestVM, func(a map[string]string) { a[annotationVMFirewallRepair] = "later" })
	}}
	if _, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestAssignFence()); err != nil {
		t.Fatal(err)
	}
	if f.anchor(vmTestVM).Annotations[annotationVMFirewallRepair] != "later" {
		t.Fatal("the relation fence overwrote an unrelated anchor change")
	}
}

func TestVMFirewallRelationOwnerRefusesAtLimitBeforeReceipt(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, f.member(s1), f.member(s2))
	f.addForeignFirewall(vmTestVM, 1)
	f.addForeignFirewall(vmTestVM, 2)
	if f.firewallCount(vmTestVM) != 3 {
		t.Fatalf("setup: %d firewalls", f.firewallCount(vmTestVM))
	}
	before := f.anchor(vmTestVM)
	owner := f.controller.vmFirewallRelationOwner(vmTestVM, f.members)
	_, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestAssignFence())
	var limit *FirewallLimitExceededError
	if !errors.As(err, &limit) {
		t.Fatalf("error = %v, want FirewallLimitExceededError", err)
	}
	if len(f.api.assignedFirewalls) != 0 {
		t.Fatalf("a refused attach was dispatched: %v", f.api.assignedFirewalls)
	}
	after := f.anchor(vmTestVM)
	if after.ResourceVersion != before.ResourceVersion || len(after.Annotations) != len(before.Annotations) ||
		after.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("a refusal must not write the anchor: %#v", after.Annotations)
	}
	events := f.eventsFor(FirewallLimitExceededReason)
	involved := map[string]bool{}
	for _, event := range events {
		involved[event.InvolvedObject.Name] = true
	}
	if !involved[s1.Name] || !involved[s2.Name] || len(events) != 2 {
		t.Fatalf("FirewallLimitExceeded Events = %v, want one per member Service", involved)
	}
}

func TestVMFirewallRelationOwnerDetachNeedsVMAbsenceOrIntent(t *testing.T) {
	setup := func(t *testing.T) (*vmFirewallFixture, nodeLoadBalancerFirewallRelationOwner) {
		f := newVMFirewallFixture(t)
		service := f.addService("svc-a", 1935)
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(service))
		return f, f.controller.vmFirewallRelationOwner(vmTestVM, f.members)
	}
	t.Run("live VM without a delete intent keeps the firewall", func(t *testing.T) {
		f, owner := setup(t)
		_, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestUnassignFence())
		if err == nil {
			t.Fatal("a live VM must not lose its firewall without intent")
		}
		if len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("detach dispatched: %v", f.api.unassignedFirewalls)
		}
		if f.anchor(vmTestVM).Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
			t.Fatal("a refused detach must clear its receipt")
		}
	})
	t.Run("live VM with a staged delete detaches", func(t *testing.T) {
		f, owner := setup(t)
		f.setAnchor(vmTestVM, func(a map[string]string) {
			a[annotationVMFirewallPendingOp] = vmFirewallPendingOpDelete
			a[annotationVMFirewallPending] = `{"v":1,"members":[]}`
		})
		for pass := 0; pass < 4; pass++ {
			converged, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestUnassignFence())
			if err != nil {
				var pending *nodeLoadBalancerFirewallRelationPendingError
				if !errors.As(err, &pending) {
					t.Fatalf("pass %d: %v", pass, err)
				}
				f.advance(pending.retryAfter + time.Second)
			}
			if converged {
				break
			}
		}
		if len(f.api.unassignedFirewalls) != 1 || f.firewallCount(vmTestVM) != 1 {
			t.Fatalf("unassigned = %v, firewalls on VM = %d", f.api.unassignedFirewalls, f.firewallCount(vmTestVM))
		}
	})
	t.Run("absent VM detaches only after two spaced observations", func(t *testing.T) {
		f, owner := setup(t)
		f.api.vms = f.api.vms[1:]
		_, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestUnassignFence())
		var pending *nodeLoadBalancerFirewallRelationPendingError
		if !errors.As(err, &pending) || len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("first observation = %v, unassigned %v; want a wait", err, f.api.unassignedFirewalls)
		}
		f.advance(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
		_, err = f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestUnassignFence())
		if err != nil && !errors.As(err, &pending) {
			t.Fatal(err)
		}
		if len(f.api.unassignedFirewalls) != 1 {
			t.Fatalf("unassigned = %v after the second observation", f.api.unassignedFirewalls)
		}
	})
}

func TestVMFirewallRelationOwnerRefusesAttachOfDriftedFirewall(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, f.member(service))
	// Someone edits the rules in the console.
	port := int32(22)
	f.api.firewalls[len(f.api.firewalls)-1].Rules[0].PortStart = &port
	f.api.firewalls[len(f.api.firewalls)-1].Rules[0].PortEnd = &port
	owner := f.controller.vmFirewallRelationOwner(vmTestVM, f.members)
	if _, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, owner, vmTestAssignFence()); err == nil {
		t.Fatal("a drifted firewall must not be attached")
	}
	if len(f.api.assignedFirewalls) != 0 {
		t.Fatalf("assigned = %v", f.api.assignedFirewalls)
	}
}
