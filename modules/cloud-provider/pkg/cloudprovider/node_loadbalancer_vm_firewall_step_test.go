package cloudprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func allowVMFirewallDelta(context.Context, *corev1.ConfigMap, *inspace.Firewall) error { return nil }

func (f *vmFirewallFixture) step(vmUUID string, delta vmFirewallDelta, authorize vmFirewallDeltaAuthority) (vmFirewallStepResult, error) {
	if authorize == nil {
		authorize = allowVMFirewallDelta
	}
	return f.controller.vmFirewallStep(f.ctx, vmUUID, delta, authorize, f.members)
}

// stepUntilConverged repeats a step the way the Service pass does: a bounded
// wait advances the clock, anything else fails the test.
func (f *vmFirewallFixture) stepUntilConverged(vmUUID string, delta vmFirewallDelta) vmFirewallStepResult {
	f.t.Helper()
	for pass := 0; pass < 16; pass++ {
		result, err := f.step(vmUUID, delta, nil)
		if err != nil {
			var pending *nodeLoadBalancerFirewallRelationPendingError
			if errors.As(err, &pending) {
				f.advance(pending.retryAfter + time.Second)
				continue
			}
			f.t.Fatalf("pass %d: %v", pass, err)
		}
		if result.Converged {
			return result
		}
	}
	f.t.Fatal("the step did not converge")
	return vmFirewallStepResult{}
}

func addDelta(m vmFirewallMember) vmFirewallDelta { return vmFirewallDelta{Add: &m} }
func removeDelta(m vmFirewallMember) vmFirewallDelta {
	k := m.key()
	return vmFirewallDelta{Remove: &k}
}
func ruleSummary(rules []inspace.FirewallRule) []string { return mergedRuleSummary(rules) }

func TestVMFirewallStepCreateThenAttach(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	member := f.member(service)

	first, err := f.step(vmTestVM, addDelta(member), nil)
	if err != nil || first.Converged {
		t.Fatalf("the pass that creates the firewall must not report converged: %v, %v", first, err)
	}
	result := f.stepUntilConverged(vmTestVM, addDelta(member))

	if len(f.api.createdFirewalls) != 1 || len(f.api.assignedFirewalls) != 1 || len(f.api.updatedFirewalls) != 0 {
		t.Fatalf("creates=%d assigns=%d updates=%d, want 1/1/0", len(f.api.createdFirewalls), len(f.api.assignedFirewalls), len(f.api.updatedFirewalls))
	}
	firewall := f.vmFirewall(vmTestVM)
	if firewall == nil || result.FirewallUUID != firewall.UUID || result.AppliedAt.IsZero() {
		t.Fatalf("result = %#v, firewall = %#v", result, firewall)
	}
	if got := ruleSummary(firewall.Rules); !reflect.DeepEqual(got, []string{"tcp/1935/any/"}) {
		t.Fatalf("rules = %v", got)
	}
	annotations := f.anchor(vmTestVM).Annotations
	for _, key := range []string{annotationVMFirewallApplied, annotationVMFirewallAppliedHash, annotationVMFirewallAppliedAt, annotationVMFirewallUUID} {
		if annotations[key] == "" {
			t.Fatalf("anchor lacks %s: %#v", key, annotations)
		}
	}
	for _, key := range []string{annotationVMFirewallPending, annotationVMFirewallPendingHash, annotationVMFirewallPendingOp, annotationVMFirewallPendingAt, annotationVMFirewallIssuedAt, annotationVMFirewallIssueID} {
		if annotations[key] != "" {
			t.Fatalf("anchor kept receipt %s=%q", key, annotations[key])
		}
	}
	if annotations[annotationVMFirewallUUID] != firewall.UUID {
		t.Fatalf("anchor uuid %q, firewall %q", annotations[annotationVMFirewallUUID], firewall.UUID)
	}
	if f.firewallCount(vmTestVM) != 2 || f.gate.maxObservedFirewallsPerVM > 2 {
		t.Fatalf("firewalls on the VM = %d (max seen %d), want base + per-VM", f.firewallCount(vmTestVM), f.gate.maxObservedFirewallsPerVM)
	}
	// Converged is stable and makes no further call.
	again, err := f.step(vmTestVM, addDelta(member), nil)
	if err != nil || !again.Converged || len(f.api.createdFirewalls) != 1 || len(f.api.assignedFirewalls) != 1 {
		t.Fatalf("a converged step must be a no-op: %v, %v", again, err)
	}
}

func TestVMFirewallStepAddIsOnePut(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	s2.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	if _, err := f.provider.kubeClient.CoreV1().Services(s2.Namespace).Update(f.ctx, s2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1))

	f.stepUntilConverged(vmTestVM, addDelta(f.member(s2)))

	if len(f.api.updatedFirewalls) != 1 || len(f.api.createdFirewalls) != 0 || len(f.api.assignedFirewalls) != 0 {
		t.Fatalf("updates=%d creates=%d assigns=%d, want exactly one PUT", len(f.api.updatedFirewalls), len(f.api.createdFirewalls), len(f.api.assignedFirewalls))
	}
	put := f.api.updatedFirewalls[0]
	want := []string{"tcp/1935/any/", "tcp/1936/ip_prefixes/203.0.113.0/24"}
	if got := ruleSummary(put.Rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("PUT rules = %v, want %v", got, want)
	}
	if put.Rules[0].UUID != "bbbbbbbb-0000-4000-8000-000000000001" {
		t.Fatalf("the sibling's rule UUID must be retained: %q", put.Rules[0].UUID)
	}
	name, _ := inspace.NodeLoadBalancerVMFirewallName(vmTestCluster, vmTestVM)
	if put.Name != name {
		t.Fatalf("PUT display name = %q", put.Name)
	}
}

// A sibling whose Service spec is broken or being edited must keep exactly its
// recorded rules on every PUT made for someone else.
func TestVMFirewallStepKeepsSiblingRulesWhenSiblingSpecInvalid(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1))
	broken := s1.DeepCopy()
	broken.Spec.Ports = []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 0}}
	if _, err := f.provider.kubeClient.CoreV1().Services(broken.Namespace).Update(f.ctx, broken, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.controller.desiredServiceFirewall(broken); err == nil {
		t.Fatal("setup: the sibling's spec must be invalid")
	}

	m2 := f.member(s2)
	f.stepUntilConverged(vmTestVM, addDelta(m2))
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("PUTs after the add = %d", len(f.api.updatedFirewalls))
	}
	if got := ruleSummary(f.api.updatedFirewalls[0].Rules); !reflect.DeepEqual(got, []string{"tcp/1935/any/", "tcp/1936/any/"}) {
		t.Fatalf("add PUT rules = %v", got)
	}
	f.stepUntilConverged(vmTestVM, removeDelta(m2))
	if len(f.api.updatedFirewalls) != 2 {
		t.Fatalf("PUTs after the remove = %d", len(f.api.updatedFirewalls))
	}
	if got := ruleSummary(f.api.updatedFirewalls[1].Rules); !reflect.DeepEqual(got, []string{"tcp/1935/any/"}) {
		t.Fatalf("remove PUT rules = %v: the sibling's ledger rules must survive", got)
	}
}

func TestVMFirewallStepConflictPersistsNothing(t *testing.T) {
	f := newVMFirewallFixture(t)
	s1 := f.addService("svc-a", 443)
	s2 := f.addService("svc-b", 443)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1))
	before := f.anchor(vmTestVM).DeepCopy()

	_, err := f.step(vmTestVM, addDelta(f.member(s2)), nil)
	var conflict *errVMFirewallPortConflict
	if !errors.As(err, &conflict) || conflict.Port != 443 {
		t.Fatalf("error = %v, want *errVMFirewallPortConflict", err)
	}
	after := f.anchor(vmTestVM)
	if !reflect.DeepEqual(before.Annotations, after.Annotations) || before.ResourceVersion != after.ResourceVersion {
		t.Fatalf("a conflict must persist nothing: %#v", after.Annotations)
	}
	if len(f.api.updatedFirewalls) != 0 || len(f.api.createdFirewalls) != 0 {
		t.Fatal("a conflict must make no API mutation")
	}
	events := f.eventsFor("PublicNodeLocalVMPortConflict")
	if len(events) != 1 || events[0].InvolvedObject.Name != s2.Name {
		t.Fatalf("PortConflict Events = %#v, want one on the asking Service", events)
	}
}

func TestVMFirewallStepCapacityGuardBeforeReceipt(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	f.addForeignFirewall(vmTestVM, 1)
	f.addForeignFirewall(vmTestVM, 2)
	if f.firewallCount(vmTestVM) != 3 {
		t.Fatalf("setup: %d firewalls", f.firewallCount(vmTestVM))
	}
	_, err := f.step(vmTestVM, addDelta(f.member(service)), nil)
	var limit *FirewallLimitExceededError
	if !errors.As(err, &limit) {
		t.Fatalf("error = %v, want FirewallLimitExceededError", err)
	}
	if f.anchor(vmTestVM) != nil {
		t.Fatal("a refused create must not even create the anchor, so no pending receipt exists")
	}
	if len(f.api.createdFirewalls) != 0 {
		t.Fatal("a refused create was dispatched")
	}
	if events := f.eventsFor(FirewallLimitExceededReason); len(events) != 1 || events[0].InvolvedObject.Name != service.Name {
		t.Fatalf("FirewallLimitExceeded Events = %#v", events)
	}
}

func TestVMFirewallStepAuthorityRejection(t *testing.T) {
	deny := func(context.Context, *corev1.ConfigMap, *inspace.Firewall) error {
		return errors.New("Service no longer wants this VM")
	}
	t.Run("create", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		service := f.addService("svc-a", 1935)
		_, err := f.step(vmTestVM, addDelta(f.member(service)), deny)
		if err == nil || len(f.api.createdFirewalls) != 0 {
			t.Fatalf("error = %v, creates = %d", err, len(f.api.createdFirewalls))
		}
		annotations := f.anchor(vmTestVM).Annotations
		for _, key := range []string{annotationVMFirewallPending, annotationVMFirewallPendingOp, annotationVMFirewallIssuedAt, annotationVMFirewallIssueID} {
			if annotations[key] != "" {
				t.Fatalf("receipt %s survived a rejection: %#v", key, annotations)
			}
		}
	})
	t.Run("update", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		s1 := f.addService("svc-a", 1935)
		s2 := f.addService("svc-b", 1936)
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1))
		_, err := f.step(vmTestVM, addDelta(f.member(s2)), deny)
		if err == nil || len(f.api.updatedFirewalls) != 0 {
			t.Fatalf("error = %v, PUTs = %d", err, len(f.api.updatedFirewalls))
		}
		if f.anchor(vmTestVM).Annotations[annotationVMFirewallPending] != "" {
			t.Fatal("the staged receipt must be reset")
		}
		// The same step succeeds once the authority holds.
		f.stepUntilConverged(vmTestVM, addDelta(f.member(s2)))
		if len(f.api.updatedFirewalls) != 1 {
			t.Fatalf("PUTs = %d", len(f.api.updatedFirewalls))
		}
	})
}

func TestVMFirewallStepIsIdempotent(t *testing.T) {
	f := newVMFirewallFixture(t)
	service := f.addService("svc-a", 1935)
	member := f.member(service)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	result, err := f.step(vmTestVM, addDelta(member), nil)
	if err != nil || !result.Converged || result.FirewallUUID != vmTestFirewallUUID {
		t.Fatalf("result = %#v, %v", result, err)
	}
	if len(f.api.updatedFirewalls)+len(f.api.createdFirewalls)+len(f.api.assignedFirewalls) != 0 {
		t.Fatal("adding a member that is already applied must not touch the cloud")
	}
	gone, err := f.step(vmTestVM, removeDelta(vmTestMember(t, "svc-z", vmTestRule("tcp", 7))), nil)
	if err != nil || !gone.Converged || len(f.api.updatedFirewalls) != 0 {
		t.Fatalf("removing an unknown member = %#v, %v", gone, err)
	}
}

// Removing one entry must never close a port another entry still needs.
func TestVMFirewallStepRemoveKeepsPortStillNeeded(t *testing.T) {
	f := newVMFirewallFixture(t)
	s := f.addService("svc-a", 443)
	f.addService("svc-b", 9000)
	oldMember := vmTestMember(t, string(s.UID), vmTestRule("tcp", 443, "198.51.100.0/24"))
	newMember := vmTestMember(t, string(s.UID), vmTestRule("tcp", 443, "203.0.113.0/24"), vmTestRule("tcp", 8443))
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, oldMember, newMember)

	f.stepUntilConverged(vmTestVM, removeDelta(oldMember))
	want := []string{"tcp/443/ip_prefixes/203.0.113.0/24", "tcp/8443/any/"}
	if got := ruleSummary(f.api.updatedFirewalls[len(f.api.updatedFirewalls)-1].Rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules after removing the old policy = %v, want %v", got, want)
	}
}

func TestVMFirewallMergedNarrows(t *testing.T) {
	merge := func(members ...vmFirewallMember) []inspace.FirewallRule {
		rules, err := mergeVMFirewallLedger(vmTestLedger(members...))
		if err != nil {
			t.Fatal(err)
		}
		return rules
	}
	a := merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "198.51.100.0/24")))
	for name, test := range map[string]struct {
		after   []inspace.FirewallRule
		narrows bool
	}{
		"same":          {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "198.51.100.0/24"))), false},
		"wider sources": {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "198.51.100.0/24", "203.0.113.0/24"))), false},
		"any":           {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443))), false},
		"extra port":    {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "198.51.100.0/24"), vmTestRule("udp", 53))), false},
		"narrower":      {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "203.0.113.0/24"))), true},
		"port dropped":  {merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 80))), true},
	} {
		if got := vmFirewallMergedNarrows(a, test.after); got != test.narrows {
			t.Errorf("%s: narrows = %t, want %t", name, got, test.narrows)
		}
	}
	anyBefore := merge(vmTestMember(t, "svc-a", vmTestRule("tcp", 443)))
	if !vmFirewallMergedNarrows(anyBefore, a) {
		t.Error("any to a CIDR list narrows")
	}
}
