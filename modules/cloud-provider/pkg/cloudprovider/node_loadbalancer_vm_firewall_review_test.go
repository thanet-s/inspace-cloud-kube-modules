package cloudprovider

import (
	"errors"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// A VM that is gone together with its firewall must not leave the anchor stuck
// on drift: the spaced absence proof deletes and finalizes it.
func TestVMFirewallLedgerOnlyRemovalWhenVMAndFirewallAreGone(t *testing.T) {
	setup := func(t *testing.T) (*vmFirewallFixture, vmFirewallMember, vmFirewallMember) {
		f := newVMFirewallFixture(t)
		m1 := f.member(f.addService("svc-a", 1935))
		m2 := f.member(f.addService("svc-b", 1936))
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, m1, m2)
		return f, m1, m2
	}
	dropFirewall := func(f *vmFirewallFixture) {
		kept := f.api.firewalls[:0]
		for _, fw := range f.api.firewalls {
			if fw.UUID != vmTestFirewallUUID {
				kept = append(kept, fw)
			}
		}
		f.api.firewalls = kept
	}
	ledgerOnly := func(m vmFirewallMember) vmFirewallDelta {
		k := m.key()
		return vmFirewallDelta{Remove: &k, LedgerOnly: true}
	}
	t.Run("VM and firewall gone", func(t *testing.T) {
		f, m1, m2 := setup(t)
		f.api.vms = f.api.vms[1:]
		dropFirewall(f)
		start := f.clock
		f.stepUntil(vmTestVM, ledgerOnly(m1), func() bool { return f.anchor(vmTestVM) == nil })
		if len(f.api.deletedFirewalls) != 0 || len(f.api.updatedFirewalls) != 0 {
			t.Fatalf("nothing is left to delete or PUT: deleted=%v PUTs=%d", f.api.deletedFirewalls, len(f.api.updatedFirewalls))
		}
		if f.clock.Sub(start) < 2*nodeLoadBalancerAbsenceConfirmationDelay {
			t.Fatalf("only %s passed: the firewall absence needs three spaced reads", f.clock.Sub(start))
		}
		// The sibling's removal finds nothing left to do.
		if result, err := f.step(vmTestVM, ledgerOnly(m2), nil); err != nil || !result.Converged {
			t.Fatalf("sibling removal = %v, %v", result, err)
		}
	})
	t.Run("a live VM with a missing firewall still holds", func(t *testing.T) {
		f, m1, _ := setup(t)
		dropFirewall(f)
		if _, err := f.step(vmTestVM, ledgerOnly(m1), nil); err == nil {
			t.Fatal("a live VM cannot take a ledger-only removal")
		}
		if f.anchor(vmTestVM) == nil {
			t.Fatal("the anchor of a live VM must stay")
		}
	})
}

func TestVMFirewallSettleCountsFromTheAttach(t *testing.T) {
	f := newVMFirewallFixture(t)
	member := f.member(f.addService("svc-a", 1935))
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, false, member)
	applied := f.clock
	f.advance(time.Hour) // the attach is delayed
	result := f.stepUntilConverged(vmTestVM, addDelta(member))
	anchor := f.anchor(vmTestVM)
	raw := anchor.Annotations[annotationVMFirewallAttachedAt]
	attachedAt, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !attachedAt.After(applied.Add(59*time.Minute)) {
		t.Fatalf("attached-at = %q (%v), want a stamp from after the delayed attach", raw, err)
	}
	if !result.AppliedAt.Equal(attachedAt) {
		t.Fatalf("result.AppliedAt = %s, want the attach stamp %s", result.AppliedAt, attachedAt)
	}
	if got := vmFirewallSettleRemaining(anchor, 10*time.Second, attachedAt.Add(3*time.Second)); got != 7*time.Second {
		t.Fatalf("remaining = %s, want 7s: the settle counts from the attach, not from the rule commit an hour earlier", got)
	}

	// A detach and a later re-attach start a new settle.
	if err := f.api.UnassignFirewallFromVM(f.ctx, "bkk01", vmTestFirewallUUID, vmTestVM); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Hour)
	result = f.stepUntilConverged(vmTestVM, addDelta(member))
	if !result.AppliedAt.After(attachedAt.Add(59 * time.Minute)) {
		t.Fatalf("re-attach stamp %s did not move past %s", result.AppliedAt, attachedAt)
	}
}

func TestVMFirewallSettleFailsClosedOnCorruptStamp(t *testing.T) {
	f := newVMFirewallFixture(t)
	member := f.member(f.addService("svc-a", 1935))
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	for _, key := range []string{annotationVMFirewallAppliedAt, annotationVMFirewallAttachedAt} {
		anchor := f.setAnchor(vmTestVM, func(a map[string]string) { a[key] = "yesterday" })
		if got := vmFirewallSettleRemaining(anchor, 10*time.Second, f.clock.Add(time.Hour)); got != 10*time.Second {
			t.Errorf("corrupt %s: remaining = %s, want the full settle", key, got)
		}
		f.setAnchor(vmTestVM, func(a map[string]string) { delete(a, key) })
	}
}

// The forward migration resolves adopt receipts. One that does not name the
// firewall it adopts is not one this code wrote: it is corruption, and holds.
func TestVMFirewallAdoptReceiptWithoutATargetIsCorrupt(t *testing.T) {
	f := newVMFirewallFixture(t)
	member := f.member(f.addService("svc-a", 1935))
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, member)
	f.setAnchor(vmTestVM, func(a map[string]string) {
		a[annotationVMFirewallPending] = a[annotationVMFirewallApplied]
		a[annotationVMFirewallPendingOp] = string(vmFirewallOpAdopt)
		a[annotationVMFirewallIssuedAt] = f.clock.Format(time.RFC3339Nano)
	})
	_, err := f.step(vmTestVM, addDelta(member), nil)
	if !errors.Is(err, errVMFirewallLedgerCorrupt) {
		t.Fatalf("error = %v, want a corrupt-receipt error", err)
	}
}

func TestVMFirewallThirdEntryIsACallerOrderingError(t *testing.T) {
	l := vmTestLedger(vmTestMember(t, "svc-a", vmTestRule("tcp", 1)), vmTestMember(t, "svc-a", vmTestRule("tcp", 2)))
	_, err := l.with(vmTestMember(t, "svc-a", vmTestRule("tcp", 3)))
	if !errors.Is(err, errVMFirewallEntryOrder) || errors.Is(err, errVMFirewallLedgerCorrupt) {
		t.Fatalf("error = %v, want a caller-ordering error, not a corrupt ledger", err)
	}
}

// A PUT that times out may still land inside the retire window. The readback
// then shows the pending rules and commits; nothing is sent again.
func TestVMFirewallStepLatePutCommitsInsideRetireWindow(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	f.api.updateFirewallErr = vmTestTimeoutError()
	_, err := f.step(vmTestVM, addDelta(m2), nil)
	f.requirePending(err)
	f.api.updateFirewallErr = nil
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("attempts = %d", len(f.api.updatedFirewalls))
	}
	// The request lands late, from the cloud's side.
	if _, err := f.api.UpdateFirewall(f.ctx, "bkk01", vmTestFirewallUUID, f.api.updatedFirewalls[0]); err != nil {
		t.Fatal(err)
	}
	attempts := len(f.api.updatedFirewalls)
	f.advance(time.Minute) // well inside the retire window
	if _, err := f.step(vmTestVM, addDelta(m2), nil); err != nil {
		t.Fatalf("the late PUT must commit by hash: %v", err)
	}
	f.requireNoReceipt(vmTestVM)
	applied, err := vmFirewallAnchorView{cm: f.anchor(vmTestVM)}.applied()
	if err != nil || len(applied.Members) != 2 {
		t.Fatalf("applied = %#v, %v", applied, err)
	}
	f.stepUntilConverged(vmTestVM, addDelta(m2))
	if len(f.api.updatedFirewalls) != attempts {
		t.Fatalf("PUT attempts went from %d to %d: a committed late PUT is never re-sent", attempts, len(f.api.updatedFirewalls))
	}
}

func vmTestTimeoutError() error {
	return &inspace.APIError{StatusCode: 504, Method: "PUT", Path: "/firewall", Message: "gateway timeout"}
}
