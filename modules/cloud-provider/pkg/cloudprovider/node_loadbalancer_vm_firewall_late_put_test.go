package cloudprovider

import (
	"context"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// latePutAPI times out the first firewall PUT without applying it and applies it
// later, on land(): a request that commits after its caller gave up, the case an
// ambiguous receipt exists for.
type latePutAPI struct {
	API
	armed bool
	fired bool
	calls int
	held  func()
}

func (a *latePutAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	a.calls++
	if a.armed && !a.fired {
		a.fired = true
		a.held = func() { _, _ = a.API.UpdateFirewall(context.WithoutCancel(ctx), location, uuid, request) }
		return nil, vmTestTimeoutError()
	}
	return a.API.UpdateFirewall(ctx, location, uuid, request)
}

// land applies the held request, as the provider does when it commits late.
func (a *latePutAPI) land() {
	if a.held != nil {
		a.held()
		a.held = nil
	}
}

// retireWindowPasses is how many passes of seven seconds still fit inside the
// retire delay of an issued request.
const retireWindowPasses = 3

// A forward adopt PUT that times out and commits later, inside the retire window:
// the receipt stays ambiguous while the readback shows the old firewall, the
// request lands, the next readback commits it, and no second PUT is ever sent.
func TestVMFirewallMigrationAdoptThatCommitsLaterIsNotSentTwice(t *testing.T) {
	m := newRelayMigrationCluster(t, VMFirewallMigrationManual)
	m.trackCoverage()
	late := &latePutAPI{API: m.provider.api, armed: true}
	m.provider.api = late
	m.annotateNode(mgRelay.name, "true")
	for pass := 0; pass < 20 && !late.fired; pass++ {
		_ = m.vmRound()
	}
	if !late.fired {
		t.Fatal("the adopt PUT was never sent")
	}
	for pass := 0; pass < retireWindowPasses; pass++ {
		_ = m.vmRound()
	}
	anchor := m.anchor(mgRelay)
	if anchor == nil || anchor.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpAdopt) || anchor.Annotations[annotationVMFirewallIssuedAt] == "" {
		t.Fatalf("the adopt receipt is not open and issued: %#v", anchor)
	}
	if m.perVMFirewall(mgRelay) != nil || late.calls != 1 {
		t.Fatalf("the adopt landed early or was sent again: per-VM firewall %v, %d PUTs", m.perVMFirewall(mgRelay) != nil, late.calls)
	}
	late.land()
	for pass := 0; pass < 200 && !m.servicePerVM("relay-prod")() && !m.servicePerVM("relay-staging")(); pass++ {
		_ = m.vmRound()
		for _, name := range m.services {
			_ = m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name))
		}
	}
	if late.calls != 1 {
		t.Fatalf("%d PUTs, want the one that landed late", late.calls)
	}
	if m.perVMFirewall(mgRelay) == nil || len(m.api.updatedFirewalls) != 1 {
		t.Fatalf("the late adopt was not taken: per-VM firewall %v, %d applied PUTs", m.perVMFirewall(mgRelay) != nil, len(m.api.updatedFirewalls))
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}

// The reverse adopt PUT that times out and commits later, inside the retire
// window, is read back and committed the same way: the Service records the
// firewall, the anchor goes, and no second PUT is sent.
func TestReverseMigrationRenameThatCommitsLaterIsNotSentTwice(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.trackCoverage()
	late := &latePutAPI{API: m.provider.api, armed: true}
	m.provider.api = late
	m.switchToPerService()
	for pass := 0; pass < 400 && !late.fired; pass++ {
		m.reverseRound()
	}
	if !late.fired {
		t.Fatal("the rename PUT was never sent")
	}
	for pass := 0; pass < retireWindowPasses; pass++ {
		m.reverseRound()
	}
	anchor := m.anchor(mgRelay)
	if anchor == nil || anchor.Annotations[annotationVMFirewallPendingOp] != string(vmFirewallOpUnadopt) || anchor.Annotations[annotationVMFirewallIssuedAt] == "" {
		t.Fatalf("the rename receipt is not open and issued: %#v", anchor)
	}
	if m.perVMFirewall(mgRelay) == nil || late.calls != 1 {
		t.Fatalf("the rename landed early or was sent again: %d PUTs", late.calls)
	}
	late.land()
	m.runUntilReversed(1500)
	if late.calls != 1 {
		t.Fatalf("%d PUTs, want the one that landed late", late.calls)
	}
	if left := m.perVMFirewallsLeft(); left != 0 {
		t.Fatalf("%d per-VM firewalls are left", left)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Fatalf("peak %d firewalls, %d refused attaches", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
}
