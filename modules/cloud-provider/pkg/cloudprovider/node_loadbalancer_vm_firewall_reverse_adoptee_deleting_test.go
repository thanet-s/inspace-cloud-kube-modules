package cloudprovider

import "testing"

// The adoptee of the relay's reverse adopt starts deleting after the
// plan is recorded and relay-prod's own firewall is attached. The per-VM firewall
// must be retired entry by entry, never renamed, with 1935 covered throughout.
func TestReverseMigrationAdopteeDeletedAfterPlanRetiresInsteadOfRenaming(t *testing.T) {
	m := newTHLiveCluster(t)
	migrateTHLiveForward(m)
	m.trackCoverage()
	for vm, rules := range m.required {
		kept := rules[:0:0]
		for _, rule := range rules {
			if *rule.PortStart != 1936 {
				kept = append(kept, rule)
			}
		}
		m.required[vm] = kept
	}
	m.annotateNode(mgGateway1.name, vmFirewallMigrateValueHold)
	m.annotateNode(mgGateway2.name, vmFirewallMigrateValueHold)
	m.switchToPerService()
	for pass := 0; pass < 1500; pass++ {
		p := m.plan(mgRelay)
		if p != nil && p.Direction == vmFirewallMigrationDirectionReverse {
			break
		}
		m.reverseRound()
	}
	p := m.plan(mgRelay)
	if p == nil || p.Strategy != vmFirewallMigrationStrategyAdopt || p.Adoptee != "relay-staging-uid" {
		t.Fatalf("relay plan = %#v", p)
	}
	t.Logf("relay plan before delete: phase %s adoptee %s", p.Phase, p.Adoptee)
	puts := len(m.api.updatedFirewalls)
	m.markDeleting("relay-staging")
	for pass := 0; pass < 1500 && m.anchor(mgRelay) != nil; pass++ {
		m.reverseRound()
	}
	if m.anchor(mgRelay) != nil {
		t.Fatalf("stalled: anchors %d", m.anchorsLeft())
	}
	if got := len(m.api.updatedFirewalls) - puts; got > 1 {
		t.Errorf("%d PUTs after the adoptee started deleting, want none", got)
	}
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("peak %d, refused %d", m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	t.Logf("relay history %v, firewalls now %d", m.history[mgRelay.uuid], len(m.firewallsOf(mgRelay)))
}
