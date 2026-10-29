package cloudprovider

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	vmTestCluster = "unit-test-cluster"
	vmTestVM      = "11111111-2222-4333-8444-555555555555"
	vmTestOtherVM = "99999999-2222-4333-8444-555555555555"
)

func mergedRuleSummary(rules []inspace.FirewallRule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Protocol+"/"+itoa32(*rule.PortStart)+"/"+rule.EndpointSpecType+"/"+strings.Join(rule.EndpointSpec, ","))
	}
	return out
}

func itoa32(v int32) string { return strconv.Itoa(int(v)) }

func TestMergeVMFirewallLedgerPerServiceRanges(t *testing.T) {
	s1 := vmTestMember(t, "svc-a", vmTestRule("tcp", 1935))
	s2 := vmTestMember(t, "svc-b", vmTestRule("tcp", 1936, "203.0.113.0/24"))
	merged, err := mergeVMFirewallLedger(vmTestLedger(s2, s1))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcp/1935/any/", "tcp/1936/ip_prefixes/203.0.113.0/24"}
	if got := mergedRuleSummary(merged); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}
}

func TestMergeVMFirewallLedgerSameUIDUnion(t *testing.T) {
	old := vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "198.51.100.0/24"))
	next := vmTestMember(t, "svc-a", vmTestRule("tcp", 443, "203.0.113.0/24"), vmTestRule("tcp", 8443))
	merged, err := mergeVMFirewallLedger(vmTestLedger(old, next))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcp/443/ip_prefixes/198.51.100.0/24,203.0.113.0/24", "tcp/8443/any/"}
	if got := mergedRuleSummary(merged); !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}
	anyWins := vmTestMember(t, "svc-a", vmTestRule("tcp", 443))
	merged, err = mergeVMFirewallLedger(vmTestLedger(old, anyWins))
	if err != nil {
		t.Fatal(err)
	}
	if got := mergedRuleSummary(merged); !reflect.DeepEqual(got, []string{"tcp/443/any/"}) {
		t.Fatalf("any must win, merged = %v", got)
	}
}

func TestMergeVMFirewallLedgerCrossUIDConflict(t *testing.T) {
	s1 := vmTestMember(t, "svc-a", vmTestRule("tcp", 443))
	s2 := vmTestMember(t, "svc-b", vmTestRule("tcp", 443, "203.0.113.0/24"))
	_, err := mergeVMFirewallLedger(vmTestLedger(s1, s2))
	var conflict *errVMFirewallPortConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want *errVMFirewallPortConflict", err)
	}
	if conflict.Protocol != "tcp" || conflict.Port != 443 || !reflect.DeepEqual(conflict.UIDs, []string{"svc-a", "svc-b"}) {
		t.Fatalf("conflict = %#v", conflict)
	}
	// The same port on another protocol is not a conflict.
	udp := vmTestMember(t, "svc-b", vmTestRule("udp", 443))
	if _, err := mergeVMFirewallLedger(vmTestLedger(s1, udp)); err != nil {
		t.Fatal(err)
	}
}

func TestMergeVMFirewallLedgerEmptyIsError(t *testing.T) {
	if _, err := mergeVMFirewallLedger(vmTestLedger()); err == nil {
		t.Fatal("an empty ledger must not merge; callers choose delete")
	}
}

func TestMergeVMFirewallLedgerRuleLimit(t *testing.T) {
	previous := maxVMFirewallRulesForTest
	maxVMFirewallRulesForTest = 2
	t.Cleanup(func() { maxVMFirewallRulesForTest = previous })
	two := vmTestMember(t, "svc-a", vmTestRule("tcp", 1), vmTestRule("tcp", 2))
	if _, err := mergeVMFirewallLedger(vmTestLedger(two)); err != nil {
		t.Fatalf("two rules are within the limit: %v", err)
	}
	three := vmTestMember(t, "svc-a", vmTestRule("tcp", 1), vmTestRule("tcp", 2), vmTestRule("tcp", 3))
	if _, err := mergeVMFirewallLedger(vmTestLedger(three)); err == nil {
		t.Fatal("a 3-rule merge must be refused at a limit of 2")
	}
	maxVMFirewallRulesForTest = 0
	if _, err := mergeVMFirewallLedger(vmTestLedger(three)); err != nil {
		t.Fatalf("limit 0 means no client-side limit: %v", err)
	}
}

func TestVMFirewallLiveConstants(t *testing.T) {
	if vmFirewallSettleDefault != 10*time.Second {
		t.Fatalf("settle = %s, want the measured 10s floor", vmFirewallSettleDefault)
	}
	if !vmFirewallRenameSupported {
		t.Fatal("rename through display_name was measured as supported")
	}
	if maxVMFirewallRules != 0 {
		t.Fatalf("no rule-count limit was observed up to 50 rules, got %d", maxVMFirewallRules)
	}
}

// InSpace ignores the name field of a PUT and answers 200, so a rename counts
// only when the name reads back.
func TestVMFirewallRenameIsVerifiedByReadback(t *testing.T) {
	ignored := inspace.Firewall{Name: "inlb-old", DisplayName: "inlb-old"}
	if vmFirewallRenameApplied(ignored, "inlb-new") {
		t.Fatal("an ignored rename must not read as applied")
	}
	renamed := inspace.Firewall{DisplayName: "inlb-new"}
	if !vmFirewallRenameApplied(renamed, "inlb-new") {
		t.Fatal("a renamed firewall must read as applied")
	}
	request, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, vmTestCurrentFirewall(t), nil)
	if err == nil {
		t.Fatalf("an empty rule set must not produce a request: %#v", request)
	}
}

// PUT latency grew with the rule count in the live test (about 1 s at 4 rules,
// 3.3 s at 20, 10 s at 50), so the per-PUT deadline has to grow with it, and it
// must stay below the retire delay so a timed-out request can never still be in
// flight when its receipt retires.
func TestVMFirewallMutationTimeoutGrowsWithRules(t *testing.T) {
	small, large := vmFirewallMutationTimeout(3), vmFirewallMutationTimeout(50)
	if large <= small {
		t.Fatalf("timeout(50)=%s must exceed timeout(3)=%s", large, small)
	}
	if large < 3*10*time.Second {
		t.Fatalf("timeout(50)=%s leaves no margin over the measured 10s", large)
	}
	if got := vmFirewallMutationTimeout(100000); got >= nodeLoadBalancerFirewallRelationRetireDelay {
		t.Fatalf("timeout is capped at %s, must stay below the retire delay %s", got, nodeLoadBalancerFirewallRelationRetireDelay)
	}
}

func vmTestCurrentFirewall(t *testing.T) inspace.Firewall {
	t.Helper()
	fw := perVMTestFirewall(t, vmTestCluster, vmTestVM, "33333333-3333-4333-8333-333333333333", 1935, 9000)
	fw.Rules[0].UUID = "aaaaaaaa-0000-4000-8000-000000000001"
	fw.Rules[1].UUID = "aaaaaaaa-0000-4000-8000-000000000002"
	return fw
}

func TestVMFirewallUpdateRequestKeepsRuleUUIDs(t *testing.T) {
	current := vmTestCurrentFirewall(t)
	merged, err := mergeVMFirewallLedger(vmTestLedger(
		vmTestMember(t, "svc-a", vmTestRule("tcp", 1935, "203.0.113.0/24"), vmTestRule("tcp", 8080)),
	))
	if err != nil {
		t.Fatal(err)
	}
	request, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, current, merged)
	if err != nil {
		t.Fatal(err)
	}
	wantName, _ := inspace.NodeLoadBalancerVMFirewallName(vmTestCluster, vmTestVM)
	if request.Name != wantName || request.Description != inspace.NodeLoadBalancerVMFirewallDescription {
		t.Fatalf("request identity = %q / %q", request.Name, request.Description)
	}
	if len(request.Rules) != 2 {
		t.Fatalf("rules = %#v", request.Rules)
	}
	if request.Rules[0].UUID != "aaaaaaaa-0000-4000-8000-000000000001" || request.Rules[0].EndpointSpecType != "ip_prefixes" {
		t.Fatalf("1935 must keep its UUID with the new sources: %#v", request.Rules[0])
	}
	if request.Rules[1].UUID != "" || *request.Rules[1].PortStart != 8080 {
		t.Fatalf("a new port has an empty UUID: %#v", request.Rules[1])
	}
	for _, rule := range request.Rules {
		if *rule.PortStart == 9000 {
			t.Fatal("a removed port must be absent")
		}
	}
	// After an adopt the list `name` is the old per-Service name (a rename only
	// rewrites display_name), so the two differ and the update is judged on
	// display_name alone. A display_name that is not the per-VM name is refused.
	adopted := current
	adopted.Name = "inlb-00000000-old-service-name"
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, adopted, merged); err != nil {
		t.Fatalf("an adopted firewall with a stale list name must be updatable: %v", err)
	}
	wrongDisplay := current
	wrongDisplay.DisplayName = "another-name"
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, wrongDisplay, merged); err == nil {
		t.Fatal("a display_name that is not the per-VM name must be refused")
	}
	badRuleUUID := vmTestCurrentFirewall(t)
	badRuleUUID.Rules[0].UUID = "not-a-uuid"
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, badRuleUUID, merged); err == nil {
		t.Fatal("a malformed provider rule UUID must be refused")
	}
}

func TestVMFirewallUpdateRequestRefusesWrongIdentity(t *testing.T) {
	merged, err := mergeVMFirewallLedger(vmTestLedger(vmTestMember(t, "svc-a", vmTestRule("tcp", 1935))))
	if err != nil {
		t.Fatal(err)
	}
	other := perVMTestFirewall(t, vmTestCluster, vmTestOtherVM, "33333333-3333-4333-8333-333333333333", 1935)
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, other, merged); err == nil {
		t.Fatal("the firewall of another VM must be refused")
	}
	described := vmTestCurrentFirewall(t)
	described.Description = "x"
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, described, merged); err == nil {
		t.Fatal("a foreign description must be refused")
	}
	badUUID := vmTestCurrentFirewall(t)
	badUUID.UUID = "nope"
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, badUUID, merged); err == nil {
		t.Fatal("a malformed firewall UUID must be refused")
	}
	// A stored description is never relied on: InSpace does not store it, so an
	// empty one is the normal read.
	empty := vmTestCurrentFirewall(t)
	empty.Description = ""
	if _, err := vmFirewallUpdateRequest(vmTestCluster, vmTestVM, empty, merged); err != nil {
		t.Fatalf("an empty description is what the API returns: %v", err)
	}
}

func TestVMFirewallCreateRequest(t *testing.T) {
	merged, err := mergeVMFirewallLedger(vmTestLedger(vmTestMember(t, "svc-a", vmTestRule("tcp", 1935))))
	if err != nil {
		t.Fatal(err)
	}
	request, err := vmFirewallCreateRequest(vmTestCluster, vmTestVM, 42, merged)
	if err != nil {
		t.Fatal(err)
	}
	wantName, _ := inspace.NodeLoadBalancerVMFirewallName(vmTestCluster, vmTestVM)
	if request.DisplayName != wantName || request.BillingAccountID != 42 || request.Description != inspace.NodeLoadBalancerVMFirewallDescription ||
		len(request.Rules) != 1 || request.Rules[0].UUID != "" {
		t.Fatalf("request = %#v", request)
	}
	if _, err := vmFirewallCreateRequest(vmTestCluster, vmTestVM, 0, merged); err == nil {
		t.Fatal("a missing billing account must be refused")
	}
	if _, err := vmFirewallCreateRequest(vmTestCluster, vmTestVM, 42, nil); err == nil {
		t.Fatal("a create needs at least one rule")
	}
}
