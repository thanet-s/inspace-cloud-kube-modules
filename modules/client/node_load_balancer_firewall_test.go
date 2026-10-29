package inspace

import (
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

func TestNodeLoadBalancerShardFirewallContractGoldenVectors(t *testing.T) {
	tcpPort := int32(443)
	udpPort := int32(443)
	rules := []FirewallRule{
		{
			UUID: "11111111-2222-4333-8444-555555555555", Protocol: "udp", Direction: "inbound",
			PortStart: &udpPort, PortEnd: &udpPort, EndpointSpecType: "ip_prefixes",
			EndpointSpec: []string{"203.0.113.0/24", "10.0.0.0/8"},
		},
		{Protocol: "tcp", Direction: "inbound", PortStart: &tcpPort, PortEnd: &tcpPort, EndpointSpecType: "any"},
	}
	hash, err := NodeLoadBalancerShardFirewallSpecHash(rules)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "636e14a70c093c72b0d7f37640df2114404b0754860b731b9a3803f24a40d97a" {
		t.Fatalf("shard firewall policy hash = %q", hash)
	}

	// Canonicalization ignores API rule identities, rule order, and prefix order.
	reordered := []FirewallRule{
		{UUID: "66666666-7777-4888-8999-aaaaaaaaaaaa", Protocol: "tcp", Direction: "inbound", PortStart: &tcpPort, PortEnd: &tcpPort, EndpointSpecType: "any"},
		{Protocol: "udp", Direction: "inbound", PortStart: &udpPort, PortEnd: &udpPort, EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/8", "203.0.113.0/24"}},
	}
	if reorderedHash, err := NodeLoadBalancerShardFirewallSpecHash(reordered); err != nil || reorderedHash != hash {
		t.Fatalf("reordered shard policy hash = %q, %v; want %q", reorderedHash, err, hash)
	}

	name, err := NodeLoadBalancerShardFirewallName("cluster", "inlb-7255785b")
	if err != nil {
		t.Fatal(err)
	}
	const wantName = "inlb-164cf1ca8391532e4f239c556c0c1958-shard-7255785b"
	if name != wantName {
		t.Fatalf("shard firewall name = %q, want %q", name, wantName)
	}
	firewall := Firewall{Name: name, BillingAccountID: 42, Rules: rules}
	if err := ValidateNodeLoadBalancerShardFirewall(firewall, "cluster", "inlb-7255785b", 42, hash); err != nil {
		t.Fatalf("producer shard firewall rejected by consumer contract: %v", err)
	}
}

func TestNodeLoadBalancerShardFirewallContractRejectsIdentityAndPolicyDrift(t *testing.T) {
	port := int32(443)
	rules := []FirewallRule{{Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any"}}
	hash, err := NodeLoadBalancerShardFirewallSpecHash(rules)
	if err != nil {
		t.Fatal(err)
	}
	name, err := NodeLoadBalancerShardFirewallName("cluster", "inlb-7255785b")
	if err != nil {
		t.Fatal(err)
	}
	valid := Firewall{Name: name, BillingAccountID: 42, Rules: rules}
	tests := []struct {
		name       string
		firewall   Firewall
		cluster    string
		shard      string
		billing    int64
		policyHash string
	}{
		{name: "billing", firewall: valid, cluster: "cluster", shard: "inlb-7255785b", billing: 43, policyHash: hash},
		{name: "cluster", firewall: valid, cluster: "other", shard: "inlb-7255785b", billing: 42, policyHash: hash},
		{name: "shard", firewall: valid, cluster: "cluster", shard: "inlb-deadbeef", billing: 42, policyHash: hash},
		{name: "wrong stable name", firewall: Firewall{Name: "inlb-164cf1ca8391532e4f239c556c0c1958-shard-deadbeef", BillingAccountID: 42, Rules: rules}, cluster: "cluster", shard: "inlb-7255785b", billing: 42, policyHash: hash},
		{name: "invalid expected hash", firewall: valid, cluster: "cluster", shard: "inlb-7255785b", billing: 42, policyHash: "DEADBEEF"},
		{name: "unexpected policy", firewall: valid, cluster: "cluster", shard: "inlb-7255785b", billing: 42, policyHash: strings.Repeat("d", 64)},
		{name: "ICMP policy", firewall: Firewall{Name: name, BillingAccountID: 42, Rules: []FirewallRule{{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"}}}, cluster: "cluster", shard: "inlb-7255785b", billing: 42, policyHash: hash},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateNodeLoadBalancerShardFirewall(test.firewall, test.cluster, test.shard, test.billing, test.policyHash); err == nil {
				t.Fatal("drifted shard firewall was accepted")
			}
		})
	}

	for _, shard := range []string{"", "shared", "inlb-7255785B", "inlb-7255785b-extra"} {
		if _, err := NodeLoadBalancerShardFirewallName("cluster", shard); err == nil {
			t.Errorf("invalid managed shard name %q was accepted", shard)
		}
	}
}

func TestNodeLoadBalancerFirewallContractGoldenVectors(t *testing.T) {
	port := int32(443)
	serviceRules := []FirewallRule{{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}}
	serviceName, serviceHash, err := NodeLoadBalancerServiceFirewallName("cluster", "service-uid", serviceRules)
	if err != nil {
		t.Fatal(err)
	}
	if serviceHash != "886b49b4" || serviceName != "inlb-164cf1ca-service-uid-886b49b4" {
		t.Fatalf("Service firewall identity = %q/%q", serviceName, serviceHash)
	}
	service := Firewall{DisplayName: serviceName, BillingAccountID: 42, Rules: serviceRules}
	if err := ValidateNodeLoadBalancerServiceFirewall(service, "cluster", 42); err != nil {
		t.Fatalf("producer Service firewall rejected by consumer contract: %v", err)
	}
	if err := ValidateNodeLoadBalancerClusterICMPFirewall(service, "cluster", 42); err == nil {
		t.Fatal("Service firewall was accepted as the cluster ICMP policy")
	}

	icmpRules := []FirewallRule{{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"}}
	icmpName, icmpHash, err := NodeLoadBalancerClusterICMPFirewallName("cluster", icmpRules)
	if err != nil {
		t.Fatal(err)
	}
	if icmpHash != "564fcbd1" || icmpName != "inlb-164cf1ca8391532e4f239c556c0c1958-icmp-564fcbd1" {
		t.Fatalf("cluster ICMP firewall identity = %q/%q", icmpName, icmpHash)
	}
	icmp := Firewall{DisplayName: icmpName, BillingAccountID: 42, Rules: icmpRules}
	if err := ValidateNodeLoadBalancerClusterICMPFirewall(icmp, "cluster", 42); err != nil {
		t.Fatalf("producer cluster ICMP firewall rejected by consumer contract: %v", err)
	}
	if err := ValidateNodeLoadBalancerServiceFirewall(icmp, "cluster", 42); err == nil {
		t.Fatal("cluster ICMP firewall was accepted as a Service port policy")
	}
}

func TestNodeLoadBalancerFirewallContractRejectsIdentityAndPolicyDrift(t *testing.T) {
	port := int32(443)
	rules := []FirewallRule{{Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any"}}
	name, _, err := NodeLoadBalancerServiceFirewallName("cluster", "service-uid", rules)
	if err != nil {
		t.Fatal(err)
	}
	valid := Firewall{DisplayName: name, BillingAccountID: 42, Rules: rules}

	mutations := map[string]func(Firewall) Firewall{
		"billing": func(f Firewall) Firewall { f.BillingAccountID = 43; return f },
		"cluster": func(f Firewall) Firewall { f.DisplayName = "inlb-deadbeef-service-uid-886b49b4"; return f },
		"hash":    func(f Firewall) Firewall { f.DisplayName = "inlb-164cf1ca-service-uid-deadbeef"; return f },
		"ICMP": func(f Firewall) Firewall {
			f.Rules = append(f.Rules, FirewallRule{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"})
			return f
		},
		"egress": func(f Firewall) Firewall { f.Rules[0].Direction = "outbound"; return f },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := valid
			copy.Rules = append([]FirewallRule(nil), valid.Rules...)
			if err := ValidateNodeLoadBalancerServiceFirewall(mutate(copy), "cluster", 42); err == nil {
				t.Fatal("drifted Service firewall was accepted")
			}
		})
	}
}

const testVMFirewallUUID = "11111111-1111-4111-8111-111111111111"

func vmFirewallTestRules(t *testing.T, ports ...int32) []FirewallRule {
	t.Helper()
	rules := make([]FirewallRule, 0, len(ports))
	for _, port := range ports {
		p := port
		rules = append(rules, FirewallRule{Protocol: "tcp", Direction: "inbound", PortStart: &p, PortEnd: &p, EndpointSpecType: "any"})
	}
	return rules
}

func vmFirewallTestFirewall(t *testing.T, cluster, vmUUID string, billing int64, rules []FirewallRule) Firewall {
	t.Helper()
	name, err := NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	return Firewall{
		UUID: "70000000-0000-4000-8000-000000000001", DisplayName: name, BillingAccountID: billing,
		Description: NodeLoadBalancerVMFirewallDescription, Rules: rules,
	}
}

func TestNodeLoadBalancerVMFirewallContractGoldenVectors(t *testing.T) {
	name, err := NodeLoadBalancerVMFirewallName("cluster-a", testVMFirewallUUID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "inlb-" + nodeLoadBalancerShortHash("cluster-a") + "-vm-" + testVMFirewallUUID; name != want || len(name) != 53 {
		t.Fatalf("name = %q (len %d), want %q (len 53)", name, len(name), want)
	}
	uuid, ok := ParseNodeLoadBalancerVMFirewallName("cluster-a", name)
	if !ok || uuid != testVMFirewallUUID {
		t.Fatalf("parse = %q, %v", uuid, ok)
	}
	if _, ok := ParseNodeLoadBalancerVMFirewallName("cluster-b", name); ok {
		t.Fatal("foreign cluster must not parse")
	}

	rules := vmFirewallTestRules(t, 443)
	hash, err := NodeLoadBalancerVMFirewallSpecHash(rules)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalNodeLoadBalancerPortFirewallPolicy("VM", rules)
	if err != nil {
		t.Fatal(err)
	}
	if hash != nodeLoadBalancerFullHash(canonical) || len(hash) != 64 {
		t.Fatalf("hash = %q", hash)
	}

	two := vmFirewallTestRules(t, 443, 80)
	rev := vmFirewallTestRules(t, 80, 443)
	rev[0].UUID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	a, err := NodeLoadBalancerVMFirewallSpecHash(two)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NodeLoadBalancerVMFirewallSpecHash(rev)
	if err != nil || a != b {
		t.Fatalf("order/uuid dependent hash: %q vs %q (%v)", a, b, err)
	}
}

func TestNodeLoadBalancerVMFirewallNameRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct{ cluster, uuid string }{
		{"", testVMFirewallUUID},
		{"cluster-a", "11111111-1111-4111-8111-11111111111A"},
		{"cluster-a", "11111111-1111-4111-8111-11111111111"},
		{"cluster-a", "not-a-uuid"},
	} {
		if name, err := NodeLoadBalancerVMFirewallName(tc.cluster, tc.uuid); err == nil {
			t.Fatalf("(%q,%q) accepted: %q", tc.cluster, tc.uuid, name)
		}
	}
}

func TestNodeLoadBalancerVMFirewallNameDisjointFromOtherPatterns(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	randUUID := func() string {
		var b [16]byte
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		h := hex.EncodeToString(b[:])
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	}
	rules := vmFirewallTestRules(t, 443)
	shard, err := NodeLoadBalancerShardFirewallName("cluster-a", "inlb-7255785b")
	if err != nil {
		t.Fatal(err)
	}
	icmp, _, err := NodeLoadBalancerClusterICMPFirewallName("cluster-a", []FirewallRule{{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseNodeLoadBalancerVMFirewallName("cluster-a", shard); ok {
		t.Fatalf("shard name %q parsed as per-VM", shard)
	}
	if _, ok := ParseNodeLoadBalancerVMFirewallName("cluster-a", icmp); ok {
		t.Fatalf("ICMP name %q parsed as per-VM", icmp)
	}
	for i := 0; i < 2000; i++ {
		vm := randUUID()
		name, err := NodeLoadBalancerVMFirewallName("cluster-a", vm)
		if err != nil {
			t.Fatal(err)
		}
		if nodeLoadBalancerServiceFirewallPattern.MatchString(name) || nodeLoadBalancerShardFirewallPattern.MatchString(name) ||
			nodeLoadBalancerICMPFirewallPattern.MatchString(name) || nodeLoadBalancerShardNamePattern.MatchString(name) {
			t.Fatalf("per-VM name %q matches another pattern", name)
		}
		if err := ValidateNodeLoadBalancerServiceFirewall(Firewall{DisplayName: name, BillingAccountID: 42, Rules: rules}, "cluster-a", 42); err == nil {
			t.Fatalf("Service validator accepted per-VM name %q", name)
		}
		svcName, _, err := NodeLoadBalancerServiceFirewallName("cluster-a", randUUID(), rules)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ParseNodeLoadBalancerVMFirewallName("cluster-a", svcName); ok {
			t.Fatalf("Service name %q parsed as per-VM", svcName)
		}
	}
}

func TestValidateNodeLoadBalancerVMFirewallIdentity(t *testing.T) {
	const other = "22222222-2222-4222-8222-222222222222"
	rules := vmFirewallTestRules(t, 443)
	good := vmFirewallTestFirewall(t, "cluster-a", testVMFirewallUUID, 42, rules)
	withRows := func(rows ...FirewallResource) Firewall {
		fw := good
		fw.ResourcesAssigned = rows
		return fw
	}
	icmp := []FirewallRule{{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"}}
	rangeEnd := int32(81)
	rangeRule := vmFirewallTestRules(t, 80)
	rangeRule[0].PortEnd = &rangeEnd

	noDesc := good
	noDesc.Description = ""
	accept := map[string]Firewall{
		"no rows":           good,
		"own row":           withRows(FirewallResource{ResourceType: "vm", ResourceUUID: testVMFirewallUUID}),
		"duplicate own row": withRows(FirewallResource{ResourceType: "vm", ResourceUUID: testVMFirewallUUID}, FirewallResource{ResourceType: "vm", ResourceUUID: testVMFirewallUUID}),
		"empty description": noDesc,
	}
	for label, fw := range accept {
		if err := ValidateNodeLoadBalancerVMFirewallIdentity(fw, "cluster-a", testVMFirewallUUID, 42); err != nil {
			t.Fatalf("%s rejected: %v", label, err)
		}
	}

	badDesc := good
	badDesc.Description = "x"
	reject := map[string]Firewall{
		"other VM name":     vmFirewallTestFirewall(t, "cluster-a", other, 42, rules),
		"foreign cluster":   vmFirewallTestFirewall(t, "cluster-b", testVMFirewallUUID, 42, rules),
		"other billing":     vmFirewallTestFirewall(t, "cluster-a", testVMFirewallUUID, 43, rules),
		"icmp rule":         vmFirewallTestFirewall(t, "cluster-a", testVMFirewallUUID, 42, icmp),
		"port range":        vmFirewallTestFirewall(t, "cluster-a", testVMFirewallUUID, 42, rangeRule),
		"other VM row":      withRows(FirewallResource{ResourceType: "vm", ResourceUUID: other}),
		"uppercase row":     withRows(FirewallResource{ResourceType: "vm", ResourceUUID: "11111111-1111-4111-8111-11111111111A"}),
		"non-vm row":        withRows(FirewallResource{ResourceType: "network", ResourceUUID: testVMFirewallUUID}),
		"own and other row": withRows(FirewallResource{ResourceType: "vm", ResourceUUID: testVMFirewallUUID}, FirewallResource{ResourceType: "vm", ResourceUUID: other}),
		"description x":     badDesc,
	}
	for label, fw := range reject {
		if err := ValidateNodeLoadBalancerVMFirewallIdentity(fw, "cluster-a", testVMFirewallUUID, 42); err == nil {
			t.Fatalf("%s accepted", label)
		}
	}
}

func TestValidateNodeLoadBalancerVMFirewallChecksHash(t *testing.T) {
	rules := vmFirewallTestRules(t, 443)
	fw := vmFirewallTestFirewall(t, "cluster-a", testVMFirewallUUID, 42, rules)
	hash, err := NodeLoadBalancerVMFirewallSpecHash(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNodeLoadBalancerVMFirewall(fw, "cluster-a", testVMFirewallUUID, 42, hash); err != nil {
		t.Fatal(err)
	}
	last := "0"
	if hash[63] == '0' {
		last = "1"
	}
	if err := ValidateNodeLoadBalancerVMFirewall(fw, "cluster-a", testVMFirewallUUID, 42, hash[:63]+last); err == nil {
		t.Fatal("hash one hex off accepted")
	}
	if err := ValidateNodeLoadBalancerVMFirewall(fw, "cluster-a", testVMFirewallUUID, 42, ""); err == nil {
		t.Fatal("empty hash accepted")
	}
}
