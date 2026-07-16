package inspace

import (
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
