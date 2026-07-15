package inspace

import "testing"

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
