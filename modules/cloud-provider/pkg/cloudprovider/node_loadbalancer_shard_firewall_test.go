package cloudprovider

import (
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestDesiredNodeLoadBalancerShardFirewallBuildsCanonicalExactUnion(t *testing.T) {
	web := nodeLoadBalancerTestService("web", "service-web", corev1.ProtocolTCP, 443)
	web.Spec.Ports = append(web.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolUDP, Port: 443})
	web.Spec.LoadBalancerSourceRanges = []string{"203.0.113.99/24", "198.51.100.0/24", "203.0.113.0/24"}
	health := nodeLoadBalancerTestService("health", "service-health", corev1.ProtocolTCP, 80)

	shard := nodeLoadBalancerShardPlan{
		Name:   "inlb-7255785b",
		Claims: []string{"service-web", "service-health"},
		Ports: []nodeLoadBalancerPortClaim{
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolUDP, Port: 443},
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 443},
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
		},
	}
	desired, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, shard, []*corev1.Service{web, health})
	if err != nil {
		t.Fatal(err)
	}
	name, err := inspace.NodeLoadBalancerShardFirewallName("cluster", shard.Name)
	if err != nil {
		t.Fatal(err)
	}
	if desired.ClusterID != "cluster" || desired.Shard != shard.Name ||
		desired.Request.DisplayName != name || desired.Request.Description != nodeLoadBalancerShardFirewallDescription ||
		desired.Request.BillingAccountID != 42 ||
		len(desired.Members) != 2 || desired.Members[0].ServiceUID != "service-health" || desired.Members[1].ServiceUID != "service-web" ||
		len(desired.Members[0].PolicyHash) != nodeLoadBalancerShardFirewallPolicyHashLength ||
		len(desired.Members[1].PolicyHash) != nodeLoadBalancerShardFirewallPolicyHashLength {
		t.Fatalf("desired identity = %#v", desired)
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(desired)
	if err != nil {
		t.Fatal(err)
	}
	wantLedger := "service-health=" + desired.Members[0].PolicyHash + ",service-web=" + desired.Members[1].PolicyHash
	if ledger != wantLedger {
		t.Fatalf("membership ledger = %q, want %q", ledger, wantLedger)
	}
	if len(desired.Request.Rules) != 3 {
		t.Fatalf("desired rules = %#v", desired.Request.Rules)
	}
	wantPorts := []string{"tcp/80", "tcp/443", "udp/443"}
	for index, rule := range desired.Request.Rules {
		if rule.UUID != "" || rule.Direction != "inbound" || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
			t.Fatalf("rule %d = %#v", index, rule)
		}
		if got := nodeLoadBalancerShardFirewallRuleLogicalKey(rule); got != wantPorts[index] {
			t.Fatalf("rule %d key = %q, want %q", index, got, wantPorts[index])
		}
		if *rule.PortStart == 80 {
			if rule.EndpointSpecType != "any" || len(rule.EndpointSpec) != 0 {
				t.Fatalf("empty source ranges did not become any: %#v", rule)
			}
			continue
		}
		if rule.EndpointSpecType != "ip_prefixes" || !reflect.DeepEqual(rule.EndpointSpec, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
			t.Fatalf("source ranges were not canonical: %#v", rule)
		}
	}
	if hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(desired.Request.Rules); err != nil || hash != desired.Hash {
		t.Fatalf("desired hash = %q, recomputed = %q, err = %v", desired.Hash, hash, err)
	}

	// Neither Service order, claim order, plan-port order, host bits nor duplicate
	// equivalent source ranges may change the aggregate policy.
	reorderedShard := shard
	reorderedShard.Claims = []string{"service-health", "service-web"}
	reorderedShard.Ports = []nodeLoadBalancerPortClaim{shard.Ports[2], shard.Ports[0], shard.Ports[1]}
	reorderedWeb := web.DeepCopy()
	reorderedWeb.Spec.LoadBalancerSourceRanges = []string{"198.51.100.7/24", "203.0.113.0/24"}
	reordered, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, reorderedShard, []*corev1.Service{health, reorderedWeb})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(desired, reordered) {
		t.Fatalf("canonical policy changed after reorder:\nfirst=%#v\nsecond=%#v", desired, reordered)
	}
}

func TestDesiredNodeLoadBalancerShardFirewallRejectsNonExactMembershipAndPorts(t *testing.T) {
	first := nodeLoadBalancerTestService("first", "service-first", corev1.ProtocolTCP, 80)
	second := nodeLoadBalancerTestService("second", "service-second", corev1.ProtocolUDP, 443)
	validShard := nodeLoadBalancerShardPlan{
		Name:   "inlb-7255785b",
		Claims: []string{"service-first", "service-second"},
		Ports: []nodeLoadBalancerPortClaim{
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolUDP, Port: 443},
		},
	}

	tests := map[string]func() (nodeLoadBalancerShardPlan, []*corev1.Service){
		"duplicate claim": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			shard := validShard
			shard.Claims = []string{"service-first", "service-first"}
			return shard, []*corev1.Service{first}
		},
		"missing claimed Service": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			return validShard, []*corev1.Service{first}
		},
		"unclaimed Service": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			extra := nodeLoadBalancerTestService("extra", "service-extra", corev1.ProtocolTCP, 8080)
			return validShard, []*corev1.Service{first, second, extra}
		},
		"duplicate Service object": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			return validShard, []*corev1.Service{first, first, second}
		},
		"nil Service": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			return validShard, []*corev1.Service{first, nil}
		},
		"empty Service UID": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			copy := second.DeepCopy()
			copy.UID = ""
			return validShard, []*corev1.Service{first, copy}
		},
		"duplicate public port owner": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			copy := second.DeepCopy()
			copy.Spec.Ports[0].Protocol = corev1.ProtocolTCP
			copy.Spec.Ports[0].Port = 80
			shard := validShard
			shard.Ports = shard.Ports[:1]
			return shard, []*corev1.Service{first, copy}
		},
		"planned port absent from Services": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			shard := validShard
			shard.Ports = append(append([]nodeLoadBalancerPortClaim(nil), validShard.Ports...), nodeLoadBalancerPortClaim{
				IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 8443,
			})
			return shard, []*corev1.Service{first, second}
		},
		"Service port absent from plan": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			shard := validShard
			shard.Ports = shard.Ports[:1]
			return shard, []*corev1.Service{first, second}
		},
		"duplicate planned port": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			shard := validShard
			shard.Ports = append(append([]nodeLoadBalancerPortClaim(nil), validShard.Ports...), validShard.Ports[0])
			return shard, []*corev1.Service{first, second}
		},
		"IPv6 source range": func() (nodeLoadBalancerShardPlan, []*corev1.Service) {
			copy := second.DeepCopy()
			copy.Spec.LoadBalancerSourceRanges = []string{"2001:db8::/32"}
			return validShard, []*corev1.Service{first, copy}
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			shard, services := build()
			if _, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, shard, services); err == nil {
				t.Fatal("invalid shard firewall inputs were accepted")
			}
		})
	}
}

func TestNodeLoadBalancerShardFirewallUpdatePreservesLogicalRuleIdentity(t *testing.T) {
	oldService := nodeLoadBalancerTestService("web", "service-web", corev1.ProtocolTCP, 80)
	oldService.Spec.Ports = append(oldService.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolTCP, Port: 443})
	oldShard := nodeLoadBalancerShardPlan{
		Name: "inlb-7255785b", Claims: []string{"service-web"},
		Ports: []nodeLoadBalancerPortClaim{
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 443},
		},
	}
	oldPolicy, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, oldShard, []*corev1.Service{oldService})
	if err != nil {
		t.Fatal(err)
	}
	currentRules := append([]inspace.FirewallRule(nil), oldPolicy.Request.Rules...)
	currentRules[0].UUID = "11111111-1111-4111-8111-111111111111"
	currentRules[1].UUID = "22222222-2222-4222-8222-222222222222"
	current := inspace.Firewall{
		UUID:             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		DisplayName:      oldPolicy.Request.DisplayName,
		Description:      oldPolicy.Request.Description,
		BillingAccountID: oldPolicy.Request.BillingAccountID,
		Rules:            currentRules,
	}

	newService := oldService.DeepCopy()
	newService.Spec.Ports = []corev1.ServicePort{
		{Protocol: corev1.ProtocolTCP, Port: 80},
		{Protocol: corev1.ProtocolUDP, Port: 443},
	}
	newService.Spec.LoadBalancerSourceRanges = []string{"203.0.113.9/24"}
	newShard := oldShard
	newShard.Ports = []nodeLoadBalancerPortClaim{
		{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
		{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolUDP, Port: 443},
	}
	newPolicy, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, newShard, []*corev1.Service{newService})
	if err != nil {
		t.Fatal(err)
	}
	request, err := nodeLoadBalancerShardFirewallUpdateRequest(current, newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if request.Name != oldPolicy.Request.DisplayName || request.Description != nodeLoadBalancerShardFirewallDescription || len(request.Rules) != 2 {
		t.Fatalf("update request = %#v", request)
	}
	if key := nodeLoadBalancerShardFirewallRuleLogicalKey(request.Rules[0]); key != "tcp/80" || request.Rules[0].UUID != currentRules[0].UUID ||
		request.Rules[0].EndpointSpecType != "ip_prefixes" || !reflect.DeepEqual(request.Rules[0].EndpointSpec, []string{"203.0.113.0/24"}) {
		t.Fatalf("retained logical rule = %#v", request.Rules[0])
	}
	if key := nodeLoadBalancerShardFirewallRuleLogicalKey(request.Rules[1]); key != "udp/443" || request.Rules[1].UUID != "" {
		t.Fatalf("new logical rule = %#v", request.Rules[1])
	}
	for _, rule := range request.Rules {
		if rule.UUID == currentRules[1].UUID {
			t.Fatalf("removed tcp/443 rule leaked into update: %#v", request.Rules)
		}
	}
	for _, rule := range newPolicy.Request.Rules {
		if rule.UUID != "" {
			t.Fatal("update helper mutated desired create policy")
		}
	}

	// Some InSpace list responses omit an otherwise managed description. The
	// exact stable identity, billing ownership and policy still make this a safe
	// source for a full PUT body.
	current.Description = ""
	if _, err := nodeLoadBalancerShardFirewallUpdateRequest(current, newPolicy); err != nil {
		t.Fatalf("omitted readback description was rejected: %v", err)
	}
}

func TestNodeLoadBalancerShardFirewallUpdateRejectsUntrustedReadback(t *testing.T) {
	service := nodeLoadBalancerTestService("web", "service-web", corev1.ProtocolTCP, 80)
	service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolUDP, Port: 443})
	shard := nodeLoadBalancerShardPlan{
		Name: "inlb-7255785b", Claims: []string{"service-web"},
		Ports: []nodeLoadBalancerPortClaim{
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
			{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolUDP, Port: 443},
		},
	}
	policy, err := desiredNodeLoadBalancerShardFirewall("cluster", 42, shard, []*corev1.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	rules := append([]inspace.FirewallRule(nil), policy.Request.Rules...)
	rules[0].UUID = "11111111-1111-4111-8111-111111111111"
	rules[1].UUID = "22222222-2222-4222-8222-222222222222"
	valid := inspace.Firewall{
		UUID:             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		DisplayName:      policy.Request.DisplayName,
		Description:      policy.Request.Description,
		BillingAccountID: 42,
		Rules:            rules,
	}

	tests := map[string]func(inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy){
		"missing firewall UUID": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.UUID = ""
			return f, p
		},
		"foreign stable name": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.DisplayName = strings.Replace(f.DisplayName, "7255785b", "0123abcd", 1)
			return f, p
		},
		"billing drift": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.BillingAccountID++
			return f, p
		},
		"description drift": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.Description = "foreign"
			return f, p
		},
		"missing current rule UUID": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.Rules = append([]inspace.FirewallRule(nil), f.Rules...)
			f.Rules[0].UUID = ""
			return f, p
		},
		"duplicate current rule UUID": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			f.Rules = append([]inspace.FirewallRule(nil), f.Rules...)
			f.Rules[1].UUID = f.Rules[0].UUID
			return f, p
		},
		"corrupt desired hash": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			p.Hash = "deadbeef"
			return f, p
		},
		"corrupt member hash": func(f inspace.Firewall, p nodeLoadBalancerShardFirewallPolicy) (inspace.Firewall, nodeLoadBalancerShardFirewallPolicy) {
			p.Members = append([]nodeLoadBalancerShardFirewallMember(nil), p.Members...)
			p.Members[0].PolicyHash = "BAD"
			return f, p
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			current, desired := mutate(valid, policy)
			if _, err := nodeLoadBalancerShardFirewallUpdateRequest(current, desired); err == nil {
				t.Fatal("untrusted readback or policy was accepted")
			}
		})
	}
}
