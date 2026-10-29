package cloudprovider

import (
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// perVMTestFirewall builds a per-VM firewall for vmUUID that is attached to
// vmUUID and carries one inbound TCP rule per port, open to any source.
func perVMTestFirewall(t *testing.T, cluster, vmUUID string, uuid string, ports ...int32) inspace.Firewall {
	t.Helper()
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]inspace.FirewallRule, 0, len(ports))
	for _, port := range ports {
		p := port
		rules = append(rules, inspace.FirewallRule{
			Protocol: "tcp", Direction: "inbound", PortStart: &p, PortEnd: &p, EndpointSpecType: "any",
		})
	}
	return inspace.Firewall{
		UUID: uuid, Name: name, DisplayName: name, BillingAccountID: 42,
		Description: inspace.NodeLoadBalancerVMFirewallDescription,
		Rules:       rules,
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: vmUUID},
		},
	}
}

// vmTestRule builds one ledger rule. No sources means any source.
func vmTestRule(protocol string, port int32, sources ...string) vmFirewallRule {
	if sources == nil {
		sources = []string{}
	}
	return vmFirewallRule{Protocol: protocol, Port: port, Sources: sources}
}

// vmTestMember builds a ledger member whose policy hash is the real one.
func vmTestMember(t *testing.T, uid string, rules ...vmFirewallRule) vmFirewallMember {
	t.Helper()
	member := vmFirewallMember{UID: uid, Rules: rules}
	policy, err := inspace.NodeLoadBalancerServiceFirewallSpecHash(vmFirewallMemberFirewallRules(member))
	if err != nil {
		t.Fatal(err)
	}
	member.Policy = policy
	return member
}

// vmTestLedger builds a ledger with the given members, in the order given.
func vmTestLedger(members ...vmFirewallMember) vmFirewallLedger {
	return vmFirewallLedger{V: 1, Members: members}
}
