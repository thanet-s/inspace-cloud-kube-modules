package cloudprovider

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const nodeLoadBalancerShardFirewallDescription = "Managed InSpace node load balancer shard firewall"

var nodeLoadBalancerFirewallUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type nodeLoadBalancerShardFirewallMember struct {
	ServiceUID string
	PolicyHash string
}

// nodeLoadBalancerShardFirewallPolicy is the canonical public edge policy for
// one exact planner shard. Members is also the durable membership ledger:
// callers must not infer membership from firewall rules because a Service may
// own more than one port. Each member hash lets reconciliation distinguish an
// applied old Service policy from a newly observed Service spec.
type nodeLoadBalancerShardFirewallPolicy struct {
	ClusterID string
	Shard     string
	Members   []nodeLoadBalancerShardFirewallMember
	Request   inspace.CreateFirewallRequest
	Hash      string
}

// desiredNodeLoadBalancerShardFirewall builds one deterministic firewall from
// exactly the Services claimed by shard. It revalidates both membership and
// the planner's port union so a stale or partially observed Service list fails
// closed instead of widening the public edge.
func desiredNodeLoadBalancerShardFirewall(
	clusterID string,
	billingAccountID int64,
	shard nodeLoadBalancerShardPlan,
	services []*corev1.Service,
) (nodeLoadBalancerShardFirewallPolicy, error) {
	if clusterID == "" || billingAccountID < 1 {
		return nodeLoadBalancerShardFirewallPolicy{}, errors.New("node load balancer: cluster identity and billing account are required for the shard firewall")
	}
	name, err := inspace.NodeLoadBalancerShardFirewallName(clusterID, shard.Name)
	if err != nil {
		return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard firewall name: %w", err)
	}

	claims := make(map[string]struct{}, len(shard.Claims))
	serviceUIDs := append([]string(nil), shard.Claims...)
	for _, serviceUID := range serviceUIDs {
		if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q claim: %w", shard.Name, err)
		}
		if _, exists := claims[serviceUID]; exists {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q claims Service UID %q more than once", shard.Name, serviceUID)
		}
		claims[serviceUID] = struct{}{}
	}
	if len(claims) == 0 {
		return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q has no Service claims", shard.Name)
	}
	sort.Strings(serviceUIDs)

	servicesByUID := make(map[string]*corev1.Service, len(services))
	for index, service := range services {
		if service == nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service %d is nil", shard.Name, index)
		}
		serviceUID := string(service.UID)
		if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service %s/%s: %w", shard.Name, service.Namespace, service.Name, err)
		}
		if _, claimed := claims[serviceUID]; !claimed {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q received unclaimed Service UID %q", shard.Name, serviceUID)
		}
		if _, exists := servicesByUID[serviceUID]; exists {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q received Service UID %q more than once", shard.Name, serviceUID)
		}
		servicesByUID[serviceUID] = service
	}
	if len(servicesByUID) != len(claims) {
		missing := make([]string, 0, len(claims)-len(servicesByUID))
		for serviceUID := range claims {
			if servicesByUID[serviceUID] == nil {
				missing = append(missing, serviceUID)
			}
		}
		sort.Strings(missing)
		return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q is missing claimed Service UIDs %s", shard.Name, strings.Join(missing, ","))
	}

	plannedPorts := make(map[nodeLoadBalancerPortClaim]struct{}, len(shard.Ports))
	for _, claim := range shard.Ports {
		if claim.IPFamily != corev1.IPv4Protocol || (claim.Protocol != corev1.ProtocolTCP && claim.Protocol != corev1.ProtocolUDP) || claim.Port < 1 || claim.Port > 65535 {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q has invalid planned port %#v", shard.Name, claim)
		}
		if _, exists := plannedPorts[claim]; exists {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q contains duplicate planned %s/%d", shard.Name, claim.Protocol, claim.Port)
		}
		plannedPorts[claim] = struct{}{}
	}

	type ownedRule struct {
		claim      nodeLoadBalancerPortClaim
		serviceUID string
		rule       inspace.FirewallRule
	}
	ownedRules := make([]ownedRule, 0, len(plannedPorts))
	portOwners := make(map[string]string, len(plannedPorts))
	observedPorts := make(map[nodeLoadBalancerPortClaim]struct{}, len(plannedPorts))
	members := make([]nodeLoadBalancerShardFirewallMember, 0, len(serviceUIDs))
	for _, serviceUID := range serviceUIDs {
		service := servicesByUID[serviceUID]
		sources, err := canonicalNodeLoadBalancerSourceRanges(service.Spec.LoadBalancerSourceRanges)
		if err != nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service UID %q: %w", shard.Name, serviceUID, err)
		}
		ports, err := nodeLoadBalancerPortClaims(service)
		if err != nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service UID %q: %w", shard.Name, serviceUID, err)
		}
		serviceRules := make([]inspace.FirewallRule, 0, len(ports))
		for _, claim := range ports {
			logicalKey := nodeLoadBalancerShardFirewallLogicalPortKey(strings.ToLower(string(claim.Protocol)), claim.Port)
			if owner, exists := portOwners[logicalKey]; exists && owner != serviceUID {
				return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q public %s/%d is owned by both Service UIDs %q and %q", shard.Name, claim.Protocol, claim.Port, owner, serviceUID)
			}
			portOwners[logicalKey] = serviceUID
			observedPorts[claim] = struct{}{}

			start, stop := claim.Port, claim.Port
			rule := inspace.FirewallRule{
				Protocol: strings.ToLower(string(claim.Protocol)), Direction: "inbound",
				PortStart: &start, PortEnd: &stop, EndpointSpecType: "any",
			}
			if len(sources) != 0 {
				rule.EndpointSpecType = "ip_prefixes"
				rule.EndpointSpec = append([]string(nil), sources...)
			}
			ownedRules = append(ownedRules, ownedRule{claim: claim, serviceUID: serviceUID, rule: rule})
			serviceRules = append(serviceRules, rule)
		}
		servicePolicyHash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(serviceRules)
		if err != nil {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service UID %q firewall policy: %w", shard.Name, serviceUID, err)
		}
		members = append(members, nodeLoadBalancerShardFirewallMember{ServiceUID: serviceUID, PolicyHash: servicePolicyHash})
	}
	if len(observedPorts) != len(plannedPorts) {
		return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q observed %d Service ports but its plan contains %d", shard.Name, len(observedPorts), len(plannedPorts))
	}
	for claim := range plannedPorts {
		if _, exists := observedPorts[claim]; !exists {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q planned %s/%d has no exact Service owner", shard.Name, claim.Protocol, claim.Port)
		}
	}
	for claim := range observedPorts {
		if _, exists := plannedPorts[claim]; !exists {
			return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q Service-owned %s/%d is absent from the plan", shard.Name, claim.Protocol, claim.Port)
		}
	}

	sort.Slice(ownedRules, func(i, j int) bool {
		if ownedRules[i].rule.Protocol != ownedRules[j].rule.Protocol {
			return ownedRules[i].rule.Protocol < ownedRules[j].rule.Protocol
		}
		if *ownedRules[i].rule.PortStart != *ownedRules[j].rule.PortStart {
			return *ownedRules[i].rule.PortStart < *ownedRules[j].rule.PortStart
		}
		return ownedRules[i].serviceUID < ownedRules[j].serviceUID
	})
	rules := make([]inspace.FirewallRule, 0, len(ownedRules))
	for _, owned := range ownedRules {
		rules = append(rules, owned.rule)
	}
	hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(rules)
	if err != nil {
		return nodeLoadBalancerShardFirewallPolicy{}, fmt.Errorf("node load balancer: shard %q firewall policy: %w", shard.Name, err)
	}
	policy := nodeLoadBalancerShardFirewallPolicy{
		ClusterID: clusterID,
		Shard:     shard.Name,
		Members:   members,
		Request: inspace.CreateFirewallRequest{
			DisplayName:      name,
			Description:      nodeLoadBalancerShardFirewallDescription,
			BillingAccountID: billingAccountID,
			Rules:            rules,
		},
		Hash: hash,
	}
	if err := validateNodeLoadBalancerShardFirewallPolicy(policy); err != nil {
		return nodeLoadBalancerShardFirewallPolicy{}, err
	}
	return policy, nil
}

// nodeLoadBalancerShardFirewallUpdateRequest forms a full replace-style PUT
// body. A rule keeps its provider UUID when its logical protocol/port remains
// present, including when only its source ranges change. New logical ports
// deliberately omit UUID; removed ports are deliberately absent.
func nodeLoadBalancerShardFirewallUpdateRequest(
	current inspace.Firewall,
	desired nodeLoadBalancerShardFirewallPolicy,
) (inspace.UpdateFirewallRequest, error) {
	if err := validateNodeLoadBalancerShardFirewallPolicy(desired); err != nil {
		return inspace.UpdateFirewallRequest{}, err
	}
	if !nodeLoadBalancerFirewallUUIDPattern.MatchString(current.UUID) {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current shard firewall UUID %q is invalid", current.UUID)
	}
	if current.Name != "" && current.DisplayName != "" && current.Name != current.DisplayName {
		return inspace.UpdateFirewallRequest{}, errors.New("node load balancer: current shard firewall has conflicting name fields")
	}
	if current.Description != "" && current.Description != desired.Request.Description {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current shard firewall description %q does not match the managed description", current.Description)
	}
	currentHash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(current.Rules)
	if err != nil {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current shard firewall policy: %w", err)
	}
	if err := inspace.ValidateNodeLoadBalancerShardFirewall(
		current,
		desired.ClusterID,
		desired.Shard,
		desired.Request.BillingAccountID,
		currentHash,
	); err != nil {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current shard firewall lost exact ownership: %w", err)
	}

	currentRuleUUIDs := make(map[string]string, len(current.Rules))
	seenUUIDs := make(map[string]struct{}, len(current.Rules))
	for _, rule := range current.Rules {
		if !nodeLoadBalancerFirewallUUIDPattern.MatchString(rule.UUID) {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current %s/%d shard firewall rule UUID %q is invalid", rule.Protocol, *rule.PortStart, rule.UUID)
		}
		uuidKey := strings.ToLower(rule.UUID)
		if _, exists := seenUUIDs[uuidKey]; exists {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("node load balancer: current shard firewall reuses rule UUID %q", rule.UUID)
		}
		seenUUIDs[uuidKey] = struct{}{}
		currentRuleUUIDs[nodeLoadBalancerShardFirewallRuleLogicalKey(rule)] = rule.UUID
	}

	rules := make([]inspace.FirewallRule, 0, len(desired.Request.Rules))
	for _, desiredRule := range desired.Request.Rules {
		copy := desiredRule
		copy.EndpointSpec = append([]string(nil), desiredRule.EndpointSpec...)
		copy.UUID = currentRuleUUIDs[nodeLoadBalancerShardFirewallRuleLogicalKey(desiredRule)]
		rules = append(rules, copy)
	}
	return inspace.UpdateFirewallRequest{
		Name:        desired.Request.DisplayName,
		Description: desired.Request.Description,
		Rules:       rules,
	}, nil
}

func validateNodeLoadBalancerShardFirewallPolicy(policy nodeLoadBalancerShardFirewallPolicy) error {
	if policy.ClusterID == "" || policy.Shard == "" || policy.Request.BillingAccountID < 1 || len(policy.Members) == 0 {
		return errors.New("node load balancer: shard firewall policy identity, billing account, and membership are required")
	}
	name, err := inspace.NodeLoadBalancerShardFirewallName(policy.ClusterID, policy.Shard)
	if err != nil {
		return fmt.Errorf("node load balancer: shard firewall policy name: %w", err)
	}
	if policy.Request.DisplayName != name || policy.Request.Description != nodeLoadBalancerShardFirewallDescription {
		return errors.New("node load balancer: shard firewall policy request identity is not canonical")
	}
	for index, member := range policy.Members {
		if err := validateNodeLoadBalancerServiceUID(member.ServiceUID); err != nil {
			return err
		}
		if !validNodeLoadBalancerShardFirewallPolicyHash(member.PolicyHash) {
			return fmt.Errorf("node load balancer: shard firewall member %q policy hash %q is invalid", member.ServiceUID, member.PolicyHash)
		}
		if index > 0 && policy.Members[index-1].ServiceUID >= member.ServiceUID {
			return errors.New("node load balancer: shard firewall policy Service UIDs must be unique and sorted")
		}
	}
	hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(policy.Request.Rules)
	if err != nil {
		return fmt.Errorf("node load balancer: shard firewall policy rules: %w", err)
	}
	for index, rule := range policy.Request.Rules {
		if rule.UUID != "" {
			return errors.New("node load balancer: create shard firewall rules must not contain provider UUIDs")
		}
		if index > 0 {
			previous := policy.Request.Rules[index-1]
			if previous.Protocol > rule.Protocol ||
				(previous.Protocol == rule.Protocol && *previous.PortStart >= *rule.PortStart) {
				return errors.New("node load balancer: shard firewall policy rules must be unique and sorted by protocol and port")
			}
		}
		for endpointIndex := 1; endpointIndex < len(rule.EndpointSpec); endpointIndex++ {
			if rule.EndpointSpec[endpointIndex-1] >= rule.EndpointSpec[endpointIndex] {
				return errors.New("node load balancer: shard firewall policy source ranges must be unique and sorted")
			}
		}
	}
	if policy.Hash != hash {
		return fmt.Errorf("node load balancer: shard firewall policy hash %q does not match canonical hash %q", policy.Hash, hash)
	}
	return nil
}

// nodeLoadBalancerShardFirewallPolicyLedger encodes the exact applied member
// set in a deterministic annotation-safe form. DNS-label UIDs and lowercase
// hexadecimal policy hashes cannot contain either delimiter.
func nodeLoadBalancerShardFirewallPolicyLedger(policy nodeLoadBalancerShardFirewallPolicy) (string, error) {
	if err := validateNodeLoadBalancerShardFirewallPolicy(policy); err != nil {
		return "", err
	}
	entries := make([]string, 0, len(policy.Members))
	for _, member := range policy.Members {
		entries = append(entries, member.ServiceUID+"="+member.PolicyHash)
	}
	return strings.Join(entries, ","), nil
}

func nodeLoadBalancerShardFirewallRuleLogicalKey(rule inspace.FirewallRule) string {
	port := int32(0)
	if rule.PortStart != nil {
		port = *rule.PortStart
	}
	return nodeLoadBalancerShardFirewallLogicalPortKey(rule.Protocol, port)
}

func nodeLoadBalancerShardFirewallLogicalPortKey(protocol string, port int32) string {
	return protocol + "/" + strconv.FormatInt(int64(port), 10)
}
