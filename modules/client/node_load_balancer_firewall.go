package inspace

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	nodeLoadBalancerServiceFirewallPattern = regexp.MustCompile(`^inlb-([0-9a-f]{8})-([a-z0-9](?:[a-z0-9-]{0,34}[a-z0-9])?)-([0-9a-f]{8})$`)
	nodeLoadBalancerShardFirewallPattern   = regexp.MustCompile(`^inlb-([0-9a-f]{32})-shard-([0-9a-f]{8})$`)
	nodeLoadBalancerShardNamePattern       = regexp.MustCompile(`^inlb-([0-9a-f]{8})$`)
	nodeLoadBalancerPolicyHashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nodeLoadBalancerICMPFirewallPattern    = regexp.MustCompile(`^inlb-([0-9a-f]{32})-icmp-([0-9a-f]{8})$`)
	nodeLoadBalancerServiceUIDPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,34}[a-z0-9])?$`)
)

// NodeLoadBalancerShardFirewallSpecHash returns the canonical policy hash for
// the aggregate inbound TCP/UDP policy attached to one managed NodeLB shard.
// Provider-assigned rule UUIDs and input ordering do not affect the hash.
func NodeLoadBalancerShardFirewallSpecHash(rules []FirewallRule) (string, error) {
	canonical, err := canonicalNodeLoadBalancerPortFirewallPolicy("shard", rules)
	if err != nil {
		return "", err
	}
	return nodeLoadBalancerFullHash(canonical), nil
}

// NodeLoadBalancerServiceFirewallSpecHash returns the canonical policy hash
// shared by CCM (producer) and Karpenter (consumer). A Service firewall is
// intentionally limited to one or more inbound TCP/UDP port rules; the
// cluster-wide ICMP rule has a separate identity and validator.
//
// Deprecated: use NodeLoadBalancerShardFirewallSpecHash. Per-Service NodeLB
// firewalls existed only in release-candidate builds.
func NodeLoadBalancerServiceFirewallSpecHash(rules []FirewallRule) (string, error) {
	canonical, err := canonicalNodeLoadBalancerPortFirewallPolicy("Service", rules)
	if err != nil {
		return "", err
	}
	return nodeLoadBalancerShortHash(canonical), nil
}

func canonicalNodeLoadBalancerPortFirewallPolicy(kind string, rules []FirewallRule) (string, error) {
	if len(rules) == 0 {
		return "", fmt.Errorf("%s firewall requires at least one ingress rule", kind)
	}
	keys := make([]string, 0, len(rules))
	seenRules := make(map[string]struct{}, len(rules))
	seenPorts := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		if rule.Direction != "inbound" {
			return "", fmt.Errorf("%s firewall rule %d must be inbound", kind, index)
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return "", fmt.Errorf("%s firewall rule %d protocol %q must be lowercase tcp or udp", kind, index, rule.Protocol)
		}
		if rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd || *rule.PortStart < 1 || *rule.PortStart > 65535 {
			return "", fmt.Errorf("%s firewall rule %d must contain one explicit valid port", kind, index)
		}
		port := strconv.FormatInt(int64(*rule.PortStart), 10)
		portKey := rule.Protocol + "|" + port
		if _, exists := seenPorts[portKey]; exists {
			return "", fmt.Errorf("%s firewall rule %d duplicates public %s/%s", kind, index, rule.Protocol, port)
		}
		seenPorts[portKey] = struct{}{}

		endpoints, err := canonicalNodeLoadBalancerFirewallEndpoints(kind, index, rule)
		if err != nil {
			return "", err
		}
		key := strings.Join([]string{rule.Protocol, port, rule.EndpointSpecType, strings.Join(endpoints, ",")}, "|")
		if _, exists := seenRules[key]; exists {
			return "", fmt.Errorf("%s firewall rule %d duplicates an existing canonical rule", kind, index)
		}
		seenRules[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n"), nil
}

// NodeLoadBalancerClusterICMPFirewallSpecHash validates and hashes the single
// reusable cluster policy: inbound ICMP from Any, with no ports or prefixes.
func NodeLoadBalancerClusterICMPFirewallSpecHash(rules []FirewallRule) (string, error) {
	if len(rules) != 1 {
		return "", errors.New("cluster ICMP firewall must contain exactly one rule")
	}
	rule := rules[0]
	if rule.Protocol != "icmp" || rule.Direction != "inbound" || rule.PortStart != nil || rule.PortEnd != nil ||
		rule.EndpointSpecType != "any" || len(rule.EndpointSpec) != 0 {
		return "", errors.New("cluster ICMP firewall must contain only portless inbound ICMP from any")
	}
	return nodeLoadBalancerShortHash("icmp|inbound|any"), nil
}

func canonicalNodeLoadBalancerFirewallEndpoints(kind string, index int, rule FirewallRule) ([]string, error) {
	switch rule.EndpointSpecType {
	case "any":
		if len(rule.EndpointSpec) != 0 {
			return nil, fmt.Errorf("%s firewall rule %d endpoint any must not include prefixes", kind, index)
		}
		return nil, nil
	case "ip_prefixes":
		if len(rule.EndpointSpec) == 0 {
			return nil, fmt.Errorf("%s firewall rule %d must include IPv4 prefixes", kind, index)
		}
		result := make([]string, 0, len(rule.EndpointSpec))
		seen := make(map[string]struct{}, len(rule.EndpointSpec))
		for _, value := range rule.EndpointSpec {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != value {
				return nil, fmt.Errorf("%s firewall rule %d prefix %q must be canonical IPv4 CIDR", kind, index, value)
			}
			if _, exists := seen[value]; exists {
				return nil, fmt.Errorf("%s firewall rule %d prefix %q is duplicated", kind, index, value)
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
		sort.Strings(result)
		return result, nil
	default:
		return nil, fmt.Errorf("%s firewall rule %d endpoint type %q is unsupported", kind, index, rule.EndpointSpecType)
	}
}

// NodeLoadBalancerShardFirewallName returns the stable CCM-owned firewall name
// for one managed shard. Policy changes deliberately do not change this name.
func NodeLoadBalancerShardFirewallName(cluster, shard string) (string, error) {
	if cluster == "" {
		return "", errors.New("cluster identity is required")
	}
	matches := nodeLoadBalancerShardNamePattern.FindStringSubmatch(shard)
	if len(matches) != 2 {
		return "", fmt.Errorf("managed shard name %q must match inlb-<8 lowercase hex characters>", shard)
	}
	return "inlb-" + nodeLoadBalancerOwnershipHash(cluster) + "-shard-" + matches[1], nil
}

// NodeLoadBalancerServiceFirewallName returns the deterministic CCM-owned
// name and policy hash for one Service firewall.
//
// Deprecated: use NodeLoadBalancerShardFirewallName. Per-Service NodeLB
// firewalls existed only in release-candidate builds.
func NodeLoadBalancerServiceFirewallName(cluster, serviceUID string, rules []FirewallRule) (string, string, error) {
	if cluster == "" || !validNodeLoadBalancerServiceUID(serviceUID) {
		return "", "", errors.New("cluster identity and a lowercase DNS Service UID of at most 36 characters are required")
	}
	hash, err := NodeLoadBalancerServiceFirewallSpecHash(rules)
	if err != nil {
		return "", "", err
	}
	return "inlb-" + nodeLoadBalancerShortHash(cluster) + "-" + serviceUID + "-" + hash, hash, nil
}

// NodeLoadBalancerClusterICMPFirewallName returns the deterministic name and
// policy hash for the reusable cluster ICMP firewall.
func NodeLoadBalancerClusterICMPFirewallName(cluster string, rules []FirewallRule) (string, string, error) {
	if cluster == "" {
		return "", "", errors.New("cluster identity is required")
	}
	hash, err := NodeLoadBalancerClusterICMPFirewallSpecHash(rules)
	if err != nil {
		return "", "", err
	}
	return "inlb-" + nodeLoadBalancerOwnershipHash(cluster) + "-icmp-" + hash, hash, nil
}

// ValidateNodeLoadBalancerShardFirewall verifies stable shard ownership and
// requires the current aggregate policy to match expectedPolicyHash exactly.
// The policy hash is passed separately because it is intentionally absent from
// the stable firewall name.
func ValidateNodeLoadBalancerShardFirewall(firewall Firewall, cluster, shard string, billingAccountID int64, expectedPolicyHash string) error {
	if cluster == "" || billingAccountID < 1 || firewall.BillingAccountID != billingAccountID {
		return errors.New("shard firewall cluster and billing identity do not match")
	}
	name, err := NodeLoadBalancerShardFirewallName(cluster, shard)
	if err != nil {
		return err
	}
	if firewall.EffectiveName() != name || !nodeLoadBalancerShardFirewallPattern.MatchString(firewall.EffectiveName()) {
		return fmt.Errorf("name %q is not the owned firewall for shard %q", firewall.EffectiveName(), shard)
	}
	if !nodeLoadBalancerPolicyHashPattern.MatchString(expectedPolicyHash) {
		return fmt.Errorf("expected shard firewall policy hash %q is invalid", expectedPolicyHash)
	}
	actualPolicyHash, err := NodeLoadBalancerShardFirewallSpecHash(firewall.Rules)
	if err != nil {
		return err
	}
	if actualPolicyHash != expectedPolicyHash {
		return fmt.Errorf("shard firewall policy hash %q does not match expected hash %q", actualPolicyHash, expectedPolicyHash)
	}
	return nil
}

// Deprecated: use ValidateNodeLoadBalancerShardFirewall. Per-Service NodeLB
// firewalls existed only in release-candidate builds.
func ValidateNodeLoadBalancerServiceFirewall(firewall Firewall, cluster string, billingAccountID int64) error {
	if cluster == "" || billingAccountID < 1 || firewall.BillingAccountID != billingAccountID {
		return errors.New("Service firewall cluster and billing identity do not match")
	}
	matches := nodeLoadBalancerServiceFirewallPattern.FindStringSubmatch(firewall.EffectiveName())
	if len(matches) != 4 || matches[1] != nodeLoadBalancerShortHash(cluster) || !validNodeLoadBalancerServiceUID(matches[2]) {
		return fmt.Errorf("name %q is not an owned Service firewall for this cluster", firewall.EffectiveName())
	}
	hash, err := NodeLoadBalancerServiceFirewallSpecHash(firewall.Rules)
	if err != nil {
		return err
	}
	if matches[3] != hash {
		return fmt.Errorf("name spec hash %q does not match Service policy hash %q", matches[3], hash)
	}
	return nil
}

func ValidateNodeLoadBalancerClusterICMPFirewall(firewall Firewall, cluster string, billingAccountID int64) error {
	if cluster == "" || billingAccountID < 1 || firewall.BillingAccountID != billingAccountID {
		return errors.New("cluster ICMP firewall cluster and billing identity do not match")
	}
	matches := nodeLoadBalancerICMPFirewallPattern.FindStringSubmatch(firewall.EffectiveName())
	if len(matches) != 3 || matches[1] != nodeLoadBalancerOwnershipHash(cluster) {
		return fmt.Errorf("name %q is not an owned cluster ICMP firewall", firewall.EffectiveName())
	}
	hash, err := NodeLoadBalancerClusterICMPFirewallSpecHash(firewall.Rules)
	if err != nil {
		return err
	}
	if matches[2] != hash {
		return fmt.Errorf("name spec hash %q does not match cluster ICMP policy hash %q", matches[2], hash)
	}
	return nil
}

func validNodeLoadBalancerServiceUID(value string) bool {
	return len(value) <= 36 && nodeLoadBalancerServiceUIDPattern.MatchString(value)
}

func nodeLoadBalancerShortHash(value string) string {
	return nodeLoadBalancerFullHash(value)[:8]
}

func nodeLoadBalancerOwnershipHash(value string) string {
	return nodeLoadBalancerFullHash(value)[:32]
}

func nodeLoadBalancerFullHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
