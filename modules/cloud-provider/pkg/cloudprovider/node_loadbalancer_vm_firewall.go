package cloudprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// vmFirewallRule is one inbound port rule of a ledger member. No sources means
// any source.
type vmFirewallRule struct {
	Protocol string   `json:"protocol"`
	Port     int32    `json:"port"`
	Sources  []string `json:"sources"`
}

// vmFirewallMember is the exact rule set one Service policy asked for on one
// VM. The rules travel with the entry, so the CCM never needs another
// Service's live spec to rebuild the per-VM firewall.
type vmFirewallMember struct {
	UID    string           `json:"uid"`
	Policy string           `json:"policy"`
	Rules  []vmFirewallRule `json:"rules"`
}

type vmFirewallMemberKey struct{ UID, Policy string }

// vmFirewallLedger is the canonical member list of one per-VM firewall. It is
// the source of truth for rule ownership.
type vmFirewallLedger struct {
	V       int                `json:"v"`
	Members []vmFirewallMember `json:"members"`
}

const (
	vmFirewallLedgerVersion = 1
	// vmFirewallMaxEntriesPerUID allows the old and the new policy of one
	// Service while a policy transition runs. Nothing else may duplicate a UID.
	vmFirewallMaxEntriesPerUID = 2
)

var (
	errVMFirewallLedgerCorrupt = errors.New("public-node-local: VM firewall ledger is corrupt")
	vmFirewallPolicyPattern    = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

func corruptVMFirewallLedger(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errVMFirewallLedgerCorrupt, fmt.Sprintf(format, args...))
}

func (m vmFirewallMember) key() vmFirewallMemberKey {
	return vmFirewallMemberKey{UID: m.UID, Policy: m.Policy}
}

// vmFirewallMemberFirewallRules turns a member's rules into provider rules.
func vmFirewallMemberFirewallRules(m vmFirewallMember) []inspace.FirewallRule {
	rules := make([]inspace.FirewallRule, 0, len(m.Rules))
	for _, rule := range m.Rules {
		port := rule.Port
		out := inspace.FirewallRule{
			Protocol: rule.Protocol, Direction: "inbound",
			PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
		}
		if len(rule.Sources) != 0 {
			out.EndpointSpecType = "ip_prefixes"
			out.EndpointSpec = append([]string(nil), rule.Sources...)
		}
		rules = append(rules, out)
	}
	return rules
}

// vmFirewallMemberFromDesired builds the ledger entry of one Service policy.
func vmFirewallMemberFromDesired(serviceUID string, desired desiredNodeLoadBalancerFirewall) (vmFirewallMember, error) {
	if err := validateNodeLoadBalancerServiceUID(serviceUID); err != nil {
		return vmFirewallMember{}, err
	}
	member := vmFirewallMember{UID: serviceUID, Policy: desired.Hash, Rules: make([]vmFirewallRule, 0, len(desired.Request.Rules))}
	for index, rule := range desired.Request.Rules {
		if rule.Direction != "inbound" || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
			return vmFirewallMember{}, fmt.Errorf("public-node-local: Service firewall rule %d is not one inbound port", index)
		}
		sources := []string{}
		switch rule.EndpointSpecType {
		case "any":
		case "ip_prefixes":
			canonical, err := canonicalNodeLoadBalancerSourceRanges(rule.EndpointSpec)
			if err != nil {
				return vmFirewallMember{}, err
			}
			sources = canonical
		default:
			return vmFirewallMember{}, fmt.Errorf("public-node-local: Service firewall rule %d endpoint type %q is unsupported", index, rule.EndpointSpecType)
		}
		member.Rules = append(member.Rules, vmFirewallRule{Protocol: rule.Protocol, Port: *rule.PortStart, Sources: sources})
	}
	sortVMFirewallRules(member.Rules)
	if err := validateVMFirewallMember(member); err != nil {
		return vmFirewallMember{}, err
	}
	return member, nil
}

func sortVMFirewallRules(rules []vmFirewallRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Protocol != rules[j].Protocol {
			return rules[i].Protocol < rules[j].Protocol
		}
		return rules[i].Port < rules[j].Port
	})
}

// validateVMFirewallMember requires a canonical entry whose rules hash to its
// recorded policy.
func validateVMFirewallMember(m vmFirewallMember) error {
	if err := validateNodeLoadBalancerServiceUID(m.UID); err != nil {
		return corruptVMFirewallLedger("%v", err)
	}
	if !vmFirewallPolicyPattern.MatchString(m.Policy) {
		return corruptVMFirewallLedger("member %s policy %q is not an 8 hex digit hash", m.UID, m.Policy)
	}
	if len(m.Rules) == 0 {
		return corruptVMFirewallLedger("member %s/%s has no rules", m.UID, m.Policy)
	}
	for index, rule := range m.Rules {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return corruptVMFirewallLedger("member %s/%s rule %d protocol %q is not tcp or udp", m.UID, m.Policy, index, rule.Protocol)
		}
		if rule.Port < 1 || rule.Port > 65535 {
			return corruptVMFirewallLedger("member %s/%s rule %d port %d is out of range", m.UID, m.Policy, index, rule.Port)
		}
		if index > 0 {
			previous := m.Rules[index-1]
			if previous.Protocol > rule.Protocol || (previous.Protocol == rule.Protocol && previous.Port >= rule.Port) {
				return corruptVMFirewallLedger("member %s/%s rules are not unique and sorted by protocol and port", m.UID, m.Policy)
			}
		}
		if rule.Sources == nil {
			return corruptVMFirewallLedger("member %s/%s rule %d has null sources", m.UID, m.Policy, index)
		}
		for sourceIndex, source := range rule.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != source {
				return corruptVMFirewallLedger("member %s/%s rule %d source %q is not a canonical IPv4 CIDR", m.UID, m.Policy, index, source)
			}
			if sourceIndex > 0 && rule.Sources[sourceIndex-1] >= source {
				return corruptVMFirewallLedger("member %s/%s rule %d sources are not unique and sorted", m.UID, m.Policy, index)
			}
		}
	}
	hash, err := inspace.NodeLoadBalancerServiceFirewallSpecHash(vmFirewallMemberFirewallRules(m))
	if err != nil {
		return corruptVMFirewallLedger("member %s/%s rules: %v", m.UID, m.Policy, err)
	}
	if hash != m.Policy {
		return corruptVMFirewallLedger("member %s rules hash to %s, not to its policy %s", m.UID, hash, m.Policy)
	}
	return nil
}

func validateVMFirewallLedger(l vmFirewallLedger) error {
	if l.V != vmFirewallLedgerVersion {
		return corruptVMFirewallLedger("unsupported version %d", l.V)
	}
	perUID := map[string]int{}
	seen := map[vmFirewallMemberKey]struct{}{}
	for index, member := range l.Members {
		if err := validateVMFirewallMember(member); err != nil {
			return err
		}
		if _, duplicate := seen[member.key()]; duplicate {
			return corruptVMFirewallLedger("member %s/%s appears twice", member.UID, member.Policy)
		}
		seen[member.key()] = struct{}{}
		perUID[member.UID]++
		if perUID[member.UID] > vmFirewallMaxEntriesPerUID {
			return corruptVMFirewallLedger("Service %s has more than %d entries", member.UID, vmFirewallMaxEntriesPerUID)
		}
		if index > 0 {
			previous := l.Members[index-1]
			if previous.UID > member.UID || (previous.UID == member.UID && previous.Policy >= member.Policy) {
				return corruptVMFirewallLedger("members are not sorted by UID then policy")
			}
		}
	}
	return nil
}

// canonicalVMFirewallLedger returns a sorted deep copy with no nil slices.
func canonicalVMFirewallLedger(l vmFirewallLedger) vmFirewallLedger {
	out := vmFirewallLedger{V: l.V, Members: make([]vmFirewallMember, 0, len(l.Members))}
	for _, member := range l.Members {
		copied := vmFirewallMember{UID: member.UID, Policy: member.Policy, Rules: make([]vmFirewallRule, 0, len(member.Rules))}
		for _, rule := range member.Rules {
			sources := append([]string{}, rule.Sources...)
			sort.Strings(sources)
			copied.Rules = append(copied.Rules, vmFirewallRule{Protocol: rule.Protocol, Port: rule.Port, Sources: sources})
		}
		sortVMFirewallRules(copied.Rules)
		out.Members = append(out.Members, copied)
	}
	sort.Slice(out.Members, func(i, j int) bool {
		if out.Members[i].UID != out.Members[j].UID {
			return out.Members[i].UID < out.Members[j].UID
		}
		return out.Members[i].Policy < out.Members[j].Policy
	})
	return out
}

// encodeVMFirewallLedger returns the canonical JSON of a ledger.
func encodeVMFirewallLedger(l vmFirewallLedger) (string, error) {
	canonical := canonicalVMFirewallLedger(l)
	if err := validateVMFirewallLedger(canonical); err != nil {
		return "", err
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", corruptVMFirewallLedger("encode: %v", err)
	}
	return string(raw), nil
}

// decodeVMFirewallLedger parses a ledger and requires it to be byte-for-byte
// canonical, so a hand edit or a partial write can never be mistaken for state.
func decodeVMFirewallLedger(raw string) (vmFirewallLedger, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var ledger vmFirewallLedger
	if err := decoder.Decode(&ledger); err != nil {
		return vmFirewallLedger{}, corruptVMFirewallLedger("decode: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return vmFirewallLedger{}, corruptVMFirewallLedger("trailing data after the ledger")
	}
	for index := range ledger.Members {
		if ledger.Members[index].Rules == nil {
			return vmFirewallLedger{}, corruptVMFirewallLedger("member %d has null rules", index)
		}
	}
	if err := validateVMFirewallLedger(canonicalVMFirewallLedger(ledger)); err != nil {
		return vmFirewallLedger{}, err
	}
	encoded, err := encodeVMFirewallLedger(ledger)
	if err != nil {
		return vmFirewallLedger{}, err
	}
	if !bytes.Equal([]byte(encoded), []byte(raw)) {
		return vmFirewallLedger{}, corruptVMFirewallLedger("ledger is not in canonical form")
	}
	return canonicalVMFirewallLedger(ledger), nil
}

func (l vmFirewallLedger) find(k vmFirewallMemberKey) (vmFirewallMember, bool) {
	for _, member := range l.Members {
		if member.key() == k {
			return member, true
		}
	}
	return vmFirewallMember{}, false
}

// with returns a copy of the ledger that also holds m. It refuses an entry
// that is already present and a third entry of one Service UID.
func (l vmFirewallLedger) with(m vmFirewallMember) (vmFirewallLedger, error) {
	if err := validateVMFirewallMember(m); err != nil {
		return vmFirewallLedger{}, err
	}
	if _, exists := l.find(m.key()); exists {
		return vmFirewallLedger{}, corruptVMFirewallLedger("member %s/%s is already in the ledger", m.UID, m.Policy)
	}
	entries := 0
	for _, member := range l.Members {
		if member.UID == m.UID {
			entries++
		}
	}
	if entries >= vmFirewallMaxEntriesPerUID {
		return vmFirewallLedger{}, corruptVMFirewallLedger("Service %s already has %d entries", m.UID, entries)
	}
	next := canonicalVMFirewallLedger(l)
	next.V = vmFirewallLedgerVersion
	next.Members = append(next.Members, canonicalVMFirewallLedger(vmFirewallLedger{V: 1, Members: []vmFirewallMember{m}}).Members[0])
	return canonicalVMFirewallLedger(next), nil
}

// without returns a copy of the ledger with entry k removed.
func (l vmFirewallLedger) without(k vmFirewallMemberKey) (vmFirewallLedger, bool) {
	next := canonicalVMFirewallLedger(l)
	next.V = vmFirewallLedgerVersion
	kept := next.Members[:0]
	found := false
	for _, member := range next.Members {
		if member.key() == k {
			found = true
			continue
		}
		kept = append(kept, member)
	}
	next.Members = kept
	return next, found
}
