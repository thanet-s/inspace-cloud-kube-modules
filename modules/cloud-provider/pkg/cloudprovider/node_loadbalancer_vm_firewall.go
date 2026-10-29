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
	"time"

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

const (
	// vmFirewallSettleDefault is how long a Service waits after a per-VM
	// firewall change is read back before it relies on the new edge.
	// LIVE-8.2 measured 2026-10-29: rules took effect at most about 1.0 s after
	// the call started (0.43 s after it returned); 2 x max is about 2 s, so the
	// 10 s floor applies.
	vmFirewallSettleDefault = 10 * time.Second
	// vmFirewallRenameSupported says a firewall can be renamed in place.
	// LIVE-8.2 measured 2026-10-29: supported only through the display_name field
	// of a PUT (the client sends it as such). The name field is accepted and
	// silently ignored, so a rename is always verified by reading the name back.
	vmFirewallRenameSupported = true
	// maxVMFirewallRules is the client-side rule-count limit; 0 means none.
	// LIVE-8.2 measured 2026-10-29: no limit up to 50 rules. PUT latency grows
	// with the rule count (about 3.3 s at 20, about 10 s at 50), which
	// vmFirewallMutationTimeout accounts for.
	maxVMFirewallRules = 0

	// vmFirewallMutationTimeoutBase and vmFirewallMutationTimeoutPerRule size the
	// deadline of one create or PUT: the measured latency was about 1 s plus
	// 0.2 s per rule, and the allowance is several times that.
	vmFirewallMutationTimeoutBase    = 30 * time.Second
	vmFirewallMutationTimeoutPerRule = 2 * time.Second
)

// maxVMFirewallRulesForTest lets a test lower the limit; production never
// changes it from maxVMFirewallRules.
var maxVMFirewallRulesForTest = maxVMFirewallRules

// vmFirewallMutationTimeout is the deadline of one create or PUT with ruleCount
// rules. It never exceeds nodeLoadBalancerShardFirewallMutationTimeout, so the
// receipt retire delay still proves that a timed-out request is not in flight.
func vmFirewallMutationTimeout(ruleCount int) time.Duration {
	if ruleCount < 0 {
		ruleCount = 0
	}
	timeout := vmFirewallMutationTimeoutBase + time.Duration(ruleCount)*vmFirewallMutationTimeoutPerRule
	if timeout > nodeLoadBalancerShardFirewallMutationTimeout {
		return nodeLoadBalancerShardFirewallMutationTimeout
	}
	return timeout
}

// vmFirewallRenameApplied reports whether a rename read back. InSpace honours
// only the display_name field of a PUT; the name field is accepted with a 200
// and ignored, so a rename is never assumed from the response. Only the name
// read back from the list endpoint proves it (a single GET is not available).
func vmFirewallRenameApplied(firewall inspace.Firewall, wantName string) bool {
	return firewall.EffectiveName() == wantName
}

// errVMFirewallPortConflict reports that two Services ask for one public port
// of the same VM. The operation that would create it is refused and nothing is
// persisted; existing members stay untouched.
type errVMFirewallPortConflict struct {
	Protocol string
	Port     int32
	UIDs     []string
}

func (e *errVMFirewallPortConflict) Error() string {
	return fmt.Sprintf("public-node-local: VM firewall %s/%d is requested by more than one Service (%s)",
		e.Protocol, e.Port, strings.Join(e.UIDs, ", "))
}

// errVMFirewallRuleLimit reports a merge with more rules than the client-side
// limit allows.
type errVMFirewallRuleLimit struct{ Rules, Limit int }

func (e *errVMFirewallRuleLimit) Error() string {
	return fmt.Sprintf("public-node-local: VM firewall would carry %d rules, above the limit of %d", e.Rules, e.Limit)
}

// mergeVMFirewallLedger returns the rules of the per-VM firewall: for every
// protocol/port, the sources of the one Service that asks for it. Within one
// Service (a policy transition) the sources are the union and any wins.
func mergeVMFirewallLedger(l vmFirewallLedger) ([]inspace.FirewallRule, error) {
	if len(l.Members) == 0 {
		return nil, errors.New("public-node-local: an empty VM firewall ledger has no rules; delete the firewall instead")
	}
	type claim struct {
		owners  map[string]struct{}
		any     bool
		sources map[string]struct{}
	}
	claims := map[string]*claim{}
	order := []vmFirewallRule{}
	for _, member := range l.Members {
		for _, rule := range member.Rules {
			key := fmt.Sprintf("%s/%d", rule.Protocol, rule.Port)
			c := claims[key]
			if c == nil {
				c = &claim{owners: map[string]struct{}{}, sources: map[string]struct{}{}}
				claims[key] = c
				order = append(order, vmFirewallRule{Protocol: rule.Protocol, Port: rule.Port})
			}
			c.owners[member.UID] = struct{}{}
			if len(rule.Sources) == 0 {
				c.any = true
			}
			for _, source := range rule.Sources {
				c.sources[source] = struct{}{}
			}
		}
	}
	sortVMFirewallRules(order)
	rules := make([]inspace.FirewallRule, 0, len(order))
	for _, id := range order {
		c := claims[fmt.Sprintf("%s/%d", id.Protocol, id.Port)]
		if len(c.owners) > 1 {
			uids := make([]string, 0, len(c.owners))
			for uid := range c.owners {
				uids = append(uids, uid)
			}
			sort.Strings(uids)
			return nil, &errVMFirewallPortConflict{Protocol: id.Protocol, Port: id.Port, UIDs: uids}
		}
		port := id.Port
		rule := inspace.FirewallRule{
			Protocol: id.Protocol, Direction: "inbound",
			PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
		}
		if !c.any {
			sources := make([]string, 0, len(c.sources))
			for source := range c.sources {
				sources = append(sources, source)
			}
			sort.Strings(sources)
			rule.EndpointSpecType = "ip_prefixes"
			rule.EndpointSpec = sources
		}
		rules = append(rules, rule)
	}
	if limit := maxVMFirewallRulesForTest; limit > 0 && len(rules) > limit {
		return nil, &errVMFirewallRuleLimit{Rules: len(rules), Limit: limit}
	}
	if _, err := inspace.NodeLoadBalancerVMFirewallSpecHash(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// vmFirewallCreateRequest is the create body for the first member of a VM.
func vmFirewallCreateRequest(cluster, vmUUID string, billing int64, merged []inspace.FirewallRule) (inspace.CreateFirewallRequest, error) {
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return inspace.CreateFirewallRequest{}, err
	}
	if billing < 1 {
		return inspace.CreateFirewallRequest{}, errors.New("public-node-local: the billing account is required to create a VM firewall")
	}
	if _, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged); err != nil {
		return inspace.CreateFirewallRequest{}, err
	}
	rules := retainFirewallRuleUUIDs(nil, merged)
	return inspace.CreateFirewallRequest{
		DisplayName: name, Description: inspace.NodeLoadBalancerVMFirewallDescription,
		BillingAccountID: billing, Rules: rules,
	}, nil
}

// vmFirewallUpdateRequest is the full replace-style PUT body that turns
// current into merged. Rules whose protocol/port survive keep their provider
// UUID. The name goes out as display_name, the only field InSpace honours.
func vmFirewallUpdateRequest(cluster, vmUUID string, current inspace.Firewall, merged []inspace.FirewallRule) (inspace.UpdateFirewallRequest, error) {
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return inspace.UpdateFirewallRequest{}, err
	}
	if !nodeLoadBalancerFirewallUUIDPattern.MatchString(current.UUID) {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: current VM firewall UUID %q is invalid", current.UUID)
	}
	if current.Name != "" && current.DisplayName != "" && current.Name != current.DisplayName {
		return inspace.UpdateFirewallRequest{}, errors.New("public-node-local: current VM firewall has conflicting name fields")
	}
	if current.EffectiveName() != name {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: firewall %q is not the VM firewall %q", current.EffectiveName(), name)
	}
	if current.Description != "" && current.Description != inspace.NodeLoadBalancerVMFirewallDescription {
		return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: current VM firewall description %q is not the managed description", current.Description)
	}
	seen := map[string]struct{}{}
	for _, rule := range current.Rules {
		if rule.UUID == "" {
			continue
		}
		if !nodeLoadBalancerFirewallUUIDPattern.MatchString(rule.UUID) {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: current VM firewall rule UUID %q is invalid", rule.UUID)
		}
		if _, duplicate := seen[strings.ToLower(rule.UUID)]; duplicate {
			return inspace.UpdateFirewallRequest{}, fmt.Errorf("public-node-local: current VM firewall reuses rule UUID %q", rule.UUID)
		}
		seen[strings.ToLower(rule.UUID)] = struct{}{}
	}
	if _, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged); err != nil {
		return inspace.UpdateFirewallRequest{}, err
	}
	return inspace.UpdateFirewallRequest{
		Name:        name,
		Description: inspace.NodeLoadBalancerVMFirewallDescription,
		Rules:       retainFirewallRuleUUIDs(current.Rules, merged),
	}, nil
}
