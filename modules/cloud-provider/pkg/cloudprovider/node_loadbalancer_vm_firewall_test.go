package cloudprovider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// rawVMFirewallLedger marshals a ledger exactly as given, without the sorting
// and normalization of encodeVMFirewallLedger.
func rawVMFirewallLedger(t *testing.T, l vmFirewallLedger) string {
	t.Helper()
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestVMFirewallLedgerRoundTripIsCanonical(t *testing.T) {
	s2 := vmTestMember(t, "svc-b", vmTestRule("udp", 53), vmTestRule("tcp", 8443, "203.0.113.0/24", "198.51.100.0/24"))
	s1 := vmTestMember(t, "svc-a", vmTestRule("tcp", 1935))
	s1b := vmTestMember(t, "svc-a", vmTestRule("tcp", 1935), vmTestRule("tcp", 1936))
	encoded, err := encodeVMFirewallLedger(vmTestLedger(s2, s1b, s1))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeVMFirewallLedger(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeVMFirewallLedger(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if again != encoded {
		t.Fatalf("encode(decode(x)) = %s, want %s", again, encoded)
	}
	if decoded.V != 1 || len(decoded.Members) != 3 {
		t.Fatalf("decoded = %#v", decoded)
	}
	if decoded.Members[0].UID != "svc-a" || decoded.Members[1].UID != "svc-a" || decoded.Members[2].UID != "svc-b" ||
		decoded.Members[0].Policy > decoded.Members[1].Policy {
		t.Fatalf("members are not sorted by UID then policy: %#v", decoded.Members)
	}
	last := decoded.Members[2]
	if last.Rules[0].Protocol != "tcp" || last.Rules[1].Protocol != "udp" {
		t.Fatalf("rules are not sorted by protocol: %#v", last.Rules)
	}
	if got := last.Rules[0].Sources; len(got) != 2 || got[0] != "198.51.100.0/24" {
		t.Fatalf("sources are not sorted: %v", got)
	}
	if !strings.Contains(encoded, `"sources":[]`) || strings.Contains(encoded, "null") {
		t.Fatalf("any-source rules must encode as an empty list: %s", encoded)
	}
}

func TestVMFirewallLedgerRejectsNonCanonical(t *testing.T) {
	a := vmTestMember(t, "svc-a", vmTestRule("tcp", 1935))
	b := vmTestMember(t, "svc-b", vmTestRule("tcp", 1936))
	good, err := encodeVMFirewallLedger(vmTestLedger(a, b))
	if err != nil {
		t.Fatal(err)
	}
	cidr, err := encodeVMFirewallLedger(vmTestLedger(vmTestMember(t, "svc-d", vmTestRule("tcp", 80, "10.0.0.0/8"))))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"unsorted members": rawVMFirewallLedger(t, vmTestLedger(b, a)),
		"unsorted rules": rawVMFirewallLedger(t, vmTestLedger(
			vmTestMember(t, "svc-c", vmTestRule("tcp", 2), vmTestRule("tcp", 1)))),
		"duplicate member":     rawVMFirewallLedger(t, vmTestLedger(a, a)),
		"version 2":            strings.Replace(good, `"v":1`, `"v":2`, 1),
		"unknown field":        strings.Replace(good, `"v":1`, `"v":1,"extra":true`, 1),
		"policy mismatch":      strings.Replace(good, a.Policy, "00000000", 1),
		"rules mismatch":       strings.Replace(good, `"port":1935`, `"port":1937`, 1),
		"trailing data":        good + "{}",
		"not json":             "members",
		"non canonical CIDR":   strings.Replace(cidr, `10.0.0.0/8`, `10.0.0.1/8`, 1),
		"member without rules": rawVMFirewallLedger(t, vmTestLedger(vmFirewallMember{UID: "svc-e", Policy: "00000000", Rules: []vmFirewallRule{}})),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVMFirewallLedger(raw); !errors.Is(err, errVMFirewallLedgerCorrupt) {
				t.Fatalf("decode(%s) error = %v, want errVMFirewallLedgerCorrupt", raw, err)
			}
		})
	}
	t.Run("three entries for one UID", func(t *testing.T) {
		l := vmTestLedger(
			vmTestMember(t, "svc-a", vmTestRule("tcp", 1)),
			vmTestMember(t, "svc-a", vmTestRule("tcp", 2)),
			vmTestMember(t, "svc-a", vmTestRule("tcp", 3)),
		)
		if _, err := encodeVMFirewallLedger(l); !errors.Is(err, errVMFirewallLedgerCorrupt) {
			t.Fatalf("encode error = %v", err)
		}
		if _, err := decodeVMFirewallLedger(rawVMFirewallLedger(t, l)); !errors.Is(err, errVMFirewallLedgerCorrupt) {
			t.Fatalf("decode error = %v", err)
		}
	})
	t.Run("with refuses a third entry and an exact duplicate", func(t *testing.T) {
		l := vmTestLedger(vmTestMember(t, "svc-a", vmTestRule("tcp", 1)), vmTestMember(t, "svc-a", vmTestRule("tcp", 2)))
		if _, err := l.with(vmTestMember(t, "svc-a", vmTestRule("tcp", 3))); !errors.Is(err, errVMFirewallEntryOrder) {
			t.Fatalf("third entry error = %v", err)
		}
		if _, err := l.with(vmTestMember(t, "svc-a", vmTestRule("tcp", 1))); !errors.Is(err, errVMFirewallEntryOrder) {
			t.Fatalf("duplicate error = %v", err)
		}
		next, err := l.with(vmTestMember(t, "svc-b", vmTestRule("tcp", 3)))
		if err != nil || len(next.Members) != 3 || len(l.Members) != 2 {
			t.Fatalf("with = %#v, %v (original %d members)", next, err, len(l.Members))
		}
	})
	t.Run("without removes one entry only", func(t *testing.T) {
		m1 := vmTestMember(t, "svc-a", vmTestRule("tcp", 1))
		m2 := vmTestMember(t, "svc-a", vmTestRule("tcp", 2))
		l := vmTestLedger(m1, m2)
		next, found := l.without(vmFirewallMemberKey{UID: "svc-a", Policy: m1.Policy})
		if !found || len(next.Members) != 1 || next.Members[0].Policy != m2.Policy || len(l.Members) != 2 {
			t.Fatalf("without = %#v found=%t", next, found)
		}
		if _, found := l.without(vmFirewallMemberKey{UID: "svc-z", Policy: m1.Policy}); found {
			t.Fatal("removed an entry that is not in the ledger")
		}
	})
}

func TestVMFirewallMemberFromDesiredMatchesServicePolicyHash(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	controller := &nodeLoadBalancerController{provider: provider}
	for name, shape := range map[string]func(*corev1.Service){
		"any source": nil,
		"source ranges": func(s *corev1.Service) {
			s.Spec.LoadBalancerSourceRanges = []string{"203.0.113.9/24", "198.51.100.0/24"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 1935)
			if shape != nil {
				shape(service)
			}
			desired, err := controller.desiredServiceFirewall(service)
			if err != nil {
				t.Fatal(err)
			}
			member, err := vmFirewallMemberFromDesired(string(service.UID), desired)
			if err != nil {
				t.Fatal(err)
			}
			if member.Policy != desired.Hash || member.UID != string(service.UID) {
				t.Fatalf("member = %#v, want policy %s", member, desired.Hash)
			}
			if _, err := encodeVMFirewallLedger(vmTestLedger(member)); err != nil {
				t.Fatalf("a member built from a Service must be a valid ledger entry: %v", err)
			}
			if name == "source ranges" && (len(member.Rules[0].Sources) != 2 || member.Rules[0].Sources[0] != "198.51.100.0/24") {
				t.Fatalf("sources = %v", member.Rules[0].Sources)
			}
		})
	}
}
