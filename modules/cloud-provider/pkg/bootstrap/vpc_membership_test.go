package bootstrap

import (
	"strings"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestCanonicalConfiguredVPCVMUUIDs(t *testing.T) {
	const (
		target = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		other  = "cccccccc-1111-4222-8333-dddddddddddd"
	)
	tests := []struct {
		name        string
		network     *inspace.Network
		wantError   bool
		wantMembers []string
	}{
		{name: "nil network", wantError: true},
		{name: "nil membership collection", network: &inspace.Network{}, wantError: true},
		{name: "empty or null member", network: &inspace.Network{VMUUIDs: []string{""}}, wantError: true},
		{name: "malformed unrelated member", network: &inspace.Network{VMUUIDs: []string{target, "bad"}}, wantError: true},
		{
			name:      "case-fold duplicate unrelated member",
			network:   &inspace.Network{VMUUIDs: []string{target, other, strings.ToUpper(other)}},
			wantError: true,
		},
		{name: "duplicate target", network: &inspace.Network{VMUUIDs: []string{target, target}}, wantError: true},
		{name: "valid empty membership", network: &inspace.Network{VMUUIDs: []string{}}, wantMembers: []string{}},
		{name: "valid unique target", network: &inspace.Network{VMUUIDs: []string{target}}, wantMembers: []string{target}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			members, err := canonicalConfiguredVPCVMUUIDs(test.network)
			if test.wantError {
				if err == nil || members != nil {
					t.Fatalf("canonicalConfiguredVPCVMUUIDs() = %#v, %v; want nil, error", members, err)
				}
				return
			}
			if err != nil || len(members) != len(test.wantMembers) {
				t.Fatalf("canonicalConfiguredVPCVMUUIDs() = %#v, %v; want %v", members, err, test.wantMembers)
			}
			for _, member := range test.wantMembers {
				if _, present := members[member]; !present {
					t.Fatalf("canonical membership omitted %s: %#v", member, members)
				}
			}
		})
	}
}
