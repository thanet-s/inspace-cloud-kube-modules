package inspace

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestCanonicalConfiguredVPCVMUUIDs(t *testing.T) {
	const (
		target = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		other  = "cccccccc-1111-4222-8333-dddddddddddd"
	)
	tests := []struct {
		name        string
		network     *sdk.Network
		wantError   bool
		wantMembers []string
	}{
		{name: "nil network", wantError: true},
		{name: "nil membership collection", network: &sdk.Network{}, wantError: true},
		{name: "empty or null member", network: &sdk.Network{VMUUIDs: []string{""}}, wantError: true},
		{name: "malformed unrelated member", network: &sdk.Network{VMUUIDs: []string{target, "bad"}}, wantError: true},
		{
			name:      "case-fold duplicate unrelated member",
			network:   &sdk.Network{VMUUIDs: []string{target, other, strings.ToUpper(other)}},
			wantError: true,
		},
		{name: "duplicate target", network: &sdk.Network{VMUUIDs: []string{target, strings.ToUpper(target)}}, wantError: true},
		{name: "valid empty membership", network: &sdk.Network{VMUUIDs: []string{}}, wantMembers: []string{}},
		{name: "valid target is canonicalized", network: &sdk.Network{VMUUIDs: []string{strings.ToUpper(target)}}, wantMembers: []string{target}},
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

func TestAuditedKarpenterMembershipConsumersRejectInvalidUnrelatedRows(t *testing.T) {
	const (
		target = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
		other  = "cccccccc-1111-4222-8333-dddddddddddd"
	)
	request := testRequest()

	t.Run("fenced discovery rejects duplicate unrelated member", func(t *testing.T) {
		api := &fakeAPI{network: &sdk.Network{
			UUID: request.NetworkUUID, Subnet: "10.0.0.0/24",
			VMUUIDs: []string{other, strings.ToUpper(other)},
		}}
		adapter, _ := New(api)
		_, _, err := adapter.fenceDiscoverySnapshot(
			context.Background(),
			request.Location,
			request.NetworkUUID,
			fenceDiscoveryPolicy{BeforeCreate: true},
		)
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "duplicate VM UUID") {
			t.Fatalf("fenceDiscoverySnapshot() error = %v, want duplicate-membership rejection", err)
		}
		if api.vmGetCalls != 0 {
			t.Fatalf("invalid fenced discovery membership reached %d canonical VM reads", api.vmGetCalls)
		}
	})

	t.Run("established protection rejects malformed unrelated member", func(t *testing.T) {
		record := newOwnership(request)
		network := &sdk.Network{
			UUID: request.NetworkUUID, Subnet: "10.0.0.0/24",
			VMUUIDs: []string{target, "bad"},
		}
		_, err := auditEstablishedVMProtection(
			sdk.VM{UUID: target},
			record,
			network,
			nil,
			nil,
		)
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "invalid VM UUID") {
			t.Fatalf("auditEstablishedVMProtection() error = %v, want malformed-membership rejection", err)
		}
	})

	t.Run("deletion absence rejects duplicate unrelated member", func(t *testing.T) {
		api := &fakeAPI{network: &sdk.Network{
			UUID: request.NetworkUUID, Subnet: "10.0.0.0/24",
			VMUUIDs: []string{target, other, strings.ToUpper(other)},
		}}
		adapter, _ := New(api)
		present, err := adapter.networkContainsVM(context.Background(), request.Location, request.NetworkUUID, target)
		if present || !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "duplicate VM UUID") {
			t.Fatalf("networkContainsVM() = %t, %v; want fail-closed duplicate-membership rejection", present, err)
		}
	})

	t.Run("attachment rejects malformed unrelated member without retry", func(t *testing.T) {
		api := &fakeAPI{network: &sdk.Network{
			UUID: request.NetworkUUID, Subnet: "10.0.0.0/24",
			VMUUIDs: []string{target, "bad"},
		}}
		adapter, _ := New(api)
		configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
		_, err := adapter.ensureNetworkAttachment(
			context.Background(),
			request.Location,
			request.NetworkUUID,
			target,
			netip.MustParseAddr(request.ControlPlaneVIP),
			testPrivateLoadBalancerPool(),
		)
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "invalid VM UUID") {
			t.Fatalf("ensureNetworkAttachment() error = %v, want malformed-membership rejection", err)
		}
		if api.networkGetCalls != 1 {
			t.Fatalf("invalid attachment membership used %d network reads, want one terminal read", api.networkGetCalls)
		}
	})
}
