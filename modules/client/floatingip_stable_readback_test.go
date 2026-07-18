package inspace_test

import (
	"encoding/json"
	"strings"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const liveAssignedFloatingIPWithoutIsVirtual = `{
	"uuid":"55555555-5555-4555-8555-555555555555",
	"id":155566,
	"address":"203.0.113.10",
	"user_id":133,
	"billing_account_id":129206,
	"type":"public",
	"name":"karpenter-edge-new-9876543210",
	"enabled":true,
	"is_deleted":false,
	"is_ipv6":false,
	"assigned_to":"22222222-2222-4222-8222-222222222222",
	"assigned_to_resource_type":"virtual_machine",
	"assigned_to_private_ip":"10.91.72.248",
	"created_at":"2026-07-18 10:50:45",
	"updated_at":"2026-07-18 10:50:47"
}`

func decodeStableFloatingIP(t *testing.T, value string) inspace.FloatingIP {
	t.Helper()
	var result inspace.FloatingIP
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFloatingIPStableReadbackMatchAcceptsTwoSourceLiveOptionalOmission(t *testing.T) {
	exact := decodeStableFloatingIP(t, liveAssignedFloatingIPWithoutIsVirtual)
	listed := decodeStableFloatingIP(t, liveAssignedFloatingIPWithoutIsVirtual)

	if err := inspace.ValidateFloatingIPStableReadback(exact); err == nil ||
		!strings.Contains(err.Error(), "omits is_virtual") {
		t.Fatalf("standalone validation error = %v, want strict is_virtual presence rejection", err)
	}
	if err := inspace.ValidateFloatingIPStableReadbackMatch(exact, listed); err != nil {
		t.Fatalf("two-source live readback match rejected: %v", err)
	}
}

func TestFloatingIPStableReadbackMatchRejectsOptionalIsVirtualDisagreement(t *testing.T) {
	without := decodeStableFloatingIP(t, liveAssignedFloatingIPWithoutIsVirtual)
	withFalse := decodeStableFloatingIP(
		t,
		strings.TrimSuffix(liveAssignedFloatingIPWithoutIsVirtual, "}")+`,"is_virtual":false}`,
	)
	withTrue := decodeStableFloatingIP(
		t,
		strings.TrimSuffix(liveAssignedFloatingIPWithoutIsVirtual, "}")+`,"is_virtual":true}`,
	)

	if err := inspace.ValidateFloatingIPStableReadbackMatch(without, withFalse); err == nil {
		t.Fatal("exact/list is_virtual presence disagreement was accepted")
	}
	if err := inspace.ValidateFloatingIPStableReadbackMatch(withFalse, withTrue); err == nil {
		t.Fatal("exact/list is_virtual value disagreement was accepted")
	}
	if err := inspace.ValidateFloatingIPStableReadbackMatch(withFalse, withFalse); err != nil {
		t.Fatalf("equal explicit is_virtual readbacks rejected: %v", err)
	}
}
