package inspace

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const convergedCleanupVMUUID = "11111111-1111-4111-8111-111111111111"

// materializedCleanupRequest is the request the controller builds for a
// deleting, materialized NodeClaim: the launch UUID is also the observed VM and
// the single exact receipt.
func materializedCleanupRequest(vmUUID, publicIPv4 string, converged bool) cloudapi.FencedCreateCleanupRequest {
	cleanup := fencedCleanupRequest(true)
	name := floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName)
	cleanup.CreatedVMUUID = vmUUID
	cleanup.ObservedVMUUID = vmUUID
	cleanup.FloatingIPName = name
	cleanup.PublicIPv4 = publicIPv4
	cleanup.AttemptResolved = true
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{{
		VMUUID: vmUUID, FloatingIPName: name, PublicIPv4: publicIPv4, Converged: converged,
	}}
	return cleanup
}

func newProductionTimedCleanupAdapter(t *testing.T, api *fakeAPI) (*Adapter, *virtualReadbackClock) {
	t.Helper()
	adapter, _ := New(api)
	adapter.networkAttachmentReadbackMinDelay = 5 * time.Millisecond
	adapter.networkAttachmentReadbackMaxDelay = 10 * time.Millisecond
	useProductionConfirmationIntervals(adapter)
	return adapter, installVirtualReadbackClock(t)
}

func TestConvergedReceiptSkipsDeleteVMReplayAndUsesShortAuditSchedule(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, clock := newProductionTimedCleanupAdapter(t, api)
	cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)

	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution != nil || result.DependentsResolved {
		t.Fatalf("CleanupFencedCreate() = %#v, %v; want completed cleanup", result, err)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || api.floatingIPAssignCalls != 0 || api.floatingIPUpdateCalls != 0 {
		t.Fatalf("converged receipt mutated the cloud: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
	}
	if len(clock.waits) != 1 || clock.waits[0] != 10*time.Second {
		t.Fatalf("waits = %v, want exactly one 10s gap between two snapshots", clock.waits)
	}
	if api.vmListCalls != convergedAbsenceConfirmations {
		t.Fatalf("location snapshots = %d, want %d", api.vmListCalls, convergedAbsenceConfirmations)
	}
	t.Logf("converged materialized cleanup simulated wait: %v", clock.total())
}

func TestConvergedReceiptStillReadsExactResourcesEverySnapshot(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, _ := newProductionTimedCleanupAdapter(t, api)
	cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatal(err)
	}
	if api.vmGetCalls < convergedAbsenceConfirmations || api.firewallListCalls < convergedAbsenceConfirmations {
		t.Fatalf("exact VM GETs=%d firewall lists=%d, want at least one of each per snapshot", api.vmGetCalls, api.firewallListCalls)
	}
}

func TestConvergedReceiptReappearanceStaysPendingWithoutMutation(t *testing.T) {
	t.Run("VM", func(t *testing.T) {
		api := &fakeAPI{}
		adapter, clock := newProductionTimedCleanupAdapter(t, api)
		created, err := adapter.CreateVM(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}
		api.operations = nil
		cleanup := materializedCleanupRequest(created.UUID, created.PublicIPv4, true)
		_, err = adapter.CleanupFencedCreate(context.Background(), cleanup)
		if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "reappeared") {
			t.Fatalf("resurrected VM = %v, want pending reappearance", err)
		}
		if api.deleteVMCalls != 0 || len(api.operations) != 0 {
			t.Fatalf("converged audit mutated the cloud: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
		}
		if clock.spaced() != 0 {
			t.Fatalf("pending result waited %v; it must return at once and let the controller requeue", clock.waits)
		}
	})

	t.Run("floating IP", func(t *testing.T) {
		api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
		cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)
		api.floatingIPs = []sdk.FloatingIP{{
			Address: "203.0.113.10", Name: floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName), BillingAccountID: cleanup.BillingAccountID,
			Enabled: true, Type: "public",
		}}
		adapter, _ := newProductionTimedCleanupAdapter(t, api)
		_, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
		if !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
			t.Fatalf("resurrected floating IP = %v, want pending", err)
		}
		if api.deleteVMCalls != 0 || len(api.operations) != 0 {
			t.Fatalf("converged audit mutated the cloud: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
		}
	})

	t.Run("firewall relation", func(t *testing.T) {
		firewall := secureFirewall()
		firewall.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: convergedCleanupVMUUID}}
		api := &fakeAPI{firewalls: []sdk.Firewall{firewall}}
		adapter, _ := newProductionTimedCleanupAdapter(t, api)
		cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)
		_, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
		if !errors.Is(err, cloudapi.ErrCreateAttemptPending) || !strings.Contains(err.Error(), "firewall relations") {
			t.Fatalf("resurrected firewall relation = %v, want pending", err)
		}
		if api.deleteVMCalls != 0 || len(api.operations) != 0 {
			t.Fatalf("converged audit mutated the cloud: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
		}
	})
}

func TestUnconvergedMaterializedReceiptKeepsFullReplayAndThreeSpacedSnapshots(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, clock := newProductionTimedCleanupAdapter(t, api)
	cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", false)

	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() = %v", err)
	}
	if api.vmListCalls < createAbsenceConfirmations {
		t.Fatalf("location snapshots = %d, want at least %d", api.vmListCalls, createAbsenceConfirmations)
	}
	thirty := 0
	for _, wait := range clock.waits {
		if wait == defaultCreateAbsenceReadInterval {
			thirty++
		}
	}
	if thirty < createAbsenceConfirmations-1 {
		t.Fatalf("waits = %v, want the three-snapshot 30s schedule", clock.waits)
	}
	t.Logf("unconverged materialized cleanup simulated wait: %v", clock.total())
}

func TestConvergedFlagOnlyShortensWhenEveryReceiptIsConverged(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, clock := newProductionTimedCleanupAdapter(t, api)
	cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)
	other := cloudapi.FencedCreateCleanupResolution{
		VMUUID: "00000000-0000-4000-8000-000000000002", FloatingIPName: cleanup.FloatingIPName, PublicIPv4: "203.0.113.12",
	}
	cleanup.Resolutions = append([]cloudapi.FencedCreateCleanupResolution{other}, cleanup.Resolutions...)

	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() = %v", err)
	}
	if api.vmListCalls < createAbsenceConfirmations {
		t.Fatalf("location snapshots = %d, want the full %d with one unconverged receipt", api.vmListCalls, createAbsenceConfirmations)
	}
	for _, wait := range clock.waits {
		if wait == 10*time.Second {
			t.Fatalf("waits = %v, a mixed history must not use the 10s schedule", clock.waits)
		}
	}
}

func TestIssuedButUnobservedAttemptNeverUsesConvergedSchedule(t *testing.T) {
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, clock := newProductionTimedCleanupAdapter(t, api)
	cleanup := materializedCleanupRequest(convergedCleanupVMUUID, "203.0.113.10", true)
	// The receipt's VM already existed before the fence and the attempt never
	// produced an attributable result, so the POST may still commit later.
	cleanup.AttemptResolved = false
	cleanup.Baseline.VMs = []string{convergedCleanupVMUUID}

	_, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if !errors.Is(err, cloudapi.ErrCreateAttemptUnresolved) {
		t.Fatalf("CleanupFencedCreate() = %v, want the unresolved-attempt error after three snapshots", err)
	}
	thirty := 0
	for _, wait := range clock.waits {
		switch wait {
		case defaultCreateAbsenceReadInterval:
			thirty++
		case 10 * time.Second:
			t.Fatalf("waits = %v, an issued-but-unobserved attempt must keep the 30s schedule", clock.waits)
		}
	}
	if thirty < createAbsenceConfirmations-1 {
		t.Fatalf("waits = %v, want the three-snapshot 30s schedule", clock.waits)
	}
}

func TestDependentTrackingAttemptNeverUsesConvergedSchedule(t *testing.T) {
	anchor := "22222222-2222-4222-8222-222222222222"
	request := testRequest()
	api := &fakeAPI{vms: []sdk.VM{canonicalVMForRequest(t, request, anchor)}, firewalls: []sdk.Firewall{secureFirewall()}}
	adapter, clock := newProductionTimedCleanupAdapter(t, api)
	adapter.networkAttachmentReadbackTimeout = boundedReadbackTestTimeout
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = anchor
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	// An unrelated, already-converged historical receipt must not shorten the
	// dependent-absence proof of the anchored VM.
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{{
		VMUUID: "00000000-0000-4000-8000-000000000002", FloatingIPName: floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName),
		PublicIPv4: "203.0.113.12", Converged: true,
	}}
	cleanup.ObservedVMUUID = cleanup.Resolutions[0].VMUUID
	cleanup.FloatingIPName = cleanup.Resolutions[0].FloatingIPName
	cleanup.PublicIPv4 = cleanup.Resolutions[0].PublicIPv4

	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || !result.DependentsResolved {
		t.Fatalf("CleanupFencedCreate() = %#v, %v; want dependent absence proof", result, err)
	}
	if api.floatingIPListCalls < createAbsenceConfirmations {
		t.Fatalf("floating-IP snapshots = %d, want at least %d", api.floatingIPListCalls, createAbsenceConfirmations)
	}
	for _, wait := range clock.waits {
		if wait == 10*time.Second {
			t.Fatalf("waits = %v, dependent tracking must keep the 30s schedule", clock.waits)
		}
	}
}
