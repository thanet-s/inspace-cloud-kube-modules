package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestFencedCreateNeverPostsTwiceWhenCommittedVMAndFIPStayInvisible(t *testing.T) {
	api := &fakeAPI{
		createErr: errors.New("connection reset after request"), commitOnCreateError: true,
		hideVMsThroughCall: 100, hideFloatingIPsThroughCall: 100,
	}
	adapter, _ := New(api)
	request := fencedAdapterRequest(true)
	authorizations := 0
	request.AuthorizeLaunch = func(_ context.Context, _ cloudapi.CreateAuthorizationKind) error {
		authorizations++
		return nil
	}
	if _, err := adapter.CreateVM(context.Background(), request); err == nil || !errors.Is(err, api.createErr) {
		t.Fatalf("first CreateVM() error = %v, want ambiguous transport result", err)
	}
	if api.createCalls != 1 || authorizations != 1 || len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != "" {
		t.Fatalf("first ambiguous launch = POSTs=%d auth=%d VMs=%d FIPs=%#v", api.createCalls, authorizations, len(api.vms), api.floatingIPs)
	}

	retry := request
	retry.CreateAttemptAllowPOST = false
	retry.AuthorizeLaunch = nil
	if _, err := adapter.CreateVM(context.Background(), retry); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("second CreateVM() error = %v, want immutable attempt pending", err)
	}
	if api.createCalls != 1 {
		t.Fatalf("invisible committed launch caused %d VM POSTs, want exactly one", api.createCalls)
	}
}

func TestReadAdoptionConsumesLaunchAuthorityBeforeRepair(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	fenced := fencedAdapterRequest(true)
	authorizations := 0
	fenced.AuthorizeLaunch = func(_ context.Context, _ cloudapi.CreateAuthorizationKind) error {
		authorizations++
		return nil
	}
	if _, err := adapter.CreateVM(context.Background(), fenced); err != nil {
		t.Fatal(err)
	}
	if authorizations != 1 || api.createCalls != 1 {
		t.Fatalf("adoption authority=%d VM POSTs=%d, want one authority CAS and no second POST", authorizations, api.createCalls)
	}
}

func TestIssuedCleanupBlocksOnUnnamedAutoFloatingIPWhenVMIsHidden(t *testing.T) {
	request := fencedCleanupRequest(true)
	api := &fakeAPI{floatingIPs: []sdk.FloatingIP{{
		Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: "11111111-1111-4111-8111-111111111111", AssignedToResourceType: "virtual_machine",
	}}}
	adapter, _ := New(api)
	adapter.createAmbiguityWindow = 0
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("CleanupFencedCreate() error = %v, want unnamed-FIP ambiguity", err)
	}
	if api.deleteVMCalls != 0 {
		t.Fatalf("unnamed FIP without canonical VM authorized %d deletes", api.deleteVMCalls)
	}
}

func TestIssuedCleanupBlocksOnPostBaselineSparseVM(t *testing.T) {
	request := fencedCleanupRequest(true)
	api := &fakeAPI{vms: []sdk.VM{{UUID: "11111111-1111-4111-8111-111111111111"}}}
	adapter, _ := New(api)
	adapter.createAmbiguityWindow = 0
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("CleanupFencedCreate() error = %v, want sparse-VM ambiguity", err)
	}
}

func TestIssuedCleanupNeverAutoReleasesOnEmptySnapshots(t *testing.T) {
	adapter, _ := New(&fakeAPI{})
	adapter.createAmbiguityWindow = 0
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), fencedCleanupRequest(true)); !errors.Is(err, cloudapi.ErrCreateAttemptUnresolved) {
		t.Fatalf("CleanupFencedCreate() error = %v, want permanent issued ambiguity", err)
	}
}

func TestPrepareCreateDoesNotTreatAttributedManualVMAsPotentialTarget(t *testing.T) {
	manualUUID := "99999999-9999-4999-8999-999999999999"
	api := &fakeAPI{
		vms: []sdk.VM{{UUID: manualUUID, Name: "manual-vm"}},
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.99", BillingAccountID: 1, Enabled: true, Type: "public",
			AssignedTo: manualUUID, AssignedToResourceType: "virtual_machine",
		}},
	}
	adapter, _ := New(api)
	inventory, err := adapter.PrepareCreate(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.PotentialVMs) != 0 {
		t.Fatalf("manual attributed VM was classified as a potential fenced launch: %v", inventory.PotentialVMs)
	}
	cleanup := fencedCleanupRequest(false)
	cleanup.Baseline = inventory
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("reserved cleanup with unchanged manual VM/FIP = %v, want safe absence", err)
	}
}

func TestPrepareCreateCanonicalizesSparseSummaryIntoDurableTarget(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := testRequest()
	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	api.omitVMListDescriptions = true
	inventory, err := adapter.PrepareCreate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.TargetVMs) != 1 || inventory.TargetVMs[0] != created.UUID || len(inventory.PotentialVMs) != 1 {
		t.Fatalf("canonical sparse inventory = %#v, want exact target %s", inventory, created.UUID)
	}
}

func TestFenceInventoryRoutesDriftedForeignNodeClaimBeforeShapeValidation(t *testing.T) {
	request := testRequest()
	record := newOwnership(request)
	record.NodeClaim = "other-claim"
	record.VMName = request.ClusterName + "-karp-other-claim"
	record.HostClass = inspacev1.HostClassAMDEPYC // Deliberately contradict Intel instance identity.
	description, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{vms: []sdk.VM{{
		UUID: "99999999-9999-4999-8999-999999999999", Name: record.VMName, Description: string(description),
	}}}
	adapter, _ := New(api)
	inventory, err := adapter.PrepareCreate(context.Background(), request)
	if err != nil {
		t.Fatalf("PrepareCreate() let foreign shape drift wedge target inventory: %v", err)
	}
	if len(inventory.PotentialVMs) != 0 || len(inventory.TargetVMs) != 0 {
		t.Fatalf("drifted foreign NodeClaim classified as target: %#v", inventory)
	}
	cleanup := fencedCleanupRequest(false)
	cleanup.Baseline = inventory
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("CleanupFencedCreate() drifted foreign VM = %v, want safe absence", err)
	}
}

func TestReservedCleanupSupportsStrictLegacyV1NameContract(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	request := testRequest()
	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var record ownership
	if err := json.Unmarshal([]byte(api.vms[0].Description), &record); err != nil {
		t.Fatal(err)
	}
	record.Schema = legacyOwnershipSchema
	record.VMName = ""
	record.HostPoolUUID = ""
	record.VCPU = 0
	record.MemoryGiB = 0
	record.PublicIPv4 = created.PublicIPv4
	description, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Name = request.NodeClaimName
	api.vms[0].Description = string(description)
	baseline, err := adapter.PrepareCreate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.TargetVMs) != 1 || baseline.TargetVMs[0] != created.UUID {
		t.Fatalf("legacy v1 target inventory = %#v", baseline)
	}
	cleanup := fencedCleanupRequest(false)
	cleanup.Baseline = baseline
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution == nil || result.Resolution.VMUUID != created.UUID {
		t.Fatalf("legacy cleanup resolution = %#v, %v", result, err)
	}
	cleanup.ObservedVMUUID = result.Resolution.VMUUID
	cleanup.FloatingIPName = result.Resolution.FloatingIPName
	cleanup.PublicIPv4 = result.Resolution.PublicIPv4
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{*result.Resolution}
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("legacy cleanup after durable receipt = %v", err)
	}
	if len(api.vms) != 0 {
		t.Fatal("legacy v1 exact-owned VM survived cleanup")
	}
}

func TestReservedAndMaterializedCleanupIgnoreUnrelatedLaterFloatingIP(t *testing.T) {
	manual := sdk.FloatingIP{
		UUID: "99999999-9999-4999-8999-999999999999", Address: "203.0.113.99", Name: "operator-reserved",
		BillingAccountID: 1, Enabled: true, Type: "public",
	}
	for _, test := range []struct {
		name    string
		cleanup cloudapi.FencedCreateCleanupRequest
		wantErr error
	}{
		{name: "reserved", cleanup: fencedCleanupRequest(false), wantErr: cloudapi.ErrNotFound},
		{name: "materialized", cleanup: func() cloudapi.FencedCreateCleanupRequest {
			cleanup := fencedCleanupRequest(true)
			cleanup.ObservedVMUUID = "11111111-1111-4111-8111-111111111111"
			cleanup.FloatingIPName = floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName)
			cleanup.PublicIPv4 = "203.0.113.10"
			cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{{
				VMUUID: cleanup.ObservedVMUUID, FloatingIPName: cleanup.FloatingIPName, PublicIPv4: cleanup.PublicIPv4,
			}}
			return cleanup
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := New(&fakeAPI{floatingIPs: []sdk.FloatingIP{manual}})
			adapter.createAbsenceReadInterval = time.Millisecond
			_, err := adapter.CleanupFencedCreate(context.Background(), test.cleanup)
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("CleanupFencedCreate() = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("CleanupFencedCreate() = %v, want success", err)
			}
		})
	}
}

func TestDefinitiveCreateRejectionIsTerminallyTyped(t *testing.T) {
	api := &fakeAPI{createErr: &sdk.APIError{StatusCode: 422, Message: "invalid launch"}}
	adapter, _ := New(api)
	request := fencedAdapterRequest(true)
	request.AuthorizeLaunch = func(context.Context, cloudapi.CreateAuthorizationKind) error { return nil }
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
		t.Fatalf("CreateVM() error = %v, want definitive rejection", err)
	}
	if api.createCalls != 1 || len(api.vms) != 0 {
		t.Fatalf("definitive rejection POSTs=%d VMs=%d", api.createCalls, len(api.vms))
	}
}

func TestFencedInternalRollbackPersistsExactReceiptBeforeDelete(t *testing.T) {
	api := &fakeAPI{createdPrivateIPv4: "10.0.0.10"}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := fencedAdapterRequest(true)
	request.AuthorizeLaunch = func(context.Context, cloudapi.CreateAuthorizationKind) error { return nil }
	var receipt cloudapi.FencedCreateCleanupResolution
	anchored := ""
	request.RecordCreatedVM = func(_ context.Context, vmUUID string) error {
		anchored = vmUUID
		return nil
	}
	request.ChooseRollback = func(_ context.Context, vmUUID string, resolution *cloudapi.FencedCreateCleanupResolution) error {
		if api.deleteVMCalls != 0 {
			t.Fatal("destructive rollback began before cleanup receipt persistence")
		}
		if anchored == "" || vmUUID != anchored || resolution == nil {
			t.Fatalf("rollback choice = anchor %q VM %q receipt %#v", anchored, vmUUID, resolution)
		}
		receipt = *resolution
		return nil
	}
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
		t.Fatalf("CreateVM() error = %v, want fully rolled-back terminal rejection", err)
	}
	if !vmUUIDPattern.MatchString(receipt.VMUUID) || receipt.FloatingIPName == "" || receipt.PublicIPv4 == "" {
		t.Fatalf("rollback receipt = %#v, want exact VM/FIP identity", receipt)
	}
	if api.deleteVMCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("rollback did not converge: deletes=%d VMs=%d FIPs=%d", api.deleteVMCalls, len(api.vms), len(api.floatingIPs))
	}
}

func TestCleanupIgnoresCanonicalPostBaselineManualVMAndFIP(t *testing.T) {
	manualUUID := "99999999-9999-4999-8999-999999999999"
	api := &fakeAPI{
		vms: []sdk.VM{{UUID: manualUUID, Name: "manual-vm", Description: "owned by an operator"}},
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.99", BillingAccountID: 1, Enabled: true, Type: "public",
			AssignedTo: manualUUID, AssignedToResourceType: "virtual_machine",
		}},
	}
	adapter, _ := New(api)
	adapter.createAbsenceReadInterval = time.Millisecond
	if _, err := adapter.CleanupFencedCreate(context.Background(), fencedCleanupRequest(false)); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("reserved cleanup with post-baseline manual VM/FIP = %v, want safe absence", err)
	}
}

func TestCleanupTreatsListPresentGetNotFoundAsUncertainty(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{
		vms:              []sdk.VM{{UUID: uuid, Name: testRequest().Name}},
		getVMErrorByUUID: map[string]error{uuid: &sdk.APIError{StatusCode: 404}},
	}
	adapter, _ := New(api)
	if _, err := adapter.CleanupFencedCreate(context.Background(), fencedCleanupRequest(false)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("CleanupFencedCreate() error = %v, want list/Get disagreement uncertainty", err)
	}
}

func TestReservedCleanupExactGetsPotentialBaselineVMBeforeRelease(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	baseline, err := adapter.PrepareCreate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.PotentialVMs) != 1 {
		t.Fatalf("potential baseline VMs = %v, want exact existing worker", baseline.PotentialVMs)
	}
	api.hideVMsThroughCall = api.vmListCalls + 100
	cleanup := fencedCleanupRequest(false)
	cleanup.Baseline = baseline
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution == nil {
		t.Fatalf("CleanupFencedCreate() = %#v, %v, want non-destructive exact resolution", result, err)
	}
	if api.deleteVMCalls != 0 {
		t.Fatal("reserved cleanup deleted baseline candidate before its receipt was durable")
	}
	cleanup.ObservedVMUUID = result.Resolution.VMUUID
	cleanup.FloatingIPName = result.Resolution.FloatingIPName
	cleanup.PublicIPv4 = result.Resolution.PublicIPv4
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{*result.Resolution}
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() after durable receipt = %v, want converged delete", err)
	}
	if api.deleteVMCalls == 0 {
		t.Fatal("reserved cleanup trusted empty VM list without exact-GET/deleting the baseline candidate after receipt")
	}
}

func TestCleanupCanonicalizesSparseListedLateTargetBeforeClassification(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.omitVMListDescriptions = true
	cleanup := fencedCleanupRequest(true)
	adapter.createAmbiguityWindow = 0
	adapter.createAbsenceReadInterval = time.Millisecond
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution == nil {
		t.Fatalf("CleanupFencedCreate() = %#v, %v, want canonical resolution before cleanup", result, err)
	}
	if api.deleteVMCalls != 0 || len(api.vms) != 1 {
		t.Fatalf("sparse list row was mutated before receipt: deletes=%d VMs=%d", api.deleteVMCalls, len(api.vms))
	}
	cleanup.ObservedVMUUID = result.Resolution.VMUUID
	cleanup.FloatingIPName = result.Resolution.FloatingIPName
	cleanup.PublicIPv4 = result.Resolution.PublicIPv4
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{*result.Resolution}
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() after durable receipt = %v", err)
	}
	if api.deleteVMCalls == 0 || len(api.vms) != 0 {
		t.Fatalf("sparse list row was not canonical-read/deleted after receipt: deletes=%d VMs=%d", api.deleteVMCalls, len(api.vms))
	}
}

func TestObservedCleanupDeletesDuplicateAndRequiresGlobalRescan(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	request := testRequest()
	first, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := api.vms[0]
	duplicate.UUID = "22222222-2222-4222-8222-222222222222"
	api.vms = append(api.vms, duplicate)
	api.floatingIPs = append(api.floatingIPs, sdk.FloatingIP{
		Address: "203.0.113.11", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: duplicate.UUID, AssignedToResourceType: "virtual_machine",
	})
	cleanup := fencedCleanupRequest(true)
	cleanup.ObservedVMUUID = first.UUID
	cleanup.FloatingIPName = first.FloatingIPName
	cleanup.PublicIPv4 = first.PublicIPv4
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{{
		VMUUID: first.UUID, FloatingIPName: first.FloatingIPName, PublicIPv4: first.PublicIPv4,
	}}
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution == nil || result.Resolution.VMUUID != duplicate.UUID {
		t.Fatalf("CleanupFencedCreate() = %#v, %v, want second duplicate resolution after deleting first", result, err)
	}
	if api.deleteVMCalls < 1 || len(api.vms) != 1 {
		t.Fatalf("first cleanup dispatched %d idempotent deletes and left %d VMs, want one unique deletion plus durable second receipt", api.deleteVMCalls, len(api.vms))
	}
	cleanup.ObservedVMUUID = result.Resolution.VMUUID
	cleanup.FloatingIPName = result.Resolution.FloatingIPName
	cleanup.PublicIPv4 = result.Resolution.PublicIPv4
	cleanup.Resolutions = append(cleanup.Resolutions, *result.Resolution)
	sort.Slice(cleanup.Resolutions, func(i, j int) bool { return cleanup.Resolutions[i].VMUUID < cleanup.Resolutions[j].VMUUID })
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() after second durable receipt = %v", err)
	}
	if api.deleteVMCalls < 2 || len(api.vms) != 0 {
		t.Fatalf("observed cleanup dispatched %d idempotent deletes and left %d, want both exact duplicates absent before release", api.deleteVMCalls, len(api.vms))
	}
}

func TestCleanupExactDeletesEveryHistoricalReceiptWhenListHidesEarlierTarget(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	request := testRequest()
	first, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second := cloudapi.FencedCreateCleanupResolution{
		VMUUID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", FloatingIPName: first.FloatingIPName, PublicIPv4: "203.0.113.12",
	}
	cleanup := fencedCleanupRequest(true)
	cleanup.ObservedVMUUID = second.VMUUID
	cleanup.FloatingIPName = second.FloatingIPName
	cleanup.PublicIPv4 = second.PublicIPv4
	cleanup.Resolutions = []cloudapi.FencedCreateCleanupResolution{
		{VMUUID: first.UUID, FloatingIPName: first.FloatingIPName, PublicIPv4: first.PublicIPv4}, second,
	}
	sort.Slice(cleanup.Resolutions, func(i, j int) bool { return cleanup.Resolutions[i].VMUUID < cleanup.Resolutions[j].VMUUID })
	api.hideVMsThroughCall = api.vmListCalls + 100
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("CleanupFencedCreate() with hidden historical target = %v", err)
	}
	if api.deleteVMCalls < 1 || len(api.vms) != 0 {
		t.Fatalf("hidden historical receipt was not exact-deleted: deletes=%d VMs=%d", api.deleteVMCalls, len(api.vms))
	}
}

func TestAnchoredRetryExactReadsVMWhenListOmitsIt(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.hideVMsThroughCall = api.vmListCalls + 100
	retry := fencedAdapterRequest(false)
	retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
	retry.CreatedVMUUID = created.UUID
	got, err := adapter.CreateVM(context.Background(), retry)
	if err != nil {
		t.Fatalf("anchored retry failed while ListVMs omitted the VM: %v", err)
	}
	if got.UUID != created.UUID || api.createCalls != 1 {
		t.Fatalf("anchored retry = VM %s POSTs=%d, want exact VM %s and no second POST", got.UUID, api.createCalls, created.UUID)
	}
}

func TestProtectFencedCreateRejectsForeignSameVPCVMBeforeFirewallMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	record, managed := parseOwnership(api.vms[0].Description)
	if !managed {
		t.Fatal("fixture VM lacks managed ownership")
	}
	record.NodeClaim = "foreign-nodeclaim"
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Description = string(encoded)
	api.firewalls[0].ResourcesAssigned = nil
	api.operations = nil
	api.firewallAssignCalls = 0

	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = created.UUID
	err = adapter.ProtectFencedCreate(context.Background(), cleanup)
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
		t.Fatalf("ProtectFencedCreate() error = %v, want exact ownership rejection", err)
	}
	if api.firewallAssignCalls != 0 || len(api.operations) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("foreign same-VPC VM reached firewall mutation: assigns=%d operations=%v firewall=%#v", api.firewallAssignCalls, api.operations, api.firewalls[0])
	}
}

func TestProtectFencedCreateReattachesFirewallToExactOwnedSameVPCVM(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.firewalls[0].ResourcesAssigned = nil
	api.operations = nil
	api.firewallAssignCalls = 0
	api.firewallListCalls = 0

	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = created.UUID
	if err := adapter.ProtectFencedCreate(context.Background(), cleanup); err != nil {
		t.Fatalf("ProtectFencedCreate() exact-owned recovery = %v", err)
	}
	if api.firewallAssignCalls != 1 || api.firewallListCalls != 1 || len(api.operations) != 1 || api.operations[0] != "assign-firewall" || !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("exact-owned recovery assigns=%d readbacks=%d operations=%v firewall=%#v, want one assignment and one successful readback", api.firewallAssignCalls, api.firewallListCalls, api.operations, api.firewalls[0])
	}
}

func TestPrepareCreateFailsClosedOnVPCOnlyCanonical404(t *testing.T) {
	uuid := "99999999-9999-4999-8999-999999999999"
	api := &fakeAPI{
		vms:                []sdk.VM{{UUID: uuid, Name: testRequest().Name}},
		hideVMsThroughCall: 100,
		getVMErrorByUUID:   map[string]error{uuid: &sdk.APIError{StatusCode: 404}},
	}
	adapter, _ := New(api)
	if _, err := adapter.PrepareCreate(context.Background(), testRequest()); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("PrepareCreate() error = %v, want VPC-only target uncertainty", err)
	}
	if api.createCalls != 0 {
		t.Fatalf("VPC-only/Get404 uncertainty reached %d VM POSTs", api.createCalls)
	}
}

func TestPrepareCreateIgnoresUnrelatedStaleFIPOnlyVMHint(t *testing.T) {
	uuid := "99999999-9999-4999-8999-999999999999"
	api := &fakeAPI{
		floatingIPs: []sdk.FloatingIP{{
			UUID: "88888888-8888-4888-8888-888888888888", Address: "203.0.113.99", Name: "manual",
			BillingAccountID: 1, Enabled: true, Type: "public", AssignedTo: uuid, AssignedToResourceType: "virtual_machine",
		}},
		getVMErrorByUUID: map[string]error{uuid: &sdk.APIError{StatusCode: 404}},
	}
	adapter, _ := New(api)
	inventory, err := adapter.PrepareCreate(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("unrelated stale FIP-only hint blocked PrepareCreate: %v", err)
	}
	if len(inventory.VMs) != 0 || len(inventory.FloatingIPs) != 1 {
		t.Fatalf("stale FIP-only inventory = %#v, want no canonical VM and retained FIP baseline", inventory)
	}
}

func TestCleanupCanNameAnchorWhenSiblingAlreadyUsesDeterministicFIPName(t *testing.T) {
	anchor := "11111111-1111-4111-8111-111111111111"
	sibling := "22222222-2222-4222-8222-222222222222"
	expectedName := floatingIPName(testRequest().ClusterName, testRequest().NodeClaimName)
	candidate, needsUpdate, err := autoFloatingIPForVM([]sdk.FloatingIP{
		{Address: "203.0.113.10", BillingAccountID: 1, Enabled: true, Type: "public", AssignedTo: anchor, AssignedToResourceType: "virtual_machine"},
		{Address: "203.0.113.11", Name: expectedName, BillingAccountID: 1, Enabled: true, Type: "public", AssignedTo: sibling, AssignedToResourceType: "virtual_machine"},
	}, anchor, expectedName, 1, false, true)
	if err != nil || candidate == nil || candidate.Address != "203.0.113.10" || !needsUpdate {
		t.Fatalf("autoFloatingIPForVM() = %#v update=%t err=%v, want exact assigned anchor to remain nameable", candidate, needsUpdate, err)
	}
}

func TestAnchoredCleanupNeverBindsSameNameSiblingFIP(t *testing.T) {
	anchor := "11111111-1111-4111-8111-111111111111"
	sibling := "22222222-2222-4222-8222-222222222222"
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = anchor
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	api := &fakeAPI{
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.11", Name: floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName), BillingAccountID: cleanup.BillingAccountID,
			Enabled: true, Type: "public", AssignedTo: sibling, AssignedToResourceType: "virtual_machine",
		}},
		getVMErrorByUUID: map[string]error{sibling: &sdk.APIError{StatusCode: 404}},
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if result.Resolution != nil || !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("sibling FIP cleanup = %#v, %v; want no anchor receipt and pending", result, err)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Address != "203.0.113.11" {
		t.Fatalf("same-name sibling FIP was mutated: %#v", api.floatingIPs)
	}
}

func TestAnchoredRollbackKeepsUnnamedPostBaselineDependentPending(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.floatingIPs[0].Name = ""
	api.hideFloatingIPsUntilVMDelete = true
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = created.UUID
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if result.DependentsResolved || result.Resolution != nil || !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("cleanup = %#v, %v; want unnamed post-baseline dependent to remain pending", result, err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("rollback fixture did not leave only the unassigned dependent: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
}

func TestAnchoredRollbackProvesDependentAbsenceAfterThreeSnapshots(t *testing.T) {
	anchor := "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{vms: []sdk.VM{{UUID: anchor}}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = anchor
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || !result.DependentsResolved || result.Resolution != nil {
		t.Fatalf("cleanup = %#v, %v; want terminal dependent absence proof", result, err)
	}
	if api.deleteVMCalls != 1 || api.floatingIPListCalls < 3 {
		t.Fatalf("dependent proof used deletes=%d FIP snapshots=%d, want exact VM delete and at least three snapshots", api.deleteVMCalls, api.floatingIPListCalls)
	}
}

func TestAnchoredRollbackWaitsForOriginalAmbiguityWindowBeforeDependentProof(t *testing.T) {
	anchor := "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{vms: []sdk.VM{{UUID: anchor}}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	cleanup := fencedCleanupRequest(true)
	cleanup.AttemptIssuedAt = time.Now().Add(-time.Minute)
	cleanup.CreatedVMUUID = anchor
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if result.DependentsResolved || result.Resolution != nil || !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("cleanup inside ambiguity window = %#v, %v; want pending", result, err)
	}
}

func TestResolvedDependentStillBlocksLateVisiblePostBaselineFIP(t *testing.T) {
	anchor := "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{floatingIPs: []sdk.FloatingIP{{
		Address: "203.0.113.10", BillingAccountID: testRequest().BillingAccountID, Enabled: true, Type: "public",
	}}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = anchor
	cleanup.RollbackChosen = true
	cleanup.DependentsResolved = true
	cleanup.AttemptResolved = true
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if result.DependentsResolved || result.Resolution != nil || !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("late dependent cleanup = %#v, %v; want pending despite prior absence proof", result, err)
	}
}

func TestAdoptedTargetBaselineFIPIsRecoveredAfterDeleteUnassignsIt(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := adapter.PrepareCreate(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.TargetFloatingIPs) != 1 || baseline.TargetFloatingIPs[0].VMUUID != created.UUID {
		t.Fatalf("adoption baseline lost target dependent association: %#v", baseline)
	}
	api.floatingIPs[0].Name = ""
	api.hideFloatingIPsUntilVMDelete = true
	adapter.launchFloatingIPCleanupTimeout = 20 * time.Millisecond
	adapter.launchCleanupTimeout = boundedReadbackTestTimeout
	adapter.createAbsenceReadInterval = time.Millisecond
	cleanup := fencedCleanupRequest(true)
	cleanup.Baseline = baseline
	cleanup.CreatedVMUUID = created.UUID
	cleanup.RollbackChosen = true
	cleanup.DependentUnresolved = true
	cleanup.AttemptResolved = true
	result, err := adapter.CleanupFencedCreate(context.Background(), cleanup)
	if err != nil || result.Resolution == nil || result.DependentsResolved {
		t.Fatalf("adopted dependent cleanup = %#v, %v; want exact durable receipt", result, err)
	}
	if result.Resolution.VMUUID != created.UUID || result.Resolution.FloatingIPName != floatingIPName(cleanup.ClusterName, cleanup.NodeClaimName) || result.Resolution.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("adopted dependent receipt = %#v", result.Resolution)
	}
}

func TestDeleteAlwaysDispatchesExactUUIDWhenAllReadIndexesHideLiveVM(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.floatingIPs[0].AssignedTo = ""
	api.floatingIPs[0].AssignedToResourceType = ""
	api.getVMErrorByUUID = map[string]error{created.UUID: &sdk.APIError{StatusCode: 404}}
	api.hideVMsThroughCall = api.vmListCalls + 100
	api.network = &sdk.Network{UUID: testRequest().NetworkUUID, Subnet: "10.0.0.0/24"}
	identity := cloudapi.DeleteVMIdentity{
		FloatingIPName: created.FloatingIPName, PublicIPv4: created.PublicIPv4,
		BillingAccountID: created.BillingAccountID, NetworkUUID: testRequest().NetworkUUID,
	}
	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatal(err)
	}
	if api.deleteVMCalls == 0 || len(api.vms) != 0 {
		t.Fatalf("hidden live VM survived durable UUID delete: calls=%d VMs=%#v", api.deleteVMCalls, api.vms)
	}
}

func TestDeleteCleansStaleAssignedFIPAfterCoreVMAbsence(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil // Simulate a gone VM while its exact FIP assignment lags.
	identity := cloudapi.DeleteVMIdentity{
		FloatingIPName: created.FloatingIPName, PublicIPv4: created.PublicIPv4,
		BillingAccountID: created.BillingAccountID, NetworkUUID: testRequest().NetworkUUID,
	}
	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatal(err)
	}
	if len(api.floatingIPs) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("stale assigned dependent did not converge before firewall detach: FIPs=%#v firewall=%#v", api.floatingIPs, api.firewalls[0])
	}
}

func fencedAdapterRequest(allow bool) cloudapi.CreateVMRequest {
	request := testRequest()
	request.CreateAttemptToken = "11111111111111111111111111111111"
	request.CreateAttemptStartedAt = time.Now().Add(-time.Minute)
	request.CreateAttemptAllowPOST = allow
	request.RecordCreatedVM = func(context.Context, string) error { return nil }
	request.ChooseRollback = func(context.Context, string, *cloudapi.FencedCreateCleanupResolution) error { return nil }
	return request
}

func fencedCleanupRequest(issued bool) cloudapi.FencedCreateCleanupRequest {
	request := testRequest()
	cleanup := cloudapi.FencedCreateCleanupRequest{
		ClusterName: request.ClusterName, Location: request.Location, NetworkUUID: request.NetworkUUID,
		NodePoolName: request.NodePoolName, ControlPlaneVIP: request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: request.PrivateLoadBalancerPoolStop,
		FirewallUUID: request.FirewallUUID, FirewallProfile: inspacev1.EffectiveFirewallProfile(request.FirewallProfile),
		SpecHash: request.SpecHash, BootstrapHash: request.BootstrapHash, NodeClaimName: request.NodeClaimName,
		VMName: request.Name, BillingAccountID: request.BillingAccountID, OwnershipKeyHash: hashKey(request.IdempotencyKey),
		AttemptToken: "11111111111111111111111111111111", POSTIssued: issued,
	}
	if issued {
		cleanup.AttemptIssuedAt = time.Now().Add(-time.Hour)
	}
	return cleanup
}
