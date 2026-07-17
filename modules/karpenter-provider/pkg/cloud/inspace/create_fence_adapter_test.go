package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
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

func TestLocalPredispatchCreateRejectionIsTerminallyTyped(t *testing.T) {
	api := &fakeAPI{createErr: sdk.ErrMutationBlocked}
	adapter, _ := New(api)
	request := fencedAdapterRequest(true)
	request.AuthorizeLaunch = func(context.Context, cloudapi.CreateAuthorizationKind) error { return nil }
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
		t.Fatalf("CreateVM() error = %v, want local pre-dispatch rejection", err)
	}
	if api.createCalls != 1 || len(api.vms) != 0 {
		t.Fatalf("local rejection POSTs=%d VMs=%d", api.createCalls, len(api.vms))
	}
}

func TestHTTP400CommittedCreateNeverRepostsAfterRestart(t *testing.T) {
	api := &fakeAPI{
		createErr: &sdk.APIError{StatusCode: 400, Message: "late error after dispatch"}, commitOnCreateError: true,
		hideVMsThroughCall: 10_000, hideFloatingIPsThroughCall: 10_000,
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	request := fencedAdapterRequest(true)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.attach(&request, true)

	if _, err := adapter.CreateVM(context.Background(), request); err == nil || errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
		t.Fatalf("first HTTP 400 create error = %v, want ambiguous issued result", err)
	}
	if api.createCalls != 1 || len(api.vms) != 1 || harness.fence.Phase != cloudapi.FirewallAssignmentIssued {
		t.Fatalf("HTTP 400 create did not preserve one issued launch: POSTs=%d VMs=%d fence=%#v", api.createCalls, len(api.vms), harness.fence)
	}

	api.hideVMsThroughCall = 0
	api.hideFloatingIPsThroughCall = 0
	retry := request
	harness.launchAuthority = false // process-local assignment authority is lost on restart
	harness.attach(&retry, false)
	retry.CreateAttemptAllowPOST = false
	retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 60*time.Millisecond)
	if _, err := restarted.CreateVM(context.Background(), retry); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("restart recovery error = %v, want read-only issued assignment pending", err)
	}
	if api.createCalls != 1 || api.firewallAssignCalls != 0 || harness.vmUUID == "" {
		t.Fatalf("restart replayed an additive mutation: VMPOSTs=%d firewallPOSTs=%d anchor=%q", api.createCalls, api.firewallAssignCalls, harness.vmUUID)
	}
}

func TestExactCreateUUIDAnchorFailureMakesNoRelationMutation(t *testing.T) {
	anchorErr := errors.New("created VM anchor write failed")
	createErr := errors.New("connection reset after VM create response")
	for _, test := range []struct {
		name string
		api  *fakeAPI
	}{
		{name: "successful response", api: &fakeAPI{}},
		{name: "partial response", api: &fakeAPI{
			createErr: createErr, commitOnCreateError: true, returnVMOnCreateError: true,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := New(test.api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			request := fencedAdapterRequest(true)
			request.AuthorizeLaunch = func(context.Context, cloudapi.CreateAuthorizationKind) error { return nil }
			request.RecordCreatedVM = func(context.Context, string) error { return anchorErr }

			_, err := adapter.CreateVM(context.Background(), request)
			if !errors.Is(err, anchorErr) {
				t.Fatalf("CreateVM() error = %v, want durable anchor failure", err)
			}
			if test.api.firewallAssignCalls != 0 || len(test.api.vms) != 1 || firewallHasVM(test.api.firewalls[0], test.api.vms[0].UUID) {
				t.Fatalf("unanchored response UUID reached a firewall relation: assigns=%d VMs=%#v firewall=%#v", test.api.firewallAssignCalls, test.api.vms, test.api.firewalls)
			}
			if test.api.floatingIPUpdateCalls != 0 || test.api.floatingIPCreateCalls != 0 || test.api.floatingIPAssignCalls != 0 || test.api.deleteVMCalls != 0 ||
				countOperation(test.api.operations, "unassign-floating-ip") != 0 || countOperation(test.api.operations, "delete-floating-ip") != 0 ||
				len(test.api.operations) != 0 {
				t.Fatalf("anchor failure reached a dependent/destructive mutation: FIPPOSTs=%d FIPPATCHes=%d FIPassigns=%d VMdeletes=%d operations=%v",
					test.api.floatingIPCreateCalls, test.api.floatingIPUpdateCalls, test.api.floatingIPAssignCalls, test.api.deleteVMCalls, test.api.operations)
			}
			if len(test.api.floatingIPs) != 1 || test.api.floatingIPs[0].Name != "" || test.api.floatingIPs[0].AssignedTo != test.api.vms[0].UUID {
				t.Fatalf("anchor failure did not preserve the auto-reserved floating IP: %#v", test.api.floatingIPs)
			}
		})
	}
}

func TestExactCreateUUIDAnchorFailureDoesNotExerciseFirewallMutation(t *testing.T) {
	anchorErr := errors.New("created VM anchor write failed")
	firewallErr := errors.New("firewall assignment failed")
	api := &fakeAPI{assignFirewallErrors: []error{firewallErr}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	request := fencedAdapterRequest(true)
	request.AuthorizeLaunch = func(context.Context, cloudapi.CreateAuthorizationKind) error { return nil }
	request.RecordCreatedVM = func(context.Context, string) error { return anchorErr }

	_, err := adapter.CreateVM(context.Background(), request)
	if !errors.Is(err, anchorErr) || errors.Is(err, firewallErr) {
		t.Fatalf("CreateVM() error = %v, want only durable anchor failure", err)
	}
	if api.firewallAssignCalls != 0 || api.deleteVMCalls != 0 || api.floatingIPUpdateCalls != 0 ||
		countOperation(api.operations, "unassign-floating-ip") != 0 || countOperation(api.operations, "delete-floating-ip") != 0 ||
		len(api.operations) != 0 {
		t.Fatalf("dual failure reached cleanup/dependent mutation: firewall=%d FIPPATCHes=%d VMdeletes=%d operations=%v",
			api.firewallAssignCalls, api.floatingIPUpdateCalls, api.deleteVMCalls, api.operations)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != api.vms[0].UUID {
		t.Fatalf("dual failure did not preserve exact VM/FIP for reconciliation: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
}

func TestWrongCreateResponseUUIDNeverAuthorizesForeignMutationAcrossRestart(t *testing.T) {
	const foreignUUID = "99999999-9999-4999-8999-999999999999"
	const actualUUID = "11111111-1111-4111-8111-111111111111"
	foreign := sdk.VM{
		UUID: foreignUUID, Name: "pre-existing-foreign-vm", Description: `{"owner":"foreign"}`,
		BillingAccountID: 999, NetworkUUID: testRequest().NetworkUUID,
		VCPU: 8, MemoryMiB: 16384, OSName: "ubuntu", OSVersion: "24.04",
		Storage: []sdk.VMStorage{{SizeGiB: 100, Primary: true}},
	}
	api := &fakeAPI{vms: []sdk.VM{foreign}, createResponseUUID: foreignUUID}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableBaseFirewallHarness(testRequest().FirewallUUID)
	request := fencedAdapterRequest(true)
	harness.attach(&request, true)

	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateVM() failed to recover the real launch behind a wrong response UUID: %v", err)
	}
	if created == nil || created.UUID != actualUUID || harness.vmUUID != actualUUID || harness.anchorAttempt == foreignUUID {
		t.Fatalf("verified launch identity = created=%#v durable=%q attempted=%q, want only actual %s", created, harness.vmUUID, harness.anchorAttempt, actualUUID)
	}
	if api.createCalls != 1 || api.firewallAssignCalls != 1 || api.floatingIPUpdateCalls != 1 || api.deleteVMCalls != 0 {
		t.Fatalf("real launch was not contained exactly once: creates=%d assigns=%d FIP updates=%d deletes=%d operations=%v",
			api.createCalls, api.firewallAssignCalls, api.floatingIPUpdateCalls, api.deleteVMCalls, api.operations)
	}
	if len(api.vms) != 2 || api.vms[0].UUID != foreignUUID || api.vms[0].Name != foreign.Name {
		t.Fatalf("foreign VM changed after wrong response: %#v", api.vms)
	}
	if firewallHasVM(api.firewalls[0], foreignUUID) || !firewallHasVM(api.firewalls[0], actualUUID) {
		t.Fatalf("firewall protection targeted the wrong VM: %#v", api.firewalls[0].ResourcesAssigned)
	}
	for _, address := range api.floatingIPs {
		if strings.EqualFold(address.AssignedTo, foreignUUID) {
			t.Fatalf("foreign VM received a floating-IP mutation: %#v", address)
		}
	}

	retry := fencedAdapterRequest(false)
	retry.CreatedVMUUID = actualUUID
	retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
	harness.attach(&retry, false)
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	restartedCreated, err := restarted.CreateVM(context.Background(), retry)
	if err != nil || restartedCreated == nil || restartedCreated.UUID != actualUUID {
		t.Fatalf("restart did not retain the verified actual launch: created=%#v err=%v", restartedCreated, err)
	}
	if api.createCalls != 1 || api.firewallAssignCalls != 1 || api.floatingIPUpdateCalls != 1 || api.deleteVMCalls != 0 || firewallHasVM(api.firewalls[0], foreignUUID) {
		t.Fatalf("restart replayed create/protection or mutated foreign UUID: creates=%d assigns=%d FIP updates=%d deletes=%d operations=%v",
			api.createCalls, api.firewallAssignCalls, api.floatingIPUpdateCalls, api.deleteVMCalls, api.operations)
	}
}

func TestDurableBaseFirewallNormalFreshCreatePostsExactlyOnce(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := fencedAdapterRequest(true)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.attach(&request, true)

	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if created == nil || api.firewallAssignCalls != 1 || harness.fence.Phase != cloudapi.FirewallAssignmentObserved ||
		harness.authorizeCalls < 1 || harness.observeCalls < 1 {
		t.Fatalf("normal durable assignment = created=%#v assigns=%d fence=%#v authorize=%d observe=%d", created, api.firewallAssignCalls, harness.fence, harness.authorizeCalls, harness.observeCalls)
	}
}

func TestDurableBaseFirewallCommittedHTTPErrorNeverReplaysAcrossRestartAndLateVisibility(t *testing.T) {
	for _, status := range []int{400, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			api := &fakeAPI{
				assignFirewallErrors:               []error{&sdk.APIError{StatusCode: status, Message: "response lost after dispatch"}},
				assignFirewallCommitOnError:        true,
				hideFirewallAssignmentsThroughCall: 10_000,
			}
			request := fencedAdapterRequest(true)
			harness := newDurableBaseFirewallHarness(request.FirewallUUID)
			harness.attach(&request, true)
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, 60*time.Millisecond)

			if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
				t.Fatalf("first ambiguous assignment error = %v, want pending", err)
			}
			if api.firewallAssignCalls != 1 || api.deleteVMCalls != 0 || len(api.vms) != 1 || harness.fence.Phase != cloudapi.FirewallAssignmentIssued || harness.rejectCalls != 0 {
				t.Fatalf("first ambiguous assignment was not preserved: assigns=%d deletes=%d VMs=%d rejects=%d fence=%#v", api.firewallAssignCalls, api.deleteVMCalls, len(api.vms), harness.rejectCalls, harness.fence)
			}

			retry := request
			harness.attach(&retry, false)
			retry.CreatedVMUUID = harness.vmUUID
			retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
			retry.CreateAttemptAllowPOST = false
			restarted, _ := New(api)
			configureFastNetworkReadback(restarted, 60*time.Millisecond)
			if _, err := restarted.CreateVM(context.Background(), retry); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
				t.Fatalf("hidden restart assignment error = %v, want pending", err)
			}
			if api.firewallAssignCalls != 1 {
				t.Fatalf("restart replayed hidden committed assignment: calls=%d", api.firewallAssignCalls)
			}

			api.hideFirewallAssignmentsThroughCall = 0
			retry = request
			harness.attach(&retry, false)
			retry.CreatedVMUUID = harness.vmUUID
			retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
			retry.CreateAttemptAllowPOST = false
			restarted, _ = New(api)
			configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
			created, err := restarted.CreateVM(context.Background(), retry)
			if err != nil {
				t.Fatal(err)
			}
			if created == nil || api.firewallAssignCalls != 1 || harness.fence.Phase != cloudapi.FirewallAssignmentObserved {
				t.Fatalf("late visibility did not recover read-only: created=%#v assigns=%d fence=%#v", created, api.firewallAssignCalls, harness.fence)
			}
		})
	}
}

func TestDurableBaseFirewallLocalMutationBlockRejectsAndAllowsOneFreshRetry(t *testing.T) {
	request := fencedAdapterRequest(true)
	vmUUID := "11111111-1111-4111-8111-111111111111"
	api := &fakeAPI{
		assignFirewallErrors: []error{sdk.ErrMutationBlocked},
		vms:                  []sdk.VM{canonicalVMForRequest(t, request, vmUUID)},
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.vmUUID = vmUUID
	harness.anchorAttempt = harness.vmUUID
	harness.attachAssignmentCallbacks(&request)
	prefix := netip.MustParsePrefix("10.0.0.0/24")

	if err := adapter.ensureCreateBaseFirewall(context.Background(), request, harness.vmUUID, prefix, true); err == nil || harness.fence.Phase != cloudapi.FirewallAssignmentRejected {
		t.Fatalf("definitive rejection = fence=%#v err=%v", harness.fence, err)
	}
	if api.firewallAssignCalls != 1 || harness.rejectCalls != 1 {
		t.Fatalf("definitive rejection calls: assigns=%d rejects=%d", api.firewallAssignCalls, harness.rejectCalls)
	}
	request.BaseFirewallAssignment = harness.fence
	if err := adapter.ensureCreateBaseFirewall(context.Background(), request, harness.vmUUID, prefix, true); err != nil {
		t.Fatal(err)
	}
	if api.firewallAssignCalls != 2 || harness.fence.Phase != cloudapi.FirewallAssignmentObserved {
		t.Fatalf("definitive retry = assigns=%d fence=%#v", api.firewallAssignCalls, harness.fence)
	}
}

func TestDurableBaseFirewallLocalMutationBlockKeepsVMForReauthorizedCreateRetry(t *testing.T) {
	api := &fakeAPI{assignFirewallErrors: []error{sdk.ErrMutationBlocked}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := fencedAdapterRequest(true)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.attach(&request, true)

	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("first CreateVM() error = %v, want safely reauthorizable pending result", err)
	}
	if api.firewallAssignCalls != 1 || api.deleteVMCalls != 0 || len(api.vms) != 1 || harness.fence.Phase != cloudapi.FirewallAssignmentRejected {
		t.Fatalf("definitive rejection did not retain exact VM for retry: assigns=%d deletes=%d VMs=%d fence=%#v",
			api.firewallAssignCalls, api.deleteVMCalls, len(api.vms), harness.fence)
	}

	retry := request
	harness.attach(&retry, false)
	retry.CreatedVMUUID = harness.vmUUID
	retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
	retry.CreateAttemptAllowPOST = false
	created, err := adapter.CreateVM(context.Background(), retry)
	if err != nil {
		t.Fatal(err)
	}
	if created == nil || api.createCalls != 1 || api.firewallAssignCalls != 2 || api.deleteVMCalls != 0 || harness.fence.Phase != cloudapi.FirewallAssignmentObserved {
		t.Fatalf("reauthorized retry = created=%#v VMPOSTs=%d firewallPOSTs=%d deletes=%d fence=%#v",
			created, api.createCalls, api.firewallAssignCalls, api.deleteVMCalls, harness.fence)
	}
}

func TestDurableBaseFirewallStaleSnapshotAfterObservedNeverReplays(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	firewall := secureFirewall()
	firewall.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}}
	api := &fakeAPI{firewalls: []sdk.Firewall{firewall}, hideFirewallAssignmentsThroughCall: 1}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	request := fencedAdapterRequest(true)
	harness := newDurableBaseFirewallHarness(request.FirewallUUID)
	harness.vmUUID = vmUUID
	harness.anchorAttempt = vmUUID
	harness.fence = cloudapi.FirewallAssignmentFence{
		VMUUID: vmUUID, FirewallUUID: request.FirewallUUID, Phase: cloudapi.FirewallAssignmentObserved, IssueID: "33333333333333333333333333333333",
	}
	harness.attachAssignmentCallbacks(&request)
	// Deliberately stale request state: the callback must return authoritative
	// observed state and suppress a POST while the first cloud list is stale.
	request.BaseFirewallAssignment = cloudapi.FirewallAssignmentFence{VMUUID: vmUUID, FirewallUUID: request.FirewallUUID, Phase: cloudapi.FirewallAssignmentIntent}

	if err := adapter.ensureCreateBaseFirewall(context.Background(), request, vmUUID, netip.MustParsePrefix("10.0.0.0/24"), true); err != nil {
		t.Fatal(err)
	}
	if api.firewallAssignCalls != 0 || harness.authorizeCalls != 1 {
		t.Fatalf("stale observed snapshot replayed assignment: assigns=%d authorize=%d", api.firewallAssignCalls, harness.authorizeCalls)
	}
}

func TestDurableFloatingIPHTTP400OldReadbackNeverReplaysAfterRestart(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	api := &fakeAPI{
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
		}},
		updateFloatingIPErrors: []error{&sdk.APIError{StatusCode: 400, Message: "late response"}},
	}
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), request.Location, vmUUID, expectedName, request.BillingAccountID, createFloatingIPUpdateAuthority(request)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("first HTTP 400 PATCH error = %v, want issued pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateIssued || harness.rejectCalls != 0 {
		t.Fatalf("first ambiguous PATCH = calls=%d fence=%#v rejects=%d", api.floatingIPUpdateCalls, harness.fence, harness.rejectCalls)
	}
	retry := request
	harness.attachCreate(&retry)
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 60*time.Millisecond)
	if _, err := restarted.ensureAutoFloatingIP(context.Background(), retry.Location, vmUUID, expectedName, retry.BillingAccountID, createFloatingIPUpdateAuthority(retry)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("restart old readback error = %v, want issued pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("restart replayed ambiguous PATCH: calls=%d fence=%#v", api.floatingIPUpdateCalls, harness.fence)
	}
}

func TestDurableFloatingIPHTTP400HiddenCommitObservesAfterRestartWithoutReplay(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	old := sdk.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
	}
	snapshots := map[int][]sdk.FloatingIP{}
	for call := 2; call < 100; call++ {
		snapshots[call] = []sdk.FloatingIP{old}
	}
	api := &fakeAPI{
		floatingIPs: []sdk.FloatingIP{old}, floatingIPListSnapshots: snapshots,
		updateFloatingIPErrors:        []error{&sdk.APIError{StatusCode: 400, Message: "committed but response lost"}},
		updateFloatingIPCommitOnError: true,
	}
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), request.Location, vmUUID, expectedName, request.BillingAccountID, createFloatingIPUpdateAuthority(request)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("hidden committed PATCH error = %v, want issued pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("hidden commit = calls=%d fence=%#v", api.floatingIPUpdateCalls, harness.fence)
	}
	api.floatingIPListSnapshots = nil
	retry := request
	harness.attachCreate(&retry)
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	floatingIP, err := restarted.ensureAutoFloatingIP(context.Background(), retry.Location, vmUUID, expectedName, retry.BillingAccountID, createFloatingIPUpdateAuthority(retry))
	if err != nil {
		t.Fatal(err)
	}
	if floatingIP == nil || floatingIP.Name != expectedName || api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateObserved {
		t.Fatalf("late visibility recovery = FIP=%#v PATCHes=%d fence=%#v", floatingIP, api.floatingIPUpdateCalls, harness.fence)
	}
}

func TestDurableFloatingIPPostPATCHReadbackFailureNeverReplaysAfterRestart(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	api := &fakeAPI{
		vms: []sdk.VM{canonicalVMForRequest(t, request, vmUUID)},
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
		}},
		// Calls 2-3 are the post-CAS exact-row proof. Fail the first
		// observation after PATCH so this remains an ambiguous commit test.
		floatingIPListErrors: map[int]error{4: &sdk.APIError{StatusCode: 400, Message: "readback failed"}},
	}
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), request.Location, vmUUID, expectedName, request.BillingAccountID, createFloatingIPUpdateAuthority(request)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("post-PATCH readback error = %v, want issued pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("post-PATCH failure = calls=%d fence=%#v", api.floatingIPUpdateCalls, harness.fence)
	}
	retry := request
	harness.attachCreate(&retry)
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	if _, err := restarted.ensureAutoFloatingIP(context.Background(), retry.Location, vmUUID, expectedName, retry.BillingAccountID, createFloatingIPUpdateAuthority(retry)); err != nil {
		t.Fatal(err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateObserved {
		t.Fatalf("restart replayed PATCH after readback failure: calls=%d fence=%#v", api.floatingIPUpdateCalls, harness.fence)
	}
}

func TestDurableFloatingIPLocalMutationBlockRejectsAndReissuesOnce(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	api := &fakeAPI{
		floatingIPs: []sdk.FloatingIP{{
			Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
		}},
		updateFloatingIPErrors: []error{sdk.ErrMutationBlocked},
	}
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), request.Location, vmUUID, expectedName, request.BillingAccountID, createFloatingIPUpdateAuthority(request)); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("local mutation block = %v, want reauthorizable pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || harness.rejectCalls != 1 || harness.fence.Phase != cloudapi.FloatingIPUpdateRejected {
		t.Fatalf("local block = calls=%d rejects=%d fence=%#v", api.floatingIPUpdateCalls, harness.rejectCalls, harness.fence)
	}
	retry := request
	harness.attachCreate(&retry)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), retry.Location, vmUUID, expectedName, retry.BillingAccountID, createFloatingIPUpdateAuthority(retry)); err != nil {
		t.Fatal(err)
	}
	if api.floatingIPUpdateCalls != 2 || harness.fence.Phase != cloudapi.FloatingIPUpdateObserved {
		t.Fatalf("reauthorized local retry = calls=%d fence=%#v", api.floatingIPUpdateCalls, harness.fence)
	}
}

func TestDurableFloatingIPDesiredStateObservesWithoutPATCH(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	request := fencedAdapterRequest(true)
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	api := &fakeAPI{floatingIPs: []sdk.FloatingIP{{
		Address: "203.0.113.10", Name: expectedName, BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public",
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine",
	}}}
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	if _, err := adapter.ensureAutoFloatingIP(context.Background(), request.Location, vmUUID, expectedName, request.BillingAccountID, createFloatingIPUpdateAuthority(request)); err != nil {
		t.Fatal(err)
	}
	if api.floatingIPUpdateCalls != 0 || harness.fence.Phase != cloudapi.FloatingIPUpdateObserved || harness.observeCalls != 1 {
		t.Fatalf("visible desired state = PATCHes=%d fence=%#v observes=%d", api.floatingIPUpdateCalls, harness.fence, harness.observeCalls)
	}
}

func TestDurableFloatingIPObserveFailureStaysPendingWithoutRollbackOrReplay(t *testing.T) {
	api := &fakeAPI{}
	request := fencedAdapterRequest(true)
	baseHarness := newDurableBaseFirewallHarness(request.FirewallUUID)
	baseHarness.attach(&request, true)
	fipHarness := newDurableFloatingIPUpdateHarness()
	fipHarness.observeErr = errors.New("NodeClaim observation CAS failed")
	fipHarness.attachCreate(&request)
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("observe failure error = %v, want pending", err)
	}
	if api.floatingIPUpdateCalls != 1 || api.deleteVMCalls != 0 || len(api.vms) != 1 || fipHarness.fence.Phase != cloudapi.FloatingIPUpdateIssued {
		t.Fatalf("observe failure mutated cleanup path: PATCHes=%d deletes=%d VMs=%d fence=%#v", api.floatingIPUpdateCalls, api.deleteVMCalls, len(api.vms), fipHarness.fence)
	}
	fipHarness.observeErr = nil
	retry := request
	baseHarness.attach(&retry, false)
	fipHarness.attachCreate(&retry)
	retry.CreatedVMUUID = baseHarness.vmUUID
	retry.CreateAttemptIntent = cloudapi.CreateAuthorizationPost
	retry.CreateAttemptAllowPOST = false
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	if _, err := restarted.CreateVM(context.Background(), retry); err != nil {
		t.Fatal(err)
	}
	if api.floatingIPUpdateCalls != 1 || api.deleteVMCalls != 0 || fipHarness.fence.Phase != cloudapi.FloatingIPUpdateObserved {
		t.Fatalf("restart after observe failure replayed/cleaned up: PATCHes=%d deletes=%d fence=%#v", api.floatingIPUpdateCalls, api.deleteVMCalls, fipHarness.fence)
	}
}

func TestFencedCreateMissingBaseFirewallCallbacksPerformsZeroMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := fencedAdapterRequest(true)
	request.AuthorizeBaseFirewall = nil
	request.ObserveBaseFirewall = nil
	request.RejectBaseFirewall = nil
	if _, err := adapter.CreateVM(context.Background(), request); err == nil {
		t.Fatal("CreateVM() accepted a durable request without base-firewall callbacks")
	}
	if api.createCalls != 0 || api.firewallAssignCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("missing durable callbacks reached cloud mutation: VMPOSTs=%d firewallPOSTs=%d operations=%v", api.createCalls, api.firewallAssignCalls, api.operations)
	}
}

func TestFencedCreateMissingFloatingIPUpdateCallbacksPerformsZeroMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := fencedAdapterRequest(true)
	request.AuthorizeFloatingIPUpdate = nil
	request.ObserveFloatingIPUpdate = nil
	request.RejectFloatingIPUpdate = nil
	if _, err := adapter.CreateVM(context.Background(), request); err == nil {
		t.Fatal("CreateVM() accepted a durable request without floating-IP update callbacks")
	}
	if api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPUpdateCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("missing durable FIP callbacks reached cloud mutation: VMPOSTs=%d firewallPOSTs=%d FIPPATCHes=%d operations=%v", api.createCalls, api.firewallAssignCalls, api.floatingIPUpdateCalls, api.operations)
	}
}

func TestProductionAdapterRejectsTokenlessCreateBeforeCloudMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, err := New(&productionLikeAPI{API: api})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
		t.Fatal("production adapter accepted a tokenless VM create")
	}
	if api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPUpdateCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("tokenless production request reached mutation: VMPOSTs=%d firewallPOSTs=%d FIPPATCHes=%d operations=%v", api.createCalls, api.firewallAssignCalls, api.floatingIPUpdateCalls, api.operations)
	}
}

func TestFencedCleanupMissingMutationCallbacksPerformsZeroMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	cleanup := fencedCleanupRequest(true)
	cleanup.AuthorizeBaseFirewall = nil
	cleanup.ObserveBaseFirewall = nil
	cleanup.RejectBaseFirewall = nil
	cleanup.AuthorizeFloatingIPUpdate = nil
	cleanup.ObserveFloatingIPUpdate = nil
	cleanup.RejectFloatingIPUpdate = nil
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); err == nil {
		t.Fatal("CleanupFencedCreate() accepted missing mutation callbacks")
	}
	if api.deleteVMCalls != 0 || api.floatingIPUpdateCalls != 0 || api.firewallAssignCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("missing cleanup callbacks reached mutation: deletes=%d FIPPATCHes=%d firewallPOSTs=%d operations=%v", api.deleteVMCalls, api.floatingIPUpdateCalls, api.firewallAssignCalls, api.operations)
	}
}

type productionLikeAPI struct{ API }

func TestCreateAndFirewallAmbiguityClassification(t *testing.T) {
	for _, test := range []struct {
		name                 string
		err                  error
		ambiguous            bool
		definitiveAssignment bool
	}{
		{name: "transport", err: errors.New("connection reset"), ambiguous: true},
		{name: "cross-origin redirect", err: sdk.ErrCrossOriginRedirect, ambiguous: true},
		{name: "mutation blocked", err: sdk.ErrMutationBlocked, definitiveAssignment: true},
		{name: "400", err: &sdk.APIError{StatusCode: 400}, ambiguous: true},
		{name: "408", err: &sdk.APIError{StatusCode: 408}, ambiguous: true},
		{name: "409", err: &sdk.APIError{StatusCode: 409}, ambiguous: true},
		{name: "425", err: &sdk.APIError{StatusCode: 425}, ambiguous: true},
		{name: "429", err: &sdk.APIError{StatusCode: 429}, ambiguous: true},
		{name: "499", err: &sdk.APIError{StatusCode: 499}, ambiguous: true},
		{name: "500 non-retryable flag", err: &sdk.APIError{StatusCode: 500}, ambiguous: true},
		{name: "599", err: &sdk.APIError{StatusCode: 599}, ambiguous: true},
		{name: "422", err: &sdk.APIError{StatusCode: 422}, ambiguous: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isAmbiguousCreate(test.err); got != test.ambiguous {
				t.Fatalf("isAmbiguousCreate() = %t, want %t", got, test.ambiguous)
			}
			definitiveAssignment := isDefinitiveFirewallAssignmentRejection(test.err)
			if definitiveAssignment != test.definitiveAssignment {
				t.Fatalf("isDefinitiveFirewallAssignmentRejection() = %t, want %t", definitiveAssignment, test.definitiveAssignment)
			}
		})
	}
}

type durableBaseFirewallHarness struct {
	fence           cloudapi.FirewallAssignmentFence
	vmUUID          string
	anchorAttempt   string
	launchAuthority bool
	nextIssue       byte
	authorizeCalls  int
	observeCalls    int
	rejectCalls     int
}

func newDurableBaseFirewallHarness(firewallUUID string) *durableBaseFirewallHarness {
	return &durableBaseFirewallHarness{
		fence:     cloudapi.FirewallAssignmentFence{FirewallUUID: firewallUUID, Phase: cloudapi.FirewallAssignmentIntent},
		nextIssue: '3',
	}
}

func (h *durableBaseFirewallHarness) attach(request *cloudapi.CreateVMRequest, allowLaunch bool) {
	request.BaseFirewallAssignment = h.fence
	request.AuthorizeLaunch = func(_ context.Context, _ cloudapi.CreateAuthorizationKind) error {
		if !allowLaunch || h.fence.Phase != cloudapi.FirewallAssignmentIntent {
			return cloudapi.ErrCreateAttemptPending
		}
		h.issue(true)
		return nil
	}
	request.RecordCreatedVM = func(_ context.Context, vmUUID string) error {
		h.anchorAttempt = strings.ToLower(vmUUID)
		if h.vmUUID != "" && h.vmUUID != h.anchorAttempt {
			return errors.New("created VM anchor changed")
		}
		h.vmUUID = h.anchorAttempt
		if h.fence.VMUUID == "" {
			h.fence.VMUUID = h.vmUUID
		}
		return nil
	}
	h.attachAssignmentCallbacks(request)
}

func (h *durableBaseFirewallHarness) attachAssignmentCallbacks(request *cloudapi.CreateVMRequest) {
	request.AuthorizeBaseFirewall = func(_ context.Context, vmUUID string) (cloudapi.FirewallAssignmentAuthorization, error) {
		h.authorizeCalls++
		vmUUID = strings.ToLower(vmUUID)
		if h.anchorAttempt != vmUUID || h.vmUUID != vmUUID {
			return cloudapi.FirewallAssignmentAuthorization{}, errors.New("base firewall requested before exact anchor attempt")
		}
		if h.fence.VMUUID == "" {
			h.fence.VMUUID = vmUUID
		}
		if h.fence.VMUUID != vmUUID {
			return cloudapi.FirewallAssignmentAuthorization{}, errors.New("base firewall VM changed")
		}
		if h.fence.Phase == cloudapi.FirewallAssignmentRejected || h.fence.Phase == cloudapi.FirewallAssignmentIntent {
			h.issue(true)
		}
		authorization := cloudapi.FirewallAssignmentAuthorization{Fence: h.fence, AllowPOST: h.launchAuthority}
		h.launchAuthority = false
		return authorization, nil
	}
	request.ObserveBaseFirewall = func(_ context.Context, vmUUID, issueID string) error {
		h.observeCalls++
		if h.fence.Phase == cloudapi.FirewallAssignmentObserved && h.fence.IssueID == issueID {
			return nil
		}
		if h.fence.Phase != cloudapi.FirewallAssignmentIssued || h.fence.VMUUID != strings.ToLower(vmUUID) || h.fence.IssueID != issueID {
			return errors.New("observed base firewall does not match issued receipt")
		}
		h.fence.Phase = cloudapi.FirewallAssignmentObserved
		return nil
	}
	request.RejectBaseFirewall = func(_ context.Context, vmUUID, issueID string) error {
		h.rejectCalls++
		if h.fence.Phase != cloudapi.FirewallAssignmentIssued || h.fence.VMUUID != strings.ToLower(vmUUID) || h.fence.IssueID != issueID {
			return errors.New("rejected base firewall does not match issued receipt")
		}
		h.fence.Phase = cloudapi.FirewallAssignmentRejected
		return nil
	}
}

func (h *durableBaseFirewallHarness) issue(allowPOST bool) {
	h.fence.Phase = cloudapi.FirewallAssignmentIssued
	h.fence.IssueID = strings.Repeat(string(h.nextIssue), 32)
	h.nextIssue++
	h.launchAuthority = allowPOST
}

type durableFloatingIPUpdateHarness struct {
	fence          cloudapi.FloatingIPUpdateFence
	nextIssue      byte
	allowPOST      bool
	authorizeCalls int
	observeCalls   int
	rejectCalls    int
	observeErr     error
}

func newDurableFloatingIPUpdateHarness() *durableFloatingIPUpdateHarness {
	return &durableFloatingIPUpdateHarness{nextIssue: '6'}
}

func (h *durableFloatingIPUpdateHarness) attachCreate(request *cloudapi.CreateVMRequest) {
	request.AuthorizeFloatingIPUpdate = h.authorize
	request.ObserveFloatingIPUpdate = h.observe
	request.RejectFloatingIPUpdate = h.reject
}

func (h *durableFloatingIPUpdateHarness) attachCleanup(request *cloudapi.FencedCreateCleanupRequest) {
	request.AuthorizeFloatingIPUpdate = h.authorize
	request.ObserveFloatingIPUpdate = h.observe
	request.RejectFloatingIPUpdate = h.reject
}

func (h *durableFloatingIPUpdateHarness) authorize(_ context.Context, vmUUID, address, name string, billingAccountID int64) (cloudapi.FloatingIPUpdateAuthorization, error) {
	h.authorizeCalls++
	vmUUID = strings.ToLower(vmUUID)
	if h.fence.IssueID != "" {
		if h.fence.VMUUID != vmUUID || h.fence.Address != address || h.fence.Name != name || h.fence.BillingAccountID != billingAccountID {
			return cloudapi.FloatingIPUpdateAuthorization{}, errors.New("floating-IP update identity changed")
		}
		if h.fence.Phase == cloudapi.FloatingIPUpdateIssued || h.fence.Phase == cloudapi.FloatingIPUpdateObserved {
			return cloudapi.FloatingIPUpdateAuthorization{Fence: h.fence}, nil
		}
	}
	h.fence = cloudapi.FloatingIPUpdateFence{
		VMUUID: vmUUID, Address: address, Name: name, BillingAccountID: billingAccountID,
		Phase: cloudapi.FloatingIPUpdateIssued, IssueID: strings.Repeat(string(h.nextIssue), 32),
	}
	h.nextIssue++
	h.allowPOST = true
	return cloudapi.FloatingIPUpdateAuthorization{Fence: h.fence, AllowPOST: true}, nil
}

func (h *durableFloatingIPUpdateHarness) observe(_ context.Context, fence cloudapi.FloatingIPUpdateFence) error {
	h.observeCalls++
	if h.observeErr != nil {
		return h.observeErr
	}
	if h.fence.Phase == cloudapi.FloatingIPUpdateObserved && h.fence.IssueID == fence.IssueID {
		return nil
	}
	if h.fence.Phase != cloudapi.FloatingIPUpdateIssued || h.fence.IssueID != fence.IssueID {
		return errors.New("observed floating-IP update does not match issued receipt")
	}
	h.fence.Phase = cloudapi.FloatingIPUpdateObserved
	h.allowPOST = false
	return nil
}

func (h *durableFloatingIPUpdateHarness) reject(_ context.Context, fence cloudapi.FloatingIPUpdateFence) error {
	h.rejectCalls++
	if h.fence.Phase != cloudapi.FloatingIPUpdateIssued || h.fence.IssueID != fence.IssueID {
		return errors.New("rejected floating-IP update does not match issued receipt")
	}
	h.fence.Phase = cloudapi.FloatingIPUpdateRejected
	h.allowPOST = false
	return nil
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

func TestFencedRollbackCommittedHTTP500ThenRestartAbsenceDoesNotReplayDelete(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 80*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = created.UUID
	cleanup.RollbackChosen = true
	cleanup.AttemptResolved = true
	api.deleteVMErrors = []error{&sdk.APIError{StatusCode: 500, Message: "committed after response failure"}}
	api.deleteVMCommitOnError = true
	api.networkErrors = map[int]error{}
	api.networkGetHook = func(call int) {
		if api.deleteVMCalls > 0 {
			api.networkErrors[call] = &sdk.APIError{StatusCode: 503, Message: "readback unavailable"}
		}
	}
	api.operations = nil

	if _, err := adapter.reconcileFencedCreatedVMAnchor(context.Background(), cleanup, true); err == nil || !strings.Contains(err.Error(), "checking VPC membership") {
		t.Fatalf("first fenced rollback error = %v, want committed delete readback uncertainty", err)
	}
	if api.deleteVMCalls != 1 || len(api.vms) != 0 || !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("ambiguous fenced rollback state: calls=%d VMs=%#v firewall=%#v", api.deleteVMCalls, api.vms, api.firewalls[0])
	}

	api.networkErrors = nil
	api.networkGetHook = nil
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, boundedReadbackTestTimeout)
	if _, err := restarted.reconcileFencedCreatedVMAnchor(context.Background(), cleanup, true); err != nil {
		t.Fatalf("restart fenced rollback did not converge from absence: %v", err)
	}
	if api.deleteVMCalls != 1 || !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("restart fenced anchor reconciliation replayed DELETE or mutated a relation without a durable receipt: calls=%d operations=%v firewall=%#v", api.deleteVMCalls, api.operations, api.firewalls[0])
	}
}

func TestFencedAnchorAbsenceUsesDestructiveBudgetBeyondLaunchCleanupTimeout(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	adapter.launchCleanupTimeout = 10 * time.Millisecond
	adapter.destructiveAbsenceTimeout = 250 * time.Millisecond
	adapter.destructiveAbsenceReadInterval = 20 * time.Millisecond
	adapter.networkAttachmentRequestTimeout = 50 * time.Millisecond

	cleanup := fencedCleanupRequest(true)
	cleanup.CreatedVMUUID = "11111111-1111-4111-8111-111111111111"
	cleanup.RollbackChosen = true
	cleanup.AttemptResolved = true

	if _, err := adapter.reconcileFencedCreatedVMAnchor(context.Background(), cleanup, true); err != nil {
		t.Fatalf("fenced absent-anchor cleanup inherited the shorter launch deadline: %v", err)
	}
	if api.vmGetCalls < destructiveAbsenceConfirmations || api.networkGetCalls < destructiveAbsenceConfirmations {
		t.Fatalf("fenced absent-anchor proof used VM GETs=%d VPC GETs=%d, want at least %d complete observations",
			api.vmGetCalls, api.networkGetCalls, destructiveAbsenceConfirmations)
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

func TestReservedCleanupHiddenBaselineVMRemainsPendingAfterReceipt(t *testing.T) {
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
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("CleanupFencedCreate() after durable receipt = %v, want pending while ListVMs omits the exact target", err)
	}
	if api.deleteVMCalls != 0 || len(api.vms) != 1 {
		t.Fatalf("reserved cleanup mutated a target omitted from the post-CAS inventory: deletes=%d VMs=%d", api.deleteVMCalls, len(api.vms))
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

func TestCleanupHistoricalReceiptRemainsPendingWhenListHidesTarget(t *testing.T) {
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
	if _, err := adapter.CleanupFencedCreate(context.Background(), cleanup); !errors.Is(err, cloudapi.ErrCreateAttemptPending) {
		t.Fatalf("CleanupFencedCreate() with hidden historical target = %v, want pending", err)
	}
	if api.deleteVMCalls != 0 || len(api.vms) != 1 {
		t.Fatalf("hidden historical receipt reached DELETE without a fresh ListVM proof: deletes=%d VMs=%d", api.deleteVMCalls, len(api.vms))
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

func TestProtectFencedCreateRejectsInactiveOrDriftedAnchorBeforeFirewallMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*sdk.VM)
	}{
		{name: "HTTP 200 deleted tombstone", mutate: func(vm *sdk.VM) { vm.Status = "Deleted" }},
		{name: "top-level launch shape drift", mutate: func(vm *sdk.VM) { vm.VCPU++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&api.vms[0])
			api.firewalls[0].ResourcesAssigned = nil
			api.operations = nil
			api.firewallAssignCalls = 0
			api.floatingIPUpdateCalls = 0
			api.deleteVMCalls = 0

			cleanup := fencedCleanupRequest(true)
			cleanup.CreatedVMUUID = created.UUID
			err = adapter.ProtectFencedCreate(context.Background(), cleanup)
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
				t.Fatalf("ProtectFencedCreate() error = %v, want active ownership rejection", err)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPUpdateCalls != 0 || api.deleteVMCalls != 0 ||
				len(api.operations) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
				t.Fatalf("inactive/drifted anchor reached cloud mutation: firewall=%d FIP PATCHes=%d VM deletes=%d operations=%v firewallState=%#v",
					api.firewallAssignCalls, api.floatingIPUpdateCalls, api.deleteVMCalls, api.operations, api.firewalls[0])
			}
		})
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
	if api.firewallAssignCalls != 1 || api.firewallListCalls != 2 || len(api.operations) != 1 || api.operations[0] != "assign-firewall" || !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("exact-owned recovery assigns=%d reads=%d operations=%v firewall=%#v, want one pre-read, one assignment, and one successful readback", api.firewallAssignCalls, api.firewallListCalls, api.operations, api.firewalls[0])
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
	request := testRequest()
	api := &fakeAPI{vms: []sdk.VM{canonicalVMForRequest(t, request, anchor)}}
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

func TestDeleteDoesNotDispatchFromMultiIndexAbsenceSnapshot(t *testing.T) {
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
		BillingAccountID: created.BillingAccountID, NetworkUUID: testRequest().NetworkUUID, FirewallUUID: testRequest().FirewallUUID,
	}
	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatal(err)
	}
	if api.deleteVMCalls != 0 || len(api.vms) != 1 {
		t.Fatalf("absence snapshot authorized a VM DELETE: calls=%d VMs=%#v", api.deleteVMCalls, api.vms)
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
		BillingAccountID: created.BillingAccountID, NetworkUUID: testRequest().NetworkUUID, FirewallUUID: testRequest().FirewallUUID,
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
	request.AuthorizeBaseFirewall = func(_ context.Context, vmUUID string) (cloudapi.FirewallAssignmentAuthorization, error) {
		return cloudapi.FirewallAssignmentAuthorization{Fence: cloudapi.FirewallAssignmentFence{
			VMUUID: vmUUID, FirewallUUID: request.FirewallUUID, Phase: cloudapi.FirewallAssignmentIssued, IssueID: "33333333333333333333333333333333",
		}, AllowPOST: true}, nil
	}
	request.ObserveBaseFirewall = func(context.Context, string, string) error { return nil }
	request.RejectBaseFirewall = func(context.Context, string, string) error { return nil }
	attachTestFloatingIPUpdateCallbacks(&request)
	attachTestRemovalMutationCallbacksToCreate(&request)
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
	cleanup.AuthorizeBaseFirewall = func(_ context.Context, vmUUID string) (cloudapi.FirewallAssignmentAuthorization, error) {
		return cloudapi.FirewallAssignmentAuthorization{Fence: cloudapi.FirewallAssignmentFence{
			VMUUID: vmUUID, FirewallUUID: cleanup.FirewallUUID, Phase: cloudapi.FirewallAssignmentIssued, IssueID: "33333333333333333333333333333333",
		}, AllowPOST: true}, nil
	}
	cleanup.ObserveBaseFirewall = func(context.Context, string, string) error { return nil }
	cleanup.RejectBaseFirewall = func(context.Context, string, string) error { return nil }
	attachTestCleanupFloatingIPUpdateCallbacks(&cleanup)
	attachTestRemovalMutationCallbacksToCleanup(&cleanup)
	return cleanup
}

func attachTestFloatingIPUpdateCallbacks(request *cloudapi.CreateVMRequest) {
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCreate(request)
}

func attachTestCleanupFloatingIPUpdateCallbacks(request *cloudapi.FencedCreateCleanupRequest) {
	harness := newDurableFloatingIPUpdateHarness()
	harness.attachCleanup(request)
}

type testRemovalMutationHarness struct {
	current cloudapi.RemovalMutationFence
	issued  int
}

func (h *testRemovalMutationHarness) authorize(_ context.Context, mutation cloudapi.RemovalMutation, present bool) (cloudapi.RemovalMutationAuthorization, error) {
	if h.current.IssueID != "" && h.current.RemovalMutation == mutation {
		if h.current.Phase == cloudapi.RemovalMutationObserved && present {
			return cloudapi.RemovalMutationAuthorization{}, errors.New("observed test removal resource reappeared")
		}
		if h.current.Phase == cloudapi.RemovalMutationRejected && present {
			// ErrMutationBlocked is positive local proof that a new issue is safe.
		} else {
			return cloudapi.RemovalMutationAuthorization{Fence: h.current, Active: true}, nil
		}
	} else if h.current.IssueID != "" && h.current.Phase != cloudapi.RemovalMutationObserved {
		if !present {
			return cloudapi.RemovalMutationAuthorization{}, nil
		}
		return cloudapi.RemovalMutationAuthorization{}, errors.New("different test removal remains unresolved")
	}
	if !present {
		return cloudapi.RemovalMutationAuthorization{}, nil
	}
	h.issued++
	h.current = cloudapi.RemovalMutationFence{
		RemovalMutation: mutation, Phase: cloudapi.RemovalMutationIssued,
		IssueID: fmt.Sprintf("%032x", h.issued),
	}
	return cloudapi.RemovalMutationAuthorization{Fence: h.current, Active: true, AllowMutation: true}, nil
}

func (h *testRemovalMutationHarness) observe(_ context.Context, fence cloudapi.RemovalMutationFence) error {
	if h.current != fence {
		return errors.New("test removal observation identity changed")
	}
	h.current.Phase = cloudapi.RemovalMutationObserved
	return nil
}

func (h *testRemovalMutationHarness) reject(_ context.Context, fence cloudapi.RemovalMutationFence) error {
	if h.current != fence {
		return errors.New("test removal rejection identity changed")
	}
	h.current.Phase = cloudapi.RemovalMutationRejected
	return nil
}

func attachTestRemovalMutationCallbacksToCreate(request *cloudapi.CreateVMRequest) {
	harness := &testRemovalMutationHarness{}
	request.AuthorizeRemovalMutation = harness.authorize
	request.ObserveRemovalMutation = harness.observe
	request.RejectRemovalMutation = harness.reject
}

func attachTestRemovalMutationCallbacksToCleanup(request *cloudapi.FencedCreateCleanupRequest) {
	harness := &testRemovalMutationHarness{}
	request.AuthorizeRemovalMutation = harness.authorize
	request.ObserveRemovalMutation = harness.observe
	request.RejectRemovalMutation = harness.reject
}

func (h *testRemovalMutationHarness) attachDelete(identity *cloudapi.DeleteVMIdentity) {
	identity.AuthorizeRemovalMutation = h.authorize
	identity.ObserveRemovalMutation = h.observe
	identity.RejectRemovalMutation = h.reject
}

func TestDurableVMDeleteCommittedHTTP500NeverReplaysAfterAdapterRestart(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 500*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteVMErrors = []error{errors.New("HTTP 500 after committed VM DELETE")}
	api.deleteVMCommitOnError = true
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("committed VM DELETE recovery = %v", err)
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("VM DELETE calls = %d, want exactly one", api.deleteVMCalls)
	}

	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 500*time.Millisecond)
	err = restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("restarted absent VM delete = %v, want ErrNotFound", err)
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("reconstructed adapter replayed VM DELETE: calls=%d", api.deleteVMCalls)
	}
}

func TestDurableVMDeleteCommittedHTTP500ConvergesThroughExactDeletedTombstone(t *testing.T) {
	api := &fakeAPI{deleteVMLeavesTombstone: true}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 500*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteVMErrors = []error{errors.New("HTTP 500 after committed VM DELETE")}
	api.deleteVMCommitOnError = true
	api.operations = nil

	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("committed VM DELETE tombstone recovery = %v", err)
	}
	tombstone, ok := api.exactVMTombstones[created.UUID]
	if !ok || !vmDeletedTombstone(tombstone) || api.deleteVMCalls != 1 || len(api.vms) != 0 ||
		len(api.floatingIPs) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("tombstone convergence state: tombstone=%#v present=%t calls=%d VMs=%#v FIPs=%#v firewall=%#v operations=%v",
			tombstone, ok, api.deleteVMCalls, api.vms, api.floatingIPs, api.firewalls[0], api.operations)
	}

	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 500*time.Millisecond)
	err = restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("restarted tombstone delete = %v, want ErrNotFound", err)
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("reconstructed adapter replayed VM DELETE against exact tombstone: calls=%d", api.deleteVMCalls)
	}
}

func TestDurableVMDeletePresentAfterHTTP500StaysReadOnlyAcrossRestart(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 50*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteVMErrors = []error{errors.New("HTTP 500 with unknown outcome")}
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("ambiguous uncommitted VM DELETE unexpectedly converged")
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("first reconciliation VM DELETE calls = %d, want one", api.deleteVMCalls)
	}

	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 50*time.Millisecond)
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("restarted ambiguous VM DELETE unexpectedly converged")
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("issued VM DELETE replayed after restart: calls=%d", api.deleteVMCalls)
	}

	api.getVMErrorByUUID = map[string]error{created.UUID: errors.New("readback outage")}
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("readback outage unexpectedly converged")
	}
	if api.deleteVMCalls != 1 {
		t.Fatalf("readback outage replayed issued VM DELETE: calls=%d", api.deleteVMCalls)
	}
}

func TestDurableFloatingIPRemovalCommittedHTTP500NeverReplays(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 500*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	// Model a VM already absent while its exact dependent still points at the
	// deleted UUID, as can happen after VM/FIP relationship convergence lags.
	api.vms = nil
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.unassignFloatingIPErrors = []error{errors.New("HTTP 500 after committed FIP unassign")}
	api.unassignFloatingIPCommitOnError = true
	api.deleteFloatingIPErrors = []error{errors.New("HTTP 500 after committed FIP DELETE")}
	api.deleteFloatingIPCommitOnError = true
	err = adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("committed floating-IP removal recovery = %v", err)
	}
	if got := countOperation(api.operations, "unassign-floating-ip"); got != 1 {
		t.Fatalf("floating-IP unassign calls = %d, want one", got)
	}
	if got := countOperation(api.operations, "delete-floating-ip"); got != 1 {
		t.Fatalf("floating-IP DELETE calls = %d, want one", got)
	}

	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 500*time.Millisecond)
	_ = restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	if got := countOperation(api.operations, "unassign-floating-ip"); got != 1 {
		t.Fatalf("reconstructed adapter replayed floating-IP unassign: %d", got)
	}
	if got := countOperation(api.operations, "delete-floating-ip"); got != 1 {
		t.Fatalf("reconstructed adapter replayed floating-IP DELETE: %d", got)
	}
}

func TestDurableFloatingIPUnassignPresentAfterHTTP500StaysReadOnly(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 50*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.unassignFloatingIPErrors = []error{errors.New("HTTP 500 with unknown unassign outcome")}
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("ambiguous floating-IP unassign unexpectedly converged")
	}
	if got := countOperation(api.operations, "unassign-floating-ip"); got != 1 {
		t.Fatalf("first floating-IP unassign calls = %d, want one", got)
	}
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 50*time.Millisecond)
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("restarted ambiguous floating-IP unassign unexpectedly converged")
	}
	if got := countOperation(api.operations, "unassign-floating-ip"); got != 1 {
		t.Fatalf("issued floating-IP unassign replayed: calls=%d", got)
	}
}

func TestDurableFloatingIPDeletePresentAfterHTTP500StaysReadOnly(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 50*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil
	api.floatingIPs[0].AssignedTo = ""
	api.floatingIPs[0].AssignedToResourceType = ""
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	api.deleteFloatingIPErrors = []error{errors.New("HTTP 500 with unknown floating-IP DELETE outcome")}
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("ambiguous floating-IP DELETE unexpectedly converged")
	}
	if got := countOperation(api.operations, "delete-floating-ip"); got != 1 {
		t.Fatalf("first floating-IP DELETE calls = %d, want one", got)
	}
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 50*time.Millisecond)
	if err := restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err == nil {
		t.Fatal("restarted ambiguous floating-IP DELETE unexpectedly converged")
	}
	if got := countOperation(api.operations, "delete-floating-ip"); got != 1 {
		t.Fatalf("issued floating-IP DELETE replayed: calls=%d", got)
	}
}
