package inspace

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const boundedReadbackTestTimeout = 200 * time.Millisecond

func TestCreateIsReadBeforeCreateIdempotent(t *testing.T) {
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: inspacev1.IntelScalableHostPoolUUID}}}
	passwordCalls := 0
	adapter, err := newAdapter(api, func() (string, error) {
		passwordCalls++
		return validGeneratedTestPassword, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	first, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.UUID != second.UUID || api.createCalls != 1 {
		t.Fatalf("idempotent creates returned %q/%q with %d POSTs", first.UUID, second.UUID, api.createCalls)
	}
	if passwordCalls != 1 {
		t.Fatalf("password generator called %d times, want once for the actual POST only", passwordCalls)
	}
	if api.lastVMRequest.ReservePublicIP == nil || *api.lastVMRequest.ReservePublicIP {
		t.Fatalf("VM create must reserve no implicit public IP: %#v", api.lastVMRequest.ReservePublicIP)
	}
	if api.lastVMRequest.NetworkUUID != request.NetworkUUID {
		t.Fatalf("VM create network UUID = %q, want %q", api.lastVMRequest.NetworkUUID, request.NetworkUUID)
	}
	if !strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), "203.0.113.10") || strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), "__INSPACE_FLOATING_IPV4__") {
		t.Fatalf("VM cloud-init external IP was not resolved: %s", api.lastVMRequest.CloudInit)
	}
	if !strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), "10.0.0.0/24") || strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), bootstrap.VPCSubnetPlaceholder) {
		t.Fatalf("VM cloud-init exact VPC subnet was not resolved: %s", api.lastVMRequest.CloudInit)
	}
	if api.lastVMRequest.Username != defaultUsername || api.lastVMRequest.Password != validGeneratedTestPassword || api.lastVMRequest.PublicKey != "" {
		t.Fatalf("default VM access contract not applied: username=%q passwordSet=%t publicKeySet=%t", api.lastVMRequest.Username, api.lastVMRequest.Password != "", api.lastVMRequest.PublicKey != "")
	}
	if strings.Contains(api.lastVMRequest.Description, api.lastVMRequest.Password) {
		t.Fatal("ephemeral password leaked into VM ownership")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(api.lastVMRequest.Description), &record); err != nil {
		t.Fatalf("decode ownership: %v", err)
	}
	for key := range record {
		if strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "credential") {
			t.Fatalf("ownership contains forbidden credential field %q", key)
		}
	}
	if record["keyHash"] != hashKey(request.IdempotencyKey) {
		t.Fatal("ownership key hash must derive only from the idempotency key")
	}
	if record["privateLoadBalancerPoolStart"] != request.PrivateLoadBalancerPoolStart || record["privateLoadBalancerPoolStop"] != request.PrivateLoadBalancerPoolStop {
		t.Fatalf("ownership omitted exact private Service pool: %#v", record)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != first.UUID {
		t.Fatalf("expected one owned assigned floating IP, got %#v", api.floatingIPs)
	}
	if second.State != cloudapi.LifecyclePending {
		t.Fatalf("state = %q", second.State)
	}
}

func TestCreateRequiresVMNameToMatchNodeClaimBeforeMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	request.Name = "different-vm-name"
	if _, err := adapter.CreateVM(context.Background(), request); err == nil || !strings.Contains(err.Error(), "must exactly match NodeClaim") {
		t.Fatalf("CreateVM() error = %v, want VM/NodeClaim name contract", err)
	}
	if api.createCalls != 0 || api.floatingIPCreateCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("invalid VM/NodeClaim name reached mutation: VMPOSTs=%d FIPPOSTs=%d operations=%v", api.createCalls, api.floatingIPCreateCalls, api.operations)
	}
}

func TestCreateAdoptsExactNameFromSparseListAfterCanonicalDetail(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	first, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	getCallsBefore := api.vmGetCalls
	api.omitVMListDescriptions = true
	second, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.UUID != first.UUID || api.createCalls != 1 || len(api.vms) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("sparse-list adoption result=%#v POSTs=%d VMs=%#v FIPs=%#v", second, api.createCalls, api.vms, api.floatingIPs)
	}
	if api.vmGetCalls-getCallsBefore < 2 {
		t.Fatalf("sparse-list adoption did not use canonical detail before protection: GET delta=%d", api.vmGetCalls-getCallsBefore)
	}
}

func TestAmbiguousCreateRecoversSparseListCandidateThroughCanonicalDetail(t *testing.T) {
	api := &fakeAPI{
		createErr:              errors.New("connection reset after request"),
		commitOnCreateError:    true,
		omitVMListDescriptions: true,
	}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID == "" || api.createCalls != 1 || len(api.vms) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("ambiguous sparse-list recovery result=%#v POSTs=%d VMs=%#v FIPs=%#v", created, api.createCalls, api.vms, api.floatingIPs)
	}
	if api.vmGetCalls < 2 || api.firewallAssignCalls != 1 || api.floatingIPAssignCalls != 1 {
		t.Fatalf("ambiguous recovery lacked canonical proof/protection: GETs=%d firewall=%d floatingIP=%d", api.vmGetCalls, api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateRejectsInvalidOrDuplicateListCandidateAuthorityBeforeMutation(t *testing.T) {
	tests := map[string][]sdk.VM{
		"invalid UUID": {{UUID: "not-a-uuid", Name: "foreign"}},
		"duplicate UUID": {
			{UUID: "11111111-1111-4111-8111-111111111111", Name: "foreign-a"},
			{UUID: "11111111-1111-4111-8111-111111111111", Name: "foreign-b"},
		},
		"duplicate deterministic name": {
			{UUID: "11111111-1111-4111-8111-111111111111", Name: "nodeclaim-a"},
			{UUID: "22222222-2222-4222-8222-222222222222", Name: "nodeclaim-a"},
		},
	}
	for name, vms := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{vms: vms}
			adapter, _ := New(api)
			if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
				t.Fatal("CreateVM() accepted invalid or duplicate list candidate authority")
			}
			if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.vmGetCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("list authority failure reached mutation/detail lookup: FIPPOSTs=%d VMPOSTs=%d GETs=%d operations=%v", api.floatingIPCreateCalls, api.createCalls, api.vmGetCalls, api.operations)
			}
		})
	}
}

func TestCreateCanonicalCandidateNotFoundOrNilFailsClosed(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"not found": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 404}}
		},
		"nil response": func(api *fakeAPI, uuid string) { api.nilGetVMUUID = uuid },
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			api.omitVMListDescriptions = true
			inject(api, created.UUID)
			getCallsBefore := api.vmGetCalls
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
				t.Fatal("CreateVM() accepted an uncertain canonical candidate")
			}
			if api.vmGetCalls-getCallsBefore < 2 || api.createCalls != 1 || api.deleteVMCalls != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 {
				t.Fatalf("uncertain canonical candidate mutated resources: GET delta=%d POSTs=%d deletes=%d VMs=%#v FIPs=%#v", api.vmGetCalls-getCallsBefore, api.createCalls, api.deleteVMCalls, api.vms, api.floatingIPs)
			}
		})
	}
}

func TestCreateSparseResponseUsesPersistedVMDetailAuthority(t *testing.T) {
	api := &fakeAPI{sparseCreateResponse: true}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID != "11111111-1111-4111-8111-111111111111" || created.PrivateIPv4 != "10.0.0.20" || created.SpecHash != "spec-a" {
		t.Fatalf("CreateVM() did not return authoritative persisted details: %#v", created)
	}
	if api.vmGetCalls != 1 || api.firewallAssignCalls != 1 || api.floatingIPAssignCalls != 1 {
		t.Fatalf("sparse create did not pass through persisted detail proof: GETs=%d firewall=%d floatingIP=%d", api.vmGetCalls, api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateWaitsForIncompletePersistedOwnership(t *testing.T) {
	remainingIncompleteReads := 2
	api := &fakeAPI{
		sparseCreateResponse: true,
		mutateGetVMResponse: func(vm *sdk.VM) {
			switch remainingIncompleteReads {
			case 2:
				vm.Description = ""
			case 1:
				var partial ownership
				if err := json.Unmarshal([]byte(vm.Description), &partial); err != nil {
					t.Fatalf("decode ownership fixture: %v", err)
				}
				partial.SpecHash = ""
				encoded, err := json.Marshal(partial)
				if err != nil {
					t.Fatalf("encode partial ownership fixture: %v", err)
				}
				vm.Description = string(encoded)
			}
			if remainingIncompleteReads > 0 {
				remainingIncompleteReads--
			}
		},
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 200*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID != "11111111-1111-4111-8111-111111111111" || api.vmGetCalls != 3 {
		t.Fatalf("CreateVM() result=%#v GETs=%d, want canonical ownership on the third detail read", created, api.vmGetCalls)
	}
	if api.deleteVMCalls != 0 || api.firewallAssignCalls != 1 || api.floatingIPAssignCalls != 1 {
		t.Fatalf("eventual ownership read-back caused rollback or skipped protection: deletes=%d firewall=%d floatingIP=%d", api.deleteVMCalls, api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateWaitsForIncompletePersistedLaunchIdentity(t *testing.T) {
	remainingIncompleteReads := 2
	api := &fakeAPI{
		mutateGetVMResponse: func(vm *sdk.VM) {
			if remainingIncompleteReads == 0 {
				return
			}
			remainingIncompleteReads--
			vm.Name = ""
			vm.VCPU = 0
			vm.MemoryMiB = 0
			vm.OSName = ""
			vm.OSVersion = ""
			vm.DesignatedPoolUUID = ""
			vm.NetworkUUID = ""
			vm.BillingAccountID = 0
			vm.Storage = nil
		},
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 200*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "nodeclaim-a" || created.VCPU != 2 || created.MemoryGiB != 4 || api.vmGetCalls != 3 {
		t.Fatalf("CreateVM() result=%#v GETs=%d, want complete launch identity on the third detail read", created, api.vmGetCalls)
	}
	if api.deleteVMCalls != 0 || api.firewallAssignCalls != 1 || api.floatingIPAssignCalls != 1 {
		t.Fatalf("eventual launch identity caused rollback or skipped protection: deletes=%d firewall=%d floatingIP=%d", api.deleteVMCalls, api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateBoundsIncompletePersistedLaunchIdentity(t *testing.T) {
	api := &fakeAPI{mutateGetVMResponse: func(vm *sdk.VM) { vm.NetworkUUID = "" }}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CreateVM() error = %v, want bounded incomplete launch identity failure", err)
	}
	if api.vmGetCalls < 2 || api.deleteVMCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("bounded launch identity cleanup: GETs=%d deletes=%d VMs=%#v FIPs=%#v", api.vmGetCalls, api.deleteVMCalls, api.vms, api.floatingIPs)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("incomplete launch identity reached protection: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestWorkerPrivateIPv4CancellationPreservesLastOwnershipObservation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	expected, managed := parseOwnership(api.vms[0].Description)
	if !managed {
		t.Fatal("created VM fixture lacks Karpenter ownership")
	}
	api.mutateGetVMResponse = func(vm *sdk.VM) { vm.Description = "" }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hookCalls := 0
	api.getVMHook = func(string) {
		hookCalls++
		if hookCalls == 2 {
			cancel()
		}
	}
	configureFastNetworkReadback(adapter, time.Second)
	_, _, ownershipProven, err := adapter.ensureWorkerPrivateIPv4(
		ctx,
		request,
		created.UUID,
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParseAddr(request.ControlPlaneVIP),
		inspacev1.PrivateLoadBalancerPool{Start: request.PrivateLoadBalancerPoolStart, Stop: request.PrivateLoadBalancerPoolStop},
		expected,
	)
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureWorkerPrivateIPv4() error = %v, want prior ownership observation joined with cancellation", err)
	}
	if ownershipProven || hookCalls != 2 {
		t.Fatalf("canceled read-back ownershipProven=%t GET hooks=%d, want false/2", ownershipProven, hookCalls)
	}
}

func TestCreateRejectsPresentLaunchIdentityConflictImmediately(t *testing.T) {
	tests := map[string]func(*sdk.VM){
		"name": func(vm *sdk.VM) { vm.Name = "foreign" },
		"name with incomplete ownership": func(vm *sdk.VM) {
			vm.Description = ""
			vm.Name = "foreign"
		},
		"vCPU":                 func(vm *sdk.VM) { vm.VCPU++ },
		"memory":               func(vm *sdk.VM) { vm.MemoryMiB++ },
		"OS name":              func(vm *sdk.VM) { vm.OSName = "debian" },
		"OS version":           func(vm *sdk.VM) { vm.OSVersion = "22.04" },
		"designated pool UUID": func(vm *sdk.VM) { vm.DesignatedPoolUUID = "foreign-pool" },
		"network UUID":         func(vm *sdk.VM) { vm.NetworkUUID = "foreign-network" },
		"billing account":      func(vm *sdk.VM) { vm.BillingAccountID++ },
		"root disk size":       func(vm *sdk.VM) { vm.Storage[0].SizeGiB++ },
		"multiple root disks": func(vm *sdk.VM) {
			vm.Storage = append(vm.Storage, sdk.VMStorage{SizeGiB: int(testRequest().RootDiskGiB), Primary: true})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{mutateGetVMResponse: mutate}
			adapter, _ := New(api)
			_, err := adapter.CreateVM(context.Background(), testRequest())
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
				t.Fatalf("CreateVM() error = %v, want launch identity conflict", err)
			}
			if api.vmGetCalls != 1 || api.deleteVMCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("present conflict was retried or leaked fresh launch: GETs=%d deletes=%d VMs=%#v FIPs=%#v", api.vmGetCalls, api.deleteVMCalls, api.vms, api.floatingIPs)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
				t.Fatalf("present conflict reached protection: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
			}
		})
	}
}

func TestCreateRejectsUnpersistedOwnershipBeforeProtection(t *testing.T) {
	tests := map[string]struct {
		mutate     func(string) string
		incomplete bool
	}{
		"missing": {
			mutate: func(string) string { return "" }, incomplete: true,
		},
		"truncated": {
			mutate: func(description string) string { return description[:len(description)/2] }, incomplete: true,
		},
		"mismatched": {
			mutate: func(description string) string {
				var record ownership
				if err := json.Unmarshal([]byte(description), &record); err != nil {
					t.Fatalf("decode ownership fixture: %v", err)
				}
				record.SpecHash = "foreign-spec"
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("encode ownership fixture: %v", err)
				}
				return string(encoded)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{persistDescription: test.mutate}
			adapter, _ := New(api)
			if test.incomplete {
				configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			}
			_, err := adapter.CreateVM(context.Background(), testRequest())
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
				t.Fatalf("CreateVM() error = %v, want persisted ownership rejection", err)
			}
			if test.incomplete && (!errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatalf("CreateVM() error = %v, want incomplete observation and read-back deadline", err)
			}
			if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
				t.Fatalf("ownership rejection leaked launched resources: VMs=%#v FIPs=%#v POSTs=%d GETs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.vmGetCalls, api.deleteVMCalls)
			}
			if test.incomplete && api.vmGetCalls < 2 {
				t.Fatalf("incomplete ownership was not retried within the read-back bound: GETs=%d", api.vmGetCalls)
			}
			if !test.incomplete && api.vmGetCalls != 1 {
				t.Fatalf("complete conflicting ownership was retried: GETs=%d", api.vmGetCalls)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
				t.Fatalf("ownership rejection reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
			}
			if !reflect.DeepEqual(api.operations, []string{"delete-floating-ip", "delete-vm"}) {
				t.Fatalf("unsafe ownership rollback operations: %v", api.operations)
			}
		})
	}
}

func TestAmbiguousCreateInvalidListOwnershipNeverProtectsOrDeletesUnprovenVM(t *testing.T) {
	tests := map[string]struct {
		mutate     func(string) string
		incomplete bool
	}{
		"missing": {
			mutate: func(string) string { return "" }, incomplete: true,
		},
		"truncated": {
			mutate: func(description string) string { return description[:len(description)/2] }, incomplete: true,
		},
		"mismatched identity": {
			mutate: func(description string) string {
				var record ownership
				if err := json.Unmarshal([]byte(description), &record); err != nil {
					t.Fatalf("decode ownership fixture: %v", err)
				}
				record.NodeClaim = "foreign-nodeclaim"
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("encode ownership fixture: %v", err)
				}
				return string(encoded)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				createErr:           errors.New("connection reset after request"),
				commitOnCreateError: true,
				persistDescription:  test.mutate,
			}
			adapter, _ := New(api)
			if test.incomplete {
				configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			}
			if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
				t.Fatal("CreateVM() unexpectedly trusted invalid ListVMs ownership")
			}
			if len(api.vms) != 1 || api.createCalls != 1 || api.deleteVMCalls != 0 {
				t.Fatalf("ambiguous unproven VM was retried, trusted, or unsafely deleted: VMs=%#v POSTs=%d GETs=%d deletes=%d", api.vms, api.createCalls, api.vmGetCalls, api.deleteVMCalls)
			}
			if test.incomplete && api.vmGetCalls < 2 {
				t.Fatalf("incomplete canonical ownership was not retried: GETs=%d", api.vmGetCalls)
			}
			if !test.incomplete && api.vmGetCalls != 1 {
				t.Fatalf("complete canonical ownership conflict was retried: GETs=%d", api.vmGetCalls)
			}
			if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
				t.Fatalf("ambiguous ownership anchor was changed: %#v", api.floatingIPs)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("invalid ListVMs ownership reached a mutation: firewall=%d floatingIP=%d operations=%v", api.firewallAssignCalls, api.floatingIPAssignCalls, api.operations)
			}
		})
	}
}

func TestAmbiguousCreateCanonicalOwnershipUncertaintyNeverMutatesListMatchedVM(t *testing.T) {
	tests := map[string]struct {
		mutate     func(*sdk.VM)
		incomplete bool
	}{
		"missing description": {
			mutate: func(vm *sdk.VM) { vm.Description = "" }, incomplete: true,
		},
		"truncated description": {
			mutate: func(vm *sdk.VM) { vm.Description = vm.Description[:len(vm.Description)/2] }, incomplete: true,
		},
		"missing launch identity": {
			mutate: func(vm *sdk.VM) { vm.DesignatedPoolUUID = "" }, incomplete: true,
		},
		"mismatched ownership": {
			mutate: func(vm *sdk.VM) {
				var record ownership
				if err := json.Unmarshal([]byte(vm.Description), &record); err != nil {
					t.Fatalf("decode ownership fixture: %v", err)
				}
				record.SpecHash = "foreign-spec"
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("encode ownership fixture: %v", err)
				}
				vm.Description = string(encoded)
			},
		},
		"mismatched UUID": {
			mutate: func(vm *sdk.VM) { vm.UUID = "99999999-9999-4999-8999-999999999999" },
		},
		"mismatched name": {
			mutate: func(vm *sdk.VM) { vm.Name = "foreign" },
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{
				createErr:           errors.New("connection reset after request"),
				commitOnCreateError: true,
				mutateGetVMResponse: test.mutate,
			}
			adapter, _ := New(api)
			if test.incomplete {
				configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			}
			_, err := adapter.CreateVM(context.Background(), testRequest())
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
				t.Fatalf("CreateVM() error = %v, want canonical ownership rejection", err)
			}
			if len(api.vms) != 1 || api.createCalls != 1 || api.deleteVMCalls != 0 {
				t.Fatalf("canonical disagreement retried or deleted list-matched VM: VMs=%#v POSTs=%d GETs=%d deletes=%d", api.vms, api.createCalls, api.vmGetCalls, api.deleteVMCalls)
			}
			if test.incomplete && api.vmGetCalls < 2 {
				t.Fatalf("incomplete canonical ownership was not retried: GETs=%d", api.vmGetCalls)
			}
			if !test.incomplete && api.vmGetCalls != 1 {
				t.Fatalf("complete canonical ownership conflict was retried: GETs=%d", api.vmGetCalls)
			}
			if record, managed := parseOwnership(api.vms[0].Description); !managed || record.SpecHash != "spec-a" {
				t.Fatalf("ListVMs fixture did not retain exact ownership: %#v, managed=%t", record, managed)
			}
			if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
				t.Fatalf("ambiguous ownership anchor was changed: %#v", api.floatingIPs)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("canonical disagreement reached mutation: firewall=%d floatingIP=%d operations=%v", api.firewallAssignCalls, api.floatingIPAssignCalls, api.operations)
			}
		})
	}
}

func TestAmbiguousCreateDoesNotRollbackBeforeCanonicalOwnershipProof(t *testing.T) {
	api := &fakeAPI{
		createErr:           errors.New("connection reset after request"),
		commitOnCreateError: true,
		network:             &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"},
	}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "attachment to network") {
		t.Fatalf("CreateVM() error = %v, want pre-ownership network read-back failure", err)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.createCalls != 1 || api.vmGetCalls != 1 || api.deleteVMCalls != 0 {
		t.Fatalf("pre-proof failure changed ambiguous resources: VMs=%#v FIPs=%#v POSTs=%d GETs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.vmGetCalls, api.deleteVMCalls)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("pre-proof failure reached mutation: firewall=%d floatingIP=%d operations=%v", api.firewallAssignCalls, api.floatingIPAssignCalls, api.operations)
	}
}

func TestCreatePassesOptionalSSHAccess(t *testing.T) {
	api := &fakeAPI{}
	adapter, err := newAdapter(api, func() (string, error) { return validGeneratedTestPassword, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	request.SSHUsername = "inspacee2e"
	request.SSHPublicKey = validAdapterTestPublicKey
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if api.lastVMRequest.Username != request.SSHUsername || api.lastVMRequest.PublicKey != request.SSHPublicKey || api.lastVMRequest.Password != validGeneratedTestPassword {
		t.Fatalf("SSH access was not passed through: username=%q publicKeyMatch=%t passwordSet=%t", api.lastVMRequest.Username, api.lastVMRequest.PublicKey == request.SSHPublicKey, api.lastVMRequest.Password != "")
	}
}

func TestPasswordGenerationFailsClosedBeforeVMPost(t *testing.T) {
	for name, generator := range map[string]func() (string, error){
		"error":           func() (string, error) { return "", errors.New("entropy unavailable") },
		"empty":           func() (string, error) { return "", nil },
		"wrong length":    func() (string, error) { return "Aa1!short", nil },
		"missing classes": func() (string, error) { return strings.Repeat("a", 32), nil },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, err := newAdapter(api, generator)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
				t.Fatal("expected password generation failure")
			}
			if api.createCalls != 0 {
				t.Fatalf("VM POST occurred after password generation failure: %d", api.createCalls)
			}
			if len(api.floatingIPs) != 0 {
				t.Fatalf("floating IP leaked after password generation failure: %#v", api.floatingIPs)
			}
		})
	}
}

func TestPasswordFailurePreservesPriorAmbiguousCreateAnchor(t *testing.T) {
	api := &fakeAPI{createErr: errors.New("connection reset")}
	passwordCalls := 0
	adapter, err := newAdapter(api, func() (string, error) {
		passwordCalls++
		if passwordCalls == 1 {
			return validGeneratedTestPassword, nil
		}
		return "", errors.New("entropy unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err == nil {
		t.Fatal("expected ambiguous VM create error")
	}
	if api.createCalls != 1 || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("ambiguous create anchor was not preserved: POSTs=%d floatingIPs=%#v", api.createCalls, api.floatingIPs)
	}
	address := api.floatingIPs[0].Address
	if _, err := adapter.CreateVM(context.Background(), request); err == nil {
		t.Fatal("expected password generation error on reconciliation")
	}
	if api.createCalls != 1 {
		t.Fatalf("unexpected second VM POST after password failure: %d", api.createCalls)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Address != address || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("prior ambiguous-create anchor was removed or changed: %#v", api.floatingIPs)
	}
}

func TestGeneratedPasswordContract(t *testing.T) {
	first, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("generated password lengths = %d/%d, want 32", len(first), len(second))
	}
	if first == second {
		t.Fatal("independent generated passwords unexpectedly matched")
	}
	for name, pattern := range map[string]string{
		"lowercase": `[a-z]`, "uppercase": `[A-Z]`, "digit": `[0-9]`, "symbol": `[^A-Za-z0-9]`,
	} {
		if !regexp.MustCompile(pattern).MatchString(first) {
			t.Fatalf("generated password lacks %s character class", name)
		}
	}
}

func TestCreateRecoversAmbiguousCommittedPOSTWithoutRetry(t *testing.T) {
	api := &fakeAPI{createErr: errors.New("connection reset after request"), commitOnCreateError: true}
	adapter, _ := New(api)
	vm, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if vm.UUID == "" || api.createCalls != 1 {
		t.Fatalf("recovery VM = %#v, POSTs = %d", vm, api.createCalls)
	}
}

func TestCreateWaitsForNetworkAttachmentWithoutDuplicatePOST(t *testing.T) {
	api := &fakeAPI{networkMembershipAfter: 8}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 500*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID == "" || api.createCalls != 1 {
		t.Fatalf("created VM = %#v, POSTs = %d", created, api.createCalls)
	}
	if api.networkGetCalls < 9 {
		t.Fatalf("network read-backs = %d, want propagation beyond the old five-read boundary", api.networkGetCalls)
	}
}

func TestCreateWaitsForExactlyOneWorkerPrivateIPv4(t *testing.T) {
	api := &fakeAPI{privateIPv4VisibleAfter: 3}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 250*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.PrivateIPv4 != "10.0.0.20" || api.vmGetCalls != 4 || api.createCalls != 1 {
		t.Fatalf("private-IP readback result=%#v GETs=%d POSTs=%d", created, api.vmGetCalls, api.createCalls)
	}
}

func TestWorkerPrivateIPv4MustBeExactlyOneRFC1918AddressInsideVPC(t *testing.T) {
	network := netip.MustParsePrefix("10.0.0.0/24")
	vip := netip.MustParseAddr("10.0.0.10")
	for name, test := range map[string]struct {
		value     string
		wantError bool
	}{
		"valid":             {value: "10.0.0.20"},
		"missing":           {wantError: true},
		"multiple":          {value: "10.0.0.20,10.0.0.21", wantError: true},
		"surrounding space": {value: " 10.0.0.20", wantError: true},
		"public":            {value: "203.0.113.20", wantError: true},
		"outside VPC":       {value: "10.1.0.20", wantError: true},
		"network address":   {value: "10.0.0.0", wantError: true},
		"broadcast address": {value: "10.0.0.255", wantError: true},
		"VIP collision":     {value: "10.0.0.10", wantError: true},
		"Service pool":      {value: "10.0.0.200", wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := validateWorkerPrivateIPv4(sdk.VM{UUID: "worker-1", PrivateIPv4: test.value}, network, vip, testPrivateLoadBalancerPool())
			if (err != nil) != test.wantError {
				t.Fatalf("validateWorkerPrivateIPv4(%q) = %s, %v; wantError=%t", test.value, got, err, test.wantError)
			}
		})
	}
}

func TestCreatedWorkerPrivateIPCollisionRollsBackOwnedResources(t *testing.T) {
	api := &fakeAPI{createdPrivateIPv4: "10.0.0.10"}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "collides with the private RKE2 supervisor VIP") {
		t.Fatalf("CreateVM() error = %v, want supervisor VIP collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("collision rollback leaked resources: VMs=%#v FIPs=%#v VMPOSTs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("collision reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
	if !reflect.DeepEqual(api.operations, []string{"delete-floating-ip", "delete-vm"}) {
		t.Fatalf("unsafe collision rollback order: %v", api.operations)
	}
}

func TestAmbiguousCommittedWorkerVIPCollisionRollsBackOwnedResources(t *testing.T) {
	api := &fakeAPI{createdPrivateIPv4: "10.0.0.10", createErr: errors.New("connection reset after request"), commitOnCreateError: true}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "collides with the private RKE2 supervisor VIP") {
		t.Fatalf("CreateVM() error = %v, want supervisor VIP collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("ambiguous collision rollback leaked resources: VMs=%#v FIPs=%#v VMPOSTs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls)
	}
}

func TestPositivelyOwnedExistingWorkerVIPCollisionRollsBack(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.vms[0].PrivateIPv4 = request.ControlPlaneVIP
	api.operations = nil
	if _, err := adapter.CreateVM(context.Background(), request); err == nil || !strings.Contains(err.Error(), "collides with the private RKE2 supervisor VIP") {
		t.Fatalf("CreateVM() error = %v, want supervisor VIP collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("existing collision was not rolled back: VMs=%#v FIPs=%#v POSTs=%d deletes=%d operations=%v", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls, api.operations)
	}
	wantOrder := []string{"unassign-floating-ip", "delete-floating-ip", "delete-vm", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOrder) {
		t.Fatalf("unsafe existing-collision rollback order %v, want %v", api.operations, wantOrder)
	}
}

func TestCreatedWorkerServiceVIPPoolCollisionRollsBackOwnedResources(t *testing.T) {
	api := &fakeAPI{createdPrivateIPv4: "10.0.0.200"}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if !errors.Is(err, errWorkerServiceVIPPoolCollision) {
		t.Fatalf("CreateVM() error = %v, want reserved Service VIP-pool collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("Service-pool collision rollback leaked resources: VMs=%#v FIPs=%#v VMPOSTs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("Service-pool collision reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
	if !reflect.DeepEqual(api.operations, []string{"delete-floating-ip", "delete-vm"}) {
		t.Fatalf("unsafe Service-pool collision rollback order: %v", api.operations)
	}
}

func TestAmbiguousCommittedWorkerServiceVIPPoolCollisionRollsBackOwnedResources(t *testing.T) {
	api := &fakeAPI{createdPrivateIPv4: "10.0.0.219", createErr: errors.New("connection reset after request"), commitOnCreateError: true}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if !errors.Is(err, errWorkerServiceVIPPoolCollision) {
		t.Fatalf("CreateVM() error = %v, want reserved Service VIP-pool collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("ambiguous Service-pool collision rollback leaked resources: VMs=%#v FIPs=%#v VMPOSTs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls)
	}
}

func TestPositivelyOwnedExistingWorkerServiceVIPPoolCollisionRollsBack(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.vms[0].PrivateIPv4 = "10.0.0.210"
	api.operations = nil
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, errWorkerServiceVIPPoolCollision) {
		t.Fatalf("CreateVM() error = %v, want reserved Service VIP-pool collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("existing Service-pool collision was not rolled back: VMs=%#v FIPs=%#v POSTs=%d deletes=%d operations=%v", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls, api.operations)
	}
	wantOrder := []string{"unassign-floating-ip", "delete-floating-ip", "delete-vm", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOrder) {
		t.Fatalf("unsafe existing Service-pool collision rollback order %v, want %v", api.operations, wantOrder)
	}
}

func TestAmbiguousCommittedGenericOwnershipMismatchIsNotDeleted(t *testing.T) {
	api := &fakeAPI{
		createdNetworkUUID:  "other-network",
		createErr:           errors.New("connection reset after request"),
		commitOnCreateError: true,
	}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "persisted launch identity differs") {
		t.Fatalf("CreateVM() error = %v, want generic launch mismatch", err)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.deleteVMCalls != 0 || slicesContain(api.operations, "delete-vm") {
		t.Fatalf("generic ambiguous mismatch deleted resources: VMs=%#v FIPs=%#v deletes=%d operations=%v", api.vms, api.floatingIPs, api.deleteVMCalls, api.operations)
	}
}

func TestOwnedVIPCollisionRollsBackBeforeUnusableFIPOrFirewallAssignment(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.vms[0].PrivateIPv4 = request.ControlPlaneVIP
	api.floatingIPs[0].Enabled = false
	api.firewalls[0].ResourcesAssigned = nil
	api.operations = nil
	api.firewallAssignCalls = 0
	api.floatingIPAssignCalls = 0
	_, err := adapter.CreateVM(context.Background(), request)
	if !errors.Is(err, errWorkerSupervisorVIPCollision) {
		t.Fatalf("CreateVM() error = %v, want owned VIP collision", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("collision was not rolled back before protection assignment: VMs=%#v FIPs=%#v firewall=%d floating=%d", api.vms, api.floatingIPs, api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestExistingWorkerRejectsUnexpectedSecondFloatingIPWithoutMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	api.floatingIPs = append(api.floatingIPs, sdk.FloatingIP{
		Name: "foreign-address", Address: "203.0.113.11", BillingAccountID: request.BillingAccountID,
		AssignedTo: created.UUID, AssignedToResourceType: "virtual_machine", Enabled: true, Type: "public",
	})
	api.operations = nil
	_, err = adapter.CreateVM(context.Background(), request)
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "exactly one floating IP") {
		t.Fatalf("CreateVM() error = %v, want extra floating-IP rejection", err)
	}
	if api.createCalls != 1 || api.deleteVMCalls != 0 || len(api.operations) != 0 || len(api.floatingIPs) != 2 {
		t.Fatalf("extra floating-IP audit mutated resources: POSTs=%d deletes=%d operations=%v FIPs=%#v", api.createCalls, api.deleteVMCalls, api.operations, api.floatingIPs)
	}
}

func TestFloatingIPMustBeUsablePublicNonVirtualAddress(t *testing.T) {
	base := sdk.FloatingIP{Address: "203.0.113.10", Name: "worker-public", Enabled: true, Type: "public"}
	tests := map[string]func(*sdk.FloatingIP){
		"disabled":   func(address *sdk.FloatingIP) { address.Enabled = false },
		"deleted":    func(address *sdk.FloatingIP) { address.IsDeleted = true },
		"virtual":    func(address *sdk.FloatingIP) { address.IsVirtual = true },
		"empty type": func(address *sdk.FloatingIP) { address.Type = "" },
		"wrong type": func(address *sdk.FloatingIP) { address.Type = "private" },
		"private IP": func(address *sdk.FloatingIP) { address.Address = "10.0.0.20" },
		"IPv6":       func(address *sdk.FloatingIP) { address.Address = "2001:db8::20" },
	}
	if err := validateUsableFloatingIP(base); err != nil {
		t.Fatalf("valid floating IP rejected: %v", err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			address := base
			mutate(&address)
			if err := validateUsableFloatingIP(address); err == nil {
				t.Fatalf("unusable floating IP accepted: %#v", address)
			}
		})
	}
}

func TestExistingWorkerDoesNotAdoptUnusableFloatingIP(t *testing.T) {
	for name, mutate := range map[string]func(*sdk.FloatingIP){
		"disabled":   func(address *sdk.FloatingIP) { address.Enabled = false },
		"virtual":    func(address *sdk.FloatingIP) { address.IsVirtual = true },
		"wrong type": func(address *sdk.FloatingIP) { address.Type = "private" },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			request := testRequest()
			if _, err := adapter.CreateVM(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			mutate(&api.floatingIPs[0])
			api.operations = nil
			_, err := adapter.CreateVM(context.Background(), request)
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "unusable") {
				t.Fatalf("CreateVM() error = %v, want unusable floating-IP rejection", err)
			}
			if api.createCalls != 1 || api.deleteVMCalls != 0 || len(api.vms) != 1 || len(api.operations) != 0 {
				t.Fatalf("unusable FIP adoption mutated VM: POSTs=%d deletes=%d VMs=%#v operations=%v", api.createCalls, api.deleteVMCalls, api.vms, api.operations)
			}
		})
	}
}

func TestUnusableNewFloatingIPIsCleanedBeforeVMCreate(t *testing.T) {
	for name, mutate := range map[string]func(*sdk.FloatingIP){
		"disabled":   func(address *sdk.FloatingIP) { address.Enabled = false },
		"virtual":    func(address *sdk.FloatingIP) { address.IsVirtual = true },
		"wrong type": func(address *sdk.FloatingIP) { address.Type = "private" },
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{createFloatingIPHook: mutate}
			adapter, _ := New(api)
			_, err := adapter.CreateVM(context.Background(), testRequest())
			if err == nil || !strings.Contains(err.Error(), "created floating IP is unusable") {
				t.Fatalf("CreateVM() error = %v, want unusable new floating-IP rejection", err)
			}
			if api.createCalls != 0 || len(api.floatingIPs) != 0 || api.floatingIPCreateCalls != 1 {
				t.Fatalf("unusable new FIP reached VM create or leaked: VMPOSTs=%d FIPs=%#v FIPPOSTs=%d", api.createCalls, api.floatingIPs, api.floatingIPCreateCalls)
			}
		})
	}
}

func TestCreatedWorkerUnexpectedFirewallRollsBackAfterVMDeletion(t *testing.T) {
	extra := secureFirewall()
	extra.UUID = "44444444-4444-4444-8444-444444444444"
	api := &fakeAPI{
		firewalls:                     []sdk.Firewall{secureFirewall(), extra},
		attachCreatedVMToFirewallUUID: extra.UUID,
	}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "attached exactly once to intended firewall") {
		t.Fatalf("CreateVM() error = %v, want unexpected-firewall rejection", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.deleteVMCalls != 1 {
		t.Fatalf("unexpected-firewall rollback leaked resources: VMs=%#v FIPs=%#v deletes=%d", api.vms, api.floatingIPs, api.deleteVMCalls)
	}
	for _, firewall := range api.firewalls {
		if firewallHasVM(firewall, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("deleted VM retained firewall assignment: %#v", api.firewalls)
		}
	}
	deleteIndex, detachIndex := -1, -1
	for index, operation := range api.operations {
		if operation == "delete-vm" {
			deleteIndex = index
		}
		if operation == "unassign-firewall" && detachIndex == -1 {
			detachIndex = index
		}
	}
	if deleteIndex < 0 || detachIndex <= deleteIndex {
		t.Fatalf("firewall was not retained until VM deletion: %v", api.operations)
	}
}

func TestPostAssignmentSecondFirewallAuditRollsBackNewWorker(t *testing.T) {
	extra := secureFirewall()
	extra.UUID = "44444444-4444-4444-8444-444444444444"
	api := &fakeAPI{
		firewalls:                  []sdk.Firewall{secureFirewall(), extra},
		secondFirewallOnAssignUUID: extra.UUID,
	}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "attached exactly once to intended firewall") {
		t.Fatalf("CreateVM() error = %v, want post-assignment firewall audit rejection", err)
	}
	if api.firewallAssignCalls != 1 || api.floatingIPAssignCalls != 0 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("post-assignment drift was not safely rolled back: firewallAssigns=%d floatingAssigns=%d VMs=%#v FIPs=%#v", api.firewallAssignCalls, api.floatingIPAssignCalls, api.vms, api.floatingIPs)
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("firewall assignment leaked after rollback: %#v", api.firewalls)
		}
	}
}

func TestExistingWorkerSecondFirewallFailsClosedWithoutDeletion(t *testing.T) {
	extra := secureFirewall()
	extra.UUID = "44444444-4444-4444-8444-444444444444"
	api := &fakeAPI{firewalls: []sdk.Firewall{secureFirewall(), extra}}
	adapter, _ := New(api)
	request := testRequest()
	created, err := adapter.CreateVM(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	api.firewalls[1].ResourcesAssigned = append(api.firewalls[1].ResourcesAssigned, sdk.FirewallResource{ResourceType: "vm", ResourceUUID: created.UUID})
	api.operations = nil
	_, err = adapter.CreateVM(context.Background(), request)
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "attached exactly once to intended firewall") {
		t.Fatalf("CreateVM() error = %v, want second-firewall rejection", err)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.deleteVMCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("existing second-firewall drift caused mutation: VMs=%#v FIPs=%#v deletes=%d operations=%v", api.vms, api.floatingIPs, api.deleteVMCalls, api.operations)
	}
}

func TestCreateRetriesTransientNetworkReadbackErrors(t *testing.T) {
	for name, transientErr := range map[string]error{
		"service unavailable": &sdk.APIError{StatusCode: 503, Retryable: true},
		"request deadline":    context.DeadlineExceeded,
		"transport":           errors.New("connection reset while reading response"),
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{networkErrors: map[int]error{2: transientErr}}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, 250*time.Millisecond)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			if created.UUID == "" || api.createCalls != 1 || api.networkGetCalls < 3 {
				t.Fatalf("created VM = %#v, POSTs = %d, network reads = %d", created, api.createCalls, api.networkGetCalls)
			}
			if slicesContain(api.operations, "delete-vm") {
				t.Fatalf("transient read caused rollback: %v", api.operations)
			}
		})
	}
}

func TestCreateDoesNotRetryNonRetryableNetworkReadbackError(t *testing.T) {
	api := &fakeAPI{networkErrors: map[int]error{2: &sdk.APIError{StatusCode: 403}}}
	adapter, _ := New(api)
	started := time.Now()
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "getting worker network") {
		t.Fatalf("CreateVM() error = %v, want terminal network read error", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("terminal read error took %s, want no retry delay", elapsed)
	}
	if api.networkGetCalls != 2 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("terminal read was retried or leaked resources: reads=%d VMs=%#v FIPs=%#v", api.networkGetCalls, api.vms, api.floatingIPs)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("terminal VPC read reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateRejectsMalformedNetworkMembershipReadback(t *testing.T) {
	const vmUUID = "11111111-1111-4111-8111-111111111111"
	for name, api := range map[string]*fakeAPI{
		"nil network": {networkNilOnCalls: map[int]bool{2: true}},
		"duplicate membership": {network: &sdk.Network{
			UUID: "network-1", Subnet: "10.0.0.0/24", VMUUIDs: []string{vmUUID, vmUUID},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, _ := New(api)
			_, err := adapter.CreateVM(context.Background(), testRequest())
			if err == nil {
				t.Fatal("expected malformed network read-back rejection")
			}
			if api.createCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("malformed read-back leaked launch: POSTs=%d VMs=%#v FIPs=%#v", api.createCalls, api.vms, api.floatingIPs)
			}
			if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
				t.Fatalf("malformed VPC proof reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
			}
		})
	}
}

func TestCreateCleansVMWhenNetworkAttachmentNeverAppears(t *testing.T) {
	api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil || !strings.Contains(err.Error(), "attachment to network") {
		t.Fatalf("CreateVM() error = %v, want missing network attachment", err)
	}
	if api.createCalls != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("failed network attachment leaked resources: POSTs=%d VMs=%#v FIPs=%#v", api.createCalls, api.vms, api.floatingIPs)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("protection mutated before VPC proof: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateCancellationStopsVPCWaitAndUsesDetachedCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}}
	api.networkGetHook = func(call int) {
		if call == 2 {
			cancel()
		}
	}
	adapter, _ := New(api)
	started := time.Now()
	_, err := adapter.CreateVM(ctx, testRequest())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateVM() error = %v, want context cancellation", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("cancellation took %s, want prompt return after detached cleanup", elapsed)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.deleteVMCalls != 1 {
		t.Fatalf("canceled launch was not cleaned: VMs=%#v FIPs=%#v deleteVMCalls=%d", api.vms, api.floatingIPs, api.deleteVMCalls)
	}
	if api.deleteVMContextCanceled || api.deleteFloatingIPContextCanceled {
		t.Fatal("cleanup inherited the canceled reconciliation context")
	}
}

func TestCreateCallerDeadlineFailsClosed(t *testing.T) {
	api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}}
	adapter, _ := New(api)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := adapter.CreateVM(ctx, testRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CreateVM() error = %v, want caller deadline", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.deleteVMCalls != 1 {
		t.Fatalf("deadline launch was not cleaned: VMs=%#v FIPs=%#v deleteVMCalls=%d", api.vms, api.floatingIPs, api.deleteVMCalls)
	}
}

func TestCreateRejectsNetworkUUIDReadbackMismatchBeforeMutation(t *testing.T) {
	api := &fakeAPI{network: &sdk.Network{UUID: "other-network", Subnet: "10.0.0.0/24"}}
	adapter, _ := New(api)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil || !strings.Contains(err.Error(), "read-back UUID") {
		t.Fatalf("CreateVM() error = %v, want mismatched network read-back", err)
	}
	if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("network mismatch mutated cloud state: floatingIPCreates=%d VMPOSTs=%d operations=%v", api.floatingIPCreateCalls, api.createCalls, api.operations)
	}
}

func TestCreatedWorkerRejectsServiceCIDROverlapAppearingDuringNetworkReadback(t *testing.T) {
	api := &fakeAPI{}
	api.networkGetHook = func(call int) {
		if call == 2 {
			api.network = &sdk.Network{
				UUID:    "network-1",
				Subnet:  "10.43.0.0/16",
				VMUUIDs: []string{"11111111-1111-4111-8111-111111111111"},
			}
		}
	}
	adapter, _ := New(api)
	_, err := adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "must not overlap Kubernetes Service CIDR 10.43.0.0/16") {
		t.Fatalf("CreateVM() error = %v, want Service-CIDR overlap during readback", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || api.createCalls != 1 || api.deleteVMCalls != 1 {
		t.Fatalf("readback overlap rollback leaked resources: VMs=%#v FIPs=%#v POSTs=%d deletes=%d", api.vms, api.floatingIPs, api.createCalls, api.deleteVMCalls)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("readback overlap reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateRejectsImpossibleControlPlaneVIPBeforeMutation(t *testing.T) {
	for name, vip := range map[string]string{
		"public":          "203.0.113.10",
		"pod CIDR":        "10.42.0.10",
		"Service CIDR":    "10.43.0.10",
		"outside network": "10.1.0.10",
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			request := testRequest()
			request.ControlPlaneVIP = vip
			_, err := adapter.CreateVM(context.Background(), request)
			if err == nil {
				t.Fatalf("CreateVM() accepted impossible control-plane VIP %q", vip)
			}
			if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("impossible VIP reached mutation: floatingIPPOSTs=%d VMPOSTs=%d firewall=%d floatingIP=%d operations=%v", api.floatingIPCreateCalls, api.createCalls, api.firewallAssignCalls, api.floatingIPAssignCalls, api.operations)
			}
		})
	}
}

func TestCreateRejectsNonEmptyMismatchedVMNetwork(t *testing.T) {
	api := &fakeAPI{createdNetworkUUID: "other-network"}
	adapter, _ := New(api)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("CreateVM() error = %v, want wrong-network rejection", err)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("wrong-network VM leaked resources: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
	if api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
		t.Fatalf("wrong-network response reached protection mutation: firewall=%d floatingIP=%d", api.firewallAssignCalls, api.floatingIPAssignCalls)
	}
}

func TestCreateRefusesToAdoptOwnedVMFromAnotherNetwork(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	api.floatingIPs = nil
	api.operations = nil
	api.vms[0].NetworkUUID = "other-network"
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil || !strings.Contains(err.Error(), "persisted launch identity differs") {
		t.Fatalf("CreateVM() error = %v, want wrong-network adoption refusal", err)
	}
	if api.createCalls != 1 || len(api.vms) != 1 || api.floatingIPCreateCalls != 1 || len(api.operations) != 0 {
		t.Fatalf("wrong-network adoption mutated resources: VMPOSTs=%d floatingIPPOSTs=%d VMs=%#v operations=%v", api.createCalls, api.floatingIPCreateCalls, api.vms, api.operations)
	}
}

func TestCreateDoesNotReplaceMissingFloatingIPForOwnedVM(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.floatingIPs = nil
	api.operations = nil
	if _, err := adapter.CreateVM(context.Background(), request); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("CreateVM() error = %v, want missing recorded floating IP", err)
	}
	if api.floatingIPCreateCalls != 1 || api.createCalls != 1 || len(api.vms) != 1 || len(api.operations) != 0 {
		t.Fatalf("missing adoption anchor caused mutation: floatingIPPOSTs=%d VMPOSTs=%d VMs=%#v operations=%v", api.floatingIPCreateCalls, api.createCalls, api.vms, api.operations)
	}
}

func TestCreateDoesNotDestroyAdoptedVMWhenVPCAttachmentIsTemporarilyAbsent(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	request := testRequest()
	if _, err := adapter.CreateVM(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	api.network = &sdk.Network{UUID: request.NetworkUUID, Subnet: "10.0.0.0/24"}
	api.operations = nil
	configureFastNetworkReadback(adapter, 60*time.Millisecond)
	if _, err := adapter.CreateVM(context.Background(), request); err == nil || !strings.Contains(err.Error(), "attachment to network") {
		t.Fatalf("CreateVM() error = %v, want temporary missing membership", err)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.deleteVMCalls != 0 || slicesContain(api.operations, "delete-vm") {
		t.Fatalf("adoption verification destroyed owned resources: VMs=%#v FIPs=%#v operations=%v", api.vms, api.floatingIPs, api.operations)
	}
}

func TestCreateNeverRetriesAmbiguousUncommittedPOST(t *testing.T) {
	api := &fakeAPI{createErr: errors.New("connection reset")}
	adapter, _ := New(api)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err == nil {
		t.Fatal("expected create error")
	}
	if api.createCalls != 1 {
		t.Fatalf("expected exactly one POST, got %d", api.createCalls)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("ambiguous create must preserve its unassigned ownership anchor: %#v", api.floatingIPs)
	}
}

func TestGetListDeleteAreOwnershipBound(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "other-cluster"); !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
		t.Fatalf("GetVM error = %v", err)
	}
	if got, err := adapter.ListVMs(context.Background(), "bkk01", "other-cluster"); err != nil || len(got) != 0 {
		t.Fatalf("ListVMs = %#v, %v", got, err)
	}
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "other-nodeclaim"); !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
		t.Fatalf("DeleteVM error = %v", err)
	}
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a"); err != nil {
		t.Fatal(err)
	}
	if len(api.floatingIPs) != 0 {
		t.Fatalf("floating IP leaked after delete: %#v", api.floatingIPs)
	}
	wantOrder := []string{"unassign-floating-ip", "delete-floating-ip", "delete-vm", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOrder) {
		t.Fatalf("unsafe deletion order %v, want %v", api.operations, wantOrder)
	}
}

func TestListVMsUsesCanonicalDetailsWhenListDescriptionsAreSparse(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.omitVMListDescriptions = true
	getCallsBefore := api.vmGetCalls
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].UUID != created.UUID || listed[0].SpecHash != "spec-a" {
		t.Fatalf("ListVMs() = %#v, want one canonically owned worker", listed)
	}
	if api.vmGetCalls-getCallsBefore != 1 {
		t.Fatalf("ListVMs canonical detail GET delta=%d, want one", api.vmGetCalls-getCallsBefore)
	}
}

func TestListVMsWaitsForCanonicalKarpenterOwnershipToConverge(t *testing.T) {
	tests := map[string]func(string) string{
		"empty": func(string) string { return "" },
		"truncated": func(description string) string {
			return description[:len(description)/2]
		},
		"valid JSON with missing field": func(description string) string {
			var record ownership
			if err := json.Unmarshal([]byte(description), &record); err != nil {
				t.Fatalf("decode ownership fixture: %v", err)
			}
			record.NetworkUUID = ""
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatalf("encode ownership fixture: %v", err)
			}
			return string(encoded)
		},
	}
	for name, makeIncomplete := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			incompleteDescription := makeIncomplete(api.vms[0].Description)
			remainingIncompleteReads := 1
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == created.UUID && remainingIncompleteReads > 0 {
					remainingIncompleteReads--
					vm.Description = incompleteDescription
				}
			}
			getCallsBefore := api.vmGetCalls
			listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 || listed[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, want worker after ownership convergence", listed)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("ListVMs canonical detail GET delta=%d, want incomplete then complete", delta)
			}
		})
	}
}

func TestListVMsRetriesTransientCanonicalReadUncertaintyForOwnedSummary(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"retryable GET": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 503, Retryable: true}}
			api.getVMHook = func(string) {
				api.mu.Lock()
				delete(api.getVMErrorByUUID, uuid)
				api.mu.Unlock()
			}
		},
		"nil detail": func(api *fakeAPI, uuid string) {
			api.nilGetVMUUID = uuid
			api.getVMHook = func(string) {
				api.mu.Lock()
				api.nilGetVMUUID = ""
				api.mu.Unlock()
			}
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			inject(api, created.UUID)
			getCallsBefore := api.vmGetCalls
			listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 || listed[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, want worker after transient canonical read uncertainty", listed)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("ListVMs canonical detail GET delta=%d, want uncertain then complete", delta)
			}
		})
	}
}

func TestListVMsBoundsIncompleteCanonicalKarpenterOwnership(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.mutateGetVMResponse = func(vm *sdk.VM) {
		if vm.UUID == created.UUID {
			vm.Description = ""
		}
	}
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	adapter.protectionAuditTimeout = boundedReadbackTestTimeout
	getCallsBefore := api.vmGetCalls
	operationsBefore := append([]string(nil), api.operations...)
	_, err = adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListVMs() error = %v, want bounded incomplete Karpenter ownership failure", err)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta < 2 {
		t.Fatalf("ListVMs canonical detail GET delta=%d, want bounded retries", delta)
	}
	if !reflect.DeepEqual(api.operations, operationsBefore) || api.deleteVMCalls != 0 {
		t.Fatalf("read-only ownership convergence mutated cloud resources: before=%v after=%v deletes=%d", operationsBefore, api.operations, api.deleteVMCalls)
	}
}

func TestListVMsIgnoresDefinitivelyForeignDescriptions(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = append(api.vms,
		sdk.VM{UUID: "55555555-5555-4555-8555-555555555555", Name: "other-cluster-partial", Description: `{"schema":"karpenter.inspace.cloud/v1","cluster":"other-cluster"}`},
		sdk.VM{UUID: "66666666-6666-4666-8666-666666666666", Name: "foreign-note", Description: "notes mention karpenter.inspace.cloud/v1 but this VM is manual"},
		sdk.VM{UUID: "77777777-7777-4777-8777-777777777777", Name: "foreign-plain", Description: "managed manually"},
		sdk.VM{UUID: "88888888-8888-4888-8888-888888888888", Name: "foreign-malformed", Description: "{not-json"},
		sdk.VM{UUID: "99999999-9999-4999-8999-999999999999", Name: "foreign-json", Description: `{"schema":"foreign.example/v1"}`},
	)
	getCallsBefore := api.vmGetCalls
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].UUID != created.UUID {
		t.Fatalf("ListVMs() = %#v, want foreign descriptions ignored", listed)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta != 6 {
		t.Fatalf("ListVMs canonical detail GET delta=%d, want one read per row", delta)
	}
}

func TestListVMsIgnoresExplicitForeignV1RecordsBeforeLaunchSemantics(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	var base ownership
	if err := json.Unmarshal([]byte(api.vms[0].Description), &base); err != nil {
		t.Fatal(err)
	}
	base.Cluster = "other-cluster"
	tests := []struct {
		uuid   string
		mutate func(*ownership)
	}{
		{uuid: "55555555-5555-4555-8555-555555555555", mutate: func(record *ownership) { record.HostClass = "future-host" }},
		{uuid: "66666666-6666-4666-8666-666666666666", mutate: func(record *ownership) { record.InstanceType = "future-shape" }},
		{uuid: "77777777-7777-4777-8777-777777777777", mutate: func(record *ownership) { record.HostPoolUUID = "future-pool" }},
		{uuid: "88888888-8888-4888-8888-888888888888", mutate: func(record *ownership) { record.VCPU++ }},
		{uuid: "99999999-9999-4999-8999-999999999999", mutate: func(record *ownership) { record.MemoryGiB++ }},
	}
	for _, test := range tests {
		record := base
		test.mutate(&record)
		description, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		api.vms = append(api.vms, sdk.VM{UUID: test.uuid, Name: "foreign-worker", Description: string(description)})
	}
	getCallsBefore := api.vmGetCalls
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].UUID != created.UUID {
		t.Fatalf("ListVMs() = %#v, want only target-cluster worker", listed)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta != len(tests)+1 {
		t.Fatalf("ListVMs canonical GET delta=%d, want one read per row", delta)
	}
}

func TestListVMsIgnoresCanonicalDriftBetweenExplicitForeignV1Records(t *testing.T) {
	tests := map[string]func(*ownership){
		"ownership fields": func(record *ownership) {
			record.SpecHash = "foreign-reconciled-spec"
			record.HostPoolUUID = "foreign-future-pool"
			record.VCPU++
		},
		"foreign cluster": func(record *ownership) {
			record.Cluster = "another-foreign-cluster"
		},
	}
	for name, mutateCanonical := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			foreignVM := api.vms[0]
			foreignVM.UUID = "99999999-9999-4999-8999-999999999999"
			foreignVM.Name = "foreign-worker"
			var listedRecord ownership
			if err := json.Unmarshal([]byte(foreignVM.Description), &listedRecord); err != nil {
				t.Fatal(err)
			}
			listedRecord.Cluster = "foreign-cluster"
			listedDescription, err := json.Marshal(listedRecord)
			if err != nil {
				t.Fatal(err)
			}
			foreignVM.Description = string(listedDescription)
			api.vms = append(api.vms, foreignVM)

			canonicalRecord := listedRecord
			mutateCanonical(&canonicalRecord)
			canonicalDescription, err := json.Marshal(canonicalRecord)
			if err != nil {
				t.Fatal(err)
			}
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == foreignVM.UUID {
					vm.Description = string(canonicalDescription)
				}
			}
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 || listed[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, want only target-cluster worker", listed)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("ListVMs canonical GET delta=%d, want one read per row", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("foreign inventory audit mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestListVMsKeepsAmbiguousTargetOwnershipSticky(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 40*time.Millisecond)
	adapter.protectionAuditTimeout = 40 * time.Millisecond
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	var foreign ownership
	if err := json.Unmarshal([]byte(api.vms[0].Description), &foreign); err != nil {
		t.Fatal(err)
	}
	foreign.Cluster = "other-cluster"
	foreign.HostClass = "future-host"
	foreignDescription, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	foreignUUID := "99999999-9999-4999-8999-999999999999"
	api.vms = append(api.vms, sdk.VM{
		UUID: foreignUUID, Name: "ambiguous-worker",
		Description: `{"schema":"karpenter.inspace.cloud/v1","cluster":""}`,
	})
	api.mutateGetVMResponse = func(vm *sdk.VM) {
		if vm.UUID == foreignUUID {
			vm.Description = string(foreignDescription)
		}
	}
	api.operations = nil
	getCallsBefore := api.vmGetCalls
	_, err = adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListVMs() error = %v, want sticky target ownership uncertainty", err)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta < 3 {
		t.Fatalf("ListVMs ambiguous target GET delta=%d, want bounded retries", delta)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("ambiguous target audit mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
	}
}

func TestListVMsRejectsUnsupportedReservedOwnershipSchema(t *testing.T) {
	t.Run("list summary", func(t *testing.T) {
		api := &fakeAPI{vms: []sdk.VM{{
			UUID: "77777777-7777-4777-8777-777777777777", Name: "future-owned",
			Description: `{"schema":"karpenter.inspace.cloud/v2","cluster":"cluster-a"}`,
		}}}
		adapter, _ := New(api)
		_, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), `unsupported Karpenter ownership schema "karpenter.inspace.cloud/v2"`) {
			t.Fatalf("ListVMs() error = %v, want unsupported reserved list schema rejection", err)
		}
		if api.vmGetCalls != 0 || len(api.operations) != 0 {
			t.Fatalf("unsupported list schema reached canonical read or mutation: GETs=%d operations=%v", api.vmGetCalls, api.operations)
		}
	})

	t.Run("foreign cluster", func(t *testing.T) {
		api := &fakeAPI{vms: []sdk.VM{{
			UUID: "77777777-7777-4777-8777-777777777777", Name: "future-owned",
			Description: `{"schema":"karpenter.inspace.cloud/v2","cluster":"other-cluster"}`,
		}}}
		adapter, _ := New(api)
		_, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), `unsupported Karpenter ownership schema "karpenter.inspace.cloud/v2"`) {
			t.Fatalf("ListVMs() error = %v, want global unsupported reserved schema rejection", err)
		}
		if api.vmGetCalls != 0 || len(api.operations) != 0 {
			t.Fatalf("unsupported foreign schema reached canonical read or mutation: GETs=%d operations=%v", api.vmGetCalls, api.operations)
		}
	})

	t.Run("canonical detail", func(t *testing.T) {
		api := &fakeAPI{}
		adapter, _ := New(api)
		created, err := adapter.CreateVM(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}
		api.mutateGetVMResponse = func(vm *sdk.VM) {
			if vm.UUID == created.UUID {
				vm.Description = strings.Replace(vm.Description, ownershipSchema, ownershipSchemaNamespace+"v2", 1)
			}
		}
		getCallsBefore := api.vmGetCalls
		operationsBefore := append([]string(nil), api.operations...)
		_, err = adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
		if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), `unsupported Karpenter ownership schema "karpenter.inspace.cloud/v2"`) {
			t.Fatalf("ListVMs() error = %v, want unsupported reserved canonical schema rejection", err)
		}
		if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
			t.Fatalf("unsupported canonical schema GET delta=%d, want immediate rejection", delta)
		}
		if !reflect.DeepEqual(api.operations, operationsBefore) || api.deleteVMCalls != 0 {
			t.Fatalf("unsupported canonical schema mutated resources: before=%v after=%v deletes=%d", operationsBefore, api.operations, api.deleteVMCalls)
		}
	})
}

func TestInspectOwnershipDescriptionClassifiesSchemaBeforeTypedRecordFields(t *testing.T) {
	for name, description := range map[string]string{
		"unsupported schema before incompatible cluster": `{"schema":"karpenter.inspace.cloud/v2","cluster":123}`,
		"unsupported schema after incompatible fields":   `{"cluster":[],"nodeClaim":{},"schema":"karpenter.inspace.cloud/future"}`,
		"unsupported foreign-cluster record":             `{"schema":"karpenter.inspace.cloud/v99","cluster":"other-cluster","rootDiskGiB":"large"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, managed, complete, err := inspectOwnershipDescription(description, "cluster-a")
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "unsupported Karpenter ownership schema") {
				t.Fatalf("inspectOwnershipDescription() managed=%t complete=%t err=%v, want unsupported reserved schema rejection", managed, complete, err)
			}
		})
	}

	t.Run("foreign namespace remains unmanaged", func(t *testing.T) {
		record, managed, complete, err := inspectOwnershipDescription(`{"schema":"foreign.example/v1","cluster":123,"nodeClaim":[]}`, "cluster-a")
		if err != nil || managed || complete || record != (ownership{}) {
			t.Fatalf("inspectOwnershipDescription() = %#v, %t, %t, %v; want unmanaged foreign schema", record, managed, complete, err)
		}
	})

	t.Run("valid v1 with incompatible field stays managed and incomplete", func(t *testing.T) {
		record, managed, complete, err := inspectOwnershipDescription(`{"schema":"karpenter.inspace.cloud/v1","cluster":"cluster-a","nodeClaim":[]}`, "cluster-a")
		if err != nil || !managed || complete || record.Schema != ownershipSchema || record.Cluster != "cluster-a" {
			t.Fatalf("inspectOwnershipDescription() = %#v, %t, %t, %v; want sticky incomplete v1 target evidence", record, managed, complete, err)
		}
	})

	t.Run("truncated v1 target remains sticky", func(t *testing.T) {
		record, managed, complete, err := inspectOwnershipDescription(`{"schema":"karpenter.inspace.cloud/v1","cluster":"cluster-a"`, "cluster-a")
		if err != nil || !managed || complete || record.Cluster != "cluster-a" {
			t.Fatalf("inspectOwnershipDescription() = %#v, %t, %t, %v; want sticky truncated v1 target evidence", record, managed, complete, err)
		}
	})
}

func TestListVMsRejectsManagedListAndCanonicalOwnershipDisagreement(t *testing.T) {
	tests := map[string]struct {
		mutate func(*ownership)
		want   string
	}{
		"cluster": {
			mutate: func(record *ownership) { record.Cluster = "other-cluster" },
			want:   "differs from list cluster",
		},
		"same-cluster field": {
			mutate: func(record *ownership) { record.SpecHash = "other-spec" },
			want:   "differs from its complete list record",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			var canonicalRecord ownership
			if err := json.Unmarshal([]byte(api.vms[0].Description), &canonicalRecord); err != nil {
				t.Fatalf("decode ownership fixture: %v", err)
			}
			test.mutate(&canonicalRecord)
			encoded, err := json.Marshal(canonicalRecord)
			if err != nil {
				t.Fatalf("encode ownership fixture: %v", err)
			}
			canonicalDescription := string(encoded)
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID != created.UUID {
					return
				}
				vm.Description = canonicalDescription
			}
			getCallsBefore := api.vmGetCalls
			_, err = adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ListVMs() error = %v, want managed list/detail ownership disagreement", err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
				t.Fatalf("managed ownership conflict GET delta=%d, want immediate failure", delta)
			}
			if api.deleteVMCalls != 0 {
				t.Fatalf("read-only ownership disagreement deleted a VM: %d", api.deleteVMCalls)
			}
		})
	}
}

func TestListVMsCanonicalizesForeignInventoryInParallelWithoutNameCoupling(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 24; index++ {
		name := "foreign-duplicate"
		if index == 0 {
			name = ""
		}
		api.vms = append(api.vms, sdk.VM{
			UUID: fmt.Sprintf("%08d-2222-4333-8444-555555555555", index+100),
			Name: name, Description: "foreign", Status: "running",
		})
	}
	api.omitVMListDescriptions = true
	var concurrencyMu sync.Mutex
	activeReads, maxReads := 0, 0
	api.getVMHook = func(string) {
		concurrencyMu.Lock()
		activeReads++
		if activeReads > maxReads {
			maxReads = activeReads
		}
		concurrencyMu.Unlock()
		time.Sleep(5 * time.Millisecond)
		concurrencyMu.Lock()
		activeReads--
		concurrencyMu.Unlock()
	}
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].UUID != created.UUID {
		t.Fatalf("ListVMs() = %#v, want only the canonical owned worker", listed)
	}
	if maxReads < 2 || maxReads > canonicalVMReadConcurrency {
		t.Fatalf("canonical detail concurrency=%d, want 2..%d", maxReads, canonicalVMReadConcurrency)
	}
}

func TestListVMsSkipsStaleNotFoundRowButRejectsNilCanonicalDetail(t *testing.T) {
	for name, nilResponse := range map[string]bool{"stale not found": false, "nil response": true} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			foreignUUID := "99999999-9999-4999-8999-999999999999"
			api.vms = append(api.vms, sdk.VM{UUID: foreignUUID, Name: "foreign"})
			if nilResponse {
				api.nilGetVMUUID = foreignUUID
			} else {
				api.getVMErrorByUUID = map[string]error{foreignUUID: &sdk.APIError{StatusCode: 404}}
			}
			listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			if nilResponse {
				if !errors.Is(err, cloudapi.ErrOwnershipMismatch) {
					t.Fatalf("ListVMs() error = %v, want nil-detail rejection", err)
				}
				return
			}
			if err != nil || len(listed) != 1 || listed[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, %v, want stale foreign row skipped", listed, err)
			}
		})
	}
}

func TestListVMsRejectsForeignCanonicalReadErrorOrIdentityMismatch(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"non-not-found error": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 503, Retryable: true}}
		},
		"UUID mismatch": func(api *fakeAPI, uuid string) {
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == uuid {
					vm.UUID = "88888888-8888-4888-8888-888888888888"
				}
			}
		},
		"name mismatch": func(api *fakeAPI, uuid string) {
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == uuid {
					vm.Name = "changed"
				}
			}
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			if _, err := adapter.CreateVM(context.Background(), testRequest()); err != nil {
				t.Fatal(err)
			}
			foreignUUID := "99999999-9999-4999-8999-999999999999"
			api.vms = append(api.vms, sdk.VM{UUID: foreignUUID, Name: "foreign"})
			inject(api, foreignUUID)
			if _, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); err == nil {
				t.Fatal("ListVMs() accepted uncertain canonical foreign detail")
			}
			if api.deleteVMCalls != 0 {
				t.Fatalf("read-only canonical failure deleted a VM: %d", api.deleteVMCalls)
			}
		})
	}
}

func TestEstablishedWorkerReadsFailClosedOnLaunchIdentityDrift(t *testing.T) {
	tests := map[string]func(*sdk.VM){
		"name":            func(vm *sdk.VM) { vm.Name = "other-nodeclaim" },
		"vCPU":            func(vm *sdk.VM) { vm.VCPU++ },
		"memory":          func(vm *sdk.VM) { vm.MemoryMiB += 1024 },
		"OS name":         func(vm *sdk.VM) { vm.OSName = "debian" },
		"OS version":      func(vm *sdk.VM) { vm.OSVersion = "22.04" },
		"host pool":       func(vm *sdk.VM) { vm.DesignatedPoolUUID = "other-pool" },
		"network":         func(vm *sdk.VM) { vm.NetworkUUID = "other-network" },
		"billing account": func(vm *sdk.VM) { vm.BillingAccountID++ },
		"root disk size":  func(vm *sdk.VM) { vm.Storage[0].SizeGiB++ },
		"second root disk": func(vm *sdk.VM) {
			vm.Storage = append(vm.Storage, sdk.VMStorage{SizeGiB: vm.Storage[0].SizeGiB, Primary: true})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			mutate(&api.vms[0])
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			if _, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "launch identity drift") {
				t.Fatalf("GetVM() error = %v, want established launch identity drift", err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
				t.Fatalf("GetVM conflict GET delta=%d, want immediate failure", delta)
			}
			getCallsBefore = api.vmGetCalls
			if _, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !strings.Contains(err.Error(), "launch identity drift") {
				t.Fatalf("ListVMs() error = %v, want established launch identity drift", err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
				t.Fatalf("ListVMs conflict GET delta=%d, want immediate failure", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("read-only launch drift audit mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestGetVMRetriesTransientEstablishedCanonicalReads(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"retryable service unavailable": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 503, Retryable: true}}
			api.getVMHook = func(string) {
				api.mu.Lock()
				delete(api.getVMErrorByUUID, uuid)
				api.mu.Unlock()
			}
		},
		"HTTP request timeout": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 408}}
			api.getVMHook = func(string) {
				api.mu.Lock()
				delete(api.getVMErrorByUUID, uuid)
				api.mu.Unlock()
			}
		},
		"transport failure": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: errors.New("connection reset while reading response")}
			api.getVMHook = func(string) {
				api.mu.Lock()
				delete(api.getVMErrorByUUID, uuid)
				api.mu.Unlock()
			}
		},
		"request context timeout": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: context.DeadlineExceeded}
			api.getVMHook = func(string) {
				api.mu.Lock()
				delete(api.getVMErrorByUUID, uuid)
				api.mu.Unlock()
			}
		},
		"empty detail": func(api *fakeAPI, uuid string) {
			api.nilGetVMUUID = uuid
			api.getVMHook = func(string) {
				api.mu.Lock()
				api.nilGetVMUUID = ""
				api.mu.Unlock()
			}
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			inject(api, created.UUID)
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			got, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
			if err != nil || got.UUID != created.UUID {
				t.Fatalf("GetVM() = %#v, %v, want worker after transient canonical read uncertainty", got, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("GetVM canonical GET delta=%d, want uncertain then complete", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("established read convergence mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestGetVMBoundsPersistentTransientEstablishedCanonicalReads(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"retryable service unavailable": func(api *fakeAPI, uuid string) {
			api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 503, Retryable: true}}
		},
		"empty detail": func(api *fakeAPI, uuid string) {
			api.nilGetVMUUID = uuid
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, 40*time.Millisecond)
			adapter.protectionAuditTimeout = 40 * time.Millisecond
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			inject(api, created.UUID)
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			_, err = adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("GetVM() error = %v, want bounded read-back deadline", err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta < 2 {
				t.Fatalf("GetVM canonical GET delta=%d, want bounded retries", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("bounded established read mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestGetVMRejectsDefinitiveEstablishedCanonicalReadFailuresImmediately(t *testing.T) {
	tests := map[string]struct {
		inject func(*fakeAPI, string)
		check  func(error) bool
	}{
		"not found": {
			inject: func(api *fakeAPI, uuid string) {
				api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 404}}
			},
			check: func(err error) bool { return errors.Is(err, cloudapi.ErrNotFound) },
		},
		"permanent API error": {
			inject: func(api *fakeAPI, uuid string) {
				api.getVMErrorByUUID = map[string]error{uuid: &sdk.APIError{StatusCode: 400, Message: "invalid UUID"}}
			},
			check: func(err error) bool {
				var apiErr *sdk.APIError
				return errors.As(err, &apiErr) && apiErr.StatusCode == 400
			},
		},
		"UUID conflict": {
			inject: func(api *fakeAPI, uuid string) {
				api.mutateGetVMResponse = func(vm *sdk.VM) {
					if vm.UUID == uuid {
						vm.UUID = "88888888-8888-4888-8888-888888888888"
					}
				}
			},
			check: func(err error) bool {
				return errors.Is(err, cloudapi.ErrOwnershipMismatch) && strings.Contains(err.Error(), "detail UUID")
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			test.inject(api, created.UUID)
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			_, err = adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
			if !test.check(err) {
				t.Fatalf("GetVM() error = %v, want definitive immediate failure", err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
				t.Fatalf("GetVM canonical GET delta=%d, want immediate failure", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("definitive established read failure mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestEstablishedWorkerReadsAllowOmittedNetworkUUIDWithExactNetworkMembership(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.mutateGetVMResponse = func(vm *sdk.VM) {
		if vm.UUID == created.UUID {
			vm.NetworkUUID = ""
		}
	}
	getCallsBefore := api.vmGetCalls
	if got, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); err != nil || got.UUID != created.UUID {
		t.Fatalf("GetVM() = %#v, %v, want established worker with network proven by membership", got, err)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
		t.Fatalf("GetVM network-omission GET delta=%d, want no convergence retry", delta)
	}
	getCallsBefore = api.vmGetCalls
	if got, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); err != nil || len(got) != 1 || got[0].UUID != created.UUID {
		t.Fatalf("ListVMs() = %#v, %v, want established worker with network proven by membership", got, err)
	}
	if delta := api.vmGetCalls - getCallsBefore; delta != 1 {
		t.Fatalf("ListVMs network-omission GET delta=%d, want no convergence retry", delta)
	}
	api.network = &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}
	api.operations = nil
	if _, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); err == nil || !strings.Contains(err.Error(), "network contains VM UUID 0 times") {
		t.Fatalf("GetVM() error = %v, want exact GetNetwork membership rejection", err)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("missing network membership audit mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
	}
}

func TestEstablishedWorkerReadsWaitForMissingLaunchFieldsToConverge(t *testing.T) {
	tests := map[string]func(*sdk.VM){
		"name":            func(vm *sdk.VM) { vm.Name = "" },
		"vCPU":            func(vm *sdk.VM) { vm.VCPU = 0 },
		"memory":          func(vm *sdk.VM) { vm.MemoryMiB = 0 },
		"OS name":         func(vm *sdk.VM) { vm.OSName = "" },
		"OS version":      func(vm *sdk.VM) { vm.OSVersion = "" },
		"host pool":       func(vm *sdk.VM) { vm.DesignatedPoolUUID = "" },
		"billing account": func(vm *sdk.VM) { vm.BillingAccountID = 0 },
		"root disk":       func(vm *sdk.VM) { vm.Storage = nil },
	}
	for name, omit := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			adapter.protectionAuditTimeout = boundedReadbackTestTimeout
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			remainingSparseReads := 1
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == created.UUID && remainingSparseReads > 0 {
					remainingSparseReads--
					omit(vm)
				}
			}
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			if got, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); err != nil || got.UUID != created.UUID {
				t.Fatalf("GetVM() = %#v, %v, want convergence", got, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("GetVM sparse launch GET delta=%d, want sparse then complete", delta)
			}
			remainingSparseReads = 1
			getCallsBefore = api.vmGetCalls
			if got, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); err != nil || len(got) != 1 || got[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, %v, want convergence", got, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("ListVMs sparse launch GET delta=%d, want sparse then complete", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("read convergence mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestEstablishedWorkerReadsBoundPermanentlyMissingLaunchFields(t *testing.T) {
	for _, operation := range []string{"get", "list"} {
		t.Run(operation, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, 40*time.Millisecond)
			adapter.protectionAuditTimeout = 40 * time.Millisecond
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			api.mutateGetVMResponse = func(vm *sdk.VM) { vm.OSVersion = "" }
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			if operation == "get" {
				_, err = adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
			} else {
				_, err = adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
			}
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s error = %v, want bounded incomplete launch identity", operation, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta < 2 {
				t.Fatalf("%s sparse launch GET delta=%d, want bounded retries", operation, delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("bounded read convergence mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestEstablishedWorkerReadsSupportDerivableLegacyV1LaunchIdentity(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	var record ownership
	if err := json.Unmarshal([]byte(api.vms[0].Description), &record); err != nil {
		t.Fatal(err)
	}
	record.HostPoolUUID = ""
	record.VCPU = 0
	record.MemoryGiB = 0
	legacyDescription, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	api.vms[0].Description = string(legacyDescription)
	if strings.Contains(api.vms[0].Description, `"hostPoolUUID"`) || strings.Contains(api.vms[0].Description, `"vCPU"`) || strings.Contains(api.vms[0].Description, `"memoryGiB"`) {
		t.Fatalf("legacy v1 fixture retained new exact identity fields: %s", api.vms[0].Description)
	}
	got, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
	if err != nil || got.VCPU != 2 || got.MemoryGiB != 4 {
		t.Fatalf("GetVM() = %#v, %v, want derivable legacy v1 worker", got, err)
	}
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil || len(listed) != 1 || listed[0].UUID != created.UUID {
		t.Fatalf("ListVMs() = %#v, %v, want derivable legacy v1 worker", listed, err)
	}
	operationsBefore := append([]string(nil), api.operations...)
	adopted, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil || adopted.UUID != created.UUID || api.createCalls != 1 {
		t.Fatalf("CreateVM() legacy adoption = %#v, %v, POSTs=%d; want existing worker", adopted, err, api.createCalls)
	}
	if !reflect.DeepEqual(api.operations, operationsBefore) {
		t.Fatalf("legacy v1 adoption mutated cloud state: before=%v after=%v", operationsBefore, api.operations)
	}
}

func TestEstablishedWorkerReadsTreatEveryPartialExactIdentityExtensionAsIncomplete(t *testing.T) {
	tests := map[string]func(*ownership){
		"host pool only":       func(record *ownership) { record.VCPU, record.MemoryGiB = 0, 0 },
		"vCPU only":            func(record *ownership) { record.HostPoolUUID, record.MemoryGiB = "", 0 },
		"memory only":          func(record *ownership) { record.HostPoolUUID, record.VCPU = "", 0 },
		"host pool and vCPU":   func(record *ownership) { record.MemoryGiB = 0 },
		"host pool and memory": func(record *ownership) { record.VCPU = 0 },
		"vCPU and memory":      func(record *ownership) { record.HostPoolUUID = "" },
	}
	for name, makePartial := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
			adapter.protectionAuditTimeout = boundedReadbackTestTimeout
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			var partial ownership
			if err := json.Unmarshal([]byte(api.vms[0].Description), &partial); err != nil {
				t.Fatal(err)
			}
			makePartial(&partial)
			partialDescription, err := json.Marshal(partial)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, complete, err := inspectOwnershipDescription(string(partialDescription), "cluster-a"); err != nil || complete {
				t.Fatalf("partial extension inspect complete=%t, err=%v; want incomplete", complete, err)
			}
			remainingPartialReads := 1
			api.mutateGetVMResponse = func(vm *sdk.VM) {
				if vm.UUID == created.UUID && remainingPartialReads > 0 {
					remainingPartialReads--
					vm.Description = string(partialDescription)
				}
			}
			api.operations = nil
			getCallsBefore := api.vmGetCalls
			if got, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); err != nil || got.UUID != created.UUID {
				t.Fatalf("GetVM() = %#v, %v, want extension convergence", got, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("GetVM partial extension GET delta=%d, want partial then complete", delta)
			}
			remainingPartialReads = 1
			getCallsBefore = api.vmGetCalls
			if got, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); err != nil || len(got) != 1 || got[0].UUID != created.UUID {
				t.Fatalf("ListVMs() = %#v, %v, want extension convergence", got, err)
			}
			if delta := api.vmGetCalls - getCallsBefore; delta != 2 {
				t.Fatalf("ListVMs partial extension GET delta=%d, want partial then complete", delta)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("partial extension convergence mutated cloud state: deletes=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestPartialExactIdentityExtensionRejectsPresentConflictsImmediately(t *testing.T) {
	tests := map[string]func(*ownership){
		"host pool": func(record *ownership) {
			record.HostPoolUUID, record.VCPU, record.MemoryGiB = "other-pool", 0, 0
		},
		"vCPU": func(record *ownership) {
			record.HostPoolUUID, record.VCPU, record.MemoryGiB = "", 4, 0
		},
		"memory": func(record *ownership) {
			record.HostPoolUUID, record.VCPU, record.MemoryGiB = "", 0, 8
		},
	}
	for name, conflict := range tests {
		t.Run(name, func(t *testing.T) {
			record := newOwnership(testRequest(), sdk.FloatingIP{
				Name: floatingIPName("cluster-a", "nodeclaim-a"), Address: "203.0.113.10", BillingAccountID: testRequest().BillingAccountID,
			})
			conflict(&record)
			if _, partial, err := normalizeOwnershipLaunchIdentity(record); err == nil || partial {
				t.Fatalf("normalizeOwnershipLaunchIdentity() partial=%t, err=%v; want immediate conflict", partial, err)
			}
		})
	}
}

func TestGetVMRequiresCompleteEstablishedOwnershipRecord(t *testing.T) {
	for _, field := range []string{"spec hash", "bootstrap hash"} {
		t.Run(field, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			configureFastNetworkReadback(adapter, 40*time.Millisecond)
			adapter.protectionAuditTimeout = 40 * time.Millisecond
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			var record ownership
			if err := json.Unmarshal([]byte(api.vms[0].Description), &record); err != nil {
				t.Fatal(err)
			}
			if field == "spec hash" {
				record.SpecHash = ""
			} else {
				record.BootstrapHash = ""
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			api.vms[0].Description = string(encoded)
			api.operations = nil
			_, err = adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
			if !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, errPersistedOwnershipIncomplete) {
				t.Fatalf("GetVM() error = %v, want incomplete full ownership rejection", err)
			}
			if len(api.operations) != 0 || api.deleteVMCalls != 0 {
				t.Fatalf("incomplete ownership read mutated cloud state: operations=%v deletes=%d", api.operations, api.deleteVMCalls)
			}
		})
	}
}

func TestEstablishedWorkerReadsFailClosedOnProtectionDrift(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"disabled floating IP": func(api *fakeAPI, _ string) {
			api.floatingIPs[0].Enabled = false
		},
		"lost floating IP": func(api *fakeAPI, _ string) {
			api.floatingIPs = nil
		},
		"private VIP collision": func(api *fakeAPI, _ string) {
			api.vms[0].PrivateIPv4 = "10.0.0.10"
		},
		"private Service VIP pool collision": func(api *fakeAPI, _ string) {
			api.vms[0].PrivateIPv4 = "10.0.0.200"
		},
		"VPC overlaps Kubernetes Service CIDR": func(api *fakeAPI, vmUUID string) {
			api.network = &sdk.Network{UUID: "network-1", Subnet: "10.43.0.0/16", VMUUIDs: []string{vmUUID}}
		},
		"second firewall": func(api *fakeAPI, vmUUID string) {
			extra := secureFirewall()
			extra.UUID = "44444444-4444-4444-8444-444444444444"
			extra.ResourcesAssigned = []sdk.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}}
			api.firewalls = append(api.firewalls, extra)
		},
		"public firewall rule": func(api *fakeAPI, _ string) {
			port := int32(22)
			api.firewalls[0].Rules = append(api.firewalls[0].Rules, sdk.FirewallRule{
				UUID: "public-ssh", Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port,
				EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"198.51.100.10/32"},
			})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			adapter, _ := New(api)
			created, err := adapter.CreateVM(context.Background(), testRequest())
			if err != nil {
				t.Fatal(err)
			}
			mutate(api, created.UUID)
			api.operations = nil
			if _, err := adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a"); err == nil || !strings.Contains(err.Error(), "protection drift") {
				t.Fatalf("GetVM() error = %v, want protection drift", err)
			}
			if _, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a"); err == nil || !strings.Contains(err.Error(), "protection drift") {
				t.Fatalf("ListVMs() error = %v, want protection drift", err)
			}
			if api.deleteVMCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("read-only drift audit mutated cloud state: delete calls=%d operations=%v", api.deleteVMCalls, api.operations)
			}
		})
	}
}

func TestEstablishedWorkerListProtectionAuditUsesOneSharedSnapshot(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	if _, err := adapter.CreateVM(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	api.networkGetCalls = 0
	api.firewallListCalls = 0
	api.floatingIPListCalls = 0
	listed, err := adapter.ListVMs(context.Background(), "bkk01", "cluster-a")
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListVMs() = %#v, %v", listed, err)
	}
	if api.networkGetCalls != 1 || api.firewallListCalls != 1 || api.floatingIPListCalls != 1 {
		t.Fatalf("protection snapshot API calls: networks=%d firewalls=%d floatingIPs=%d, want 1 each", api.networkGetCalls, api.firewallListCalls, api.floatingIPListCalls)
	}
}

func TestEstablishedWorkerProtectionAuditIsBounded(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.blockFirewallList = true
	adapter.protectionAuditTimeout = 20 * time.Millisecond
	started := time.Now()
	_, err = adapter.GetVM(context.Background(), "bkk01", created.UUID, "cluster-a")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetVM() error = %v, want bounded audit deadline", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("bounded protection audit took %s", elapsed)
	}
}

func TestValidateNodeClassChecksHostPool(t *testing.T) {
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: "pool-1"}}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "pool-1", "33333333-3333-4333-8333-333333333333"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "missing", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("expected missing pool error")
	}
}

func TestDeleteCleansNamedFloatingIPWhenVMAlreadyMissing(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil // simulate out-of-band VM disappearance
	api.operations = nil
	getCallsBefore, listCallsBefore := api.vmGetCalls, api.vmListCalls
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a"); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("DeleteVM error = %v", err)
	}
	if len(api.floatingIPs) != 0 {
		t.Fatalf("orphan floating IP was not cleaned: %#v", api.floatingIPs)
	}
	if api.vmGetCalls-getCallsBefore != 2 || api.vmListCalls-listCallsBefore != 2 {
		t.Fatalf("absence proof GET/List deltas=%d/%d, want two confirmations from both sources", api.vmGetCalls-getCallsBefore, api.vmListCalls-listCallsBefore)
	}
	wantOperations := []string{"unassign-floating-ip", "delete-floating-ip", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOperations) {
		t.Fatalf("persistent absence cleanup operations=%v, want %v", api.operations, wantOperations)
	}
}

func TestDeleteTransientNotFoundRecoversOwnedDetailBeforeNormalDelete(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.getVMErrorByUUID = map[string]error{created.UUID: &sdk.APIError{StatusCode: 404}}
	api.getVMHook = func(string) {
		api.mu.Lock()
		delete(api.getVMErrorByUUID, created.UUID)
		api.mu.Unlock()
	}
	api.operations = nil
	getCallsBefore, listCallsBefore := api.vmGetCalls, api.vmListCalls
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a"); err != nil {
		t.Fatal(err)
	}
	if api.vmGetCalls-getCallsBefore != 2 || api.vmListCalls-listCallsBefore != 1 {
		t.Fatalf("transient 404 recovery GET/List deltas=%d/%d, want 2/1", api.vmGetCalls-getCallsBefore, api.vmListCalls-listCallsBefore)
	}
	wantOperations := []string{"unassign-floating-ip", "delete-floating-ip", "delete-vm", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOperations) {
		t.Fatalf("transient 404 delete operations=%v, want normal delete %v", api.operations, wantOperations)
	}
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("normal delete after transient 404 did not clean resources: VMs=%#v FIPs=%#v firewall=%#v", api.vms, api.floatingIPs, api.firewalls[0])
	}
}

func TestDeletePersistentGetListDisagreementFailsWithoutMutation(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.getVMErrorByUUID = map[string]error{created.UUID: &sdk.APIError{StatusCode: 404}}
	api.operations = nil
	getCallsBefore, listCallsBefore := api.vmGetCalls, api.vmListCalls
	err = adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a")
	if !errors.Is(err, errVMAbsenceUncertain) || !errors.Is(err, cloudapi.ErrOwnershipMismatch) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DeleteVM() error = %v, want bounded Get/List absence uncertainty", err)
	}
	if api.vmGetCalls-getCallsBefore < 2 || api.vmListCalls-listCallsBefore < 2 {
		t.Fatalf("uncertain absence GET/List deltas=%d/%d, want bounded repeated reads", api.vmGetCalls-getCallsBefore, api.vmListCalls-listCallsBefore)
	}
	if api.deleteVMCalls != 0 || len(api.operations) != 0 || len(api.vms) != 1 || len(api.floatingIPs) != 1 || !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatalf("uncertain absence mutated resources: deletes=%d operations=%v VMs=%#v FIPs=%#v firewall=%#v", api.deleteVMCalls, api.operations, api.vms, api.floatingIPs, api.firewalls[0])
	}
}

func TestDeleteFailureLeavesFirewallAttached(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.operations = nil
	api.deleteVMErr = errors.New("temporary delete failure")
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a"); err == nil {
		t.Fatal("expected VM delete error")
	}
	for _, operation := range api.operations {
		if operation == "unassign-firewall" {
			t.Fatalf("firewall detached while VM delete failed: %v", api.operations)
		}
	}
	if !firewallHasVM(api.firewalls[0], created.UUID) {
		t.Fatal("firewall assignment was removed from live VM")
	}
}

func TestFirewallValidationRejectsPublicInbound(t *testing.T) {
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: "pool-1"}}, firewalls: []sdk.Firewall{{
		UUID:  "33333333-3333-4333-8333-333333333333",
		Rules: []sdk.FirewallRule{{Protocol: "tcp", Direction: "inbound", EndpointSpecType: "any"}},
	}}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "pool-1", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("expected public inbound firewall rejection")
	}
}

func TestNodeClassValidationRejectsVPCOverlappingFixedClusterCIDRs(t *testing.T) {
	for name, test := range map[string]struct {
		subnet string
		want   string
	}{
		"Cilium pod CIDR":         {subnet: "10.42.128.0/17", want: "must not overlap Cilium native-routing pod CIDR 10.42.0.0/16"},
		"Kubernetes Service CIDR": {subnet: "10.43.128.0/17", want: "must not overlap Kubernetes Service CIDR 10.43.0.0/16"},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: test.subnet}}
			adapter, _ := New(api)
			err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "pool-1", secureFirewall().UUID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("overlapping VPC validation error = %v, want %q", err, test.want)
			}
			if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("overlapping VPC reached cloud mutation: %#v", api)
			}
		})
	}
}

func TestNodeClassValidationRejectsUnusableSupervisorVIP(t *testing.T) {
	for name, test := range map[string]struct {
		subnet string
		vip    string
		want   string
	}{
		"network address":   {subnet: "10.0.0.0/24", vip: "10.0.0.0", want: "network address"},
		"broadcast address": {subnet: "10.0.0.0/24", vip: "10.0.0.255", want: "broadcast address"},
		"slash 31":          {subnet: "10.0.0.0/31", vip: "10.0.0.0", want: "unusable IPv4 subnet"},
		"slash 32":          {subnet: "10.0.0.10/32", vip: "10.0.0.10", want: "unusable IPv4 subnet"},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: test.subnet}}
			adapter, _ := New(api)
			err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", test.vip, "10.0.0.200", "10.0.0.219", "pool-1", secureFirewall().UUID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateNodeClass() error = %v, want %q", err, test.want)
			}
			if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 {
				t.Fatalf("unusable VIP reached mutation: %#v", api)
			}
		})
	}

	api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/27"}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.1", "10.0.0.2", "10.0.0.17", "pool-1", secureFirewall().UUID); err != nil {
		t.Fatalf("usable /27 supervisor VIP and minimum Service pool rejected: %v", err)
	}
}

func TestNodeClassValidationRequiresExactServicePoolInsideUsableVPCHosts(t *testing.T) {
	for name, test := range map[string]struct {
		subnet string
		vip    string
		start  string
		stop   string
		want   string
	}{
		"outside VPC":        {subnet: "10.0.0.0/24", vip: "10.0.0.10", start: "10.0.1.16", stop: "10.0.1.31", want: "must be inside subnet"},
		"network address":    {subnet: "10.0.0.0/24", vip: "10.0.0.200", start: "10.0.0.0", stop: "10.0.0.15", want: "network address"},
		"broadcast address":  {subnet: "10.0.0.0/24", vip: "10.0.0.10", start: "10.0.0.240", stop: "10.0.0.255", want: "broadcast address"},
		"supervisor overlap": {subnet: "10.0.0.0/24", vip: "10.0.0.10", start: "10.0.0.1", stop: "10.0.0.16", want: "contains private RKE2 supervisor VIP"},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: test.subnet}}
			adapter, _ := New(api)
			err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", test.vip, test.start, test.stop, "pool-1", secureFirewall().UUID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateNodeClass() error = %v, want %q", err, test.want)
			}
			if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
				t.Fatalf("invalid Service pool reached mutation: %#v", api)
			}
		})
	}

	api := &fakeAPI{network: &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "pool-1", secureFirewall().UUID); err != nil {
		t.Fatalf("usable exact Service pool rejected: %v", err)
	}
}

func TestFirewallValidationRejectsUnsupportedProtocol(t *testing.T) {
	firewall := secureFirewall()
	firewall.Rules = append(firewall.Rules, sdk.FirewallRule{
		UUID: "out-gre", Protocol: "gre", Direction: "outbound", EndpointSpecType: "any",
	})
	err := validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), `unsupported rule protocol "gre"`) {
		t.Fatalf("unsupported protocol validation error = %v", err)
	}
}

func TestFirewallValidationRejectsEveryPublicInboundPrefix(t *testing.T) {
	for _, prefix := range []string{"198.51.100.24/32", "198.51.100.0/24", "2001:db8::1/128"} {
		firewall := secureFirewall()
		start, end := int32(22), int32(22)
		firewall.Rules = append(firewall.Rules, sdk.FirewallRule{
			UUID: "public-ssh", Protocol: "tcp", Direction: "inbound", PortStart: &start, PortEnd: &end,
			EndpointSpecType: "ip_prefixes", EndpointSpec: []string{prefix},
		})
		err := validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24"))
		if err == nil || !strings.Contains(err.Error(), "must not allow public inbound prefix") {
			t.Fatalf("public prefix %s validation error = %v", prefix, err)
		}
	}
}

func TestFirewallValidationRequiresEveryNativeRoutingProtocol(t *testing.T) {
	network := netip.MustParsePrefix("10.0.0.0/24")
	type testCase struct {
		name   string
		mutate func(*sdk.Firewall)
		want   string
	}
	tests := []testCase{{name: "complete firewall"}}
	for i, protocol := range []string{"TCP", "UDP", "ICMP"} {
		ruleIndex := i
		protocol := protocol
		tests = append(tests,
			testCase{
				name: "missing VPC " + protocol,
				mutate: func(firewall *sdk.Firewall) {
					firewall.Rules[ruleIndex].EndpointSpec = []string{bootstrap.NativeRoutingPodCIDR}
				},
				want: "all inbound " + protocol + " traffic from network subnet 10.0.0.0/24",
			},
			testCase{
				name: "missing pod " + protocol,
				mutate: func(firewall *sdk.Firewall) {
					firewall.Rules[ruleIndex].EndpointSpec = []string{"10.0.0.0/24"}
				},
				want: "all inbound " + protocol + " traffic from Cilium native-routing pod CIDR 10.42.0.0/16",
			},
			testCase{
				name: "missing any-destination " + protocol + " egress",
				mutate: func(firewall *sdk.Firewall) {
					firewall.Rules[ruleIndex+3].EndpointSpecType = "ip_prefixes"
					firewall.Rules[ruleIndex+3].EndpointSpec = []string{"10.0.0.0/8"}
				},
				want: "all outbound " + protocol + " traffic to any endpoint for public-IP egress",
			},
		)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firewall := secureFirewall()
			if test.mutate != nil {
				test.mutate(&firewall)
			}
			err := validateDefaultDenyFirewall(firewall, network)
			if test.want == "" {
				if err != nil {
					t.Fatalf("complete native-routing firewall rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestFirewallValidationAcceptsCompleteSplitPrefixCoverage(t *testing.T) {
	firewall := secureFirewall()
	for i := 0; i < 3; i++ {
		firewall.Rules[i].EndpointSpec = []string{
			"10.0.0.0/25", "10.0.0.128/25",
			"10.42.0.0/17", "10.42.128.0/17",
		}
	}
	if err := validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24")); err != nil {
		t.Fatalf("complete split-prefix coverage rejected: %v", err)
	}

	firewall.Rules[1].EndpointSpec = []string{
		"10.0.0.0/25", "10.0.0.128/25",
		"10.42.0.0/17", "10.42.192.0/18",
	}
	err := validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "all inbound UDP traffic from Cilium native-routing pod CIDR") {
		t.Fatalf("gapped split-prefix coverage error = %v", err)
	}
}

func TestFirewallValidationRequiresPortlessICMP(t *testing.T) {
	start, end := int32(1), int32(65535)
	firewall := secureFirewall()
	firewall.Rules[2].PortStart = &start
	firewall.Rules[2].PortEnd = &end
	err := validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "all inbound ICMP traffic from network subnet") {
		t.Fatalf("ICMP ingress with synthetic port range error = %v", err)
	}

	firewall = secureFirewall()
	firewall.Rules[5].PortStart = &start
	firewall.Rules[5].PortEnd = &end
	err = validateDefaultDenyFirewall(firewall, netip.MustParsePrefix("10.0.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "all outbound ICMP traffic to any endpoint") {
		t.Fatalf("ICMP egress with synthetic port range error = %v", err)
	}
}

func TestCreateRejectsExactVPCOnlyFirewallBeforeMutation(t *testing.T) {
	firewall := secureFirewall()
	for i := range firewall.Rules {
		if firewall.Rules[i].Direction == "inbound" {
			firewall.Rules[i].EndpointSpec = []string{"10.0.0.0/24"}
		}
	}
	original := firewall
	original.Rules = append([]sdk.FirewallRule(nil), firewall.Rules...)
	for i := range original.Rules {
		original.Rules[i].EndpointSpec = append([]string(nil), original.Rules[i].EndpointSpec...)
	}
	api := &fakeAPI{firewalls: []sdk.Firewall{firewall}}
	adapter, err := newAdapter(api, func() (string, error) { return validGeneratedTestPassword, nil })
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.CreateVM(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "Cilium native-routing pod CIDR 10.42.0.0/16") {
		t.Fatalf("CreateVM error = %v, want exact-VPC-only firewall rejection", err)
	}
	if api.floatingIPCreateCalls != 0 || api.createCalls != 0 || api.firewallAssignCalls != 0 || api.floatingIPAssignCalls != 0 || len(api.operations) != 0 {
		t.Fatalf("invalid firewall reached cloud mutation: floatingIPPOSTs=%d VMPOSTs=%d firewallAssignments=%d floatingIPAssignments=%d operations=%v",
			api.floatingIPCreateCalls, api.createCalls, api.firewallAssignCalls, api.floatingIPAssignCalls, api.operations)
	}
	if !reflect.DeepEqual(original, api.firewalls[0]) {
		t.Fatalf("provider mutated user firewall rules: before=%#v after=%#v", original, api.firewalls[0])
	}
}

func testRequest() cloudapi.CreateVMRequest {
	return cloudapi.CreateVMRequest{
		IdempotencyKey: "uid-a", Name: "nodeclaim-a", ClusterName: "cluster-a", NodeClaimName: "nodeclaim-a",
		BillingAccountID: 1,
		Location:         "bkk01", NetworkUUID: "network-1", OSName: "ubuntu", OSVersion: "24.04",
		ControlPlaneVIP:              "10.0.0.10",
		PrivateLoadBalancerPoolStart: "10.0.0.200",
		PrivateLoadBalancerPoolStop:  "10.0.0.219",
		FirewallUUID:                 "33333333-3333-4333-8333-333333333333",
		HostPoolUUID:                 inspacev1.IntelScalableHostPoolUUID, HostClass: inspacev1.HostClassIntelScalable, InstanceType: "is-general-2c-4g",
		VCPU: 2, MemoryGiB: 4, RootDiskGiB: 40, CloudInitJSON: `{"write_files":[{"path":"/etc/rancher/rke2/config.yaml","encoding":"b64","content":"bm9kZS1leHRlcm5hbC1pcDogX19JTlNQQUNFX0ZMT0FUSU5HX0lQVjRfXw=="},{"path":"/usr/local/sbin/inspace-detect-private-ip","encoding":"b64","content":"X19JTlNQQUNFX1ZQQ19TVUJORVRfXw=="}],"runcmd":[]}`,
		PublicIPv4: true,
		SpecHash:   "spec-a", BootstrapHash: "bootstrap-a",
	}
}

func testPrivateLoadBalancerPool() inspacev1.PrivateLoadBalancerPool {
	return inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"}
}

const validAdapterTestPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test@example"
const validGeneratedTestPassword = "Aa1!xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

func decodedSDKCloudInit(t *testing.T, data string) string {
	t.Helper()
	var doc struct {
		WriteFiles []struct {
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("decode cloud-init JSON: %v", err)
	}
	var decoded strings.Builder
	for _, file := range doc.WriteFiles {
		if file.Encoding != "b64" {
			t.Fatalf("write_files encoding = %q, want b64", file.Encoding)
		}
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			t.Fatalf("decode write_files content: %v", err)
		}
		decoded.Write(content)
	}
	return decoded.String()
}

func configureFastNetworkReadback(adapter *Adapter, timeout time.Duration) {
	adapter.networkAttachmentReadbackTimeout = timeout
	adapter.networkAttachmentRequestTimeout = timeout
	adapter.networkAttachmentReadbackMinDelay = 5 * time.Millisecond
	adapter.networkAttachmentReadbackMaxDelay = 10 * time.Millisecond
}

func slicesContain(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type fakeAPI struct {
	mu                              sync.Mutex
	vms                             []sdk.VM
	pools                           []sdk.HostPool
	firewalls                       []sdk.Firewall
	createErr                       error
	commitOnCreateError             bool
	sparseCreateResponse            bool
	persistDescription              func(string) string
	mutateGetVMResponse             func(*sdk.VM)
	omitVMListDescriptions          bool
	getVMErrorByUUID                map[string]error
	nilGetVMUUID                    string
	getVMHook                       func(string)
	createCalls                     int
	floatingIPs                     []sdk.FloatingIP
	lastVMRequest                   sdk.CreateVMRequest
	operations                      []string
	deleteVMErr                     error
	network                         *sdk.Network
	networkGetCalls                 int
	networkMembershipAfter          int
	createdNetworkUUID              string
	createdPrivateIPv4              string
	attachCreatedVMToFirewallUUID   string
	secondFirewallOnAssignUUID      string
	privateIPv4VisibleAfter         int
	vmGetCalls                      int
	vmListCalls                     int
	firewallListCalls               int
	blockFirewallList               bool
	floatingIPListCalls             int
	networkErrors                   map[int]error
	networkNilOnCalls               map[int]bool
	networkGetHook                  func(int)
	floatingIPCreateCalls           int
	createFloatingIPHook            func(*sdk.FloatingIP)
	floatingIPAssignCalls           int
	firewallAssignCalls             int
	deleteVMCalls                   int
	deleteVMContextCanceled         bool
	deleteFloatingIPContextCanceled bool
}

func (f *fakeAPI) ListHostPools(context.Context, string) ([]sdk.HostPool, error) {
	if f.pools == nil {
		f.pools = []sdk.HostPool{{UUID: inspacev1.IntelScalableHostPoolUUID}, {UUID: "pool-1"}}
	}
	return append([]sdk.HostPool(nil), f.pools...), nil
}
func (f *fakeAPI) GetNetwork(context.Context, string, string) (*sdk.Network, error) {
	f.networkGetCalls++
	if f.networkGetHook != nil {
		f.networkGetHook(f.networkGetCalls)
	}
	if err := f.networkErrors[f.networkGetCalls]; err != nil {
		return nil, err
	}
	if f.networkNilOnCalls[f.networkGetCalls] {
		return nil, nil
	}
	if f.network != nil {
		copy := *f.network
		copy.VMUUIDs = append([]string(nil), f.network.VMUUIDs...)
		return &copy, nil
	}
	network := &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}
	if f.networkGetCalls > f.networkMembershipAfter {
		for _, vm := range f.vms {
			network.VMUUIDs = append(network.VMUUIDs, vm.UUID)
		}
	}
	return network, nil
}
func (f *fakeAPI) ListFirewalls(ctx context.Context, _ string) ([]sdk.Firewall, error) {
	f.firewallListCalls++
	if f.blockFirewallList {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.firewalls == nil {
		f.firewalls = []sdk.Firewall{secureFirewall()}
	}
	return append([]sdk.Firewall(nil), f.firewalls...), nil
}
func (f *fakeAPI) AssignFirewallToVM(_ context.Context, _ string, firewallUUID, vmUUID string) error {
	f.firewallAssignCalls++
	if f.firewalls == nil {
		f.firewalls = []sdk.Firewall{secureFirewall()}
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID == firewallUUID {
			f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, sdk.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
			if f.secondFirewallOnAssignUUID != "" {
				for j := range f.firewalls {
					if f.firewalls[j].UUID == f.secondFirewallOnAssignUUID {
						f.firewalls[j].ResourcesAssigned = append(f.firewalls[j].ResourcesAssigned, sdk.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
					}
				}
			}
			return nil
		}
	}
	return errors.New("firewall not found")
}
func (f *fakeAPI) UnassignFirewallFromVM(_ context.Context, _ string, firewallUUID, vmUUID string) error {
	f.operations = append(f.operations, "unassign-firewall")
	if f.firewalls == nil {
		return nil
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID != firewallUUID {
			continue
		}
		for j := range f.firewalls[i].ResourcesAssigned {
			if f.firewalls[i].ResourcesAssigned[j].ResourceUUID == vmUUID {
				f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned[:j], f.firewalls[i].ResourcesAssigned[j+1:]...)
				return nil
			}
		}
		return nil
	}
	return errors.New("firewall not found")
}
func (f *fakeAPI) ListFloatingIPs(_ context.Context, _ string, filters *sdk.FloatingIPFilters) ([]sdk.FloatingIP, error) {
	f.floatingIPListCalls++
	var result []sdk.FloatingIP
	for _, address := range f.floatingIPs {
		if filters == nil || filters.BillingAccountID == 0 || address.BillingAccountID == filters.BillingAccountID {
			result = append(result, address)
		}
	}
	return result, nil
}
func (f *fakeAPI) CreateFloatingIP(_ context.Context, _ string, request sdk.CreateFloatingIPRequest) (*sdk.FloatingIP, error) {
	f.floatingIPCreateCalls++
	address := sdk.FloatingIP{Name: request.Name, Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true, Type: "public"}
	if f.createFloatingIPHook != nil {
		f.createFloatingIPHook(&address)
	}
	f.floatingIPs = append(f.floatingIPs, address)
	return &address, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _ string, address, uuid, resourceType string) (*sdk.FloatingIP, error) {
	f.floatingIPAssignCalls++
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = uuid
			f.floatingIPs[i].AssignedToResourceType = resourceType
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return nil, errors.New("floating IP not found")
}
func (f *fakeAPI) UnassignFloatingIP(_ context.Context, _ string, address string) (*sdk.FloatingIP, error) {
	f.operations = append(f.operations, "unassign-floating-ip")
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return nil, &sdk.APIError{StatusCode: 404}
}
func (f *fakeAPI) DeleteFloatingIP(ctx context.Context, _ string, address string) error {
	if ctx.Err() != nil {
		f.deleteFloatingIPContextCanceled = true
	}
	f.operations = append(f.operations, "delete-floating-ip")
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs = append(f.floatingIPs[:i], f.floatingIPs[i+1:]...)
			return nil
		}
	}
	return &sdk.APIError{StatusCode: 404}
}
func (f *fakeAPI) ListVMs(context.Context, string) ([]sdk.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vmListCalls++
	items := append([]sdk.VM(nil), f.vms...)
	if f.omitVMListDescriptions {
		for i := range items {
			items[i].Description = ""
		}
	}
	return items, nil
}

func secureFirewall() sdk.Firewall {
	return sdk.Firewall{
		UUID: "33333333-3333-4333-8333-333333333333",
		Rules: []sdk.FirewallRule{{
			UUID: "in-vpc-pods-tcp", Protocol: "tcp", Direction: "inbound",
			EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/24", bootstrap.NativeRoutingPodCIDR},
		}, {UUID: "in-vpc-pods-udp", Protocol: "udp", Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/24", bootstrap.NativeRoutingPodCIDR}},
			{UUID: "in-vpc-pods-icmp", Protocol: "icmp", Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/24", bootstrap.NativeRoutingPodCIDR}},
			{UUID: "out-tcp", Protocol: "tcp", Direction: "outbound", EndpointSpecType: "any"},
			{UUID: "out-udp", Protocol: "udp", Direction: "outbound", EndpointSpecType: "any"},
			{UUID: "out-icmp", Protocol: "icmp", Direction: "outbound", EndpointSpecType: "any"}},
	}
}
func (f *fakeAPI) GetVM(_ context.Context, _, uuid string) (*sdk.VM, error) {
	f.mu.Lock()
	f.vmGetCalls++
	injected := f.getVMErrorByUUID[uuid]
	returnNil := f.nilGetVMUUID == uuid
	mutate := f.mutateGetVMResponse
	hook := f.getVMHook
	var found *sdk.VM
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			copy := f.vms[i]
			if f.vmGetCalls <= f.privateIPv4VisibleAfter {
				copy.PrivateIPv4 = ""
			}
			found = &copy
			break
		}
	}
	f.mu.Unlock()
	if hook != nil {
		hook(uuid)
	}
	if injected != nil {
		return nil, injected
	}
	if returnNil {
		return nil, nil
	}
	if found == nil {
		return nil, &sdk.APIError{StatusCode: 404}
	}
	if mutate != nil {
		mutate(found)
	}
	return found, nil
}
func (f *fakeAPI) CreateVM(_ context.Context, _ string, request sdk.CreateVMRequest) (*sdk.VM, error) {
	f.createCalls++
	f.lastVMRequest = request
	vm := sdk.VM{
		UUID: "11111111-1111-4111-8111-111111111111", Name: request.Name, Description: request.Description,
		Status: "provisioning", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB, OSName: request.OSName,
		OSVersion: request.OSVersion, DesignatedPoolUUID: request.DesignatedPoolUUID, NetworkUUID: request.NetworkUUID,
		BillingAccountID: request.BillingAccountID,
		Storage:          []sdk.VMStorage{{SizeGiB: request.DiskGiB, Primary: true}},
	}
	vm.PrivateIPv4 = f.createdPrivateIPv4
	if vm.PrivateIPv4 == "" {
		vm.PrivateIPv4 = "10.0.0.20"
	}
	if f.createdNetworkUUID != "" {
		vm.NetworkUUID = f.createdNetworkUUID
	}
	if f.createErr == nil || f.commitOnCreateError {
		persisted := vm
		if f.persistDescription != nil {
			persisted.Description = f.persistDescription(persisted.Description)
		}
		f.vms = append(f.vms, persisted)
		if f.attachCreatedVMToFirewallUUID != "" {
			for i := range f.firewalls {
				if f.firewalls[i].UUID == f.attachCreatedVMToFirewallUUID {
					f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, sdk.FirewallResource{ResourceType: "vm", ResourceUUID: vm.UUID})
				}
			}
		}
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.sparseCreateResponse {
		return &sdk.VM{UUID: vm.UUID}, nil
	}
	return &vm, nil
}
func (f *fakeAPI) DeleteVM(ctx context.Context, _, uuid string) error {
	f.deleteVMCalls++
	if ctx.Err() != nil {
		f.deleteVMContextCanceled = true
	}
	f.operations = append(f.operations, "delete-vm")
	if f.deleteVMErr != nil {
		return f.deleteVMErr
	}
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			f.vms = append(f.vms[:i], f.vms[i+1:]...)
			return nil
		}
	}
	return &sdk.APIError{StatusCode: 404}
}
