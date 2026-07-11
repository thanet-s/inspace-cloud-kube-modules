package inspace

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/inspace"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestCreateIsReadBeforeCreateIdempotent(t *testing.T) {
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: "pool-1"}}}
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
	if !strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), "203.0.113.10") || strings.Contains(decodedSDKCloudInit(t, api.lastVMRequest.CloudInit), "__INSPACE_FLOATING_IPV4__") {
		t.Fatalf("VM cloud-init external IP was not resolved: %s", api.lastVMRequest.CloudInit)
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
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != first.UUID {
		t.Fatalf("expected one owned assigned floating IP, got %#v", api.floatingIPs)
	}
	if second.State != cloudapi.LifecyclePending {
		t.Fatalf("state = %q", second.State)
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

func TestValidateNodeClassChecksHostPool(t *testing.T) {
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: "pool-1"}}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "pool-1", "33333333-3333-4333-8333-333333333333"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "missing", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("expected missing pool error")
	}
}

func TestDeleteCleansNamedFloatingIPWhenVMAlreadyMissing(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil // simulate out-of-band VM disappearance
	if err := adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a"); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("DeleteVM error = %v", err)
	}
	if len(api.floatingIPs) != 0 {
		t.Fatalf("orphan floating IP was not cleaned: %#v", api.floatingIPs)
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
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "pool-1", "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("expected public inbound firewall rejection")
	}
}

func TestFirewallValidationAllowsHostScopedExplicitPublicPorts(t *testing.T) {
	firewall := secureFirewall()
	start, end := int32(30080), int32(30080)
	firewall.Rules = append(firewall.Rules, sdk.FirewallRule{
		UUID: "e2e-http", Protocol: "tcp", Direction: "inbound", PortStart: &start, PortEnd: &end,
		EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"198.51.100.24/32"},
	})
	api := &fakeAPI{pools: []sdk.HostPool{{UUID: "pool-1"}}, firewalls: []sdk.Firewall{firewall}}
	adapter, _ := New(api)
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "pool-1", firewall.UUID); err != nil {
		t.Fatalf("host-scoped explicit public port was rejected: %v", err)
	}

	firewall.Rules[len(firewall.Rules)-1].EndpointSpec = []string{"198.51.100.0/24"}
	api.firewalls = []sdk.Firewall{firewall}
	if err := adapter.ValidateNodeClass(context.Background(), "bkk01", "network-1", "pool-1", firewall.UUID); err == nil {
		t.Fatal("broad public prefix was accepted")
	}
}

func testRequest() cloudapi.CreateVMRequest {
	return cloudapi.CreateVMRequest{
		IdempotencyKey: "uid-a", Name: "nodeclaim-a", ClusterName: "cluster-a", NodeClaimName: "nodeclaim-a",
		BillingAccountID: 1,
		Location:         "bkk01", NetworkUUID: "network-1", OSName: "ubuntu", OSVersion: "24.04",
		FirewallUUID: "33333333-3333-4333-8333-333333333333",
		HostPoolUUID: "pool-1", HostClass: "intel-scalable", InstanceType: "is-general-2c-4g",
		VCPU: 2, MemoryGiB: 4, RootDiskGiB: 40, CloudInitJSON: `{"write_files":[{"path":"/etc/rancher/k3s/config.yaml","encoding":"b64","content":"bm9kZS1leHRlcm5hbC1pcDogX19JTlNQQUNFX0ZMT0FUSU5HX0lQVjRfXw=="}],"runcmd":[]}`,
		PublicIPv4: true,
		SpecHash:   "spec-a", BootstrapHash: "bootstrap-a",
	}
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

type fakeAPI struct {
	vms                 []sdk.VM
	pools               []sdk.HostPool
	firewalls           []sdk.Firewall
	createErr           error
	commitOnCreateError bool
	createCalls         int
	floatingIPs         []sdk.FloatingIP
	lastVMRequest       sdk.CreateVMRequest
	operations          []string
	deleteVMErr         error
}

func (f *fakeAPI) ListHostPools(context.Context, string) ([]sdk.HostPool, error) {
	if f.pools == nil {
		f.pools = []sdk.HostPool{{UUID: "pool-1"}}
	}
	return append([]sdk.HostPool(nil), f.pools...), nil
}
func (f *fakeAPI) GetNetwork(context.Context, string, string) (*sdk.Network, error) {
	return &sdk.Network{UUID: "network-1", Subnet: "10.0.0.0/24"}, nil
}
func (f *fakeAPI) ListFirewalls(context.Context, string) ([]sdk.Firewall, error) {
	if f.firewalls == nil {
		f.firewalls = []sdk.Firewall{secureFirewall()}
	}
	return append([]sdk.Firewall(nil), f.firewalls...), nil
}
func (f *fakeAPI) AssignFirewallToVM(_ context.Context, _ string, firewallUUID, vmUUID string) error {
	if f.firewalls == nil {
		f.firewalls = []sdk.Firewall{secureFirewall()}
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID == firewallUUID {
			f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, sdk.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
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
	var result []sdk.FloatingIP
	for _, address := range f.floatingIPs {
		if filters == nil || filters.BillingAccountID == 0 || address.BillingAccountID == filters.BillingAccountID {
			result = append(result, address)
		}
	}
	return result, nil
}
func (f *fakeAPI) CreateFloatingIP(_ context.Context, _ string, request sdk.CreateFloatingIPRequest) (*sdk.FloatingIP, error) {
	address := sdk.FloatingIP{Name: request.Name, Address: "203.0.113.10", BillingAccountID: request.BillingAccountID, Enabled: true}
	f.floatingIPs = append(f.floatingIPs, address)
	return &address, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _ string, address, uuid, resourceType string) (*sdk.FloatingIP, error) {
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
func (f *fakeAPI) DeleteFloatingIP(_ context.Context, _ string, address string) error {
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
	return append([]sdk.VM(nil), f.vms...), nil
}

func secureFirewall() sdk.Firewall {
	return sdk.Firewall{
		UUID: "33333333-3333-4333-8333-333333333333",
		Rules: []sdk.FirewallRule{{
			UUID: "rule-private", Protocol: "tcp", Direction: "inbound",
			EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		}, {UUID: "rule-private-udp", Protocol: "udp", Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.0.0.0/8"}},
			{UUID: "out-tcp", Protocol: "tcp", Direction: "outbound", EndpointSpecType: "any"},
			{UUID: "out-udp", Protocol: "udp", Direction: "outbound", EndpointSpecType: "any"}},
	}
}
func (f *fakeAPI) GetVM(_ context.Context, _, uuid string) (*sdk.VM, error) {
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			copy := f.vms[i]
			return &copy, nil
		}
	}
	return nil, &sdk.APIError{StatusCode: 404}
}
func (f *fakeAPI) CreateVM(_ context.Context, _ string, request sdk.CreateVMRequest) (*sdk.VM, error) {
	f.createCalls++
	f.lastVMRequest = request
	vm := sdk.VM{
		UUID: "11111111-1111-4111-8111-111111111111", Name: request.Name, Description: request.Description,
		Status: "provisioning", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB, OSName: request.OSName,
		OSVersion: request.OSVersion, DesignatedPoolUUID: request.DesignatedPoolUUID,
		Storage: []sdk.VMStorage{{SizeGiB: request.DiskGiB, Primary: true}},
	}
	if f.createErr == nil || f.commitOnCreateError {
		f.vms = append(f.vms, vm)
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &vm, nil
}
func (f *fakeAPI) DeleteVM(_ context.Context, _, uuid string) error {
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
