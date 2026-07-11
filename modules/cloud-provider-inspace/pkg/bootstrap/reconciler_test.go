package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace/pkg/inspace"
)

func TestReconcileBuildsExactlyThreeProtectedControlPlaneVMs(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	var result Result
	var err error
	for i := 0; i < 20; i++ {
		result, err = reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
		if result.Ready {
			break
		}
	}
	if !result.Ready {
		t.Fatalf("result never became ready: %#v", result)
	}
	if len(api.vmCreates) != 3 || len(api.vms) != 3 {
		t.Fatalf("VM creates=%d VMs=%d, want exactly 3", len(api.vmCreates), len(api.vms))
	}
	if len(api.firewalls) != 1 || len(api.firewalls[0].Rules) != 6 || len(api.firewalls[0].ResourcesAssigned) != 3 {
		t.Fatalf("firewall = %#v", api.firewalls)
	}
	if len(api.floatingIPs) != 4 { // three nodes and one public API NLB
		t.Fatalf("floating IPs = %#v", api.floatingIPs)
	}
	if len(api.loadBalancers) != 1 || len(api.loadBalancers[0].Targets) != 3 || len(api.loadBalancers[0].ForwardingRules) != 1 {
		t.Fatalf("load balancer = %#v", api.loadBalancers)
	}
	if indexOf(api.events, "create-lb") < 0 || indexOf(api.events, "create-vm") < 0 || indexOf(api.events, "create-lb") > indexOf(api.events, "create-vm") {
		t.Fatalf("API load balancer must be allocated before cp0: events=%v", api.events)
	}
	for i, request := range api.vmCreates {
		if request.ReservePublicIP == nil || *request.ReservePublicIP {
			t.Errorf("VM %d requested an unnamed public IP", i)
		}
		if request.NetworkUUID != cluster.Spec.Network.UUID || request.OSName != "ubuntu" || request.OSVersion != "24.04" {
			t.Errorf("VM %d request = %#v", i, request)
		}
		assertCloudInitUsesPrivateNIC(t, request.CloudInit, i == 0)
	}
	if got := result.ControlPlaneEndpoint; got != "https://api.unit.example:6443" {
		t.Fatalf("control-plane endpoint = %q", got)
	}
	if !strings.HasPrefix(result.AllocatedEndpointIPv4, "203.0.113.") {
		t.Fatalf("allocated endpoint IPv4 = %q", result.AllocatedEndpointIPv4)
	}
	if result.PrivateControlPlaneEndpoint != "https://10.20.30.50:6443" || result.FirewallUUID == "" || result.APILoadBalancerUUID == "" || result.Owner == "" {
		t.Fatalf("result is missing E2E ownership/endpoints: %#v", result)
	}

	createsBefore := len(api.vmCreates)
	result, err = reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil || !result.Ready || len(api.vmCreates) != createsBefore {
		t.Fatalf("idempotent reconcile = %#v, %v, creates=%d", result, err, len(api.vmCreates))
	}
}

func TestReconcileInjectsGuardedSSHAndManagementAccess(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{
		API: api, SSHUsername: "inspacee2e",
		SSHPublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCTest unit@test",
		ManagementCIDR: "198.51.100.24/32", ManagementTCPPorts: []int{6443, 22, 30080},
	}
	if _, err := reconciler.Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	if len(api.vmCreates) != 1 {
		t.Fatalf("VM creates = %d", len(api.vmCreates))
	}
	request := api.vmCreates[0]
	if request.Username != "inspacee2e" || !strings.HasPrefix(request.PublicKey, "ssh-rsa ") {
		t.Fatalf("SSH create fields were not propagated: username=%q publicKeySet=%t", request.Username, request.PublicKey != "")
	}
	if len(api.firewalls) != 1 || len(api.firewalls[0].Rules) != 9 {
		t.Fatalf("guarded firewall rules = %#v", api.firewalls)
	}
	for _, expected := range []string{
		"ufw allow proto tcp from 198.51.100.24/32 to any port 22",
		"ufw allow proto tcp from 198.51.100.24/32 to any port 6443",
		"ufw allow proto tcp from 198.51.100.24/32 to any port 30080",
	} {
		if !decodedCloudInitScriptContains(t, request.CloudInit, expected) {
			t.Errorf("cloud-init lacks %q", expected)
		}
	}
}

func TestReconcileRejectsUnsafeManagementAccessAndCIDROverlap(t *testing.T) {
	for name, reconciler := range map[string]Reconciler{
		"broad public prefix":       {API: newFakeAPI(), ManagementCIDR: "198.51.100.0/24", ManagementTCPPorts: []int{22}},
		"private management source": {API: newFakeAPI(), ManagementCIDR: "10.20.30.4/32", ManagementTCPPorts: []int{22}},
		"port without source":       {API: newFakeAPI(), ManagementTCPPorts: []int{22}},
		"private key material":      {API: newFakeAPI(), SSHUsername: "root", SSHPublicKey: "-----BEGIN " + "OPENSSH PRIVATE KEY-----"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := reconciler.Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil {
				t.Fatal("expected access validation error")
			}
		})
	}

	api := newFakeAPI()
	api.network.Subnet = "10.42.10.0/24"
	if _, err := (&Reconciler{API: api}).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil || len(api.vms) != 0 {
		t.Fatalf("overlapping subnet error=%v VMs=%d", err, len(api.vms))
	}
}

func decodedCloudInitScriptContains(t *testing.T, raw, expected string) bool {
	t.Helper()
	var payload struct {
		WriteFiles []struct {
			Content string `json:"content"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || len(payload.WriteFiles) == 0 {
		t.Fatalf("decode cloud-init: %v", err)
	}
	script, err := base64.StdEncoding.DecodeString(payload.WriteFiles[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(script), expected)
}

func TestFirewallAssignmentFailureRollsBackNewVM(t *testing.T) {
	api := newFakeAPI()
	api.failFirewallAssignment = true
	reconciler := Reconciler{API: api}
	_, err := reconciler.Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("reconcile error=%v creates=%d deletes=%d VMs=%d", err, len(api.vmCreates), len(api.vmDeletes), len(api.vms))
	}
}

func TestDestroyRemovesOnlyOwnedInfrastructureInSafeOrder(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	for i := 0; i < 30; i++ {
		result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if err != nil {
			t.Fatal(err)
		}
		if result.Ready {
			break
		}
	}
	api.vms = append(api.vms, inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "unrelated", Status: "running"})

	var result DestroyResult
	for i := 0; i < 40; i++ {
		var err error
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.floatingIPs) != 0 || len(api.loadBalancers) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("destroy result=%#v fips=%d lbs=%d firewalls=%d", result, len(api.floatingIPs), len(api.loadBalancers), len(api.firewalls))
	}
	if len(api.vms) != 1 || api.vms[0].Name != "unrelated" {
		t.Fatalf("destroy touched unrelated VMs: %#v", api.vms)
	}
}

func TestDestroyRefusesUnexpectedFloatingIPAssignment(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	for i := range api.floatingIPs {
		if strings.HasSuffix(api.floatingIPs[i].Name, "cp-0-ip") {
			api.floatingIPs[i].AssignedTo = "99999999-1111-4222-8333-bbbbbbbbbbbb"
		}
	}
	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil {
		t.Fatal("expected ownership mismatch")
	}
	if len(api.vms) != 1 || len(api.floatingIPs) == 0 {
		t.Fatal("destroy mutated resources after ownership mismatch")
	}
}

func TestDestroyRefusesDeterministicVMNameWithoutOwnershipRecord(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	owner := ownerKey(cluster)
	api.vms = append(api.vms, inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb",
		Name: controlPlaneName(owner, 0), Description: "unrelated VM using a colliding name",
	})

	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil {
		t.Fatal("expected ownership mismatch")
	}
	if len(api.vmDeletes) != 0 || len(api.vms) != 1 {
		t.Fatalf("destroy mutated colliding VM: deletes=%v VMs=%#v", api.vmDeletes, api.vms)
	}
}

func TestDestroyRefusesUnexpectedControlPlaneSlot(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	owner := ownerKey(cluster)
	name := controlPlaneName(owner, ControlPlaneReplicas)
	api.vms = append(api.vms, inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: name,
		Description: fmt.Sprintf("inspace-k3s-cp/v1 owner=%s slot=%d spec=%064x", owner, ControlPlaneReplicas, 1),
	})

	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil {
		t.Fatal("expected unexpected-slot rejection")
	}
	if len(api.vmDeletes) != 0 {
		t.Fatalf("destroy deleted unexpected slot: %v", api.vmDeletes)
	}
}

func TestDestroyRefusesDeterministicFirewallNameWithoutOwnershipRecord(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	api.firewalls = append(api.firewalls, inspace.Firewall{
		UUID: "77777777-1111-4222-8333-444444444444", DisplayName: firewallName(ownerKey(cluster)),
		Description: "unrelated firewall using a colliding name",
	})

	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil {
		t.Fatal("expected firewall ownership mismatch")
	}
	if len(api.firewalls) != 1 {
		t.Fatalf("destroy mutated colliding firewall: %#v", api.firewalls)
	}
}

func TestRefusesDeterministicNameWithImmutableSpecDrift(t *testing.T) {
	api := newFakeAPI()
	reconciler := Reconciler{API: api}
	cluster := testCluster()
	for i := 0; i < 20; i++ {
		result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if err != nil {
			t.Fatal(err)
		}
		if result.Ready {
			break
		}
	}
	api.vms[0].VCPU++
	creates := len(api.vmCreates)
	_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != creates || len(api.vmDeletes) != 0 {
		t.Fatalf("drift reconcile error=%v creates=%d deletes=%d", err, len(api.vmCreates), len(api.vmDeletes))
	}
}

func TestRenderCloudInitRejectsFloatingVersion(t *testing.T) {
	_, err := RenderCloudInitJSON(CloudInitInput{NodeName: "cp-0", NodeExternalIPv4: "203.0.113.10", K3sToken: "token", PrivateSubnet: "10.0.0.0/24", K3sVersion: "latest", ClusterInit: true})
	if err == nil {
		t.Fatal("RenderCloudInitJSON() accepted an unpinned K3s version")
	}
}

func TestRenderCloudInitRejectsMissingOrPrivateExternalIP(t *testing.T) {
	for _, externalIP := range []string{"", "10.0.0.10", "not-an-address"} {
		_, err := RenderCloudInitJSON(CloudInitInput{
			NodeName: "cp-0", NodeExternalIPv4: externalIP, K3sToken: "token",
			PrivateSubnet: "10.0.0.0/24", K3sVersion: "v1.35.6+k3s1", ClusterInit: true,
		})
		if err == nil {
			t.Fatalf("RenderCloudInitJSON() accepted external IP %q", externalIP)
		}
	}
}

func assertCloudInitUsesPrivateNIC(t *testing.T, raw string, clusterInit bool) {
	t.Helper()
	var payload struct {
		WriteFiles []struct {
			Content string `json:"content"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || len(payload.WriteFiles) != 3 {
		t.Fatalf("cloud_init JSON = %q, %v", raw, err)
	}
	script, err := base64.StdEncoding.DecodeString(payload.WriteFiles[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{"apt-get update", "apt-get install -y --no-install-recommends ca-certificates curl iproute2 ufw", "find_private_ip", "ufw default deny incoming", "v1.35.6+k3s1"} {
		if !strings.Contains(text, required) {
			t.Errorf("cloud-init script is missing %q", required)
		}
	}
	if strings.Contains(text, "get.k3s.io") || !strings.Contains(text, "sha256sum-amd64.txt") {
		t.Error("K3s installer is not pinned to release binary plus checksum asset")
	}
	configBytes, err := base64.StdEncoding.DecodeString(payload.WriteFiles[1].Content)
	if err != nil {
		t.Fatal(err)
	}
	config := string(configBytes)
	for _, required := range []string{"node-ip: __PRIVATE_IP__", "advertise-address: __PRIVATE_IP__", "node-external-ip:", "flannel-iface: __PRIVATE_IFACE__", `"api.unit.example"`, `"10.20.30.50"`, `"203.0.113.10"`} {
		if !strings.Contains(config, required) {
			t.Errorf("K3s config is missing %q", required)
		}
	}
	if clusterInit != strings.Contains(config, "cluster-init: true") {
		t.Errorf("cluster-init content mismatch")
	}
}

func testCluster() *v1alpha1.InSpaceCluster {
	return &v1alpha1.InSpaceCluster{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.Kind,
		Metadata: v1alpha1.ObjectMeta{Name: "unit", Namespace: "default"},
		Spec: v1alpha1.InSpaceClusterSpec{
			Location: "bkk01", BillingAccountID: 42,
			CredentialsSecretRef: v1alpha1.SecretKeyReference{Name: "inspace-api", Key: "apikey"},
			ControlPlane: v1alpha1.ControlPlaneSpec{Replicas: 3, Machine: v1alpha1.MachineSpec{
				VCPU: 4, MemoryMiB: 8192, RootDiskGiB: 60,
				HostPoolUUID: "aac7dd66-f390-4edd-80c0-dd7cae49bd99",
				Image:        v1alpha1.ImageSpec{OSName: "ubuntu", OSVersion: "24.04"},
			}},
			K3s:      v1alpha1.K3sSpec{Version: "v1.35.6+k3s1", TokenSecretRef: v1alpha1.SecretKeyReference{Name: "k3s-token", Key: "token"}, Disable: []string{"servicelb"}},
			Network:  v1alpha1.NetworkSpec{UUID: "11111111-2222-4333-8444-555555555555", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16"},
			Firewall: v1alpha1.FirewallSpec{Managed: true}, PublicIPv4: v1alpha1.PublicIPv4Spec{Managed: true},
			Endpoint: v1alpha1.ControlPlaneEndpoint{Host: "api.unit.example", Port: 6443, Public: true},
		},
	}
}

type fakeAPI struct {
	network       inspace.Network
	vms           []inspace.VM
	firewalls     []inspace.Firewall
	floatingIPs   []inspace.FloatingIP
	loadBalancers []inspace.LoadBalancer
	vmCreates     []inspace.CreateVMRequest
	vmDeletes     []string

	failFirewallAssignment bool
	events                 []string
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{network: inspace.Network{UUID: "11111111-2222-4333-8444-555555555555", Name: "private", Type: "private", Subnet: "10.20.30.0/24"}}
}

func (f *fakeAPI) GetNetwork(context.Context, string, string) (*inspace.Network, error) {
	copy := f.network
	return &copy, nil
}
func (f *fakeAPI) ListVMs(context.Context, string) ([]inspace.VM, error) {
	return append([]inspace.VM(nil), f.vms...), nil
}
func (f *fakeAPI) CreateVM(_ context.Context, _ string, request inspace.CreateVMRequest) (*inspace.VM, error) {
	f.events = append(f.events, "create-vm")
	f.vmCreates = append(f.vmCreates, request)
	index := len(f.vmCreates)
	vm := inspace.VM{
		UUID: fmt.Sprintf("%08d-1111-4222-8333-bbbbbbbbbbbb", index), Name: request.Name, Description: request.Description,
		Hostname: request.Name, Status: "running", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB,
		OSName: request.OSName, OSVersion: request.OSVersion, PrivateIPv4: fmt.Sprintf("10.20.30.%d", index+10),
		NetworkUUID: request.NetworkUUID, BillingAccountID: request.BillingAccountID, DesignatedPoolUUID: request.DesignatedPoolUUID,
		Storage: []inspace.VMStorage{{UUID: fmt.Sprintf("%08d-9999-4222-8333-bbbbbbbbbbbb", index), Name: "vda", SizeGiB: request.DiskGiB, Primary: true}},
	}
	f.vms = append(f.vms, vm)
	f.network.VMUUIDs = append(f.network.VMUUIDs, vm.UUID)
	return &vm, nil
}
func (f *fakeAPI) DeleteVM(_ context.Context, _ string, uuid string) error {
	f.vmDeletes = append(f.vmDeletes, uuid)
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			f.vms = append(f.vms[:i], f.vms[i+1:]...)
			break
		}
	}
	for i := range f.network.VMUUIDs {
		if f.network.VMUUIDs[i] == uuid {
			f.network.VMUUIDs = append(f.network.VMUUIDs[:i], f.network.VMUUIDs[i+1:]...)
			break
		}
	}
	for i := range f.firewalls {
		kept := f.firewalls[i].ResourcesAssigned[:0]
		for _, resource := range f.firewalls[i].ResourcesAssigned {
			if resource.ResourceUUID != uuid {
				kept = append(kept, resource)
			}
		}
		f.firewalls[i].ResourcesAssigned = kept
	}
	return nil
}
func (f *fakeAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	return append([]inspace.Firewall(nil), f.firewalls...), nil
}
func (f *fakeAPI) CreateFirewall(_ context.Context, _ string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	f.events = append(f.events, "create-firewall")
	item := inspace.Firewall{
		UUID: "77777777-1111-4222-8333-444444444444", DisplayName: request.DisplayName,
		Description: request.Description, BillingAccountID: request.BillingAccountID, Rules: request.Rules,
	}
	f.firewalls = append(f.firewalls, item)
	return &item, nil
}
func (f *fakeAPI) AssignFirewallToVM(_ context.Context, _ string, firewallUUID, vmUUID string) error {
	if f.failFirewallAssignment {
		return errors.New("injected firewall failure")
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID == firewallUUID {
			for _, resource := range f.firewalls[i].ResourcesAssigned {
				if resource.ResourceUUID == vmUUID {
					return nil
				}
			}
			f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
		}
	}
	return nil
}
func (f *fakeAPI) DeleteFirewall(_ context.Context, _, uuid string) error {
	for i := range f.firewalls {
		if f.firewalls[i].UUID == uuid {
			f.firewalls = append(f.firewalls[:i], f.firewalls[i+1:]...)
			return nil
		}
	}
	return nil
}
func (f *fakeAPI) ListFloatingIPs(context.Context, string, *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error) {
	return append([]inspace.FloatingIP(nil), f.floatingIPs...), nil
}
func (f *fakeAPI) CreateFloatingIP(_ context.Context, _ string, request inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error) {
	f.events = append(f.events, "create-ip")
	item := inspace.FloatingIP{Name: request.Name, Address: fmt.Sprintf("203.0.113.%d", len(f.floatingIPs)+10), BillingAccountID: request.BillingAccountID}
	f.floatingIPs = append(f.floatingIPs, item)
	return &item, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _, address, resourceUUID, resourceType string) (*inspace.FloatingIP, error) {
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = resourceUUID
			f.floatingIPs[i].AssignedToResourceType = resourceType
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return nil, errors.New("floating IP not found")
}
func (f *fakeAPI) UnassignFloatingIP(_ context.Context, _, address string) (*inspace.FloatingIP, error) {
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "POST", Path: "/ip/unassign", Message: "not found"}
}
func (f *fakeAPI) DeleteFloatingIP(_ context.Context, _, address string) error {
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs = append(f.floatingIPs[:i], f.floatingIPs[i+1:]...)
			return nil
		}
	}
	return nil
}
func (f *fakeAPI) ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error) {
	return append([]inspace.LoadBalancer(nil), f.loadBalancers...), nil
}
func (f *fakeAPI) CreateLoadBalancer(_ context.Context, _ string, request inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error) {
	f.events = append(f.events, "create-lb")
	item := inspace.LoadBalancer{UUID: "88888888-1111-4222-8333-444444444444", DisplayName: request.DisplayName, NetworkUUID: request.NetworkUUID, PrivateAddress: "10.20.30.50", Targets: request.Targets, ForwardingRules: request.Rules}
	f.loadBalancers = append(f.loadBalancers, item)
	return &item, nil
}
func (f *fakeAPI) AddLoadBalancerTarget(_ context.Context, _, loadBalancerUUID, vmUUID string) (*inspace.LoadBalancerTarget, error) {
	for i := range f.loadBalancers {
		if f.loadBalancers[i].UUID == loadBalancerUUID {
			target := inspace.LoadBalancerTarget{TargetUUID: vmUUID, TargetType: "vm"}
			f.loadBalancers[i].Targets = append(f.loadBalancers[i].Targets, target)
			return &target, nil
		}
	}
	return nil, errors.New("load balancer not found")
}
func (f *fakeAPI) DeleteLoadBalancer(_ context.Context, _, uuid string) error {
	for i := range f.loadBalancers {
		if f.loadBalancers[i].UUID == uuid {
			f.loadBalancers = append(f.loadBalancers[:i], f.loadBalancers[i+1:]...)
			return nil
		}
	}
	return nil
}

var _ API = (*fakeAPI)(nil)

func indexOf(values []string, wanted string) int {
	for i, value := range values {
		if value == wanted {
			return i
		}
	}
	return -1
}
