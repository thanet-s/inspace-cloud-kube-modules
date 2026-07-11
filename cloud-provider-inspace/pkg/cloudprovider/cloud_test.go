package cloudprovider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
)

const (
	testNetworkUUID = "11111111-2222-4333-8444-555555555555"
	testVMUUID      = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	testLBUUID      = "bbbbbbbb-2222-4333-8444-cccccccccccc"
)

func TestInstancesV2MetadataUsesCanonicalProviderID(t *testing.T) {
	api := &fakeAPI{vms: []inspace.VM{{
		UUID: testVMUUID, Name: "worker-0", Hostname: "worker-0", Status: "running",
		VCPU: 4, MemoryMiB: 8192, PrivateIPv4: "10.0.0.10",
	}}, floatingIPs: []inspace.FloatingIP{{Address: "203.0.113.10", AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine"}}}
	provider := newTestProvider(t, api)
	metadata, err := provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ProviderID != "inspace://bkk01/"+testVMUUID {
		t.Fatalf("ProviderID = %q", metadata.ProviderID)
	}
	if metadata.Zone != "bkk01" || metadata.Region != "thailand" || len(metadata.NodeAddresses) != 3 {
		t.Fatalf("metadata = %#v", metadata)
	}

	exists, err := provider.InstanceExists(context.Background(), &corev1.Node{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/99999999-1111-4222-8333-444444444444"}})
	if err != nil || exists {
		t.Fatalf("InstanceExists() = %v, %v", exists, err)
	}
}

func TestInstancesV2MetadataPreservesKarpenterInstanceType(t *testing.T) {
	api := &fakeAPI{vms: []inspace.VM{{
		UUID: testVMUUID, Name: "worker-0", Hostname: "worker-0", Status: "running",
		VCPU: 4, MemoryMiB: 8192, PrivateIPv4: "10.0.0.10",
		Description: `{"schema":"karpenter.inspace.cloud/v1","instanceType":"is-general-4c-8g"}`,
	}}}
	provider := newTestProvider(t, api)
	metadata, err := provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstanceType != "is-general-4c-8g" {
		t.Fatalf("InstanceType = %q", metadata.InstanceType)
	}

	api.vms[0].Description = `{"schema":"karpenter.inspace.cloud/v1","instanceType":"invalid/value"}`
	metadata, err = provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstanceType != "inspace-4c-8192mib" {
		t.Fatalf("invalid ownership instance type did not fall back: %q", metadata.InstanceType)
	}
}

func TestEnsureLoadBalancerCreatesTCPRulesAndOwnedName(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	nodes := []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}}
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.creates) != 1 {
		t.Fatalf("CreateLoadBalancer calls = %d", len(api.creates))
	}
	request := api.creates[0]
	if request.DisplayName != provider.GetLoadBalancerName(context.Background(), "ignored", service) || request.NetworkUUID != testNetworkUUID {
		t.Fatalf("request ownership = %#v", request)
	}
	if request.ReservePublicIP || len(request.Rules) != 1 || request.Rules[0].Protocol != "TCP" || request.Rules[0].SourcePort != 443 || request.Rules[0].TargetPort != 30443 {
		t.Fatalf("request rules = %#v", request)
	}
	if len(request.Targets) != 1 || request.Targets[0].TargetUUID != testVMUUID {
		t.Fatalf("request targets = %#v", request.Targets)
	}
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "10.0.0.50" {
		t.Fatalf("status = %#v", status)
	}
}

func TestLoadBalancerRejectsNonTCPBeforeMutation(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Spec.Ports[0].Protocol = corev1.ProtocolUDP
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil)
	if err == nil || len(api.creates) != 0 {
		t.Fatalf("EnsureLoadBalancer() error = %v, create calls = %d", err, len(api.creates))
	}
}

func TestLoadBalancerRejectsCrossLocationNode(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", testService(), []*corev1.Node{{
		Spec: corev1.NodeSpec{ProviderID: "inspace://jkt01/" + testVMUUID},
	}})
	if err == nil || len(api.creates) != 0 {
		t.Fatalf("EnsureLoadBalancer() error = %v, create calls = %d", err, len(api.creates))
	}
}

func TestPublicLoadBalancerUsesExplicitOwnedFloatingIP(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Annotations = map[string]string{AnnotationPublicLoadBalancer: "true"}
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}})
	if err != nil {
		t.Fatal(err)
	}
	if api.creates[0].ReservePublicIP {
		t.Fatal("NLB requested an unnamed public IP")
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != provider.floatingIPName(service) {
		t.Fatalf("floating IPs = %#v", api.floatingIPs)
	}
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" {
		t.Fatalf("status = %#v", status)
	}
}

func TestPublicToPrivateTransitionRemovesFloatingIP(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Annotations = map[string]string{AnnotationPublicLoadBalancer: "true"}
	nodes := []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}}
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	service.Annotations[AnnotationPublicLoadBalancer] = "false"
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	if len(api.unassignedIPs) != 1 || len(api.deletedIPs) != 1 || len(api.floatingIPs) != 0 {
		t.Fatalf("floating IP cleanup: unassign=%v delete=%v remaining=%v", api.unassignedIPs, api.deletedIPs, api.floatingIPs)
	}
}

func TestFloatingIPCleanupRejectsUnexpectedAssignment(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20",
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine",
	}}
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil {
		t.Fatal("expected cleanup to reject an unexpected floating IP assignment")
	}
	if len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 || len(api.deletedLBs) != 0 {
		t.Fatalf("unexpected cleanup mutation: unassign=%v deleteIP=%v deleteLB=%v", api.unassignedIPs, api.deletedIPs, api.deletedLBs)
	}
}

func TestLoadBalancerRejectsMalformedPublicAnnotationAndLocalTrafficPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Service){
		"malformed annotation": func(service *corev1.Service) {
			service.Annotations = map[string]string{AnnotationPublicLoadBalancer: "yes"}
		},
		"local policy": func(service *corev1.Service) {
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			service := testService()
			mutate(service)
			_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil)
			if err == nil || len(api.creates) != 0 {
				t.Fatalf("EnsureLoadBalancer() error = %v, creates = %d", err, len(api.creates))
			}
		})
	}
}

func TestEnsureLoadBalancerReconcilesTargetsAndRules(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	ownedName := provider.GetLoadBalancerName(context.Background(), "ignored", service)
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: ownedName, NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
		Targets:         []inspace.LoadBalancerTarget{{TargetUUID: "99999999-1111-4222-8333-444444444444", TargetType: "vm"}},
		ForwardingRules: []inspace.LoadBalancerRule{{UUID: "77777777-1111-4222-8333-444444444444", Protocol: "TCP", SourcePort: 443, TargetPort: 30001}},
	}}
	nodes := []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}}
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	if len(api.addedTargets) != 1 || api.addedTargets[0] != testVMUUID || len(api.removedTargets) != 1 {
		t.Fatalf("target changes: add=%v remove=%v", api.addedTargets, api.removedTargets)
	}
	if len(api.addedRules) != 1 || api.addedRules[0].TargetPort != 30443 || len(api.removedRules) != 1 {
		t.Fatalf("rule changes: add=%v remove=%v", api.addedRules, api.removedRules)
	}
}

func TestEnsureLoadBalancerDeletedOnlyDeletesExactOwnedName(t *testing.T) {
	api := &fakeAPI{lbs: []inspace.LoadBalancer{{UUID: testLBUUID, DisplayName: "unrelated", NetworkUUID: testNetworkUUID}}}
	provider := newTestProvider(t, api)
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", testService()); err != nil {
		t.Fatal(err)
	}
	if len(api.deletedLBs) != 0 {
		t.Fatalf("deleted unrelated LB: %v", api.deletedLBs)
	}
}

func newTestProvider(t *testing.T, api *fakeAPI) *Provider {
	t.Helper()
	provider, err := New(api, Config{
		Location: "bkk01", Region: "thailand", NetworkUUID: testNetworkUUID,
		BillingAccountID: 42, ClusterID: "unit-test-cluster",
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func testService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID("12345678-1234-4234-8234-123456789012")},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 443, NodePort: 30443}}},
	}
}

type fakeAPI struct {
	vms []inspace.VM
	lbs []inspace.LoadBalancer

	creates        []inspace.CreateLoadBalancerRequest
	deletedLBs     []string
	addedTargets   []string
	removedTargets []string
	addedRules     []inspace.LoadBalancerRule
	removedRules   []string
	floatingIPs    []inspace.FloatingIP
	unassignedIPs  []string
	deletedIPs     []string
}

func (f *fakeAPI) ListVMs(context.Context, string) ([]inspace.VM, error) { return f.vms, nil }
func (f *fakeAPI) GetVM(_ context.Context, _ string, uuid string) (*inspace.VM, error) {
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			return &f.vms[i], nil
		}
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "GET", Path: "/vm", Message: "not found"}
}
func (f *fakeAPI) ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error) {
	return f.lbs, nil
}
func (f *fakeAPI) CreateLoadBalancer(_ context.Context, _ string, request inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error) {
	f.creates = append(f.creates, request)
	lb := inspace.LoadBalancer{UUID: testLBUUID, DisplayName: request.DisplayName, NetworkUUID: request.NetworkUUID, PrivateAddress: "10.0.0.50", ForwardingRules: request.Rules, Targets: request.Targets}
	f.lbs = append(f.lbs, lb)
	return &lb, nil
}
func (f *fakeAPI) DeleteLoadBalancer(_ context.Context, _ string, uuid string) error {
	f.deletedLBs = append(f.deletedLBs, uuid)
	return nil
}
func (f *fakeAPI) AddLoadBalancerTarget(_ context.Context, _, _ string, uuid string) (*inspace.LoadBalancerTarget, error) {
	f.addedTargets = append(f.addedTargets, uuid)
	return &inspace.LoadBalancerTarget{TargetUUID: uuid, TargetType: "vm"}, nil
}
func (f *fakeAPI) RemoveLoadBalancerTarget(_ context.Context, _, _, uuid string) error {
	f.removedTargets = append(f.removedTargets, uuid)
	return nil
}
func (f *fakeAPI) AddLoadBalancerRule(_ context.Context, _, _ string, rule inspace.LoadBalancerRule) (*inspace.LoadBalancerRule, error) {
	f.addedRules = append(f.addedRules, rule)
	return &rule, nil
}
func (f *fakeAPI) RemoveLoadBalancerRule(_ context.Context, _, _, uuid string) error {
	f.removedRules = append(f.removedRules, uuid)
	return nil
}
func (f *fakeAPI) ListFloatingIPs(context.Context, string, *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error) {
	return f.floatingIPs, nil
}
func (f *fakeAPI) CreateFloatingIP(_ context.Context, _ string, request inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error) {
	item := inspace.FloatingIP{Name: request.Name, Address: "203.0.113.20", BillingAccountID: request.BillingAccountID}
	f.floatingIPs = append(f.floatingIPs, item)
	return &item, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _, address, uuid, resourceType string) (*inspace.FloatingIP, error) {
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = uuid
			f.floatingIPs[i].AssignedToResourceType = resourceType
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return &inspace.FloatingIP{Address: address, AssignedTo: uuid, AssignedToResourceType: resourceType}, nil
}
func (f *fakeAPI) UnassignFloatingIP(_ context.Context, _, address string) (*inspace.FloatingIP, error) {
	f.unassignedIPs = append(f.unassignedIPs, address)
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
		}
	}
	return &inspace.FloatingIP{Address: address}, nil
}
func (f *fakeAPI) DeleteFloatingIP(_ context.Context, _, address string) error {
	f.deletedIPs = append(f.deletedIPs, address)
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs = append(f.floatingIPs[:i], f.floatingIPs[i+1:]...)
			break
		}
	}
	return nil
}

var _ API = (*fakeAPI)(nil)
