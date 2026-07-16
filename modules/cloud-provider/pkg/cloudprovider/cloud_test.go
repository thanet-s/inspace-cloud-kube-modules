package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	cloud "k8s.io/cloud-provider"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
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
	}}, floatingIPs: []inspace.FloatingIP{{
		Address: "203.0.113.10", BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: "10.0.0.10",
	}}}
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

func TestNodeLoadBalancerConfigDefaultsNodesPerShardToOne(t *testing.T) {
	provider, err := New(&fakeAPI{}, Config{
		Location: "bkk01", Region: "thailand", NetworkUUID: testNetworkUUID,
		BillingAccountID: 42, ClusterID: "unit-test-cluster", ControlPlaneVIP: "10.0.0.10",
		PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
		NodeLoadBalancer: NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.config.NodeLoadBalancer.NodesPerShard != 1 {
		t.Fatalf("nodes per shard = %d, want 1", provider.config.NodeLoadBalancer.NodesPerShard)
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

	api.vms[0].Description = `{"schema":"karpenter.inspace.cloud/v2","instanceType":"is-general-4c-8g"}`
	metadata, err = provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstanceType != "is-general-4c-8g" {
		t.Fatalf("v2 InstanceType = %q", metadata.InstanceType)
	}

	api.vms[0].Description = `{"schema":"karpenter.inspace.cloud/v3","instanceType":"is-general-4c-8g"}`
	metadata, err = provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstanceType != "is-general-4c-8g" {
		t.Fatalf("v3 InstanceType = %q", metadata.InstanceType)
	}

	api.vms[0].Description = `{"schema":"karpenter.inspace.cloud/v2","instanceType":"invalid/value"}`
	metadata, err = provider.InstanceMetadata(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstanceType != "inspace-4c-8192mib" {
		t.Fatalf("invalid ownership instance type did not fall back: %q", metadata.InstanceType)
	}
}

func TestExternalIPv4ForVMRequiresExactActiveAssignment(t *testing.T) {
	vm := inspace.VM{UUID: testVMUUID, PrivateIPv4: "10.0.0.10", PublicIPv4: "198.51.100.90"}
	valid := inspace.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
	}

	provider := newTestProvider(t, &fakeAPI{floatingIPs: []inspace.FloatingIP{valid}})
	address, err := provider.externalIPv4ForVM(context.Background(), "bkk01", &vm)
	if err != nil || address != valid.Address {
		t.Fatalf("externalIPv4ForVM() = %q, %v", address, err)
	}

	tests := []struct {
		name   string
		mutate func(*inspace.FloatingIP)
	}{
		{name: "wrong billing account", mutate: func(item *inspace.FloatingIP) { item.BillingAccountID++ }},
		{name: "disabled", mutate: func(item *inspace.FloatingIP) { item.Enabled = false }},
		{name: "deleted", mutate: func(item *inspace.FloatingIP) { item.IsDeleted = true }},
		{name: "virtual", mutate: func(item *inspace.FloatingIP) { item.IsVirtual = true }},
		{name: "wrong address type", mutate: func(item *inspace.FloatingIP) { item.Type = "private" }},
		{name: "private address", mutate: func(item *inspace.FloatingIP) { item.Address = "10.0.0.20" }},
		{name: "IPv6 address", mutate: func(item *inspace.FloatingIP) { item.Address = "2001:db8::10" }},
		{name: "noncanonical address", mutate: func(item *inspace.FloatingIP) { item.Address = "203.0.113.010" }},
		{name: "wrong VM", mutate: func(item *inspace.FloatingIP) { item.AssignedTo = testLBUUID }},
		{name: "wrong resource type", mutate: func(item *inspace.FloatingIP) { item.AssignedToResourceType = "load_balancer" }},
		{name: "missing private assignment", mutate: func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "" }},
		{name: "wrong private assignment", mutate: func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.0.0.99" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := valid
			test.mutate(&item)
			provider := newTestProvider(t, &fakeAPI{floatingIPs: []inspace.FloatingIP{item}})
			if address, err := provider.externalIPv4ForVM(context.Background(), "bkk01", &vm); err == nil || address != "" {
				t.Fatalf("externalIPv4ForVM() = %q, %v; want fail-closed error", address, err)
			}
		})
	}
}

func TestExternalIPv4ForVMRejectsMultipleRowsAndDoesNotUseNICFallback(t *testing.T) {
	vm := inspace.VM{UUID: testVMUUID, PrivateIPv4: "10.0.0.10", PublicIPv4: "198.51.100.90"}
	valid := inspace.FloatingIP{
		Address: "203.0.113.10", BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
	}

	provider := newTestProvider(t, &fakeAPI{floatingIPs: []inspace.FloatingIP{valid, valid}})
	if address, err := provider.externalIPv4ForVM(context.Background(), "bkk01", &vm); err == nil || address != "" {
		t.Fatalf("multiple rows externalIPv4ForVM() = %q, %v; want fail-closed error", address, err)
	}

	provider = newTestProvider(t, &fakeAPI{})
	if address, err := provider.externalIPv4ForVM(context.Background(), "bkk01", &vm); err != nil || address != "" {
		t.Fatalf("NIC fallback externalIPv4ForVM() = %q, %v; want no published address", address, err)
	}
}

func TestExternalIPv4ForVMAcceptsNullIsVirtualAsFalse(t *testing.T) {
	var item inspace.FloatingIP
	if err := json.Unmarshal([]byte(`{"address":"203.0.113.10","billing_account_id":42,"type":"public","enabled":true,"is_deleted":false,"is_virtual":null,"assigned_to":"`+testVMUUID+`","assigned_to_resource_type":"virtual_machine","assigned_to_private_ip":"10.0.0.10"}`), &item); err != nil {
		t.Fatal(err)
	}
	if item.IsVirtual {
		t.Fatal("null is_virtual decoded as true")
	}
	vm := inspace.VM{UUID: testVMUUID, PrivateIPv4: "10.0.0.10"}
	provider := newTestProvider(t, &fakeAPI{floatingIPs: []inspace.FloatingIP{item}})
	if address, err := provider.externalIPv4ForVM(context.Background(), "bkk01", &vm); err != nil || address != item.Address {
		t.Fatalf("externalIPv4ForVM() = %q, %v", address, err)
	}
}

func TestEnsureLoadBalancerCreatesTCPRulesAndOwnedName(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
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
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" {
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

func TestLoadBalancerSkipsCrossLocationNode(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", testService(), []*corev1.Node{
		readyNode("worker-0", "inspace://jkt01/"+testVMUUID),
	})
	if err != nil || len(api.creates) != 1 || len(api.creates[0].Targets) != 0 {
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

func TestPublicLoadBalancerRecreatesFloatingIPAfterSoftDeletedOwnershipRow(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service),
		NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
		ForwardingRules: serviceRules(service),
		Targets:         []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}},
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.19", BillingAccountID: 42,
		Type: "public", Enabled: false, IsDeleted: true,
	}}

	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{
		Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" {
		t.Fatalf("status = %#v", status)
	}
	if len(api.floatingIPs) != 2 || !api.floatingIPs[0].IsDeleted || api.floatingIPs[1].IsDeleted ||
		api.floatingIPs[1].Name != provider.floatingIPName(service) || api.floatingIPs[1].AssignedTo != testLBUUID {
		t.Fatalf("soft-deleted FIP was not ignored before recreation: %#v", api.floatingIPs)
	}
}

func TestPublicServiceFloatingIPCreateAndAssignResponsesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutateCreate func(*inspace.FloatingIP)
		mutateAssign func(*inspace.FloatingIP)
	}{
		{name: "wrong create name", mutateCreate: func(item *inspace.FloatingIP) { item.Name = "foreign" }},
		{name: "wrong create account", mutateCreate: func(item *inspace.FloatingIP) { item.BillingAccountID++ }},
		{name: "disabled create response", mutateCreate: func(item *inspace.FloatingIP) { item.Enabled = false }},
		{name: "deleted create response", mutateCreate: func(item *inspace.FloatingIP) { item.IsDeleted = true }},
		{name: "virtual create response", mutateCreate: func(item *inspace.FloatingIP) { item.IsVirtual = true }},
		{name: "wrong type create response", mutateCreate: func(item *inspace.FloatingIP) { item.Type = "private" }},
		{name: "non-public create address", mutateCreate: func(item *inspace.FloatingIP) { item.Address = "10.0.0.20" }},
		{name: "noncanonical create address", mutateCreate: func(item *inspace.FloatingIP) { item.Address = "203.0.113.020" }},
		{name: "residual create private assignment", mutateCreate: func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.0.0.50" }},
		{name: "wrong assign response", mutateAssign: func(item *inspace.FloatingIP) { item.AssignedTo = testVMUUID }},
		{name: "wrong assign type", mutateAssign: func(item *inspace.FloatingIP) { item.AssignedToResourceType = "virtual_machine" }},
		{name: "wrong assign private address", mutateAssign: func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.0.0.99" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{mutateCreateFloatingIPResponse: test.mutateCreate, mutateAssignFloatingIPResponse: test.mutateAssign}
			provider := newTestProvider(t, api)
			service := testService()
			status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}})
			if err == nil || status != nil {
				t.Fatalf("malformed FIP response returned status=%#v error=%v", status, err)
			}
		})
	}
}

func TestPublicServiceFloatingIPListRequiresStrictIdentityAndAssignment(t *testing.T) {
	mutations := []func(*inspace.FloatingIP){
		func(item *inspace.FloatingIP) { item.BillingAccountID++ },
		func(item *inspace.FloatingIP) { item.Enabled = false },
		func(item *inspace.FloatingIP) { item.IsVirtual = true },
		func(item *inspace.FloatingIP) { item.Type = "private" },
		func(item *inspace.FloatingIP) { item.Address = "10.0.0.20" },
		func(item *inspace.FloatingIP) { item.Address = "203.0.113.020" },
		func(item *inspace.FloatingIP) { item.AssignedTo = testVMUUID },
		func(item *inspace.FloatingIP) { item.AssignedToResourceType = "virtual_machine" },
		func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.0.0.99" },
	}
	for index, mutate := range mutations {
		api := &fakeAPI{}
		provider := newTestProvider(t, api)
		service := testService()
		api.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
		}}
		item := inspace.FloatingIP{
			Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
		}
		mutate(&item)
		api.floatingIPs = []inspace.FloatingIP{item}
		status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
		if err == nil || !exists || status != nil {
			t.Errorf("invalid listed FIP %d returned status=%#v exists=%t error=%v", index, status, exists, err)
		}
	}
}

func TestMalformedListedPublicFIPBlocksNLBMutation(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
		Targets: []inspace.LoadBalancerTarget{{TargetUUID: "99999999-1111-4222-8333-444444444444", TargetType: "vm"}},
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine",
	}}
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}})
	if err == nil {
		t.Fatal("expected malformed listed public FIP rejection")
	}
	if len(api.addedTargets) != 0 || len(api.removedTargets) != 0 || len(api.addedRules) != 0 || len(api.removedRules) != 0 {
		t.Fatalf("malformed FIP allowed NLB mutation: addTargets=%v removeTargets=%v addRules=%v removeRules=%v", api.addedTargets, api.removedTargets, api.addedRules, api.removedRules)
	}
}

func TestNonExplicitPublicServiceIsImplementedElsewhere(t *testing.T) {
	for _, mutate := range []func(*corev1.Service){
		func(service *corev1.Service) { service.Labels = nil; service.Annotations = nil },
		func(service *corev1.Service) { delete(service.Annotations, AnnotationPublicLoadBalancer) },
		func(service *corev1.Service) { delete(service.Labels, LabelLoadBalancerScope) },
		func(service *corev1.Service) {
			service.Labels[LabelLoadBalancerScope] = LoadBalancerScopePrivate
			service.Annotations = nil
			class := "io.cilium/l2-announcer"
			service.Spec.LoadBalancerClass = &class
		},
	} {
		api := &fakeAPI{}
		provider := newTestProvider(t, api)
		service := testService()
		mutate(service)
		if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); !errors.Is(err, cloud.ImplementedElsewhere) {
			t.Fatalf("EnsureLoadBalancer() error = %v, want ImplementedElsewhere", err)
		}
		if err := provider.UpdateLoadBalancer(context.Background(), "ignored", service, nil); !errors.Is(err, cloud.ImplementedElsewhere) {
			t.Fatalf("UpdateLoadBalancer() error = %v, want ImplementedElsewhere", err)
		}
		if len(api.creates) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("non-public Service mutated InSpace resources: creates=%#v FIPs=%#v", api.creates, api.floatingIPs)
		}
	}
}

func TestGetReportsOwnedLegacyResourcesRegardlessMarkers(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Labels = nil
	service.Annotations = nil
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true, AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
	}}
	status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
	if err != nil || !exists || len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" {
		t.Fatalf("GetLoadBalancer() = %#v, %t, %v", status, exists, err)
	}
	api.floatingIPs = nil
	status, exists, err = provider.GetLoadBalancer(context.Background(), "ignored", service)
	if err != nil || !exists || len(status.Ingress) != 1 || status.Ingress[0].IP != "10.0.0.50" {
		t.Fatalf("legacy private GetLoadBalancer() = %#v, %t, %v", status, exists, err)
	}
}

func TestMarkerRemovalNeverLeaksOwnedResourcesOrReturnsImplementedElsewhereEarly(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	delete(service.Labels, LabelLoadBalancerScope)
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil || len(status.Ingress) != 0 || len(api.lbs) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("cleanup result = %#v, %v; LBs=%#v FIPs=%#v", status, err, api.lbs, api.floatingIPs)
	}
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); !errors.Is(err, cloud.ImplementedElsewhere) {
		t.Fatalf("post-cleanup error = %v, want ImplementedElsewhere", err)
	}

	api.lbs = []inspace.LoadBalancer{{UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50"}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true, AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine",
	}}
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || errors.Is(err, cloud.ImplementedElsewhere) {
		t.Fatalf("unsafe partial cleanup error = %v", err)
	}
	if len(api.lbs) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("unsafe cleanup mutated resources: LBs=%#v FIPs=%#v", api.lbs, api.floatingIPs)
	}
}

func TestPublicLoadBalancerReservedAddressCollisionDeletesBeforeFIP(t *testing.T) {
	for _, collision := range []struct {
		name    string
		address string
	}{
		{name: "Cilium pool", address: "10.0.0.205"},
		{name: "control-plane VIP", address: "10.0.0.10"},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", collision.name, existing), func(t *testing.T) {
				address := collision.address
				api := &fakeAPI{createPrivateAddress: &address}
				provider := newTestProvider(t, api)
				service := testService()
				if existing {
					api.lbs = []inspace.LoadBalancer{{
						UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: address,
					}}
					api.floatingIPs = []inspace.FloatingIP{{
						Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true,
						AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
					}}
				}
				nodes := []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}}
				if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil {
					t.Fatal("expected reserved-address NLB collision")
				}
				if len(api.deletedLBs) != 1 || len(api.lbs) != 0 || len(api.floatingIPs) != 0 || (!existing && len(api.deletedIPs) != 0) || (existing && len(api.deletedIPs) != 1) {
					t.Fatalf("collision cleanup: deletedLB=%v LBs=%#v FIPs=%#v deletedIPs=%v", api.deletedLBs, api.lbs, api.floatingIPs, api.deletedIPs)
				}
			})
		}
	}
}

func TestExistingReservedAddressCollisionCleanupPrecedesUnrelatedValidation(t *testing.T) {
	validNodes := []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}}
	for _, test := range []struct {
		name          string
		billingID     int64
		withFIP       bool
		update        bool
		mutateService func(*corev1.Service)
		nodes         []*corev1.Node
	}{
		{
			name: "Ensure before invalid Service", billingID: 42, withFIP: true, nodes: validNodes,
			mutateService: func(service *corev1.Service) { service.Spec.Ports[0].Protocol = corev1.ProtocolUDP },
		},
		{
			name: "Ensure before invalid node", billingID: 42, withFIP: true,
			nodes: []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "foreign://node"}}},
		},
		{
			name: "Update before invalid Service", billingID: 42, withFIP: true, update: true, nodes: validNodes,
			mutateService: func(service *corev1.Service) {
				service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			provider, err := New(api, Config{
				Location: "bkk01", Region: "thailand", NetworkUUID: testNetworkUUID,
				BillingAccountID: test.billingID, ClusterID: "unit-test-cluster",
				ControlPlaneVIP:              "10.0.0.10",
				PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
			})
			if err != nil {
				t.Fatal(err)
			}
			service := testService()
			if test.mutateService != nil {
				test.mutateService(service)
			}
			api.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.10",
			}}
			if test.withFIP {
				api.floatingIPs = []inspace.FloatingIP{{
					Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: test.billingID, Type: "public", Enabled: true,
					AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer", AssignedToPrivateIP: "10.0.0.10",
				}}
			}
			if test.update {
				err = provider.UpdateLoadBalancer(context.Background(), "ignored", service, test.nodes)
			} else {
				_, err = provider.EnsureLoadBalancer(context.Background(), "ignored", service, test.nodes)
			}
			if err == nil || !strings.Contains(err.Error(), "collides with") {
				t.Fatalf("collision result = %v, want collision error", err)
			}
			wantDeletedIPs := 0
			if test.withFIP {
				wantDeletedIPs = 1
			}
			if len(api.lbs) != 0 || len(api.floatingIPs) != 0 || len(api.deletedLBs) != 1 || len(api.deletedIPs) != wantDeletedIPs || len(api.creates) != 0 {
				t.Fatalf("collision cleanup: LBs=%#v FIPs=%#v deletedLBs=%v deletedIPs=%v creates=%v", api.lbs, api.floatingIPs, api.deletedLBs, api.deletedIPs, api.creates)
			}
		})
	}
}

func TestPublicLoadBalancerWaitsForPrivateAddressBeforeFIP(t *testing.T) {
	empty := ""
	api := &fakeAPI{createPrivateAddress: &empty}
	provider := newTestProvider(t, api)
	service := testService()
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}})
	if err == nil || len(api.lbs) != 1 || len(api.floatingIPs) != 0 {
		t.Fatalf("pending private address result: err=%v LBs=%#v FIPs=%#v", err, api.lbs, api.floatingIPs)
	}
}

func TestProviderRequiresBoundedCanonicalPrivateLoadBalancerPool(t *testing.T) {
	for _, pool := range [][2]string{
		{"", ""}, {"203.0.113.1", "203.0.113.20"}, {"10.0.0.20", "10.0.0.10"},
		{"10.0.0.1", "10.0.0.15"}, {"10.0.0.0", "10.0.1.0"},
		{"10.41.255.250", "10.42.0.9"}, {"10.42.255.250", "10.43.0.9"},
	} {
		_, err := New(&fakeAPI{}, Config{
			Location: "bkk01", NetworkUUID: testNetworkUUID, ClusterID: "unit-test-cluster",
			BillingAccountID:             42,
			ControlPlaneVIP:              "10.0.0.10",
			PrivateLoadBalancerPoolStart: pool[0], PrivateLoadBalancerPoolStop: pool[1],
		})
		if err == nil {
			t.Fatalf("invalid private load-balancer pool %#v accepted", pool)
		}
	}
}

func TestProviderRequiresPositiveBillingAccountID(t *testing.T) {
	for _, billingAccountID := range []int64{-1, 0} {
		_, err := New(&fakeAPI{}, Config{
			Location: "bkk01", NetworkUUID: testNetworkUUID, BillingAccountID: billingAccountID, ClusterID: "unit-test-cluster",
			ControlPlaneVIP:              "10.0.0.10",
			PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
		})
		if err == nil || !strings.Contains(err.Error(), "billing account ID") {
			t.Fatalf("billing account ID %d was accepted: %v", billingAccountID, err)
		}
	}
}

func TestProviderRequiresCanonicalControlPlaneVIPOutsidePrivateLoadBalancerPool(t *testing.T) {
	for _, controlPlaneVIP := range []string{
		"", "203.0.113.10", "10.0.0.010", " 10.0.0.10", "fd00::10", "10.0.0.205", "10.42.0.10", "10.43.0.10",
	} {
		_, err := New(&fakeAPI{}, Config{
			Location: "bkk01", NetworkUUID: testNetworkUUID, ClusterID: "unit-test-cluster",
			BillingAccountID:             42,
			ControlPlaneVIP:              controlPlaneVIP,
			PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
		})
		if err == nil {
			t.Fatalf("invalid control-plane VIP %q accepted", controlPlaneVIP)
		}
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
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Ingress) != 0 || len(api.unassignedIPs) != 1 || len(api.deletedIPs) != 1 || len(api.floatingIPs) != 0 || len(api.deletedLBs) != 1 || len(api.lbs) != 0 {
		t.Fatalf("public cleanup: status=%#v unassign=%v deleteIP=%v remainingIPs=%v deleteLB=%v remainingLBs=%v", status, api.unassignedIPs, api.deletedIPs, api.floatingIPs, api.deletedLBs, api.lbs)
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
		Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: testVMUUID, AssignedToResourceType: "virtual_machine",
	}}
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil {
		t.Fatal("expected cleanup to reject an unexpected floating IP assignment")
	}
	if len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 || len(api.deletedLBs) != 0 {
		t.Fatalf("unexpected cleanup mutation: unassign=%v deleteIP=%v deleteLB=%v", api.unassignedIPs, api.deletedIPs, api.deletedLBs)
	}
}

func TestLoadBalancerRejectsMalformedPublicAnnotation(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Annotations = map[string]string{AnnotationPublicLoadBalancer: "yes"}
	_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil)
	if err == nil || len(api.creates) != 0 {
		t.Fatalf("EnsureLoadBalancer() error = %v, creates = %d", err, len(api.creates))
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
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
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

func TestSameOwnershipNameInAnotherNetworkFailsClosedBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*Provider, *corev1.Service) error
	}{
		{
			name: "explicit public adoption",
			run: func(provider *Provider, service *corev1.Service) error {
				_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, []*corev1.Node{{
					Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID},
				}})
				return err
			},
		},
		{
			name: "public marker removal cleanup",
			run: func(provider *Provider, service *corev1.Service) error {
				service.Labels = nil
				service.Annotations = nil
				_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil)
				return err
			},
		},
		{
			name: "service deletion cleanup",
			run: func(provider *Provider, service *corev1.Service) error {
				return provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{}
			provider := newTestProvider(t, api)
			service := testService()
			api.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: provider.loadBalancerName(service),
				NetworkUUID: "99999999-8888-4777-8666-555555555555", PrivateAddress: "10.99.0.50",
			}}

			err := test.run(provider, service)
			if err == nil || !strings.Contains(err.Error(), "configured network") {
				t.Fatalf("foreign-network ownership collision error = %v", err)
			}
			if len(api.lbs) != 1 || len(api.creates) != 0 || len(api.deletedLBs) != 0 ||
				len(api.addedTargets) != 0 || len(api.removedTargets) != 0 ||
				len(api.addedRules) != 0 || len(api.removedRules) != 0 ||
				len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 {
				t.Fatalf("foreign-network ownership collision allowed mutation: %#v", api)
			}
		})
	}
}

func TestEnsureLoadBalancerDeletedCleansOwnedResourcesWithoutMarkers(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	service.Labels = nil
	service.Annotations = nil
	api.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
	}}
	api.floatingIPs = []inspace.FloatingIP{{
		Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42, Type: "public", Enabled: true, AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
	}}
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err != nil {
		t.Fatal(err)
	}
	if len(api.lbs) != 0 || len(api.floatingIPs) != 0 || len(api.deletedLBs) != 1 || len(api.deletedIPs) != 1 {
		t.Fatalf("marker-independent cleanup failed: LBs=%#v FIPs=%#v deleteLB=%v deleteIP=%v", api.lbs, api.floatingIPs, api.deletedLBs, api.deletedIPs)
	}
}

func newTestProvider(t *testing.T, api *fakeAPI) *Provider {
	t.Helper()
	provider, err := New(api, Config{
		Location: "bkk01", Region: "thailand", NetworkUUID: testNetworkUUID,
		BillingAccountID: 42, ClusterID: "unit-test-cluster",
		ControlPlaneVIP:              "10.0.0.10",
		PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.dynamicClient = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			nodePoolGVR: "NodePoolList", nodeClaimGVR: "NodeClaimList",
		},
	)
	return provider
}

func testService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "web", UID: types.UID("12345678-1234-4234-8234-123456789012"),
			Labels:      map[string]string{LabelLoadBalancerScope: LoadBalancerScopePublic},
			Annotations: map[string]string{AnnotationPublicLoadBalancer: "true"},
		},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 443, NodePort: 30443}}},
	}
}

func readyNode(name, providerID string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{ProviderID: providerID},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		}}},
	}
}

type fakeAPI struct {
	vms       []inspace.VM
	lbs       []inspace.LoadBalancer
	firewalls []inspace.Firewall

	creates                        []inspace.CreateLoadBalancerRequest
	deletedLBs                     []string
	addedTargets                   []string
	removedTargets                 []string
	addedRules                     []inspace.LoadBalancerRule
	removedRules                   []string
	floatingIPs                    []inspace.FloatingIP
	unassignedIPs                  []string
	deletedIPs                     []string
	createdFirewalls               []inspace.CreateFirewallRequest
	createFirewallErr              error
	updatedFirewalls               []inspace.UpdateFirewallRequest
	updateFirewallErr              error
	deletedFirewalls               []string
	assignedFirewalls              []string
	unassignedFirewalls            []string
	createPrivateAddress           *string
	mutateCreateFloatingIPResponse func(*inspace.FloatingIP)
	mutateAssignFloatingIPResponse func(*inspace.FloatingIP)
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
	privateAddress := "10.0.0.50"
	if f.createPrivateAddress != nil {
		privateAddress = *f.createPrivateAddress
	}
	lb := inspace.LoadBalancer{UUID: testLBUUID, DisplayName: request.DisplayName, NetworkUUID: request.NetworkUUID, PrivateAddress: privateAddress, ForwardingRules: request.Rules, Targets: request.Targets}
	f.lbs = append(f.lbs, lb)
	return &lb, nil
}
func (f *fakeAPI) DeleteLoadBalancer(_ context.Context, _ string, uuid string) error {
	f.deletedLBs = append(f.deletedLBs, uuid)
	for i := range f.lbs {
		if f.lbs[i].UUID == uuid {
			f.lbs = append(f.lbs[:i], f.lbs[i+1:]...)
			break
		}
	}
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
	item := inspace.FloatingIP{Name: request.Name, Address: "203.0.113.20", BillingAccountID: request.BillingAccountID, Type: "public", Enabled: true}
	if f.mutateCreateFloatingIPResponse != nil {
		f.mutateCreateFloatingIPResponse(&item)
	}
	f.floatingIPs = append(f.floatingIPs, item)
	return &item, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _, address, uuid, resourceType string) (*inspace.FloatingIP, error) {
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = uuid
			f.floatingIPs[i].AssignedToResourceType = resourceType
			if f.mutateAssignFloatingIPResponse != nil {
				f.mutateAssignFloatingIPResponse(&f.floatingIPs[i])
			}
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
			f.floatingIPs[i].AssignedToPrivateIP = ""
			copy := f.floatingIPs[i]
			return &copy, nil
		}
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "POST", Path: "/ip/unassign", Message: "not found"}
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

func (f *fakeAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	return append([]inspace.Firewall(nil), f.firewalls...), nil
}

func (f *fakeAPI) CreateFirewall(_ context.Context, _ string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	f.createdFirewalls = append(f.createdFirewalls, request)
	if f.createFirewallErr != nil {
		return nil, f.createFirewallErr
	}
	rules := append([]inspace.FirewallRule(nil), request.Rules...)
	for index := range rules {
		if rules[index].UUID == "" {
			rules[index].UUID = fmt.Sprintf("10000000-0000-4000-8000-%012d", index+1)
		}
	}
	item := inspace.Firewall{
		UUID:        fmt.Sprintf("00000000-0000-4000-8000-%012d", len(f.firewalls)+1),
		DisplayName: request.DisplayName, Description: request.Description,
		BillingAccountID: request.BillingAccountID, Rules: rules,
	}
	f.firewalls = append(f.firewalls, item)
	return &item, nil
}

func (f *fakeAPI) UpdateFirewall(_ context.Context, _, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	f.updatedFirewalls = append(f.updatedFirewalls, request)
	if f.updateFirewallErr != nil {
		return nil, f.updateFirewallErr
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID != uuid {
			continue
		}
		f.firewalls[i].Name = request.Name
		f.firewalls[i].DisplayName = request.Name
		f.firewalls[i].Description = request.Description
		rules := append([]inspace.FirewallRule(nil), request.Rules...)
		for index := range rules {
			if rules[index].UUID == "" {
				rules[index].UUID = fmt.Sprintf("20000000-0000-4000-8000-%012d", index+1)
			}
		}
		f.firewalls[i].Rules = rules
		copy := f.firewalls[i]
		return &copy, nil
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "PUT", Path: "/firewall", Message: "not found"}
}

func (f *fakeAPI) DeleteFirewall(_ context.Context, _, uuid string) error {
	f.deletedFirewalls = append(f.deletedFirewalls, uuid)
	for i := range f.firewalls {
		if f.firewalls[i].UUID == uuid {
			f.firewalls = append(f.firewalls[:i], f.firewalls[i+1:]...)
			return nil
		}
	}
	return &inspace.APIError{StatusCode: 404, Method: "DELETE", Path: "/firewall", Message: "not found"}
}

func (f *fakeAPI) AssignFirewallToVM(_ context.Context, _, firewallUUID, vmUUID string) error {
	f.assignedFirewalls = append(f.assignedFirewalls, firewallUUID+"/"+vmUUID)
	for i := range f.firewalls {
		if f.firewalls[i].UUID == firewallUUID {
			for _, resource := range f.firewalls[i].ResourcesAssigned {
				if resource.ResourceType == "vm" && resource.ResourceUUID == vmUUID {
					return nil
				}
			}
			f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
			return nil
		}
	}
	return &inspace.APIError{StatusCode: 404, Method: "POST", Path: "/firewall/vms", Message: "not found"}
}

func (f *fakeAPI) UnassignFirewallFromVM(_ context.Context, _, firewallUUID, vmUUID string) error {
	f.unassignedFirewalls = append(f.unassignedFirewalls, firewallUUID+"/"+vmUUID)
	for i := range f.firewalls {
		if f.firewalls[i].UUID != firewallUUID {
			continue
		}
		resources := f.firewalls[i].ResourcesAssigned[:0]
		for _, resource := range f.firewalls[i].ResourcesAssigned {
			if resource.ResourceType != "vm" || resource.ResourceUUID != vmUUID {
				resources = append(resources, resource)
			}
		}
		f.firewalls[i].ResourcesAssigned = resources
		return nil
	}
	return &inspace.APIError{StatusCode: 404, Method: "DELETE", Path: "/firewall/vms", Message: "not found"}
}

var _ API = (*fakeAPI)(nil)
