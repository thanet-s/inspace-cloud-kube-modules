package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubefake "k8s.io/client-go/kubernetes/fake"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// migrationVM names one VM of a migration cluster. pool is the public-node-local
// pool of its Node; empty means the default "edge".
type migrationVM struct{ name, uuid, private, public, pool string }

// The three VMs of th-live: two gateways and the relay.
var (
	mgGateway1 = migrationVM{"gw-1", "ee1b82ca-2222-4333-8444-555555555555", "10.0.0.21", "203.0.113.21", ""}
	mgGateway2 = migrationVM{"gw-2", "0069af98-2222-4333-8444-555555555555", "10.0.0.22", "203.0.113.22", ""}
	mgRelay    = migrationVM{"relay-1", "c6bcc2f2-2222-4333-8444-555555555555", "10.0.0.23", "203.0.113.23", ""}
)

// migrationCluster is a v1.1.9 cluster that the tests then move to the per-VM
// firewall: Services are published by the real Service pass on per-Service
// firewalls (the perService mode), then the controller is switched to perVM.
type migrationCluster struct {
	t          *testing.T
	ctx        context.Context
	api        *fakeAPI
	gate       *limitEnforcingFirewallAPI
	provider   *Provider
	controller *nodeLoadBalancerController
	kube       *kubefake.Clientset
	vms        []migrationVM
	services   []string
	endpoints  map[string][]string
	clock      time.Time
	// history is the number of firewalls each VM carried over time.
	history map[string][]int
	// required is what each VM must keep allowing, as trackCoverage captured it.
	required map[string][]inspace.FirewallRule
	// observe, when set, runs after every mutating cloud call.
	observe func(call string)
}

func newMigrationCluster(t *testing.T, vms ...migrationVM) *migrationCluster {
	t.Helper()
	api := &fakeAPI{}
	objects := []runtime.Object{}
	base := publicNodeLocalTestBaseFirewall("")
	base.ResourcesAssigned = nil
	for _, vm := range vms {
		node := publicNodeLocalTestNode(vm.name, vm.uuid, vm.private, vm.public)
		if vm.pool != "" {
			node.Labels[publicNodeLocalPoolLabel] = vm.pool
		}
		api.vms = append(api.vms, inspace.VM{
			UUID: vm.uuid, Name: vm.name, Hostname: vm.name, Status: "running",
			PrivateIPv4: vm.private, BillingAccountID: 42, NetworkUUID: testNetworkUUID,
		})
		api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{
			Address: vm.public, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vm.uuid, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.private,
		})
		base.ResourcesAssigned = append(base.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm.uuid})
		objects = append(objects, node)
	}
	api.firewalls = append(api.firewalls, base)
	gate := &limitEnforcingFirewallAPI{API: &publicNodeLocalFilteringIPAPI{fakeAPI: api}}
	provider := newTestProvider(t, gate)
	kube := kubefake.NewSimpleClientset(objects...)
	// The fake apiserver does not assign UIDs; the real one does.
	kube.PrependReactor("create", "configmaps", func(action kubetesting.Action) (bool, runtime.Object, error) {
		if create, ok := action.(kubetesting.CreateAction); ok {
			if cm, ok := create.GetObject().(*corev1.ConfigMap); ok && cm.UID == "" {
				cm.UID = types.UID("uid-" + cm.Name)
			}
		}
		return false, nil, nil
	})
	kube.PrependReactor("create", "services", func(action kubetesting.Action) (bool, runtime.Object, error) {
		if create, ok := action.(kubetesting.CreateAction); ok {
			if svc, ok := create.GetObject().(*corev1.Service); ok && svc.UID == "" {
				svc.UID = types.UID("uid-" + svc.Name)
			}
		}
		return false, nil, nil
	})
	provider.kubeClient = kube
	provider.config.NodeLoadBalancer.DefaultNodeClass = "workers"
	nodeClass := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.inspace.cloud/v1", "kind": "InSpaceNodeClass",
		"metadata": map[string]any{"name": "workers"},
		"spec": map[string]any{
			"clusterName": provider.config.ClusterID, "location": provider.config.Location,
			"networkUUID":             provider.config.NetworkUUID,
			"privateLoadBalancerPool": map[string]any{"start": provider.config.PrivateLoadBalancerPoolStart, "stop": provider.config.PrivateLoadBalancerPoolStop},
			"rke2":                    map[string]any{"server": "https://" + provider.config.ControlPlaneVIP + ":9345"},
			"billingAccountID":        int64(provider.config.BillingAccountID),
			"firewallUUID":            base.UUID,
		},
		"status": map[string]any{"firewallUUID": base.UUID},
	}}
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Create(context.Background(), nodeClass, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	t.Cleanup(controller.queue.ShutDown)
	m := &migrationCluster{
		t: t, ctx: context.Background(), api: api, gate: gate, provider: provider, controller: controller, kube: kube,
		vms: vms, endpoints: map[string][]string{}, clock: time.Now().UTC(),
	}
	return m
}

func (m *migrationCluster) vm(name string) migrationVM {
	for _, vm := range m.vms {
		if vm.name == name {
			return vm
		}
	}
	m.t.Fatalf("no VM %s", name)
	return migrationVM{}
}

func (m *migrationCluster) now() time.Time { return m.clock }

// refreshEndpoints rebuilds the EndpointSlice lister from the endpoint map.
func (m *migrationCluster) refreshEndpoints() {
	m.t.Helper()
	ready, controller := true, true
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for _, name := range m.services {
		svc := m.service(name)
		endpoints := []discoveryv1.Endpoint{}
		for _, node := range m.endpoints[name] {
			nodeName := node
			endpoints = append(endpoints, discoveryv1.Endpoint{NodeName: &nodeName, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
		}
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: svc.Namespace, Name: svc.Name + "-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller,
				}},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   endpoints,
		}
		if err := indexer.Add(slice); err != nil {
			m.t.Fatal(err)
		}
	}
	m.controller.endpointSlices = discoverylisters.NewEndpointSliceLister(indexer)
}

func mgPort(protocol corev1.Protocol, port int32) corev1.ServicePort {
	return corev1.ServicePort{Name: fmt.Sprintf("%s-%d", strings.ToLower(string(protocol)), port), Protocol: protocol, Port: port, TargetPort: intstr.FromInt32(port)}
}

// addService creates a Service served from the named Nodes.
func (m *migrationCluster) addService(name, uid string, ports []corev1.ServicePort, nodes []string, ranges ...string) {
	m.t.Helper()
	pool := "edge"
	if len(nodes) != 0 {
		if vmPool := m.vm(nodes[0]).pool; vmPool != "" {
			pool = vmPool
		}
	}
	svc := publicNodeLocalTestService(name, uid, pool, corev1.ProtocolTCP, 1)
	svc.Spec.Ports = ports
	svc.Spec.LoadBalancerSourceRanges = ranges
	if _, err := m.kube.CoreV1().Services(svc.Namespace).Create(m.ctx, svc, metav1.CreateOptions{}); err != nil {
		m.t.Fatal(err)
	}
	m.services = append(m.services, name)
	m.endpoints[name] = nodes
	m.refreshEndpoints()
}

func (m *migrationCluster) service(name string) *corev1.Service {
	m.t.Helper()
	svc, err := m.kube.CoreV1().Services("default").Get(m.ctx, name, metav1.GetOptions{})
	if err != nil {
		m.t.Fatal(err)
	}
	return svc
}

func (m *migrationCluster) key(name string) string { return "default/" + name }

// publish drives the real Service pass of one Service until it is published on
// all its Nodes with no fence left.
func (m *migrationCluster) publish(name string) {
	m.t.Helper()
	for attempt := 0; attempt < 80; attempt++ {
		if err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name)); err != nil {
			m.t.Fatalf("publish %s, pass %d: %v", name, attempt, err)
		}
		svc := m.service(name)
		if len(svc.Status.LoadBalancer.Ingress) == len(m.endpoints[name]) && !publicNodeLocalAssignmentFencePresent(svc) {
			return
		}
	}
	m.t.Fatalf("%s did not publish: %#v", name, m.service(name).Annotations)
}

// switchToPerVM turns the controller into the perVM mode, as a restart with the
// flag does. The firewall limit gate stays.
func (m *migrationCluster) switchToPerVM(mode VMFirewallMigrationMode) {
	m.t.Helper()
	m.provider.config.NodeLoadBalancer.LocalFirewallMode = PublicNodeLocalFirewallModePerVM
	m.provider.config.NodeLoadBalancer.ControllerNamespace = vmTestNamespace
	m.provider.config.NodeLoadBalancer.VMFirewallSettle = 10 * time.Second
	m.provider.config.NodeLoadBalancer.VMFirewallMigration = mode
	m.restart()
}

// restart replaces the controller by a fresh one over the same cluster, as a
// crash and restart would.
func (m *migrationCluster) restart() {
	m.t.Helper()
	m.controller = &nodeLoadBalancerController{
		provider: m.provider, queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		endpointSlices:      m.controller.endpointSlices,
		firewallRelationNow: m.now, firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
		assignFenceNow: m.now,
	}
	m.t.Cleanup(m.controller.queue.ShutDown)
}

func (m *migrationCluster) annotateNode(vmName, value string) {
	m.t.Helper()
	node, err := m.kube.CoreV1().Nodes().Get(m.ctx, vmName, metav1.GetOptions{})
	if err != nil {
		m.t.Fatal(err)
	}
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	if value == "" {
		delete(node.Annotations, annotationPublicNodeLocalVMFirewallMigrate)
	} else {
		node.Annotations[annotationPublicNodeLocalVMFirewallMigrate] = value
	}
	if _, err := m.kube.CoreV1().Nodes().Update(m.ctx, node, metav1.UpdateOptions{}); err != nil {
		m.t.Fatal(err)
	}
}

func (m *migrationCluster) anchor(vm migrationVM) *corev1.ConfigMap {
	m.t.Helper()
	anchor, err := m.controller.getVMFirewallAnchor(m.ctx, vm.uuid)
	if err != nil {
		m.t.Fatal(err)
	}
	return anchor
}

// plan returns the migration record of a VM's anchor, or nil.
func (m *migrationCluster) plan(vm migrationVM) *vmFirewallMigrationPlan {
	m.t.Helper()
	anchor := m.anchor(vm)
	if anchor == nil {
		return nil
	}
	plan, ok, err := (vmFirewallAnchorView{cm: anchor}).migration()
	if err != nil {
		m.t.Fatal(err)
	}
	if !ok {
		return nil
	}
	return &plan
}

func (m *migrationCluster) firewallsOf(vm migrationVM) []inspace.Firewall {
	var out []inspace.Firewall
	for _, firewall := range m.api.firewalls {
		if vmFirewallAttachedTo(firewall, vm.uuid) {
			out = append(out, firewall)
		}
	}
	return out
}

// firewallOfService returns the per-Service firewall a v1.1.9 Service owns.
func (m *migrationCluster) firewallOfService(name string) *inspace.Firewall {
	uuid := m.service(name).Annotations[annotationNodeLoadBalancerFirewallUUID]
	for index := range m.api.firewalls {
		if m.api.firewalls[index].UUID == uuid {
			copied := m.api.firewalls[index]
			return &copied
		}
	}
	return nil
}

// tolerated says whether a pass error is a wait or a hold, not a fault.
func tolerableMigrationError(err error) bool {
	if err == nil {
		return true
	}
	var pending *nodeLoadBalancerFirewallRelationPendingError
	var settling *errPublicNodeLocalVMFirewallSettling
	var holding *errPublicNodeLocalHolding
	var limit *FirewallLimitExceededError
	return errors.As(err, &pending) || errors.As(err, &settling) || errors.As(err, &holding) || errors.As(err, &limit) ||
		strings.Contains(err.Error(), "waiting for")
}

// round runs one pass of every VM and every Service, tolerating waits and holds,
// and moves the clock on.
func (m *migrationCluster) round() map[string]error {
	m.t.Helper()
	errs := map[string]error{}
	m.clock = m.clock.Add(7 * time.Second)
	for _, vm := range m.vms {
		err := m.controller.syncVMFirewall(m.ctx, vm.uuid)
		if !tolerableMigrationError(err) {
			m.t.Fatalf("VM pass of %s: %v", vm.name, err)
		}
		errs["vm/"+vm.name] = err
	}
	for _, name := range m.services {
		err := m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name))
		if !tolerableMigrationError(err) {
			m.t.Fatalf("Service pass of %s: %v", name, err)
		}
		errs[name] = err
	}
	return errs
}

// runUntil repeats rounds until cond holds.
func (m *migrationCluster) runUntil(limit int, what string, cond func() bool) {
	m.t.Helper()
	var last map[string]error
	for pass := 0; pass < limit; pass++ {
		last = m.round()
		if cond() {
			return
		}
	}
	m.t.Fatalf("%s: never reached in %d rounds; last errors %v", what, limit, last)
}

// migrationObserverAPI reports every mutating cloud call to the cluster's
// observer, so an invariant is checked between any two calls and not only
// between passes.
type migrationObserverAPI struct {
	API
	m *migrationCluster
}

func (a *migrationObserverAPI) after(call string) {
	if a.m.observe != nil {
		a.m.observe(call)
	}
}

func (a *migrationObserverAPI) CreateFirewall(ctx context.Context, location string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	firewall, err := a.API.CreateFirewall(ctx, location, request)
	a.after("create " + request.DisplayName)
	return firewall, err
}

func (a *migrationObserverAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	firewall, err := a.API.UpdateFirewall(ctx, location, uuid, request)
	a.after("update " + uuid)
	return firewall, err
}

func (a *migrationObserverAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	err := a.API.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
	a.after("assign " + firewallUUID + "/" + vmUUID)
	return err
}

func (a *migrationObserverAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	err := a.API.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
	a.after("unassign " + firewallUUID + "/" + vmUUID)
	return err
}

func (a *migrationObserverAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	err := a.API.DeleteFirewall(ctx, location, uuid)
	a.after("delete " + uuid)
	return err
}

// trackCoverage records what every VM must keep allowing, from the firewalls it
// carries now, and from then on checks it after every mutating cloud call and
// records the number of firewalls each VM carries. The migration may move rules
// between firewalls; it may never leave a port that serves uncovered.
func (m *migrationCluster) trackCoverage() {
	m.t.Helper()
	base := publicNodeLocalTestBaseFirewall("").UUID
	required := map[string][]inspace.FirewallRule{}
	for _, vm := range m.vms {
		for _, firewall := range m.firewallsOf(vm) {
			if firewall.UUID != base {
				required[vm.uuid] = append(required[vm.uuid], firewall.Rules...)
			}
		}
	}
	m.required = required
	m.history = map[string][]int{}
	record := func() {
		for _, vm := range m.vms {
			count := len(m.firewallsOf(vm))
			if h := m.history[vm.uuid]; len(h) == 0 || h[len(h)-1] != count {
				m.history[vm.uuid] = append(h, count)
			}
		}
	}
	record()
	m.observe = func(call string) {
		record()
		for _, vm := range m.vms {
			allow := edgeAllowOf(m.firewallsOf(vm))
			for _, rule := range required[vm.uuid] {
				if !allow.covers(rule) {
					m.t.Errorf("after %q: VM %s no longer allows %s/%d %v", call, vm.name, rule.Protocol, *rule.PortStart, rule.EndpointSpec)
				}
			}
		}
	}
	m.provider.api = &migrationObserverAPI{API: m.provider.api, m: m}
}

// writes counts the mutating cloud calls so far.
func (m *migrationCluster) writes() int {
	return len(m.api.createdFirewalls) + len(m.api.updatedFirewalls) + len(m.api.assignedFirewalls) +
		len(m.api.unassignedFirewalls) + len(m.api.deletedFirewalls)
}
