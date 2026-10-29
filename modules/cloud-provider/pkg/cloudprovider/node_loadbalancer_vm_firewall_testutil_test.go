package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// perVMTestFirewall builds a per-VM firewall for vmUUID that is attached to
// vmUUID and carries one inbound TCP rule per port, open to any source.
func perVMTestFirewall(t *testing.T, cluster, vmUUID string, uuid string, ports ...int32) inspace.Firewall {
	t.Helper()
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]inspace.FirewallRule, 0, len(ports))
	for _, port := range ports {
		p := port
		rules = append(rules, inspace.FirewallRule{
			Protocol: "tcp", Direction: "inbound", PortStart: &p, PortEnd: &p, EndpointSpecType: "any",
		})
	}
	return inspace.Firewall{
		UUID: uuid, Name: name, DisplayName: name, BillingAccountID: 42,
		Description: inspace.NodeLoadBalancerVMFirewallDescription,
		Rules:       rules,
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: vmUUID},
		},
	}
}

// vmTestRule builds one ledger rule. No sources means any source.
func vmTestRule(protocol string, port int32, sources ...string) vmFirewallRule {
	if sources == nil {
		sources = []string{}
	}
	return vmFirewallRule{Protocol: protocol, Port: port, Sources: sources}
}

// vmTestMember builds a ledger member whose policy hash is the real one.
func vmTestMember(t *testing.T, uid string, rules ...vmFirewallRule) vmFirewallMember {
	t.Helper()
	member := vmFirewallMember{UID: uid, Rules: rules}
	policy, err := inspace.NodeLoadBalancerServiceFirewallSpecHash(vmFirewallMemberFirewallRules(member))
	if err != nil {
		t.Fatal(err)
	}
	member.Policy = policy
	return member
}

// vmTestLedger builds a ledger with the given members, in the order given.
func vmTestLedger(members ...vmFirewallMember) vmFirewallLedger {
	return vmFirewallLedger{V: 1, Members: members}
}

// limitEnforcingFirewallAPI refuses an attach that would leave a VM with more
// firewalls than limit, with a dispatched 400 like production, and records the
// most firewalls any VM ever carried after a mutation.
type limitEnforcingFirewallAPI struct {
	API
	limit                      int
	maxObservedFirewallsPerVM  int
	refusedAttaches            int
	attachesAttemptedPerVMUUID map[string]int
}

func (a *limitEnforcingFirewallAPI) countPerVM(ctx context.Context) map[string]int {
	counts := map[string]int{}
	items, err := a.API.ListFirewalls(ctx, "bkk01")
	if err != nil {
		return counts
	}
	for _, fw := range items {
		seen := map[string]bool{}
		for _, row := range fw.ResourcesAssigned {
			if strings.EqualFold(row.ResourceType, "vm") && !seen[row.ResourceUUID] {
				seen[row.ResourceUUID] = true
				counts[row.ResourceUUID]++
			}
		}
	}
	return counts
}

func (a *limitEnforcingFirewallAPI) observe(ctx context.Context) {
	for _, n := range a.countPerVM(ctx) {
		if n > a.maxObservedFirewallsPerVM {
			a.maxObservedFirewallsPerVM = n
		}
	}
}

func (a *limitEnforcingFirewallAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if a.attachesAttemptedPerVMUUID == nil {
		a.attachesAttemptedPerVMUUID = map[string]int{}
	}
	a.attachesAttemptedPerVMUUID[vmUUID]++
	limit := a.limit
	if limit < 1 {
		limit = int(DefaultMaxFirewallsPerVM)
	}
	items, err := a.API.ListFirewalls(ctx, location)
	if err != nil {
		return err
	}
	attached := 0
	already := false
	for _, fw := range items {
		for _, row := range fw.ResourcesAssigned {
			if strings.EqualFold(row.ResourceType, "vm") && strings.EqualFold(row.ResourceUUID, vmUUID) {
				attached++
				if strings.EqualFold(fw.UUID, firewallUUID) {
					already = true
				}
				break
			}
		}
	}
	if !already && attached+1 > limit {
		a.refusedAttaches++
		return &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/firewall/vms", Message: "firewall limit"}
	}
	err = a.API.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
	a.observe(ctx)
	return err
}

// vmFirewallFixture is a small cluster for the per-VM firewall library: two
// healthy VMs with their Nodes and the base firewall, a fake clock, and the
// anchor namespace.
type vmFirewallFixture struct {
	t          *testing.T
	ctx        context.Context
	api        *fakeAPI
	gate       *limitEnforcingFirewallAPI
	provider   *Provider
	controller *nodeLoadBalancerController
	clock      time.Time
}

const vmTestNamespace = "kube-system"

func newVMFirewallFixture(t *testing.T) *vmFirewallFixture {
	t.Helper()
	api := &fakeAPI{}
	objects := []runtime.Object{}
	for index, vmUUID := range []string{vmTestVM, vmTestOtherVM} {
		name := fmt.Sprintf("edge-%d", index+1)
		privateIP := fmt.Sprintf("10.0.0.%d", 21+index)
		publicIP := fmt.Sprintf("203.0.113.%d", 21+index)
		api.vms = append(api.vms, inspace.VM{
			UUID: vmUUID, Name: name, Hostname: name, Status: "running",
			PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID,
		})
		node := publicNodeLocalTestNode(name, vmUUID, privateIP, publicIP)
		node.Labels[nodeLoadBalancerNodeLabel] = "true"
		node.Labels[nodeLoadBalancerNodeClusterLabel] = "unit-test-cluster"
		objects = append(objects, node)
	}
	base := publicNodeLocalTestBaseFirewall(vmTestVM)
	base.ResourcesAssigned = append(base.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmTestOtherVM})
	api.firewalls = append(api.firewalls, base)

	gate := &limitEnforcingFirewallAPI{API: api}
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
	provider.kubeClient = kube
	provider.config.NodeLoadBalancer.ControllerNamespace = vmTestNamespace
	f := &vmFirewallFixture{
		t: t, ctx: context.Background(), api: api, gate: gate, provider: provider,
		clock: time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC),
	}
	f.controller = f.newController()
	return f
}

func (f *vmFirewallFixture) newController() *nodeLoadBalancerController {
	return &nodeLoadBalancerController{
		provider:                    f.provider,
		firewallRelationNow:         func() time.Time { return f.clock },
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
}

// restart replaces the controller by a fresh one over the same cluster and
// cloud, as a crash and restart would.
func (f *vmFirewallFixture) restart() { f.controller = f.newController() }

func (f *vmFirewallFixture) advance(d time.Duration) { f.clock = f.clock.Add(d) }

// addService creates a Service with the given UID that owns the given ports.
func (f *vmFirewallFixture) addService(uid string, ports ...int32) *corev1.Service {
	f.t.Helper()
	service := publicNodeLocalTestService("svc-"+uid, uid, "edge", corev1.ProtocolTCP, ports[0])
	service.Spec.Ports = nil
	for _, port := range ports {
		service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolTCP, Port: port})
	}
	if _, err := f.provider.kubeClient.CoreV1().Services(service.Namespace).Create(f.ctx, service, metav1.CreateOptions{}); err != nil {
		f.t.Fatal(err)
	}
	return service
}

// members lists the Services of the cluster, as the Service pass would.
func (f *vmFirewallFixture) members(ctx context.Context) []*corev1.Service {
	list, err := f.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		f.t.Fatal(err)
	}
	out := make([]*corev1.Service, 0, len(list.Items))
	for index := range list.Items {
		out = append(out, list.Items[index].DeepCopy())
	}
	return out
}

// member builds the ledger entry a Service asks for.
func (f *vmFirewallFixture) member(service *corev1.Service) vmFirewallMember {
	f.t.Helper()
	desired, err := f.controller.desiredServiceFirewall(service)
	if err != nil {
		f.t.Fatal(err)
	}
	member, err := vmFirewallMemberFromDesired(string(service.UID), desired)
	if err != nil {
		f.t.Fatal(err)
	}
	return member
}

func (f *vmFirewallFixture) events() []corev1.Event {
	list, err := f.provider.kubeClient.CoreV1().Events(metav1.NamespaceAll).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		f.t.Fatal(err)
	}
	return list.Items
}

func (f *vmFirewallFixture) eventsFor(reason string) []corev1.Event {
	out := []corev1.Event{}
	for _, event := range f.events() {
		if event.Reason == reason {
			out = append(out, event)
		}
	}
	return out
}

// anchor returns the anchor of vmUUID, or nil.
func (f *vmFirewallFixture) anchor(vmUUID string) *corev1.ConfigMap {
	f.t.Helper()
	anchor, err := f.controller.getVMFirewallAnchor(f.ctx, vmUUID)
	if err != nil {
		f.t.Fatal(err)
	}
	return anchor
}

// vmFirewall returns the per-VM firewall of vmUUID from the fake cloud, or nil.
func (f *vmFirewallFixture) vmFirewall(vmUUID string) *inspace.Firewall {
	name, err := inspace.NodeLoadBalancerVMFirewallName(f.provider.config.ClusterID, vmUUID)
	if err != nil {
		f.t.Fatal(err)
	}
	for index := range f.api.firewalls {
		if f.api.firewalls[index].EffectiveName() == name {
			copy := f.api.firewalls[index]
			return &copy
		}
	}
	return nil
}

// seedVMFirewall puts a settled per-VM firewall into the fake cloud together
// with its anchor: the firewall carries the merged rules of members, and the
// anchor records them as applied. The firewall is attached to vmUUID when
// attached is true.
func (f *vmFirewallFixture) seedVMFirewall(vmUUID, firewallUUID string, attached bool, members ...vmFirewallMember) *corev1.ConfigMap {
	f.t.Helper()
	ledger := vmTestLedger(members...)
	encoded, err := encodeVMFirewallLedger(ledger)
	if err != nil {
		f.t.Fatal(err)
	}
	merged, err := mergeVMFirewallLedger(ledger)
	if err != nil {
		f.t.Fatal(err)
	}
	hash, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged)
	if err != nil {
		f.t.Fatal(err)
	}
	name, err := inspace.NodeLoadBalancerVMFirewallName(f.provider.config.ClusterID, vmUUID)
	if err != nil {
		f.t.Fatal(err)
	}
	rules := retainFirewallRuleUUIDs(nil, merged)
	for index := range rules {
		rules[index].UUID = fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", index+1)
	}
	firewall := inspace.Firewall{UUID: firewallUUID, DisplayName: name, BillingAccountID: 42, Rules: rules}
	if attached {
		firewall.ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}}
	}
	f.api.firewalls = append(f.api.firewalls, firewall)
	anchor, err := f.controller.createVMFirewallAnchor(f.ctx, vmUUID)
	if err != nil {
		f.t.Fatal(err)
	}
	updated, _, err := f.controller.updateVMFirewallAnchor(f.ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		cm.Annotations[annotationVMFirewallUUID] = firewallUUID
		cm.Annotations[annotationVMFirewallApplied] = encoded
		cm.Annotations[annotationVMFirewallAppliedHash] = hash
		cm.Annotations[annotationVMFirewallAppliedAt] = f.clock.Format(time.RFC3339Nano)
		return true, nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return updated
}

// setAnchor applies mutate to the anchor of vmUUID.
func (f *vmFirewallFixture) setAnchor(vmUUID string, mutate func(map[string]string)) *corev1.ConfigMap {
	f.t.Helper()
	updated, _, err := f.controller.updateVMFirewallAnchor(f.ctx, f.anchor(vmUUID), func(cm *corev1.ConfigMap) (bool, error) {
		mutate(cm.Annotations)
		return true, nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return updated
}

// addForeignFirewall attaches an unrelated valid-looking firewall to vmUUID.
func (f *vmFirewallFixture) addForeignFirewall(vmUUID string, index int) {
	f.api.firewalls = append(f.api.firewalls, inspace.Firewall{
		UUID:              fmt.Sprintf("77777777-0000-4000-8000-%012d", index),
		DisplayName:       fmt.Sprintf("foreign-%d", index),
		BillingAccountID:  42,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	})
}

// firewallCount is how many firewalls are attached to vmUUID in the fake cloud.
func (f *vmFirewallFixture) firewallCount(vmUUID string) int {
	return f.gate.countPerVM(f.ctx)[vmUUID]
}

// newPerVMPublicNodeLocalFixture is newPublishedPublicNodeLocalFixtureN on the
// per-VM firewall mode: the namespace of the anchors is set, the settle delay
// is as short as the clock allows, every VM carries the base firewall, and the
// provider API refuses an attach beyond the firewall limit and records the most
// firewalls any VM ever carried. The Service is published on n Nodes.
func newPerVMPublicNodeLocalFixture(t *testing.T, n int) *publicNodeLocalTransientFixture {
	return newPerVMPublicNodeLocalFixtureWith(t, n, nil)
}

func newPerVMPublicNodeLocalFixtureWith(t *testing.T, n int, shape func(*corev1.Service)) *publicNodeLocalTransientFixture {
	t.Helper()
	f := buildPerVMPublicNodeLocalFixture(t, n, shape)
	for attempt := 0; attempt < 200; attempt++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var settling *errPublicNodeLocalVMFirewallSettling
		var pending *nodeLoadBalancerFirewallRelationPendingError
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &settling) && !errors.As(err, &pending) && !errors.As(err, &holding) {
			t.Fatalf("publish reconcile %d: %v", attempt, err)
		}
		current := f.current(t)
		if len(current.Status.LoadBalancer.Ingress) == n && !publicNodeLocalAssignmentFencePresent(current) {
			return f
		}
	}
	t.Fatalf("per-VM fixture did not publish: %#v", f.current(t).Annotations)
	return nil
}

// buildPerVMPublicNodeLocalFixture builds the fixture without running a pass.
func buildPerVMPublicNodeLocalFixture(t *testing.T, n int, shape func(*corev1.Service)) *publicNodeLocalTransientFixture {
	t.Helper()
	service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	if shape != nil {
		shape(service)
	}
	api := &fakeAPI{}
	objects := []runtime.Object{service.DeepCopy()}
	nodeNames := make([]string, 0, n)
	base := publicNodeLocalTestBaseFirewall("")
	base.ResourcesAssigned = nil
	for i := 0; i < n; i++ {
		name, vmUUID, privateIP, publicIP := publicNodeLocalFixtureNode(i)
		node := publicNodeLocalTestNode(name, vmUUID, privateIP, publicIP)
		api.vms = append(api.vms, inspace.VM{UUID: vmUUID, Name: node.Name, Hostname: node.Name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID})
		api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		})
		base.ResourcesAssigned = append(base.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
		objects = append(objects, node.DeepCopy())
		nodeNames = append(nodeNames, name)
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
	provider.kubeClient = kube
	provider.config.NodeLoadBalancer.LocalFirewallMode = PublicNodeLocalFirewallModePerVM
	provider.config.NodeLoadBalancer.ControllerNamespace = vmTestNamespace
	provider.config.NodeLoadBalancer.VMFirewallSettle = time.Nanosecond
	controller := &nodeLoadBalancerController{
		provider:       provider,
		assignFenceNow: testAssignFenceClock,
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	t.Cleanup(controller.queue.ShutDown)
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, nodeNames...)
	fixture := &publicNodeLocalTransientFixture{
		ctx: context.Background(), api: api, provider: provider, controller: controller,
		service: service, key: service.Namespace + "/" + service.Name, endpointNodes: nodeNames,
		gate: gate,
	}
	fixture.requireGateClean(t)
	return fixture
}

// edgeAllows is the effective inbound allow set of a VM: for every
// protocol/port the sources of all its firewalls; nil means any source.
type edgeAllowSet map[string]map[string]struct{}

func edgeAllowKey(rule inspace.FirewallRule) (string, bool) {
	if !strings.EqualFold(rule.Direction, "inbound") || rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
		return "", false
	}
	return fmt.Sprintf("%s/%d", strings.ToLower(rule.Protocol), *rule.PortStart), true
}

func edgeAllowOf(firewalls []inspace.Firewall) edgeAllowSet {
	allow := edgeAllowSet{}
	for _, firewall := range firewalls {
		for _, rule := range firewall.Rules {
			key, ok := edgeAllowKey(rule)
			if !ok {
				continue
			}
			if rule.EndpointSpecType != "ip_prefixes" {
				allow[key] = nil
				continue
			}
			if existing, seen := allow[key]; seen && existing == nil {
				continue
			}
			if allow[key] == nil {
				allow[key] = map[string]struct{}{}
			}
			for _, source := range rule.EndpointSpec {
				allow[key][source] = struct{}{}
			}
		}
	}
	return allow
}

// covers reports whether the allow set admits every source of the rule.
func (a edgeAllowSet) covers(rule inspace.FirewallRule) bool {
	key, ok := edgeAllowKey(rule)
	if !ok {
		return true
	}
	sources, open := a[key]
	if !open {
		return false
	}
	if sources == nil {
		return true
	}
	if rule.EndpointSpecType != "ip_prefixes" {
		return false
	}
	for _, source := range rule.EndpointSpec {
		if _, ok := sources[source]; !ok {
			return false
		}
	}
	return true
}

// servicePolicyRules lists, one entry per policy, the rules the edge holds for a
// Service: the ledger entries on the VM anchors, or the Service firewalls.
func servicePolicyRules(f *publicNodeLocalTransientFixture, service *corev1.Service) [][]inspace.FirewallRule {
	var policies [][]inspace.FirewallRule
	if publicNodeLocalServicePerVM(service) {
		anchors, err := f.controller.listVMFirewallAnchors(f.ctx)
		if err != nil {
			return nil
		}
		seen := map[vmFirewallMemberKey]bool{}
		for index := range anchors {
			ledger, err := (vmFirewallAnchorView{cm: &anchors[index]}).applied()
			if err != nil {
				continue
			}
			for _, member := range ledger.Members {
				if member.UID == string(service.UID) && !seen[member.key()] {
					seen[member.key()] = true
					policies = append(policies, vmFirewallMemberFirewallRules(member))
				}
			}
		}
		return policies
	}
	prefix := nodeLoadBalancerFirewallServicePrefix(f.provider.config.ClusterID, string(service.UID))
	for _, firewall := range f.api.firewalls {
		if strings.HasPrefix(firewall.EffectiveName(), prefix) {
			policies = append(policies, firewall.Rules)
		}
	}
	return policies
}

// requireVMEdgeSafe is the invariant every pass of every scenario keeps, on
// either firewall mode:
//
//  1. every published FIP is on a VM whose attached firewalls together allow
//     every port of the Service's active policy, from at least its sources;
//  2. no VM carries a Service's rules without the Service's child VIP on it;
//  3. no VM ever carried more firewalls than the limit, and no attach was
//     refused by it (the controller itself never tries a fourth).
func requireVMEdgeSafe(t *testing.T, f *publicNodeLocalTransientFixture, services ...*corev1.Service) {
	t.Helper()
	if err := vmEdgeViolation(f, services...); err != nil {
		t.Fatal(err)
	}
}

// vmEdgeViolation is requireVMEdgeSafe returning what it found, so a test can
// prove the invariant fails on a mutation.
func vmEdgeViolation(f *publicNodeLocalTransientFixture, services ...*corev1.Service) error {
	if len(services) == 0 {
		services = []*corev1.Service{f.service}
	}
	nodes, err := f.provider.kubeClient.CoreV1().Nodes().List(f.ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	vmOfPublic := map[string]string{}
	privateOfVM := map[string]string{}
	poolOfVM := map[string]string{}
	for index := range nodes.Items {
		node := &nodes.Items[index]
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			continue
		}
		poolOfVM[vmUUID] = node.Labels[publicNodeLocalPoolLabel]
		if public, ok := nodeLoadBalancerNodeExternalIPv4(node); ok {
			vmOfPublic[public] = vmUUID
		}
		if private, ok := nodeLoadBalancerNodeInternalIPv4(node); ok {
			privateOfVM[vmUUID] = private
		}
	}
	for _, raw := range services {
		service, err := f.provider.kubeClient.CoreV1().Services(raw.Namespace).Get(f.ctx, raw.Name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		policies := servicePolicyRules(f, service)
		withdrawing := service.DeletionTimestamp != nil || service.Annotations[annotationNodeLoadBalancerRebuilding] != ""
		if !withdrawing && len(service.Status.LoadBalancer.Ingress) != 0 && len(policies) == 0 {
			// A published Service whose edge records no policy at all would pass any
			// coverage check vacuously.
			return fmt.Errorf("Service %s is published but no firewall or ledger records any policy for it", service.Name)
		}
		// Without a change pending, the spec is the oracle: it does not come from
		// the controller state that could be the thing that is wrong.
		var steady []inspace.FirewallRule
		if desired, derr := f.controller.desiredServiceFirewall(service); derr == nil &&
			service.Annotations[annotationPublicNodeLocalActivePolicy] == desired.Hash &&
			service.Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
			steady = desired.Request.Rules
		}
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			vmUUID, known := vmOfPublic[ingress.IP]
			if !known {
				continue
			}
			// A published VM carries at least one whole policy of its Service: the
			// active one, the target one while the union runs, or the old one while it
			// is retired. A withdrawal closes the firewall first, by design.
			allow := edgeAllowOf(vmFirewallsOfVM(f, vmUUID))
			covered := withdrawing
			if !withdrawing && steady != nil && poolOfVM[vmUUID] == service.Annotations[annotationPublicNodeLocalActivePool] {
				covered = true
				for _, rule := range steady {
					covered = covered && allow.covers(rule)
				}
				if !covered {
					return fmt.Errorf("FIP %s on VM %s is published but its firewalls do not allow the rules the Service spec asks for: %#v",
						ingress.IP, vmUUID, vmFirewallsOfVM(f, vmUUID))
				}
			}
			for _, rules := range policies {
				whole := true
				for _, rule := range rules {
					whole = whole && allow.covers(rule)
				}
				covered = covered || whole
			}
			if !covered {
				return fmt.Errorf("FIP %s on VM %s is published but its firewalls cover no whole policy of the Service %d: %#v",
					ingress.IP, vmUUID, len(policies), vmFirewallsOfVM(f, vmUUID))
			}
		}
		var child *corev1.Service
		if object, getErr := f.provider.kubeClient.CoreV1().Services(service.Namespace).Get(f.ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{}); getErr == nil {
			child = object
		}
		for _, firewall := range f.api.firewalls {
			if _, isVM := inspace.ParseNodeLoadBalancerVMFirewallName(f.provider.config.ClusterID, firewall.EffectiveName()); !isVM &&
				!strings.HasPrefix(firewall.EffectiveName(), nodeLoadBalancerFirewallServicePrefix(f.provider.config.ClusterID, string(service.UID))) {
				continue
			}
			carries := false
			if publicNodeLocalServicePerVM(service) {
				anchors, listErr := f.controller.listVMFirewallAnchors(f.ctx)
				if listErr == nil {
					for index := range anchors {
						view := vmFirewallAnchorView{cm: &anchors[index]}
						if view.uuid() == firewall.UUID && len(view.memberKeys(string(service.UID))) != 0 {
							carries = true
						}
					}
				}
			} else {
				carries = strings.HasPrefix(firewall.EffectiveName(), nodeLoadBalancerFirewallServicePrefix(f.provider.config.ClusterID, string(service.UID)))
			}
			if !carries || child == nil {
				continue
			}
			vips := publicNodeLocalIngressSet(child.Status.LoadBalancer)
			if len(vips) == 0 {
				// A child that was lost and recreated is being repaired from the edge.
				continue
			}
			for _, row := range firewall.ResourcesAssigned {
				if private := privateOfVM[row.ResourceUUID]; private != "" {
					if _, has := vips[private]; !has {
						return fmt.Errorf("VM %s carries the rules of Service %s without its child VIP %s: vips=%v", row.ResourceUUID, service.Name, private, vips)
					}
				}
			}
		}
	}
	if f.gate != nil {
		limit := f.gate.limit
		if limit < 1 {
			limit = int(DefaultMaxFirewallsPerVM)
		}
		if f.gate.maxObservedFirewallsPerVM > limit {
			return fmt.Errorf("a VM carried %d firewalls, limit %d", f.gate.maxObservedFirewallsPerVM, limit)
		}
		if f.gate.refusedAttaches != 0 {
			return fmt.Errorf("%d attaches ran into the firewall limit: the controller must never try a fourth", f.gate.refusedAttaches)
		}
	}
	return nil
}

// requireSteadyFirewallCount requires exactly want firewalls on each of the
// first nodes VMs, the steady state of a single Service: the base firewall and
// one more.
func requireSteadyFirewallCount(t *testing.T, f *publicNodeLocalTransientFixture, nodes, want int) {
	t.Helper()
	for index := 0; index < nodes; index++ {
		_, vmUUID, _, _ := publicNodeLocalFixtureNode(index)
		if got := len(vmFirewallsOfVM(f, vmUUID)); got != want {
			t.Fatalf("VM %d carries %d firewalls, want %d: %#v", index, got, want, vmFirewallsOfVM(f, vmUUID))
		}
	}
}

// perVMEntryPolicies is how many policies of the Service the anchor of vmUUID
// lists.
func perVMEntryPolicies(t *testing.T, f *publicNodeLocalTransientFixture, service *corev1.Service, vmUUID string) int {
	t.Helper()
	anchor, err := f.controller.getVMFirewallAnchor(f.ctx, vmUUID)
	if err != nil || anchor == nil {
		return 0
	}
	return len((vmFirewallAnchorView{cm: anchor}).memberKeys(string(service.UID)))
}

// perVMFixtureBaseFirewallUUID is the base firewall every VM of a gated fixture
// carries, so a steady VM shows the two firewalls of production.
const perVMFixtureBaseFirewallUUID = "22222222-2222-4222-8222-222222222222"

// publicNodeLocalTestMode is the firewall mode the shared fixtures run in. The
// dual-mode scenario test sets it for the length of one scenario.
var publicNodeLocalTestMode = PublicNodeLocalFirewallModePerService

// publicNodeLocalTestGated makes the per-Service fixtures carry the base
// firewall and the firewall limit gate too, so the same invariant runs on both
// modes. Only the dual-mode scenario test sets it.
var publicNodeLocalTestGated = false

// gateFixture gives a built fixture the base firewall on every VM and a
// provider API that enforces the firewall limit and records the peak count. A
// scenario that ever drove a VM past the limit, or tried to, fails when it ends.
func (f *publicNodeLocalTransientFixture) gateFixture(t *testing.T) {
	t.Helper()
	if f.gate != nil {
		return
	}
	inner := f.provider.api
	if inner == API(f.api) {
		inner = &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}
	}
	f.gate = &limitEnforcingFirewallAPI{API: inner}
	f.provider.api = f.gate
	base := publicNodeLocalTestBaseFirewall("")
	base.ResourcesAssigned = nil
	for _, vm := range f.api.vms {
		base.ResourcesAssigned = append(base.ResourcesAssigned, inspaceVMResource(vm.UUID))
	}
	f.api.firewalls = append(f.api.firewalls, base)
	f.requireGateClean(t)
}

// requireGateClean registers the end-of-scenario check of the firewall limit.
func (f *publicNodeLocalTransientFixture) requireGateClean(t *testing.T) {
	t.Cleanup(func() {
		limit := f.gate.limit
		if limit < 1 {
			limit = int(DefaultMaxFirewallsPerVM)
		}
		if f.gate.maxObservedFirewallsPerVM > limit {
			t.Errorf("a VM carried %d firewalls, limit %d", f.gate.maxObservedFirewallsPerVM, limit)
		}
		if f.gate.refusedAttaches != 0 {
			t.Errorf("%d attaches ran into the firewall limit: the controller must never try one", f.gate.refusedAttaches)
		}
	})
}

// attachFixtureBaseFirewall puts the base firewall on a VM added to a fixture
// that has one, as Karpenter does when it creates the VM.
func (f *publicNodeLocalTransientFixture) attachFixtureBaseFirewall(vmUUID string) {
	for index := range f.api.firewalls {
		if f.api.firewalls[index].UUID != perVMFixtureBaseFirewallUUID {
			continue
		}
		for _, row := range f.api.firewalls[index].ResourcesAssigned {
			if row.ResourceUUID == vmUUID {
				return
			}
		}
		f.api.firewalls[index].ResourcesAssigned = append(f.api.firewalls[index].ResourcesAssigned, inspaceVMResource(vmUUID))
	}
}

func inspaceVMResource(vmUUID string) inspace.FirewallResource {
	return inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID}
}

// vmFirewallsOfVM lists the firewalls attached to vmUUID in the fake cloud.
func vmFirewallsOfVM(f *publicNodeLocalTransientFixture, vmUUID string) []inspace.Firewall {
	var out []inspace.Firewall
	for _, firewall := range f.api.firewalls {
		for _, row := range firewall.ResourcesAssigned {
			if strings.EqualFold(row.ResourceType, "vm") && strings.EqualFold(row.ResourceUUID, vmUUID) {
				out = append(out, firewall)
				break
			}
		}
	}
	return out
}
