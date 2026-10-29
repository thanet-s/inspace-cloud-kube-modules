package cloudprovider

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"

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
		objects = append(objects, publicNodeLocalTestNode(name, vmUUID, privateIP, publicIP))
	}
	base := publicNodeLocalTestBaseFirewall(vmTestVM)
	base.ResourcesAssigned = append(base.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmTestOtherVM})
	api.firewalls = append(api.firewalls, base)

	gate := &limitEnforcingFirewallAPI{API: api}
	provider := newTestProvider(t, gate)
	provider.kubeClient = kubefake.NewSimpleClientset(objects...)
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

// firewallCount is how many firewalls are attached to vmUUID in the fake cloud.
func (f *vmFirewallFixture) firewallCount(vmUUID string) int {
	return f.gate.countPerVM(f.ctx)[vmUUID]
}
