package cloudprovider

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

// relayServices serves several Services from the one edge VM, as the relay VM
// of th-live does, and drives them in turn.
type relayServices struct {
	f     *publicNodeLocalTransientFixture
	names []string
}

func relayEndpointSlices(t *testing.T, node string, services ...*corev1.Service) discoverylisters.EndpointSliceLister {
	t.Helper()
	ready, controller := true, true
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	for _, service := range services {
		nodeName := node
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: service.Namespace, Name: service.Name + "-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: service.Name},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID, Controller: &controller,
				}},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{NodeName: &nodeName, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		}
		if err := indexer.Add(slice); err != nil {
			t.Fatal(err)
		}
	}
	return discoverylisters.NewEndpointSliceLister(indexer)
}

func relayPorts(ports ...corev1.ServicePort) func(*corev1.Service) {
	return func(s *corev1.Service) {
		s.Spec.Ports = nil
		for _, port := range ports {
			port.TargetPort = intstr.FromInt32(port.Port)
			s.Spec.Ports = append(s.Spec.Ports, port)
		}
	}
}

func relayPort(protocol corev1.Protocol, port int32) corev1.ServicePort {
	return corev1.ServicePort{Name: fmt.Sprintf("%s-%d", protocol, port), Protocol: protocol, Port: port}
}

// add creates a Service served by the one edge Node.
func (r *relayServices) add(t *testing.T, name, uid string, shape func(*corev1.Service)) *corev1.Service {
	t.Helper()
	service := publicNodeLocalTestService(name, uid, "edge", corev1.ProtocolTCP, 1)
	shape(service)
	created, err := r.f.provider.kubeClient.CoreV1().Services(service.Namespace).Create(r.f.ctx, service, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r.names = append(r.names, name)
	all := make([]*corev1.Service, 0, len(r.names))
	for _, known := range r.names {
		current, getErr := r.f.provider.kubeClient.CoreV1().Services(created.Namespace).Get(r.f.ctx, known, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		all = append(all, current)
	}
	node, _, _, _ := publicNodeLocalFixtureNode(0)
	r.f.controller.endpointSlices = relayEndpointSlices(t, node, all...)
	return created
}

func (r *relayServices) get(t *testing.T, name string) *corev1.Service {
	t.Helper()
	current, err := r.f.provider.kubeClient.CoreV1().Services(r.f.service.Namespace).Get(r.f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return current
}

// round runs one pass of every Service, tolerating only waits and holds.
func (r *relayServices) round(t *testing.T) []error {
	t.Helper()
	var errs []error
	for _, name := range r.names {
		service := r.get(t, name)
		err := r.f.controller.syncPublicNodeLocal(r.f.ctx, service.Namespace+"/"+name, service)
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		var settling *errPublicNodeLocalVMFirewallSettling
		var limit *FirewallLimitExceededError
		waiting := err != nil && strings.Contains(err.Error(), "waiting for")
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) && !errors.As(err, &settling) && !errors.As(err, &limit) && !waiting {
			t.Fatalf("%s: %v", name, err)
		}
		errs = append(errs, err)
	}
	return errs
}

func (r *relayServices) services(t *testing.T) []*corev1.Service {
	t.Helper()
	out := make([]*corev1.Service, 0, len(r.names))
	for _, name := range r.names {
		out = append(out, r.get(t, name))
	}
	return out
}

// runUntil drives rounds, checking the edge invariant of every Service on every
// round, until cond holds.
func (r *relayServices) runUntil(t *testing.T, limit int, what string, cond func() bool) {
	t.Helper()
	var last []error
	for round := 0; round < limit; round++ {
		last = r.round(t)
		requireVMEdgeSafe(t, r.f, r.services(t)...)
		if cond() {
			return
		}
	}
	t.Fatalf("%s: never reached; last round %v", what, last)
}

func (r *relayServices) published(t *testing.T, names ...string) func() bool {
	return func() bool {
		for _, name := range names {
			s := r.get(t, name)
			if len(s.Status.LoadBalancer.Ingress) != 1 || publicNodeLocalAssignmentFencePresent(s) {
				return false
			}
		}
		return true
	}
}

func newRelayFixture(t *testing.T, mode PublicNodeLocalFirewallMode) *relayServices {
	t.Helper()
	previousMode, previousGated := publicNodeLocalTestMode, publicNodeLocalTestGated
	publicNodeLocalTestMode, publicNodeLocalTestGated = mode, true
	t.Cleanup(func() { publicNodeLocalTestMode, publicNodeLocalTestGated = previousMode, previousGated })
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalPorts(1935))
	r := &relayServices{f: f, names: []string{f.service.Name}}
	return r
}

// The relay VM of th-live: RTMP production on 1935, RTMP staging on 1936 from
// one range, then the web ports. The VM ends with the base firewall and one
// per-VM firewall, and a range change of the staging Service completes
// make-before-break, which three per-Service firewalls could not do.
func TestPerVMRelayShapeThreeServices(t *testing.T) {
	r := newRelayFixture(t, PublicNodeLocalFirewallModePerVM)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	requireVMEdgeSafe(t, r.f)

	r.add(t, "relay-staging", "relay-staging-uid", func(s *corev1.Service) {
		relayPorts(relayPort(corev1.ProtocolTCP, 1936))(s)
		s.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	})
	r.runUntil(t, 200, "the staging Service is published", r.published(t, "edge", "relay-staging"))
	r.add(t, "relay-web", "relay-web-uid", relayPorts(
		relayPort(corev1.ProtocolTCP, 80), relayPort(corev1.ProtocolTCP, 443), relayPort(corev1.ProtocolUDP, 443)))
	r.runUntil(t, 300, "the web Service is published", r.published(t, "edge", "relay-staging", "relay-web"))
	if got := len(vmFirewallsOfVM(r.f, vm0)); got != 2 {
		t.Fatalf("the relay VM carries %d firewalls, want the base and one per-VM firewall: %#v", got, vmFirewallsOfVM(r.f, vm0))
	}
	var rules int
	for _, firewall := range vmFirewallsOfVM(r.f, vm0) {
		if _, isVM := parseVMFirewallNameForTest(r.f, firewall.EffectiveName()); isVM {
			rules = len(firewall.Rules)
		}
	}
	if rules != 5 {
		t.Fatalf("the per-VM firewall has %d rules, want 5 (1935, 1936, 80, 443/tcp, 443/udp)", rules)
	}

	// A range change of the staging Service, made while the other two serve.
	before := r.get(t, "relay-staging").Annotations[annotationPublicNodeLocalActivePolicy]
	current := r.get(t, "relay-staging")
	current.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"}
	if _, err := r.f.provider.kubeClient.CoreV1().Services(current.Namespace).Update(r.f.ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	r.runUntil(t, 400, "the range change completes", func() bool {
		s := r.get(t, "relay-staging")
		return s.Annotations[annotationPublicNodeLocalActivePolicy] != before && s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			!publicNodeLocalOldEdgePending(s) && !publicNodeLocalAssignmentFencePresent(s)
	})
	if r.f.gate.maxObservedFirewallsPerVM > 2 {
		t.Fatalf("a VM carried %d firewalls", r.f.gate.maxObservedFirewallsPerVM)
	}
	if got := len(vmFirewallsOfVM(r.f, vm0)); got != 2 {
		t.Fatalf("the relay VM carries %d firewalls after the change, want 2", got)
	}
}

// With one firewall per Service, the third Service on the relay VM runs into the
// firewall limit and never opens: the v1.1.9 behaviour the per-VM mode removes.
func TestPerServiceRelayShapeRefusesThirdService(t *testing.T) {
	r := newRelayFixture(t, PublicNodeLocalFirewallModePerService)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	r.add(t, "relay-staging", "relay-staging-uid", func(s *corev1.Service) {
		relayPorts(relayPort(corev1.ProtocolTCP, 1936))(s)
		s.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	})
	r.runUntil(t, 200, "the staging Service is published", r.published(t, "edge", "relay-staging"))
	r.add(t, "relay-web", "relay-web-uid", relayPorts(relayPort(corev1.ProtocolTCP, 80), relayPort(corev1.ProtocolTCP, 443)))
	for round := 0; round < 60; round++ {
		r.round(t)
		requireVMEdgeSafe(t, r.f, r.services(t)...)
	}
	if len(r.get(t, "relay-web").Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("the third Service published beyond the firewall limit: %#v", r.get(t, "relay-web").Status)
	}
	if got := len(vmFirewallsOfVM(r.f, vm0)); got != 3 {
		t.Fatalf("the VM carries %d firewalls, want the base and two Service firewalls", got)
	}
	events, err := r.f.provider.kubeClient.CoreV1().Events("default").List(r.f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for _, event := range events.Items {
		refused = refused || event.Reason == "FirewallLimitExceeded"
	}
	if !refused {
		t.Fatal("no FirewallLimitExceeded Event was recorded for the refused attach")
	}
}
