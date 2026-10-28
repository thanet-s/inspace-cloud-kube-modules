package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// The incumbent keeps its claim from the parent's own state. A child that is
// absent, unparsable or unreadable must hold, never lose.
func TestPublicNodeLocalIncumbencyDoesNotDependOnChildReadability(t *testing.T) {
	const childReadFailure = "child read failure"
	tests := []struct {
		name    string
		prepare func(*testing.T, *kubefake.Clientset, *corev1.Service)
	}{
		{name: "child absent", prepare: func(t *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			if err := kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("services"), child.Namespace, child.Name); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "child ports unparsable", prepare: func(t *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			broken := child.DeepCopy()
			broken.Spec.Ports = nil
			if err := kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("services"), broken, broken.Namespace); err != nil {
				t.Fatal(err)
			}
		}},
		{name: childReadFailure, prepare: func(_ *testing.T, kube *kubefake.Clientset, child *corev1.Service) {
			kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.GetAction).GetName() == child.Name {
					return true, nil, errors.New("child read failed")
				}
				return false, nil, nil
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			incumbent := publicNodeLocalTestService("incumbent", "z-service-uid", "edge", corev1.ProtocolTCP, 443)
			incumbent.Annotations[annotationPublicNodeLocalActivePool] = "edge"
			incumbent.Annotations[annotationPublicNodeLocalActivePolicy] = "policy"
			child := desiredPublicNodeLocalDatapath(incumbent, "edge")
			newcomer := publicNodeLocalTestService("newcomer", "a-service-uid", "edge", corev1.ProtocolTCP, 443)
			provider := newTestProvider(t, &fakeAPI{})
			kube := kubefake.NewSimpleClientset(incumbent.DeepCopy(), newcomer.DeepCopy(), child)
			provider.kubeClient = kube
			controller := &nodeLoadBalancerController{provider: provider}
			test.prepare(t, kube, child)

			intent, err := parseNodeLoadBalancerService(incumbent, nodeLoadBalancerDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			// A child that cannot be read must never make the incumbent lose; it
			// either holds the claim or reports an error, and the parent state
			// alone already proves the claim here.
			loses, _, err := controller.publicNodeLocalPortConflict(context.Background(), incumbent, intent)
			if loses {
				t.Fatalf("the incumbent lost its claim to a lower-UID newcomer: %v", err)
			}
			// The newcomer still loses to the incumbent, whatever the child says.
			if test.name == childReadFailure {
				return
			}
			newcomerIntent, err := parseNodeLoadBalancerService(newcomer, nodeLoadBalancerDefaults{})
			if err != nil {
				t.Fatal(err)
			}
			if loses, _, err := controller.publicNodeLocalPortConflict(context.Background(), newcomer, newcomerIntent); !loses {
				t.Fatalf("the newcomer won against the incumbent: %v", err)
			}
		})
	}
}

// A published Node that is verifiably excluded leaves the edge even while its
// local endpoint is still Ready. Only real ambiguity holds a Node.
func TestPublicNodeLocalVerifiedIneligiblePublishedNodeIsRemoved(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *publicNodeLocalTransientFixture)
		// foreign leaves only the public FIP to remove: the relation fence never
		// touches a VM of another billing account.
		foreign bool
	}{
		{name: "excluded from load balancers", mutate: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureNode(t, f, "edge-1", func(node *corev1.Node) {
				node.Labels[corev1.LabelNodeExcludeBalancers] = "true"
			})
		}},
		{name: "control-plane role", mutate: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureNode(t, f, "edge-1", func(node *corev1.Node) {
				node.Labels[nodeRoleControlPlaneLabel] = ""
			})
		}},
		{name: "billing account mismatch", foreign: true, mutate: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.api.vms[1].BillingAccountID = 99
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			_, _, priv1, pub1 := publicNodeLocalFixtureNode(0)
			_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
			test.mutate(t, f)
			done := false
			for pass := 0; pass < 40 && !done; pass++ {
				err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
				var holding *errPublicNodeLocalHolding
				if err != nil && !(test.foreign && errors.As(err, &holding)) {
					t.Fatalf("pass %d: %v", pass, err)
				}
				observed := observePublicNodeLocal(t, f)
				if !observed.fips[pub1] || !observed.vips[priv1] {
					t.Fatalf("pass %d: the remaining node left the edge: %#v", pass, observed)
				}
				done = !observed.fips[pub2]
				if !test.foreign {
					done = done && !observed.vips[priv2] && !observed.assigned[vm2]
				}
			}
			if !done {
				t.Fatalf("the ineligible published node stayed on the edge: %#v", observePublicNodeLocal(t, f))
			}
		})
	}
}

func updatePublicNodeLocalFixtureNode(t *testing.T, f *publicNodeLocalTransientFixture, name string, mutate func(*corev1.Node)) {
	t.Helper()
	node, err := f.provider.kubeClient.CoreV1().Nodes().Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mutate(node)
	if _, err := f.provider.kubeClient.CoreV1().Nodes().Update(f.ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// An InSpaceNodeClass that is no longer a public-node-local class is verified
// intent: the Node leaves. An absent class stays ambiguous and holds.
func TestPublicNodeLocalNodeClassWithoutProfileIsGone(t *testing.T) {
	f := newPublicNodeLocalAuditFixture(t)
	class, err := f.provider.dynamicClient.Resource(nodeClassGVR).Get(f.ctx, "edge-workers", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(class.Object, "default", "spec", "firewallProfile"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.provider.dynamicClient.Resource(nodeClassGVR).Update(f.ctx, class, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	verdict, err := f.verdict(t, nil)
	if err != nil || verdict.kind != publicNodeLocalNodeGone {
		t.Fatalf("verdict = %#v err=%v, want a gone node", verdict, err)
	}

	if err := f.provider.dynamicClient.Resource(nodeClassGVR).Delete(f.ctx, "edge-workers", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	verdict, err = f.verdict(t, nil)
	if verdict.kind == publicNodeLocalNodeGone || verdict.kind == publicNodeLocalNodeAuthorized {
		t.Fatalf("an absent class was treated as %#v (err=%v), want an ambiguous node", verdict, err)
	}
}

// While no Node has a Ready endpoint, the per-node grace does not run. One pod
// that comes back must not remove every other Node at once.
func TestPublicNodeLocalGraceRestartsWhenAnEndpointReturns(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 3)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	_, _, _, pub1 := publicNodeLocalFixtureNode(0)
	_, _, _, pub2 := publicNodeLocalFixtureNode(1)
	_, _, _, pub3 := publicNodeLocalFixtureNode(2)
	run := func(passes int) {
		t.Helper()
		for pass := 0; pass < passes; pass++ {
			err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
			var holding *errPublicNodeLocalHolding
			if err != nil && !errors.As(err, &holding) {
				t.Fatalf("pass %d: %v", pass, err)
			}
		}
	}
	f.setEndpoints(t)
	run(2)
	now = now.Add(time.Hour)
	run(2)

	f.setEndpoints(t, "edge-0")
	run(4)
	if observed := observePublicNodeLocal(t, f); !observed.fips[pub2] || !observed.fips[pub3] {
		t.Fatalf("one returning pod removed the other Nodes at once: %#v", observed)
	}
	now = now.Add(publicNodeLocalEndpointGoneGrace + time.Second)
	run(20)
	if observed := observePublicNodeLocal(t, f); observed.fips[pub2] || observed.fips[pub3] || !observed.fips[pub1] {
		t.Fatalf("the Nodes without an endpoint stayed after the grace: %#v", observed)
	}
}

// After the child is recreated or its class is repaired, every kept and
// published Node gets its VIP back, whether or not it is Ready right now.
func TestPublicNodeLocalChildRepairRestoresVIPsOfEveryKeptNode(t *testing.T) {
	_, vm2, _, _ := publicNodeLocalFixtureNode(1)
	tests := []struct {
		name  string
		setup func(*testing.T, *publicNodeLocalTransientFixture)
	}{
		{name: "zero Ready endpoints", setup: func(t *testing.T, f *publicNodeLocalTransientFixture) { f.setEndpoints(t) }},
		{name: "one endpoint missing", setup: func(t *testing.T, f *publicNodeLocalTransientFixture) { f.setEndpoints(t, "edge-0") }},
		{name: "one Node unverified", setup: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.provider.api = &vmGetErrorAPI{
				publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api},
				badVM:                         vm2, err: errors.New("canonical ownership read failed"),
			}
		}},
	}
	for _, repair := range []string{"child deleted", "child class drift"} {
		for _, test := range tests {
			t.Run(repair+"/"+test.name, func(t *testing.T) {
				f := newPublishedPublicNodeLocalFixtureN(t, 2)
				_, _, priv1, _ := publicNodeLocalFixtureNode(0)
				_, _, priv2, _ := publicNodeLocalFixtureNode(1)
				test.setup(t, f)
				childName := nodeLoadBalancerDatapathName(f.service)
				if repair == "child deleted" {
					if err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Delete(f.ctx, childName, metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				} else {
					drifted := trackedPublicNodeLocalDatapath(t, f)
					// A real apiserver assigns the UID that the replacement is fenced on.
					drifted.UID = "child-datapath-uid"
					other := "example.com/other"
					drifted.Spec.LoadBalancerClass = &other
					if _, err := f.provider.kubeClient.CoreV1().Services(drifted.Namespace).Update(f.ctx, drifted, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				parentBefore := f.current(t)
				restored := false
				for pass := 0; pass < 20 && !restored; pass++ {
					err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
					var holding *errPublicNodeLocalHolding
					if err != nil && !errors.As(err, &holding) {
						t.Fatalf("pass %d: %v", pass, err)
					}
					if !reflect.DeepEqual(f.current(t).Status, parentBefore.Status) {
						t.Fatalf("pass %d: the parent FIPs changed: %#v", pass, f.current(t).Status)
					}
					if len(f.api.unassignedFirewalls) != 0 {
						t.Fatalf("pass %d: a firewall was detached: %v", pass, f.api.unassignedFirewalls)
					}
					if child := trackedPublicNodeLocalDatapathOrNil(f); child != nil {
						restored = len(child.Status.LoadBalancer.Ingress) == 2
						if restored && (!observePublicNodeLocal(t, f).vips[priv1] || !observePublicNodeLocal(t, f).vips[priv2]) {
							t.Fatalf("pass %d: the wrong VIPs were restored: %#v", pass, child.Status.LoadBalancer)
						}
					}
				}
				if !restored {
					t.Fatalf("the VIPs of the kept nodes were not restored: %#v", observePublicNodeLocal(t, f))
				}
			})
		}
	}
}

// neverAppliesAssignAPI accepts a firewall assignment for one VM and never
// applies it, which leaves an add stuck for as long as the test runs.
type neverAppliesAssignAPI struct {
	*publicNodeLocalFilteringIPAPI
	stuckVM string
}

func (a *neverAppliesAssignAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if vmUUID == a.stuckVM {
		return nil
	}
	return a.publicNodeLocalFilteringIPAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

// A stuck add must not starve the removal of a Node that is proven gone.
func TestPublicNodeLocalStuckAddDoesNotStarveGoneRemoval(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm3, _, _ := publicNodeLocalFixtureNode(2)
	f.provider.api = &neverAppliesAssignAPI{
		publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, stuckVM: vm3,
	}
	f.addNode(t, 2)
	f.provider.api = &neverAppliesAssignAPI{
		publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, stuckVM: vm3,
	}
	name2, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, "edge-0", "edge-2")
	for pass := 0; pass < 30; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub2] && !observed.vips[priv2] && !observed.assigned[vm2] {
			return
		}
	}
	t.Fatalf("the gone node stayed on the edge behind the stuck add: %#v", observePublicNodeLocal(t, f))
}

// A cloud answer alone (an empty VPC member list) never withdraws the whole
// Service after one observation. It takes two reads that are spaced apart.
func TestPublicNodeLocalFullWithdrawNeedsSpacedConfirmationFromCloudOnlyEvidence(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	f.api.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}
	before := f.current(t)
	childBefore := trackedPublicNodeLocalDatapath(t, f)

	for pass := 0; pass < 12; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &holding) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if !reflect.DeepEqual(f.current(t).Status, before.Status) || len(f.api.unassignedFirewalls) != 0 ||
			!reflect.DeepEqual(trackedPublicNodeLocalDatapath(t, f).Status, childBefore.Status) {
			t.Fatalf("pass %d: one observation of an empty member list withdrew the Service", pass)
		}
	}
	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	for pass := 0; pass < 60; pass++ {
		// With an empty member list the relation fence itself refuses to touch
		// the VMs, so the attempt shows as a fail-closed error.
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &holding) && strings.Contains(err.Error(), "failing closed") {
			return
		}
		if current := f.current(t); len(current.Status.LoadBalancer.Ingress) == 0 &&
			current.Annotations[annotationPublicNodeLocalActivePool] == "" {
			return
		}
	}
	t.Fatalf("the second spaced observation did not withdraw the Service: %#v", f.current(t).Status)
}

// A recovered member list resets the confirmation.
func TestPublicNodeLocalFullWithdrawConfirmationResetsWhenNodesReturn(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	good := f.api.network
	f.api.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}
	for pass := 0; pass < 3; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	}
	f.api.network = good
	now = now.Add(time.Minute)
	for pass := 0; pass < 3; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	}
	f.api.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}
	for pass := 0; pass < 12; pass++ {
		// A withdrawal attempt would report a fail-closed error here.
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &holding) {
			t.Fatalf("pass %d tried to withdraw on a first observation: %v", pass, err)
		}
	}
	if got := len(f.current(t).Status.LoadBalancer.Ingress); got != 2 {
		t.Fatalf("an earlier observation counted after the member list recovered: %d FIPs", got)
	}
}

// Publishing a FIP on a serving Service is gated like the bootstrap: after the
// status write the VIP and the firewall assignment of the added VM are read
// back. A failed readback must not leave the new FIP published.
func TestPublicNodeLocalActivePublishReadsBackVIPAndAssignment(t *testing.T) {
	tests := []struct {
		name    string
		onWrite func(*testing.T, *publicNodeLocalTransientFixture, *kubefake.Clientset)
	}{
		{name: "child VIP missing after the write", onWrite: func(t *testing.T, f *publicNodeLocalTransientFixture, kube *kubefake.Clientset) {
			child := trackedPublicNodeLocalDatapath(t, f)
			_, _, priv2, _ := publicNodeLocalFixtureNode(1)
			kept := child.Status.LoadBalancer.Ingress[:0:0]
			for _, ingress := range child.Status.LoadBalancer.Ingress {
				if ingress.IP != priv2 {
					kept = append(kept, ingress)
				}
			}
			child.Status.LoadBalancer.Ingress = kept
			if err := kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("services"), child, child.Namespace); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "firewall assignment missing after the write", onWrite: func(t *testing.T, f *publicNodeLocalTransientFixture, _ *kubefake.Clientset) {
			_, vm2, _, _ := publicNodeLocalFixtureNode(1)
			for index := range f.api.firewalls {
				resources := f.api.firewalls[index].ResourcesAssigned[:0:0]
				for _, resource := range f.api.firewalls[index].ResourcesAssigned {
					if resource.ResourceUUID != vm2 {
						resources = append(resources, resource)
					}
				}
				f.api.firewalls[index].ResourcesAssigned = resources
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			kube := f.provider.kubeClient.(*kubefake.Clientset)
			f.addNode(t, 1)
			_, _, _, pub1 := publicNodeLocalFixtureNode(0)
			_, _, _, pub2 := publicNodeLocalFixtureNode(1)
			armed := false
			kube.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
				update := action.(k8stesting.UpdateAction)
				if update.GetSubresource() != "status" || update.GetObject().(*corev1.Service).Name != f.service.Name {
					return false, nil, nil
				}
				// Let the write through first, then break the proof it relied on.
				object := update.GetObject()
				if err := kube.Tracker().Update(update.GetResource(), object, update.GetNamespace()); err != nil {
					return true, nil, err
				}
				if !armed {
					armed = true
					test.onWrite(t, f, kube)
				}
				return true, object, nil
			})
			sawGateFailure := false
			for pass := 0; pass < 40; pass++ {
				err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
				var holding *errPublicNodeLocalHolding
				if err != nil && !errors.As(err, &holding) {
					t.Fatalf("pass %d: %v", pass, err)
				}
				if armed {
					if err == nil {
						t.Fatalf("pass %d: the failed readback was not reported", pass)
					}
					sawGateFailure = true
					break
				}
			}
			if !sawGateFailure {
				t.Fatal("the FIP was never published, so the gate never ran")
			}
			status := f.current(t).Status.LoadBalancer.Ingress
			if len(status) != 1 || status[0].IP != pub1 {
				t.Fatalf("the unproven FIP %s stayed published: %#v", pub2, status)
			}
		})
	}
}

// A hold whose cause never changes backs off from the hold delay up to a cap,
// and the Event tells the operator how long the hold has lasted.
func TestPublicNodeLocalUnchangingHoldBacksOffExponentially(t *testing.T) {
	f := newPublishedPublicNodeLocalFixture(t)
	corrupt := func() {
		updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
			delete(s.Annotations, annotationPublicNodeLocalActivePolicy)
		})
	}
	corrupt()
	var delays []time.Duration
	for pass := 0; pass < 12; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		delay, fixed := nodeLoadBalancerRequeueDelay(err)
		if !fixed {
			t.Fatalf("pass %d: error %v has no fixed requeue delay", pass, err)
		}
		delays = append(delays, delay)
	}
	if delays[0] != nodeLoadBalancerRetry {
		t.Fatalf("first hold delay = %s, want %s", delays[0], nodeLoadBalancerRetry)
	}
	for index := 1; index < len(delays); index++ {
		if delays[index] < delays[index-1] || delays[index] > publicNodeLocalHoldBackoffMax {
			t.Fatalf("delays %v are not a capped non-decreasing backoff", delays)
		}
	}
	if delays[1] != 2*nodeLoadBalancerRetry || delays[len(delays)-1] != publicNodeLocalHoldBackoffMax {
		t.Fatalf("delays %v do not double up to the %s cap", delays, publicNodeLocalHoldBackoffMax)
	}
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalHolding")
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalHoldBackoff")

	// A pass that makes progress resets the backoff.
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Annotations[annotationPublicNodeLocalActivePolicy] = f.current(t).Annotations[annotationNodeLoadBalancerFirewallHash]
	})
	if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
		t.Fatalf("healthy pass: %v", err)
	}
	corrupt()
	err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	if delay, _ := nodeLoadBalancerRequeueDelay(err); delay != nodeLoadBalancerRetry {
		t.Fatalf("the backoff survived a healthy pass: %s", delay)
	}
}

// The Event name derives from the reason and a stable cause class, never from
// the full cause text, so a changing message updates one Event.
func TestPublicNodeLocalHoldEventNameIgnoresCauseText(t *testing.T) {
	f := newPublishedPublicNodeLocalFixture(t)
	service := f.current(t)
	for _, text := range []string{"first cause 1", "second cause 2", "third cause 3"} {
		if err := f.controller.recordPublicNodeLocalHoldEvent(f.ctx, service, "PublicNodeLocalHolding", errors.New(text)); err != nil {
			t.Fatal(err)
		}
	}
	events, err := f.provider.kubeClient.CoreV1().Events(service.Namespace).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 {
		t.Fatalf("%d Events for one reason and cause class, want 1: %#v", len(events.Items), events.Items)
	}
	if got := events.Items[0].Message; !strings.Contains(got, "third cause 3") {
		t.Fatalf("the Event kept a stale message: %q", got)
	}
	if events.Items[0].Count != 3 {
		t.Fatalf("Event count = %d, want 3", events.Items[0].Count)
	}
}

func setPublicNodeLocalFixturePorts(t *testing.T, f *publicNodeLocalTransientFixture, ports ...int32) {
	t.Helper()
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		base := s.Spec.Ports[0]
		s.Spec.Ports = nil
		for index, port := range ports {
			next := base
			next.Name = fmt.Sprintf("p%d", index)
			next.Port = port
			next.TargetPort = intstr.FromInt32(port)
			s.Spec.Ports = append(s.Spec.Ports, next)
		}
	})
}

// runPublicNodeLocalPasses drives passes and tolerates only holds and waits.
func runPublicNodeLocalPasses(t *testing.T, f *publicNodeLocalTransientFixture, passes int, stop func() bool) {
	t.Helper()
	for pass := 0; pass < passes; pass++ {
		if current := f.current(t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
			// Deleting the superseded firewall needs spaced absence reads.
			ageNodeLoadBalancerAbsenceEvidence(t, f.ctx, f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
		}
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		// A withdrawal reports its wait for the detachment readback as an error.
		waiting := err != nil && strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback")
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) && !waiting {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if stop != nil && stop() {
			return
		}
	}
}

// While a pool or policy change is pending, the active exposure keeps
// converging under the active pool and policy, and the pass requeues.
func TestPublicNodeLocalPendingTransitionKeepsConvergingUnderActiveIdentity(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *publicNodeLocalTransientFixture)
	}{
		{name: "pool change", change: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "other" })
		}},
		{name: "port widening", change: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			childPortsBefore := trackedPublicNodeLocalDatapath(t, f).Spec.Ports
			activeBefore := f.current(t).Annotations
			test.change(t, f)
			name2, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
			_, vm1, priv1, pub1 := publicNodeLocalFixtureNode(0)
			if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			f.setEndpoints(t, "edge-0")
			runPublicNodeLocalPasses(t, f, 40, func() bool {
				observed := observePublicNodeLocal(t, f)
				return !observed.fips[pub2] && !observed.vips[priv2] && !observed.assigned[vm2]
			})
			observed := observePublicNodeLocal(t, f)
			if observed.fips[pub2] || observed.vips[priv2] || observed.assigned[vm2] {
				t.Fatalf("the gone node stayed on the edge while the change was pending: %#v", observed)
			}
			if !observed.fips[pub1] || !observed.vips[priv1] || !observed.assigned[vm1] {
				t.Fatalf("the remaining node left the edge: %#v", observed)
			}
			current := f.current(t)
			for _, key := range []string{annotationPublicNodeLocalActivePool, annotationPublicNodeLocalActivePolicy} {
				if current.Annotations[key] != activeBefore[key] {
					t.Fatalf("the active identity %s changed: %q -> %q", key, activeBefore[key], current.Annotations[key])
				}
			}
			if !reflect.DeepEqual(trackedPublicNodeLocalDatapath(t, f).Spec.Ports, childPortsBefore) {
				t.Fatalf("the child ports followed the pending change")
			}
			// A settled pass holds, requeues and says why.
			settled := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
			var holding *errPublicNodeLocalHolding
			if !errors.As(settled, &holding) {
				t.Fatalf("a pending change returned %v, want a hold that requeues", settled)
			}
			if delay, fixed := nodeLoadBalancerRequeueDelay(settled); !fixed || delay <= 0 {
				t.Fatalf("no requeue delay for %v", settled)
			}
			requirePublicNodeLocalEvent(t, f, "PublicNodeLocalTransitionPending")
		})
	}
}

// A pool change keeps the full incremental convergence, adds included.
func TestPublicNodeLocalPendingPoolChangeStillAddsNodesUnderActivePool(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "other" })
	f.addNode(t, 1)
	_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	runPublicNodeLocalPasses(t, f, 60, func() bool {
		observed := observePublicNodeLocal(t, f)
		return observed.fips[pub2] && observed.vips[priv2] && observed.assigned[vm2] && !publicNodeLocalAssignmentFencePresent(f.current(t))
	})
	if observed := observePublicNodeLocal(t, f); !observed.fips[pub2] || !observed.vips[priv2] || !observed.assigned[vm2] {
		t.Fatalf("the added node never joined under the active pool: %#v", observed)
	}
	if got := f.current(t).Annotations[annotationPublicNodeLocalActivePool]; got != "edge" {
		t.Fatalf("active pool = %q", got)
	}
}

func shapePublicNodeLocalPorts(ports ...int32) func(*corev1.Service) {
	return func(s *corev1.Service) {
		base := s.Spec.Ports[0]
		s.Spec.Ports = nil
		for index, port := range ports {
			next := base
			next.Name = fmt.Sprintf("p%d", index)
			next.Port = port
			next.TargetPort = intstr.FromInt32(port)
			s.Spec.Ports = append(s.Spec.Ports, next)
		}
	}
}

func firewallRuleOn(protocol string, port int32, sources ...string) inspace.FirewallRule {
	rule := inspace.FirewallRule{
		Protocol: protocol, Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	if len(sources) != 0 {
		rule.EndpointSpecType = "ip_prefixes"
		rule.EndpointSpec = sources
	}
	return rule
}

func TestPublicNodeLocalRulesNarrow(t *testing.T) {
	tests := []struct {
		name     string
		old, new []inspace.FirewallRule
		want     bool
	}{
		{name: "fewer ports", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443), firewallRuleOn("tcp", 8443)}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, want: true},
		{name: "any to a prefix", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8")}, want: true},
		{name: "prefix to a subset prefix", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8")}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.1.0.0/16")}, want: true},
		{name: "fewer prefixes", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8", "192.168.0.0/16")}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "192.168.0.0/16")}, want: true},
		{name: "extra port", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443), firewallRuleOn("tcp", 8443)}},
		{name: "different port", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 8443)}},
		{name: "different protocol", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, new: []inspace.FirewallRule{firewallRuleOn("udp", 443)}},
		{name: "prefix to any", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8")}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}},
		{name: "superset prefix", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.1.0.0/16")}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8")}},
		{name: "mixed: one narrowed one added", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.0.0.0/8")}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443, "10.1.0.0/16"), firewallRuleOn("tcp", 9000)}},
		{name: "identical", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}, new: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}},
		{name: "nothing left", old: []inspace.FirewallRule{firewallRuleOn("tcp", 443)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := publicNodeLocalRulesNarrow(test.old, test.new); got != test.want {
				t.Fatalf("narrow(%v -> %v) = %t, want %t", test.old, test.new, got, test.want)
			}
		})
	}
}

// reconcileUntilRepublished drives passes until the Service serves the policy
// of its current spec on every Node.
func reconcileUntilRepublished(t *testing.T, f *publicNodeLocalTransientFixture, nodes, passes int) {
	t.Helper()
	runPublicNodeLocalPasses(t, f, passes, func() bool {
		current := f.current(t)
		desired, err := f.controller.desiredServiceFirewall(current)
		return err == nil && len(current.Status.LoadBalancer.Ingress) == nodes &&
			current.Annotations[annotationPublicNodeLocalActivePolicy] == desired.Hash &&
			!publicNodeLocalAssignmentFencePresent(current)
	})
}

// A strict narrowing is verified intent and is applied promptly.
func TestPublicNodeLocalStrictNarrowingIsApplied(t *testing.T) {
	tests := []struct {
		name   string
		shape  func(*corev1.Service)
		narrow func(*testing.T, *publicNodeLocalTransientFixture)
	}{
		{name: "fewer ports", shape: shapePublicNodeLocalPorts(443, 8443), narrow: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			setPublicNodeLocalFixturePorts(t, f, 443)
		}},
		{name: "any source to a prefix", narrow: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"} })
		}},
		{name: "prefix to a subset", shape: func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"} }, narrow: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.1.0.0/16"} })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureWith(t, 2, test.shape)
			oldFirewall := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
			oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
			test.narrow(t, f)
			reconcileUntilRepublished(t, f, 2, 80)
			current := f.current(t)
			desired, err := f.controller.desiredServiceFirewall(current)
			if err != nil {
				t.Fatal(err)
			}
			if current.Annotations[annotationPublicNodeLocalActivePolicy] != desired.Hash || desired.Hash == oldPolicy {
				t.Fatalf("the narrowed policy was not applied: active=%q desired=%q old=%q",
					current.Annotations[annotationPublicNodeLocalActivePolicy], desired.Hash, oldPolicy)
			}
			if len(current.Status.LoadBalancer.Ingress) != 2 {
				t.Fatalf("the Service did not republish: %#v", current.Status.LoadBalancer)
			}
			for _, firewall := range f.api.firewalls {
				if firewall.UUID == oldFirewall {
					t.Fatalf("the wider firewall %s still exists", oldFirewall)
				}
			}
			if !publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), current, "edge") {
				t.Fatalf("the child does not follow the narrowed spec")
			}
		})
	}
}

// A widening stays held, and so does a mix of narrowing and widening.
func TestPublicNodeLocalWideningStaysHeld(t *testing.T) {
	tests := []struct {
		name   string
		shape  func(*corev1.Service)
		change func(*testing.T, *publicNodeLocalTransientFixture)
	}{
		{name: "more ports", change: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
		}},
		{name: "prefix to any", shape: func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"} }, change: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = nil })
		}},
		{name: "swapped port", change: func(t *testing.T, f *publicNodeLocalTransientFixture) { setPublicNodeLocalFixturePorts(t, f, 8443) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureWith(t, 1, test.shape)
			before := f.current(t)
			unassigned := len(f.api.unassignedFirewalls)
			test.change(t, f)
			for pass := 0; pass < 6; pass++ {
				err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
				var holding *errPublicNodeLocalHolding
				if !errors.As(err, &holding) {
					t.Fatalf("pass %d: %v, want a hold", pass, err)
				}
			}
			after := f.current(t)
			if !reflect.DeepEqual(after.Status, before.Status) ||
				after.Annotations[annotationPublicNodeLocalActivePolicy] != before.Annotations[annotationPublicNodeLocalActivePolicy] ||
				len(f.api.unassignedFirewalls) != unassigned {
				t.Fatalf("a widening was applied: %#v", after.Annotations)
			}
			requirePublicNodeLocalEvent(t, f, "PublicNodeLocalTransitionPending")
		})
	}
}

// The operator escape hatch permits the old withdraw and rebuild.
func TestPublicNodeLocalAllowRebuildAnnotationPermitsWithdrawAndRebuild(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	// Without the annotation the change stays held.
	if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err == nil {
		t.Fatal("the widening was not held")
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
	reconcileUntilRepublished(t, f, 1, 80)
	current := f.current(t)
	if current.Annotations[annotationPublicNodeLocalActivePolicy] == oldPolicy {
		t.Fatalf("the rebuild never happened: %#v", current.Annotations)
	}
	if len(f.api.unassignedFirewalls) == 0 {
		t.Fatal("the old exposure was not withdrawn")
	}
}

// nthCallAPI counts GetVM and ListFirewalls calls and fails the Nth call of
// one kind. A zero failOn only counts.
type nthCallAPI struct {
	API
	failKind string
	failOn   int
	err      error
	calls    map[string]int
}

func (a *nthCallAPI) hit(kind string) error {
	a.calls[kind]++
	if kind == a.failKind && a.calls[kind] == a.failOn {
		return a.err
	}
	return nil
}

func (a *nthCallAPI) GetVM(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	if err := a.hit("GetVM"); err != nil {
		return nil, err
	}
	return a.API.GetVM(ctx, location, uuid)
}

func (a *nthCallAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	if err := a.hit("ListFirewalls"); err != nil {
		return nil, err
	}
	return a.API.ListFirewalls(ctx, location)
}

// nthSweepScenario is one pass of an add or a remove sequence.
type nthSweepScenario struct {
	name string
	// setup builds the fixture and moves it to the start of the sequence.
	setup func(*testing.T) *publicNodeLocalTransientFixture
	// done reports that the sequence is complete.
	done func(*testing.T, *publicNodeLocalTransientFixture) bool
	// safe checks the invariants that must hold after every pass.
	safe func(*testing.T, *publicNodeLocalTransientFixture)
}

func newNthAddScenario() nthSweepScenario {
	_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	_, _, priv1, pub1 := publicNodeLocalFixtureNode(0)
	return nthSweepScenario{
		name: "add",
		setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			f.addNode(t, 1)
			return f
		},
		done: func(t *testing.T, f *publicNodeLocalTransientFixture) bool {
			o := observePublicNodeLocal(t, f)
			return o.fips[pub2] && o.vips[priv2] && o.assigned[vm2] && !publicNodeLocalAssignmentFencePresent(f.current(t))
		},
		safe: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			o := observePublicNodeLocal(t, f)
			if !o.fips[pub1] || !o.vips[priv1] {
				t.Fatalf("the serving node left the edge: %#v", o)
			}
			if len(f.api.unassignedFirewalls) != 0 {
				t.Fatalf("a firewall was detached: %v", f.api.unassignedFirewalls)
			}
			o.requireMakeBeforeBreak(t, -1, 1)
		},
	}
}

func newNthRemoveScenario() nthSweepScenario {
	name2, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	_, vm1, priv1, pub1 := publicNodeLocalFixtureNode(0)
	return nthSweepScenario{
		name: "remove",
		setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			f.setEndpoints(t, "edge-0")
			return f
		},
		done: func(t *testing.T, f *publicNodeLocalTransientFixture) bool {
			o := observePublicNodeLocal(t, f)
			return !o.fips[pub2] && !o.vips[priv2] && !o.assigned[vm2]
		},
		safe: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			o := observePublicNodeLocal(t, f)
			if !o.fips[pub1] || !o.vips[priv1] || !o.assigned[vm1] {
				t.Fatalf("the remaining node left the edge: %#v", o)
			}
			if len(f.api.unassignedFirewalls) != 0 && o.fips[pub2] {
				t.Fatalf("the firewall was detached while the FIP was still published: %#v", o)
			}
			if !o.vips[priv2] && o.assigned[vm2] {
				t.Fatalf("the child VIP left before the firewall was detached: %#v", o)
			}
		},
	}
}

// A single provider call that fails in any pass of an add or a remove must leave
// the edge safe, and the sequence must finish once the provider recovers. The
// number of calls is measured first, so every call of every pass is covered and
// nothing is skipped.
func TestPublicNodeLocalIncrementalSequencesSurviveNthProviderFailure(t *testing.T) {
	definite := errors.New("canonical ownership mismatch")
	for _, scenario := range []nthSweepScenario{newNthAddScenario(), newNthRemoveScenario()} {
		for pass := 0; pass < 5; pass++ {
			for _, kind := range []string{"GetVM", "ListFirewalls"} {
				// Measure the calls of this pass on a clean run.
				probe := scenario.setup(t)
				runPublicNodeLocalPasses(t, probe, pass, nil)
				base := probe.provider.api
				counter := &nthCallAPI{API: base, calls: map[string]int{}}
				probe.provider.api = counter
				_ = probe.controller.syncPublicNodeLocal(probe.ctx, probe.key, probe.current(t))
				total := counter.calls[kind]
				for n := 1; n <= total; n++ {
					for _, transient := range []bool{true, false} {
						name := fmt.Sprintf("%s/pass %d/%s call %d/transient=%t", scenario.name, pass, kind, n, transient)
						t.Run(name, func(t *testing.T) {
							f := scenario.setup(t)
							runPublicNodeLocalPasses(t, f, pass, nil)
							failure := definite
							if transient {
								failure = transientProviderError()
							}
							base := f.provider.api
							failing := &nthCallAPI{API: base, failKind: kind, failOn: n, err: failure, calls: map[string]int{}}
							f.provider.api = failing
							err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
							f.provider.api = base
							if failing.calls[kind] < n {
								t.Fatalf("the pass made only %d %s calls, the probe saw %d", failing.calls[kind], kind, total)
							}
							var holding *errPublicNodeLocalHolding
							var pending *nodeLoadBalancerFirewallRelationPendingError
							if err != nil && transient && !inspace.IsTransient(err) {
								t.Fatalf("a transient failure became definite: %v", err)
							}
							if err != nil && !transient && !errors.As(err, &holding) && !errors.As(err, &pending) {
								t.Fatalf("a definite failure was not held: %v", err)
							}
							scenario.safe(t, f)
							// The provider recovers and the sequence finishes.
							runPublicNodeLocalPasses(t, f, 60, func() bool {
								scenario.safe(t, f)
								return scenario.done(t, f)
							})
							if !scenario.done(t, f) {
								t.Fatalf("the sequence never finished after the failure: %#v", observePublicNodeLocal(t, f))
							}
						})
					}
				}
			}
		}
	}
}

func setPublicNodeLocalFixtureAssignFence(t *testing.T, f *publicNodeLocalTransientFixture, assignAt time.Time) {
	t.Helper()
	current := f.current(t)
	_, vm1, _, _ := publicNodeLocalFixtureNode(0)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Annotations[annotationNodeLoadBalancerFirewallAssigning] = current.Annotations[annotationNodeLoadBalancerFirewallUUID]
		s.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = assignAt.UTC().Format(time.RFC3339Nano)
		s.Annotations[annotationPublicNodeLocalAssignPolicy] = current.Annotations[annotationPublicNodeLocalActivePolicy]
		s.Annotations[annotationPublicNodeLocalAssignVMs] = vm1
	})
}

// A Service that is already published with its assignment fence still present
// (the process stopped between the publication and the fence clearance) clears
// the fence and keeps serving.
func TestPublicNodeLocalPublishedServiceWithFencePresentClearsFenceWithoutWithdraw(t *testing.T) {
	for _, age := range []time.Duration{time.Second, 7 * time.Minute} {
		t.Run(age.String(), func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			before := f.current(t)
			setPublicNodeLocalFixtureAssignFence(t, f, time.Now().Add(-age))
			if !publicNodeLocalAssignmentFencePresent(f.current(t)) {
				t.Fatal("the fence was not installed")
			}
			runPublicNodeLocalPasses(t, f, 10, func() bool { return !publicNodeLocalAssignmentFencePresent(f.current(t)) })
			after := f.current(t)
			if publicNodeLocalAssignmentFencePresent(after) {
				t.Fatalf("the fence stayed: %#v", after.Annotations)
			}
			if !reflect.DeepEqual(after.Status, before.Status) || len(f.api.unassignedFirewalls) != 0 {
				t.Fatalf("the exposure changed: status=%#v unassigned=%v", after.Status, f.api.unassignedFirewalls)
			}
			if after.Annotations[annotationPublicNodeLocalActivePool] != "edge" {
				t.Fatalf("the activation was lost: %#v", after.Annotations)
			}
		})
	}
}

// Child repair must work while an assignment fence is unresolved: the fence
// belongs to an add in flight, and the repair neither waits for it nor drops it.
func TestPublicNodeLocalChildRepairProceedsWhileAssignmentFenceIsUnresolved(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	_, _, priv1, pub1 := publicNodeLocalFixtureNode(0)
	// Run until the add holds its assignment fence but has not published yet.
	fenced := false
	for pass := 0; pass < 20 && !fenced; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		fenced = publicNodeLocalAssignmentFencePresent(f.current(t)) && !observePublicNodeLocal(t, f).fips[pub2]
	}
	if !fenced {
		t.Fatal("the add never reached an unresolved assignment fence")
	}
	if err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Delete(f.ctx, nodeLoadBalancerDatapathName(f.service), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 60; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			t.Fatalf("repair pass %d: %v", pass, err)
		}
		o := observePublicNodeLocal(t, f)
		if !o.fips[pub1] {
			t.Fatalf("pass %d: the serving FIP left: %#v", pass, o)
		}
		if len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("pass %d: a firewall was detached: %v", pass, f.api.unassignedFirewalls)
		}
		if o.fips[pub2] && o.vips[priv1] && o.vips[priv2] && o.assigned[vm2] && !publicNodeLocalAssignmentFencePresent(f.current(t)) {
			return
		}
	}
	t.Fatalf("the repair and the add never converged: %#v", observePublicNodeLocal(t, f))
}

// addPublicNodeLocalFixturePeer creates a serving peer Service in a pool.
func addPublicNodeLocalFixturePeer(t *testing.T, f *publicNodeLocalTransientFixture, name, uid, pool string, port int32) *corev1.Service {
	t.Helper()
	peer := publicNodeLocalTestService(name, uid, pool, corev1.ProtocolTCP, port)
	peer.Annotations[annotationPublicNodeLocalActivePool] = pool
	peer.Annotations[annotationPublicNodeLocalActivePolicy] = "peer-policy"
	peer.Finalizers = append(peer.Finalizers, publicNodeLocalFinalizer)
	created, err := f.provider.kubeClient.CoreV1().Services(peer.Namespace).Create(f.ctx, peer, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child := desiredPublicNodeLocalDatapath(created, pool)
	if _, err := f.provider.kubeClient.CoreV1().Services(peer.Namespace).Create(f.ctx, child, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return created
}

// A pool switch whose target pool would lose a port claim is refused before
// anything is written.
func TestPublicNodeLocalPoolSwitchRefusedWhenTargetPoolPortTaken(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	addPublicNodeLocalFixturePeer(t, f, "peer", "peer-uid", "spe-relay-share", 443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	before := f.current(t)
	for pass := 0; pass < 5; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if !errors.As(err, &holding) {
			t.Fatalf("pass %d: %v, want a hold", pass, err)
		}
	}
	after := f.current(t)
	for _, key := range []string{annotationPublicNodeLocalTargetPool, annotationPublicNodeLocalTargetPolicy} {
		if after.Annotations[key] != "" {
			t.Fatalf("the transition started despite the refusal: %s=%q", key, after.Annotations[key])
		}
	}
	if !reflect.DeepEqual(after.Status, before.Status) || len(f.api.unassignedFirewalls) != 0 {
		t.Fatalf("a refused switch changed the exposure: %#v", after.Status)
	}
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalTransitionRefused")
}

// A peer in a transition exposes in both pools, so a newcomer waits in either.
func TestPublicNodeLocalPeerInTransitionBlocksBothPools(t *testing.T) {
	peer := publicNodeLocalTestService("peer", "peer-uid", "pool-y", corev1.ProtocolTCP, 443)
	peer.Annotations[annotationPublicNodeLocalActivePool] = "pool-x"
	peer.Annotations[annotationPublicNodeLocalActivePolicy] = "policy"
	peer.Annotations[annotationPublicNodeLocalTargetPool] = "pool-y"
	peer.Annotations[annotationPublicNodeLocalTargetPolicy] = "policy"
	child := desiredPublicNodeLocalDatapath(peer, "pool-x")
	child.Annotations[annotationPublicNodeLocalDatapathTargetPool] = "pool-y"
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(peer.DeepCopy(), child)
	controller := &nodeLoadBalancerController{provider: provider}
	ctx := context.Background()
	claim := nodeLoadBalancerIntent{Ports: []nodeLoadBalancerPortClaim{{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 443}}}
	other := nodeLoadBalancerIntent{Ports: []nodeLoadBalancerPortClaim{{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 9999}}}
	for _, pool := range []string{"pool-x", "pool-y"} {
		claim.Pool, other.Pool = pool, pool
		blocks, err := controller.publicNodeLocalStaleExposureBlocks(ctx, peer, claim)
		if err != nil || !blocks {
			t.Fatalf("a newcomer in %s is not blocked by the peer in transition: blocks=%t err=%v", pool, blocks, err)
		}
		blocks, err = controller.publicNodeLocalStaleExposureBlocks(ctx, peer, other)
		if err != nil || blocks {
			t.Fatalf("a disjoint port in %s is blocked: blocks=%t err=%v", pool, blocks, err)
		}
	}
	claim.Pool = "pool-z"
	if blocks, err := controller.publicNodeLocalStaleExposureBlocks(ctx, peer, claim); err != nil || blocks {
		t.Fatalf("an unrelated pool is blocked: blocks=%t err=%v", blocks, err)
	}
}
