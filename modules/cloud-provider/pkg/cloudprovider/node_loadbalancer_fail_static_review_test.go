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
	"k8s.io/client-go/util/workqueue"

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
		// foreign: the relation fence never touches a VM of another billing account.
		// Its FIP and child VIP leave, its firewall stays attached, and an Event
		// tells the operator; the pass is not held by it.
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
				if err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
				observed := observePublicNodeLocal(t, f)
				if !observed.fips[pub1] || !observed.vips[priv1] {
					t.Fatalf("pass %d: the remaining node left the edge: %#v", pass, observed)
				}
				done = !observed.fips[pub2] && !observed.vips[priv2]
				if !test.foreign {
					done = done && !observed.assigned[vm2]
				}
			}
			if !done {
				t.Fatalf("the ineligible published node stayed on the edge: %#v", observePublicNodeLocal(t, f))
			}
			if test.foreign {
				requirePublicNodeLocalEvent(t, f, "PublicNodeLocalForeignAccountFirewall")
				// The pass is free again: it ends without a hold.
				if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
					t.Fatalf("a settled pass still holds: %v", err)
				}
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
		// A per-VM firewall is deleted by the transaction, whose relation fence
		// refuses the same way and holds the Service.
		if err != nil && publicNodeLocalServicePerVM(f.current(t)) && strings.Contains(err.Error(), "lacks unique exact GET/list/VPC identity") {
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
		if f.gate != nil {
			requireVMEdgeSafe(t, f)
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
			// A widening is no longer held: the child serves the union of the old and
			// the new ports, so every port it served before is still there.
			after := childPortSet(trackedPublicNodeLocalDatapath(t, f))
			for _, port := range childPortsBefore {
				if !after[port.Port] {
					t.Fatalf("port %d left the child during the pending change: %v", port.Port, after)
				}
			}
			if test.name != "pool change" {
				// A widening is a transition in progress, not a hold: it moves on.
				return
			}
			// A pool change into a pool without Nodes holds, requeues and says why.
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

// The operator escape hatch permits the old withdraw and rebuild.
func TestPublicNodeLocalAllowRebuildAnnotationPermitsWithdrawAndRebuild(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	// Without the annotation the change runs in place (see the make-before-break
	// tests); with it, the operator accepts the old withdraw and rebuild.
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

// moveFixtureNodeToPool relabels the i-th fixture Node.
func moveFixtureNodeToPool(t *testing.T, f *publicNodeLocalTransientFixture, index int, pool string) {
	t.Helper()
	name, _, _, _ := publicNodeLocalFixtureNode(index)
	updatePublicNodeLocalFixtureNode(t, f, name, func(n *corev1.Node) { n.Labels[publicNodeLocalPoolLabel] = pool })
}

// requireNeverEmptyAndMakeBeforeBreak checks the edge after one pass of a
// transition: it is never empty, and every published FIP points at a VM with
// a firewall and a child VIP.
func requireTransitionEdgeSafe(t *testing.T, f *publicNodeLocalTransientFixture, pass int, nodes ...int) publicNodeLocalObservation {
	t.Helper()
	if f.gate != nil {
		requireVMEdgeSafe(t, f)
	}
	observed := observePublicNodeLocal(t, f)
	if len(f.current(t).Status.LoadBalancer.Ingress) == 0 {
		t.Fatalf("pass %d: the parent status is empty", pass)
	}
	for _, index := range nodes {
		observed.requireMakeBeforeBreak(t, pass, index)
	}
	return observed
}

// A pool switch publishes the union of both pools, promotes the target and only
// then removes the old pool, and the edge is never empty.
func TestPublicNodeLocalPoolSwitchMakeBeforeBreak(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
	_, vmB, privB, pubB := publicNodeLocalFixtureNode(1)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	sawUnion, done := false, false
	for pass := 0; pass < 120 && !done; pass++ {
		if current := f.current(t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
			ageNodeLoadBalancerAbsenceEvidence(t, f.ctx, f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
		}
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		observed := requireTransitionEdgeSafe(t, f, pass, 0, 1)
		if observed.fips[pubA] && observed.fips[pubB] {
			sawUnion = true
		}
		current := f.current(t)
		done = current.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" &&
			current.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			!observed.fips[pubA] && !observed.vips[privA] && !observed.assigned[vmA]
	}
	if !done {
		t.Fatalf("the switch never completed: %#v %#v", observePublicNodeLocal(t, f), f.current(t).Annotations)
	}
	if !sawUnion {
		t.Fatal("both pools were never published together")
	}
	observed := observePublicNodeLocal(t, f)
	if !observed.fips[pubB] || !observed.vips[privB] || !observed.assigned[vmB] || len(f.current(t).Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("the target pool does not serve alone: %#v", observed)
	}
	if got := trackedPublicNodeLocalDatapath(t, f).Annotations[annotationPublicNodeLocalDatapathPool]; got != "spe-relay-share" {
		t.Fatalf("child pool = %q", got)
	}
	if got := trackedPublicNodeLocalDatapath(t, f).Annotations[annotationPublicNodeLocalDatapathTargetPool]; got != "" {
		t.Fatalf("child target pool = %q", got)
	}
}

// A pool change no longer holds: the first pass records the target next to the
// active identity and touches nothing else. (It replaces the "pool annotation
// change" row of the definite-failure table, which expected a pending hold.)
func TestPublicNodeLocalPoolChangeStartsTransitionWithoutTouchingTheEdge(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	before := f.current(t)
	childBefore := trackedPublicNodeLocalDatapath(t, f)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "other" })
	if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
		t.Fatalf("start pass: %v", err)
	}
	after := f.current(t)
	if after.Annotations[annotationPublicNodeLocalTargetPool] != "other" ||
		after.Annotations[annotationPublicNodeLocalTargetPolicy] != before.Annotations[annotationPublicNodeLocalActivePolicy] {
		t.Fatalf("target not recorded: %#v", after.Annotations)
	}
	if after.Annotations[annotationPublicNodeLocalActivePool] != "edge" || !reflect.DeepEqual(after.Status, before.Status) ||
		len(f.api.unassignedFirewalls) != 0 {
		t.Fatalf("the start pass changed the edge: %#v", after)
	}
	if !reflect.DeepEqual(trackedPublicNodeLocalDatapath(t, f).Status, childBefore.Status) {
		t.Fatal("the start pass changed the child status")
	}
}

// The target is promoted only when its Nodes are on the edge. A target Node
// whose firewall assignment is not applied keeps the old pool as the active one.
func TestPublicNodeLocalPromotionRequiresTargetConverged(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	_, vmB, _, _ := publicNodeLocalFixtureNode(1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	f.provider.api = &neverAppliesAssignAPI{
		publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, stuckVM: vmB,
	}
	_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	for pass := 0; pass < 40; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalActivePool] != "edge" {
			t.Fatalf("pass %d: promoted with a target Node that has no firewall", pass)
		}
		if observed := observePublicNodeLocal(t, f); !observed.fips[pubA] || !observed.vips[privA] || !observed.assigned[vmA] {
			t.Fatalf("pass %d: the old node left the edge: %#v", pass, observed)
		}
	}
	if current := f.current(t); current.Annotations[annotationPublicNodeLocalTargetPool] != "spe-relay-share" {
		t.Fatalf("the transition did not stay open: %#v", current.Annotations)
	}
}

// policyChangeWatch checks every pass of an in-place policy change against one
// original firewall.
type policyChangeWatch struct {
	oldFirewall string
	oldPorts    []int32
	newPorts    []int32
}

func childPortSet(child *corev1.Service) map[int32]bool {
	ports := map[int32]bool{}
	for _, port := range child.Spec.Ports {
		ports[port.Port] = true
	}
	return ports
}

// firewallHolds says which firewalls (by UUID) are assigned to a VM.
func firewallsOfVM(f *publicNodeLocalTransientFixture, vmUUID string) map[string]bool {
	held := map[string]bool{}
	for _, firewall := range f.api.firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			if resource.ResourceUUID == vmUUID && strings.HasPrefix(firewall.EffectiveName(), "inlb-") {
				held[firewall.UUID] = true
			}
		}
	}
	return held
}

// runPolicyChange drives a policy change to the end and checks the edge on
// every pass: never empty, every published VM keeps a Service firewall, and
// every published port keeps its child frontend while a firewall guards it.
func runPolicyChange(t *testing.T, f *publicNodeLocalTransientFixture, nodes int, watch policyChangeWatch, afterPass func(pass int)) {
	t.Helper()
	oldHash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	sawBoth := false
	done := false
	for pass := 0; pass < 200 && !done; pass++ {
		if current := f.current(t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
			ageNodeLoadBalancerAbsenceEvidence(t, f.ctx, f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
		}
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		var pending *nodeLoadBalancerFirewallRelationPendingError
		waiting := err != nil && strings.Contains(err.Error(), "waiting for")
		if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) && !waiting {
			t.Fatalf("pass %d: %v", pass, err)
		}
		indexes := make([]int, nodes)
		for i := range indexes {
			indexes[i] = i
		}
		requireTransitionEdgeSafe(t, f, pass, indexes...)
		child := trackedPublicNodeLocalDatapath(t, f)
		ports := childPortSet(child)
		for i := 0; i < nodes; i++ {
			_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
			held := firewallsOfVM(f, vmUUID)
			if len(held) == 0 {
				t.Fatalf("pass %d: VM %d has no Service firewall: %#v", pass, i, f.current(t).Annotations)
			}
			if len(held) > 1 {
				sawBoth = true
			}
			// A port the old firewall allowed keeps its child frontend until that
			// firewall is detached everywhere.
			if held[watch.oldFirewall] {
				for _, port := range watch.oldPorts {
					if !ports[port] {
						t.Fatalf("pass %d: port %d left the child while the old firewall is still attached", pass, port)
					}
				}
			}
		}
		if afterPass != nil {
			afterPass(pass)
		}
		current := f.current(t)
		done = current.Annotations[annotationPublicNodeLocalActivePolicy] != oldHash &&
			current.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			!publicNodeLocalOldEdgePending(current) &&
			!publicNodeLocalAssignmentFencePresent(current) &&
			publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), current, current.Annotations[annotationPublicNodeLocalActivePool])
	}
	if !done {
		t.Fatalf("the policy change never completed: %#v", f.current(t).Annotations)
	}
	if watch.oldFirewall != "" && !sawBoth {
		t.Fatal("the old and the new firewall were never attached together")
	}
	for _, firewall := range f.api.firewalls {
		if watch.oldFirewall != "" && firewall.UUID == watch.oldFirewall {
			t.Fatalf("the old firewall %s still exists", watch.oldFirewall)
		}
	}
	ports := childPortSet(trackedPublicNodeLocalDatapath(t, f))
	if len(ports) != len(watch.newPorts) {
		t.Fatalf("child ports = %v, want %v", ports, watch.newPorts)
	}
	for _, port := range watch.newPorts {
		if !ports[port] {
			t.Fatalf("child ports = %v, want %v", ports, watch.newPorts)
		}
	}
	if len(f.current(t).Status.LoadBalancer.Ingress) != nodes {
		t.Fatalf("the Service lost nodes: %#v", f.current(t).Status)
	}
}

// 443 becomes 443+8443: 443 stays served, the old firewall stays attached until
// the new one is on every VM, then it is detached and deleted.
func TestPublicNodeLocalPortAddMakeBeforeBreak(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	newFirewall := ""
	runPolicyChange(t, f, 2, policyChangeWatch{oldFirewall: old, oldPorts: []int32{443}, newPorts: []int32{443, 8443}}, func(int) {
		current := f.current(t)
		if uuid := current.Annotations[annotationNodeLoadBalancerFirewallUUID]; uuid != old {
			newFirewall = uuid
		}
		// The old firewall is detached only after the new one is on every VM.
		if newFirewall == "" {
			return
		}
		for i := 0; i < 2; i++ {
			_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
			held := firewallsOfVM(f, vmUUID)
			if !held[old] && !held[newFirewall] {
				t.Fatalf("VM %d has neither firewall", i)
			}
		}
	})
}

// 443+80 becomes 443: port 80 stays in the child until the old firewall is
// detached, so the narrower policy is applied without any outage.
func TestPublicNodeLocalPortRemovalClosesFirewallBeforeVIP(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443, 80))
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443)
	runPolicyChange(t, f, 2, policyChangeWatch{oldFirewall: old, oldPorts: []int32{443, 80}, newPorts: []int32{443}}, nil)
	if len(f.api.unassignedFirewalls) == 0 && !publicNodeLocalServicePerVM(f.current(t)) {
		// A per-VM firewall is narrowed in place; there is no old firewall to detach.
		t.Fatal("the old firewall was never detached")
	}
}

func TestPublicNodeLocalSourceRangeChangeKeepsServing(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"} })
	runPolicyChange(t, f, 2, policyChangeWatch{oldFirewall: old, oldPorts: []int32{443}, newPorts: []int32{443}}, nil)
}

// A mix of narrowing and widening is not held and not rebuilt either.
func TestPublicNodeLocalMixedPolicyChangeKeepsServing(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443, 80))
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"} })
	runPolicyChange(t, f, 2, policyChangeWatch{oldFirewall: old, oldPorts: []int32{443, 80}, newPorts: []int32{443, 8443}}, nil)
}

// stepPublicNodeLocal runs one pass and tolerates only holds and waits.
func stepPublicNodeLocal(t *testing.T, f *publicNodeLocalTransientFixture, pass int) {
	t.Helper()
	if current := f.current(t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
		ageNodeLoadBalancerAbsenceEvidence(t, f.ctx, f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
	}
	err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	var holding *errPublicNodeLocalHolding
	var pending *nodeLoadBalancerFirewallRelationPendingError
	waiting := err != nil && strings.Contains(err.Error(), "waiting for")
	if err != nil {
		t.Logf("pass %d held: %v", pass, err)
	}
	if err != nil && !errors.As(err, &holding) && !errors.As(err, &pending) && !waiting {
		t.Fatalf("pass %d: %v", pass, err)
	}
	if f.gate != nil {
		requireVMEdgeSafe(t, f)
	}
}

// runUntil steps until the condition holds, checking the edge each pass.
func runUntil(t *testing.T, f *publicNodeLocalTransientFixture, nodes []int, limit int, what string, cond func(publicNodeLocalObservation, *corev1.Service) bool) {
	t.Helper()
	for pass := 0; pass < limit; pass++ {
		stepPublicNodeLocal(t, f, pass)
		observed := requireTransitionEdgeSafe(t, f, pass, nodes...)
		if cond(observed, f.current(t)) {
			return
		}
	}
	t.Fatalf("%s: never reached: %#v %#v", what, observePublicNodeLocal(t, f), f.current(t).Annotations)
}

// Going back to the active pool in the middle of a switch drops the target only.
func TestPublicNodeLocalTransitionRevertPrunesTargetOnly(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
	_, vmB, privB, pubB := publicNodeLocalFixtureNode(1)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	runUntil(t, f, []int{0, 1}, 80, "both pools published", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return o.fips[pubA] && o.fips[pubB] && s.Annotations[annotationPublicNodeLocalTargetPool] != ""
	})
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "edge" })
	runUntil(t, f, []int{0, 1}, 120, "the target is pruned", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPool] == "" && !o.fips[pubB] && !o.vips[privB] && !o.assigned[vmB]
	})
	observed := observePublicNodeLocal(t, f)
	if !observed.fips[pubA] || !observed.vips[privA] || !observed.assigned[vmA] {
		t.Fatalf("the active pool node was touched: %#v", observed)
	}
	for _, entry := range f.api.unassignedFirewalls {
		if strings.HasSuffix(entry, "/"+vmA) {
			t.Fatalf("the active pool node was unassigned: %v", f.api.unassignedFirewalls)
		}
	}
	if got := f.current(t).Annotations[annotationPublicNodeLocalActivePool]; got != "edge" {
		t.Fatalf("active pool = %q", got)
	}
}

// Reverting a policy change in the middle hands the ledger back to the active
// firewall and retires the target firewall.
func TestPublicNodeLocalPolicyChangeRevertRestoresActiveFirewall(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	oldHash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	vm1 := "11111111-2222-4333-8444-555555555555"
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	runUntil(t, f, []int{0, 1}, 80, "the target firewall is attached", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		if publicNodeLocalServicePerVM(s) {
			return s.Annotations[annotationPublicNodeLocalTargetPolicy] != "" && perVMEntryPolicies(t, f, s, vm1) == 2
		}
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] != "" && s.Annotations[annotationNodeLoadBalancerFirewallUUID] != old &&
			len(firewallsOfVM(f, vm1)) == 2
	})
	setPublicNodeLocalFixturePorts(t, f, 443)
	runUntil(t, f, []int{0, 1}, 200, "the old policy is restored", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" && s.Annotations[annotationNodeLoadBalancerFirewallUUID] == old &&
			s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" &&
			publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), s, s.Annotations[annotationPublicNodeLocalActivePool])
	})
	current := f.current(t)
	if current.Annotations[annotationPublicNodeLocalActivePolicy] != oldHash || len(firewallsOfVM(f, vm1)) != 1 {
		t.Fatalf("the active policy did not come back: %#v", current.Annotations)
	}
}

// A third pool in the middle of a switch first ends the union, then starts a
// new one, and the active pool is never withdrawn.
func TestPublicNodeLocalTransitionRetargetAbortsThenStartsAgain(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	f.addNode(t, 2)
	moveFixtureNodeToPool(t, f, 1, "pool-b")
	moveFixtureNodeToPool(t, f, 2, "pool-c")
	_, vmA, _, pubA := publicNodeLocalFixtureNode(0)
	_, _, _, pubB := publicNodeLocalFixtureNode(1)
	_, _, _, pubC := publicNodeLocalFixtureNode(2)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "pool-b" })
	runUntil(t, f, []int{0, 1, 2}, 80, "the first union", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return o.fips[pubB] && s.Annotations[annotationPublicNodeLocalTargetPool] == "pool-b"
	})
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "pool-c" })
	sawAbort, sawC := false, false
	runUntil(t, f, []int{0, 1, 2}, 400, "the switch to pool C", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		if s.Annotations[annotationPublicNodeLocalTargetPool] == "" && s.Annotations[annotationPublicNodeLocalActivePool] == "edge" {
			sawAbort = true
		}
		if o.fips[pubC] && o.fips[pubA] {
			sawC = true
		}
		return s.Annotations[annotationPublicNodeLocalActivePool] == "pool-c" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			!o.fips[pubA] && !o.assigned[vmA] && !o.fips[pubB]
	})
	if !sawAbort || !sawC {
		t.Fatalf("abort seen %t, union with C seen %t", sawAbort, sawC)
	}
}

// A pool and a policy changing together use the same tuple: the new firewall
// goes to the target pool only, and the old one stays on the old pool.
func TestPublicNodeLocalPoolAndPolicyChangeTogether(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
	_, vmB, _, pubB := publicNodeLocalFixtureNode(1)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	sawUnion := false
	runUntil(t, f, []int{0, 1}, 300, "the combined change", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		if o.fips[pubA] && o.fips[pubB] {
			sawUnion = true
			if firewallsOfVM(f, vmB)[old] {
				t.Fatalf("the old firewall went to the target pool VM")
			}
		}
		if s.Annotations[annotationPublicNodeLocalActivePool] == "edge" {
			// Until the promotion the new firewall goes to the target pool only; the
			// old pool's VM keeps the old firewall and nothing else.
			if old == "" && perVMEntryPolicies(t, f, s, vmA) > 1 {
				t.Fatalf("the new policy was added to the old pool VM before the promotion")
			}
			for uuid := range firewallsOfVM(f, vmA) {
				if old != "" && uuid != old {
					t.Fatalf("the new firewall %s was attached to the old pool VM before the promotion", uuid)
				}
			}
		}
		return s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" && !o.fips[pubA] && !o.vips[privA] && !o.assigned[vmA] &&
			publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), s, "spe-relay-share")
	})
	if !sawUnion {
		t.Fatal("both pools were never published together")
	}
	for _, firewall := range f.api.firewalls {
		if firewall.UUID == old {
			t.Fatal("the old firewall was not deleted")
		}
	}
}

// listFirewallsFailingAPI fails every firewall list and passes the rest on.
type listFirewallsFailingAPI struct {
	API
	err error
}

func (a *listFirewallsFailingAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	return nil, a.err
}

// restartPublicNodeLocalController replaces the controller by a fresh one over
// the same cluster and cloud, as a crash and restart would.
func restartPublicNodeLocalController(f *publicNodeLocalTransientFixture) {
	controller := &nodeLoadBalancerController{
		provider:       f.provider,
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		endpointSlices: f.controller.endpointSlices,
	}
	f.controller = controller
}

type publicNodeLocalTransitionScenario struct {
	name  string
	nodes []int
	setup func(*testing.T) *publicNodeLocalTransientFixture
	done  func(*testing.T, *publicNodeLocalTransientFixture) bool
}

func publicNodeLocalTransitionScenarios() []publicNodeLocalTransitionScenario {
	twoPools := func(t *testing.T, shape func(*corev1.Service)) *publicNodeLocalTransientFixture {
		f := newPublishedPublicNodeLocalFixtureWith(t, 1, shape)
		f.addNode(t, 1)
		moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
		return f
	}
	poolDone := func(t *testing.T, f *publicNodeLocalTransientFixture) bool {
		_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
		o := observePublicNodeLocal(t, f)
		s := f.current(t)
		return s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" && !o.fips[pubA] && !o.vips[privA] && !o.assigned[vmA] &&
			publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), s, "spe-relay-share")
	}
	policyDone := func(oldHash string) func(*testing.T, *publicNodeLocalTransientFixture) bool {
		return func(t *testing.T, f *publicNodeLocalTransientFixture) bool {
			s := f.current(t)
			return s.Annotations[annotationPublicNodeLocalActivePolicy] != oldHash && s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
				s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" && !publicNodeLocalAssignmentFencePresent(s) &&
				publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), s, s.Annotations[annotationPublicNodeLocalActivePool])
		}
	}
	return []publicNodeLocalTransitionScenario{
		{name: "pool switch", nodes: []int{0, 1}, setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := twoPools(t, nil)
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
			return f
		}, done: poolDone},
		{name: "widening", nodes: []int{0, 1}, setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
			return f
		}, done: func(t *testing.T, f *publicNodeLocalTransientFixture) bool { return policyDone("886b49b4")(t, f) }},
		{name: "narrowing", nodes: []int{0, 1}, setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := newPublishedPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443, 80))
			setPublicNodeLocalFixturePorts(t, f, 443)
			return f
		}, done: func(t *testing.T, f *publicNodeLocalTransientFixture) bool {
			return policyDone("")(t, f) && len(childPortSet(trackedPublicNodeLocalDatapath(t, f))) == 1
		}},
		{name: "pool and policy", nodes: []int{0, 1}, setup: func(t *testing.T) *publicNodeLocalTransientFixture {
			f := twoPools(t, nil)
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
			return f
		}, done: poolDone},
	}
}

// A restart at any step of a transition resumes or rolls back safely: the edge
// is never empty and the transition still completes. The same holds when the
// first pass after the restart meets one definite firewall list error.
func TestPublicNodeLocalTransitionResumesAfterRestartAtEveryStep(t *testing.T) {
	for _, scenario := range publicNodeLocalTransitionScenarios() {
		t.Run(scenario.name, func(t *testing.T) {
			probe := scenario.setup(t)
			steps := 0
			for ; steps < 400; steps++ {
				stepPublicNodeLocal(t, probe, steps)
				requireTransitionEdgeSafe(t, probe, steps, scenario.nodes...)
				if scenario.done(t, probe) {
					break
				}
			}
			if steps >= 400 {
				t.Fatalf("the scenario never completed without a restart: %#v", probe.current(t).Annotations)
			}
			for restartAt := 0; restartAt <= steps; restartAt++ {
				for _, injectError := range []bool{false, true} {
					f := scenario.setup(t)
					for pass := 0; pass < restartAt; pass++ {
						stepPublicNodeLocal(t, f, pass)
					}
					restartPublicNodeLocalController(f)
					completed := false
					for pass := 0; pass < 400 && !completed; pass++ {
						if injectError && pass == 0 {
							real := f.provider.api
							f.provider.api = &listFirewallsFailingAPI{API: real, err: errors.New("definite list failure")}
							stepPublicNodeLocal(t, f, pass)
							f.provider.api = real
						} else {
							stepPublicNodeLocal(t, f, pass)
						}
						requireTransitionEdgeSafe(t, f, restartAt*1000+pass, scenario.nodes...)
						completed = scenario.done(t, f)
					}
					if !completed {
						t.Fatalf("restart at %d (error %t): never completed: %#v", restartAt, injectError, f.current(t).Annotations)
					}
				}
			}
		})
	}
}

// A single provider call that fails in any pass of a transition must leave the
// edge safe and never empty, and the transition must finish once the provider
// recovers. The calls of every pass are counted first, so none is skipped.
func TestPublicNodeLocalTransitionSurvivesNthProviderFailure(t *testing.T) {
	definite := errors.New("canonical ownership mismatch")
	for _, scenario := range publicNodeLocalTransitionScenarios() {
		probe := scenario.setup(t)
		steps := 0
		for ; steps < 400; steps++ {
			stepPublicNodeLocal(t, probe, steps)
			if scenario.done(t, probe) {
				break
			}
		}
		for pass := 0; pass < steps; pass++ {
			for _, kind := range []string{"GetVM", "ListFirewalls"} {
				counted := scenario.setup(t)
				for i := 0; i < pass; i++ {
					stepPublicNodeLocal(t, counted, i)
				}
				base := counted.provider.api
				counter := &nthCallAPI{API: base, calls: map[string]int{}}
				counted.provider.api = counter
				_ = counted.controller.syncPublicNodeLocal(counted.ctx, counted.key, counted.current(t))
				total := counter.calls[kind]
				for n := 1; n <= total; n++ {
					for _, transient := range []bool{true, false} {
						name := fmt.Sprintf("%s/pass %d/%s call %d/transient=%t", scenario.name, pass, kind, n, transient)
						t.Run(name, func(t *testing.T) {
							f := scenario.setup(t)
							for i := 0; i < pass; i++ {
								stepPublicNodeLocal(t, f, i)
							}
							failure := definite
							if transient {
								failure = transientProviderError()
							}
							base := f.provider.api
							failing := &nthCallAPI{API: base, failKind: kind, failOn: n, err: failure, calls: map[string]int{}}
							f.provider.api = failing
							err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
							f.provider.api = base
							var holding *errPublicNodeLocalHolding
							var pending *nodeLoadBalancerFirewallRelationPendingError
							if err != nil && transient && !inspace.IsTransient(err) {
								t.Fatalf("a transient failure became definite: %v", err)
							}
							if err != nil && !transient && !errors.As(err, &holding) && !errors.As(err, &pending) &&
								!strings.Contains(err.Error(), "waiting for") {
								t.Fatalf("a definite failure was not held: %v", err)
							}
							requireTransitionEdgeSafe(t, f, pass, scenario.nodes...)
							for i := 0; i < 400 && !scenario.done(t, f); i++ {
								stepPublicNodeLocal(t, f, i)
								requireTransitionEdgeSafe(t, f, i, scenario.nodes...)
							}
							if !scenario.done(t, f) {
								t.Fatalf("the transition never finished after the failure: %#v", f.current(t).Annotations)
							}
						})
					}
				}
			}
		}
	}
}

// neverUnassignVMAPI accepts the unassign of one VM and never applies it.
type neverUnassignVMAPI struct {
	*publicNodeLocalFilteringIPAPI
	stuckVM string
}

func (a *neverUnassignVMAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if vmUUID == a.stuckVM {
		return nil
	}
	return a.publicNodeLocalFilteringIPAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

// A parked unassign must not starve the adds of the Service. The VIP of the
// node whose firewall is still attached stays, as the safety order requires.
func TestPublicNodeLocalParkedUnassignDoesNotStarveAdds(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	name2, vm2, priv2, _ := publicNodeLocalFixtureNode(1)
	_, _, _, pub1 := publicNodeLocalFixtureNode(0)
	f.provider.api = &neverUnassignVMAPI{
		publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, stuckVM: vm2,
	}
	clock := time.Now().UTC()
	f.controller.firewallRelationNow = func() time.Time { return clock }
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, "edge-0")
	parked := false
	for pass := 0; pass < 60 && !parked; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		events, err := f.provider.kubeClient.CoreV1().Events(f.service.Namespace).List(f.ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events.Items {
			parked = parked || event.Reason == "PublicNodeLocalFirewallRelationStuck"
		}
		clock = clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
	}
	if !parked {
		t.Fatalf("the unassign never parked: %#v", observePublicNodeLocal(t, f))
	}
	// A replacement node arrives while the old unassign is parked.
	f.addNode(t, 2)
	_, vm3, priv3, pub3 := publicNodeLocalFixtureNode(2)
	for pass := 0; pass < 40; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			var holding *errPublicNodeLocalHolding
			var pending *nodeLoadBalancerFirewallRelationPendingError
			if !errors.As(err, &holding) && !errors.As(err, &pending) {
				t.Fatalf("pass %d: %v", pass, err)
			}
		}
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub1] {
			t.Fatalf("pass %d: the serving node left: %#v", pass, observed)
		}
		if observed.assigned[vm2] && !observed.vips[priv2] {
			t.Fatalf("pass %d: the VIP left while the firewall is still attached: %#v", pass, observed)
		}
		if observed.fips[pub3] && observed.vips[priv3] && observed.assigned[vm3] {
			return
		}
	}
	t.Fatalf("the add starved behind the parked unassign: %#v", observePublicNodeLocal(t, f))
}

func deletePublicNodeLocalFixtureChild(t *testing.T, f *publicNodeLocalTransientFixture) {
	t.Helper()
	if err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Delete(f.ctx, nodeLoadBalancerDatapathName(f.service), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}

// requireChildAndVIPsRestored runs passes until the child exists again with the
// VIP of every published node and the given ports, never touching the FIPs.
func requireChildAndVIPsRestored(t *testing.T, f *publicNodeLocalTransientFixture, nodes int, ports ...int32) {
	t.Helper()
	statusBefore := f.current(t).Status
	for pass := 0; pass < 40; pass++ {
		stepPublicNodeLocal(t, f, pass)
		if !reflect.DeepEqual(f.current(t).Status, statusBefore) {
			t.Fatalf("pass %d: the parent FIPs changed: %#v", pass, f.current(t).Status)
		}
		child := trackedPublicNodeLocalDatapathOrNil(f)
		if child == nil || len(child.Status.LoadBalancer.Ingress) != nodes {
			continue
		}
		have := childPortSet(child)
		complete := true
		for _, port := range ports {
			complete = complete && have[port]
		}
		if complete {
			return
		}
	}
	t.Fatalf("the child and its VIPs were not restored with ports %v: %#v", ports, trackedPublicNodeLocalDatapathOrNil(f))
}

// A held policy change (refused because a peer serves the new port) must still
// recreate a missing child and restore the VIPs of the published nodes.
func TestPublicNodeLocalHeldPolicyRecreatesMissingChild(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	addPublicNodeLocalFixturePeer(t, f, "peer", "peer-uid", "edge", 8443)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	stepPublicNodeLocal(t, f, 0)
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalTransitionRefused")
	deletePublicNodeLocalFixtureChild(t, f)
	requireChildAndVIPsRestored(t, f, 2, 443)
	if len(f.api.unassignedFirewalls) != 0 {
		t.Fatalf("a firewall was detached: %v", f.api.unassignedFirewalls)
	}
}

// A child lost in the middle of a policy transition comes back with the ports
// of the old firewall too, so a port the old firewall still allows is not
// blackholed.
func TestPublicNodeLocalUnionRecreatesMissingChildWithOldPorts(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 8443)
	for pass := 0; pass < 80; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" && (publicNodeLocalServicePerVM(current) || current.Annotations[annotationNodeLoadBalancerFirewallUUID] != old) {
			break
		}
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
		t.Fatal("the union never started")
	}
	deletePublicNodeLocalFixtureChild(t, f)
	requireChildAndVIPsRestored(t, f, 2, 443, 8443)
}

// The escape hatch is single use: "true" is honoured for one target and the
// controller records it as consumed, so a manifest that keeps the annotation
// cannot replay a rebuild on a later change.
func TestPublicNodeLocalAllowRebuildIsSingleUse(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	oldHash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
	reconcileUntilRepublished(t, f, 1, 80)
	current := f.current(t)
	if current.Annotations[annotationPublicNodeLocalActivePolicy] == oldHash || len(f.api.unassignedFirewalls) == 0 {
		t.Fatalf("the first change was not rebuilt: %#v", current.Annotations)
	}
	if current.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed] != "true" {
		t.Fatalf("consumed marker = %q, want the raw annotation value", current.Annotations[annotationNodeLoadBalancerAllowRebuildConsumed])
	}
	// The manifest still says "true". The next change runs in place.
	unassigned := len(f.api.unassignedFirewalls)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443)
	runPolicyChange(t, f, 1, policyChangeWatch{oldFirewall: old, oldPorts: []int32{443, 8443}, newPorts: []int32{443}}, nil)
	if len(f.api.unassignedFirewalls) == unassigned {
		t.Fatal("the old firewall of the second change was never detached")
	}
	// Removing the annotation resets the marker; the next "true" counts again.
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { delete(s.Annotations, annotationNodeLoadBalancerAllowRebuild) })
	stepPublicNodeLocal(t, f, 0)
	if got := f.current(t).Annotations[annotationNodeLoadBalancerAllowRebuildConsumed]; got != "" {
		t.Fatalf("the consumed marker survived the annotation: %q", got)
	}
}

// addPublicNodeLocalWaitingPeer creates a Service that wants a port in a pool
// and exposes nothing yet.
func addPublicNodeLocalWaitingPeer(t *testing.T, f *publicNodeLocalTransientFixture, name, uid, pool string, port int32) (*corev1.Service, nodeLoadBalancerIntent) {
	t.Helper()
	peer := publicNodeLocalTestService(name, uid, pool, corev1.ProtocolTCP, port)
	peer.Finalizers = append(peer.Finalizers, publicNodeLocalFinalizer)
	created, err := f.provider.kubeClient.CoreV1().Services(peer.Namespace).Create(f.ctx, peer, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := parseNodeLoadBalancerService(created, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	return created, intent
}

// requirePeerBlockedWhileVIPOn checks, after every pass, that a peer wanting the
// port in a pool is blocked for as long as the Service still has a child VIP on
// a Node of that pool: Cilium would program the same node IP and port twice.
func requirePeerBlockedWhileVIPOn(
	t *testing.T, f *publicNodeLocalTransientFixture, peer *corev1.Service, intent nodeLoadBalancerIntent,
	privateIP string, limit int, done func(publicNodeLocalObservation, *corev1.Service) bool,
) {
	t.Helper()
	sawVIP, sawFree := false, false
	for pass := 0; pass < limit; pass++ {
		stepPublicNodeLocal(t, f, pass)
		observed := observePublicNodeLocal(t, f)
		loses, waiting, err := f.controller.publicNodeLocalPortConflict(f.ctx, peer, intent)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		blocked := loses || waiting
		if observed.vips[privateIP] {
			sawVIP = true
			if !blocked {
				t.Fatalf("pass %d: the peer is free while the child still has a VIP on node %s: %#v %v", pass, privateIP, observed, f.current(t).Annotations)
			}
		} else if sawVIP && !blocked {
			sawFree = true
		}
		if done(observed, f.current(t)) && sawFree {
			return
		}
	}
	t.Fatalf("the peer was never freed after the VIP drained (sawVIP %t, sawFree %t): %#v", sawVIP, sawFree, observePublicNodeLocal(t, f))
}

// After a promotion the old pool is still drained for a while. A peer that
// waits for the port in the old pool must stay blocked until the last VIP of
// the old pool's nodes is gone.
func TestPublicNodeLocalPromotionKeepsDrainingPoolAttributed(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	_, _, privA, _ := publicNodeLocalFixtureNode(0)
	peer, intent := addPublicNodeLocalWaitingPeer(t, f, "waiter", "waiter-uid", "edge", 443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	requirePeerBlockedWhileVIPOn(t, f, peer, intent, privA, 200, func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && !o.vips[privA]
	})
}

// An abandoned transition leaves the target pool's Nodes draining. A peer that
// waits for the port in the target pool stays blocked until they are gone.
func TestPublicNodeLocalAbortKeepsDrainingTargetPoolAttributed(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	_, _, privB, pubB := publicNodeLocalFixtureNode(1)
	peer, intent := addPublicNodeLocalWaitingPeer(t, f, "waiter", "waiter-uid", "spe-relay-share", 443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	runUntil(t, f, []int{0, 1}, 80, "the target Node is on the edge", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return o.fips[pubB] && s.Annotations[annotationPublicNodeLocalTargetPool] != ""
	})
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "edge" })
	requirePeerBlockedWhileVIPOn(t, f, peer, intent, privB, 200, func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPool] == "" && !o.vips[privB]
	})
}

// A Node that is relabelled to another pool is Gone for its Service, but its VIP
// stays until the removal order has run. A peer in the new pool is blocked
// meanwhile, because the VIP is on that Node.
func TestPublicNodeLocalRelabelledNodeVIPBlocksPeerInNewPool(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, _, priv2, _ := publicNodeLocalFixtureNode(1)
	peer, intent := addPublicNodeLocalWaitingPeer(t, f, "waiter", "waiter-uid", "other-pool", 443)
	moveFixtureNodeToPool(t, f, 1, "other-pool")
	requirePeerBlockedWhileVIPOn(t, f, peer, intent, priv2, 120, func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return !o.vips[priv2]
	})
}

// lagUnassignAPI accepts the first skip unassigns without applying them, as a
// cloud whose detach readback lags.
type lagUnassignAPI struct {
	*publicNodeLocalFilteringIPAPI
	skip int
}

func (a *lagUnassignAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if a.skip > 0 {
		a.skip--
		return nil
	}
	return a.publicNodeLocalFilteringIPAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

// A rebuild the operator asked for is finished as a rebuild. When the detach
// readback lags, the withdrawal goes on until it is complete; it never falls into
// a union half way, with the withdraw journal and the unassign receipt live.
func TestPublicNodeLocalAllowRebuildFinishesWithdrawWhenDetachLags(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.provider.api = &lagUnassignAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, skip: 1}
	oldHash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	clock := time.Now().UTC()
	f.controller.firewallRelationNow = func() time.Time { return clock }
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
	sawEmpty := false
	for pass := 0; pass < 200; pass++ {
		// The lagging unassign is retired after the relation retire delay.
		clock = clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
		if current := f.current(t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
			ageNodeLoadBalancerAbsenceEvidence(t, f.ctx, f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
		}
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" || current.Annotations[annotationPublicNodeLocalTargetPool] != "" {
			t.Fatalf("pass %d: a union started in the middle of the rebuild: %#v", pass, current.Annotations)
		}
		sawEmpty = sawEmpty || len(current.Status.LoadBalancer.Ingress) == 0
		if current.Annotations[annotationPublicNodeLocalActivePolicy] != "" && current.Annotations[annotationPublicNodeLocalActivePolicy] != oldHash &&
			len(current.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(current) {
			if !sawEmpty {
				t.Fatal("the rebuild never withdrew the edge")
			}
			return
		}
	}
	t.Fatalf("the rebuild never finished: %#v", f.current(t).Annotations)
}

// A rebuild value is honoured once, whatever it is, until the annotation is
// changed or removed. A manifest that keeps it cannot replay it on a later
// change of another kind, such as a pool switch.
func TestPublicNodeLocalAllowRebuildValueDoesNotReplayOnPoolSwitch(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	desired, err := f.controller.desiredServiceFirewall(f.current(t))
	if err != nil {
		t.Fatal(err)
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = desired.Hash })
	reconcileUntilRepublished(t, f, 1, 80)
	if got := f.current(t).Annotations[annotationNodeLoadBalancerAllowRebuildConsumed]; got != desired.Hash {
		t.Fatalf("consumed marker = %q, want the raw annotation value %q", got, desired.Hash)
	}
	// The manifest still carries the value. A pool switch runs in place.
	f.addNode(t, 1)
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	runUntil(t, f, []int{0, 1}, 200, "the pool switch", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		_, vmA, _, pubA := publicNodeLocalFixtureNode(0)
		return s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			!o.fips[pubA] && !o.assigned[vmA]
	})
}

// A new value is honoured again, once.
func TestPublicNodeLocalAllowRebuildNewValueIsHonouredAgain(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "first" })
	reconcileUntilRepublished(t, f, 1, 80)
	unassigned := len(f.api.unassignedFirewalls)
	setPublicNodeLocalFixturePorts(t, f, 443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "second" })
	reconcileUntilRepublished(t, f, 1, 80)
	if len(f.api.unassignedFirewalls) == unassigned {
		t.Fatal("the second value was not honoured")
	}
	if got := f.current(t).Annotations[annotationNodeLoadBalancerAllowRebuildConsumed]; got != "second" {
		t.Fatalf("consumed marker = %q", got)
	}
}

// The endpoint grace and the not-eligible removals run during a union too. Pods
// move while a pool is switched, so waiting for the promotion would keep a node
// that serves nothing on the edge for as long as the target pool is empty.
func TestPublicNodeLocalUnionStillRemovesNodeWithoutEndpointAfterGrace(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	_, _, privA, pubA := publicNodeLocalFixtureNode(0)
	_, vmB, privB, pubB := publicNodeLocalFixtureNode(1)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "empty-pool" })
	for pass := 0; pass < 4; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPool] != "empty-pool" {
		t.Fatalf("the union did not start: %#v", f.current(t).Annotations)
	}
	f.setEndpoints(t, "edge-0")
	for pass := 0; pass < 4; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	if !observePublicNodeLocal(t, f).fips[pubB] {
		t.Fatal("the node left inside the grace")
	}
	now = now.Add(publicNodeLocalEndpointGoneGrace + time.Minute)
	for pass := 0; pass < 40; pass++ {
		stepPublicNodeLocal(t, f, pass)
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pubA] || !observed.vips[privA] {
			t.Fatalf("pass %d: the last serving node left: %#v", pass, observed)
		}
	}
	observed := observePublicNodeLocal(t, f)
	if observed.fips[pubB] || observed.vips[privB] || observed.assigned[vmB] {
		t.Fatalf("the node without an endpoint stayed on the edge during the union: %#v", observed)
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPool] != "empty-pool" {
		t.Fatal("the union ended")
	}
}

// shapePublicNodeLocalNamedPorts is the shape of a real edge Service: container
// ports that differ from the Service ports, a named one, and a UDP twin.
func shapePublicNodeLocalNamedPorts(s *corev1.Service) {
	s.Spec.Ports = []corev1.ServicePort{
		{Name: "web", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(8000)},
		{Name: "websecure", Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")},
		{Name: "http3", Protocol: corev1.ProtocolUDP, Port: 443, TargetPort: intstr.FromInt32(8443)},
	}
}

func requireNamedTargetPortsKept(t *testing.T, child *corev1.Service) {
	t.Helper()
	want := map[string]intstr.IntOrString{
		"TCP/80": intstr.FromInt32(8000), "TCP/443": intstr.FromString("https"), "UDP/443": intstr.FromInt32(8443),
	}
	for _, port := range child.Spec.Ports {
		key := fmt.Sprintf("%s/%d", port.Protocol, port.Port)
		expected, tracked := want[key]
		if !tracked {
			continue
		}
		if port.TargetPort != expected {
			t.Fatalf("port %s has target port %v, want %v", key, port.TargetPort, expected)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("ports missing from the rebuilt child: %v (child ports %v)", want, child.Spec.Ports)
	}
}

// A child rebuilt while a new port is held back keeps the real target ports of
// the Service, named or numbered, not the Service port numbers.
func TestPublicNodeLocalHeldRebuildKeepsNamedTargetPorts(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalNamedPorts)
	addPublicNodeLocalFixturePeer(t, f, "peer", "peer-uid", "edge", 9000)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{Name: "extra", Protocol: corev1.ProtocolTCP, Port: 9000, TargetPort: intstr.FromInt32(9000)})
	})
	stepPublicNodeLocal(t, f, 0)
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalTransitionRefused")
	deletePublicNodeLocalFixtureChild(t, f)
	requireChildAndVIPsRestored(t, f, 1, 80, 443)
	requireNamedTargetPortsKept(t, trackedPublicNodeLocalDatapath(t, f))
}

// A port that the change drops stays in the child until its firewall is gone;
// a child lost meanwhile comes back with that port's real target port.
func TestPublicNodeLocalUnionRebuildKeepsNamedTargetPortsOfDroppedPort(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalNamedPorts)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Spec.Ports = []corev1.ServicePort{
			{Name: "websecure", Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")},
			{Name: "http3", Protocol: corev1.ProtocolUDP, Port: 443, TargetPort: intstr.FromInt32(8443)},
		}
	})
	for pass := 0; pass < 80; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" && current.Annotations[annotationNodeLoadBalancerFirewallUUID] != old {
			break
		}
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
		t.Fatal("the union never started")
	}
	deletePublicNodeLocalFixtureChild(t, f)
	requireChildAndVIPsRestored(t, f, 1, 80, 443)
	requireNamedTargetPortsKept(t, trackedPublicNodeLocalDatapath(t, f))
}

func TestPublicNodeLocalActivePortsRoundTripAndBound(t *testing.T) {
	ports := []corev1.ServicePort{
		{Name: "web", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(8000)},
		{Name: "websecure", Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")},
		{Name: "http3", Port: 443, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromInt32(8443)},
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		annotationPublicNodeLocalActivePorts: encodePublicNodeLocalActivePorts(ports),
	}}}
	if got := publicNodeLocalActivePorts(service); !reflect.DeepEqual(got, ports) {
		t.Fatalf("round trip = %#v", got)
	}
	var many []corev1.ServicePort
	for port := int32(1); port <= 400; port++ {
		many = append(many, corev1.ServicePort{Name: fmt.Sprintf("port-%d", port), Protocol: corev1.ProtocolTCP, Port: port, TargetPort: intstr.FromInt32(port)})
	}
	if encoded := encodePublicNodeLocalActivePorts(many); encoded != "" {
		t.Fatalf("an oversized record was kept: %d bytes", len(encoded))
	}
}

func publicNodeLocalEventMessages(t *testing.T, f *publicNodeLocalTransientFixture, reason string) []string {
	t.Helper()
	events, err := f.provider.kubeClient.CoreV1().Events(f.service.Namespace).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var messages []string
	for _, event := range events.Items {
		if event.Reason == reason && event.InvolvedObject.UID == f.service.UID {
			messages = append(messages, event.Message)
		}
	}
	return messages
}

// The TransitionPending Event of a union says how long the union has been open.
func TestPublicNodeLocalPendingEventCarriesUnionAge(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "empty-pool" })
	for pass := 0; pass < 4; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	now = now.Add(3*time.Minute + 20*time.Second)
	for pass := 0; pass < 3; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	found := false
	for _, message := range publicNodeLocalEventMessages(t, f, "PublicNodeLocalTransitionPending") {
		found = found || strings.Contains(message, "union age 3m")
	}
	if !found {
		t.Fatalf("no TransitionPending Event with the union age: %v", publicNodeLocalEventMessages(t, f, "PublicNodeLocalTransitionPending"))
	}
}

// The foreign-account Event is emitted once per state change, not every pass.
func TestPublicNodeLocalForeignAccountEventIsEmittedOncePerStateChange(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	f.api.vms[1].BillingAccountID = 99
	kube := f.provider.kubeClient.(*kubefake.Clientset)
	creates := 0
	kube.PrependReactor("create", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if event, ok := action.(k8stesting.CreateAction).GetObject().(*corev1.Event); ok && event.Reason == publicNodeLocalReasonForeignAccountFirewall {
			creates++
		}
		return false, nil, nil
	})
	for pass := 0; pass < 20; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	if creates != 1 {
		t.Fatalf("the foreign-account Event was emitted %d times in 20 passes, want once", creates)
	}
}

// While the narrowed old firewall is still attached after a promotion, an Event
// says how long that has been going on.
func TestPublicNodeLocalNarrowedOldFirewallEventCarriesAge(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalPorts(443, 80))
	f.provider.api = &lagUnassignAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, skip: 1000}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	setPublicNodeLocalFixturePorts(t, f, 443)
	for pass := 0; pass < 60; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" && current.Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
			break
		}
	}
	if f.current(t).Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		t.Fatal("the change never promoted")
	}
	now = now.Add(7*time.Minute + 5*time.Second)
	for pass := 0; pass < 4; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	found := false
	for _, message := range publicNodeLocalEventMessages(t, f, "PublicNodeLocalOldFirewallAttached") {
		found = found || strings.Contains(message, "7m")
	}
	if !found {
		t.Fatalf("no Event with the age of the attached narrowed firewall: %v", publicNodeLocalEventMessages(t, f, "PublicNodeLocalOldFirewallAttached"))
	}
}

// countingUnassignAPI never applies an unassign and counts the dispatches.
type countingUnassignAPI struct {
	*publicNodeLocalFilteringIPAPI
	calls int
}

func (a *countingUnassignAPI) UnassignFirewallFromVM(context.Context, string, string, string) error {
	a.calls++
	return nil
}

// A parked detach of the narrowed old firewall is retried at the normal cadence:
// detaching is the safe direction, so the 30 minute park does not apply to it.
func TestPublicNodeLocalParkedOldFirewallDetachIsRetried(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalPorts(443, 80))
	api := &countingUnassignAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}}
	f.provider.api = api
	clock := time.Now().UTC()
	f.controller.firewallRelationNow = func() time.Time { return clock }
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	setPublicNodeLocalFixturePorts(t, f, 443)
	parkedAt := -1
	for pass := 0; pass < 120 && parkedAt < 0; pass++ {
		stepPublicNodeLocal(t, f, pass)
		for _, message := range publicNodeLocalEventMessages(t, f, "PublicNodeLocalFirewallRelationStuck") {
			if message != "" {
				parkedAt = pass
			}
		}
		clock = clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
	}
	if parkedAt < 0 {
		t.Fatal("the detach never parked")
	}
	before := api.calls
	// Less than the park time later (one retire interval), the detach is issued again.
	for pass := 0; pass < 4; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	if api.calls <= before {
		t.Fatalf("the parked detach of the old firewall was not retried (calls %d)", api.calls)
	}
}

// Reverting between the creation of the target firewall and the move of the
// ledger leaves the active firewall as the only one.
func TestPublicNodeLocalAbortBetweenFirewallCreateAndLedgerKeepsActiveFirewall(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	hit := false
	for pass := 0; pass < 40 && !hit; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		current := f.current(t)
		hit = len(f.api.firewalls) >= 2 && current.Annotations[annotationNodeLoadBalancerFirewallUUID] == old &&
			current.Annotations[annotationPublicNodeLocalTargetPolicy] != ""
	}
	if !hit {
		t.Fatal("the window between the firewall create and the ledger move was not reached")
	}
	setPublicNodeLocalFixturePorts(t, f, 443)
	runUntil(t, f, []int{0, 1}, 300, "the active firewall is the only one", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" && s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" &&
			len(f.api.firewalls) == 1
	})
	if got := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]; got != old {
		t.Fatalf("ledger = %s, want the active firewall %s", got, old)
	}
}

// promotionPass returns the index of the pass of a fresh scenario in which the
// target is promoted.
func promotionPass(t *testing.T, scenario publicNodeLocalTransitionScenario) int {
	t.Helper()
	probe := scenario.setup(t)
	before := probe.current(t).Annotations[annotationPublicNodeLocalActivePool] + "/" + probe.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	for pass := 0; pass < 400; pass++ {
		stepPublicNodeLocal(t, probe, pass)
		now := probe.current(t).Annotations[annotationPublicNodeLocalActivePool] + "/" + probe.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
		if now != before {
			return pass
		}
	}
	t.Fatal("the scenario never promoted")
	return -1
}

// The promotion needs the proof after publication. In the promotion pass the
// child loses the VIP of the target node for every read after the first one: the
// passes earlier checks work from what they read first, and only the proof reads
// the child again.
func TestPublicNodeLocalPromotionNeedsPostPublicationProof(t *testing.T) {
	scenario := publicNodeLocalTransitionScenarios()[0]
	k := promotionPass(t, scenario)
	f := scenario.setup(t)
	for pass := 0; pass < k; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	_, _, privB, _ := publicNodeLocalFixtureNode(1)
	kube := f.provider.kubeClient.(*kubefake.Clientset)
	name := nodeLoadBalancerDatapathName(f.service)
	reads := 0
	kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		get := action.(k8stesting.GetAction)
		if get.GetName() != name {
			return false, nil, nil
		}
		reads++
		if reads < 2 {
			return false, nil, nil
		}
		object, err := kube.Tracker().Get(get.GetResource(), get.GetNamespace(), get.GetName())
		if err != nil {
			return true, nil, err
		}
		child := object.(*corev1.Service).DeepCopy()
		kept := child.Status.LoadBalancer.Ingress[:0]
		for _, ingress := range child.Status.LoadBalancer.Ingress {
			if ingress.IP != privB {
				kept = append(kept, ingress)
			}
		}
		child.Status.LoadBalancer.Ingress = kept
		return true, child, nil
	})
	_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	if got := f.current(t).Annotations[annotationPublicNodeLocalActivePool]; got != "edge" {
		t.Fatalf("promoted to %q although the proof after publication fails", got)
	}
}

// A new change does not start a union while the previous firewall of the last
// one is still being retired: the ledger has one slot for it.
func TestPublicNodeLocalUnionDoesNotStartWhilePreviousFirewallExists(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	clock := time.Now().UTC()
	f.controller.firewallRelationNow = func() time.Time { return clock }
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	f.provider.api = &lagUnassignAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, skip: 1000}
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	for pass := 0; pass < 60; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" && current.Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
			break
		}
	}
	if f.current(t).Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
		t.Fatal("the first change never promoted")
	}
	setPublicNodeLocalFixturePorts(t, f, 443, 8443, 9443)
	for pass := 0; pass < 20; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" {
			break
		}
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" || current.Annotations[annotationPublicNodeLocalTargetPool] != "" {
			t.Fatalf("pass %d: a union started while the previous firewall %s exists: %#v", pass, current.Annotations[annotationNodeLoadBalancerPreviousFirewall], current.Annotations)
		}
	}
	// The cloud catches up: the old firewall goes, and then the second change is
	// carried out. Refusing to start must not stop the old firewall from going.
	f.provider.api = &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}
	runUntil(t, f, []int{0}, 300, "the second change", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		clock = clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
		return s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" && s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			len(childPortSet(trackedPublicNodeLocalDatapath(t, f))) == 3 && len(f.api.firewalls) == 1
	})
}

// The promotion is compare-and-swap on the ledger too: a ledger that does not
// carry the target policy is not promoted.
func TestPublicNodeLocalPromotionRefusedWhenLedgerPolicyDiffers(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	for pass := 0; pass < 60; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" &&
			current.Annotations[annotationNodeLoadBalancerFirewallHash] == current.Annotations[annotationPublicNodeLocalTargetPolicy] {
			break
		}
	}
	current := f.current(t)
	target := current.Annotations[annotationPublicNodeLocalTargetPolicy]
	if target == "" || current.Annotations[annotationNodeLoadBalancerFirewallHash] != target {
		t.Fatalf("no ledger on the target policy: %#v", current.Annotations)
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerFirewallHash] = "00000000" })
	stale := f.current(t)
	if err := f.controller.promotePublicNodeLocalTransition(f.ctx, stale, "edge", target, stale.Annotations[annotationNodeLoadBalancerFirewallUUID]); err == nil {
		t.Fatal("the promotion went through with a ledger that does not carry the target policy")
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
		t.Fatal("the target was promoted")
	}
}

// The old firewall stays on a kept node that does not hold the new one yet: a
// published node whose endpoint is gone but still inside the grace is kept, never
// gets the new firewall, and keeps its gate until it does.
func TestPublicNodeLocalOldFirewallStaysOnKeptNodeWithoutTheNewOne(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	old := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	_, vm2, _, _ := publicNodeLocalFixtureNode(1)
	f.setEndpoints(t, "edge-0")
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	for pass := 0; pass < 120; pass++ {
		stepPublicNodeLocal(t, f, pass)
		if held := firewallsOfVM(f, vm2); len(held) == 0 {
			t.Fatalf("pass %d: the kept node lost its only firewall: %#v", pass, f.current(t).Annotations)
		}
	}
	current := f.current(t)
	if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" || current.Annotations[annotationNodeLoadBalancerPreviousFirewall] != old {
		t.Fatalf("the change did not reach the promotion with the old firewall kept: %#v", current.Annotations)
	}
	if held := firewallsOfVM(f, vm2); !held[old] || len(held) != 1 {
		t.Fatalf("the kept node does not hold only the old firewall: %v", held)
	}
	// The endpoint returns, the node takes the new firewall, and the old one goes.
	f.setEndpoints(t, "edge-0", "edge-1")
	for pass := 0; pass < 200; pass++ {
		stepPublicNodeLocal(t, f, pass)
		if len(firewallsOfVM(f, vm2)) == 0 {
			t.Fatalf("pass %d: the node had no firewall while it was handed over", pass)
		}
	}
	if current := f.current(t); current.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" {
		t.Fatalf("the old firewall was never retired: %#v", current.Annotations)
	}
}

// A spec change that keeps the policy hash (a new target port, a renamed port)
// still updates the recorded active ports of a Service in the steady state.
func TestPublicNodeLocalActivePortsFollowSpecChangeThatKeepsPolicy(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureWith(t, 1, shapePublicNodeLocalNamedPorts)
	hash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Spec.Ports[1].TargetPort = intstr.FromString("https-new")
		s.Spec.Ports[0].Name = "web-renamed"
	})
	for pass := 0; pass < 6; pass++ {
		stepPublicNodeLocal(t, f, pass)
	}
	current := f.current(t)
	if current.Annotations[annotationPublicNodeLocalActivePolicy] != hash {
		t.Fatalf("the policy changed: %#v", current.Annotations)
	}
	recorded := publicNodeLocalActivePorts(current)
	if len(recorded) != 3 || recorded[1].TargetPort != intstr.FromString("https-new") || recorded[0].Name != "web-renamed" {
		t.Fatalf("the recorded active ports are stale: %#v", recorded)
	}
}

// The promotion re-checks the live Service: a spec that moved on since the pass
// began is not promoted, and its ports are not recorded.
func TestPublicNodeLocalPromotionRefusedWhenLivePolicyMovedOn(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	for pass := 0; pass < 60; pass++ {
		stepPublicNodeLocal(t, f, pass)
		current := f.current(t)
		if current.Annotations[annotationPublicNodeLocalTargetPolicy] != "" &&
			current.Annotations[annotationNodeLoadBalancerFirewallHash] == current.Annotations[annotationPublicNodeLocalTargetPolicy] {
			break
		}
	}
	target := f.current(t).Annotations[annotationPublicNodeLocalTargetPolicy]
	ledger := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]
	setPublicNodeLocalFixturePorts(t, f, 443, 9443)
	if err := f.controller.promotePublicNodeLocalTransition(f.ctx, f.current(t), "edge", target, ledger); err == nil {
		t.Fatal("the promotion went through although the live policy is not the target")
	}
	if f.current(t).Annotations[annotationPublicNodeLocalTargetPolicy] == "" {
		t.Fatal("the target was promoted")
	}
}

// startStuckRebuild begins a rebuild whose detach never reads back. It returns
// once the rebuild marker and the detach journal are set.
func startStuckRebuild(t *testing.T, f *publicNodeLocalTransientFixture) {
	t.Helper()
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
	for pass := 0; pass < 20; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		current := f.current(t)
		if current.Annotations[annotationNodeLoadBalancerRebuilding] != "" && current.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != "" {
			return
		}
	}
	t.Fatalf("the rebuild never started: %#v", f.current(t).Annotations)
}

// The operator removes the escape hatch before any detach has been read back:
// the rebuild is cancelled and the Service goes back to normal convergence, which
// carries the pending change out in place.
func TestPublicNodeLocalRebuildCancelledWhenAnnotationRemovedBeforeAnyDetachReadBack(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.provider.api = &lagUnassignAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, skip: 1000}
	oldHash := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	startStuckRebuild(t, f)
	statusBefore := f.current(t).Status
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { delete(s.Annotations, annotationNodeLoadBalancerAllowRebuild) })
	// The cloud recovers.
	f.provider.api = &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}
	clock := time.Now().UTC()
	f.controller.firewallRelationNow = func() time.Time { return clock }
	f.controller.firewallRelationAbsentDelay = nodeLoadBalancerAbsenceConfirmationDelay
	cancelled := false
	runUntil(t, f, []int{0}, 300, "the pending change in place", func(o publicNodeLocalObservation, s *corev1.Service) bool {
		clock = clock.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
		cancelled = cancelled || s.Annotations[annotationNodeLoadBalancerRebuilding] == ""
		return s.Annotations[annotationPublicNodeLocalActivePolicy] != oldHash && s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == ""
	})
	if !cancelled || len(f.current(t).Status.LoadBalancer.Ingress) != len(statusBefore.LoadBalancer.Ingress) {
		t.Fatalf("the rebuild was not cancelled in place: %#v", f.current(t).Annotations)
	}
	if f.current(t).Annotations[annotationNodeLoadBalancerRebuilding] != "" {
		t.Fatal("the rebuild marker stayed")
	}
}

// Once a detach has been read back, the rebuild can no longer be cancelled. It
// goes on, and an Event says how to recover.
func TestPublicNodeLocalRebuildCannotBeCancelledAfterADetachReadBack(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm1, _, _ := publicNodeLocalFixtureNode(0)
	_, vm2, _, _ := publicNodeLocalFixtureNode(1)
	// vm2 never detaches (a stuck relation); vm1 does.
	f.provider.api = &neverUnassignVMAPI{publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}, stuckVM: vm2}
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
	for pass := 0; pass < 40; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		if len(firewallsOfVM(f, vm1)) == 0 {
			break
		}
	}
	if len(firewallsOfVM(f, vm1)) != 0 || len(firewallsOfVM(f, vm2)) == 0 {
		t.Fatalf("no partial detach: vm1 %v vm2 %v", firewallsOfVM(f, vm1), firewallsOfVM(f, vm2))
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { delete(s.Annotations, annotationNodeLoadBalancerAllowRebuild) })
	for pass := 0; pass < 6; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	}
	if f.current(t).Annotations[annotationNodeLoadBalancerRebuilding] == "" {
		t.Fatal("the rebuild was cancelled after a detach had been read back")
	}
	found := false
	for _, message := range publicNodeLocalEventMessages(t, f, "PublicNodeLocalRebuildStuck") {
		found = found || (strings.Contains(message, "cannot be cancelled") && strings.Contains(message, "recover"))
	}
	if !found {
		t.Fatalf("no Event that says how to recover: %v", publicNodeLocalEventMessages(t, f, "PublicNodeLocalRebuildStuck"))
	}
}
