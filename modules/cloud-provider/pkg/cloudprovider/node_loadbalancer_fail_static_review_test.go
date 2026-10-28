package cloudprovider

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
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
