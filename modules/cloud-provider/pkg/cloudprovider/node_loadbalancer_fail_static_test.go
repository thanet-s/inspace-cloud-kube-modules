package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestPublicNodeLocalAssignTimeoutExceedsRelationRetireDelay(t *testing.T) {
	floor := nodeLoadBalancerFirewallRelationRetireDelay + 2*nodeLoadBalancerAbsenceConfirmationDelay
	if nodeLoadBalancerPublicNodeLocalAssignTimeout < floor {
		t.Fatalf("assignment timeout %s is shorter than the relation retire path %s",
			nodeLoadBalancerPublicNodeLocalAssignTimeout, floor)
	}
}

func TestPublicNodeLocalExpiredAssignmentIntentRefreshesWithoutWithdraw(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "51111111-2222-4333-8444-555555555555"
		firewallUUID = "52222222-2222-4333-8444-555555555555"
		privateIP    = "10.0.0.51"
		publicIP     = "203.0.113.51"
	)
	service := publicNodeLocalTestService("expired", "expired-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	node := publicNodeLocalTestNode("edge-expired", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		floatingIPs: []inspace.FloatingIP{{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		}},
	}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, node.Name)
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-7 * time.Minute)
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = expired.Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
	service.Annotations[annotationPublicNodeLocalAssignVMs] = vmUUID
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("expired-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy(), datapath)
	key := service.Namespace + "/" + service.Name

	if err := controller.syncPublicNodeLocal(ctx, key, service); err != nil {
		t.Fatalf("expired intent failed the Service: %v", err)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("expired intent unassigned a firewall: %#v", api.unassignedFirewalls)
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assignAt, parseErr := time.Parse(time.RFC3339Nano, stored.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
	if parseErr != nil || !assignAt.After(expired.Add(6*time.Minute)) {
		t.Fatalf("assignment intent was not refreshed: %q err=%v", stored.Annotations[annotationNodeLoadBalancerFirewallAssignAt], parseErr)
	}
	for attempt := 0; attempt < 12; attempt++ {
		current, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if len(current.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(current) {
			break
		}
		if err := controller.syncPublicNodeLocal(ctx, key, current); err != nil {
			t.Fatalf("recovery reconcile %d: %v", attempt, err)
		}
	}
	stored, err = provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Status.LoadBalancer.Ingress) != 1 || publicNodeLocalAssignmentFencePresent(stored) {
		t.Fatalf("refreshed intent did not converge: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("recovery unassigned a firewall: %#v", api.unassignedFirewalls)
	}
}

func requirePublicNodeLocalEvent(t *testing.T, f *publicNodeLocalTransientFixture, reason string) {
	t.Helper()
	events, err := f.provider.kubeClient.CoreV1().Events(f.service.Namespace).List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Items {
		if event.Reason == reason && event.Type == corev1.EventTypeWarning && event.InvolvedObject.UID == f.service.UID {
			return
		}
	}
	t.Fatalf("no Warning Event with reason %s: %#v", reason, events.Items)
}

func updatePublicNodeLocalFixtureService(t *testing.T, f *publicNodeLocalTransientFixture, mutate func(*corev1.Service)) {
	t.Helper()
	current := f.current(t).DeepCopy()
	mutate(current)
	if _, err := f.provider.kubeClient.CoreV1().Services(current.Namespace).Update(f.ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// trackedPublicNodeLocalDatapath reads the child straight from the object
// tracker, so tests that count reactor reads are not disturbed.
func trackedPublicNodeLocalDatapath(t *testing.T, f *publicNodeLocalTransientFixture) *corev1.Service {
	t.Helper()
	kube := f.provider.kubeClient.(*kubefake.Clientset)
	object, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("services"), f.service.Namespace, nodeLoadBalancerDatapathName(f.service))
	if err != nil {
		t.Fatal(err)
	}
	return object.(*corev1.Service).DeepCopy()
}

func TestPublicNodeLocalDefiniteFailureHoldsPublishedState(t *testing.T) {
	definite := errors.New("canonical ownership mismatch")
	datapathReads := func() int {
		probe := newPublishedPublicNodeLocalFixture(t)
		kube := probe.provider.kubeClient.(*kubefake.Clientset)
		name := nodeLoadBalancerDatapathName(probe.service)
		reads := 0
		kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if action.(k8stesting.GetAction).GetName() == name {
				reads++
			}
			return false, nil, nil
		})
		if err := probe.controller.syncPublicNodeLocal(probe.ctx, probe.key, probe.current(t)); err != nil {
			t.Fatalf("steady-state reconcile: %v", err)
		}
		return reads
	}()
	if datapathReads < 2 {
		t.Fatalf("steady-state reconcile read the datapath only %d times", datapathReads)
	}

	type holdCase struct {
		name       string
		prepare    func(*testing.T, *publicNodeLocalTransientFixture)
		wantReason string
		wantNil    bool
	}
	cases := []holdCase{
		{name: "GetVM definite error", wantReason: "PublicNodeLocalHolding", prepare: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: f.api, err: definite}
		}},
		{name: "ListFirewalls definite error", wantReason: "PublicNodeLocalHolding", prepare: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.provider.api = &aggregateListFirewallsErrorAPI{fakeAPI: f.api, err: definite}
		}},
		{name: "Services list definite error", wantReason: "PublicNodeLocalHolding", prepare: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
			f.provider.kubeClient.(*kubefake.Clientset).PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, definite
			})
		}},
		{name: "invalid pool annotation", wantReason: "PublicNodeLocalHolding", prepare: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "Bad_Pool" })
		}},
		{name: "pool annotation change", wantReason: "PublicNodeLocalTransitionPending", wantNil: true, prepare: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "other" })
		}},
		{name: "port change", wantReason: "PublicNodeLocalTransitionPending", wantNil: true, prepare: func(t *testing.T, f *publicNodeLocalTransientFixture) {
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.Ports[0].Port = 8443 })
		}},
	}
	for drifted := 2; drifted <= datapathReads; drifted++ {
		drifted := drifted
		cases = append(cases, holdCase{
			name: fmt.Sprintf("datapath drift at read %d", drifted), wantReason: "PublicNodeLocalHolding",
			prepare: func(_ *testing.T, f *publicNodeLocalTransientFixture) {
				kube := f.provider.kubeClient.(*kubefake.Clientset)
				name := nodeLoadBalancerDatapathName(f.service)
				seen := 0
				kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
					get := action.(k8stesting.GetAction)
					if get.GetName() != name {
						return false, nil, nil
					}
					seen++
					if seen != drifted {
						return false, nil, nil
					}
					object, err := kube.Tracker().Get(get.GetResource(), get.GetNamespace(), get.GetName())
					if err != nil {
						return true, nil, err
					}
					copy := object.(*corev1.Service).DeepCopy()
					copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
					copy.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
					return true, copy, nil
				})
			},
		})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixture(t)
			test.prepare(t, f)
			before := f.current(t)
			datapathBefore := trackedPublicNodeLocalDatapath(t, f)
			unassignedBefore := len(f.api.unassignedFirewalls)

			syncErr := f.controller.syncPublicNodeLocal(f.ctx, f.key, before)

			var holding *errPublicNodeLocalHolding
			switch {
			case test.wantNil && syncErr != nil:
				t.Fatalf("pending transition returned an error: %v", syncErr)
			case !test.wantNil && !errors.As(syncErr, &holding):
				t.Fatalf("error = %v, want a holding error", syncErr)
			case syncErr != nil && inspace.IsTransient(syncErr):
				t.Fatalf("holding error is transient: %v", syncErr)
			}
			after := f.current(t)
			if !reflect.DeepEqual(after.Status, before.Status) || !reflect.DeepEqual(after.Annotations, before.Annotations) {
				t.Fatalf("parent changed: status=%#v annotations=%#v", after.Status, after.Annotations)
			}
			datapath := trackedPublicNodeLocalDatapath(t, f)
			if !reflect.DeepEqual(datapath.Status, datapathBefore.Status) || !reflect.DeepEqual(datapath.Spec, datapathBefore.Spec) {
				t.Fatalf("child changed: %#v", datapath)
			}
			if len(f.api.unassignedFirewalls) != unassignedBefore {
				t.Fatalf("firewall detached: %v", f.api.unassignedFirewalls)
			}
			requirePublicNodeLocalEvent(t, f, test.wantReason)
		})
	}
}

func TestPublicNodeLocalUnpublishedFailureStillFailsClosed(t *testing.T) {
	f := newPublishedPublicNodeLocalFixture(t)
	// Nothing is serving: no activation and no public status, only a leftover
	// firewall assignment. That is not a last known good exposure.
	current := f.current(t).DeepCopy()
	for _, key := range []string{
		annotationPublicNodeLocalActivePool, annotationPublicNodeLocalActivePolicy,
		annotationNodeLoadBalancerFirewallAssigning, annotationNodeLoadBalancerFirewallAssignAt,
		annotationPublicNodeLocalAssignPolicy, annotationPublicNodeLocalAssignVMs,
	} {
		delete(current.Annotations, key)
	}
	if _, err := f.provider.kubeClient.CoreV1().Services(current.Namespace).Update(f.ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	current = f.current(t).DeepCopy()
	current.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	if _, err := f.provider.kubeClient.CoreV1().Services(current.Namespace).UpdateStatus(f.ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	unassignedBefore := len(f.api.unassignedFirewalls)
	err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	var holding *errPublicNodeLocalHolding
	if err == nil || errors.As(err, &holding) {
		t.Fatalf("unpublished failure error = %v, want a fail-closed error", err)
	}
	if len(f.api.unassignedFirewalls) == unassignedBefore {
		t.Fatal("unpublished failure did not close the leftover firewall assignment")
	}
}
