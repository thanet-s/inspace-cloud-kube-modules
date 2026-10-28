package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
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

func TestPublicNodeLocalClassifyNodes(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID    = "21111111-2222-4333-8444-555555555555"
		privateIP = "10.0.0.31"
		publicIP  = "203.0.113.31"
	)
	tests := []struct {
		name        string
		mutate      func(*fakeAPI, *corev1.Node)
		getVMErr    error
		noNode      bool
		noEndpoint  bool
		publishedIP string
		ready       []string
		gone        []string
		unverified  []string
		missing     []string
		notEligible []string
	}{
		{name: "ready node", ready: []string{"edge-classify"}},
		{name: "no ready endpoint", noEndpoint: true, missing: []string{"edge-classify"}},
		{name: "node object absent but published", noNode: true, publishedIP: privateIP, gone: []string{privateIP}},
		{name: "node is deleting", gone: []string{"edge-classify"}, mutate: func(_ *fakeAPI, node *corev1.Node) {
			now := metav1.Now()
			node.DeletionTimestamp = &now
		}},
		{name: "deleted VM tombstone", gone: []string{"edge-classify"}, mutate: func(api *fakeAPI, _ *corev1.Node) {
			api.vms[0].Status = "Deleted"
		}},
		{name: "VM exact not found", gone: []string{"edge-classify"}, mutate: func(api *fakeAPI, _ *corev1.Node) {
			api.vms = nil
		}},
		{name: "valid empty VPC membership", gone: []string{"edge-classify"}, mutate: func(api *fakeAPI, _ *corev1.Node) {
			api.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}
		}},
		{name: "pool label changed", gone: []string{"edge-classify"}, mutate: func(_ *fakeAPI, node *corev1.Node) {
			node.Labels[publicNodeLocalPoolLabel] = "other"
		}},
		{name: "GetVM definite error", unverified: []string{"edge-classify"}, getVMErr: errors.New("canonical ownership read failed")},
		{name: "metadata mismatch", unverified: []string{"edge-classify"}, mutate: func(api *fakeAPI, _ *corev1.Node) {
			api.floatingIPs[0].Address = "203.0.113.99"
		}},
		{name: "foreign billing account", notEligible: []string{"edge-classify"}, mutate: func(api *fakeAPI, _ *corev1.Node) {
			api.vms[0].BillingAccountID = 99
		}},
		{name: "node not ready", notEligible: []string{"edge-classify"}, mutate: func(_ *fakeAPI, node *corev1.Node) {
			node.Status.Conditions[0].Status = corev1.ConditionFalse
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := publicNodeLocalTestService("classify", "classify-service-uid", "edge", corev1.ProtocolTCP, 443)
			service.Finalizers = []string{publicNodeLocalFinalizer}
			node := publicNodeLocalTestNode("edge-classify", vmUUID, privateIP, publicIP)
			api := &fakeAPI{
				vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
				floatingIPs: []inspace.FloatingIP{{
					Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
					AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
				}},
			}
			if test.mutate != nil {
				test.mutate(api, node)
			}
			var providerAPI API = &publicNodeLocalFilteringIPAPI{fakeAPI: api}
			if test.getVMErr != nil {
				providerAPI = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: api, err: test.getVMErr}
			}
			provider := newTestProvider(t, providerAPI)
			objects := []runtime.Object{service.DeepCopy()}
			if !test.noNode {
				objects = append(objects, node.DeepCopy())
			}
			if test.publishedIP != "" {
				datapath := desiredPublicNodeLocalDatapath(service, "edge")
				mode := corev1.LoadBalancerIPModeVIP
				datapath.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: test.publishedIP, IPMode: &mode}}
				objects = append(objects, datapath)
			}
			provider.kubeClient = kubefake.NewSimpleClientset(objects...)
			controller := &nodeLoadBalancerController{provider: provider}
			if test.noEndpoint {
				controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service)
			} else {
				controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, node.Name)
			}
			intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{})
			if err != nil {
				t.Fatal(err)
			}

			set, _, err := controller.classifyPublicNodeLocalNodes(ctx, service, intent)
			if err != nil {
				t.Fatalf("classification failed: %v", err)
			}
			readyNames := make([]string, 0, len(set.Ready))
			for _, address := range set.Ready {
				readyNames = append(readyNames, address.Node.Name)
			}
			keys := func(values map[string]string) []string {
				result := make([]string, 0, len(values))
				for key := range values {
					result = append(result, key)
				}
				sort.Strings(result)
				return result
			}
			unverified := make([]string, 0, len(set.Unverified))
			for key := range set.Unverified {
				unverified = append(unverified, key)
			}
			missing := make([]string, 0, len(set.EndpointMissing))
			for key := range set.EndpointMissing {
				missing = append(missing, key)
			}
			for name, got := range map[string][2][]string{
				"ready": {readyNames, test.ready}, "gone": {keys(set.Gone), test.gone},
				"unverified": {unverified, test.unverified}, "endpoint missing": {missing, test.missing},
				"not eligible": {keys(set.NotEligible), test.notEligible},
			} {
				if len(got[0]) != len(got[1]) || (len(got[0]) != 0 && !reflect.DeepEqual(got[0], got[1])) {
					t.Fatalf("%s = %v, want %v (set=%#v)", name, got[0], got[1], set)
				}
			}
		})
	}
}

// publicNodeLocalObservation is one look at the three places that carry the
// exposure of a Service: the parent FIPs, the child VIPs and the firewall.
type publicNodeLocalObservation struct {
	fips     map[string]bool
	vips     map[string]bool
	assigned map[string]bool
}

func observePublicNodeLocal(t *testing.T, f *publicNodeLocalTransientFixture) publicNodeLocalObservation {
	t.Helper()
	observed := publicNodeLocalObservation{fips: map[string]bool{}, vips: map[string]bool{}, assigned: map[string]bool{}}
	for _, ingress := range f.current(t).Status.LoadBalancer.Ingress {
		observed.fips[ingress.IP] = true
	}
	for _, ingress := range trackedPublicNodeLocalDatapath(t, f).Status.LoadBalancer.Ingress {
		observed.vips[ingress.IP] = true
	}
	for _, firewall := range f.api.firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			observed.assigned[resource.ResourceUUID] = true
		}
	}
	return observed
}

// requireMakeBeforeBreak checks the order of the edge: a FIP only points at a
// node whose firewall is assigned, and a firewall is only assigned to a node
// whose child VIP exists.
func (o publicNodeLocalObservation) requireMakeBeforeBreak(t *testing.T, pass int, index int) {
	t.Helper()
	_, vmUUID, privateIP, publicIP := publicNodeLocalFixtureNode(index)
	if o.fips[publicIP] && (!o.assigned[vmUUID] || !o.vips[privateIP]) {
		t.Fatalf("pass %d: FIP %s is published before its firewall and VIP: %#v", pass, publicIP, o)
	}
	if o.assigned[vmUUID] && !o.vips[privateIP] {
		t.Fatalf("pass %d: VM %s is assigned before its child VIP exists: %#v", pass, vmUUID, o)
	}
}

func (f *publicNodeLocalTransientFixture) setEndpoints(t *testing.T, names ...string) {
	t.Helper()
	f.endpointNodes = names
	f.controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, f.service, names...)
}

// addNode creates the i-th fixture Node with its VM and FIP, and gives it a
// Ready endpoint.
func (f *publicNodeLocalTransientFixture) addNode(t *testing.T, index int) {
	t.Helper()
	if f.provider.api == API(f.api) {
		// With several Nodes the FIP lookup has to filter by VM.
		f.provider.api = &publicNodeLocalFilteringIPAPI{fakeAPI: f.api}
	}
	name, vmUUID, privateIP, publicIP := publicNodeLocalFixtureNode(index)
	node := publicNodeLocalTestNode(name, vmUUID, privateIP, publicIP)
	f.api.vms = append(f.api.vms, inspace.VM{UUID: vmUUID, Name: name, Hostname: name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID})
	f.api.floatingIPs = append(f.api.floatingIPs, inspace.FloatingIP{
		Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
	})
	if _, err := f.provider.kubeClient.CoreV1().Nodes().Create(f.ctx, node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, append(append([]string(nil), f.endpointNodes...), name)...)
}

func TestPublicNodeLocalAddNodeKeepsExistingIPsPublished(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 1)
	f.addNode(t, 1)
	_, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	_, _, priv1, pub1 := publicNodeLocalFixtureNode(0)
	converged := false
	for pass := 0; pass < 40 && !converged; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub1] || !observed.vips[priv1] {
			t.Fatalf("pass %d: the existing node left the edge: %#v", pass, observed)
		}
		if len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("pass %d: a firewall was detached: %v", pass, f.api.unassignedFirewalls)
		}
		observed.requireMakeBeforeBreak(t, pass, 1)
		converged = observed.fips[pub2] && observed.vips[priv2] && observed.assigned[vm2] &&
			!publicNodeLocalAssignmentFencePresent(f.current(t))
	}
	if !converged {
		t.Fatalf("the added node never converged: %#v", observePublicNodeLocal(t, f))
	}
}

func TestPublicNodeLocalRemoveNodeDetachesOnlyThatVM(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm1, priv1, pub1 := publicNodeLocalFixtureNode(0)
	name2, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, "edge-0")
	firewallUUID := f.api.firewalls[0].UUID
	done := false
	for pass := 0; pass < 40 && !done; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub1] || !observed.vips[priv1] || !observed.assigned[vm1] {
			t.Fatalf("pass %d: the remaining node left the edge: %#v", pass, observed)
		}
		if len(f.api.unassignedFirewalls) != 0 && observed.fips[pub2] {
			t.Fatalf("pass %d: the firewall was detached while the FIP was still published", pass)
		}
		if !observed.vips[priv2] && observed.assigned[vm2] {
			t.Fatalf("pass %d: the child VIP left before the firewall was detached: %#v", pass, observed)
		}
		done = !observed.fips[pub2] && !observed.vips[priv2] && !observed.assigned[vm2]
	}
	if !done {
		t.Fatalf("the removed node never left the edge: %#v", observePublicNodeLocal(t, f))
	}
	if want := []string{firewallUUID + "/" + vm2}; !reflect.DeepEqual(f.api.unassignedFirewalls, want) {
		t.Fatalf("unassigned = %v, want %v", f.api.unassignedFirewalls, want)
	}
}

func TestPublicNodeLocalEndpointGoneRemovesAfterGrace(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	_, _, _, pub1 := publicNodeLocalFixtureNode(0)
	_, _, _, pub2 := publicNodeLocalFixtureNode(1)
	f.setEndpoints(t, "edge-0")
	run := func(passes int) {
		for pass := 0; pass < passes; pass++ {
			if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err != nil {
				t.Fatalf("pass %d: %v", pass, err)
			}
		}
	}
	run(1)
	now = now.Add(30 * time.Second)
	run(3)
	if observed := observePublicNodeLocal(t, f); !observed.fips[pub2] || len(f.api.unassignedFirewalls) != 0 {
		t.Fatalf("the node was removed inside the grace: %#v", observed)
	}
	now = now.Add(31 * time.Second)
	run(12)
	observed := observePublicNodeLocal(t, f)
	if observed.fips[pub2] || !observed.fips[pub1] {
		t.Fatalf("the node was not removed after the grace: %#v", observed)
	}
}

func TestPublicNodeLocalZeroReadyEndpointsHoldsPublication(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	f.controller.publicNodeLocalNow = func() time.Time { return now }
	f.setEndpoints(t)
	before := f.current(t)
	childBefore := trackedPublicNodeLocalDatapath(t, f)
	mutations := managedNodeLoadBalancerMutationSnapshot(f.api)
	for pass := 0; pass < 10; pass++ {
		if pass == 5 {
			now = now.Add(time.Hour)
		}
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &holding) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		after := f.current(t)
		if !reflect.DeepEqual(after.Status, before.Status) || !reflect.DeepEqual(after.Annotations, before.Annotations) {
			t.Fatalf("pass %d: the parent changed: %#v", pass, after.Status)
		}
		if child := trackedPublicNodeLocalDatapath(t, f); !reflect.DeepEqual(child.Status, childBefore.Status) {
			t.Fatalf("pass %d: the child changed: %#v", pass, child.Status)
		}
		if got := managedNodeLoadBalancerMutationSnapshot(f.api); got != mutations || len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("pass %d: the firewall changed", pass)
		}
	}
	requirePublicNodeLocalEvent(t, f, "PublicNodeLocalNoReadyEndpoints")
}

// vmGetErrorAPI fails GetVM for one VM only.
type vmGetErrorAPI struct {
	*publicNodeLocalFilteringIPAPI
	badVM string
	err   error
}

func (a *vmGetErrorAPI) GetVM(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	if uuid == a.badVM {
		return nil, a.err
	}
	return a.publicNodeLocalFilteringIPAPI.GetVM(ctx, location, uuid)
}

func TestPublicNodeLocalUnverifiedPublishedNodeIsHeld(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	_, vm2, _, pub2 := publicNodeLocalFixtureNode(1)
	_, _, _, pub3 := publicNodeLocalFixtureNode(2)
	f.provider.api = &vmGetErrorAPI{
		publicNodeLocalFilteringIPAPI: &publicNodeLocalFilteringIPAPI{fakeAPI: f.api},
		badVM:                         vm2, err: errors.New("canonical ownership read failed"),
	}
	f.addNode(t, 2)
	for pass := 0; pass < 50; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &holding) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub2] {
			t.Fatalf("pass %d: the unverified published node was removed: %#v", pass, observed)
		}
		if len(f.api.unassignedFirewalls) != 0 {
			t.Fatalf("pass %d: a firewall was detached: %v", pass, f.api.unassignedFirewalls)
		}
		observed.requireMakeBeforeBreak(t, pass, 2)
		if observed.fips[pub3] {
			return
		}
	}
	t.Fatalf("the third node was never added: %#v", observePublicNodeLocal(t, f))
}

func TestPublicNodeLocalAllPublishedNodesGoneWithdraws(t *testing.T) {
	f := newPublishedPublicNodeLocalFixtureN(t, 2)
	for _, name := range []string{"edge-0", "edge-1"} {
		if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	f.setEndpoints(t)
	for pass := 0; pass < 60; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		if current := f.current(t); len(current.Status.LoadBalancer.Ingress) == 0 &&
			current.Annotations[annotationPublicNodeLocalActivePool] == "" {
			break
		}
	}
	current := f.current(t)
	if len(current.Status.LoadBalancer.Ingress) != 0 || current.Annotations[annotationPublicNodeLocalActivePool] != "" {
		t.Fatalf("the Service was not withdrawn: %#v %#v", current.Status, current.Annotations)
	}
	if len(f.api.unassignedFirewalls) != 2 {
		t.Fatalf("unassigned = %v, want both VMs", f.api.unassignedFirewalls)
	}
}
