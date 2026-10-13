package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	cloud "k8s.io/cloud-provider"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func transientProviderError() error {
	return &inspace.APIError{StatusCode: http.StatusServiceUnavailable, Method: http.MethodGet, Path: "/v1/bkk01/vm", Message: "unavailable", Retryable: true}
}

func transientProviderTimeout() error {
	return fmt.Errorf("inspace: GET /v1/bkk01/vm: %w", &url.Error{Op: "Get", URL: "https://api.inspace.cloud", Err: context.DeadlineExceeded})
}

// requireNoServiceOrNodeWrites fails when the Kubernetes client wrote a Node
// or Service after the first `since` actions.
func requireNoServiceOrNodeWrites(t *testing.T, harness *aggregateSafetySyncHarness, since int) {
	t.Helper()
	kube := harness.provider.kubeClient.(*kubefake.Clientset)
	for _, action := range kube.Actions()[since:] {
		switch action.GetVerb() {
		case "create", "update", "patch", "delete":
			switch action.GetResource().Resource {
			case "nodes", "services":
				t.Fatalf("transient provider error wrote Kubernetes state: %s %s", action.GetVerb(), action.GetResource().Resource)
			}
		}
	}
}

func TestAggregateKeepsPublishedStateOnTransientProviderErrors(t *testing.T) {
	const vmUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		name   string
		inject func(*aggregateSafetySyncHarness)
	}{
		{name: "GetVM timeout", inject: func(h *aggregateSafetySyncHarness) {
			h.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: h.api, err: transientProviderTimeout()}
		}},
		{name: "GetVM 503", inject: func(h *aggregateSafetySyncHarness) {
			h.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: h.api, err: transientProviderError()}
		}},
		{name: "ListFirewalls 503", inject: func(h *aggregateSafetySyncHarness) {
			h.provider.api = &aggregateListFirewallsErrorAPI{fakeAPI: h.api, err: transientProviderError()}
		}},
		{name: "network read 503", inject: func(h *aggregateSafetySyncHarness) {
			h.api.networkErr = transientProviderError()
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
				fmt.Sprintf("aggregate-transient-%d", index),
				fmt.Sprintf("7777777%d-7777-4777-8777-777777777777", index),
				corev1.ProtocolTCP,
				9100+int32(index),
			))
			defer harness.controller.queue.ShutDown()
			harness.converge(t)
			parentBefore := harness.service(t)
			childBefore, err := harness.provider.kubeClient.CoreV1().Services(parentBefore.Namespace).Get(
				harness.ctx, nodeLoadBalancerDatapathName(parentBefore), metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(parentBefore.Status.LoadBalancer.Ingress) == 0 || len(childBefore.Status.LoadBalancer.Ingress) == 0 {
				t.Fatalf("fixture is not published: parent=%#v child=%#v", parentBefore.Status, childBefore.Status)
			}
			firewallsBefore := append([]inspace.Firewall(nil), harness.api.firewalls...)
			mutationsBefore := managedNodeLoadBalancerMutationSnapshot(harness.api)
			actionsBefore := len(harness.provider.kubeClient.(*kubefake.Clientset).Actions())

			test.inject(harness)
			if err := harness.controller.sync(harness.ctx, harness.key); err == nil {
				t.Fatal("sync under a transient provider error returned nil, want a retryable error")
			} else if !inspace.IsTransient(err) {
				t.Fatalf("sync error lost its transient cause: %v", err)
			}

			requireNoServiceOrNodeWrites(t, harness, actionsBefore)
			parentAfter := harness.service(t)
			if !reflect.DeepEqual(parentAfter.Status, parentBefore.Status) {
				t.Fatalf("parent status changed: got %#v want %#v", parentAfter.Status, parentBefore.Status)
			}
			childAfter, err := harness.provider.kubeClient.CoreV1().Services(parentAfter.Namespace).Get(
				harness.ctx, nodeLoadBalancerDatapathName(parentAfter), metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(childAfter.Status, childBefore.Status) {
				t.Fatalf("datapath status changed: got %#v want %#v", childAfter.Status, childBefore.Status)
			}
			node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if node.Labels[nodeLoadBalancerReadyLabel] != "true" {
				t.Fatalf("ready label removed on a transient error: %#v", node.Labels)
			}
			if got := managedNodeLoadBalancerMutationSnapshot(harness.api); got != mutationsBefore {
				t.Fatalf("firewall mutated on a transient error: before=%#v after=%#v", mutationsBefore, got)
			}
			if !reflect.DeepEqual(harness.api.firewalls, firewallsBefore) {
				t.Fatalf("firewalls changed on a transient error")
			}
			_ = vmUUID
		})
	}
}

func TestAggregateStillWithdrawsOnDefiniteProviderErrors(t *testing.T) {
	const vmUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		name string
		err  error
	}{
		{name: "exact GET 404", err: &inspace.APIError{
			StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/bkk01/vm/" + vmUUID,
			ExactLookup: true, RequestedUUID: vmUUID,
		}},
		{name: "ownership mismatch", err: errors.New("canonical ownership mismatch")},
		{name: "transient joined with definite", err: errors.Join(transientProviderTimeout(), errors.New("canonical ownership mismatch"))},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
				fmt.Sprintf("aggregate-definite-%d", index),
				fmt.Sprintf("6666666%d-6666-4666-8666-666666666666", index),
				corev1.ProtocolTCP,
				9200+int32(index),
			))
			defer harness.controller.queue.ShutDown()
			harness.converge(t)
			harness.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: harness.api, err: test.err}
			_ = harness.controller.sync(harness.ctx, harness.key)
			harness.requireClosed(t)
		})
	}
}

type publicNodeLocalTransientFixture struct {
	ctx        context.Context
	api        *fakeAPI
	provider   *Provider
	controller *nodeLoadBalancerController
	service    *corev1.Service
	key        string
}

func newPublishedPublicNodeLocalFixture(t *testing.T) *publicNodeLocalTransientFixture {
	t.Helper()
	const (
		vmUUID    = "11111111-2222-4333-8444-555555555555"
		privateIP = "10.0.0.21"
		publicIP  = "203.0.113.21"
	)
	service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	node := publicNodeLocalTestNode("edge-0", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		floatingIPs: []inspace.FloatingIP{{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		}},
	}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, node.Name)
	fixture := &publicNodeLocalTransientFixture{
		ctx: context.Background(), api: api, provider: provider, controller: controller,
		service: service, key: service.Namespace + "/" + service.Name,
	}
	for attempt := 0; attempt < 24; attempt++ {
		if err := controller.syncPublicNodeLocal(fixture.ctx, fixture.key, fixture.current(t)); err != nil {
			t.Fatalf("publish reconcile %d: %v", attempt, err)
		}
		if len(fixture.current(t).Status.LoadBalancer.Ingress) == 1 {
			return fixture
		}
	}
	t.Fatalf("fixture did not publish: %#v", fixture.current(t).Status)
	return nil
}

func (f *publicNodeLocalTransientFixture) current(t *testing.T) *corev1.Service {
	t.Helper()
	current, err := f.provider.kubeClient.CoreV1().Services(f.service.Namespace).Get(f.ctx, f.service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func TestPublicNodeLocalKeepsPublishedStateOnTransientProviderErrors(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*publicNodeLocalTransientFixture)
	}{
		{name: "GetVM timeout", inject: func(f *publicNodeLocalTransientFixture) {
			f.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: f.api, err: transientProviderTimeout()}
		}},
		{name: "ListFirewalls 503", inject: func(f *publicNodeLocalTransientFixture) {
			f.provider.api = &aggregateListFirewallsErrorAPI{fakeAPI: f.api, err: transientProviderError()}
		}},
		{name: "network read 503", inject: func(f *publicNodeLocalTransientFixture) {
			f.api.networkErr = transientProviderError()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublishedPublicNodeLocalFixture(t)
			before := fixture.current(t)
			unassignedBefore := len(fixture.api.unassignedFirewalls)
			datapathBefore, err := fixture.provider.kubeClient.CoreV1().Services(before.Namespace).Get(
				fixture.ctx, nodeLoadBalancerDatapathName(before), metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}

			test.inject(fixture)
			err = fixture.controller.syncPublicNodeLocal(fixture.ctx, fixture.key, before)
			if err == nil || !inspace.IsTransient(err) {
				t.Fatalf("sync error = %v, want a transient error", err)
			}

			after := fixture.current(t)
			if !reflect.DeepEqual(after.Status, before.Status) || !reflect.DeepEqual(after.Annotations, before.Annotations) {
				t.Fatalf("parent changed on a transient error: status=%#v annotations=%#v", after.Status, after.Annotations)
			}
			datapath, err := fixture.provider.kubeClient.CoreV1().Services(before.Namespace).Get(
				fixture.ctx, nodeLoadBalancerDatapathName(before), metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(datapath.Status, datapathBefore.Status) {
				t.Fatalf("datapath status changed on a transient error: %#v", datapath.Status)
			}
			if len(fixture.api.unassignedFirewalls) != unassignedBefore {
				t.Fatalf("firewall detached on a transient error: %v", fixture.api.unassignedFirewalls)
			}
		})
	}
}

// A definite publication-gate failure must withdraw the published address. The
// gates return no Service on failure, so the withdrawal has to use the Service
// read before the gate rather than the nil result. Drift the private datapath
// on each of its reads in turn: whichever read trips a definite failure, the
// public address must be gone afterwards.
func TestPublicNodeLocalDefiniteDatapathDriftWithdraws(t *testing.T) {
	probe := newPublishedPublicNodeLocalFixture(t)
	probeKube := probe.provider.kubeClient.(*kubefake.Clientset)
	datapathName := nodeLoadBalancerDatapathName(probe.service)
	var reads int
	probeKube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.GetAction).GetName() == datapathName {
			reads++
		}
		return false, nil, nil
	})
	if err := probe.controller.syncPublicNodeLocal(probe.ctx, probe.key, probe.current(t)); err != nil {
		t.Fatalf("steady-state reconcile: %v", err)
	}
	if reads == 0 {
		t.Fatal("steady-state reconcile never read the datapath Service")
	}

	for drifted := 1; drifted <= reads; drifted++ {
		t.Run(fmt.Sprintf("read %d", drifted), func(t *testing.T) {
			fixture := newPublishedPublicNodeLocalFixture(t)
			kube := fixture.provider.kubeClient.(*kubefake.Clientset)
			seen := 0
			kube.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
				get := action.(k8stesting.GetAction)
				if get.GetName() != datapathName {
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
			unassignedBefore := len(fixture.api.unassignedFirewalls)
			err := fixture.controller.syncPublicNodeLocal(fixture.ctx, fixture.key, fixture.current(t))
			if drifted == 1 {
				// The first read belongs to the datapath ensure step, which
				// repairs the drift in place and republishes on later passes.
				if err != nil {
					t.Fatalf("ensure step failed on repairable drift: %v", err)
				}
				for attempt := 0; attempt < 24 && len(fixture.current(t).Status.LoadBalancer.Ingress) != 1; attempt++ {
					if err := fixture.controller.syncPublicNodeLocal(fixture.ctx, fixture.key, fixture.current(t)); err != nil {
						t.Fatalf("repair reconcile %d: %v", attempt, err)
					}
				}
				if got := fixture.current(t).Status.LoadBalancer.Ingress; len(got) != 1 {
					t.Fatalf("repairable drift never republished: %#v", got)
				}
				return
			}
			if err == nil {
				t.Fatal("datapath drift on this read was not detected")
			}
			if inspace.IsTransient(err) {
				t.Fatalf("definite drift reported as transient: %v", err)
			}
			if got := fixture.current(t).Status.LoadBalancer.Ingress; len(got) != 0 {
				t.Fatalf("definite failure %q left the public address published: %#v", err, got)
			}
			if len(fixture.api.unassignedFirewalls) == unassignedBefore {
				t.Fatalf("definite failure %q did not detach the firewall", err)
			}
		})
	}
}

// A provider answer that never arrived must not tell the node lifecycle
// controller that a VM is gone or stopped, which would delete or taint the Node.
func TestInstancesV2TransientProviderErrorsNeverReportAbsence(t *testing.T) {
	absent := exactVMNotFound(testVMUUID)
	tests := []struct {
		name string
		api  *resolvedVMReadErrorAPI
	}{
		{name: "GetVM url timeout", api: &resolvedVMReadErrorAPI{fakeAPI: &fakeAPI{}, getErr: transientProviderTimeout()}},
		{name: "GetVM wrapped deadline", api: &resolvedVMReadErrorAPI{
			fakeAPI: &fakeAPI{}, getErr: fmt.Errorf("read VM: %w", context.DeadlineExceeded),
		}},
		{name: "GetVM 503", api: &resolvedVMReadErrorAPI{fakeAPI: &fakeAPI{}, getErr: transientProviderError()}},
		{name: "corroborating ListVMs timeout", api: &resolvedVMReadErrorAPI{
			fakeAPI: &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}},
			getErr:  absent, listErr: transientProviderTimeout(), overrideNetwork: true,
		}},
		{name: "corroborating ListVMs 503", api: &resolvedVMReadErrorAPI{
			fakeAPI: &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}},
			getErr:  absent, listErr: transientProviderError(), overrideNetwork: true,
		}},
		{name: "corroborating network timeout", api: &resolvedVMReadErrorAPI{
			fakeAPI: &fakeAPI{networkErr: transientProviderTimeout()},
			getErr:  absent, listResponse: []inspace.VM{}, overrideList: true, overrideNetwork: true,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newTestProvider(t, test.api)
			node := &corev1.Node{Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + testVMUUID}}

			exists, err := provider.InstanceExists(context.Background(), node)
			if err == nil || exists {
				t.Fatalf("InstanceExists() = %t, %v; want false and an error, never (false, nil)", exists, err)
			}
			// An exact 404 stays definite for Shutdown and Metadata, so only the
			// GetVM cases assert them.
			if !strings.HasPrefix(test.name, "GetVM") {
				return
			}
			if shutdown, err := provider.InstanceShutdown(context.Background(), node); err == nil || shutdown {
				t.Fatalf("InstanceShutdown() = %t, %v; want false and an error", shutdown, err)
			}
			if _, err := provider.InstanceMetadata(context.Background(), node); err == nil || errors.Is(err, cloud.InstanceNotFound) {
				t.Fatalf("InstanceMetadata() error = %v; want a non-NotFound error", err)
			}
		})
	}
}

func TestNodeLoadBalancerFailClosedHelpersDeferOnTransientCause(t *testing.T) {
	transient := transientProviderTimeout()
	definite := errors.New("canonical ownership mismatch")
	closers := map[string]func(*aggregateSafetySyncHarness, error) error{
		"aggregate shard": func(h *aggregateSafetySyncHarness, cause error) error {
			return h.controller.failAggregateShardClosed(h.ctx, h.shard, cause)
		},
		"aggregate cluster": func(h *aggregateSafetySyncHarness, cause error) error {
			return h.controller.failAggregateClusterClosed(h.ctx, cause)
		},
		"legacy shard": func(h *aggregateSafetySyncHarness, cause error) error {
			return h.controller.failNodeLoadBalancerShardClosed(h.ctx, h.shard, cause)
		},
		"legacy shards": func(h *aggregateSafetySyncHarness, cause error) error {
			return h.controller.failNodeLoadBalancerShardsClosed(h.ctx, h.service(t), h.shard, cause)
		},
		"legacy cluster": func(h *aggregateSafetySyncHarness, cause error) error {
			return h.controller.failClusterNodeLoadBalancerClosed(h.ctx, cause)
		},
		"shard eligibility": func(h *aggregateSafetySyncHarness, cause error) error {
			h.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: h.api, err: cause}
			return h.controller.reconcileAggregateShardNodeEligibility(h.ctx, h.shard, nil, "", false)
		},
		"shard firewall fence": func(h *aggregateSafetySyncHarness, cause error) error {
			h.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: h.api, err: cause}
			return h.controller.fenceAggregateShardFirewallAssignmentGap(h.ctx, h.shard, h.aggregateFirewall(t))
		},
	}
	index := 0
	for name, closer := range closers {
		for _, cause := range []error{transient, definite} {
			index++
			t.Run(fmt.Sprintf("%s/transient=%t", name, inspace.IsTransient(cause)), func(t *testing.T) {
				harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
					fmt.Sprintf("aggregate-closer-%d", index),
					fmt.Sprintf("5555555%d-5555-4555-8555-555555555555", index%10),
					corev1.ProtocolTCP,
					9300+int32(index),
				))
				defer harness.controller.queue.ShutDown()
				harness.converge(t)
				err := closer(harness, cause)
				node, getErr := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
				if getErr != nil {
					t.Fatal(getErr)
				}
				ready := node.Labels[nodeLoadBalancerReadyLabel] == "true"
				if inspace.IsTransient(cause) {
					if err == nil || !inspace.IsTransient(err) || !ready || len(harness.service(t).Status.LoadBalancer.Ingress) == 0 {
						t.Fatalf("transient cause was not deferred: err=%v ready=%t", err, ready)
					}
					return
				}
				if err == nil || ready {
					t.Fatalf("definite cause did not fail closed: err=%v ready=%t", err, ready)
				}
			})
		}
	}
}
