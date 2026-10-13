package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

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
