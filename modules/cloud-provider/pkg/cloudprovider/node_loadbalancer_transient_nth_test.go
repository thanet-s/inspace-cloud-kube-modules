package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// nthGetVMErrorAPI fails only the Nth GetVM call.
type nthGetVMErrorAPI struct {
	*fakeAPI
	failOn int
	calls  int
	err    error
}

func (a *nthGetVMErrorAPI) GetVM(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	a.calls++
	if a.calls == a.failOn {
		return nil, a.err
	}
	return a.fakeAPI.GetVM(ctx, location, uuid)
}

// nthListFirewallsErrorAPI fails only the Nth ListFirewalls call.
type nthListFirewallsErrorAPI struct {
	*fakeAPI
	failOn int
	calls  int
	err    error
}

func (a *nthListFirewallsErrorAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.calls++
	if a.calls == a.failOn {
		return nil, a.err
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

// installNthFailure wraps the provider API so the Nth call of kind fails with
// a transient error, and returns the call counter.
func installNthFailure(provider *Provider, api *fakeAPI, kind string, n int) *int {
	if kind == "GetVM" {
		return installNthFailureWith(provider, api, kind, n, transientProviderTimeout())
	}
	return installNthFailureWith(provider, api, kind, n, transientProviderError())
}

// installNthFailureWith fails the Nth call of kind with the given error.
func installNthFailureWith(provider *Provider, api *fakeAPI, kind string, n int, err error) *int {
	if kind == "GetVM" {
		wrapped := &nthGetVMErrorAPI{fakeAPI: api, failOn: n, err: err}
		provider.api = wrapped
		return &wrapped.calls
	}
	wrapped := &nthListFirewallsErrorAPI{fakeAPI: api, failOn: n, err: err}
	provider.api = wrapped
	return &wrapped.calls
}

// A definite failure on any single provider call must also leave a published
// public-node-local Service alone: it is held, never withdrawn.
func TestPublicNodeLocalKeepsStateOnNthDefiniteProviderCall(t *testing.T) {
	for _, kind := range []string{"GetVM", "ListFirewalls"} {
		for n := 1; n <= 24; n++ {
			t.Run(fmt.Sprintf("%s call %d", kind, n), func(t *testing.T) {
				f := newPublishedPublicNodeLocalFixture(t)
				before := f.current(t)
				datapathBefore := trackedPublicNodeLocalDatapath(t, f)
				mutations := managedNodeLoadBalancerMutationSnapshot(f.api)
				calls := installNthFailureWith(f.provider, f.api, kind, n, errors.New("canonical ownership mismatch"))

				syncErr := f.controller.syncPublicNodeLocal(f.ctx, f.key, before)
				if *calls < n {
					t.Skipf("sync made only %d %s calls", *calls, kind)
				}
				var holding *errPublicNodeLocalHolding
				if syncErr != nil && !errors.As(syncErr, &holding) {
					t.Fatalf("definite failure was not held: %v", syncErr)
				}
				after := f.current(t)
				if !reflect.DeepEqual(after.Status, before.Status) || !reflect.DeepEqual(after.Annotations, before.Annotations) {
					t.Fatalf("parent changed: status=%#v annotations=%#v err=%v", after.Status, after.Annotations, syncErr)
				}
				if datapath := trackedPublicNodeLocalDatapath(t, f); !reflect.DeepEqual(datapath.Status, datapathBefore.Status) {
					t.Fatalf("datapath status changed: %#v err=%v", datapath.Status, syncErr)
				}
				if got := managedNodeLoadBalancerMutationSnapshot(f.api); got != mutations {
					t.Fatalf("firewall mutated: before=%#v after=%#v err=%v", mutations, got, syncErr)
				}
			})
		}
	}
}

// A transient failure on any single provider call, including calls inside the
// publication gates, must leave a published public-node-local Service alone.
func TestPublicNodeLocalKeepsStateOnNthTransientProviderCall(t *testing.T) {
	for _, kind := range []string{"GetVM", "ListFirewalls"} {
		for n := 1; n <= 24; n++ {
			t.Run(fmt.Sprintf("%s call %d", kind, n), func(t *testing.T) {
				f := newPublishedPublicNodeLocalFixture(t)
				before := f.current(t)
				datapathBefore, err := f.provider.kubeClient.CoreV1().Services(before.Namespace).Get(f.ctx, nodeLoadBalancerDatapathName(before), metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				mutations := managedNodeLoadBalancerMutationSnapshot(f.api)
				calls := installNthFailure(f.provider, f.api, kind, n)

				syncErr := f.controller.syncPublicNodeLocal(f.ctx, f.key, before)
				if *calls < n {
					t.Skipf("sync made only %d %s calls", *calls, kind)
				}
				if syncErr != nil && !inspace.IsTransient(syncErr) {
					t.Fatalf("transient failure became definite: %v", syncErr)
				}
				after := f.current(t)
				if !reflect.DeepEqual(after.Status, before.Status) || !reflect.DeepEqual(after.Annotations, before.Annotations) {
					t.Fatalf("parent changed: status=%#v err=%v", after.Status, syncErr)
				}
				datapath, err := f.provider.kubeClient.CoreV1().Services(before.Namespace).Get(f.ctx, nodeLoadBalancerDatapathName(before), metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(datapath.Status, datapathBefore.Status) {
					t.Fatalf("datapath status changed: %#v err=%v", datapath.Status, syncErr)
				}
				if got := managedNodeLoadBalancerMutationSnapshot(f.api); got != mutations {
					t.Fatalf("firewall mutated: before=%#v after=%#v err=%v", mutations, got, syncErr)
				}
			})
		}
	}
}

// Same rule for the aggregate path: ready labels, parent and child statuses
// and firewall assignments stay put whichever single call fails.
func TestAggregateKeepsStateOnNthTransientProviderCall(t *testing.T) {
	for _, kind := range []string{"GetVM", "ListFirewalls"} {
		for n := 1; n <= 40; n++ {
			t.Run(fmt.Sprintf("%s call %d", kind, n), func(t *testing.T) {
				h := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService("agg-nth", "77777779-7777-4777-8777-777777777777", corev1.ProtocolTCP, 9200))
				defer h.controller.queue.ShutDown()
				h.converge(t)
				parentBefore := h.service(t)
				childBefore, err := h.provider.kubeClient.CoreV1().Services(parentBefore.Namespace).Get(h.ctx, nodeLoadBalancerDatapathName(parentBefore), metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				mutations := managedNodeLoadBalancerMutationSnapshot(h.api)
				calls := installNthFailure(h.provider, h.api, kind, n)

				syncErr := h.controller.sync(h.ctx, h.key)
				if *calls < n {
					t.Skipf("sync made only %d %s calls", *calls, kind)
				}
				if syncErr != nil && !inspace.IsTransient(syncErr) {
					t.Fatalf("transient failure became definite: %v", syncErr)
				}
				parent := h.service(t)
				child, err := h.provider.kubeClient.CoreV1().Services(parent.Namespace).Get(h.ctx, nodeLoadBalancerDatapathName(parent), metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				node, err := h.provider.kubeClient.CoreV1().Nodes().Get(h.ctx, h.nodeName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(parent.Status, parentBefore.Status) || !reflect.DeepEqual(child.Status, childBefore.Status) {
					t.Fatalf("status changed: err=%v", syncErr)
				}
				if node.Labels[nodeLoadBalancerReadyLabel] != "true" {
					t.Fatalf("ready label dropped: err=%v", syncErr)
				}
				if got := managedNodeLoadBalancerMutationSnapshot(h.api); got != mutations {
					t.Fatalf("firewall mutated: before=%#v after=%#v err=%v", mutations, got, syncErr)
				}
			})
		}
	}
}
