package cloudprovider

import (
	"context"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	corev1 "k8s.io/api/core/v1"
)

// deadlineRecordingAPI notes the time left on the context of every NLB and
// floating-IP mutation, keyed by method name.
type deadlineRecordingAPI struct {
	*fakeAPI
	budget map[string]time.Duration
}

func (a *deadlineRecordingAPI) note(name string, ctx context.Context) {
	if deadline, ok := ctx.Deadline(); ok {
		if _, seen := a.budget[name]; !seen {
			a.budget[name] = time.Until(deadline)
		}
	}
}

func (a *deadlineRecordingAPI) CreateLoadBalancer(ctx context.Context, l string, r inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error) {
	a.note("CreateLoadBalancer", ctx)
	return a.fakeAPI.CreateLoadBalancer(ctx, l, r)
}

func (a *deadlineRecordingAPI) CreateFloatingIP(ctx context.Context, l string, r inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error) {
	a.note("CreateFloatingIP", ctx)
	return a.fakeAPI.CreateFloatingIP(ctx, l, r)
}

func (a *deadlineRecordingAPI) AssignFloatingIP(ctx context.Context, l, address, uuid, kind string) (*inspace.FloatingIP, error) {
	a.note("AssignFloatingIP", ctx)
	return a.fakeAPI.AssignFloatingIP(ctx, l, address, uuid, kind)
}

func (a *deadlineRecordingAPI) UnassignFloatingIP(ctx context.Context, l, address string) (*inspace.FloatingIP, error) {
	a.note("UnassignFloatingIP", ctx)
	return a.fakeAPI.UnassignFloatingIP(ctx, l, address)
}

func (a *deadlineRecordingAPI) DeleteFloatingIP(ctx context.Context, l, address string) error {
	a.note("DeleteFloatingIP", ctx)
	return a.fakeAPI.DeleteFloatingIP(ctx, l, address)
}

func (a *deadlineRecordingAPI) DeleteLoadBalancer(ctx context.Context, l, uuid string) error {
	a.note("DeleteLoadBalancer", ctx)
	return a.fakeAPI.DeleteLoadBalancer(ctx, l, uuid)
}

func (a *deadlineRecordingAPI) AddLoadBalancerTarget(ctx context.Context, l, lb, uuid string) (*inspace.LoadBalancerTarget, error) {
	a.note("AddLoadBalancerTarget", ctx)
	return a.fakeAPI.AddLoadBalancerTarget(ctx, l, lb, uuid)
}

func (a *deadlineRecordingAPI) RemoveLoadBalancerTarget(ctx context.Context, l, lb, uuid string) error {
	a.note("RemoveLoadBalancerTarget", ctx)
	return a.fakeAPI.RemoveLoadBalancerTarget(ctx, l, lb, uuid)
}

func (a *deadlineRecordingAPI) AddLoadBalancerRule(ctx context.Context, l, lb string, r inspace.LoadBalancerRule) (*inspace.LoadBalancerRule, error) {
	a.note("AddLoadBalancerRule", ctx)
	return a.fakeAPI.AddLoadBalancerRule(ctx, l, lb, r)
}

func (a *deadlineRecordingAPI) RemoveLoadBalancerRule(ctx context.Context, l, lb, uuid string) error {
	a.note("RemoveLoadBalancerRule", ctx)
	return a.fakeAPI.RemoveLoadBalancerRule(ctx, l, lb, uuid)
}

func TestStandardNLBMutationsUsePerOperationDeadlines(t *testing.T) {
	api := &deadlineRecordingAPI{fakeAPI: &fakeAPI{}, budget: map[string]time.Duration{}}
	provider := newTestProvider(t, api)
	service := testService()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}

	// Different target and rule: add + remove of each.
	const stale = "99999999-1111-4222-8333-444444444444"
	api.fakeAPI.lbs[0].Targets = []inspace.LoadBalancerTarget{{TargetUUID: stale, TargetType: "vm"}}
	api.fakeAPI.lbs[0].ForwardingRules = []inspace.LoadBalancerRule{
		{UUID: "77777777-1111-4222-8333-444444444444", Protocol: "TCP", SourcePort: 8443, TargetPort: 30001},
	}
	requireStandardNLBConvergence(t, func() error {
		lb, err := provider.findOwnedLoadBalancer(context.Background(), service)
		if err != nil {
			return err
		}
		return provider.reconcileLoadBalancer(context.Background(), service, lb, []string{testVMUUID}, serviceRules(service))
	})

	// Unassigned FIP so the assignment is issued again after the NLB exists.
	api.fakeAPI.floatingIPs[0].AssignedTo = ""
	api.fakeAPI.floatingIPs[0].AssignedToResourceType = ""
	api.fakeAPI.floatingIPs[0].AssignedToPrivateIP = ""
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}

	delete(service.Labels, LabelLoadBalancerScope)
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
	releaseHeldStandardNLB(t, provider, service, nodes)
	requireStandardNLBConvergence(t, func() error {
		_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
		return err
	})

	want := map[string]time.Duration{
		"CreateLoadBalancer":       5 * time.Minute,
		"CreateFloatingIP":         90 * time.Second,
		"AssignFloatingIP":         3 * time.Minute,
		"AddLoadBalancerTarget":    2 * time.Minute,
		"RemoveLoadBalancerTarget": 2 * time.Minute,
		"AddLoadBalancerRule":      2 * time.Minute,
		"RemoveLoadBalancerRule":   2 * time.Minute,
		"UnassignFloatingIP":       3 * time.Minute,
		"DeleteFloatingIP":         3 * time.Minute,
		"DeleteLoadBalancer":       3 * time.Minute,
	}
	for name, limit := range want {
		got, seen := api.budget[name]
		if !seen {
			t.Errorf("%s was never called with a deadline", name)
			continue
		}
		if got > limit || got < limit-30*time.Second {
			t.Errorf("%s deadline = %s, want about %s", name, got, limit)
		}
	}
}
