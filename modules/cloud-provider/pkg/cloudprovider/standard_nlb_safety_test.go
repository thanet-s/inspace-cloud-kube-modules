package cloudprovider

import (
	"context"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// orderedTargetAPI records the NLB target count at the moment of each target
// mutation, so tests can prove a removal never ran while it would leave the
// load balancer empty.
type orderedTargetAPI struct {
	*fakeAPI
	events []string
	// targetsBeforeRemove holds len(lb.Targets) seen just before each removal.
	targetsBeforeRemove []int
}

func (a *orderedTargetAPI) AddLoadBalancerTarget(ctx context.Context, location, lb, uuid string) (*inspace.LoadBalancerTarget, error) {
	a.events = append(a.events, "add:"+uuid)
	return a.fakeAPI.AddLoadBalancerTarget(ctx, location, lb, uuid)
}

func (a *orderedTargetAPI) RemoveLoadBalancerTarget(ctx context.Context, location, lb, uuid string) error {
	a.events = append(a.events, "remove:"+uuid)
	for i := range a.fakeAPI.lbs {
		if a.fakeAPI.lbs[i].UUID == lb {
			a.targetsBeforeRemove = append(a.targetsBeforeRemove, len(a.fakeAPI.lbs[i].Targets))
		}
	}
	return a.fakeAPI.RemoveLoadBalancerTarget(ctx, location, lb, uuid)
}

func TestReconcileLoadBalancerAddsNewTargetsBeforeRemovingOld(t *testing.T) {
	const stale = "99999999-1111-4222-8333-444444444444"
	service := testService()
	base := &fakeAPI{}
	api := &orderedTargetAPI{fakeAPI: base}
	provider := newTestProvider(t, api)
	setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
	setOwnedLoadBalancer(base, provider, service, []string{stale})

	requireStandardNLBConvergence(t, func() error {
		current, err := provider.findOwnedLoadBalancer(context.Background(), service)
		if err != nil {
			return err
		}
		return provider.reconcileLoadBalancer(context.Background(), service, current, []string{testVMUUID}, serviceRules(service))
	})

	want := []string{"add:" + testVMUUID, "remove:" + stale}
	if len(api.events) != len(want) || api.events[0] != want[0] || api.events[1] != want[1] {
		t.Fatalf("target mutation order = %v, want %v", api.events, want)
	}
	if len(api.targetsBeforeRemove) != 1 || api.targetsBeforeRemove[0] < 2 {
		t.Fatalf("targets before removal = %v, want at least 2 (new target already present)", api.targetsBeforeRemove)
	}
}

func TestReconcileLoadBalancerKeepsLastTargetsWhenDesiredSetIsEmpty(t *testing.T) {
	service := testService()
	for name, current := range map[string][]string{
		"one target":  {testVMUUID},
		"two targets": {testVMUUID, testVMUUIDB},
	} {
		t.Run(name, func(t *testing.T) {
			base := &fakeAPI{}
			provider := newTestProvider(t, base)
			setOwnedLoadBalancer(base, provider, service, current)
			// A stale rule proves the rest of the reconcile still runs.
			base.lbs[0].ForwardingRules = []inspace.LoadBalancerRule{
				{UUID: "77777777-1111-4222-8333-444444444444", Protocol: "TCP", SourcePort: 443, TargetPort: 30001},
			}

			requireStandardNLBConvergence(t, func() error {
				lb, err := provider.findOwnedLoadBalancer(context.Background(), service)
				if err != nil {
					return err
				}
				return provider.reconcileLoadBalancer(context.Background(), service, lb, nil, serviceRules(service))
			})

			if len(base.removedTargets) != 0 {
				t.Fatalf("removed targets %v although the desired set was empty", base.removedTargets)
			}
			if len(base.lbs[0].Targets) != len(current) {
				t.Fatalf("NLB targets = %v, want the last known good %v", base.lbs[0].Targets, current)
			}
			if len(base.addedRules) != 1 || len(base.removedRules) != 1 {
				t.Fatalf("rule reconcile did not run: add=%v remove=%v", base.addedRules, base.removedRules)
			}
		})
	}
}

func TestReconcileLoadBalancerStillRemovesStaleTargetsWhenOthersRemain(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	provider := newTestProvider(t, base)
	setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
	setOwnedLoadBalancer(base, provider, service, []string{testVMUUID, testVMUUIDB})

	requireStandardNLBConvergence(t, func() error {
		lb, err := provider.findOwnedLoadBalancer(context.Background(), service)
		if err != nil {
			return err
		}
		return provider.reconcileLoadBalancer(context.Background(), service, lb, []string{testVMUUID}, serviceRules(service))
	})
	if !reflectStrings(base.removedTargets, []string{testVMUUIDB}) {
		t.Fatalf("removed targets = %v, want only the stale one", base.removedTargets)
	}
}
