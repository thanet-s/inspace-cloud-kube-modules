package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func publishedStandardNLB(t *testing.T) (*fakeAPI, *Provider, *corev1.Service, []*corev1.Node) {
	t.Helper()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	if len(api.lbs) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("setup: LBs=%d FIPs=%d", len(api.lbs), len(api.floatingIPs))
	}
	return api, provider, service, nodes
}

func TestDroppingPublicMarkerHoldsFloatingIPUntilExplicitRelease(t *testing.T) {
	for name, unpublish := range map[string]func(*corev1.Service){
		"label removed":        func(s *corev1.Service) { delete(s.Labels, LabelLoadBalancerScope) },
		"annotation removed":   func(s *corev1.Service) { delete(s.Annotations, AnnotationPublicLoadBalancer) },
		"annotation set false": func(s *corev1.Service) { s.Annotations[AnnotationPublicLoadBalancer] = "false" },
	} {
		t.Run(name, func(t *testing.T) {
			api, provider, service, nodes := publishedStandardNLB(t)
			unpublish(service)
			syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil ||
				!strings.Contains(err.Error(), AnnotationReleasePublicLoadBalancer) {
				t.Fatalf("EnsureLoadBalancer() error = %v, want a hold that names %s", err, AnnotationReleasePublicLoadBalancer)
			}
			if err := provider.UpdateLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
				t.Fatalf("UpdateLoadBalancer() error = %v, want a quiet hold", err)
			}
			if len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 || len(api.deletedLBs) != 0 ||
				len(api.lbs) != 1 || len(api.floatingIPs) != 1 {
				t.Fatalf("hold still mutated: unassign=%v deleteIP=%v deleteLB=%v LBs=%d FIPs=%d",
					api.unassignedIPs, api.deletedIPs, api.deletedLBs, len(api.lbs), len(api.floatingIPs))
			}

			service.Annotations[AnnotationReleasePublicLoadBalancer] = "true"
			syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
			requireStandardNLBConvergence(t, func() error {
				_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
				return err
			})
			if len(api.deletedIPs) != 1 || len(api.floatingIPs) != 0 || len(api.lbs) != 0 {
				t.Fatalf("explicit release did not clean up: deleteIP=%v LBs=%d FIPs=%d", api.deletedIPs, len(api.lbs), len(api.floatingIPs))
			}
		})
	}
}

func TestServiceDeletionStillReleasesFloatingIPWithoutOptIn(t *testing.T) {
	api, provider, service, _ := publishedStandardNLB(t)
	now := metav1.Now()
	service.DeletionTimestamp = &now
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
	requireStandardNLBConvergence(t, func() error {
		return provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service)
	})
	if len(api.floatingIPs) != 0 || len(api.lbs) != 0 {
		t.Fatalf("deletion left resources: LBs=%d FIPs=%d", len(api.lbs), len(api.floatingIPs))
	}
}

// hangingAddTargetAPI blocks AddLoadBalancerTarget until its context ends, like
// a brownout where POSTs hang instead of failing.
type hangingAddTargetAPI struct {
	*fakeAPI
	sawDeadline bool
}

func (a *hangingAddTargetAPI) AddLoadBalancerTarget(ctx context.Context, _, _, _ string) (*inspace.LoadBalancerTarget, error) {
	_, a.sawDeadline = ctx.Deadline()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, errors.New("test: mutation was never cancelled")
	}
}

func TestStandardNLBMutationIsBoundedByItsOwnDeadline(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	api := &hangingAddTargetAPI{fakeAPI: base}
	provider := newTestProvider(t, api)
	provider.standardNLBMutationTimeout = 50 * time.Millisecond
	setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
	setOwnedLoadBalancer(base, provider, service, nil)

	started := time.Now()
	err := provider.reconcileLoadBalancer(context.Background(), service, &base.lbs[0], []string{testVMUUID}, serviceRules(service))
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reconcileLoadBalancer() error = %v, want the mutation deadline", err)
	}
	if !api.sawDeadline || time.Since(started) > 5*time.Second {
		t.Fatalf("mutation was not bounded: deadline set=%t, took %s", api.sawDeadline, time.Since(started))
	}
}
