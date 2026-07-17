package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// softDeleteStandardNLBAPI models the two InSpace delete readback shapes that
// matter to the controller: floating IP tombstones remain in the list, while
// an exact load-balancer GET may keep returning the deleted object with
// is_deleted=true instead of returning 404.
type softDeleteStandardNLBAPI struct {
	*fakeAPI
}

type rejectStandardNLBFenceClearStore struct {
	standardNLBServiceStore
	err error
}

type deadlineCheckingStandardNLBStore struct {
	standardNLBServiceStore
	sawDeadline bool
}

func (s *deadlineCheckingStandardNLBStore) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > durableReceiptWriteTimeout {
		return errors.New("public NLB receipt cleanup lacks a live bounded context")
	}
	s.sawDeadline = true
	return nil
}

func (s *deadlineCheckingStandardNLBStore) GetExact(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return s.standardNLBServiceStore.GetExact(ctx, service)
}

func (s *deadlineCheckingStandardNLBStore) UpdateExact(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return s.standardNLBServiceStore.UpdateExact(ctx, service)
}

func (s *rejectStandardNLBFenceClearStore) UpdateExact(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, error) {
	if service.Annotations[annotationStandardNLBMutation] == "" {
		return nil, s.err
	}
	return s.standardNLBServiceStore.UpdateExact(ctx, service)
}

func (a *softDeleteStandardNLBAPI) DeleteFloatingIP(_ context.Context, _, address string) error {
	a.deletedIPs = append(a.deletedIPs, address)
	for index := range a.floatingIPs {
		if a.floatingIPs[index].Address == address {
			a.floatingIPs[index].IsDeleted = true
			break
		}
	}
	return nil
}

func (a *softDeleteStandardNLBAPI) DeleteLoadBalancer(_ context.Context, _ string, uuid string) error {
	a.deletedLBs = append(a.deletedLBs, uuid)
	for index := range a.lbs {
		if a.lbs[index].UUID == uuid {
			a.lbs[index].IsDeleted = true
			break
		}
	}
	return nil
}

func (a *softDeleteStandardNLBAPI) GetLoadBalancer(_ context.Context, _ string, uuid string) (*inspace.LoadBalancer, error) {
	for index := range a.lbs {
		if a.lbs[index].UUID != uuid {
			continue
		}
		copy := a.lbs[index]
		copy.ForwardingRules = append([]inspace.LoadBalancerRule{}, a.lbs[index].ForwardingRules...)
		copy.Targets = append([]inspace.LoadBalancerTarget{}, a.lbs[index].Targets...)
		return &copy, nil
	}
	return nil, exactLoadBalancerNotFound(uuid)
}

func TestGetLoadBalancerAcceptsOnlyCleanUnassignmentDuringServiceDeletion(t *testing.T) {
	newFixture := func(t *testing.T) (*Provider, *fakeAPI, *corev1.Service) {
		t.Helper()
		api := &fakeAPI{}
		provider := newTestProvider(t, api)
		service := testService()
		api.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
			BillingAccountID: 42, PrivateAddress: "10.0.0.50",
		}}
		api.floatingIPs = []inspace.FloatingIP{{
			Name: provider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
			Type: "public", Enabled: true, UnassignedAt: "2026-07-17T01:02:03Z",
		}}
		return provider, api, service
	}

	t.Run("live Service remains fail closed", func(t *testing.T) {
		provider, _, service := newFixture(t)
		status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
		if err == nil || !exists || status != nil || !strings.Contains(err.Error(), "unexpected assignment") {
			t.Fatalf("live unassigned GetLoadBalancer() = %#v, %t, %v", status, exists, err)
		}
	})

	t.Run("deleting Service continues into cleanup", func(t *testing.T) {
		provider, _, service := newFixture(t)
		now := metav1.Now()
		service.DeletionTimestamp = &now
		status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
		if err != nil || !exists || status == nil || len(status.Ingress) != 1 || status.Ingress[0].IP != "10.0.0.50" {
			t.Fatalf("deleting unassigned GetLoadBalancer() = %#v, %t, %v", status, exists, err)
		}
	})

	t.Run("deleting Service with only floating IP continues into cleanup", func(t *testing.T) {
		provider, api, service := newFixture(t)
		api.lbs = nil
		now := metav1.Now()
		service.DeletionTimestamp = &now
		status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
		if err != nil || !exists || status != nil {
			t.Fatalf("orphaned clean FIP GetLoadBalancer() = %#v, %t, %v", status, exists, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*inspace.FloatingIP)
	}{
		{
			name: "wrong owner",
			mutate: func(item *inspace.FloatingIP) {
				item.AssignedTo = testVMUUID
				item.AssignedToResourceType = "virtual_machine"
			},
		},
		{
			name: "residual resource type",
			mutate: func(item *inspace.FloatingIP) {
				item.AssignedToResourceType = "load_balancer"
			},
		},
		{
			name: "residual private address",
			mutate: func(item *inspace.FloatingIP) {
				item.AssignedToPrivateIP = "10.0.0.50"
			},
		},
	} {
		t.Run(test.name+" remains fail closed", func(t *testing.T) {
			provider, api, service := newFixture(t)
			test.mutate(&api.floatingIPs[0])
			now := metav1.Now()
			service.DeletionTimestamp = &now
			status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service)
			if err == nil || !exists || status != nil || !strings.Contains(err.Error(), "unexpected assignment") {
				t.Fatalf("drifted deleting GetLoadBalancer() = %#v, %t, %v", status, exists, err)
			}
		})
	}
}

// runStockServiceControllerDeleteStep mirrors the safety-relevant ordering in
// k8s.io/cloud-provider/controllers/service: GetLoadBalancer gates the call to
// EnsureLoadBalancerDeleted, and exists=false permits finalizer removal.
func runStockServiceControllerDeleteStep(
	ctx context.Context,
	provider *Provider,
	service *corev1.Service,
) (finished bool, err error) {
	_, exists, err := provider.GetLoadBalancer(ctx, "ignored", service)
	if err != nil {
		return false, err
	}
	if !exists {
		return true, nil
	}
	return false, provider.EnsureLoadBalancerDeleted(ctx, "ignored", service)
}

func requireStockServiceControllerDeletionConvergence(
	t *testing.T,
	provider *Provider,
	service *corev1.Service,
) {
	t.Helper()
	for range 32 {
		finished, err := runStockServiceControllerDeleteStep(context.Background(), provider, service)
		if err != nil && !errors.Is(err, errStandardNLBRemovalPending) {
			t.Fatal(err)
		}
		if finished {
			return
		}
	}
	t.Fatal("stock Service-controller deletion sequence did not converge within 32 reconciliations")
}

func TestStockServiceControllerSequenceConvergesAfterFloatingIPUnassignment(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(*fakeAPI) API
	}{
		{name: "hard delete", wrap: func(api *fakeAPI) API { return api }},
		{name: "InSpace soft-delete readback", wrap: func(api *fakeAPI) API {
			return &softDeleteStandardNLBAPI{fakeAPI: api}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			now := metav1.Now()
			service.DeletionTimestamp = &now
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
				BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}}
			base.floatingIPs = []inspace.FloatingIP{{
				Name: nameProvider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
				Type: "public", Enabled: true, AssignedTo: testLBUUID,
				AssignedToResourceType: "load_balancer", AssignedToPrivateIP: "10.0.0.50",
			}}

			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, test.wrap(base), store)
			provider.standardNLBAbsentDelay = 0
			requireStockServiceControllerDeletionConvergence(t, provider, service)

			if len(base.unassignedIPs) != 1 || len(base.deletedIPs) != 1 || len(base.deletedLBs) != 1 {
				t.Fatalf(
					"cleanup calls: unassign=%v deleteIP=%v deleteLB=%v",
					base.unassignedIPs, base.deletedIPs, base.deletedLBs,
				)
			}
			assertNoStandardNLBFence(t, store, service)
			if status, exists, err := provider.GetLoadBalancer(context.Background(), "ignored", service); err != nil || exists || status != nil {
				t.Fatalf("terminal GetLoadBalancer() = %#v, %t, %v", status, exists, err)
			}
		})
	}
}

func TestSoftDeletedExactNLBStillRejectsActiveListConflict(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{
		{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
			BillingAccountID: 42, PrivateAddress: "10.0.0.50", IsDeleted: true,
		},
		{
			UUID: "99999999-1111-4222-8333-444444444444", DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.51",
		},
	}
	provider := newStandardNLBProviderWithStore(t, &softDeleteStandardNLBAPI{fakeAPI: base}, newMemoryStandardNLBServiceStore())
	item, absent, err := provider.readExactOwnedStandardNLB(context.Background(), service, testLBUUID)
	if err == nil || absent || item != nil || !strings.Contains(err.Error(), "ownership name") {
		t.Fatalf("soft-delete/name-reuse readback = %#v, absent=%t, err=%v", item, absent, err)
	}
}

func TestSoftDeletedExactNLBRequiresCanonicalOwnedIdentity(t *testing.T) {
	service := testService()
	nameProvider := newTestProvider(t, &fakeAPI{})
	canonical := inspace.LoadBalancer{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		BillingAccountID: 42, PrivateAddress: "10.0.0.50", IsDeleted: true,
	}
	for _, test := range []struct {
		name   string
		mutate func(*inspace.LoadBalancer)
	}{
		{
			name: "ownership name drift",
			mutate: func(item *inspace.LoadBalancer) {
				item.DisplayName = "foreign"
			},
		},
		{
			name: "omitted network",
			mutate: func(item *inspace.LoadBalancer) {
				item.NetworkUUID = ""
			},
		},
		{
			name: "network drift",
			mutate: func(item *inspace.LoadBalancer) {
				item.NetworkUUID = "99999999-1111-4222-8333-444444444444"
			},
		},
		{
			name: "omitted billing",
			mutate: func(item *inspace.LoadBalancer) {
				item.BillingAccountID = 0
			},
		},
		{
			name: "billing drift",
			mutate: func(item *inspace.LoadBalancer) {
				item.BillingAccountID = 43
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tombstone := canonical
			test.mutate(&tombstone)
			base := &fakeAPI{lbs: []inspace.LoadBalancer{tombstone}}
			provider := newStandardNLBProviderWithStore(
				t,
				&softDeleteStandardNLBAPI{fakeAPI: base},
				newMemoryStandardNLBServiceStore(),
			)
			item, absent, err := provider.readExactOwnedStandardNLB(context.Background(), service, testLBUUID)
			if err == nil || absent || item != nil {
				t.Fatalf("drifted soft-delete readback = %#v, absent=%t, err=%v", item, absent, err)
			}
		})
	}
}

func TestTargetControllerSkipsDeletingServiceBeforeStagingAdditiveMutation(t *testing.T) {
	service := testService()
	markPublicIntentMirrored(service)
	now := metav1.Now()
	service.DeletionTimestamp = &now

	base := &fakeAPI{}
	api := &lateStandardNLBAPI{fakeAPI: base}
	inner := newMemoryStandardNLBServiceStore()
	store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
	provider := newStandardNLBProviderWithStore(t, api, store)
	setOwnedLoadBalancer(base, provider, service, nil)
	base.floatingIPs[0].AssignedTo = ""
	base.floatingIPs[0].AssignedToResourceType = ""
	base.floatingIPs[0].AssignedToPrivateIP = ""

	fixture := newTargetControllerFixture(t, provider)
	fixture.addService(t, service)
	if err := fixture.controller.sync(context.Background(), service.Namespace+"/"+service.Name); err != nil {
		t.Fatal(err)
	}
	if store.fired {
		t.Fatal("target reconciler staged an additive public NLB receipt for a deleting Service")
	}
	if api.assignFloatingIPCalls != 0 || len(base.addedTargets) != 0 || len(base.addedRules) != 0 {
		t.Fatalf(
			"deleting Service crossed target-controller cloud boundary: assign=%d targets=%v rules=%v",
			api.assignFloatingIPCalls, base.addedTargets, base.addedRules,
		)
	}
	assertNoStandardNLBFence(t, inner, service)
}

func TestProvenNonDispatchJoinsCASClearFailureAndRetainsReceipt(t *testing.T) {
	service := testService()
	inner := newMemoryStandardNLBServiceStore()
	clearErr := errors.New("synthetic Service CAS clear failure")
	store := &rejectStandardNLBFenceClearStore{standardNLBServiceStore: inner, err: clearErr}
	provider := newStandardNLBProviderWithStore(t, &fakeAPI{}, store)
	desired := validStandardNLBRemovalFenceForTest(t, standardNLBDeleteLoadBalancer)
	fence, raw, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired)
	if err != nil || !issue || fence.Phase != standardNLBPhaseIssued {
		t.Fatalf("issue receipt: fence=%#v raw=%q issue=%t err=%v", fence, raw, issue, err)
	}

	rejection := errors.New("synthetic final authority rejection")
	err = provider.clearStandardNLBFenceAfterProvenNonDispatch(context.Background(), service, raw, rejection)
	if !errors.Is(err, rejection) || !errors.Is(err, clearErr) {
		t.Fatalf("joined pre-dispatch clear error = %v", err)
	}
	assertIssuedStandardNLBFence(t, inner, service, standardNLBDeleteLoadBalancer)
}

func TestProvenNonDispatchClearsReceiptWithBoundedDetachedContext(t *testing.T) {
	service := testService()
	inner := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, &fakeAPI{}, inner)
	desired := validStandardNLBRemovalFenceForTest(t, standardNLBDeleteLoadBalancer)
	_, raw, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired)
	if err != nil || !issue {
		t.Fatalf("issue receipt: issue=%t err=%v", issue, err)
	}
	checking := &deadlineCheckingStandardNLBStore{standardNLBServiceStore: inner}
	provider.standardNLBServiceStore = checking
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	rejection := errors.New("synthetic proven pre-dispatch rejection")
	err = provider.clearStandardNLBFenceAfterProvenNonDispatch(canceled, service, raw, rejection)
	if !errors.Is(err, rejection) || errors.Is(err, context.Canceled) {
		t.Fatalf("detached receipt cleanup error = %v", err)
	}
	if !checking.sawDeadline {
		t.Fatal("detached receipt cleanup did not expose a finite deadline")
	}
	assertNoStandardNLBFence(t, inner, service)
}

var _ API = (*softDeleteStandardNLBAPI)(nil)
