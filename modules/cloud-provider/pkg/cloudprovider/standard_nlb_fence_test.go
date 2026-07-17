package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type standardNLBPostIssueHookStore struct {
	standardNLBServiceStore
	hook  func()
	fired bool
}

func (s *standardNLBPostIssueHookStore) UpdateExact(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, error) {
	updated, err := s.standardNLBServiceStore.UpdateExact(ctx, service)
	if err != nil || s.fired {
		return updated, err
	}
	fence, parseErr := parseStandardNLBFence(updated.Annotations[annotationStandardNLBMutation])
	if parseErr != nil {
		return nil, parseErr
	}
	if fence != nil && fence.Phase == standardNLBPhaseIssued {
		s.fired = true
		if s.hook != nil {
			s.hook()
		}
	}
	return updated, nil
}

type lateStandardNLBAPI struct {
	*fakeAPI

	loadBalancerListCalls  int
	floatingIPListCalls    int
	failLoadBalancerListOn int
	failFloatingIPListOn   int
	loadBalancerListErr    error
	floatingIPListErr      error
	hideLoadBalancerLists  int
	hideFloatingIPLists    int
	hideAssignmentLists    int
	hideTargetLists        int
	hideRuleLists          int

	loadBalancerCreateErr       error
	loadBalancerRejectErr       error
	floatingIPCreateErr         error
	assignFloatingIPErr         error
	addTargetErr                error
	addRuleErr                  error
	deleteLoadBalancerErr       error
	mutateCommittedLoadBalancer func(*inspace.LoadBalancer)

	floatingIPCreateCalls int
	assignFloatingIPCalls int
	assignmentCommitted   bool
	targetCommitted       string
	ruleCommitted         *inspace.LoadBalancerRule
}

func (a *lateStandardNLBAPI) ListLoadBalancers(ctx context.Context, location string) ([]inspace.LoadBalancer, error) {
	a.loadBalancerListCalls++
	if a.failLoadBalancerListOn == a.loadBalancerListCalls {
		return nil, a.loadBalancerListErr
	}
	items, err := a.fakeAPI.ListLoadBalancers(ctx, location)
	if err != nil {
		return nil, err
	}
	if a.hideLoadBalancerLists > 0 {
		a.hideLoadBalancerLists--
		return nil, nil
	}
	result := make([]inspace.LoadBalancer, len(items))
	copy(result, items)
	for i := range result {
		result[i].Targets = append([]inspace.LoadBalancerTarget(nil), items[i].Targets...)
		result[i].ForwardingRules = append([]inspace.LoadBalancerRule(nil), items[i].ForwardingRules...)
		if a.targetCommitted != "" && a.hideTargetLists > 0 {
			filtered := result[i].Targets[:0]
			for _, target := range result[i].Targets {
				if target.TargetUUID != a.targetCommitted {
					filtered = append(filtered, target)
				}
			}
			result[i].Targets = filtered
		}
		if a.ruleCommitted != nil && a.hideRuleLists > 0 {
			filtered := result[i].ForwardingRules[:0]
			for _, rule := range result[i].ForwardingRules {
				if rule.SourcePort != a.ruleCommitted.SourcePort || rule.TargetPort != a.ruleCommitted.TargetPort {
					filtered = append(filtered, rule)
				}
			}
			result[i].ForwardingRules = filtered
		}
	}
	if a.targetCommitted != "" && a.hideTargetLists > 0 {
		a.hideTargetLists--
	}
	if a.ruleCommitted != nil && a.hideRuleLists > 0 {
		a.hideRuleLists--
	}
	return result, nil
}

func (a *lateStandardNLBAPI) GetLoadBalancer(ctx context.Context, location, uuid string) (*inspace.LoadBalancer, error) {
	item, err := a.fakeAPI.GetLoadBalancer(ctx, location, uuid)
	if err != nil || item == nil {
		return item, err
	}
	if a.targetCommitted != "" && a.hideTargetLists > 0 {
		filtered := item.Targets[:0]
		for _, target := range item.Targets {
			if target.TargetUUID != a.targetCommitted {
				filtered = append(filtered, target)
			}
		}
		item.Targets = filtered
	}
	if a.ruleCommitted != nil && a.hideRuleLists > 0 {
		filtered := item.ForwardingRules[:0]
		for _, rule := range item.ForwardingRules {
			if rule.SourcePort != a.ruleCommitted.SourcePort || rule.TargetPort != a.ruleCommitted.TargetPort {
				filtered = append(filtered, rule)
			}
		}
		item.ForwardingRules = filtered
	}
	return item, nil
}

func (a *lateStandardNLBAPI) CreateLoadBalancer(
	ctx context.Context,
	location string,
	request inspace.CreateLoadBalancerRequest,
) (*inspace.LoadBalancer, error) {
	if a.loadBalancerRejectErr != nil {
		a.fakeAPI.creates = append(a.fakeAPI.creates, request)
		return nil, a.loadBalancerRejectErr
	}
	created, err := a.fakeAPI.CreateLoadBalancer(ctx, location, request)
	if err != nil {
		return created, err
	}
	if a.mutateCommittedLoadBalancer != nil {
		// The fake create response is a distinct Go value from the row retained
		// by fakeAPI, while its relationship slices initially alias the request.
		// Detach both before introducing server-side drift, then return a matching
		// copy so these tests model a committed POST followed by divergent state.
		row := &a.fakeAPI.lbs[len(a.fakeAPI.lbs)-1]
		row.ForwardingRules = append([]inspace.LoadBalancerRule(nil), row.ForwardingRules...)
		row.Targets = append([]inspace.LoadBalancerTarget(nil), row.Targets...)
		a.mutateCommittedLoadBalancer(row)
		copy := a.fakeAPI.lbs[len(a.fakeAPI.lbs)-1]
		created = &copy
	}
	return created, a.loadBalancerCreateErr
}

func (a *lateStandardNLBAPI) ListFloatingIPs(
	ctx context.Context,
	location string,
	filters *inspace.FloatingIPFilters,
) ([]inspace.FloatingIP, error) {
	a.floatingIPListCalls++
	if a.failFloatingIPListOn == a.floatingIPListCalls {
		return nil, a.floatingIPListErr
	}
	items, err := a.fakeAPI.ListFloatingIPs(ctx, location, filters)
	if err != nil {
		return nil, err
	}
	if a.hideFloatingIPLists > 0 {
		a.hideFloatingIPLists--
		return nil, nil
	}
	result := append([]inspace.FloatingIP(nil), items...)
	if a.assignmentCommitted && a.hideAssignmentLists > 0 {
		for i := range result {
			result[i].AssignedTo = ""
			result[i].AssignedToResourceType = ""
			result[i].AssignedToPrivateIP = ""
		}
		a.hideAssignmentLists--
	}
	return result, nil
}

func (a *lateStandardNLBAPI) DeleteLoadBalancer(ctx context.Context, location, uuid string) error {
	err := a.fakeAPI.DeleteLoadBalancer(ctx, location, uuid)
	if err != nil {
		return err
	}
	return a.deleteLoadBalancerErr
}

func (a *lateStandardNLBAPI) CreateFloatingIP(
	ctx context.Context,
	location string,
	request inspace.CreateFloatingIPRequest,
) (*inspace.FloatingIP, error) {
	a.floatingIPCreateCalls++
	created, err := a.fakeAPI.CreateFloatingIP(ctx, location, request)
	if err != nil {
		return created, err
	}
	return created, a.floatingIPCreateErr
}

func (a *lateStandardNLBAPI) AssignFloatingIP(
	ctx context.Context,
	location, address, resourceUUID, resourceType string,
) (*inspace.FloatingIP, error) {
	a.assignFloatingIPCalls++
	assigned, err := a.fakeAPI.AssignFloatingIP(ctx, location, address, resourceUUID, resourceType)
	if err != nil {
		return assigned, err
	}
	a.assignmentCommitted = true
	return assigned, a.assignFloatingIPErr
}

func (a *lateStandardNLBAPI) AddLoadBalancerTarget(
	ctx context.Context,
	location, loadBalancerUUID, targetUUID string,
) (*inspace.LoadBalancerTarget, error) {
	created, err := a.fakeAPI.AddLoadBalancerTarget(ctx, location, loadBalancerUUID, targetUUID)
	if err != nil {
		return created, err
	}
	a.targetCommitted = targetUUID
	return created, a.addTargetErr
}

func (a *lateStandardNLBAPI) AddLoadBalancerRule(
	ctx context.Context,
	location, loadBalancerUUID string,
	rule inspace.LoadBalancerRule,
) (*inspace.LoadBalancerRule, error) {
	created, err := a.fakeAPI.AddLoadBalancerRule(ctx, location, loadBalancerUUID, rule)
	if err != nil {
		return created, err
	}
	copy := rule
	a.ruleCommitted = &copy
	return created, a.addRuleErr
}

func newStandardNLBProviderWithStore(
	t *testing.T,
	api API,
	store standardNLBServiceStore,
) *Provider {
	t.Helper()
	provider := newTestProvider(t, api)
	provider.standardNLBServiceStore = store
	return provider
}

func standardNLBTestCreateRequest(provider *Provider, service *corev1.Service, targets ...string) inspace.CreateLoadBalancerRequest {
	return standardNLBDesiredRequest(provider, service, targets, serviceRules(service))
}

func assertIssuedStandardNLBFence(t *testing.T, store standardNLBServiceStore, service *corev1.Service, operation string) {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := parseStandardNLBFence(current.Annotations[annotationStandardNLBMutation])
	if err != nil {
		t.Fatal(err)
	}
	if fence == nil || fence.Operation != operation || fence.Phase != standardNLBPhaseIssued || fence.IssuedAt == "" {
		t.Fatalf("durable issued fence = %#v, annotations=%#v", fence, current.Annotations)
	}
}

func assertNoStandardNLBFence(t *testing.T, store standardNLBServiceStore, service *corev1.Service) {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if current.Annotations[annotationStandardNLBMutation] != "" {
		t.Fatalf("public NLB mutation fence was not cleared: %s", current.Annotations[annotationStandardNLBMutation])
	}
}

func TestOnlyTypedLocalBlockIsKnownPreDispatch(t *testing.T) {
	for _, test := range []struct {
		name        string
		err         error
		preDispatch bool
	}{
		{name: "validation response", err: &inspace.APIError{StatusCode: 422}},
		{name: "request timeout", err: &inspace.APIError{StatusCode: 408}},
		{name: "conflict", err: &inspace.APIError{StatusCode: 409}},
		{name: "too early", err: &inspace.APIError{StatusCode: 425}},
		{name: "rate limit", err: &inspace.APIError{StatusCode: 429, Retryable: true}},
		{name: "client closed request", err: &inspace.APIError{StatusCode: 499}},
		{name: "server error", err: &inspace.APIError{StatusCode: 503, Retryable: true}},
		{name: "transport", err: errors.New("connection reset")},
		{name: "preflight block", err: inspace.ErrMutationBlocked, preDispatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := standardNLBMutationKnownPreDispatch(test.err); got != test.preDispatch {
				t.Fatalf("standardNLBMutationKnownPreDispatch(%v) = %t, want %t", test.err, got, test.preDispatch)
			}
		})
	}
}

func TestStandardNLBReadbackNormalizesExactDuplicateRelationships(t *testing.T) {
	lb := &inspace.LoadBalancer{
		Targets: []inspace.LoadBalancerTarget{
			{TargetUUID: testVMUUID, TargetType: "vm"},
			{TargetUUID: testVMUUID, TargetType: "vm"},
		},
		ForwardingRules: []inspace.LoadBalancerRule{
			{UUID: "11111111-1111-4111-8111-111111111111", Protocol: "TCP", SourcePort: 443, TargetPort: 30443},
			{UUID: "22222222-2222-4222-8222-222222222222", Protocol: "TCP", SourcePort: 443, TargetPort: 30443},
		},
	}
	visible, err := standardNLBTargetVisible(lb, testVMUUID)
	if err != nil || !visible {
		t.Fatalf("duplicate exact target visible=%t err=%v", visible, err)
	}
	visible, err = standardNLBRuleVisible(lb, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 30443})
	if err != nil || !visible {
		t.Fatalf("duplicate exact rule visible=%t err=%v", visible, err)
	}

	lb.Targets = append(lb.Targets, inspace.LoadBalancerTarget{TargetUUID: testVMUUID, TargetType: "disk"})
	if _, err := standardNLBTargetVisible(lb, testVMUUID); err == nil {
		t.Fatal("conflicting target type was accepted")
	}
	lb.ForwardingRules = append(lb.ForwardingRules, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 31443})
	if _, err := standardNLBRuleVisible(lb, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}); err == nil {
		t.Fatal("conflicting rule on the same source port was accepted")
	}
}

func TestStandardNLBRemovalReadFailureBlocksDependentAdd(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("removal readback unavailable")

	t.Run("target", func(t *testing.T) {
		service := testService()
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		staleTarget := "99999999-1111-4222-8333-444444444444"
		base.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			Targets:         []inspace.LoadBalancerTarget{{TargetUUID: staleTarget, TargetType: "vm"}},
			ForwardingRules: serviceRules(service),
		}}
		api := &lateStandardNLBAPI{
			fakeAPI:                base,
			failLoadBalancerListOn: 2,
			loadBalancerListErr:    readErr,
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
		if err := provider.reconcileLoadBalancer(ctx, service, &base.lbs[0], []string{testVMUUID}, serviceRules(service)); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("target removal/readback result = %v", err)
		}
		if len(base.removedTargets) != 1 || len(base.addedTargets) != 0 {
			t.Fatalf("dependent target add crossed failed readback: removed=%v added=%v", base.removedTargets, base.addedTargets)
		}

		api.failLoadBalancerListOn = 0
		requireStandardNLBConvergence(t, func() error {
			current, findErr := provider.findOwnedLoadBalancer(ctx, service)
			if findErr != nil {
				return findErr
			}
			return provider.reconcileLoadBalancer(ctx, service, current, []string{testVMUUID}, serviceRules(service))
		})
		if len(base.removedTargets) != 1 || len(base.addedTargets) != 1 {
			t.Fatalf("target replacement did not converge: removed=%v added=%v", base.removedTargets, base.addedTargets)
		}
	})

	t.Run("rule", func(t *testing.T) {
		service := testService()
		service.Spec.Ports[0].NodePort = 31443
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		base.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			Targets: []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}},
			ForwardingRules: []inspace.LoadBalancerRule{{
				UUID: "11111111-1111-4111-8111-111111111111", Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
			}},
		}}
		desiredRules := serviceRules(service)
		api := &lateStandardNLBAPI{
			fakeAPI:                base,
			failLoadBalancerListOn: 3,
			loadBalancerListErr:    readErr,
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		if err := provider.reconcileLoadBalancer(ctx, service, &base.lbs[0], []string{testVMUUID}, desiredRules); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("rule removal/readback result = %v", err)
		}
		if len(base.removedRules) != 1 || len(base.addedRules) != 0 {
			t.Fatalf("dependent rule add crossed failed readback: removed=%v added=%v", base.removedRules, base.addedRules)
		}

		api.failLoadBalancerListOn = 0
		requireStandardNLBConvergence(t, func() error {
			current, findErr := provider.findOwnedLoadBalancer(ctx, service)
			if findErr != nil {
				return findErr
			}
			return provider.reconcileLoadBalancer(ctx, service, current, []string{testVMUUID}, desiredRules)
		})
		if len(base.removedRules) != 1 || len(base.addedRules) != 1 {
			t.Fatalf("rule replacement did not converge: removed=%v added=%v", base.removedRules, base.addedRules)
		}
	})
}

func TestStandardNLBHTTPCreateRejectionRetainsIssuedFence(t *testing.T) {
	api := &lateStandardNLBAPI{
		fakeAPI: &fakeAPI{},
		loadBalancerRejectErr: &inspace.APIError{
			StatusCode: 422, Method: "POST", Path: "/network/load_balancers", Message: "invalid request",
		},
	}
	store := newMemoryStandardNLBServiceStore()
	service := testService()
	provider := newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil || !strings.Contains(err.Error(), "HTTP 422") {
		t.Fatalf("HTTP create rejection = %v", err)
	}
	if len(api.creates) != 1 || len(api.lbs) != 0 {
		t.Fatalf("HTTP rejection cloud state: creates=%d LBs=%#v", len(api.creates), api.lbs)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)

	provider = newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil || !strings.Contains(err.Error(), "refusing a second paid create") {
		t.Fatalf("restart did not stay read-only: %v", err)
	}
	if len(api.creates) != 1 {
		t.Fatalf("HTTP rejection was blindly replayed: creates=%d", len(api.creates))
	}
}

func TestStandardNLBHTTP400HiddenCommitNeverReplaysAfterEmptyReadback(t *testing.T) {
	ctx := context.Background()
	api := &lateStandardNLBAPI{
		fakeAPI:               &fakeAPI{},
		hideLoadBalancerLists: 2,
		loadBalancerCreateErr: &inspace.APIError{
			StatusCode: 400, Method: "POST", Path: "/network/load_balancers",
			Message: "reported rejection after commit",
		},
	}
	store := newMemoryStandardNLBServiceStore()
	service := testService()
	provider := newStandardNLBProviderWithStore(t, api, store)
	request := standardNLBTestCreateRequest(provider, service)
	if _, _, err := provider.ensureStandardNLBLoadBalancer(ctx, service, nil, request); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("hidden HTTP 400 create result = %v", err)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)
	if len(api.creates) != 1 {
		t.Fatalf("creates = %d, want one", len(api.creates))
	}

	observed, err := provider.findOwnedLoadBalancer(ctx, service)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.ensureStandardNLBLoadBalancer(ctx, service, observed, request); err != nil {
		t.Fatal(err)
	}
	assertNoStandardNLBFence(t, store, service)
	if len(api.creates) != 1 {
		t.Fatalf("late HTTP 400 commit was replayed: creates=%d", len(api.creates))
	}
}

func TestStandardNLBPostMutationReadFailureNeverClearsIssuedFence(t *testing.T) {
	ctx := context.Background()
	definitiveErr := &inspace.APIError{StatusCode: 422, Method: "POST", Message: "reported rejection after commit"}
	readErr := errors.New("authoritative readback unavailable")

	t.Run("load balancer create", func(t *testing.T) {
		api := &lateStandardNLBAPI{
			fakeAPI:                &fakeAPI{},
			loadBalancerCreateErr:  definitiveErr,
			failLoadBalancerListOn: 2,
			loadBalancerListErr:    readErr,
		}
		store := newMemoryStandardNLBServiceStore()
		service := testService()
		provider := newStandardNLBProviderWithStore(t, api, store)
		request := standardNLBTestCreateRequest(provider, service)
		if _, _, err := provider.ensureStandardNLBLoadBalancer(ctx, service, nil, request); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("create/readback result = %v", err)
		}
		assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)
		if len(api.creates) != 1 {
			t.Fatalf("creates = %d, want one", len(api.creates))
		}

		api.failLoadBalancerListOn = 0
		observed, err := provider.findOwnedLoadBalancer(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := provider.ensureStandardNLBLoadBalancer(ctx, service, observed, request); err != nil {
			t.Fatal(err)
		}
		assertNoStandardNLBFence(t, store, service)
		if len(api.creates) != 1 {
			t.Fatalf("committed create replayed: %d", len(api.creates))
		}
	})

	t.Run("floating IP create", func(t *testing.T) {
		api := &lateStandardNLBAPI{
			fakeAPI:              &fakeAPI{},
			floatingIPCreateErr:  definitiveErr,
			failFloatingIPListOn: 2,
			floatingIPListErr:    readErr,
		}
		store := newMemoryStandardNLBServiceStore()
		service := testService()
		provider := newStandardNLBProviderWithStore(t, api, store)
		api.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
			BillingAccountID: 42, PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
		}}
		if _, err := provider.ensureStandardNLBPublicFloatingIP(ctx, service, nil); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("create/readback result = %v", err)
		}
		assertIssuedStandardNLBFence(t, store, service, standardNLBCreateFloatingIP)
		if api.floatingIPCreateCalls != 1 {
			t.Fatalf("creates = %d, want one", api.floatingIPCreateCalls)
		}

		api.failFloatingIPListOn = 0
		observed, err := provider.findOwnedFloatingIP(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.ensureStandardNLBPublicFloatingIP(ctx, service, observed); err != nil {
			t.Fatal(err)
		}
		assertNoStandardNLBFence(t, store, service)
		if api.floatingIPCreateCalls != 1 {
			t.Fatalf("committed create replayed: %d", api.floatingIPCreateCalls)
		}
	})

	t.Run("floating IP assignment", func(t *testing.T) {
		service := testService()
		base := &fakeAPI{}
		providerForNames := newTestProvider(t, base)
		lb := &inspace.LoadBalancer{
			UUID: testLBUUID, DisplayName: providerForNames.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
		}
		floatingIP := inspace.FloatingIP{
			Name: providerForNames.floatingIPName(service), Address: "203.0.113.20",
			BillingAccountID: 42, Type: "public", Enabled: true,
		}
		base.lbs = []inspace.LoadBalancer{*lb}
		base.floatingIPs = []inspace.FloatingIP{floatingIP}
		api := &lateStandardNLBAPI{
			fakeAPI:              base,
			assignFloatingIPErr:  definitiveErr,
			failFloatingIPListOn: 2,
			floatingIPListErr:    readErr,
		}
		store := newMemoryStandardNLBServiceStore()
		provider := newStandardNLBProviderWithStore(t, api, store)
		if _, err := provider.ensureStandardNLBFloatingIPAssignment(ctx, service, lb, &floatingIP); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("assign/readback result = %v", err)
		}
		assertIssuedStandardNLBFence(t, store, service, standardNLBAssignFloatingIP)
		if api.assignFloatingIPCalls != 1 {
			t.Fatalf("assignments = %d, want one", api.assignFloatingIPCalls)
		}

		api.failFloatingIPListOn = 0
		observed, err := provider.findOwnedFloatingIP(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.ensureStandardNLBFloatingIPAssignment(ctx, service, lb, observed); err != nil {
			t.Fatal(err)
		}
		assertNoStandardNLBFence(t, store, service)
		if api.assignFloatingIPCalls != 1 {
			t.Fatalf("committed assignment replayed: %d", api.assignFloatingIPCalls)
		}
	})

	for _, test := range []struct {
		name      string
		operation string
		mutate    func(*Provider, *corev1.Service, *inspace.LoadBalancer) error
		resolve   func(*Provider, *corev1.Service, *inspace.LoadBalancer) error
		configure func(*lateStandardNLBAPI)
		calls     func(*fakeAPI) int
	}{
		{
			name: "target add", operation: standardNLBAddTarget,
			mutate: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				_, err := provider.addStandardNLBTarget(ctx, service, lb, testVMUUID)
				return err
			},
			resolve: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				return provider.resolvePendingStandardNLBAdd(ctx, service, lb, []string{testVMUUID}, nil)
			},
			configure: func(api *lateStandardNLBAPI) { api.addTargetErr = definitiveErr },
			calls:     func(api *fakeAPI) int { return len(api.addedTargets) },
		},
		{
			name: "rule add", operation: standardNLBAddRule,
			mutate: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				_, err := provider.addStandardNLBRule(ctx, service, lb, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 30443})
				return err
			},
			resolve: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				return provider.resolvePendingStandardNLBAdd(ctx, service, lb, nil, []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}})
			},
			configure: func(api *lateStandardNLBAPI) { api.addRuleErr = definitiveErr },
			calls:     func(api *fakeAPI) int { return len(api.addedRules) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
			}}
			api := &lateStandardNLBAPI{
				fakeAPI:                base,
				failLoadBalancerListOn: 2,
				loadBalancerListErr:    readErr,
			}
			test.configure(api)
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			if test.operation == standardNLBAddTarget {
				setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			}
			if err := test.mutate(provider, service, &base.lbs[0]); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
				t.Fatalf("mutation/readback result = %v", err)
			}
			assertIssuedStandardNLBFence(t, store, service, test.operation)
			if test.calls(base) != 1 {
				t.Fatalf("mutation calls = %d, want one", test.calls(base))
			}

			api.failLoadBalancerListOn = 0
			observed, err := provider.findOwnedLoadBalancer(ctx, service)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.resolve(provider, service, observed); err != nil {
				t.Fatal(err)
			}
			assertNoStandardNLBFence(t, store, service)
			if test.calls(base) != 1 {
				t.Fatalf("committed mutation replayed: %d", test.calls(base))
			}
		})
	}
}

func TestStandardNLBCreateRechecksDeterministicAbsenceAfterIssue(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"desired", "foreign"} {
		t.Run("load-balancer/"+state, func(t *testing.T) {
			base := &fakeAPI{}
			service := testService()
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, base, store)
			setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			request := standardNLBTestCreateRequest(provider, service)
			store.hook = func() {
				billing := int64(42)
				if state == "foreign" {
					billing++
				}
				base.lbs = append(base.lbs, inspace.LoadBalancer{
					UUID: testLBUUID, DisplayName: request.DisplayName, NetworkUUID: testNetworkUUID,
					BillingAccountID: billing, PrivateAddress: "10.0.0.50",
					ForwardingRules: append([]inspace.LoadBalancerRule(nil), request.Rules...),
					Targets:         append([]inspace.LoadBalancerTarget(nil), request.Targets...),
				})
			}
			observed, changed, err := provider.ensureStandardNLBLoadBalancer(ctx, service, nil, request)
			if len(base.creates) != 0 {
				t.Fatalf("post-issue appearance still dispatched create: %#v", base.creates)
			}
			if state == "desired" {
				if err != nil || !changed || observed == nil || observed.UUID != testLBUUID {
					t.Fatalf("desired post-issue appearance: observed=%#v changed=%t err=%v", observed, changed, err)
				}
				assertNoStandardNLBFence(t, inner, service)
			} else {
				if err == nil || observed != nil || changed {
					t.Fatalf("foreign post-issue appearance: observed=%#v changed=%t err=%v", observed, changed, err)
				}
				assertIssuedStandardNLBFence(t, inner, service, standardNLBCreateLoadBalancer)
			}
		})

		t.Run("floating-ip/"+state, func(t *testing.T) {
			base := &fakeAPI{}
			service := testService()
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, base, store)
			store.hook = func() {
				billing := int64(42)
				if state == "foreign" {
					billing++
				}
				base.floatingIPs = append(base.floatingIPs, inspace.FloatingIP{
					Name: provider.floatingIPName(service), Address: "203.0.113.20",
					BillingAccountID: billing, Type: "public", Enabled: true,
				})
			}
			observed, err := provider.ensureStandardNLBPublicFloatingIP(ctx, service, nil)
			if len(base.floatingIPs) != 1 {
				t.Fatalf("post-issue appearance dispatched another floating-IP create: %#v", base.floatingIPs)
			}
			if state == "desired" {
				if err != nil || observed == nil || observed.Address != "203.0.113.20" {
					t.Fatalf("desired post-issue floating IP: observed=%#v err=%v", observed, err)
				}
				assertNoStandardNLBFence(t, inner, service)
			} else {
				if err == nil || observed != nil {
					t.Fatalf("foreign post-issue floating IP: observed=%#v err=%v", observed, err)
				}
				assertIssuedStandardNLBFence(t, inner, service, standardNLBCreateFloatingIP)
			}
		})
	}
}

func TestStandardNLBPostIssueAuthorityDriftBlocksEveryMutationClass(t *testing.T) {
	ctx := context.Background()
	ruleUUID := "77777777-1111-4222-8333-444444444444"
	for _, operation := range []string{
		standardNLBAssignFloatingIP,
		standardNLBUnassignFloatingIP,
		standardNLBDeleteFloatingIP,
		standardNLBDeleteLoadBalancer,
		standardNLBAddTarget,
		standardNLBRemoveTarget,
		standardNLBAddRule,
		standardNLBRemoveRule,
	} {
		t.Run(operation, func(t *testing.T) {
			base := &fakeAPI{vms: []inspace.VM{{
				UUID: testVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID,
			}}}
			service := testService()
			if operation == standardNLBUnassignFloatingIP || operation == standardNLBDeleteFloatingIP ||
				operation == standardNLBDeleteLoadBalancer {
				service.Labels = nil
				service.Annotations = nil
			}
			if operation == standardNLBRemoveRule {
				service.Spec.Ports[0].NodePort = 31443
			}
			nameProvider := newTestProvider(t, base)
			lb := inspace.LoadBalancer{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}
			if operation == standardNLBRemoveTarget {
				lb.Targets = []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}}
			}
			if operation == standardNLBRemoveRule {
				lb.ForwardingRules = []inspace.LoadBalancerRule{{
					UUID: ruleUUID, Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
				}}
			}
			if operation == standardNLBAssignFloatingIP {
				lb.ForwardingRules = serviceRules(service)
			}
			base.lbs = []inspace.LoadBalancer{lb}
			floatingIP := inspace.FloatingIP{
				Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
				BillingAccountID: 42, Type: "public", Enabled: true,
			}
			if operation == standardNLBUnassignFloatingIP {
				floatingIP.AssignedTo = testLBUUID
				floatingIP.AssignedToResourceType = "load_balancer"
				floatingIP.AssignedToPrivateIP = lb.PrivateAddress
			}
			if operation == standardNLBAssignFloatingIP || operation == standardNLBUnassignFloatingIP ||
				operation == standardNLBDeleteFloatingIP {
				base.floatingIPs = []inspace.FloatingIP{floatingIP}
			}
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, base, store)
			if operation == standardNLBAddTarget {
				setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			}
			store.hook = func() {
				if operation == standardNLBAssignFloatingIP || operation == standardNLBUnassignFloatingIP ||
					operation == standardNLBDeleteFloatingIP {
					base.floatingIPs[0].BillingAccountID++
				} else {
					base.lbs[0].BillingAccountID++
				}
			}

			var err error
			switch operation {
			case standardNLBAssignFloatingIP:
				_, err = provider.ensureStandardNLBFloatingIPAssignment(ctx, service, &lb, &floatingIP)
			case standardNLBUnassignFloatingIP, standardNLBDeleteFloatingIP:
				err = provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, testLBUUID, lb.PrivateAddress)
			case standardNLBDeleteLoadBalancer:
				err = provider.cleanupOwnedLoadBalancer(ctx, service, &lb)
			case standardNLBAddTarget:
				_, err = provider.addStandardNLBTarget(ctx, service, &lb, testVMUUID)
			case standardNLBRemoveTarget:
				_, err = provider.removeStandardNLBTarget(ctx, service, &lb, testVMUUID)
			case standardNLBAddRule:
				_, err = provider.addStandardNLBRule(ctx, service, &lb, inspace.LoadBalancerRule{
					Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
				})
			case standardNLBRemoveRule:
				_, err = provider.removeStandardNLBRule(ctx, service, &lb, ruleUUID)
			}
			if err == nil {
				t.Fatal("post-issue authority drift returned no error")
			}
			if len(base.deletedLBs) != 0 || len(base.addedTargets) != 0 || len(base.removedTargets) != 0 ||
				len(base.addedRules) != 0 || len(base.removedRules) != 0 || len(base.unassignedIPs) != 0 ||
				len(base.deletedIPs) != 0 ||
				(len(base.floatingIPs) != 0 && base.floatingIPs[0].AssignedTo != floatingIP.AssignedTo) {
				t.Fatalf("post-issue drift crossed cloud boundary: %#v", base)
			}
			assertIssuedStandardNLBFence(t, inner, service, operation)
		})
	}
}

func mutateStandardNLBStoredService(
	t *testing.T,
	store standardNLBServiceStore,
	service *corev1.Service,
	mutate func(*corev1.Service),
) {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	mutate(current)
	if _, err := store.UpdateExact(context.Background(), current); err != nil {
		t.Fatal(err)
	}
}

func TestStandardNLBAdditiveMutationsRejectServiceWithdrawalAfterIssue(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{
		standardNLBCreateLoadBalancer,
		standardNLBCreateFloatingIP,
		standardNLBAssignFloatingIP,
		standardNLBAddTarget,
		standardNLBAddRule,
	} {
		t.Run(operation, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			api := &lateStandardNLBAPI{fakeAPI: base}
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, api, store)
			lb := inspace.LoadBalancer{
				UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
				BillingAccountID: 42, PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
			}
			if operation != standardNLBCreateLoadBalancer {
				base.lbs = []inspace.LoadBalancer{lb}
			}
			floatingIP := inspace.FloatingIP{
				Name: provider.floatingIPName(service), Address: "203.0.113.20",
				BillingAccountID: 42, Type: "public", Enabled: true,
			}
			if operation == standardNLBAssignFloatingIP {
				base.floatingIPs = []inspace.FloatingIP{floatingIP}
			}
			if operation == standardNLBAddTarget {
				setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			}
			store.hook = func() {
				mutateStandardNLBStoredService(t, inner, service, func(current *corev1.Service) {
					current.Labels = nil
					current.Annotations[AnnotationPublicLoadBalancer] = "false"
				})
			}

			var err error
			switch operation {
			case standardNLBCreateLoadBalancer:
				_, _, err = provider.ensureStandardNLBLoadBalancer(
					ctx, service, nil, standardNLBTestCreateRequest(provider, service),
				)
			case standardNLBCreateFloatingIP:
				_, err = provider.ensureStandardNLBPublicFloatingIP(ctx, service, nil)
			case standardNLBAssignFloatingIP:
				_, err = provider.ensureStandardNLBFloatingIPAssignment(ctx, service, &lb, &floatingIP)
			case standardNLBAddTarget:
				_, err = provider.addStandardNLBTarget(ctx, service, &lb, testVMUUID)
			case standardNLBAddRule:
				lb.ForwardingRules = nil
				base.lbs[0] = lb
				_, err = provider.addStandardNLBRule(ctx, service, &lb, serviceRules(service)[0])
			}
			if err == nil {
				t.Fatal("withdrawn Service still authorized additive cloud mutation")
			}
			if len(base.creates) != 0 || api.floatingIPCreateCalls != 0 || api.assignFloatingIPCalls != 0 ||
				len(base.addedTargets) != 0 || len(base.addedRules) != 0 {
				t.Fatalf("withdrawn Service crossed cloud boundary: %#v", base)
			}
			assertIssuedStandardNLBFence(t, inner, service, operation)
		})
	}
}

func TestStandardNLBDestructiveMutationsRejectReaddedLiveIntentAfterIssue(t *testing.T) {
	ctx := context.Background()
	ruleUUID := "78888888-1111-4222-8333-444444444444"
	for _, operation := range []string{
		standardNLBRemoveTarget,
		standardNLBRemoveRule,
		standardNLBUnassignFloatingIP,
		standardNLBDeleteFloatingIP,
		standardNLBDeleteLoadBalancer,
	} {
		t.Run(operation, func(t *testing.T) {
			service := testService()
			if operation == standardNLBRemoveRule {
				service.Spec.Ports[0].NodePort = 31443
			}
			if operation == standardNLBUnassignFloatingIP || operation == standardNLBDeleteFloatingIP ||
				operation == standardNLBDeleteLoadBalancer {
				service.Spec.Type = corev1.ServiceTypeClusterIP
			}
			base := &fakeAPI{}
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, base, store)
			lb := inspace.LoadBalancer{
				UUID: testLBUUID, DisplayName: provider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
				BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}
			if operation == standardNLBRemoveTarget {
				lb.Targets = []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}}
			}
			if operation == standardNLBRemoveRule {
				lb.ForwardingRules = []inspace.LoadBalancerRule{{
					UUID: ruleUUID, Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
				}}
			}
			base.lbs = []inspace.LoadBalancer{lb}
			floatingIP := inspace.FloatingIP{
				Name: provider.floatingIPName(service), Address: "203.0.113.20",
				BillingAccountID: 42, Type: "public", Enabled: true,
			}
			if operation == standardNLBUnassignFloatingIP {
				floatingIP.AssignedTo = testLBUUID
				floatingIP.AssignedToResourceType = "load_balancer"
				floatingIP.AssignedToPrivateIP = lb.PrivateAddress
			}
			if operation == standardNLBUnassignFloatingIP || operation == standardNLBDeleteFloatingIP {
				base.floatingIPs = []inspace.FloatingIP{floatingIP}
			}
			store.hook = func() {
				switch operation {
				case standardNLBRemoveTarget:
					if _, err := provider.kubeClient.CoreV1().Nodes().Create(
						ctx, readyNode("worker-a", "inspace://bkk01/"+testVMUUID), metav1.CreateOptions{},
					); err != nil {
						t.Fatal(err)
					}
				case standardNLBRemoveRule:
					mutateStandardNLBStoredService(t, inner, service, func(current *corev1.Service) {
						current.Spec.Ports[0].NodePort = 30443
					})
				default:
					mutateStandardNLBStoredService(t, inner, service, func(current *corev1.Service) {
						current.Spec.Type = corev1.ServiceTypeLoadBalancer
					})
				}
			}

			var err error
			switch operation {
			case standardNLBRemoveTarget:
				_, err = provider.removeStandardNLBTarget(ctx, service, &lb, testVMUUID)
			case standardNLBRemoveRule:
				_, err = provider.removeStandardNLBRule(ctx, service, &lb, ruleUUID)
			case standardNLBUnassignFloatingIP, standardNLBDeleteFloatingIP:
				err = provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, testLBUUID, lb.PrivateAddress)
			case standardNLBDeleteLoadBalancer:
				err = provider.cleanupOwnedLoadBalancer(ctx, service, &lb)
			}
			if err == nil {
				t.Fatal("re-added live intent still authorized destructive cloud mutation")
			}
			if len(base.removedTargets) != 0 || len(base.removedRules) != 0 || len(base.unassignedIPs) != 0 ||
				len(base.deletedIPs) != 0 || len(base.deletedLBs) != 0 {
				t.Fatalf("re-added live intent crossed cloud boundary: %#v", base)
			}
			assertIssuedStandardNLBFence(t, inner, service, operation)
		})
	}
}

func TestStandardNLBAddTargetRechecksKubernetesEligibilityAfterIssue(t *testing.T) {
	for _, test := range []struct {
		name   string
		local  bool
		mutate func(context.Context, *Provider) error
	}{
		{
			name: "Node becomes NotReady",
			mutate: func(ctx context.Context, provider *Provider) error {
				node, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, "worker-a", metav1.GetOptions{})
				if err != nil {
					return err
				}
				node.Status.Conditions[0].Status = corev1.ConditionFalse
				_, err = provider.kubeClient.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
				return err
			},
		},
		{
			name:  "Local endpoint disappears",
			local: true,
			mutate: func(ctx context.Context, provider *Provider) error {
				return provider.kubeClient.DiscoveryV1().EndpointSlices("default").Delete(
					ctx,
					"web-a",
					metav1.DeleteOptions{},
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service := testService()
			if test.local {
				service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			}
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}}
			inner := newMemoryStandardNLBServiceStore()
			store := &standardNLBPostIssueHookStore{standardNLBServiceStore: inner}
			provider := newStandardNLBProviderWithStore(t, base, store)
			setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			if test.local {
				if _, err := provider.kubeClient.DiscoveryV1().EndpointSlices("default").Create(
					ctx,
					testEndpointSlice("default", "web", "web-a", endpointForNode("worker-a", true, false)),
					metav1.CreateOptions{},
				); err != nil {
					t.Fatal(err)
				}
			}
			store.hook = func() {
				if err := test.mutate(ctx, provider); err != nil {
					t.Errorf("post-issue Kubernetes mutation: %v", err)
				}
			}

			if _, err := provider.addStandardNLBTarget(ctx, service, &base.lbs[0], testVMUUID); err == nil {
				t.Fatal("post-issue target ineligibility allowed AddLoadBalancerTarget")
			}
			if len(base.addedTargets) != 0 || len(base.lbs[0].Targets) != 0 {
				t.Fatalf("post-issue target ineligibility mutated cloud state: calls=%v targets=%#v", base.addedTargets, base.lbs[0].Targets)
			}
			assertIssuedStandardNLBFence(t, inner, service, standardNLBAddTarget)
		})
	}
}

func TestStandardNLBMutationRequiresDurableExactServiceBeforeCloudWrite(t *testing.T) {
	t.Run("missing store", func(t *testing.T) {
		api := &fakeAPI{}
		provider, err := New(api, Config{
			Location: "bkk01", Region: "thailand", NetworkUUID: testNetworkUUID,
			BillingAccountID: 42, ClusterID: "unit-test-cluster", ControlPlaneVIP: "10.0.0.10",
			PrivateLoadBalancerPoolStart: "10.0.0.200", PrivateLoadBalancerPoolStop: "10.0.0.239",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", testService(), nil); err == nil || !strings.Contains(err.Error(), "Initialize must install") {
			t.Fatalf("missing-store result = %v", err)
		}
		if len(api.creates) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("missing store allowed cloud mutation: creates=%d FIPs=%#v", len(api.creates), api.floatingIPs)
		}
	})

	t.Run("UID mismatch", func(t *testing.T) {
		api := &fakeAPI{}
		store := newMemoryStandardNLBServiceStore()
		service := testService()
		foreign := service.DeepCopy()
		foreign.UID = "99999999-9999-4999-8999-999999999999"
		if _, err := store.GetExact(context.Background(), foreign); err != nil {
			t.Fatal(err)
		}
		provider := newStandardNLBProviderWithStore(t, api, store)
		if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("UID-mismatch result = %v", err)
		}
		if len(api.creates) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("UID mismatch allowed cloud mutation: creates=%d FIPs=%#v", len(api.creates), api.floatingIPs)
		}
	})
}

func TestStandardNLBCreateFenceRecoversLateCommittedLoadBalancerAfterRestart(t *testing.T) {
	api := &lateStandardNLBAPI{
		fakeAPI:               &fakeAPI{},
		hideLoadBalancerLists: 4,
		loadBalancerCreateErr: errors.New("transport timeout after NLB commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	service := testService()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}

	provider := newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("first ambiguous create error = %v", err)
	}
	if len(api.creates) != 1 {
		t.Fatalf("NLB creates = %d, want one", len(api.creates))
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "refusing a second paid create") {
		t.Fatalf("hidden post-restart create error = %v", err)
	}
	if len(api.creates) != 1 {
		t.Fatalf("hidden late commit was replayed: creates=%d", len(api.creates))
	}

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Ingress) != 1 || len(api.creates) != 1 {
		t.Fatalf("late NLB recovery status=%#v creates=%d", status, len(api.creates))
	}
	assertNoStandardNLBFence(t, store, service)
}

func TestStandardNLBCreateFenceRecoversLateCommittedFloatingIPAfterRestart(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	providerForNames := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: providerForNames.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
		Targets: []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}},
	}}
	api := &lateStandardNLBAPI{
		fakeAPI:             base,
		hideFloatingIPLists: 6,
		floatingIPCreateErr: errors.New("transport timeout after floating IP commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}

	provider := newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("first ambiguous floating IP error = %v", err)
	}
	if api.floatingIPCreateCalls != 1 {
		t.Fatalf("floating IP creates = %d, want one", api.floatingIPCreateCalls)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateFloatingIP)

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "refusing a second create") {
		t.Fatalf("hidden post-restart floating IP error = %v", err)
	}
	if api.floatingIPCreateCalls != 1 {
		t.Fatalf("hidden floating IP was replayed: creates=%d", api.floatingIPCreateCalls)
	}

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" || api.floatingIPCreateCalls != 1 {
		t.Fatalf("late floating IP recovery status=%#v creates=%d", status, api.floatingIPCreateCalls)
	}
	assertNoStandardNLBFence(t, store, service)
}

func TestStandardNLBAssignmentFenceRecoversLateCommittedAssignmentAfterRestart(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
		Targets: []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}},
	}}
	base.floatingIPs = []inspace.FloatingIP{{
		Name: nameProvider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
		Type: "public", Enabled: true,
	}}
	api := &lateStandardNLBAPI{
		fakeAPI:             base,
		hideAssignmentLists: 3,
		assignFloatingIPErr: errors.New("transport timeout after floating IP assignment commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}

	provider := newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("first ambiguous assignment error = %v", err)
	}
	if api.assignFloatingIPCalls != 1 {
		t.Fatalf("floating IP assignment calls = %d, want one", api.assignFloatingIPCalls)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBAssignFloatingIP)

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "refusing a blind replay") {
		t.Fatalf("hidden post-restart assignment error = %v", err)
	}
	if api.assignFloatingIPCalls != 1 {
		t.Fatalf("hidden assignment was replayed: calls=%d", api.assignFloatingIPCalls)
	}

	provider = newStandardNLBProviderWithStore(t, api, store)
	setStandardNLBKubeNodes(provider, nodes...)
	status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Ingress) != 1 || status.Ingress[0].IP != "203.0.113.20" || api.assignFloatingIPCalls != 1 {
		t.Fatalf("late assignment recovery status=%#v calls=%d", status, api.assignFloatingIPCalls)
	}
	assertNoStandardNLBFence(t, store, service)
}

func TestStandardNLBAddFencesDoNotReplayCommittedHiddenMutation(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		prepare   func(*lateStandardNLBAPI, *fakeAPI, *Provider, *corev1.Service)
		calls     func(*fakeAPI) int
	}{
		{
			name: "target", operation: standardNLBAddTarget,
			prepare: func(api *lateStandardNLBAPI, base *fakeAPI, provider *Provider, service *corev1.Service) {
				base.lbs[0].ForwardingRules = serviceRules(service)
				api.hideTargetLists = 3
				api.addTargetErr = errors.New("transport timeout after target commit")
			},
			calls: func(base *fakeAPI) int { return len(base.addedTargets) },
		},
		{
			name: "rule", operation: standardNLBAddRule,
			prepare: func(api *lateStandardNLBAPI, base *fakeAPI, provider *Provider, service *corev1.Service) {
				base.lbs[0].Targets = []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}}
				api.hideRuleLists = 3
				api.addRuleErr = errors.New("transport timeout after rule commit")
			},
			calls: func(base *fakeAPI) int { return len(base.addedRules) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
				PrivateAddress: "10.0.0.50",
			}}
			base.floatingIPs = []inspace.FloatingIP{{
				Name: nameProvider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
				Type: "public", Enabled: true, AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
			}}
			api := &lateStandardNLBAPI{fakeAPI: base}
			test.prepare(api, base, nameProvider, service)
			store := newMemoryStandardNLBServiceStore()
			nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}

			provider := newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)
			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
				t.Fatalf("first committed mutation error = %v", err)
			}
			if test.calls(base) != 1 {
				t.Fatalf("mutation calls = %d, want one", test.calls(base))
			}
			assertIssuedStandardNLBFence(t, store, service, test.operation)

			provider = newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)
			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil || !strings.Contains(err.Error(), "refusing a blind replay") {
				t.Fatalf("hidden post-restart mutation error = %v", err)
			}
			if test.calls(base) != 1 {
				t.Fatalf("hidden committed mutation was replayed: calls=%d", test.calls(base))
			}

			provider = newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)
			status, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if len(status.Ingress) != 1 || test.calls(base) != 1 {
				t.Fatalf("late mutation recovery status=%#v calls=%d", status, test.calls(base))
			}
			assertNoStandardNLBFence(t, store, service)
		})
	}
}

func TestStandardNLBDeletionRetainsCleanupWhileIssuedCreateIsHidden(t *testing.T) {
	service := testService()
	api := &lateStandardNLBAPI{
		fakeAPI:               &fakeAPI{},
		hideLoadBalancerLists: 4,
		loadBalancerCreateErr: errors.New("transport timeout after NLB commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil {
		t.Fatal("expected ambiguous create")
	}
	service.Labels = nil
	service.Annotations = nil
	syncMemoryStandardNLBServiceIntent(t, store, service)

	provider = newStandardNLBProviderWithStore(t, api, store)
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil || !strings.Contains(err.Error(), "retaining the cleanup finalizer") {
		t.Fatalf("hidden-create cleanup error = %v", err)
	}
	if len(api.deletedLBs) != 0 {
		t.Fatalf("cleanup crossed unresolved create fence: deletes=%v", api.deletedLBs)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)

	provider = newStandardNLBProviderWithStore(t, api, store)
	requireStandardNLBConvergence(t, func() error {
		return provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service)
	})
	if len(api.deletedLBs) != 1 || api.deletedLBs[0] != testLBUUID {
		t.Fatalf("late visible NLB was not deleted exactly once: %v", api.deletedLBs)
	}
	assertNoStandardNLBFence(t, store, service)
}

func TestStandardNLBDeletionRequiresAuthoritativeAbsence(t *testing.T) {
	ctx := context.Background()
	readErr := errors.New("authoritative deletion readback unavailable")

	t.Run("load balancer", func(t *testing.T) {
		service := testService()
		service.Labels = nil
		service.Annotations = nil
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		base.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
		}}
		api := &lateStandardNLBAPI{
			fakeAPI:                base,
			failLoadBalancerListOn: 2,
			loadBalancerListErr:    readErr,
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		if err := provider.cleanupOwnedLoadBalancer(ctx, service, &base.lbs[0]); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("delete/readback result = %v", err)
		}
		if len(api.deletedLBs) != 1 || len(base.lbs) != 0 {
			t.Fatalf("delete state: calls=%v LBs=%#v", api.deletedLBs, base.lbs)
		}

		api.failLoadBalancerListOn = 0
		requireStandardNLBConvergence(t, func() error {
			return provider.EnsureLoadBalancerDeleted(ctx, "ignored", service)
		})
		if len(api.deletedLBs) != 1 {
			t.Fatalf("absent NLB delete replayed: %v", api.deletedLBs)
		}
	})

	t.Run("committed server error", func(t *testing.T) {
		service := testService()
		service.Labels = nil
		service.Annotations = nil
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		base.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
		}}
		api := &lateStandardNLBAPI{
			fakeAPI: base,
			deleteLoadBalancerErr: &inspace.APIError{
				StatusCode: 500, Method: "DELETE", Path: "/network/load_balancers/" + testLBUUID,
				Message: "committed but response lost", Retryable: true,
			},
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		if err := provider.cleanupOwnedLoadBalancer(ctx, service, &base.lbs[0]); !errors.Is(err, errStandardNLBRemovalPending) {
			t.Fatalf("committed delete error = %v, want durable pending absence proof", err)
		}
		requireStandardNLBConvergence(t, func() error {
			return provider.EnsureLoadBalancerDeleted(ctx, "ignored", service)
		})
		if len(api.deletedLBs) != 1 || len(base.lbs) != 0 {
			t.Fatalf("committed delete state: calls=%v LBs=%#v", api.deletedLBs, base.lbs)
		}
	})

	t.Run("floating IP unassign", func(t *testing.T) {
		service := testService()
		service.Labels = nil
		service.Annotations = nil
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		floatingIP := inspace.FloatingIP{
			Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
			BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer",
		}
		base.lbs = []inspace.LoadBalancer{{
			UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
			NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
		}}
		base.floatingIPs = []inspace.FloatingIP{floatingIP}
		api := &lateStandardNLBAPI{
			fakeAPI:              base,
			failFloatingIPListOn: 2,
			floatingIPListErr:    readErr,
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		if err := provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, testLBUUID, "10.0.0.50"); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("unassign/readback result = %v", err)
		}
		if len(api.unassignedIPs) != 1 || len(api.deletedIPs) != 0 {
			t.Fatalf("dependent delete crossed unassign readback failure: unassign=%v delete=%v", api.unassignedIPs, api.deletedIPs)
		}

		api.failFloatingIPListOn = 0
		requireStandardNLBConvergence(t, func() error {
			return provider.EnsureLoadBalancerDeleted(ctx, "ignored", service)
		})
		if len(api.unassignedIPs) != 1 || len(api.deletedIPs) != 1 {
			t.Fatalf("cleanup did not converge exactly once: unassign=%v delete=%v", api.unassignedIPs, api.deletedIPs)
		}
	})

	t.Run("floating IP delete", func(t *testing.T) {
		service := testService()
		service.Labels = nil
		service.Annotations = nil
		base := &fakeAPI{}
		nameProvider := newTestProvider(t, base)
		floatingIP := inspace.FloatingIP{
			Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
			BillingAccountID: 42, Type: "public", Enabled: true,
		}
		base.floatingIPs = []inspace.FloatingIP{floatingIP}
		api := &lateStandardNLBAPI{
			fakeAPI:              base,
			failFloatingIPListOn: 2,
			floatingIPListErr:    readErr,
		}
		provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
		if err := provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, "", ""); err == nil || !strings.Contains(err.Error(), readErr.Error()) {
			t.Fatalf("delete/readback result = %v", err)
		}
		if len(api.deletedIPs) != 1 || len(base.floatingIPs) != 0 {
			t.Fatalf("delete state: calls=%v FIPs=%#v", api.deletedIPs, base.floatingIPs)
		}

		api.failFloatingIPListOn = 0
		requireStandardNLBConvergence(t, func() error {
			return provider.EnsureLoadBalancerDeleted(ctx, "ignored", service)
		})
		if len(api.deletedIPs) != 1 {
			t.Fatalf("absent floating IP delete replayed: %v", api.deletedIPs)
		}
	})
}

func TestStandardNLBDeletionDoesNotDeleteNLBWhileIssuedFloatingIPCreateIsHidden(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
	}}
	api := &lateStandardNLBAPI{
		fakeAPI:             base,
		hideFloatingIPLists: 4,
		floatingIPCreateErr: errors.New("transport timeout after floating IP commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil {
		t.Fatal("expected ambiguous floating IP create")
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateFloatingIP)
	service.Labels = nil
	service.Annotations = nil
	syncMemoryStandardNLBServiceIntent(t, store, service)

	api.hideFloatingIPLists = 1
	provider = newStandardNLBProviderWithStore(t, api, store)
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil || !strings.Contains(err.Error(), "retaining the cleanup finalizer") {
		t.Fatalf("hidden floating-IP cleanup error = %v", err)
	}
	if len(api.deletedLBs) != 0 || len(api.deletedIPs) != 0 {
		t.Fatalf("cleanup crossed hidden floating-IP fence: deleteLB=%v deleteIP=%v", api.deletedLBs, api.deletedIPs)
	}

	provider = newStandardNLBProviderWithStore(t, api, store)
	requireStandardNLBConvergence(t, func() error {
		return provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service)
	})
	if len(api.deletedLBs) != 1 || len(api.deletedIPs) != 1 {
		t.Fatalf("late floating IP cleanup did not converge: deleteLB=%v deleteIP=%v", api.deletedLBs, api.deletedIPs)
	}
	assertNoStandardNLBFence(t, store, service)
}

func TestStandardNLBDeletionWaitsForIssuedFloatingIPAssignment(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		PrivateAddress: "10.0.0.50", ForwardingRules: serviceRules(service),
	}}
	base.floatingIPs = []inspace.FloatingIP{{
		Name: nameProvider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
		Type: "public", Enabled: true,
	}}
	api := &lateStandardNLBAPI{
		fakeAPI:             base,
		hideAssignmentLists: 1,
		assignFloatingIPErr: errors.New("transport timeout after floating IP assignment commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil {
		t.Fatal("expected ambiguous floating IP assignment")
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBAssignFloatingIP)
	service.Labels = nil
	service.Annotations = nil
	syncMemoryStandardNLBServiceIntent(t, store, service)

	api.hideAssignmentLists = 1
	provider = newStandardNLBProviderWithStore(t, api, store)
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil || !strings.Contains(err.Error(), "retaining the cleanup finalizer") {
		t.Fatalf("hidden assignment cleanup error = %v", err)
	}
	if len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 || len(api.deletedLBs) != 0 {
		t.Fatalf("cleanup crossed hidden assignment fence: unassign=%v deleteIP=%v deleteLB=%v", api.unassignedIPs, api.deletedIPs, api.deletedLBs)
	}

	provider = newStandardNLBProviderWithStore(t, api, store)
	requireStandardNLBConvergence(t, func() error {
		return provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service)
	})
	if len(api.unassignedIPs) != 1 || len(api.deletedIPs) != 1 || len(api.deletedLBs) != 1 {
		t.Fatalf("late assignment cleanup did not converge: unassign=%v deleteIP=%v deleteLB=%v", api.unassignedIPs, api.deletedIPs, api.deletedLBs)
	}
	assertNoStandardNLBFence(t, store, service)
}
