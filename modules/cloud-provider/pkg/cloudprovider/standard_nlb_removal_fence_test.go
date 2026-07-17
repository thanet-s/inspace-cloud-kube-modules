package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type ambiguousStandardNLBRemovalAPI struct {
	*fakeAPI

	failNextLoadBalancerRead bool
	failNextFloatingIPRead   bool
	readErr                  error
	mutationErr              error
}

func (a *ambiguousStandardNLBRemovalAPI) ListLoadBalancers(ctx context.Context, location string) ([]inspace.LoadBalancer, error) {
	if a.failNextLoadBalancerRead {
		a.failNextLoadBalancerRead = false
		return nil, a.readErr
	}
	return a.fakeAPI.ListLoadBalancers(ctx, location)
}

func (a *ambiguousStandardNLBRemovalAPI) ListFloatingIPs(
	ctx context.Context,
	location string,
	filters *inspace.FloatingIPFilters,
) ([]inspace.FloatingIP, error) {
	if a.failNextFloatingIPRead {
		a.failNextFloatingIPRead = false
		return nil, a.readErr
	}
	return a.fakeAPI.ListFloatingIPs(ctx, location, filters)
}

func (a *ambiguousStandardNLBRemovalAPI) DeleteLoadBalancer(ctx context.Context, location, uuid string) error {
	if err := a.fakeAPI.DeleteLoadBalancer(ctx, location, uuid); err != nil {
		return err
	}
	a.failNextLoadBalancerRead = true
	return a.mutationErr
}

func (a *ambiguousStandardNLBRemovalAPI) UnassignFloatingIP(
	ctx context.Context,
	location, address string,
) (*inspace.FloatingIP, error) {
	item, err := a.fakeAPI.UnassignFloatingIP(ctx, location, address)
	if err != nil {
		return item, err
	}
	a.failNextFloatingIPRead = true
	return item, a.mutationErr
}

func (a *ambiguousStandardNLBRemovalAPI) DeleteFloatingIP(ctx context.Context, location, address string) error {
	if err := a.fakeAPI.DeleteFloatingIP(ctx, location, address); err != nil {
		return err
	}
	a.failNextFloatingIPRead = true
	return a.mutationErr
}

func (a *ambiguousStandardNLBRemovalAPI) RemoveLoadBalancerTarget(
	ctx context.Context,
	location, loadBalancerUUID, targetUUID string,
) error {
	if err := a.fakeAPI.RemoveLoadBalancerTarget(ctx, location, loadBalancerUUID, targetUUID); err != nil {
		return err
	}
	a.failNextLoadBalancerRead = true
	return a.mutationErr
}

func (a *ambiguousStandardNLBRemovalAPI) RemoveLoadBalancerRule(
	ctx context.Context,
	location, loadBalancerUUID, ruleUUID string,
) error {
	if err := a.fakeAPI.RemoveLoadBalancerRule(ctx, location, loadBalancerUUID, ruleUUID); err != nil {
		return err
	}
	a.failNextLoadBalancerRead = true
	return a.mutationErr
}

func cloneStandardNLBForRemovalTest(item inspace.LoadBalancer) *inspace.LoadBalancer {
	copy := item
	copy.Targets = append([]inspace.LoadBalancerTarget(nil), item.Targets...)
	copy.ForwardingRules = append([]inspace.LoadBalancerRule(nil), item.ForwardingRules...)
	return &copy
}

func readStandardNLBRemovalTestFence(
	t *testing.T,
	store standardNLBServiceStore,
	service *corev1.Service,
) *standardNLBMutationFence {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := parseStandardNLBFence(current.Annotations[annotationStandardNLBMutation])
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func newStandardNLBRemovalTestProvider(
	t *testing.T,
	api API,
	store standardNLBServiceStore,
	now *time.Time,
) *Provider {
	t.Helper()
	provider := newStandardNLBProviderWithStore(t, api, store)
	provider.standardNLBAbsentDelay = 30 * time.Second
	provider.standardNLBNow = func() time.Time { return *now }
	return provider
}

func TestStandardNLBRemovalCommittedHTTP500ReadFailureRestartAndTransientVisibility(t *testing.T) {
	ctx := context.Background()
	serverErr := &inspace.APIError{
		StatusCode: 500, Method: "DELETE", Path: "/committed-removal",
		Message: "committed but response lost", Retryable: true,
	}
	readErr := errors.New("authoritative removal readback unavailable")
	ruleUUID := "77777777-1111-4222-8333-444444444444"
	removedTargetUUID := "99999999-1111-4222-8333-444444444444"

	type removalCase struct {
		name string
		op   string
		new  func(*testing.T) (
			*ambiguousStandardNLBRemovalAPI,
			*corev1.Service,
			func(*Provider) error,
			func(*Provider, bool) error,
			func() int,
			func() int,
		)
	}

	cases := []removalCase{
		{
			name: "load balancer delete", op: standardNLBDeleteLoadBalancer,
			new: func(t *testing.T) (*ambiguousStandardNLBRemovalAPI, *corev1.Service, func(*Provider) error, func(*Provider, bool) error, func() int, func() int) {
				service := testService()
				service.Spec.Type = corev1.ServiceTypeClusterIP
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				base.lbs = []inspace.LoadBalancer{{
					UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
					NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
				}}
				stale := cloneStandardNLBForRemovalTest(base.lbs[0])
				api := &ambiguousStandardNLBRemovalAPI{
					fakeAPI: base, readErr: readErr, mutationErr: serverErr,
				}
				return api, service,
					func(provider *Provider) error { return provider.cleanupOwnedLoadBalancer(ctx, service, stale) },
					func(provider *Provider, visible bool) error {
						var current *inspace.LoadBalancer
						if visible {
							current = stale
							base.lbs = []inspace.LoadBalancer{*cloneStandardNLBForRemovalTest(*stale)}
						} else {
							base.lbs = nil
						}
						return provider.resolveStandardNLBDeletionFence(ctx, service, current, nil)
					},
					func() int { return len(base.deletedLBs) },
					func() int { return 0 }
			},
		},
		{
			name: "floating IP unassign", op: standardNLBUnassignFloatingIP,
			new: func(t *testing.T) (*ambiguousStandardNLBRemovalAPI, *corev1.Service, func(*Provider) error, func(*Provider, bool) error, func() int, func() int) {
				service := testService()
				service.Spec.Type = corev1.ServiceTypeClusterIP
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				lb := &inspace.LoadBalancer{
					UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
					NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
				}
				base.lbs = []inspace.LoadBalancer{*lb}
				assigned := inspace.FloatingIP{
					Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
					BillingAccountID: 42, Type: "public", Enabled: true,
					AssignedTo: testLBUUID, AssignedToResourceType: "load_balancer", AssignedToPrivateIP: "10.0.0.50",
				}
				base.floatingIPs = []inspace.FloatingIP{assigned}
				unassigned := assigned
				unassigned.AssignedTo = ""
				unassigned.AssignedToResourceType = ""
				unassigned.AssignedToPrivateIP = ""
				api := &ambiguousStandardNLBRemovalAPI{
					fakeAPI: base, readErr: readErr, mutationErr: serverErr,
				}
				return api, service,
					func(provider *Provider) error {
						return provider.cleanupOwnedFloatingIP(ctx, service, &assigned, testLBUUID, "10.0.0.50")
					},
					func(provider *Provider, visible bool) error {
						current := &unassigned
						if visible {
							current = &assigned
							base.floatingIPs = []inspace.FloatingIP{assigned}
						} else {
							base.floatingIPs = []inspace.FloatingIP{unassigned}
						}
						return provider.resolveStandardNLBDeletionFence(ctx, service, lb, current)
					},
					func() int { return len(base.unassignedIPs) },
					func() int { return len(base.deletedIPs) }
			},
		},
		{
			name: "floating IP delete", op: standardNLBDeleteFloatingIP,
			new: func(t *testing.T) (*ambiguousStandardNLBRemovalAPI, *corev1.Service, func(*Provider) error, func(*Provider, bool) error, func() int, func() int) {
				service := testService()
				service.Spec.Type = corev1.ServiceTypeClusterIP
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				floatingIP := inspace.FloatingIP{
					Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
					BillingAccountID: 42, Type: "public", Enabled: true,
				}
				base.floatingIPs = []inspace.FloatingIP{floatingIP}
				api := &ambiguousStandardNLBRemovalAPI{
					fakeAPI: base, readErr: readErr, mutationErr: serverErr,
				}
				return api, service,
					func(provider *Provider) error {
						return provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, "", "")
					},
					func(provider *Provider, visible bool) error {
						var current *inspace.FloatingIP
						if visible {
							current = &floatingIP
							base.floatingIPs = []inspace.FloatingIP{floatingIP}
						} else {
							base.floatingIPs = nil
						}
						return provider.resolveStandardNLBDeletionFence(ctx, service, nil, current)
					},
					func() int { return len(base.deletedIPs) },
					func() int { return len(base.deletedLBs) }
			},
		},
		{
			name: "target remove", op: standardNLBRemoveTarget,
			new: func(t *testing.T) (*ambiguousStandardNLBRemovalAPI, *corev1.Service, func(*Provider) error, func(*Provider, bool) error, func() int, func() int) {
				service := testService()
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				base.lbs = []inspace.LoadBalancer{{
					UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
					NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
					Targets: []inspace.LoadBalancerTarget{{TargetUUID: removedTargetUUID, TargetType: "vm"}},
				}}
				stale := cloneStandardNLBForRemovalTest(base.lbs[0])
				absent := cloneStandardNLBForRemovalTest(base.lbs[0])
				absent.Targets = nil
				api := &ambiguousStandardNLBRemovalAPI{
					fakeAPI: base, readErr: readErr, mutationErr: serverErr,
				}
				return api, service,
					func(provider *Provider) error {
						_, err := provider.removeStandardNLBTarget(ctx, service, stale, removedTargetUUID)
						return err
					},
					func(provider *Provider, visible bool) error {
						current := absent
						if visible {
							current = stale
							base.lbs = []inspace.LoadBalancer{*cloneStandardNLBForRemovalTest(*stale)}
						} else {
							base.lbs = []inspace.LoadBalancer{*cloneStandardNLBForRemovalTest(*absent)}
						}
						return provider.resolvePendingStandardNLBAdd(ctx, service, current, nil, nil)
					},
					func() int { return len(base.removedTargets) },
					func() int { return len(base.addedTargets) }
			},
		},
		{
			name: "rule remove", op: standardNLBRemoveRule,
			new: func(t *testing.T) (*ambiguousStandardNLBRemovalAPI, *corev1.Service, func(*Provider) error, func(*Provider, bool) error, func() int, func() int) {
				service := testService()
				service.Spec.Ports[0].Port = 8443
				service.Spec.Ports[0].NodePort = 32443
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				base.lbs = []inspace.LoadBalancer{{
					UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
					NetworkUUID: testNetworkUUID, PrivateAddress: "10.0.0.50",
					ForwardingRules: []inspace.LoadBalancerRule{{
						UUID: ruleUUID, Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
					}},
				}}
				stale := cloneStandardNLBForRemovalTest(base.lbs[0])
				absent := cloneStandardNLBForRemovalTest(base.lbs[0])
				absent.ForwardingRules = nil
				api := &ambiguousStandardNLBRemovalAPI{
					fakeAPI: base, readErr: readErr, mutationErr: serverErr,
				}
				return api, service,
					func(provider *Provider) error {
						_, err := provider.removeStandardNLBRule(ctx, service, stale, ruleUUID)
						return err
					},
					func(provider *Provider, visible bool) error {
						current := absent
						if visible {
							current = stale
							base.lbs = []inspace.LoadBalancer{*cloneStandardNLBForRemovalTest(*stale)}
						} else {
							base.lbs = []inspace.LoadBalancer{*cloneStandardNLBForRemovalTest(*absent)}
						}
						return provider.resolvePendingStandardNLBAdd(ctx, service, current, nil, nil)
					},
					func() int { return len(base.removedRules) },
					func() int { return len(base.addedRules) }
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			api, service, dispatch, resolve, mutationCalls, dependentCalls := test.new(t)
			store := newMemoryStandardNLBServiceStore()
			now := time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC)
			provider := newStandardNLBRemovalTestProvider(t, api, store, &now)

			err := dispatch(provider)
			if err == nil || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), readErr.Error()) {
				t.Fatalf("committed HTTP 500/readback failure = %v", err)
			}
			if mutationCalls() != 1 || dependentCalls() != 0 {
				t.Fatalf("initial calls mutation=%d dependent=%d", mutationCalls(), dependentCalls())
			}
			fence := readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.Version != standardNLBMutationVersion || fence.Operation != test.op ||
				fence.Phase != standardNLBPhaseIssued || fence.AbsenceObservedAt != "" {
				t.Fatalf("issued removal fence = %#v", fence)
			}

			// A reconstructed provider may see the old relation again. It must
			// remain read-only and retain the issued receipt.
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := resolve(provider, true); !errors.Is(err, errStandardNLBRemovalPending) {
				t.Fatalf("stale visible restart = %v, want pending", err)
			}
			if mutationCalls() != 1 || dependentCalls() != 0 {
				t.Fatalf("stale restart calls mutation=%d dependent=%d", mutationCalls(), dependentCalls())
			}

			// First exact absence is durable but not terminal.
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := resolve(provider, false); !errors.Is(err, errStandardNLBRemovalPending) {
				t.Fatalf("first absence = %v, want pending", err)
			}
			fence = readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.AbsenceObservedAt == "" {
				t.Fatalf("first absence was not persisted: %#v", fence)
			}

			// Transient reappearance clears only negative evidence. It may not
			// clear the issued receipt or authorize a second mutation.
			now = now.Add(15 * time.Second)
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := resolve(provider, true); !errors.Is(err, errStandardNLBRemovalPending) {
				t.Fatalf("transient reappearance = %v, want pending", err)
			}
			fence = readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.Phase != standardNLBPhaseIssued || fence.AbsenceObservedAt != "" {
				t.Fatalf("reappearance changed more than negative evidence: %#v", fence)
			}

			// The new absence interval starts from zero, survives another
			// reconstruction, and clears only after the full delay.
			now = now.Add(5 * time.Second)
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := resolve(provider, false); !errors.Is(err, errStandardNLBRemovalPending) {
				t.Fatalf("new first absence = %v, want pending", err)
			}
			now = now.Add(31 * time.Second)
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := resolve(provider, false); err != nil {
				t.Fatalf("terminal absence proof = %v", err)
			}
			assertNoStandardNLBFence(t, store, service)
			if mutationCalls() != 1 || dependentCalls() != 0 {
				t.Fatalf("terminal proof calls mutation=%d dependent=%d", mutationCalls(), dependentCalls())
			}
		})
	}
}

func validStandardNLBRemovalFenceForTest(t *testing.T, operation string) standardNLBMutationFence {
	t.Helper()
	fence := standardNLBMutationFence{
		Version: standardNLBMutationVersion, Operation: operation, Phase: standardNLBPhaseIntent,
	}
	switch operation {
	case standardNLBUnassignFloatingIP:
		fence.ResourceName = "203.0.113.20"
		fence.LoadBalancerUUID = testLBUUID
	case standardNLBDeleteFloatingIP:
		fence.ResourceName = "203.0.113.20"
	case standardNLBRemoveTarget:
		fence.LoadBalancerUUID = testLBUUID
		fence.TargetUUID = testVMUUID
	case standardNLBRemoveRule:
		fence.LoadBalancerUUID = testLBUUID
		fence.RuleUUID = "77777777-1111-4222-8333-444444444444"
	case standardNLBDeleteLoadBalancer:
		fence.LoadBalancerUUID = testLBUUID
	default:
		t.Fatalf("unknown removal operation %q", operation)
	}
	requestHash, err := standardNLBRemovalRequestHash(fence)
	if err != nil {
		t.Fatal(err)
	}
	fence.RequestHash = requestHash
	return fence
}

func TestStandardNLBRemovalConcurrentProvidersAuthorizeOneDispatch(t *testing.T) {
	operations := []string{
		standardNLBDeleteLoadBalancer,
		standardNLBUnassignFloatingIP,
		standardNLBDeleteFloatingIP,
		standardNLBRemoveTarget,
		standardNLBRemoveRule,
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			service := testService()
			store := newMemoryStandardNLBServiceStore()
			desired := validStandardNLBRemovalFenceForTest(t, operation)
			providers := make([]*Provider, 32)
			for index := range providers {
				providers[index] = newStandardNLBProviderWithStore(t, &fakeAPI{}, store)
			}

			start := make(chan struct{})
			var wg sync.WaitGroup
			var dispatches atomic.Int32
			var unexpected atomic.Int32
			for _, provider := range providers {
				wg.Add(1)
				go func(provider *Provider) {
					defer wg.Done()
					<-start
					_, _, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired)
					if issue {
						dispatches.Add(1)
					}
					if err != nil && !strings.Contains(err.Error(), "concurrent") &&
						!strings.Contains(err.Error(), "resourceVersion conflict") &&
						!strings.Contains(err.Error(), "readback did not match") {
						unexpected.Add(1)
					}
				}(provider)
			}
			close(start)
			wg.Wait()

			if got := dispatches.Load(); got != 1 {
				t.Fatalf("authorized dispatches = %d, want exactly one", got)
			}
			if got := unexpected.Load(); got != 0 {
				t.Fatalf("unexpected concurrent errors = %d", got)
			}
			fence := readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.Operation != operation || fence.Phase != standardNLBPhaseIssued {
				t.Fatalf("final concurrent fence = %#v", fence)
			}
		})
	}
}

func TestStandardNLBRemovalFenceRejectsDriftAndUnknownState(t *testing.T) {
	valid := validStandardNLBRemovalFenceForTest(t, standardNLBDeleteLoadBalancer)
	drifted := valid
	drifted.RequestHash = strings.Repeat("a", 64)
	driftedRaw, err := json.Marshal(drifted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseStandardNLBFence(string(driftedRaw)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("drifted request hash was accepted: %v", err)
	}

	validRaw, err := encodeStandardNLBFence(&valid)
	if err != nil {
		t.Fatal(err)
	}
	unknownRaw := strings.TrimSuffix(validRaw, "}") + `,"unexpected":"state"}`
	if _, err := parseStandardNLBFence(unknownRaw); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown receipt state was accepted: %v", err)
	}

	legacyRemoval := valid
	legacyRemoval.Version = standardNLBLegacyMutationVersion
	legacyRaw, err := json.Marshal(legacyRemoval)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseStandardNLBFence(string(legacyRaw)); err == nil || !strings.Contains(err.Error(), "cannot describe removal") {
		t.Fatalf("legacy removal receipt was accepted: %v", err)
	}

	// Prove malformed durable state fails before a cloud deletion, not merely
	// when the parsing helper is invoked directly.
	service := testService()
	store := newMemoryStandardNLBServiceStore()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	current.Annotations[annotationStandardNLBMutation] = string(driftedRaw)
	if _, err := store.UpdateExact(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	lb := &inspace.LoadBalancer{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
		NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
	}
	base.lbs = []inspace.LoadBalancer{*lb}
	provider := newStandardNLBProviderWithStore(t, base, store)
	if err := provider.cleanupOwnedLoadBalancer(context.Background(), service, lb); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("malformed durable cleanup result = %v", err)
	}
	if len(base.deletedLBs) != 0 {
		t.Fatalf("malformed receipt authorized cloud deletion: %v", base.deletedLBs)
	}
}

func TestStandardNLBLegacyV1AdditiveReceiptsStillDecode(t *testing.T) {
	issuedAt := time.Date(2026, 7, 16, 1, 2, 3, 0, time.UTC).Format(time.RFC3339Nano)
	tests := []standardNLBMutationFence{
		{Operation: standardNLBCreateLoadBalancer, ResourceName: "k8s-test-service"},
		{Operation: standardNLBCreateFloatingIP, ResourceName: "k8s-test-service-ip"},
		{Operation: standardNLBAssignFloatingIP, ResourceName: "203.0.113.20", LoadBalancerUUID: testLBUUID},
		{Operation: standardNLBAddTarget, LoadBalancerUUID: testLBUUID, TargetUUID: testVMUUID},
		{Operation: standardNLBAddRule, LoadBalancerUUID: testLBUUID, Protocol: "TCP", SourcePort: 443, TargetPort: 30443},
	}
	for _, test := range tests {
		t.Run(test.Operation, func(t *testing.T) {
			test.Version = standardNLBLegacyMutationVersion
			test.Phase = standardNLBPhaseIssued
			test.IssuedAt = issuedAt
			test.RequestHash = strings.Repeat("b", 64)
			raw, err := json.Marshal(test)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := parseStandardNLBFence(string(raw))
			if err != nil {
				t.Fatalf("legacy additive receipt did not decode: %v\n%s", err, raw)
			}
			if decoded.Version != standardNLBLegacyMutationVersion || decoded.Operation != test.Operation || decoded.Phase != standardNLBPhaseIssued {
				t.Fatalf("decoded legacy additive receipt = %#v", decoded)
			}
		})
	}
}

func TestStandardNLBUnassignAbsenceRequiresCleanRelationshipMetadata(t *testing.T) {
	service := testService()
	store := newMemoryStandardNLBServiceStore()
	desired := validStandardNLBRemovalFenceForTest(t, standardNLBUnassignFloatingIP)
	base := &fakeAPI{}
	nameProvider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service), NetworkUUID: testNetworkUUID,
		BillingAccountID: 42, PrivateAddress: "10.0.0.50",
	}}
	provider := newStandardNLBProviderWithStore(t, base, store)
	fence, raw, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired)
	if err != nil || !issue || fence.Phase != standardNLBPhaseIssued || raw == "" {
		t.Fatalf("issue unassign fence: fence=%#v issue=%t raw=%q err=%v", fence, issue, raw, err)
	}

	lb := &inspace.LoadBalancer{UUID: testLBUUID, PrivateAddress: "10.0.0.50"}
	drifted := &inspace.FloatingIP{
		Name: nameProvider.floatingIPName(service), Address: "203.0.113.20", BillingAccountID: 42,
		Type: "public", Enabled: true, AssignedToResourceType: "load_balancer",
	}
	base.floatingIPs = []inspace.FloatingIP{*drifted}
	if err := provider.resolveStandardNLBDeletionFence(context.Background(), service, lb, drifted); err == nil ||
		!strings.Contains(err.Error(), "residual") {
		t.Fatalf("residual unassignment metadata was accepted: %v", err)
	}
	stillIssued := readStandardNLBRemovalTestFence(t, store, service)
	if stillIssued == nil || stillIssued.Phase != standardNLBPhaseIssued || stillIssued.AbsenceObservedAt != "" {
		t.Fatalf("invalid negative observation changed fence: %#v", stillIssued)
	}
}

var _ API = (*ambiguousStandardNLBRemovalAPI)(nil)
