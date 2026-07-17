package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type splitViewStandardNLBAPI struct {
	*fakeAPI
	omitList        bool
	forceGetMissing bool
	transformGet    func(*inspace.LoadBalancer)
	transformList   func(*inspace.LoadBalancer)
}

func (a *splitViewStandardNLBAPI) GetLoadBalancer(
	ctx context.Context,
	location, uuid string,
) (*inspace.LoadBalancer, error) {
	if a.forceGetMissing {
		return nil, exactLoadBalancerNotFound(uuid)
	}
	item, err := a.fakeAPI.GetLoadBalancer(ctx, location, uuid)
	if err == nil && item != nil && a.transformGet != nil {
		a.transformGet(item)
	}
	return item, err
}

type exactTargetVMAPI struct {
	*fakeAPI
	getVM func(context.Context, string, string) (*inspace.VM, error)
}

func (a *exactTargetVMAPI) GetVM(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	if a.getVM != nil {
		return a.getVM(ctx, location, uuid)
	}
	return a.fakeAPI.GetVM(ctx, location, uuid)
}

func (a *splitViewStandardNLBAPI) ListLoadBalancers(
	ctx context.Context,
	location string,
) ([]inspace.LoadBalancer, error) {
	if a.omitList {
		return nil, nil
	}
	items, err := a.fakeAPI.ListLoadBalancers(ctx, location)
	if err != nil {
		return nil, err
	}
	if a.transformList != nil {
		for index := range items {
			a.transformList(&items[index])
		}
	}
	return items, nil
}

func TestStandardNLBWrongBillingAccountNeverAdoptedOrDeleted(t *testing.T) {
	service := testService()
	base := &fakeAPI{}
	provider := newTestProvider(t, base)
	base.lbs = []inspace.LoadBalancer{{
		UUID: testLBUUID, DisplayName: provider.loadBalancerName(service),
		NetworkUUID: testNetworkUUID, BillingAccountID: 43, PrivateAddress: "10.0.0.50",
	}}

	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil ||
		!strings.Contains(err.Error(), "billing account 43") {
		t.Fatalf("wrong-account adoption result = %v", err)
	}
	if len(base.creates) != 0 || len(base.addedTargets) != 0 || len(base.addedRules) != 0 || len(base.floatingIPs) != 0 {
		t.Fatalf("wrong-account NLB was adopted or mutated: creates=%d targets=%v rules=%v FIPs=%#v", len(base.creates), base.addedTargets, base.addedRules, base.floatingIPs)
	}
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil ||
		!strings.Contains(err.Error(), "billing account 43") {
		t.Fatalf("wrong-account deletion result = %v", err)
	}
	if len(base.deletedLBs) != 0 {
		t.Fatalf("wrong-account NLB was deleted: %v", base.deletedLBs)
	}
}

func TestStandardNLBHiddenCreateChangingBillingAccountFailsClosed(t *testing.T) {
	service := testService()
	api := &lateStandardNLBAPI{
		fakeAPI:               &fakeAPI{},
		hideLoadBalancerLists: 3,
		loadBalancerCreateErr: errors.New("transport timeout after commit"),
	}
	store := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil ||
		!strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("initial hidden create = %v", err)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)
	if len(api.lbs) != 1 || len(api.creates) != 1 {
		t.Fatalf("hidden create state: LBs=%#v creates=%d", api.lbs, len(api.creates))
	}
	api.lbs[0].BillingAccountID = 43

	provider = newStandardNLBProviderWithStore(t, api, store)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nil); err == nil ||
		!strings.Contains(err.Error(), "billing account 43") {
		t.Fatalf("wrong-account late adoption = %v", err)
	}
	if len(api.creates) != 1 {
		t.Fatalf("wrong-account hidden create replayed: %d", len(api.creates))
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)

	provider = newStandardNLBProviderWithStore(t, api, store)
	if err := provider.EnsureLoadBalancerDeleted(context.Background(), "ignored", service); err == nil ||
		!strings.Contains(err.Error(), "billing account 43") {
		t.Fatalf("wrong-account hidden-create deletion = %v", err)
	}
	if len(api.deletedLBs) != 0 {
		t.Fatalf("wrong-account hidden create was deleted: %v", api.deletedLBs)
	}
}

func TestStandardNLBCreateFenceRequiresExactInitialRulesTargetsAndRequestHash(t *testing.T) {
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	tests := []struct {
		name   string
		mutate func(*corev1.Service, *inspace.LoadBalancer)
		want   string
	}{
		{
			name: "forwarding rule drift",
			mutate: func(_ *corev1.Service, lb *inspace.LoadBalancer) {
				lb.ForwardingRules[0].TargetPort++
			},
			want: "exact forwarding rules",
		},
		{
			name: "target drift",
			mutate: func(_ *corev1.Service, lb *inspace.LoadBalancer) {
				lb.Targets = nil
			},
			want: "missing VM targets",
		},
		{
			name: "desired request changed",
			mutate: func(service *corev1.Service, _ *inspace.LoadBalancer) {
				service.Spec.Ports[0].NodePort++
			},
			want: "exact requested rules or targets changed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			api := &lateStandardNLBAPI{
				fakeAPI:               &fakeAPI{},
				hideLoadBalancerLists: 3,
				loadBalancerCreateErr: errors.New("transport timeout after commit"),
			}
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)
			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil ||
				!strings.Contains(err.Error(), "remains ambiguous") {
				t.Fatalf("initial hidden create = %v", err)
			}
			test.mutate(service, &api.lbs[0])

			provider = newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)
			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("drifted create adoption = %v, want %q", err, test.want)
			}
			if len(api.creates) != 1 || len(api.addedTargets) != 0 || len(api.addedRules) != 0 || len(api.removedTargets) != 0 || len(api.removedRules) != 0 {
				t.Fatalf("drifted create crossed fence: creates=%d addTargets=%v addRules=%v removeTargets=%v removeRules=%v", len(api.creates), api.addedTargets, api.addedRules, api.removedTargets, api.removedRules)
			}
			assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)
		})
	}
}

func TestStandardNLBCommittedCreateHTTPErrorRetainsFenceOnInitialPolicyDrift(t *testing.T) {
	serverErr := &inspace.APIError{
		StatusCode: 500, Method: "POST", Path: "/network/load_balancers",
		Message: "committed but response lost", Retryable: true,
	}
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	for _, test := range []struct {
		name   string
		mutate func(*inspace.LoadBalancer)
		want   string
	}{
		{
			name: "rule drift",
			mutate: func(lb *inspace.LoadBalancer) {
				lb.ForwardingRules[0].TargetPort++
			},
			want: "exact forwarding rules",
		},
		{
			name: "target drift",
			mutate: func(lb *inspace.LoadBalancer) {
				lb.Targets = nil
			},
			want: "missing VM targets",
		},
		{
			name: "duplicate observed rule",
			mutate: func(lb *inspace.LoadBalancer) {
				lb.ForwardingRules = append(lb.ForwardingRules, lb.ForwardingRules[0])
			},
			want: "duplicate forwarding rules",
		},
		{
			name: "duplicate observed target",
			mutate: func(lb *inspace.LoadBalancer) {
				lb.Targets = append(lb.Targets, lb.Targets[0])
			},
			want: "duplicate VM targets",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			api := &lateStandardNLBAPI{
				fakeAPI:                     &fakeAPI{},
				loadBalancerCreateErr:       serverErr,
				mutateCommittedLoadBalancer: test.mutate,
			}
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, nodes...)

			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("committed create with policy drift = %v, want %q", err, test.want)
			}
			assertIssuedStandardNLBFence(t, store, service, standardNLBCreateLoadBalancer)
			if len(api.creates) != 1 || len(api.addedTargets) != 0 || len(api.addedRules) != 0 ||
				len(api.floatingIPs) != 0 {
				t.Fatalf(
					"policy drift crossed create fence: creates=%d targets=%v rules=%v FIPs=%#v",
					len(api.creates), api.addedTargets, api.addedRules, api.floatingIPs,
				)
			}
		})
	}
}

func TestStandardNLBTargetVMRequiresExactCloudOwnershipBeforeMutation(t *testing.T) {
	readErr := errors.New("exact VM read unavailable")
	for _, test := range []struct {
		name  string
		getVM func(context.Context, string, string) (*inspace.VM, error)
		want  string
	}{
		{
			name: "read error",
			getVM: func(context.Context, string, string) (*inspace.VM, error) {
				return nil, readErr
			},
			want: readErr.Error(),
		},
		{
			name: "empty response",
			getVM: func(context.Context, string, string) (*inspace.VM, error) {
				return nil, nil
			},
			want: "identity does not match providerID",
		},
		{
			name: "UUID drift",
			getVM: func(context.Context, string, string) (*inspace.VM, error) {
				return &inspace.VM{UUID: testVMUUIDB, BillingAccountID: 42, NetworkUUID: testNetworkUUID}, nil
			},
			want: "identity does not match providerID",
		},
		{
			name: "billing account drift",
			getVM: func(_ context.Context, _ string, uuid string) (*inspace.VM, error) {
				return &inspace.VM{UUID: uuid, BillingAccountID: 43, NetworkUUID: testNetworkUUID}, nil
			},
			want: "belongs to billing account 43",
		},
		{
			name: "network drift",
			getVM: func(_ context.Context, _ string, uuid string) (*inspace.VM, error) {
				return &inspace.VM{UUID: uuid, BillingAccountID: 42, NetworkUUID: "99999999-1111-4222-8333-444444444444"}, nil
			},
			want: "belongs to network",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := &fakeAPI{}
			api := &exactTargetVMAPI{fakeAPI: base, getVM: test.getVM}
			provider := newStandardNLBProviderWithStore(t, api, newMemoryStandardNLBServiceStore())
			nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}

			if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", testService(), nodes); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("unowned target VM result = %v, want %q", err, test.want)
			}
			assertNoStandardNLBCloudWrites(t, base)
		})
	}

	t.Run("duplicate provider identity", func(t *testing.T) {
		base := &fakeAPI{}
		provider := newStandardNLBProviderWithStore(t, base, newMemoryStandardNLBServiceStore())
		nodes := []*corev1.Node{
			readyNode("worker-0", "inspace://bkk01/"+testVMUUID),
			readyNode("worker-1", "inspace://bkk01/"+testVMUUID),
		}
		if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", testService(), nodes); err == nil ||
			!strings.Contains(err.Error(), "multiple eligible Nodes claim exact InSpace VM") {
			t.Fatalf("duplicate target VM result = %v", err)
		}
		assertNoStandardNLBCloudWrites(t, base)
	})
}

func assertNoStandardNLBCloudWrites(t *testing.T, api *fakeAPI) {
	t.Helper()
	if len(api.creates) != 0 || len(api.deletedLBs) != 0 || len(api.addedTargets) != 0 ||
		len(api.removedTargets) != 0 || len(api.addedRules) != 0 || len(api.removedRules) != 0 ||
		len(api.floatingIPs) != 0 || len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 {
		t.Fatalf(
			"unexpected paid-NLB mutation: creates=%d deleteLB=%v addTargets=%v removeTargets=%v addRules=%v removeRules=%v FIPs=%#v unassign=%v deleteIPs=%v",
			len(api.creates), api.deletedLBs, api.addedTargets, api.removedTargets, api.addedRules,
			api.removedRules, api.floatingIPs, api.unassignedIPs, api.deletedIPs,
		)
	}
}

func TestStandardNLBExactDeleteReceiptRejectsListOmissionAndExactRename(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*splitViewStandardNLBAPI)
		want      string
	}{
		{
			name:      "list omission",
			configure: func(api *splitViewStandardNLBAPI) { api.omitList = true },
			want:      "missing from its deterministic-name list",
		},
		{
			name: "exact GET 404 with stale list presence",
			configure: func(api *splitViewStandardNLBAPI) {
				api.forceGetMissing = true
			},
			want: "returned 404 but remains visible in list readback",
		},
		{
			name: "exact GET renamed",
			configure: func(api *splitViewStandardNLBAPI) {
				api.transformGet = func(lb *inspace.LoadBalancer) { lb.DisplayName = "renamed-outside-controller" }
			},
			want: "lacks deterministic ownership name",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}}
			api := &splitViewStandardNLBAPI{fakeAPI: base}
			test.configure(api)
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			desired := validStandardNLBRemovalFenceForTest(t, standardNLBDeleteLoadBalancer)
			if _, _, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired); err != nil || !issue {
				t.Fatalf("issue delete receipt: issue=%t err=%v", issue, err)
			}

			provider = newStandardNLBProviderWithStore(t, api, store)
			if err := provider.resolveStandardNLBDeletionFence(context.Background(), service, nil, nil); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("split-view delete resolution = %v, want %q", err, test.want)
			}
			fence := readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.Phase != standardNLBPhaseIssued || fence.AbsenceObservedAt != "" {
				t.Fatalf("split-view exact presence changed delete receipt: %#v", fence)
			}
		})
	}
}

func TestStandardNLBAddRelationRecoveryUsesExactUUIDRead(t *testing.T) {
	rule := inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}
	for _, test := range []struct {
		name    string
		desired func(*testing.T) standardNLBMutationFence
		prepare func(*inspace.LoadBalancer)
		hide    func(*inspace.LoadBalancer)
		targets []string
		rules   []inspace.LoadBalancerRule
	}{
		{
			name: "add target",
			desired: func(t *testing.T) standardNLBMutationFence {
				payload := struct {
					LoadBalancerUUID string `json:"loadBalancerUUID"`
					TargetUUID       string `json:"targetUUID"`
				}{LoadBalancerUUID: testLBUUID, TargetUUID: testVMUUID}
				hash, err := standardNLBRequestHash(payload)
				if err != nil {
					t.Fatal(err)
				}
				return standardNLBMutationFence{
					Operation: standardNLBAddTarget, RequestHash: hash,
					LoadBalancerUUID: testLBUUID, TargetUUID: testVMUUID,
				}
			},
			prepare: func(lb *inspace.LoadBalancer) {
				lb.Targets = []inspace.LoadBalancerTarget{{TargetUUID: testVMUUID, TargetType: "vm"}}
			},
			hide:    func(lb *inspace.LoadBalancer) { lb.Targets = nil },
			targets: []string{testVMUUID},
		},
		{
			name: "add rule",
			desired: func(t *testing.T) standardNLBMutationFence {
				payload := struct {
					LoadBalancerUUID string                   `json:"loadBalancerUUID"`
					Rule             inspace.LoadBalancerRule `json:"rule"`
				}{LoadBalancerUUID: testLBUUID, Rule: rule}
				hash, err := standardNLBRequestHash(payload)
				if err != nil {
					t.Fatal(err)
				}
				return standardNLBMutationFence{
					Operation: standardNLBAddRule, RequestHash: hash, LoadBalancerUUID: testLBUUID,
					Protocol: rule.Protocol, SourcePort: rule.SourcePort, TargetPort: rule.TargetPort,
				}
			},
			prepare: func(lb *inspace.LoadBalancer) { lb.ForwardingRules = []inspace.LoadBalancerRule{rule} },
			hide:    func(lb *inspace.LoadBalancer) { lb.ForwardingRules = nil },
			rules:   []inspace.LoadBalancerRule{rule},
		},
	} {
		for _, view := range []struct {
			name      string
			hideExact bool
		}{
			{name: "list relationship omitted"},
			{name: "exact relationship omitted", hideExact: true},
		} {
			t.Run(test.name+"/"+view.name, func(t *testing.T) {
				service := testService()
				base := &fakeAPI{}
				nameProvider := newTestProvider(t, base)
				lb := inspace.LoadBalancer{
					UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
					NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
				}
				test.prepare(&lb)
				base.lbs = []inspace.LoadBalancer{lb}
				api := &splitViewStandardNLBAPI{fakeAPI: base}
				if view.hideExact {
					api.transformGet = test.hide
				} else {
					api.transformList = test.hide
				}
				store := newMemoryStandardNLBServiceStore()
				provider := newStandardNLBProviderWithStore(t, api, store)
				desired := test.desired(t)
				fence, raw, err := provider.stageStandardNLBMutation(context.Background(), service, desired)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := provider.issueStandardNLBMutation(context.Background(), service, fence, raw); err != nil {
					t.Fatal(err)
				}

				err = provider.resolvePendingStandardNLBAdd(
					context.Background(), service, &lb, test.targets, test.rules,
				)
				if view.hideExact {
					if err == nil || !strings.Contains(err.Error(), "omitted") {
						t.Fatalf("list-only additive evidence = %v, want omitted exact relationship", err)
					}
					assertIssuedStandardNLBFence(t, store, service, desired.Operation)
					return
				}
				if err != nil {
					t.Fatalf("exact additive evidence = %v", err)
				}
				assertNoStandardNLBFence(t, store, service)
			})
		}
	}
}

func TestStandardNLBFloatingIPRemovalRejectsRenamedExactAddressAfterCommittedHTTP500(t *testing.T) {
	ctx := context.Background()
	serverErr := &inspace.APIError{
		StatusCode: 500, Method: "DELETE", Path: "/network/floating_ips/203.0.113.20",
		Message: "committed but response lost", Retryable: true,
	}
	readErr := errors.New("authoritative floating IP readback unavailable")
	for _, test := range []struct {
		name      string
		assigned  bool
		operation string
		calls     func(*fakeAPI) int
	}{
		{
			name: "unassign", assigned: true, operation: standardNLBUnassignFloatingIP,
			calls: func(api *fakeAPI) int { return len(api.unassignedIPs) },
		},
		{
			name: "delete", operation: standardNLBDeleteFloatingIP,
			calls: func(api *fakeAPI) int { return len(api.deletedIPs) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			service.Labels = nil
			service.Annotations = nil
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			lb := &inspace.LoadBalancer{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}
			floatingIP := inspace.FloatingIP{
				Name: nameProvider.floatingIPName(service), Address: "203.0.113.20",
				BillingAccountID: 42, Type: "public", Enabled: true,
			}
			if test.assigned {
				floatingIP.AssignedTo = testLBUUID
				floatingIP.AssignedToResourceType = "load_balancer"
				floatingIP.AssignedToPrivateIP = lb.PrivateAddress
				base.lbs = []inspace.LoadBalancer{*lb}
			}
			base.floatingIPs = []inspace.FloatingIP{floatingIP}
			api := &ambiguousStandardNLBRemovalAPI{
				fakeAPI: base, readErr: readErr, mutationErr: serverErr,
			}
			store := newMemoryStandardNLBServiceStore()
			now := time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC)
			provider := newStandardNLBRemovalTestProvider(t, api, store, &now)

			err := provider.cleanupOwnedFloatingIP(ctx, service, &floatingIP, testLBUUID, lb.PrivateAddress)
			if err == nil || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), readErr.Error()) {
				t.Fatalf("committed floating IP removal = %v", err)
			}
			if test.calls(base) != 1 {
				t.Fatalf("floating IP mutation calls = %d, want one", test.calls(base))
			}
			assertIssuedStandardNLBFence(t, store, service, test.operation)

			// Whether unassignment retained the address or deletion briefly removed
			// it, an exact address that reappears under another name is positive
			// ownership drift. It must not become delete/unassign absence evidence.
			renamed := floatingIP
			renamed.Name = "renamed-outside-controller"
			if test.assigned {
				renamed.AssignedTo = ""
				renamed.AssignedToResourceType = ""
				renamed.AssignedToPrivateIP = ""
			}
			base.floatingIPs = []inspace.FloatingIP{renamed}
			provider = newStandardNLBRemovalTestProvider(t, api, store, &now)
			if err := provider.resolveStandardNLBDeletionFence(ctx, service, lb, &renamed); err == nil ||
				!strings.Contains(err.Error(), "lacks the expected Service ownership name") {
				t.Fatalf("renamed exact-address recovery = %v", err)
			}
			fence := readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.Phase != standardNLBPhaseIssued || fence.AbsenceObservedAt != "" {
				t.Fatalf("renamed exact address changed removal receipt: %#v", fence)
			}
			if test.calls(base) != 1 {
				t.Fatalf("renamed exact-address recovery replayed mutation: %d", test.calls(base))
			}
		})
	}
}

func TestStandardNLBRelationRecoveryUsesExactUUIDNotListRelationship(t *testing.T) {
	removedTarget := "99999999-1111-4222-8333-444444444444"
	ruleUUID := "77777777-1111-4222-8333-444444444444"
	for _, test := range []struct {
		name      string
		operation string
		prepare   func(*inspace.LoadBalancer)
		hideList  func(*inspace.LoadBalancer)
	}{
		{
			name: "remove target", operation: standardNLBRemoveTarget,
			prepare: func(lb *inspace.LoadBalancer) {
				lb.Targets = []inspace.LoadBalancerTarget{{TargetUUID: removedTarget, TargetType: "vm"}}
			},
			hideList: func(lb *inspace.LoadBalancer) { lb.Targets = nil },
		},
		{
			name: "remove rule", operation: standardNLBRemoveRule,
			prepare: func(lb *inspace.LoadBalancer) {
				lb.ForwardingRules = []inspace.LoadBalancerRule{{UUID: ruleUUID, Protocol: "TCP", SourcePort: 443, TargetPort: 30443}}
			},
			hideList: func(lb *inspace.LoadBalancer) { lb.ForwardingRules = nil },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			lb := inspace.LoadBalancer{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
			}
			test.prepare(&lb)
			base.lbs = []inspace.LoadBalancer{lb}
			api := &splitViewStandardNLBAPI{fakeAPI: base, transformList: test.hideList}
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			desired := validStandardNLBRemovalFenceForTest(t, test.operation)
			if test.operation == standardNLBRemoveTarget {
				desired.TargetUUID = removedTarget
			} else {
				desired.RuleUUID = ruleUUID
			}
			hash, err := standardNLBRemovalRequestHash(desired)
			if err != nil {
				t.Fatal(err)
			}
			desired.RequestHash = hash
			if _, _, issue, err := provider.issueStandardNLBRemoval(context.Background(), service, desired); err != nil || !issue {
				t.Fatalf("issue relation removal: issue=%t err=%v", issue, err)
			}

			provider = newStandardNLBProviderWithStore(t, api, store)
			if err := provider.resolvePendingStandardNLBAdd(context.Background(), service, &lb, nil, nil); !errors.Is(err, errStandardNLBRemovalPending) {
				t.Fatalf("list-omitted exact relation = %v, want pending", err)
			}
			fence := readStandardNLBRemovalTestFence(t, store, service)
			if fence == nil || fence.AbsenceObservedAt != "" {
				t.Fatalf("list-only relationship omission became negative evidence: %#v", fence)
			}
		})
	}
}

var _ API = (*splitViewStandardNLBAPI)(nil)
var _ API = (*exactTargetVMAPI)(nil)
