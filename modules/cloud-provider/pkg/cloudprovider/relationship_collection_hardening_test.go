package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type omittedExactStandardNLBRelationshipAPI struct {
	*fakeAPI
	omitTargets bool
	omitRules   bool
}

func (a *omittedExactStandardNLBRelationshipAPI) GetLoadBalancer(
	ctx context.Context,
	location, uuid string,
) (*inspace.LoadBalancer, error) {
	lb, err := a.fakeAPI.GetLoadBalancer(ctx, location, uuid)
	if err != nil || lb == nil {
		return lb, err
	}
	if a.omitTargets {
		lb.Targets = nil
	}
	if a.omitRules {
		lb.ForwardingRules = nil
	}
	return lb, nil
}

func TestStandardNLBExactRelationshipOmissionBlocksMutationBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name      string
		configure func(*omittedExactStandardNLBRelationshipAPI)
		mutate    func(*Provider, *corev1.Service, *inspace.LoadBalancer) error
		calls     func(*fakeAPI) int
		want      string
	}{
		{
			name: "targets",
			configure: func(api *omittedExactStandardNLBRelationshipAPI) {
				api.omitTargets = true
			},
			mutate: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				_, err := provider.addStandardNLBTarget(ctx, service, lb, testVMUUID)
				return err
			},
			calls: func(api *fakeAPI) int { return len(api.addedTargets) },
			want:  "omitted targets",
		},
		{
			name: "forwarding rules",
			configure: func(api *omittedExactStandardNLBRelationshipAPI) {
				api.omitRules = true
			},
			mutate: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				_, err := provider.addStandardNLBRule(ctx, service, lb, inspace.LoadBalancerRule{
					Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
				})
				return err
			},
			calls: func(api *fakeAPI) int { return len(api.addedRules) },
			want:  "omitted forwarding_rules",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
				ForwardingRules: []inspace.LoadBalancerRule{}, Targets: []inspace.LoadBalancerTarget{},
			}}
			api := &omittedExactStandardNLBRelationshipAPI{fakeAPI: base}
			test.configure(api)
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, api, store)
			setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))

			err := test.mutate(provider, service, &base.lbs[0])
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("omitted relationship mutation error = %v", err)
			}
			if calls := test.calls(base); calls != 0 {
				t.Fatalf("omitted relationship crossed cloud boundary %d time(s)", calls)
			}
			assertNoStandardNLBFence(t, store, service)
		})
	}
}

func TestStandardNLBIssuedFenceSurvivesOmittedExactRelationshipReadback(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name      string
		operation string
		mutate    func(*Provider, *corev1.Service, *inspace.LoadBalancer) error
		resolve   func(*Provider, *corev1.Service, *inspace.LoadBalancer) error
		configure func(*lateStandardNLBAPI)
		omit      func(*omittedExactStandardNLBRelationshipAPI)
		calls     func(*fakeAPI) int
		want      string
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
			configure: func(api *lateStandardNLBAPI) {
				api.addTargetErr = &inspace.APIError{StatusCode: 500, Method: "POST", Message: "response lost", Retryable: true}
			},
			omit:  func(api *omittedExactStandardNLBRelationshipAPI) { api.omitTargets = true },
			calls: func(api *fakeAPI) int { return len(api.addedTargets) },
			want:  "omitted targets",
		},
		{
			name: "rule add", operation: standardNLBAddRule,
			mutate: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				_, err := provider.addStandardNLBRule(ctx, service, lb, inspace.LoadBalancerRule{
					Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
				})
				return err
			},
			resolve: func(provider *Provider, service *corev1.Service, lb *inspace.LoadBalancer) error {
				return provider.resolvePendingStandardNLBAdd(
					ctx,
					service,
					lb,
					nil,
					[]inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}},
				)
			},
			configure: func(api *lateStandardNLBAPI) {
				api.addRuleErr = &inspace.APIError{StatusCode: 500, Method: "POST", Message: "response lost", Retryable: true}
			},
			omit:  func(api *omittedExactStandardNLBRelationshipAPI) { api.omitRules = true },
			calls: func(api *fakeAPI) int { return len(api.addedRules) },
			want:  "omitted forwarding_rules",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService()
			base := &fakeAPI{}
			nameProvider := newTestProvider(t, base)
			base.lbs = []inspace.LoadBalancer{{
				UUID: testLBUUID, DisplayName: nameProvider.loadBalancerName(service),
				NetworkUUID: testNetworkUUID, BillingAccountID: 42, PrivateAddress: "10.0.0.50",
				ForwardingRules: []inspace.LoadBalancerRule{}, Targets: []inspace.LoadBalancerTarget{},
			}}
			issuingAPI := &lateStandardNLBAPI{
				fakeAPI: base, failLoadBalancerListOn: 2,
				loadBalancerListErr: errors.New("authoritative readback unavailable"),
			}
			test.configure(issuingAPI)
			store := newMemoryStandardNLBServiceStore()
			provider := newStandardNLBProviderWithStore(t, issuingAPI, store)
			setStandardNLBKubeNodes(provider, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))

			if err := test.mutate(provider, service, &base.lbs[0]); err == nil {
				t.Fatal("ambiguous mutation unexpectedly converged")
			}
			assertIssuedStandardNLBFence(t, store, service, test.operation)
			if calls := test.calls(base); calls != 1 {
				t.Fatalf("initial mutation calls = %d, want one", calls)
			}

			omittedAPI := &omittedExactStandardNLBRelationshipAPI{fakeAPI: base}
			test.omit(omittedAPI)
			restarted := newStandardNLBProviderWithStore(t, omittedAPI, store)
			setStandardNLBKubeNodes(restarted, readyNode("worker-a", "inspace://bkk01/"+testVMUUID))
			err := test.resolve(restarted, service, &base.lbs[0])
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("omitted relationship readback error = %v", err)
			}
			assertIssuedStandardNLBFence(t, store, service, test.operation)
			if calls := test.calls(base); calls != 1 {
				t.Fatalf("omitted relationship replayed mutation: calls=%d", calls)
			}
		})
	}
}

type omittedFirewallRelationshipAPI struct {
	*fakeAPI
	omit            bool
	assignCalls     int
	omitAfterAssign bool
}

func (a *omittedFirewallRelationshipAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil || !a.omit {
		return items, err
	}
	for index := range items {
		if items[index].UUID == testFirewallRelationFirewallUUID {
			items[index].ResourcesAssigned = nil
		}
	}
	return items, nil
}

func (a *omittedFirewallRelationshipAPI) AssignFirewallToVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.assignCalls++
	if err := a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID); err != nil {
		return err
	}
	if a.omitAfterAssign {
		a.omit = true
	}
	return &inspace.APIError{
		StatusCode: 500, Method: "POST", Path: "/firewall/vms",
		Message: "committed response lost", Retryable: true,
	}
}

func TestFirewallRelationshipOmissionBlocksDispatchAndRetainsIssuedReceipt(t *testing.T) {
	ctx := context.Background()
	newController := func(t *testing.T, api API, service *corev1.Service) *nodeLoadBalancerController {
		t.Helper()
		provider := newTestProvider(t, api)
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		return &nodeLoadBalancerController{provider: provider}
	}
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}

	t.Run("pre-dispatch omission", func(t *testing.T) {
		service := nodeLoadBalancerTestService("relation-omitted-pre", "relation-omitted-pre-uid", corev1.ProtocolTCP, 443)
		api := &omittedFirewallRelationshipAPI{
			fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{
				UUID: testFirewallRelationFirewallUUID, ResourcesAssigned: []inspace.FirewallResource{},
			}}},
			omit: true,
		}
		controller := newController(t, api, service)
		converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
			desired,
		)
		if err == nil || converged || !strings.Contains(err.Error(), "omitted resources_assigned") {
			t.Fatalf("pre-dispatch omission result: converged=%t err=%v", converged, err)
		}
		if api.assignCalls != 0 {
			t.Fatalf("pre-dispatch omission issued %d mutation(s)", api.assignCalls)
		}
		stored := getNodeLoadBalancerTestService(t, ctx, controller.provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
			t.Fatalf("pre-dispatch omission retained unissued receipt: %#v", stored.Annotations)
		}
	})

	t.Run("post-dispatch omission", func(t *testing.T) {
		service := nodeLoadBalancerTestService("relation-omitted-post", "relation-omitted-post-uid", corev1.ProtocolTCP, 443)
		api := &omittedFirewallRelationshipAPI{
			fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{
				UUID: testFirewallRelationFirewallUUID, ResourcesAssigned: []inspace.FirewallResource{},
			}}},
			omitAfterAssign: true,
		}
		controller := newController(t, api, service)
		owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
		converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired)
		if err == nil || converged || !strings.Contains(err.Error(), "omitted resources_assigned") {
			t.Fatalf("post-dispatch omission result: converged=%t err=%v", converged, err)
		}
		if api.assignCalls != 1 {
			t.Fatalf("post-dispatch assignment calls = %d, want one", api.assignCalls)
		}
		stored := getNodeLoadBalancerTestService(t, ctx, controller.provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" {
			t.Fatalf("post-dispatch omission cleared issued receipt: %#v", stored.Annotations)
		}

		if converged, err = controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired); err == nil || converged {
			t.Fatalf("restart omission result: converged=%t err=%v", converged, err)
		}
		if api.assignCalls != 1 {
			t.Fatalf("post-dispatch omission replayed assignment: calls=%d", api.assignCalls)
		}
	})
}
