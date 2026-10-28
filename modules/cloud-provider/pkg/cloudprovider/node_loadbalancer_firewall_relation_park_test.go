package cloudprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const testFirewallRelationSecondVMUUID = "73333333-2222-4333-8444-555555555555"

// neverAppliesUnassignAPI accepts every unassign but never applies it.
type neverAppliesUnassignAPI struct {
	*fakeAPI
	unassignCalls int
}

func (a *neverAppliesUnassignAPI) UnassignFirewallFromVM(context.Context, string, string, string) error {
	a.unassignCalls++
	return nil
}

type relationParkFixture struct {
	ctx        context.Context
	api        *neverAppliesUnassignAPI
	controller *nodeLoadBalancerController
	owner      nodeLoadBalancerFirewallRelationOwner
	now        *time.Time
}

func newRelationParkFixture(t *testing.T) *relationParkFixture {
	t.Helper()
	service := nodeLoadBalancerTestService("relation-park", "relation-park-uid", corev1.ProtocolTCP, 443)
	api := &neverAppliesUnassignAPI{fakeAPI: &fakeAPI{
		vms: []inspace.VM{
			{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID},
			{UUID: testFirewallRelationSecondVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID},
		},
		firewalls: []inspace.Firewall{{
			UUID: testFirewallRelationFirewallUUID,
			ResourcesAssigned: []inspace.FirewallResource{
				{ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID},
				{ResourceType: "vm", ResourceUUID: testFirewallRelationSecondVMUUID},
			},
		}},
	}}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Date(2026, 10, 28, 2, 0, 0, 0, time.UTC)
	controller := &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: func() time.Time { return now },
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	return &relationParkFixture{
		ctx: context.Background(), api: api, controller: controller, now: &now,
		owner: withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
	}
}

func (f *relationParkFixture) unassign(vmUUID string) error {
	_, err := f.controller.reconcileNodeLoadBalancerFirewallRelation(f.ctx, f.owner, &nodeLoadBalancerFirewallRelationFence{
		operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: testFirewallRelationFirewallUUID, vmUUID: vmUUID,
	})
	return err
}

// retireThrice issues the unassign, lets the receipt retire, and repeats.
func (f *relationParkFixture) retireThrice(t *testing.T) {
	t.Helper()
	for retirement := 1; retirement <= 3; retirement++ {
		if err := f.unassign(testFirewallRelationVMUUID); err == nil {
			t.Fatalf("attempt %d: an unapplied unassign returned nil", retirement)
		}
		if f.api.unassignCalls != retirement {
			t.Fatalf("attempt %d: unassign calls = %d", retirement, f.api.unassignCalls)
		}
		*f.now = f.now.Add(nodeLoadBalancerFirewallRelationRetireDelay + time.Second)
		if err := f.unassign(testFirewallRelationVMUUID); err != nil {
			t.Fatalf("retirement %d: %v", retirement, err)
		}
	}
}

func TestNodeLoadBalancerFirewallRelationParksAfterThreeRetirements(t *testing.T) {
	f := newRelationParkFixture(t)
	f.retireThrice(t)

	for attempt := 0; attempt < 2; attempt++ {
		if err := f.unassign(testFirewallRelationVMUUID); !errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
			t.Fatalf("parked attempt %d: err = %v, want the parked error", attempt, err)
		}
	}
	if f.api.unassignCalls != 3 {
		t.Fatalf("a parked relation was dispatched: calls = %d", f.api.unassignCalls)
	}
	// Another VM is a different logical relation, so it is not parked.
	if err := f.unassign(testFirewallRelationSecondVMUUID); errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
		t.Fatalf("a different relation was parked: %v", err)
	}
	if f.api.unassignCalls != 4 {
		t.Fatalf("the different relation was not issued: calls = %d", f.api.unassignCalls)
	}
}

func TestNodeLoadBalancerFirewallRelationParkExpiresAfterThirtyMinutes(t *testing.T) {
	f := newRelationParkFixture(t)
	f.retireThrice(t)
	*f.now = f.now.Add(nodeLoadBalancerFirewallRelationParkDuration - time.Minute)
	if err := f.unassign(testFirewallRelationVMUUID); !errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
		t.Fatalf("park ended early: %v", err)
	}
	*f.now = f.now.Add(2 * time.Minute)
	if err := f.unassign(testFirewallRelationVMUUID); errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
		t.Fatalf("park did not expire: %v", err)
	}
	if f.api.unassignCalls != 4 {
		t.Fatalf("the relation was not issued again after the park: calls = %d", f.api.unassignCalls)
	}
}
