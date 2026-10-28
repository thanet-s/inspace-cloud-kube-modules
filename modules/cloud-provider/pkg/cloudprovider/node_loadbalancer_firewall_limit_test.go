package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func firewallLimitTestFirewalls(attachedToVM int) []inspace.Firewall {
	firewalls := make([]inspace.Firewall, 0, attachedToVM+1)
	for index := 0; index < attachedToVM; index++ {
		firewalls = append(firewalls, inspace.Firewall{
			UUID: fmt.Sprintf("73333333-2222-4333-8444-%012d", index+1),
			ResourcesAssigned: []inspace.FirewallResource{
				{ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID},
			},
		})
	}
	return append(firewalls, inspace.Firewall{
		UUID:              testFirewallRelationFirewallUUID,
		ResourcesAssigned: []inspace.FirewallResource{},
	})
}

type firewallLimitListFailureAPI struct {
	*fakeAPI
	listCalls int
	failFrom  int
}

func (a *firewallLimitListFailureAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.listCalls++
	if a.listCalls >= a.failFrom {
		return nil, errors.New("inventory unavailable")
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func newFirewallLimitTestController(t *testing.T, api API, limit int32) (*nodeLoadBalancerController, *corev1.Service) {
	t.Helper()
	service := nodeLoadBalancerTestService("limit-service", "limit-service-uid", corev1.ProtocolTCP, 443)
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer.MaxFirewallsPerVM = limit
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	return &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: func() time.Time { return now },
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}, service
}

func firewallLimitAssignFence() *nodeLoadBalancerFirewallRelationFence {
	return &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
}

func TestNodeLoadBalancerFirewallAssignRefusedAtVMFirewallLimit(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(3),
	}
	controller, service := newFirewallLimitTestController(t, api, 0)
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))

	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, firewallLimitAssignFence())
	var limitErr *FirewallLimitExceededError
	if converged || !errors.As(err, &limitErr) {
		t.Fatalf("fourth firewall = converged %t, err %v; want FirewallLimitExceededError", converged, err)
	}
	if limitErr.Current != 3 || limitErr.Limit != 3 || limitErr.VMUUID != testFirewallRelationVMUUID ||
		limitErr.FirewallUUID != testFirewallRelationFirewallUUID {
		t.Fatalf("limit error fields = %#v", limitErr)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("refused attach was dispatched: %v", api.assignedFirewalls)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, controller.provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("refused attach left an issued receipt: %#v", stored.Annotations)
	}
	events, err := controller.provider.kubeClient.CoreV1().Events(service.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 || events.Items[0].Reason != "FirewallLimitExceeded" ||
		events.Items[0].Type != corev1.EventTypeWarning ||
		!strings.Contains(events.Items[0].Message, testFirewallRelationVMUUID) {
		t.Fatalf("limit Events = %#v", events.Items)
	}
}

func TestNodeLoadBalancerFirewallAssignAllowedBelowVMFirewallLimit(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(2),
	}
	controller, service := newFirewallLimitTestController(t, api, 0)
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))

	if _, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, firewallLimitAssignFence()); err != nil {
		t.Fatalf("third firewall refused: %v", err)
	}
	if len(api.assignedFirewalls) != 1 {
		t.Fatalf("third firewall was not attached: %v", api.assignedFirewalls)
	}
}

func TestNodeLoadBalancerFirewallLimitIsConfigurable(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(3),
	}
	controller, service := newFirewallLimitTestController(t, api, 4)
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))

	if _, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, firewallLimitAssignFence()); err != nil {
		t.Fatalf("fourth firewall refused with limit 4: %v", err)
	}
	if len(api.assignedFirewalls) != 1 {
		t.Fatalf("fourth firewall was not attached: %v", api.assignedFirewalls)
	}
}

func TestNodeLoadBalancerFirewallAssignRefusedWhenReadbackFails(t *testing.T) {
	ctx := context.Background()
	api := &firewallLimitListFailureAPI{fakeAPI: &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(0),
	}, failFrom: 2}
	controller, service := newFirewallLimitTestController(t, api, 0)
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))

	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, firewallLimitAssignFence())
	var limitErr *FirewallLimitExceededError
	if converged || err == nil || errors.As(err, &limitErr) || !strings.Contains(err.Error(), "inventory unavailable") {
		t.Fatalf("failed readback = converged %t, err %v", converged, err)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("attach was dispatched without a readback: %v", api.assignedFirewalls)
	}
}

func TestRequireFirewallVMCapacityCountsEveryFirewallAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	foreign := inspace.Firewall{
		UUID: "74444444-2222-4333-8444-555555555555",
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: strings.ToUpper(testFirewallRelationVMUUID)},
			{ResourceType: "vm", ResourceUUID: "75555555-2222-4333-8444-555555555555"},
		},
	}
	api := &fakeAPI{firewalls: append(firewallLimitTestFirewalls(2), foreign)}
	controller, _ := newFirewallLimitTestController(t, api, 0)

	var limitErr *FirewallLimitExceededError
	err := controller.requireFirewallVMCapacity(ctx, testFirewallRelationFirewallUUID, testFirewallRelationVMUUID)
	if !errors.As(err, &limitErr) || limitErr.Current != 3 {
		t.Fatalf("foreign firewall was not counted: %v", err)
	}
	// Re-assigning a firewall that is already on the VM never adds to the count.
	if err := controller.requireFirewallVMCapacity(ctx, api.firewalls[0].UUID, testFirewallRelationVMUUID); err != nil {
		t.Fatalf("idempotent re-assign refused: %v", err)
	}
}

func TestMaxFirewallsPerVMDefaultsToThree(t *testing.T) {
	provider := newTestProvider(t, &fakeAPI{})
	if got := provider.maxFirewallsPerVM(); got != 3 {
		t.Fatalf("default limit = %d, want 3", got)
	}
	provider.config.NodeLoadBalancer.MaxFirewallsPerVM = -2
	if got := provider.maxFirewallsPerVM(); got != 3 {
		t.Fatalf("negative limit = %d, want 3", got)
	}
	provider.config.NodeLoadBalancer.MaxFirewallsPerVM = 5
	if got := provider.maxFirewallsPerVM(); got != 5 {
		t.Fatalf("configured limit = %d, want 5", got)
	}
}
