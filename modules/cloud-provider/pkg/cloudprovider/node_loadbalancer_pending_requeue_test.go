package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// omitAfterFirstListAPI shows the relation on the first firewall read only,
// and then reports an empty firewall list. The unassign it receives never
// commits.
type omitAfterFirstListAPI struct {
	*fakeAPI
	listCalls     int
	unassignCalls int
}

func (a *omitAfterFirstListAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.listCalls++
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	if a.listCalls >= 2 {
		return nil, nil
	}
	return cloneNodeLoadBalancerTestFirewalls(items), nil
}

func (a *omitAfterFirstListAPI) UnassignFirewallFromVM(context.Context, string, string, string) error {
	a.unassignCalls++
	return &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/firewall/vms", Message: "no commit", Retryable: true}
}

func TestNodeLoadBalancerFirewallRelationPendingIsTypedAndBounded(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-pending", "relation-pending-uid", corev1.ProtocolTCP, 443)
	api := &omitAfterFirstListAPI{fakeAPI: &fakeAPI{
		vms: []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: []inspace.Firewall{{
			UUID: testFirewallRelationFirewallUUID,
			ResourcesAssigned: []inspace.FirewallResource{{
				ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
			}},
		}},
	}}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	controller := &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: func() time.Time { return now },
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationUnassign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
	// The dispatch fails and the readback shows the first absence.
	if _, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired); err == nil {
		t.Fatal("ambiguous unassign returned nil")
	}
	now = now.Add(5 * time.Second)
	_, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired)
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("first absence did not return a typed pending error: %v", err)
	}
	if !strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("pending message changed: %v", err)
	}
	if pending.retryAfter <= 0 || pending.retryAfter > nodeLoadBalancerAbsenceConfirmationDelay {
		t.Fatalf("retryAfter after first absence = %s, want within (0, %s]", pending.retryAfter, nodeLoadBalancerAbsenceConfirmationDelay)
	}
	if want := nodeLoadBalancerAbsenceConfirmationDelay - 5*time.Second; pending.retryAfter != want {
		t.Fatalf("retryAfter = %s, want the time left until the second absence read (%s)", pending.retryAfter, want)
	}
	if delay, ok := nodeLoadBalancerRequeueDelay(err); !ok || delay != pending.retryAfter {
		t.Fatalf("requeue delay = %s ok=%t, want %s", delay, ok, pending.retryAfter)
	}
	if api.unassignCalls != 1 {
		t.Fatalf("pending wait dispatched again: %d", api.unassignCalls)
	}
}

func TestNodeLoadBalancerFirewallRelationUnconvergedReceiptRetryIsBounded(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-unconverged", "relation-unconverged-uid", corev1.ProtocolTCP, 443)
	api := &transientlyOmittedUnassignAPI{fakeAPI: &fakeAPI{
		vms: []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: []inspace.Firewall{{
			UUID: testFirewallRelationFirewallUUID,
			ResourcesAssigned: []inspace.FirewallResource{{
				ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
			}},
		}},
	}}
	api.listCalls = 2 // every read shows the relation
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	controller := &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: func() time.Time { return now },
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationUnassign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
	if _, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired); err == nil {
		t.Fatal("uncommitted unassign returned nil")
	}
	// Close to the retire time the wait is the time that is left.
	now = now.Add(nodeLoadBalancerFirewallRelationRetireDelay - 4*time.Second)
	_, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired)
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("unconverged receipt did not return a typed pending error: %v", err)
	}
	if pending.retryAfter != 4*time.Second {
		t.Fatalf("retryAfter = %s, want 4s", pending.retryAfter)
	}
	// Far from the retire time the wait is the normal retry.
	api.unassignCalls = 0
	other := nodeLoadBalancerTestService("relation-unconverged-2", "relation-unconverged-uid-2", corev1.ProtocolTCP, 443)
	provider.kubeClient = kubefake.NewSimpleClientset(other.DeepCopy())
	now = time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	owner = withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(other))
	if _, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired); err == nil {
		t.Fatal("second uncommitted unassign returned nil")
	}
	_, err = controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired)
	if !errors.As(err, &pending) {
		t.Fatalf("fresh unconverged receipt did not return a typed pending error: %v", err)
	}
	if pending.retryAfter != nodeLoadBalancerRetry {
		t.Fatalf("retryAfter = %s, want %s", pending.retryAfter, nodeLoadBalancerRetry)
	}
}

func TestNodeLoadBalancerRequeueDelayForError(t *testing.T) {
	pending := &nodeLoadBalancerFirewallRelationPendingError{message: "waiting", retryAfter: 7 * time.Second}
	if delay, ok := nodeLoadBalancerRequeueDelay(fmt.Errorf("wrapped: %w", pending)); !ok || delay != 7*time.Second {
		t.Fatalf("pending delay = %s ok=%t", delay, ok)
	}
	transient := &errTransientProviderDeferral{cause: errors.New("api down")}
	if delay, ok := nodeLoadBalancerRequeueDelay(transient); ok {
		t.Fatalf("transient deferral got a fixed delay %s", delay)
	}
	if delay, ok := nodeLoadBalancerRequeueDelay(errors.New("plain")); ok {
		t.Fatalf("plain error got a fixed delay %s", delay)
	}
	if delay, ok := nodeLoadBalancerRequeueDelay(nil); ok {
		t.Fatalf("nil error got a fixed delay %s", delay)
	}
}
