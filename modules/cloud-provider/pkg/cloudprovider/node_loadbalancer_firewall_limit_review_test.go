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
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// countServiceWrites counts every Service write the kube client receives.
func countServiceWrites(client *kubefake.Clientset) *int {
	writes := new(int)
	client.PrependReactor("*", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "update", "patch", "create", "delete":
			*writes++
		}
		return false, nil, nil
	})
	return writes
}

func TestFirewallLimitRefusalCommitsNoReceiptAndNoServiceUpdate(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(3),
	}
	controller, service := newFirewallLimitTestController(t, api, 0)
	writes := countServiceWrites(controller.provider.kubeClient.(*kubefake.Clientset))
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))

	for pass := 0; pass < 3; pass++ {
		converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, firewallLimitAssignFence())
		var limitErr *FirewallLimitExceededError
		if converged || !errors.As(err, &limitErr) {
			t.Fatalf("pass %d = converged %t, err %v; want FirewallLimitExceededError", pass, converged, err)
		}
	}
	if *writes != 0 {
		t.Fatalf("refused attach wrote the Service %d times; a Service update re-enqueues the key and defeats the hold backoff", *writes)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("refused attach was dispatched: %v", api.assignedFirewalls)
	}
}

// laggingAssignAPI acknowledges an attach without ever showing it in the
// listing, as an eventually consistent provider does.
type laggingAssignAPI struct {
	*fakeAPI
	assigns int
}

func (a *laggingAssignAPI) AssignFirewallToVM(context.Context, string, string, string) error {
	a.assigns++
	return nil
}

func TestFirewallLimitCountsRecentAttachmentsHiddenByListingLag(t *testing.T) {
	ctx := context.Background()
	const secondFirewall = "76666666-2222-4333-8444-555555555555"
	base := &fakeAPI{
		vms:       []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: firewallLimitTestFirewalls(2),
	}
	base.firewalls = append(base.firewalls, inspace.Firewall{UUID: secondFirewall, ResourcesAssigned: []inspace.FirewallResource{}})
	api := &laggingAssignAPI{fakeAPI: base}
	controller, first := newFirewallLimitTestController(t, api, 0)
	second := nodeLoadBalancerTestService("limit-second", "limit-second-uid", corev1.ProtocolTCP, 8443)
	if _, err := controller.provider.kubeClient.CoreV1().Services(second.Namespace).Create(ctx, second.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	controller.firewallRelationNow = func() time.Time { return now }

	// The first attach is acknowledged; its listing row has not appeared yet.
	_, _ = controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(first)), firewallLimitAssignFence(),
	)
	if api.assigns != 1 {
		t.Fatalf("first attach calls = %d, want 1", api.assigns)
	}
	// A different firewall for the same VM would be the fourth.
	secondFence := &nodeLoadBalancerFirewallRelationFence{
		operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: secondFirewall, vmUUID: testFirewallRelationVMUUID,
	}
	_, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(second)), secondFence,
	)
	var limitErr *FirewallLimitExceededError
	if !errors.As(err, &limitErr) || limitErr.Current != 3 {
		t.Fatalf("second attach during listing lag = %v; want FirewallLimitExceededError with 3 attached", err)
	}
	if api.assigns != 1 {
		t.Fatalf("second attach was dispatched: calls=%d", api.assigns)
	}

	// The memory expires, so a listing that never shows the first attach stops
	// blocking after the TTL.
	now = now.Add(recentFirewallAssignTTL + time.Second)
	if err := controller.requireFirewallVMCapacity(ctx, secondFirewall, testFirewallRelationVMUUID); err != nil {
		t.Fatalf("expired recent attachment still counted: %v", err)
	}
}

func TestFirewallLimitRecentAttachmentForgottenOnDetach(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{firewalls: firewallLimitTestFirewalls(2)}
	controller, _ := newFirewallLimitTestController(t, api, 0)
	const other = "77777777-2222-4333-8444-555555555555"
	controller.provider.rememberFirewallAssign(testFirewallRelationVMUUID, other, time.Now())
	if err := controller.requireFirewallVMCapacity(ctx, testFirewallRelationFirewallUUID, testFirewallRelationVMUUID); err == nil {
		t.Fatal("recent attachment was not counted")
	}
	controller.provider.forgetFirewallAssign(testFirewallRelationVMUUID, other)
	if err := controller.requireFirewallVMCapacity(ctx, testFirewallRelationFirewallUUID, testFirewallRelationVMUUID); err != nil {
		t.Fatalf("detached firewall still counted: %v", err)
	}
}

func addFirewallLimitForeignFirewalls(api *fakeAPI, vmUUID string, count int) {
	for index := 0; index < count; index++ {
		api.firewalls = append(api.firewalls, inspace.Firewall{
			UUID:              fmt.Sprintf("78888888-2222-4333-8444-%012d", index+1),
			DisplayName:       fmt.Sprintf("foreign-%d", index),
			ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
		})
	}
}

func TestClusterICMPLimitRefusalDoesNotStopOtherVMs(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"icmp-limit-service", "86868686-8686-4686-8686-868686868686", corev1.ProtocolTCP, 12843,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)

	const vmFull = "b1b1b1b1-b1b1-41b1-81b1-b1b1b1b1b1b1"
	const vmFree = "c2c2c2c2-c2c2-42c2-82c2-c2c2c2c2c2c2"
	aggregateAddSafetyNode(t, harness, harness.shard, "icmp-limit-full", vmFull, "10.0.0.41", "203.0.113.41", false)
	aggregateAddSafetyNode(t, harness, harness.shard, "icmp-limit-free", vmFree, "10.0.0.42", "203.0.113.42", false)
	addFirewallLimitForeignFirewalls(harness.api, vmFull, 2)
	nodes, err := harness.controller.authorizedNodesForCluster(harness.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ordered []*corev1.Node
	for _, node := range nodes {
		if strings.HasSuffix(node.Spec.ProviderID, vmFull) {
			ordered = append([]*corev1.Node{node}, ordered...)
		} else {
			ordered = append(ordered, node)
		}
	}
	nodeClassName := managedNodeLoadBalancerName(harness.provider.config.ClusterID, "node-lb")

	before := len(harness.api.assignedFirewalls)
	firewall, _, err := harness.controller.ensureClusterICMPFirewall(harness.ctx, nodeClassName, ordered)
	if err != nil || firewall == nil {
		t.Fatalf("ICMP ensure with a VM at the limit = %#v, %v", firewall, err)
	}
	var sawFree bool
	for _, assigned := range harness.api.assignedFirewalls[before:] {
		if strings.HasSuffix(assigned, "/"+vmFull) {
			t.Fatalf("ICMP firewall attached to the VM at the limit: %v", assigned)
		}
		if assigned == firewall.UUID+"/"+vmFree {
			sawFree = true
		}
	}
	if !sawFree {
		t.Fatalf("VM below the limit was not attached after a refusal: %v", harness.api.assignedFirewalls[before:])
	}
}

func TestShardFirewallLimitRefusalDoesNotStopOtherVMs(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"shard-limit-service", "87878787-8787-4787-8787-878787878787", corev1.ProtocolTCP, 12943,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	const vmFull = "d3d3d3d3-d3d3-43d3-83d3-d3d3d3d3d3d3"
	const vmFree = "e4e4e4e4-e4e4-44e4-84e4-e4e4e4e4e4e4"
	aggregateAddSafetyNode(t, harness, harness.shard, "shard-limit-full", vmFull, "10.0.0.51", "203.0.113.51", true)
	aggregateAddSafetyNode(t, harness, harness.shard, "shard-limit-free", vmFree, "10.0.0.52", "203.0.113.52", true)
	addFirewallLimitForeignFirewalls(harness.api, vmFull, 1)
	harness.fixture.refreshListers(t)
	shardFirewall := harness.aggregateFirewall(t)

	// The map order of the VMs is random, so run enough passes for both to be
	// visited; a refusal must never surface as an error or stop the loop.
	for pass := 0; pass < 4; pass++ {
		_, current, err := harness.controller.ensureShardFirewallAssignments(harness.ctx, harness.shard, shardFirewall)
		if err != nil {
			t.Fatalf("pass %d: a VM at the limit failed the shard assignment: %v", pass, err)
		}
		if current != nil {
			shardFirewall = *current
		}
	}
	var sawFree bool
	for _, assigned := range harness.api.assignedFirewalls {
		if assigned == shardFirewall.UUID+"/"+vmFull {
			t.Fatalf("shard firewall attached to the VM at the limit")
		}
		if assigned == shardFirewall.UUID+"/"+vmFree {
			sawFree = true
		}
	}
	if !sawFree {
		t.Fatalf("VM below the limit was not attached: %v", harness.api.assignedFirewalls)
	}
}

func TestServingPublicNodeLocalIsHeldAtFirewallLimit(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("limit-serving", "limit-serving-uid", corev1.ProtocolTCP, 443)
	service.Annotations[annotationPublicNodeLocalActivePool] = "edge"
	service.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.9"}}
	api := &fakeAPI{firewalls: firewallLimitTestFirewalls(3)}
	controller, _ := newFirewallLimitTestController(t, api, 0)
	kube := kubefake.NewSimpleClientset(service.DeepCopy())
	controller.provider.kubeClient = kube
	writes := countServiceWrites(kube)

	cause := fmt.Errorf("public-node-local: assign firewall %s to VM %s: %w", testFirewallRelationFirewallUUID, testFirewallRelationVMUUID,
		&FirewallLimitExceededError{VMUUID: testFirewallRelationVMUUID, FirewallUUID: testFirewallRelationFirewallUUID, Current: 3, Limit: 3})
	err := controller.holdOrFailPublicNodeLocal(ctx, service, cause)
	var holding *errPublicNodeLocalHolding
	var limitErr *FirewallLimitExceededError
	if !errors.As(err, &holding) || !errors.As(err, &limitErr) || holding.retryAfter <= 0 {
		t.Fatalf("serving Service at the limit = %v; want a hold with a retry delay", err)
	}
	if *writes != 0 {
		t.Fatalf("hold wrote the Service %d times; exposure must stay as is", *writes)
	}
	stored, getErr := kube.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if getErr != nil || len(stored.Status.LoadBalancer.Ingress) != 1 || stored.Annotations[annotationPublicNodeLocalActivePool] != "edge" {
		t.Fatalf("held Service exposure changed: %#v err=%v", stored, getErr)
	}
	// A repeat of the same refusal backs off instead of staying at the base delay.
	first := holding.retryAfter
	var last time.Duration
	for repeat := 0; repeat < 4; repeat++ {
		again := controller.holdOrFailPublicNodeLocal(ctx, service, cause)
		if !errors.As(again, &holding) {
			t.Fatalf("repeat %d is not a hold: %v", repeat, again)
		}
		last = holding.retryAfter
	}
	if last <= first {
		t.Fatalf("repeated refusal did not back off: first %s, last %s", first, last)
	}
}
