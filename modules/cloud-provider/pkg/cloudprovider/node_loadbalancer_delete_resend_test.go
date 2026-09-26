package cloudprovider

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// uncommittedFirewallDeleteAPI models a DELETE that crosses the HTTP boundary
// but fails without committing: the firewall remains listed indefinitely.
type uncommittedFirewallDeleteAPI struct {
	*fakeAPI
	failures    int
	deleteCalls int
}

func (a *uncommittedFirewallDeleteAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	a.deleteCalls++
	if a.deleteCalls <= a.failures {
		return &inspace.APIError{StatusCode: 503, Method: "DELETE", Path: "/firewall", Retryable: true}
	}
	return a.fakeAPI.DeleteFirewall(ctx, location, uuid)
}

func TestServiceFirewallDeleteResendsAfterUncommittedDelete(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("delete-resend", "delete-resend-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	base := &fakeAPI{}
	provider := newTestProvider(t, base)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Now().UTC()
	controller := &nodeLoadBalancerController{provider: provider, firewallRelationNow: func() time.Time { return now }}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "12121212-2222-4333-8444-555555555555"
	base.firewalls = []inspace.Firewall{{
		UUID: uuid, DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
		BillingAccountID: desired.Request.BillingAccountID, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
	}}
	api := &uncommittedFirewallDeleteAPI{fakeAPI: base, failures: 1}
	provider.api = api

	if _, err := controller.deleteOwnedServiceFirewall(ctx, service, uuid); err == nil {
		t.Fatal("uncommitted DELETE returned nil")
	}
	// An immediate positive read may be stale and must not replay DELETE.
	if done, err := controller.deleteOwnedServiceFirewall(ctx, service, uuid); err != nil || done || api.deleteCalls != 1 {
		t.Fatalf("immediate retry = done %t err=%v calls=%d", done, err, api.deleteCalls)
	}
	now = now.Add(nodeLoadBalancerFirewallDeleteResendDelay + time.Second)
	if _, err := controller.deleteOwnedServiceFirewall(ctx, service, uuid); err != nil {
		t.Fatalf("resend after proven non-commit: %v", err)
	}
	if api.deleteCalls != 2 || len(base.firewalls) != 0 {
		t.Fatalf("uncommitted DELETE was not re-sent: calls=%d firewalls=%#v", api.deleteCalls, base.firewalls)
	}
	converged := false
	for observation := 0; observation <= nodeLoadBalancerAbsenceConfirmations && !converged; observation++ {
		now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
		if converged, err = controller.deleteOwnedServiceFirewall(ctx, service, uuid); err != nil {
			t.Fatalf("absence observation %d: %v", observation, err)
		}
	}
	if !converged || api.deleteCalls != 2 {
		t.Fatalf("Service delete did not converge after resend: converged=%t calls=%d", converged, api.deleteCalls)
	}
}

func TestShardFirewallDeleteResendsAfterUncommittedDelete(t *testing.T) {
	ctx := context.Background()
	service := aggregateTestService("delete-resend", "23232323-2222-4222-8222-222222222222", corev1.ProtocolTCP, 443)
	plan := nodeLoadBalancerShardPlan{
		Name: aggregateTestShard, Claims: []string{string(service.UID)}, Ports: nodeLoadBalancerPortClaimsOrFatal(t, service),
	}
	policy, err := desiredNodeLoadBalancerShardFirewall("unit-test-cluster", 42, plan, []*corev1.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(policy)
	if err != nil {
		t.Fatal(err)
	}
	base := &fakeAPI{firewalls: []inspace.Firewall{aggregateTestFirewall(policy, aggregateTestFirewallUUID)}}
	provider := newTestProvider(t, base)
	pool := deletingNodeLoadBalancerStateAnchorPool(nodeLoadBalancerSafetyNodePool(
		aggregateTestShard, provider.config.ClusterID, "delete-resend", 1,
	))
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerShardFirewallUUID] = aggregateTestFirewallUUID
	annotations[annotationNodeLoadBalancerShardFirewallHash] = policy.Hash
	annotations[annotationNodeLoadBalancerShardFirewallLedger] = ledger
	pool.SetAnnotations(annotations)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool)
	api := &uncommittedFirewallDeleteAPI{fakeAPI: base, failures: 1}
	provider.api = api
	controller := &nodeLoadBalancerController{provider: provider}

	for attempt := 0; attempt < 4 && api.deleteCalls == 0; attempt++ {
		_, _ = controller.deleteAggregateShardFirewall(ctx, aggregateTestShard)
	}
	if api.deleteCalls != 1 {
		t.Fatalf("first shard DELETE calls = %d", api.deleteCalls)
	}
	if done, err := controller.deleteAggregateShardFirewall(ctx, aggregateTestShard); err != nil || done || api.deleteCalls != 1 {
		t.Fatalf("immediate shard retry = done %t err=%v calls=%d", done, err, api.deleteCalls)
	}
	resource := provider.dynamicClient.Resource(nodePoolGVR)
	stored, err := resource.Get(ctx, aggregateTestShard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	values := stored.GetAnnotations()
	values[annotationNodeLoadBalancerShardFWDeleteIssued] = time.Now().Add(-nodeLoadBalancerFirewallDeleteResendDelay - time.Second).UTC().Format(time.RFC3339Nano)
	stored.SetAnnotations(values)
	if _, err := resource.Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.deleteAggregateShardFirewall(ctx, aggregateTestShard); err != nil {
		t.Fatalf("shard resend after proven non-commit: %v", err)
	}
	if api.deleteCalls != 2 || len(base.firewalls) != 0 {
		t.Fatalf("uncommitted shard DELETE was not re-sent: calls=%d firewalls=%#v", api.deleteCalls, base.firewalls)
	}
}

func TestClusterICMPFirewallDeleteResendsAfterUncommittedDelete(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	const uuid = "34343434-2222-4333-8444-555555555555"
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: uuid,
	})
	base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
	api := &uncommittedFirewallDeleteAPI{fakeAPI: base, failures: 1}
	provider.api = api

	for attempt := 0; attempt < 4 && api.deleteCalls == 0; attempt++ {
		_, _ = controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
	}
	if api.deleteCalls != 1 {
		t.Fatalf("first ICMP DELETE calls = %d", api.deleteCalls)
	}
	if done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName); err != nil || done || api.deleteCalls != 1 {
		t.Fatalf("immediate ICMP retry = done %t err=%v calls=%d", done, err, api.deleteCalls)
	}
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPDeleteIssued: time.Now().Add(-nodeLoadBalancerFirewallDeleteResendDelay - time.Second).UTC().Format(time.RFC3339Nano),
	})
	if _, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName); err != nil {
		t.Fatalf("ICMP resend after proven non-commit: %v", err)
	}
	if api.deleteCalls != 2 || len(base.firewalls) != 0 {
		t.Fatalf("uncommitted ICMP DELETE was not re-sent: calls=%d firewalls=%#v", api.deleteCalls, base.firewalls)
	}
}
