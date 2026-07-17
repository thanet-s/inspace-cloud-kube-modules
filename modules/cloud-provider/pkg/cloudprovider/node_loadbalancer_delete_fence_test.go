package cloudprovider

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// committedHTTP500FirewallDeleteAPI models the unsafe response class that
// motivated these fences: DELETE commits, the server returns HTTP 500, and one
// later list still exposes the deleted object. The first DELETE is blocked so a
// second controller can reconcile concurrently while the winning request is in
// flight.
type committedHTTP500FirewallDeleteAPI struct {
	*fakeAPI

	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu          sync.Mutex
	deleteCalls int
	stale       *inspace.Firewall
	staleReads  int
}

type postIssueFirewallDeleteDriftAPI struct {
	*fakeAPI
	hook        func()
	deleteCalls int
}

func (a *postIssueFirewallDeleteDriftAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	if a.hook != nil {
		a.hook()
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func (a *postIssueFirewallDeleteDriftAPI) DeleteFirewall(
	ctx context.Context,
	location, uuid string,
) error {
	a.deleteCalls++
	return a.fakeAPI.DeleteFirewall(ctx, location, uuid)
}

func TestNodeLoadBalancerFirewallDeleteRechecksAuthorityAfterIssue(t *testing.T) {
	t.Run("Service", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("delete-authority", "delete-authority-uid", corev1.ProtocolTCP, 443)
		service.Finalizers = []string{nodeLoadBalancerFinalizer}
		base := &fakeAPI{}
		provider := newTestProvider(t, base)
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}
		desired, err := controller.desiredServiceFirewall(service)
		if err != nil {
			t.Fatal(err)
		}
		const uuid = "95555555-2222-4333-8444-555555555555"
		base.firewalls = []inspace.Firewall{{
			UUID: uuid, DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
			BillingAccountID: desired.Request.BillingAccountID, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
		}}
		stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		stored.Annotations[annotationNodeLoadBalancerFirewallUUID] = uuid
		stored.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
		if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		api := &postIssueFirewallDeleteDriftAPI{fakeAPI: base}
		fired := false
		api.hook = func() {
			if fired {
				return
			}
			current, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
			if getErr == nil && current.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" {
				fired = true
				base.firewalls[0].BillingAccountID++
			}
		}
		provider.api = api
		if done, err := controller.deleteOwnedServiceFirewall(ctx, service, uuid); err == nil || done {
			t.Fatalf("post-issue Service firewall drift = done %t, err %v", done, err)
		}
		if !fired || api.deleteCalls != 0 {
			t.Fatalf("Service delete final authority: fired=%t deletes=%d", fired, api.deleteCalls)
		}
		stored, err = provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil || stored.Annotations[annotationNodeLoadBalancerFWDeleteIssued] == "" {
			t.Fatalf("Service delete issue receipt was not retained: %#v err=%v", stored, err)
		}
	})

	t.Run("shard", func(t *testing.T) {
		ctx := context.Background()
		service := aggregateTestService("delete-authority", "96666666-2222-4333-8444-555555555555", corev1.ProtocolTCP, 443)
		plan := nodeLoadBalancerShardPlan{
			Name: aggregateTestShard, Claims: []string{string(service.UID)},
			Ports: nodeLoadBalancerPortClaimsOrFatal(t, service),
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
			aggregateTestShard,
			provider.config.ClusterID,
			"delete-authority",
			1,
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
		controller := &nodeLoadBalancerController{provider: provider}
		api := &postIssueFirewallDeleteDriftAPI{fakeAPI: base}
		fired := false
		api.hook = func() {
			if fired {
				return
			}
			current, getErr := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, aggregateTestShard, metav1.GetOptions{})
			if getErr == nil && current.GetAnnotations()[annotationNodeLoadBalancerShardFWDeleteIssued] != "" {
				fired = true
				base.firewalls[0].BillingAccountID++
			}
		}
		provider.api = api
		if done, err := controller.deleteAggregateShardFirewall(ctx, aggregateTestShard); err == nil || done {
			t.Fatalf("post-issue shard firewall drift = done %t, err %v", done, err)
		}
		if !fired || api.deleteCalls != 0 {
			t.Fatalf("shard delete final authority: fired=%t deletes=%d", fired, api.deleteCalls)
		}
		stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, aggregateTestShard, metav1.GetOptions{})
		if err != nil || stored.GetAnnotations()[annotationNodeLoadBalancerShardFWDeleteIssued] == "" {
			t.Fatalf("shard delete issue receipt was not retained: %#v err=%v", stored, err)
		}
	})

	t.Run("cluster ICMP", func(t *testing.T) {
		ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
		const uuid = "97777777-2222-4333-8444-555555555555"
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID: uuid,
		})
		base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
		api := &postIssueFirewallDeleteDriftAPI{fakeAPI: base}
		fired := false
		api.hook = func() {
			if fired {
				return
			}
			current, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if getErr == nil && current.GetAnnotations()[annotationNodeLoadBalancerICMPDeleteIssued] != "" {
				fired = true
				base.firewalls[0].BillingAccountID++
			}
		}
		provider.api = api
		if done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName); err == nil || done {
			t.Fatalf("post-issue cluster ICMP firewall drift = done %t, err %v", done, err)
		}
		if !fired || api.deleteCalls != 0 {
			t.Fatalf("cluster ICMP delete final authority: fired=%t deletes=%d", fired, api.deleteCalls)
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil || stored.GetAnnotations()[annotationNodeLoadBalancerICMPDeleteIssued] == "" {
			t.Fatalf("cluster ICMP delete issue receipt was not retained: %#v err=%v", stored, err)
		}
	})
}

func newCommittedHTTP500FirewallDeleteAPI(base *fakeAPI) *committedHTTP500FirewallDeleteAPI {
	return &committedHTTP500FirewallDeleteAPI{
		fakeAPI: base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (a *committedHTTP500FirewallDeleteAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stale != nil && a.staleReads > 0 {
		a.staleReads--
		items = append(items, *a.stale)
	}
	return items, nil
}

func (a *committedHTTP500FirewallDeleteAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	a.mu.Lock()
	a.deleteCalls++
	a.mu.Unlock()
	a.once.Do(func() { close(a.entered) })
	<-a.release

	var deleted *inspace.Firewall
	for index := range a.fakeAPI.firewalls {
		if a.fakeAPI.firewalls[index].UUID == uuid {
			copy := a.fakeAPI.firewalls[index]
			deleted = &copy
			break
		}
	}
	if err := a.fakeAPI.DeleteFirewall(ctx, location, uuid); err != nil {
		return err
	}
	a.mu.Lock()
	a.stale = deleted
	a.staleReads = 1
	a.mu.Unlock()
	return &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/firewalls/" + uuid, Message: "committed but response failed"}
}

func (a *committedHTTP500FirewallDeleteAPI) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deleteCalls
}

func waitForFirewallDeleteDispatch(t *testing.T, api *committedHTTP500FirewallDeleteAPI) {
	t.Helper()
	select {
	case <-api.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for firewall DELETE dispatch")
	}
}

func TestServiceFirewallDeleteFenceSurvivesCommittedHTTP500StaleReadAndRestart(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("delete-fence", "delete-fence-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}

	base := &fakeAPI{}
	provider := newTestProvider(t, base)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Now().UTC()
	first := &nodeLoadBalancerController{provider: provider, firewallRelationNow: func() time.Time { return now }}
	desired, err := first.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-4333-8444-555555555555"
	base.firewalls = []inspace.Firewall{{
		UUID: uuid, DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
		BillingAccountID: desired.Request.BillingAccountID, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
	}}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stored.Annotations[annotationNodeLoadBalancerFirewallUUID] = uuid
	stored.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	api := newCommittedHTTP500FirewallDeleteAPI(base)
	provider.api = api
	firstErr := make(chan error, 1)
	go func() {
		_, deleteErr := first.deleteOwnedServiceFirewall(ctx, service, uuid)
		firstErr <- deleteErr
	}()
	waitForFirewallDeleteDispatch(t, api)

	second := &nodeLoadBalancerController{provider: provider, firewallRelationNow: func() time.Time { return now }}
	if done, err := second.deleteOwnedServiceFirewall(ctx, service, uuid); err != nil || done {
		t.Fatalf("concurrent controller = done %t, err=%v", done, err)
	}
	if api.calls() != 1 {
		t.Fatalf("concurrent Service firewall DELETE calls = %d, want 1", api.calls())
	}
	close(api.release)
	if err := <-firstErr; err == nil {
		t.Fatal("winning committed HTTP 500 delete returned nil")
	}

	// A reconstructed controller observes one stale positive read. The issued
	// receipt remains immutable and prevents replay.
	restarted := &nodeLoadBalancerController{provider: provider, firewallRelationNow: func() time.Time { return now }}
	if done, err := restarted.deleteOwnedServiceFirewall(ctx, service, uuid); err != nil || done {
		t.Fatalf("stale post-error read = done %t, err=%v", done, err)
	}
	if api.calls() != 1 {
		t.Fatalf("stale Service read replayed DELETE: calls=%d", api.calls())
	}
	converged := false
	for observation := 0; observation <= nodeLoadBalancerAbsenceConfirmations; observation++ {
		now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
		converged, err = restarted.deleteOwnedServiceFirewall(ctx, service, uuid)
		if err != nil {
			t.Fatalf("Service absence observation %d: %v", observation+1, err)
		}
		if converged {
			break
		}
	}
	if !converged {
		t.Fatal("Service delete fence did not converge after spaced absence")
	}
	final, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if final.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != "" ||
		final.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" ||
		final.Annotations[annotationNodeLoadBalancerFirewallUUID] != "" {
		t.Fatalf("Service delete fence did not converge: %#v", final.Annotations)
	}
	if api.calls() != 1 {
		t.Fatalf("Service firewall DELETE calls after recovery = %d, want 1", api.calls())
	}
}

func TestShardFirewallDeleteFenceSurvivesCommittedHTTP500StaleReadAndRestart(t *testing.T) {
	ctx := context.Background()
	service := aggregateTestService("delete-fence", "22222222-2222-4222-8222-222222222222", corev1.ProtocolTCP, 443)
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
		aggregateTestShard, provider.config.ClusterID, "delete-fence", 1,
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
	api := newCommittedHTTP500FirewallDeleteAPI(base)
	provider.api = api
	first := &nodeLoadBalancerController{provider: provider}

	firstErr := make(chan error, 1)
	go func() {
		_, deleteErr := first.deleteAggregateShardFirewall(ctx, aggregateTestShard)
		firstErr <- deleteErr
	}()
	waitForFirewallDeleteDispatch(t, api)
	second := &nodeLoadBalancerController{provider: provider}
	if done, err := second.deleteAggregateShardFirewall(ctx, aggregateTestShard); err != nil || done {
		t.Fatalf("concurrent shard controller = done %t, err=%v", done, err)
	}
	if api.calls() != 1 {
		t.Fatalf("concurrent shard firewall DELETE calls = %d, want 1", api.calls())
	}
	close(api.release)
	if err := <-firstErr; err == nil {
		t.Fatal("winning shard committed HTTP 500 delete returned nil")
	}

	restarted := &nodeLoadBalancerController{provider: provider}
	if done, err := restarted.deleteAggregateShardFirewall(ctx, aggregateTestShard); err != nil || done {
		t.Fatalf("stale shard post-error read = done %t, err=%v", done, err)
	}
	for observation := 1; observation <= nodeLoadBalancerAbsenceConfirmations; observation++ {
		if observation > 1 {
			backdateShardDeleteFenceObservation(t, ctx, provider, aggregateTestShard)
		}
		done, err := restarted.deleteAggregateShardFirewall(ctx, aggregateTestShard)
		if err != nil {
			t.Fatalf("shard absence observation %d: %v", observation, err)
		}
		if observation == nodeLoadBalancerAbsenceConfirmations && !done {
			t.Fatal("shard delete fence did not converge after spaced absence")
		}
	}
	if api.calls() != 1 {
		t.Fatalf("shard firewall DELETE calls after recovery = %d, want 1", api.calls())
	}
}

func TestClusterICMPFirewallDeleteFenceSurvivesCommittedHTTP500StaleReadAndRestart(t *testing.T) {
	ctx, base, provider, first, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	const uuid = "33333333-2222-4333-8444-555555555555"
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: uuid,
	})
	base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
	api := newCommittedHTTP500FirewallDeleteAPI(base)
	provider.api = api

	firstErr := make(chan error, 1)
	go func() {
		_, deleteErr := first.cleanupClusterICMPFirewall(ctx, nodeClassName)
		firstErr <- deleteErr
	}()
	waitForFirewallDeleteDispatch(t, api)
	second := &nodeLoadBalancerController{provider: provider}
	if done, err := second.cleanupClusterICMPFirewall(ctx, nodeClassName); err != nil || done {
		t.Fatalf("concurrent ICMP controller = done %t, err=%v", done, err)
	}
	if api.calls() != 1 {
		t.Fatalf("concurrent ICMP firewall DELETE calls = %d, want 1", api.calls())
	}
	close(api.release)
	if err := <-firstErr; err == nil {
		t.Fatal("winning ICMP committed HTTP 500 delete returned nil")
	}

	restarted := &nodeLoadBalancerController{provider: provider}
	if done, err := restarted.cleanupClusterICMPFirewall(ctx, nodeClassName); err != nil || done {
		t.Fatalf("stale ICMP post-error read = done %t, err=%v", done, err)
	}
	for observation := 1; observation <= nodeLoadBalancerAbsenceConfirmations; observation++ {
		if observation > 1 {
			ageClusterICMPSafetyAnnotation(t, ctx, provider, nodeClassName, annotationNodeLoadBalancerICMPCleanupChecked)
		}
		done, err := restarted.cleanupClusterICMPFirewall(ctx, nodeClassName)
		if err != nil || done {
			t.Fatalf("ICMP absence observation %d = done %t, err=%v", observation, done, err)
		}
	}
	done, err := restarted.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil || !done {
		t.Fatalf("ICMP proven absence = done %t, err=%v", done, err)
	}
	if api.calls() != 1 {
		t.Fatalf("ICMP firewall DELETE calls after recovery = %d, want 1", api.calls())
	}
}

func backdateShardDeleteFenceObservation(t *testing.T, ctx context.Context, provider *Provider, shard string) {
	t.Helper()
	resource := provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerShardFWCleanupCheck] = time.Now().Add(-2 * nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano)
	pool.SetAnnotations(annotations)
	if _, err := resource.Update(ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
