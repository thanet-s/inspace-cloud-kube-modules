package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type nodeLoadBalancerBlockedFirewallDeleteAPI struct {
	*fakeAPI
	deleteCalls int
}

func (a *nodeLoadBalancerBlockedFirewallDeleteAPI) DeleteFirewall(context.Context, string, string) error {
	a.deleteCalls++
	return inspace.ErrMutationBlocked
}

func TestNodeLoadBalancerErrMutationBlockedResetsExactFirewallReceipt(t *testing.T) {
	t.Run("Service create", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("blocked-create", "blocked-create-uid", corev1.ProtocolTCP, 443)
		api := &fakeAPI{createFirewallErr: inspace.ErrMutationBlocked}
		provider := newTestProvider(t, api)
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}

		if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("Service create error = %v", err)
		}
		stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(api.createdFirewalls) != 1 ||
			stored.Annotations[annotationNodeLoadBalancerPendingFWName] == "" ||
			stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" ||
			stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != "" {
			t.Fatalf("Service create receipt did not reset to intent: calls=%d annotations=%#v", len(api.createdFirewalls), stored.Annotations)
		}
	})

	t.Run("shard create", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"blocked-shard-create",
			"81111111-2222-4333-8444-555555555555",
			corev1.ProtocolTCP,
			443,
		))
		fixture.reconcile(t)
		fixture.api.createFirewallErr = inspace.ErrMutationBlocked
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("shard create error = %v", err)
		}
		annotations := fixture.pool(t).GetAnnotations()
		if len(fixture.api.createdFirewalls) != 1 ||
			annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
			annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			t.Fatalf("shard create receipt did not reset to intent: calls=%d annotations=%#v", len(fixture.api.createdFirewalls), annotations)
		}
	})

	t.Run("shard update", func(t *testing.T) {
		existing := aggregateTestService(
			"blocked-shard-update-existing",
			"82222222-2222-4333-8444-555555555555",
			corev1.ProtocolTCP,
			80,
		)
		fixture := newAggregateShardFirewallTestFixture(t, existing)
		desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err != nil || desired == nil {
			t.Fatalf("initial desired shard policy = %#v, err=%v", desired, err)
		}
		fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*desired, aggregateTestFirewallUUID)}
		fixture.reconcile(t)
		fixture.reconcile(t)
		member := aggregateTestService(
			"blocked-shard-update-member",
			"83333333-2222-4333-8444-555555555555",
			corev1.ProtocolTCP,
			443,
		)
		if _, err := fixture.provider.kubeClient.CoreV1().Services(member.Namespace).Create(
			fixture.ctx,
			member,
			metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		fixture.reconcile(t)
		fixture.api.updateFirewallErr = inspace.ErrMutationBlocked
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("shard update error = %v", err)
		}
		annotations := fixture.pool(t).GetAnnotations()
		if len(fixture.api.updatedFirewalls) != 1 ||
			annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
			annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			t.Fatalf("shard update receipt did not reset to intent: calls=%d annotations=%#v", len(fixture.api.updatedFirewalls), annotations)
		}
	})

	t.Run("cluster ICMP create", func(t *testing.T) {
		ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
		api.createFirewallErr = inspace.ErrMutationBlocked
		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("cluster ICMP create error = %v", err)
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations := stored.GetAnnotations()
		if len(api.createdFirewalls) != 1 ||
			annotations[annotationNodeLoadBalancerICMPPendingName] != desired.Request.DisplayName ||
			annotations[annotationNodeLoadBalancerICMPCreateIssued] != "" {
			t.Fatalf("cluster ICMP create receipt did not reset to intent: calls=%d annotations=%#v", len(api.createdFirewalls), annotations)
		}
	})

	t.Run("Service delete", func(t *testing.T) {
		ctx, controller, provider, api, service, uuid := blockedServiceFirewallDeleteFixture(t)
		if done, err := controller.deleteOwnedServiceFirewall(ctx, service, uuid); done || !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("Service delete = done %t, err=%v", done, err)
		}
		stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if api.deleteCalls != 1 ||
			stored.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != uuid ||
			stored.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" {
			t.Fatalf("Service delete receipt did not reset to intent: calls=%d annotations=%#v", api.deleteCalls, stored.Annotations)
		}
	})

	t.Run("shard delete", func(t *testing.T) {
		ctx, controller, provider, api, shard, uuid := blockedShardFirewallDeleteFixture(t)
		if done, err := controller.deleteAggregateShardFirewall(ctx, shard); done || !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("shard delete = done %t, err=%v", done, err)
		}
		stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations := stored.GetAnnotations()
		if api.deleteCalls != 1 ||
			annotations[annotationNodeLoadBalancerShardFWDeleteTarget] != uuid ||
			annotations[annotationNodeLoadBalancerShardFWDeleteIssued] != "" {
			t.Fatalf("shard delete receipt did not reset to intent: calls=%d annotations=%#v", api.deleteCalls, annotations)
		}
	})

	t.Run("cluster ICMP delete", func(t *testing.T) {
		ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
		const uuid = "84444444-2222-4333-8444-555555555555"
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID: uuid,
		})
		base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
		api := &nodeLoadBalancerBlockedFirewallDeleteAPI{fakeAPI: base}
		provider.api = api
		if done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName); done || !errors.Is(err, inspace.ErrMutationBlocked) {
			t.Fatalf("cluster ICMP delete = done %t, err=%v", done, err)
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations := stored.GetAnnotations()
		if api.deleteCalls != 1 ||
			annotations[annotationNodeLoadBalancerICMPDeleteTarget] != uuid ||
			annotations[annotationNodeLoadBalancerICMPDeleteIssued] != "" {
			t.Fatalf("cluster ICMP delete receipt did not reset to intent: calls=%d annotations=%#v", api.deleteCalls, annotations)
		}
	})
}

func blockedServiceFirewallDeleteFixture(
	t *testing.T,
) (context.Context, *nodeLoadBalancerController, *Provider, *nodeLoadBalancerBlockedFirewallDeleteAPI, *corev1.Service, string) {
	t.Helper()
	ctx := context.Background()
	service := nodeLoadBalancerTestService("blocked-delete", "blocked-delete-uid", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	base := &fakeAPI{}
	provider := newTestProvider(t, base)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "85555555-2222-4333-8444-555555555555"
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
	api := &nodeLoadBalancerBlockedFirewallDeleteAPI{fakeAPI: base}
	provider.api = api
	return ctx, controller, provider, api, service, uuid
}

func blockedShardFirewallDeleteFixture(
	t *testing.T,
) (context.Context, *nodeLoadBalancerController, *Provider, *nodeLoadBalancerBlockedFirewallDeleteAPI, string, string) {
	t.Helper()
	ctx := context.Background()
	service := aggregateTestService("blocked-shard-delete", "86666666-2222-4333-8444-555555555555", corev1.ProtocolTCP, 443)
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
		"blocked-shard-delete",
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
	api := &nodeLoadBalancerBlockedFirewallDeleteAPI{fakeAPI: base}
	provider.api = api
	return ctx, &nodeLoadBalancerController{provider: provider}, provider, api, aggregateTestShard, aggregateTestFirewallUUID
}

func TestNodeLoadBalancerReceiptResetUsesDetachedContextAndRejectsReplacement(t *testing.T) {
	t.Run("Service create", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("reset-service-create", "reset-service-create-uid", corev1.ProtocolTCP, 443)
		desiredName := "inlb-unit-reset-create"
		service.Annotations[annotationNodeLoadBalancerPendingFWName] = desiredName
		service.Annotations[annotationNodeLoadBalancerPendingFWStarted] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		service.Annotations[annotationNodeLoadBalancerPendingFWIssued] = strings.Repeat("a", 32)
		service.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] = time.Now().UTC().Format(time.RFC3339Nano)
		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := controller.resetServiceFirewallCreateAfterProvenNonDispatch(canceled, service.DeepCopy()); err != nil {
			t.Fatalf("canceled Service create reset: %v", err)
		}
		replacement := service.DeepCopy()
		replacement.Annotations[annotationNodeLoadBalancerPendingFWIssued] = strings.Repeat("b", 32)
		replacement.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := controller.resetServiceFirewallCreateAfterProvenNonDispatch(ctx, service.DeepCopy()); err == nil {
			t.Fatal("stale Service create receipt reset replaced authority")
		}
		stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil || stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != strings.Repeat("b", 32) {
			t.Fatalf("replacement Service create receipt changed: %#v err=%v", stored, err)
		}
	})

	t.Run("Service delete", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("reset-service-delete", "reset-service-delete-uid", corev1.ProtocolTCP, 443)
		const uuid = "87777777-2222-4333-8444-555555555555"
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		service.Annotations[annotationNodeLoadBalancerFWDeleteTarget] = uuid
		service.Annotations[annotationNodeLoadBalancerFWDeleteIssued] = issuedAt
		provider := newTestProvider(t, &fakeAPI{})
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := controller.resetServiceFirewallDeleteAfterProvenNonDispatch(canceled, service.DeepCopy(), uuid, issuedAt); err != nil {
			t.Fatalf("canceled Service delete reset: %v", err)
		}
		replacement := service.DeepCopy()
		replacement.Annotations[annotationNodeLoadBalancerFWDeleteIssued] = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := controller.resetServiceFirewallDeleteAfterProvenNonDispatch(ctx, service.DeepCopy(), uuid, issuedAt); err == nil {
			t.Fatal("stale Service delete receipt reset replaced authority")
		}
		stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil || stored.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != replacement.Annotations[annotationNodeLoadBalancerFWDeleteIssued] {
			t.Fatalf("replacement Service delete receipt changed: %#v err=%v", stored, err)
		}
	})

	t.Run("shard create or update", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"reset-shard-policy",
			"88888888-2222-4333-8444-555555555555",
			corev1.ProtocolTCP,
			443,
		))
		fixture.reconcile(t)
		pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
			fixture.ctx,
			fixture.shard,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatal(err)
		}
		annotations, err := nodeLoadBalancerShardFirewallAnnotations(pool)
		if err != nil {
			t.Fatal(err)
		}
		expectedStaged := nodeLoadBalancerShardFirewallMutationExpected(annotations, "")
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		expected, err := fixture.controller.issueShardFirewallMutation(
			fixture.ctx,
			fixture.shard,
			pool.GetUID(),
			expectedStaged,
			issuedAt,
			true,
		)
		if err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithCancel(fixture.ctx)
		cancel()
		if err := fixture.controller.resetShardFirewallMutationAfterProvenNonDispatch(
			canceled,
			fixture.shard,
			pool.GetUID(),
			expected,
		); err != nil {
			t.Fatalf("canceled shard policy reset: %v", err)
		}
		replacementIssued := time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		replacement, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
			fixture.ctx,
			fixture.shard,
			metav1.GetOptions{},
		)
		if err != nil {
			t.Fatal(err)
		}
		replacementAnnotations := replacement.GetAnnotations()
		replacementAnnotations[annotationNodeLoadBalancerShardFWIssuedAt] = replacementIssued
		replacement.SetAnnotations(replacementAnnotations)
		if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
			fixture.ctx,
			replacement,
			metav1.UpdateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		if err := fixture.controller.resetShardFirewallMutationAfterProvenNonDispatch(
			fixture.ctx,
			fixture.shard,
			pool.GetUID(),
			expected,
		); err == nil {
			t.Fatal("stale shard policy receipt reset replaced authority")
		}
		if got := fixture.pool(t).GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt]; got != replacementIssued {
			t.Fatalf("replacement shard policy receipt changed from %q to %q", replacementIssued, got)
		}
	})

	t.Run("shard delete", func(t *testing.T) {
		ctx := context.Background()
		const (
			shard = "inlb-reset-delete"
			uuid  = "89999999-2222-4333-8444-555555555555"
		)
		provider := newTestProvider(t, &fakeAPI{})
		pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, "reset-delete", 1)
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		annotations := pool.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[annotationNodeLoadBalancerShardFWDeleteTarget] = uuid
		annotations[annotationNodeLoadBalancerShardFWDeleteIssued] = issuedAt
		pool.SetAnnotations(annotations)
		provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool)
		controller := &nodeLoadBalancerController{provider: provider}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := controller.resetShardFirewallDeleteAfterProvenNonDispatch(
			canceled,
			shard,
			pool.GetUID(),
			uuid,
			issuedAt,
		); err != nil {
			t.Fatalf("canceled shard delete reset: %v", err)
		}
		replacementIssued := time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		replacement, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		replacementAnnotations := replacement.GetAnnotations()
		replacementAnnotations[annotationNodeLoadBalancerShardFWDeleteIssued] = replacementIssued
		replacement.SetAnnotations(replacementAnnotations)
		if _, err := provider.dynamicClient.Resource(nodePoolGVR).Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := controller.resetShardFirewallDeleteAfterProvenNonDispatch(
			ctx,
			shard,
			pool.GetUID(),
			uuid,
			issuedAt,
		); err == nil {
			t.Fatal("stale shard delete receipt reset replaced authority")
		}
		stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if err != nil || stored.GetAnnotations()[annotationNodeLoadBalancerShardFWDeleteIssued] != replacementIssued {
			t.Fatalf("replacement shard delete receipt changed: %#v err=%v", stored, err)
		}
	})

	t.Run("cluster ICMP create", func(t *testing.T) {
		ctx, _, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
		startedAt := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		expected := map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   "",
			annotationNodeLoadBalancerICMPPendingUUID:    "",
			annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
			annotationNodeLoadBalancerICMPPendingStarted: startedAt,
			annotationNodeLoadBalancerICMPCreateIssued:   issuedAt,
		}
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, expected)
		nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := controller.resetManagedNodeClassICMPCreateAfterProvenNonDispatch(
			canceled,
			nodeClassName,
			nodeClass.GetUID(),
			expected,
		); err != nil {
			t.Fatalf("canceled ICMP create reset: %v", err)
		}
		replacementIssued := time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
			annotationNodeLoadBalancerICMPCreateIssued: replacementIssued,
		})
		if err := controller.resetManagedNodeClassICMPCreateAfterProvenNonDispatch(
			ctx,
			nodeClassName,
			nodeClass.GetUID(),
			expected,
		); err == nil {
			t.Fatal("stale ICMP create receipt reset replaced authority")
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil || stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] != replacementIssued {
			t.Fatalf("replacement ICMP create receipt changed: %#v err=%v", stored, err)
		}
	})

	t.Run("cluster ICMP delete", func(t *testing.T) {
		ctx, _, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
		const uuid = "8aaaaaaa-2222-4333-8444-555555555555"
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		expected := map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   uuid,
			annotationNodeLoadBalancerICMPPendingUUID:    "",
			annotationNodeLoadBalancerICMPPendingName:    "",
			annotationNodeLoadBalancerICMPPendingStarted: "",
			annotationNodeLoadBalancerICMPCreateIssued:   "",
			annotationNodeLoadBalancerICMPDeleteTarget:   uuid,
			annotationNodeLoadBalancerICMPDeleteIssued:   issuedAt,
			annotationNodeLoadBalancerICMPCleanupAbsent:  "",
			annotationNodeLoadBalancerICMPCleanupChecked: "",
		}
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, expected)
		nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := controller.resetClusterICMPFirewallDeleteAfterProvenNonDispatch(
			canceled,
			nodeClassName,
			nodeClass.GetUID(),
			expected,
		); err != nil {
			t.Fatalf("canceled ICMP delete reset: %v", err)
		}
		replacementIssued := time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
			annotationNodeLoadBalancerICMPDeleteIssued: replacementIssued,
		})
		if err := controller.resetClusterICMPFirewallDeleteAfterProvenNonDispatch(
			ctx,
			nodeClassName,
			nodeClass.GetUID(),
			expected,
		); err == nil {
			t.Fatal("stale ICMP delete receipt reset replaced authority")
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil || stored.GetAnnotations()[annotationNodeLoadBalancerICMPDeleteIssued] != replacementIssued {
			t.Fatalf("replacement ICMP delete receipt changed: %#v err=%v", stored, err)
		}
	})
}
