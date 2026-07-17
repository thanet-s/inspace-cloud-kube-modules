package cloudprovider

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	aggregateTestShard        = "inlb-7255785b"
	aggregateTestFirewallUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	aggregateTestVMUUID       = "cccccccc-1111-4222-8333-dddddddddddd"
	aggregateTestStaleVMUUID  = "eeeeeeee-1111-4222-8333-ffffffffffff"
)

func TestNodeLoadBalancerShardFirewallStateCoversExactAppliedLedger(t *testing.T) {
	service := nodeLoadBalancerTestService(
		"existing",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	)
	policyHash, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		t.Fatal(err)
	}
	state := nodeLoadBalancerShardFirewallState{
		AppliedLedger: string(service.UID) + "=" + policyHash,
	}
	if !state.covers(service) {
		t.Fatal("exact applied ledger did not cover its Service policy")
	}

	changed := service.DeepCopy()
	changed.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	if state.covers(changed) {
		t.Fatal("applied ledger covered a changed Service policy")
	}
	other := service.DeepCopy()
	other.UID = types.UID("22222222-2222-4222-8222-222222222222")
	if state.covers(other) {
		t.Fatal("applied ledger covered an unlisted Service UID")
	}
	if (nodeLoadBalancerShardFirewallState{AppliedLedger: "not-a-ledger"}).covers(service) {
		t.Fatal("malformed applied ledger covered a Service")
	}
	if state.covers(nil) {
		t.Fatal("applied ledger covered a nil Service")
	}
}

func TestReconcileShardFirewallPolicyStableCreateAndAdopt(t *testing.T) {
	t.Run("create progresses through a durable fence", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"existing",
			"11111111-1111-4111-8111-111111111111",
			corev1.ProtocolTCP,
			80,
		))

		first := fixture.reconcile(t)
		if first.Firewall != nil || len(fixture.api.createdFirewalls) != 0 {
			t.Fatalf("first fence reconcile mutated cloud state: state=%#v creates=%d", first, len(fixture.api.createdFirewalls))
		}
		pool := fixture.pool(t)
		if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
			pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			t.Fatalf("first reconcile did not persist only the pending fence: %#v", pool.GetAnnotations())
		}

		second := fixture.reconcile(t)
		if second.Firewall == nil || !second.PolicyReady || second.AssignmentsReady ||
			len(fixture.api.createdFirewalls) != 1 || len(fixture.api.firewalls) != 1 {
			t.Fatalf("create reconcile = state %#v, requests=%d, firewalls=%#v", second, len(fixture.api.createdFirewalls), fixture.api.firewalls)
		}
		createdUUID := fixture.api.firewalls[0].UUID
		if createdUUID == "" {
			t.Fatal("fake cloud create returned no firewall UUID")
		}

		// The create response is provisional; the same reconciliation performs
		// an unfiltered deterministic-name readback and promotes only that row.
		third := fixture.reconcile(t)
		if third.Firewall == nil || third.Firewall.UUID != createdUUID || !third.PolicyReady || third.AssignmentsReady {
			t.Fatalf("stable reconcile did not return persisted policy state: %#v", third)
		}
		pool = fixture.pool(t)
		if got := pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID]; got != createdUUID {
			t.Fatalf("promoted firewall UUID = %q, want %q", got, createdUUID)
		}
		for _, key := range []string{
			annotationNodeLoadBalancerShardFWPendingHash,
			annotationNodeLoadBalancerShardFWPendingLedger,
			annotationNodeLoadBalancerShardFWPendingAt,
			annotationNodeLoadBalancerShardFWIssuedAt,
			annotationNodeLoadBalancerShardFWPendingUUID,
		} {
			if pool.GetAnnotations()[key] != "" {
				t.Fatalf("promotion retained pending annotation %q: %#v", key, pool.GetAnnotations())
			}
		}

		ready := fixture.reconcile(t)
		if ready.Firewall == nil || ready.Firewall.UUID != createdUUID || !ready.PolicyReady || ready.AssignmentsReady {
			t.Fatalf("stable created firewall state = %#v", ready)
		}
		if len(fixture.api.createdFirewalls) != 1 || len(fixture.api.updatedFirewalls) != 0 {
			t.Fatalf("stable readback recreated or updated firewall: creates=%d updates=%d", len(fixture.api.createdFirewalls), len(fixture.api.updatedFirewalls))
		}
	})

	t.Run("adopt exact stable name and preserve UUID", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"existing",
			"11111111-1111-4111-8111-111111111111",
			corev1.ProtocolTCP,
			80,
		))
		desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err != nil || desired == nil {
			t.Fatalf("desired policy = %#v, %v", desired, err)
		}
		fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*desired, aggregateTestFirewallUUID)}

		adopting := fixture.reconcile(t)
		if adopting.Firewall == nil || adopting.Firewall.UUID != aggregateTestFirewallUUID ||
			!adopting.PolicyReady || adopting.AssignmentsReady {
			t.Fatalf("adoption did not return persisted policy state: %#v", adopting)
		}
		adopted := fixture.reconcile(t)
		if adopted.Firewall == nil || adopted.Firewall.UUID != aggregateTestFirewallUUID || !adopted.PolicyReady || adopted.AssignmentsReady {
			t.Fatalf("adopted firewall state = %#v", adopted)
		}
		if len(fixture.api.createdFirewalls) != 0 || len(fixture.api.updatedFirewalls) != 0 {
			t.Fatalf("adoption mutated exact cloud firewall: creates=%d updates=%d", len(fixture.api.createdFirewalls), len(fixture.api.updatedFirewalls))
		}
	})
}

func TestReconcileShardFirewallPolicyExpandsAndShrinksOneFirewallInPlace(t *testing.T) {
	existing := aggregateTestService(
		"existing",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil {
		t.Fatalf("initial desired policy = %#v, %v", desired, err)
	}
	initial := aggregateTestFirewall(*desired, aggregateTestFirewallUUID)
	fixture.api.firewalls = []inspace.Firewall{initial}
	fixture.reconcile(t) // adopt
	ready := fixture.reconcile(t)
	if ready.Firewall == nil || !ready.PolicyReady {
		t.Fatalf("initial adopted state = %#v", ready)
	}
	initialRuleUUID := ready.Firewall.Rules[0].UUID

	newMember := aggregateTestService(
		"new-member",
		"22222222-2222-4222-8222-222222222222",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(newMember.Namespace).Create(
		fixture.ctx,
		newMember,
		metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	pendingExpansion := fixture.reconcile(t)
	if !pendingExpansion.covers(existing) {
		t.Fatal("existing sibling lost applied coverage while expansion was pending")
	}
	if pendingExpansion.covers(newMember) {
		t.Fatal("new member was covered before aggregate PUT readback")
	}
	if pendingExpansion.Firewall == nil || pendingExpansion.Firewall.UUID != aggregateTestFirewallUUID {
		t.Fatalf("pending expansion changed firewall identity: %#v", pendingExpansion)
	}

	fixture.reconcile(t) // issue PUT
	if len(fixture.api.updatedFirewalls) != 1 {
		t.Fatalf("expansion PUT count = %d, want 1", len(fixture.api.updatedFirewalls))
	}
	expansion := fixture.api.updatedFirewalls[0]
	if expansion.Name != initial.EffectiveName() || len(expansion.Rules) != 2 {
		t.Fatalf("expansion PUT = %#v", expansion)
	}
	expandedRules := aggregateTestRulesByKey(expansion.Rules)
	if expandedRules["tcp/80"].UUID != initialRuleUUID || expandedRules["tcp/443"].UUID != "" {
		t.Fatalf("expansion rule identities = %#v", expandedRules)
	}
	fixture.reconcile(t) // promote pending readback
	expanded := fixture.reconcile(t)
	if expanded.Firewall == nil || expanded.Firewall.UUID != aggregateTestFirewallUUID ||
		!expanded.PolicyReady || !expanded.covers(existing) || !expanded.covers(newMember) {
		t.Fatalf("expanded stable state = %#v", expanded)
	}
	if got := aggregateTestRulesByKey(expanded.Firewall.Rules)["tcp/80"].UUID; got != initialRuleUUID {
		t.Fatalf("expanded unchanged rule UUID = %q, want %q", got, initialRuleUUID)
	}

	if err := fixture.provider.kubeClient.CoreV1().Services(newMember.Namespace).Delete(
		fixture.ctx,
		newMember.Name,
		metav1.DeleteOptions{},
	); err != nil {
		t.Fatal(err)
	}
	fixture.reconcile(t) // persist shrink fence
	fixture.reconcile(t) // issue PUT
	if len(fixture.api.updatedFirewalls) != 2 {
		t.Fatalf("total PUT count after shrink = %d, want 2", len(fixture.api.updatedFirewalls))
	}
	shrink := fixture.api.updatedFirewalls[1]
	if len(shrink.Rules) != 1 || nodeLoadBalancerShardFirewallRuleLogicalKey(shrink.Rules[0]) != "tcp/80" ||
		shrink.Rules[0].UUID != initialRuleUUID {
		t.Fatalf("shrink PUT did not retain only the unchanged rule identity: %#v", shrink)
	}
	fixture.reconcile(t) // promote
	shrunk := fixture.reconcile(t)
	if shrunk.Firewall == nil || shrunk.Firewall.UUID != aggregateTestFirewallUUID || !shrunk.PolicyReady || !shrunk.covers(existing) {
		t.Fatalf("shrunk stable state = %#v", shrunk)
	}
	if len(fixture.api.firewalls) != 1 || fixture.api.firewalls[0].UUID != aggregateTestFirewallUUID {
		t.Fatalf("in-place updates replaced firewall identity: %#v", fixture.api.firewalls)
	}
}

func TestEnsureShardFirewallAssignmentsRetainsNotReadyNodeAndDetachesDeletedVM(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())

	node := readyNode("lb-not-ready", "inspace://bkk01/"+aggregateTestVMUUID)
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   aggregateTestShard,
		nodeLoadBalancerReadyLabel:       "true",
	}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, aggregateTestShard)
	node.Status.Conditions[0].Status = corev1.ConditionFalse
	provider.kubeClient = kubefake.NewSimpleClientset(node.DeepCopy())
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	controller := &nodeLoadBalancerController{
		provider: provider,
		nodes:    corelisters.NewNodeLister(nodeIndexer),
	}
	shardFirewallName, err := inspace.NodeLoadBalancerShardFirewallName(provider.config.ClusterID, aggregateTestShard)
	if err != nil {
		t.Fatal(err)
	}
	port := int32(443)
	api.firewalls = append(api.firewalls, inspace.Firewall{
		UUID: aggregateTestFirewallUUID, DisplayName: shardFirewallName,
		BillingAccountID: provider.config.BillingAccountID,
		Rules: []inspace.FirewallRule{{
			Protocol: "tcp", Direction: "inbound", EndpointSpecType: "any",
			PortStart: &port, PortEnd: &port,
		}},
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: aggregateTestVMUUID},
			{ResourceType: "vm", ResourceUUID: aggregateTestStaleVMUUID},
		},
	})
	firewall := *nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, aggregateTestFirewallUUID)

	ready, _, err := controller.ensureShardFirewallAssignments(ctx, aggregateTestShard, firewall)
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("assignment mutation was reported ready before authoritative readback")
	}
	wantUnassign := aggregateTestFirewallUUID + "/" + aggregateTestStaleVMUUID
	if !reflect.DeepEqual(api.unassignedFirewalls, []string{wantUnassign}) {
		t.Fatalf("unassignments = %#v, want only stale deleted VM %q", api.unassignedFirewalls, wantUnassign)
	}
	current := nodeLoadBalancerSafetyFirewallByUUID(t, api.firewalls, aggregateTestFirewallUUID)
	if !firewallAssignedToVM(*current, aggregateTestVMUUID) || firewallAssignedToVM(*current, aggregateTestStaleVMUUID) {
		t.Fatalf("post-reconcile assignments = %#v", current.ResourcesAssigned)
	}

	ready, _, err = controller.ensureShardFirewallAssignments(ctx, aggregateTestShard, *current)
	if err != nil || !ready {
		t.Fatalf("stable NotReady-node assignment readback: ready=%t err=%v", ready, err)
	}
	if len(api.unassignedFirewalls) != 1 {
		t.Fatalf("NotReady node triggered a later detach: %#v", api.unassignedFirewalls)
	}
}

func TestDeleteAggregateShardFirewallValidatesIdentityBeforeCleanup(t *testing.T) {
	service := aggregateTestService(
		"existing",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	)
	plan := nodeLoadBalancerShardPlan{
		Name:   aggregateTestShard,
		Claims: []string{string(service.UID)},
		Ports:  nodeLoadBalancerPortClaimsOrFatal(t, service),
	}
	desired, err := desiredNodeLoadBalancerShardFirewall("unit-test-cluster", 42, plan, []*corev1.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(desired)
	if err != nil {
		t.Fatal(err)
	}
	installDeletingAnchor := func(t *testing.T, provider *Provider) {
		t.Helper()
		pool := nodeLoadBalancerSafetyNodePool(aggregateTestShard, provider.config.ClusterID, "aggregate-cleanup", 1)
		pool = deletingNodeLoadBalancerStateAnchorPool(pool)
		annotations := pool.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[annotationNodeLoadBalancerShardFirewallUUID] = aggregateTestFirewallUUID
		annotations[annotationNodeLoadBalancerShardFirewallHash] = desired.Hash
		annotations[annotationNodeLoadBalancerShardFirewallLedger] = ledger
		pool.SetAnnotations(annotations)
		provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool)
	}
	backdateCleanupProof := func(t *testing.T, provider *Provider) {
		t.Helper()
		resource := provider.dynamicClient.Resource(nodePoolGVR)
		pool, err := resource.Get(context.Background(), aggregateTestShard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations := pool.GetAnnotations()
		annotations[annotationNodeLoadBalancerShardFWCleanupCheck] = time.Now().Add(-2 * nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano)
		pool.SetAnnotations(annotations)
		if _, err := resource.Update(context.Background(), pool, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("foreign billing owner is never mutated", func(t *testing.T) {
		api := &fakeAPI{firewalls: []inspace.Firewall{aggregateTestFirewall(desired, aggregateTestFirewallUUID)}}
		api.firewalls[0].BillingAccountID++
		api.firewalls[0].ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: aggregateTestVMUUID}}
		provider := newTestProvider(t, api)
		installDeletingAnchor(t, provider)
		controller := &nodeLoadBalancerController{provider: provider}
		if _, err := controller.deleteAggregateShardFirewall(context.Background(), aggregateTestShard); err == nil || !strings.Contains(err.Error(), "refuse foreign") {
			t.Fatalf("foreign cleanup error = %v", err)
		}
		if len(api.unassignedFirewalls) != 0 || len(api.deletedFirewalls) != 0 {
			t.Fatalf("foreign firewall was mutated: unassign=%#v delete=%#v", api.unassignedFirewalls, api.deletedFirewalls)
		}
	})

	t.Run("owned identity is detached then deleted", func(t *testing.T) {
		firewall := aggregateTestFirewall(desired, aggregateTestFirewallUUID)
		firewall.ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: aggregateTestVMUUID}}
		api := &fakeAPI{firewalls: []inspace.Firewall{firewall}}
		provider := newTestProvider(t, api)
		installDeletingAnchor(t, provider)
		controller := &nodeLoadBalancerController{provider: provider}

		absent, err := controller.deleteAggregateShardFirewall(context.Background(), aggregateTestShard)
		if err != nil || absent || len(api.unassignedFirewalls) != 1 || len(api.deletedFirewalls) != 0 {
			t.Fatalf("detach step: absent=%t err=%v unassign=%#v delete=%#v", absent, err, api.unassignedFirewalls, api.deletedFirewalls)
		}
		absent, err = controller.deleteAggregateShardFirewall(context.Background(), aggregateTestShard)
		if err != nil || absent || len(api.deletedFirewalls) != 1 {
			t.Fatalf("delete step: absent=%t err=%v delete=%#v", absent, err, api.deletedFirewalls)
		}
		for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
			absent, err = controller.deleteAggregateShardFirewall(context.Background(), aggregateTestShard)
			if err != nil {
				t.Fatalf("absence readback %d: %v", confirmation, err)
			}
			if confirmation < nodeLoadBalancerAbsenceConfirmations && absent {
				t.Fatalf("cleanup finalized after only %d absence confirmations", confirmation)
			}
			if confirmation < nodeLoadBalancerAbsenceConfirmations {
				backdateCleanupProof(t, provider)
			}
		}
		if !absent {
			t.Fatal("cleanup remained pending after three spaced absence confirmations")
		}
	})
}

type aggregateShardFirewallTestFixture struct {
	ctx        context.Context
	shard      string
	api        *fakeAPI
	provider   *Provider
	controller *nodeLoadBalancerController
}

func newAggregateShardFirewallTestFixture(t *testing.T, services ...*corev1.Service) *aggregateShardFirewallTestFixture {
	t.Helper()
	ctx := context.Background()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset()
	for _, service := range services {
		if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Create(
			ctx,
			service.DeepCopy(),
			metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
	}
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared,
		nodeLoadBalancerDefaultPool,
		1,
		nodeLoadBalancerDefaultCPU,
		nodeLoadBalancerDefaultMemoryMiB,
	)
	pool := nodeLoadBalancerSafetyNodePool(aggregateTestShard, provider.config.ClusterID, profile, 1)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool)
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	controller := &nodeLoadBalancerController{
		provider: provider,
		nodes:    corelisters.NewNodeLister(nodeIndexer),
	}
	return &aggregateShardFirewallTestFixture{
		ctx: ctx, shard: aggregateTestShard, api: api, provider: provider, controller: controller,
	}
}

func (fixture *aggregateShardFirewallTestFixture) reconcile(t *testing.T) nodeLoadBalancerShardFirewallState {
	t.Helper()
	state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (fixture *aggregateShardFirewallTestFixture) pool(t *testing.T) interface{ GetAnnotations() map[string]string } {
	t.Helper()
	pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func aggregateTestService(name, uid string, protocol corev1.Protocol, port int32) *corev1.Service {
	service := nodeLoadBalancerTestService(name, uid, protocol, port)
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	service.Annotations[annotationNodeLoadBalancerShard] = aggregateTestShard
	service.Annotations[annotationNodeLoadBalancerDatapathActive] = aggregateTestShard
	service.Annotations[annotationNodeLoadBalancerDatapathStaged] = aggregateTestShard
	hash, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		panic(err)
	}
	service.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy] = hash
	return service
}

func aggregateTestFirewall(policy nodeLoadBalancerShardFirewallPolicy, uuid string) inspace.Firewall {
	rules := append([]inspace.FirewallRule(nil), policy.Request.Rules...)
	for index := range rules {
		rules[index].UUID = fmt.Sprintf("10000000-0000-4000-8000-%012d", index+1)
	}
	return inspace.Firewall{
		UUID:             uuid,
		DisplayName:      policy.Request.DisplayName,
		Description:      policy.Request.Description,
		BillingAccountID: policy.Request.BillingAccountID,
		Rules:            rules,
	}
}

func aggregateTestRulesByKey(rules []inspace.FirewallRule) map[string]inspace.FirewallRule {
	result := make(map[string]inspace.FirewallRule, len(rules))
	for _, rule := range rules {
		result[nodeLoadBalancerShardFirewallRuleLogicalKey(rule)] = rule
	}
	return result
}

func nodeLoadBalancerPortClaimsOrFatal(t *testing.T, service *corev1.Service) []nodeLoadBalancerPortClaim {
	t.Helper()
	claims, err := nodeLoadBalancerPortClaims(service)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}
