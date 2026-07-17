package cloudprovider

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// These tests intentionally exercise the controller entrypoint and durable
// NodePool state. They protect ordering guarantees that helper-only tests can
// miss when several individually safe cloud mutations are composed.

type aggregateHiddenPostCreateFirewallAPI struct {
	*fakeAPI
	hideLists int
}

func (a *aggregateHiddenPostCreateFirewallAPI) CreateFirewall(
	ctx context.Context,
	location string,
	request inspace.CreateFirewallRequest,
) (*inspace.Firewall, error) {
	created, err := a.fakeAPI.CreateFirewall(ctx, location, request)
	if err == nil {
		a.hideLists = 100
	}
	return created, err
}

func (a *aggregateHiddenPostCreateFirewallAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	if a.hideLists > 0 {
		a.hideLists--
		return nil, nil
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func TestAggregateFirstServiceStaysClosedUntilFirewallAssignmentReadback(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-bootstrap-fence",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	))
	defer harness.controller.queue.ShutDown()

	assignmentsBefore := len(harness.api.assignedFirewalls)
	for attempt := 0; attempt < 48; attempt++ {
		harness.syncOne(t)
		if len(harness.api.assignedFirewalls) == assignmentsBefore {
			harness.requireClosed(t)
			continue
		}
		if got := len(harness.api.assignedFirewalls) - assignmentsBefore; got != 1 {
			t.Fatalf("bootstrap aggregate assignment calls = %d, want exactly 1", got)
		}
		// AssignFirewallToVM returning is not authoritative readback. The Node
		// and Cilium child must remain closed until a later reconciliation Lists
		// the assignment and validates it against the same firewall identity.
		harness.requireClosed(t)
		return
	}
	t.Fatal("aggregate bootstrap never issued its firewall assignment")
}

func TestAggregateSourceRangeEditStaysClosedUntilNewLedgerIsApplied(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-source-edit",
		"22222222-2222-4222-8222-222222222222",
		corev1.ProtocolTCP,
		443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	service := harness.service(t)
	service.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
	updated, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Update(updated.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	newPolicyHash, err := desiredNodeLoadBalancerServicePolicyHash(updated)
	if err != nil {
		t.Fatal(err)
	}

	applied := false
	for attempt := 0; attempt < 48; attempt++ {
		harness.syncOne(t)
		applied = harness.appliedLedgerCovers(t, updated.UID, newPolicyHash)
		if !applied {
			// The edited Service is closed, but the shard-wide eligibility label
			// deliberately remains available to healthy shared siblings.
			harness.requireServiceClosed(t)
			continue
		}
		break
	}
	if !applied {
		t.Fatal("source-range edit never reached the durable applied ledger")
	}

	harness.converge(t)
	firewall := harness.aggregateFirewall(t)
	if len(firewall.Rules) != 1 || firewall.Rules[0].EndpointSpecType != "ip_prefixes" ||
		len(firewall.Rules[0].EndpointSpec) != 1 || firewall.Rules[0].EndpointSpec[0] != "203.0.113.0/24" {
		t.Fatalf("source-range edit did not converge to the exact aggregate rule: %#v", firewall.Rules)
	}
}

func TestAggregateMissingEstablishedAssignmentClosesBeforeSingleAttach(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-assignment-recovery",
		"33333333-3333-4333-8333-333333333333",
		corev1.ProtocolTCP,
		8443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)

	firewall := harness.aggregateFirewall(t)
	for index := range harness.api.firewalls {
		if harness.api.firewalls[index].UUID == firewall.UUID {
			harness.api.firewalls[index].ResourcesAssigned = nil
		}
	}
	assignmentsBefore := len(harness.api.assignedFirewalls)

	// The protected ready label is the first-pass fence: close Kubernetes and
	// Cilium state before attempting to repair the cloud attachment.
	harness.syncOne(t)
	if got := len(harness.api.assignedFirewalls); got != assignmentsBefore {
		t.Fatalf("missing established assignment was repaired before close: before=%d after=%d", assignmentsBefore, got)
	}
	harness.requireClosed(t)

	// The next pass may attach exactly once, but still cannot advertise until a
	// subsequent authoritative List confirms that attachment.
	harness.syncOne(t)
	if got := len(harness.api.assignedFirewalls) - assignmentsBefore; got != 1 {
		t.Fatalf("aggregate recovery assignment calls = %d, want exactly 1", got)
	}
	harness.requireClosed(t)

	harness.converge(t)
	if got := len(harness.api.assignedFirewalls) - assignmentsBefore; got != 1 {
		t.Fatalf("aggregate recovery repeated assignment: calls=%d", got)
	}
}

func TestAggregateCleanupRefusesToDeleteWhenNodePoolAnchorBackfillIsStripped(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-anchor-strip",
		"34343434-3434-4343-8343-343434343434",
		corev1.ProtocolTCP,
		8743,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	service := harness.service(t)
	if !aggregateShardStateWasMaterialized(service.Annotations[annotationNodeLoadBalancerShardStateMaterial], harness.shard) {
		t.Fatalf("converged Service lacks durable shard materialization handoff: %#v", service.Annotations)
	}
	dynamicClient, ok := harness.provider.dynamicClient.(interface {
		PrependReactor(string, string, k8stesting.ReactionFunc)
		Tracker() k8stesting.ObjectTracker
	})
	if !ok {
		t.Fatalf("test dynamic client does not expose reactors and tracker: %T", harness.provider.dynamicClient)
	}
	pool, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(harness.ctx, harness.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stripped := pool.DeepCopy()
	stripped.SetFinalizers(removeString(stripped.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
	if err := dynamicClient.Tracker().Update(nodePoolGVR, stripped, ""); err != nil {
		t.Fatal(err)
	}

	// Model an admission policy that strips every attempted CCM finalizer
	// backfill. Cleanup must detect the failed exact readback before it withdraws
	// the live datapath or mutates any paid cloud resource.
	dynamicClient.PrependReactor("update", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		update, ok := action.(k8stesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		object, ok := update.GetObject().(*unstructured.Unstructured)
		if !ok || object.GetName() != harness.shard {
			return false, nil, nil
		}
		copy := object.DeepCopy()
		copy.SetFinalizers(removeString(copy.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
		if err := dynamicClient.Tracker().Update(nodePoolGVR, copy, ""); err != nil {
			return true, nil, err
		}
		return true, copy, nil
	})

	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
	if _, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)
	createdBefore := len(harness.api.createdFirewalls)
	updatedBefore := len(harness.api.updatedFirewalls)
	deletedBefore := len(harness.api.deletedFirewalls)
	unassignedBefore := len(harness.api.unassignedFirewalls)

	err = harness.controller.sync(harness.ctx, harness.key)
	if err == nil || !strings.Contains(err.Error(), "failed exact state-anchor readback") {
		t.Fatalf("cleanup with stripped NodePool finalizer error = %v", err)
	}
	current := harness.service(t)
	if !containsString(current.Finalizers, nodeLoadBalancerFinalizer) || len(current.Status.LoadBalancer.Ingress) == 0 {
		t.Fatalf("cleanup crossed the anchor fence: finalizers=%#v status=%#v", current.Finalizers, current.Status.LoadBalancer)
	}
	if len(harness.api.createdFirewalls) != createdBefore || len(harness.api.updatedFirewalls) != updatedBefore ||
		len(harness.api.deletedFirewalls) != deletedBefore || len(harness.api.unassignedFirewalls) != unassignedBefore {
		t.Fatalf("cleanup mutated cloud state behind a stripped anchor: creates=%d/%d updates=%d/%d deletes=%d/%d unassigns=%d/%d",
			createdBefore, len(harness.api.createdFirewalls), updatedBefore, len(harness.api.updatedFirewalls),
			deletedBefore, len(harness.api.deletedFirewalls), unassignedBefore, len(harness.api.unassignedFirewalls))
	}
}

func TestAggregateAmbiguousCreateNeverRetriesAndRejectsPendingUUIDConflict(t *testing.T) {
	t.Run("issued create remains permanently fenced across empty reads", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"ambiguous-create",
			"44444444-4444-4444-8444-444444444444",
			corev1.ProtocolTCP,
			9443,
		))

		fixture.reconcile(t) // persist pending policy
		fixture.api.createFirewallErr = errors.New("transport timeout after request write")
		_, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err == nil || !strings.Contains(err.Error(), "transport timeout") {
			t.Fatalf("ambiguous create error = %v", err)
		}
		if len(fixture.api.createdFirewalls) != 1 {
			t.Fatalf("initial create calls = %d, want 1", len(fixture.api.createdFirewalls))
		}
		fixture.api.createFirewallErr = nil
		fixture.api.firewalls = nil // authoritative List is transiently empty
		aggregateSafetySetPoolAnnotation(t, fixture.provider, fixture.shard,
			annotationNodeLoadBalancerShardFWIssuedAt,
			time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout-time.Minute).UTC().Format(time.RFC3339Nano),
		)

		for attempt := 1; attempt <= nodeLoadBalancerAbsenceConfirmations+2; attempt++ {
			state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
			if err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
				t.Fatalf("ambiguous read %d error = %v", attempt, err)
			}
			if state.MutationIssued || len(fixture.api.createdFirewalls) != 1 {
				t.Fatalf("ambiguous read %d retried create: state=%#v creates=%d", attempt, state, len(fixture.api.createdFirewalls))
			}
			pool := fixture.pool(t)
			if got := pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt]; got == "" {
				t.Fatalf("ambiguous read %d cleared durable issued fence", attempt)
			}
			if got := pool.GetAnnotations()[annotationNodeLoadBalancerShardFWCreateAbsent]; got != "" {
				t.Fatalf("ambiguous read %d accumulated unsafe retry evidence %q", attempt, got)
			}
		}
	})

	t.Run("pending UUID conflict is fail closed", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"pending-uuid-conflict",
			"55555555-5555-4555-8555-555555555555",
			corev1.ProtocolTCP,
			10443,
		))
		fixture.reconcile(t)
		fixture.reconcile(t)
		aggregateSafetySetPoolAnnotation(t, fixture.provider, fixture.shard,
			annotationNodeLoadBalancerShardFWPendingUUID,
			"ffffffff-ffff-4fff-8fff-ffffffffffff",
		)

		_, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err == nil || !strings.Contains(err.Error(), "pending shard firewall UUID") {
			t.Fatalf("pending UUID conflict error = %v", err)
		}
		if len(fixture.api.createdFirewalls) != 1 || len(fixture.api.updatedFirewalls) != 0 {
			t.Fatalf("pending UUID conflict mutated cloud state: creates=%d updates=%d", len(fixture.api.createdFirewalls), len(fixture.api.updatedFirewalls))
		}
	})
}

func TestAggregateDeletingShardRetainsAmbiguousCreateUntilLateCommitIsDeleted(t *testing.T) {
	fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
		"ambiguous-delete",
		"56565656-5656-4656-8656-565656565656",
		corev1.ProtocolTCP,
		12443,
	))
	fixture.reconcile(t) // persist staged policy
	fixture.api.createFirewallErr = errors.New("transport timeout after request write")
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil || !strings.Contains(err.Error(), "transport timeout") {
		t.Fatalf("ambiguous create error = %v", err)
	}
	fixture.api.createFirewallErr = nil

	pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deletingAt := metav1.Now()
	pool.SetDeletionTimestamp(&deletingAt)
	if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(fixture.ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= nodeLoadBalancerAbsenceConfirmations+2; attempt++ {
		absent, err := fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
		if err == nil || !strings.Contains(err.Error(), "remains ambiguous during cleanup") || absent {
			t.Fatalf("ambiguous cleanup %d = absent %t, err=%v", attempt, absent, err)
		}
		stored, getErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
			!containsString(stored.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			t.Fatalf("ambiguous cleanup %d released durable fence: annotations=%#v finalizers=%#v", attempt, stored.GetAnnotations(), stored.GetFinalizers())
		}
		if got := stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupAbsent]; got != "" {
			t.Fatalf("ambiguous cleanup %d accumulated unsafe absence proof %q", attempt, got)
		}
	}

	request := fixture.api.createdFirewalls[0]
	const lateUUID = "abababab-abab-4bab-8bab-abababababab"
	fixture.api.firewalls = []inspace.Firewall{{
		UUID: lateUUID, DisplayName: request.DisplayName, Description: request.Description,
		BillingAccountID: request.BillingAccountID, Rules: request.Rules,
	}}
	absent, err := fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
	if err != nil || absent {
		t.Fatalf("late committed firewall observation handoff = absent %t, err=%v", absent, err)
	}
	stored, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupSeen] != lateUUID {
		t.Fatalf("late committed firewall observation was not persisted: %#v", stored.GetAnnotations())
	}
	absent, err = fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
	if err != nil || absent {
		t.Fatalf("late committed firewall delete = absent %t, err=%v", absent, err)
	}
	if len(fixture.api.deletedFirewalls) != 1 || fixture.api.deletedFirewalls[0] != lateUUID {
		t.Fatalf("late committed firewall was not deleted exactly once: %#v", fixture.api.deletedFirewalls)
	}
}

func TestAggregateDeletingShardRetainsReturnedUUIDCreateUntilVisible(t *testing.T) {
	fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
		"returned-uuid-delete",
		"57575757-5757-4757-8757-575757575757",
		corev1.ProtocolTCP,
		13443,
	))
	fixture.reconcile(t) // persist staged policy
	hidden := &aggregateHiddenPostCreateFirewallAPI{fakeAPI: fixture.api}
	fixture.provider.api = hidden
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
		!strings.Contains(err.Error(), "remains ambiguous") {
		t.Fatalf("hidden authoritative create readback = %v", err)
	}
	if len(fixture.api.firewalls) != 1 {
		t.Fatalf("created firewalls = %#v", fixture.api.firewalls)
	}
	lateFirewall := fixture.api.firewalls[0]
	pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFWPendingUUID] != "" ||
		annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
		annotations[annotationNodeLoadBalancerShardFirewallUUID] != "" {
		t.Fatalf("returned UUID create fence = %#v", annotations)
	}
	fixture.api.firewalls = nil // resource is temporarily omitted from List
	deletingAt := metav1.Now()
	pool.SetDeletionTimestamp(&deletingAt)
	if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(fixture.ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	aggregateSafetySetPoolAnnotation(t, fixture.provider, fixture.shard,
		annotationNodeLoadBalancerShardFWIssuedAt,
		time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout-time.Minute).UTC().Format(time.RFC3339Nano),
	)
	for attempt := 1; attempt <= nodeLoadBalancerAbsenceConfirmations+2; attempt++ {
		absent, err := fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
		if err == nil || !strings.Contains(err.Error(), "remains ambiguous during cleanup") || absent {
			t.Fatalf("returned-UUID ambiguous cleanup %d = absent %t, err=%v", attempt, absent, err)
		}
		stored, getErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.GetAnnotations()[annotationNodeLoadBalancerShardFWPendingUUID] != "" ||
			stored.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
			stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupAbsent] != "" {
			t.Fatalf("returned-UUID cleanup %d released durable fence: %#v", attempt, stored.GetAnnotations())
		}
	}

	hidden.hideLists = 0
	fixture.api.firewalls = []inspace.Firewall{lateFirewall}
	absent, err := fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
	if err != nil || absent {
		t.Fatalf("late returned-UUID observation handoff = absent %t, err=%v", absent, err)
	}
	stored, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupSeen] != lateFirewall.UUID {
		t.Fatalf("late returned-UUID observation was not persisted: %#v", stored.GetAnnotations())
	}
	absent, err = fixture.controller.deleteAggregateShardFirewall(fixture.ctx, fixture.shard)
	if err != nil || absent {
		t.Fatalf("late returned-UUID firewall delete = absent %t, err=%v", absent, err)
	}
	if len(fixture.api.deletedFirewalls) != 1 || fixture.api.deletedFirewalls[0] != lateFirewall.UUID {
		t.Fatalf("late returned-UUID firewall was not deleted exactly once: %#v", fixture.api.deletedFirewalls)
	}
}

func TestAggregateAmbiguousPUTNeverReordersAcrossLaterPolicyGeneration(t *testing.T) {
	existing := aggregateTestService(
		"put-existing",
		"67676767-6767-4676-8676-676767676767",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	initialPolicy, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || initialPolicy == nil {
		t.Fatalf("initial policy = %#v, err=%v", initialPolicy, err)
	}
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*initialPolicy, aggregateTestFirewallUUID)}
	fixture.reconcile(t) // adopt
	fixture.reconcile(t) // stable

	memberB := aggregateTestService(
		"put-member-b",
		"68686868-6868-4686-8686-686868686868",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(memberB.Namespace).Create(
		fixture.ctx, memberB, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	policyB, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || policyB == nil {
		t.Fatalf("policy B = %#v, err=%v", policyB, err)
	}
	fixture.reconcile(t) // persist B fence
	fixture.api.updateFirewallErr = errors.New("transport timeout after PUT request write")
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil || !strings.Contains(err.Error(), "transport timeout") {
		t.Fatalf("ambiguous B PUT error = %v", err)
	}
	fixture.api.updateFirewallErr = nil
	if len(fixture.api.updatedFirewalls) != 1 {
		t.Fatalf("initial B PUT calls = %d, want one", len(fixture.api.updatedFirewalls))
	}
	aggregateSafetySetPoolAnnotation(t, fixture.provider, fixture.shard,
		annotationNodeLoadBalancerShardFWIssuedAt,
		time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout-time.Minute).UTC().Format(time.RFC3339Nano),
	)
	for attempt := 1; attempt <= 4; attempt++ {
		_, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err == nil || !strings.Contains(err.Error(), "update issued") || !strings.Contains(err.Error(), "remains ambiguous") {
			t.Fatalf("aged ambiguous B PUT %d error = %v", attempt, err)
		}
		if len(fixture.api.updatedFirewalls) != 1 {
			t.Fatalf("aged ambiguous B PUT %d reissued mutation: %#v", attempt, fixture.api.updatedFirewalls)
		}
	}

	memberC := aggregateTestService(
		"put-member-c",
		"69696969-6969-4696-8696-696969696969",
		corev1.ProtocolUDP,
		8443,
	)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(memberC.Namespace).Create(
		fixture.ctx, memberC, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil || !strings.Contains(err.Error(), "waiting for issued") {
		t.Fatalf("later generation crossed unresolved B fence: %v", err)
	}
	if len(fixture.api.updatedFirewalls) != 1 {
		t.Fatalf("later generation reissued before B readback: %#v", fixture.api.updatedFirewalls)
	}

	// The original B request finally becomes visible. It is promoted before the
	// newer C generation can be staged, leaving no duplicate B request capable
	// of committing after C.
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*policyB, aggregateTestFirewallUUID)}
	promoted, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || promoted.AppliedHash != policyB.Hash {
		t.Fatalf("late B promotion = %#v, err=%v", promoted, err)
	}
	fixture.reconcile(t) // persist C fence
	fixture.reconcile(t) // issue C PUT
	if len(fixture.api.updatedFirewalls) != 2 {
		t.Fatalf("total PUT calls after C = %d, want exactly B then C", len(fixture.api.updatedFirewalls))
	}
	if len(fixture.api.updatedFirewalls[1].Rules) != 3 {
		t.Fatalf("C PUT did not contain the three-member policy: %#v", fixture.api.updatedFirewalls[1].Rules)
	}
}

func TestAggregateCleanupTransientEmptyListRetainsAnchorUntilThreeAbsences(t *testing.T) {
	ctx := context.Background()
	service := aggregateTestService(
		"cleanup-anchor",
		"66666666-6666-4666-8666-666666666666",
		corev1.ProtocolTCP,
		11443,
	)
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
	api := &fakeAPI{} // simulate an empty authoritative firewall List
	provider := newTestProvider(t, api)
	pool := deletingNodeLoadBalancerStateAnchorPool(nodeLoadBalancerSafetyNodePool(
		aggregateTestShard, provider.config.ClusterID, "aggregate-cleanup-regression", 1,
	))
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerShardFirewallUUID] = aggregateTestFirewallUUID
	annotations[annotationNodeLoadBalancerShardFirewallHash] = policy.Hash
	annotations[annotationNodeLoadBalancerShardFirewallLedger] = ledger
	pool.SetAnnotations(annotations)
	dynamicClient := newNodeLoadBalancerTestDynamicClient(pool)
	provider.dynamicClient = dynamicClient
	controller := &nodeLoadBalancerController{provider: provider}

	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			aggregateSafetySetPoolAnnotation(t, provider, aggregateTestShard,
				annotationNodeLoadBalancerShardFWCleanupCheck,
				time.Now().Add(-2*nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano),
			)
		}
		absent, err := controller.deleteAggregateShardFirewall(ctx, aggregateTestShard)
		if err != nil {
			t.Fatalf("cleanup absence confirmation %d: %v", confirmation, err)
		}
		if confirmation < nodeLoadBalancerAbsenceConfirmations {
			if absent {
				t.Fatalf("cleanup completed after only %d absence confirmations", confirmation)
			}
			stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, aggregateTestShard, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !containsString(stored.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
				t.Fatalf("state anchor finalizer cleared after only %d confirmations", confirmation)
			}
			if got := stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupAbsent]; got != strconv.Itoa(confirmation) {
				t.Fatalf("cleanup absence count %d = %q", confirmation, got)
			}
			continue
		}
		if !absent {
			t.Fatal("cleanup remained pending after three spaced absence confirmations")
		}
		stored, getErr := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, aggregateTestShard, metav1.GetOptions{})
		if getErr == nil && (stored.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID] != "" ||
			stored.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupAbsent] != "") {
			t.Fatalf("proven cleanup retained cloud identity state: %#v", stored.GetAnnotations())
		}
		if getErr != nil && !apierrors.IsNotFound(getErr) {
			t.Fatal(getErr)
		}
	}
}

func TestAggregateCrossShardMigrationRetiresOnlyMovedMember(t *testing.T) {
	ctx := context.Background()
	const (
		oldShard = "inlb-0123abcd"
		newShard = "inlb-89abcdef"
	)
	moved := nodeLoadBalancerTestService(
		"migrating-a", "77777777-7777-4777-8777-777777777777", corev1.ProtocolTCP, 80,
	)
	peer := nodeLoadBalancerTestService(
		"remaining-b", "88888888-8888-4888-8888-888888888888", corev1.ProtocolTCP, 443,
	)
	aggregateSafetyStageService(t, moved, newShard)
	moved.Annotations[annotationNodeLoadBalancerPreviousShard] = oldShard
	aggregateSafetyStageService(t, peer, oldShard)

	oldPlan := nodeLoadBalancerShardPlan{
		Name:   oldShard,
		Claims: []string{string(moved.UID), string(peer.UID)},
		Ports:  append(nodeLoadBalancerPortClaimsOrFatal(t, moved), nodeLoadBalancerPortClaimsOrFatal(t, peer)...),
	}
	sortNodeLoadBalancerPorts(oldPlan.Ports)
	oldPolicy, err := desiredNodeLoadBalancerShardFirewall(
		"unit-test-cluster", 42, oldPlan, []*corev1.Service{moved, peer},
	)
	if err != nil {
		t.Fatal(err)
	}
	oldLedger, err := nodeLoadBalancerShardFirewallPolicyLedger(oldPolicy)
	if err != nil {
		t.Fatal(err)
	}
	const oldFirewallUUID = "99999999-9999-4999-8999-999999999999"
	api := &fakeAPI{firewalls: []inspace.Firewall{aggregateTestFirewall(oldPolicy, oldFirewallUUID)}}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(moved.DeepCopy(), peer.DeepCopy())
	profile := nodeLoadBalancerProfileHash(
		nodeLoadBalancerModeShared, nodeLoadBalancerDefaultPool, 1,
		nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB,
	)
	oldPool := nodeLoadBalancerSafetyNodePool(oldShard, provider.config.ClusterID, profile, 1)
	poolAnnotations := oldPool.GetAnnotations()
	if poolAnnotations == nil {
		poolAnnotations = map[string]string{}
	}
	poolAnnotations[annotationNodeLoadBalancerShardFirewallUUID] = oldFirewallUUID
	poolAnnotations[annotationNodeLoadBalancerShardFirewallHash] = oldPolicy.Hash
	poolAnnotations[annotationNodeLoadBalancerShardFirewallLedger] = oldLedger
	oldPool.SetAnnotations(poolAnnotations)
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(oldPool)
	controller := &nodeLoadBalancerController{provider: provider}

	retired := false
	for attempt := 0; attempt < 12; attempt++ {
		current, err := provider.kubeClient.CoreV1().Services(moved.Namespace).Get(ctx, moved.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		retired, err = controller.retireAggregatePreviousShard(ctx, current, oldShard)
		if err != nil {
			t.Fatalf("retire old shard attempt %d: %v", attempt, err)
		}
		stored, err := provider.kubeClient.CoreV1().Services(moved.Namespace).Get(ctx, moved.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !retired && stored.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard {
			t.Fatalf("previous-shard marker cleared before old ledger retired moved UID: %#v", stored.Annotations)
		}
		if retired {
			if stored.Annotations[annotationNodeLoadBalancerPreviousShard] != "" {
				t.Fatalf("retired migration retained previous shard: %#v", stored.Annotations)
			}
			break
		}
	}
	if !retired {
		t.Fatal("cross-shard migration never retired its old membership")
	}

	pool, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, oldShard, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("shared old NodePool was stranded or deleted: %v", err)
	}
	if pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID] != oldFirewallUUID {
		t.Fatalf("old shard firewall identity changed: %#v", pool.GetAnnotations())
	}
	members, err := parseNodeLoadBalancerShardFirewallLedger(pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallLedger])
	if err != nil {
		t.Fatal(err)
	}
	if members[string(moved.UID)] != "" || members[string(peer.UID)] == "" {
		t.Fatalf("old shard ledger after migration = %#v", members)
	}
	if len(api.firewalls) != 1 || api.firewalls[0].UUID != oldFirewallUUID ||
		len(api.deletedFirewalls) != 0 || len(api.unassignedFirewalls) != 0 {
		t.Fatalf("migration replaced or tore down the peer shard: firewalls=%#v deleted=%#v unassigned=%#v", api.firewalls, api.deletedFirewalls, api.unassignedFirewalls)
	}
}

func TestAggregateDeletingProspectiveMigrationDoesNotRequireMissingShardAnchor(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-delete-during-migration",
		"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		corev1.ProtocolTCP,
		12443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)
	harness.ensureDatapathUID(t)

	oldShard := harness.shard
	oldFirewall := harness.aggregateFirewall(t)
	dynamicClient, ok := harness.provider.dynamicClient.(interface {
		PrependReactor(string, string, k8stesting.ReactionFunc)
		Tracker() k8stesting.ObjectTracker
	})
	if !ok {
		t.Fatalf("test dynamic client does not expose reactors and tracker: %T", harness.provider.dynamicClient)
	}
	// The generic object tracker deletes immediately and does not model API
	// finalizers. Preserve a deleting NodePool state anchor until CCM releases
	// its finalizer, matching real apiserver behavior.
	dynamicClient.PrependReactor("delete", nodePoolGVR.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteAction, ok := action.(k8stesting.DeleteAction)
		if !ok {
			return false, nil, nil
		}
		object, err := dynamicClient.Tracker().Get(nodePoolGVR, "", deleteAction.GetName())
		if apierrors.IsNotFound(err) {
			return true, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		pool, ok := object.(*unstructured.Unstructured)
		if !ok {
			return true, nil, nil
		}
		copy := pool.DeepCopy()
		if copy.GetDeletionTimestamp() == nil {
			now := metav1.Now()
			copy.SetDeletionTimestamp(&now)
		}
		return true, nil, dynamicClient.Tracker().Update(nodePoolGVR, copy, "")
	})

	// Changing the shape forces a new dedicated shard. Run exactly one sync:
	// ensureServiceMetadata must persist current=B and previous/active=A, then
	// return before creating B's NodePool.
	service := harness.service(t)
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
	service.Annotations[annotationNodeLoadBalancerCPU] = "2"
	service.Annotations[annotationNodeLoadBalancerMemory] = "4Gi"
	updated, err := harness.provider.kubeClient.CoreV1().Services(service.Namespace).Update(
		harness.ctx, service, metav1.UpdateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.serviceIndexer.Update(updated.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	harness.syncOne(t)
	migrating := harness.service(t)
	newShard := migrating.Annotations[annotationNodeLoadBalancerShard]
	if !isManagedNodeLoadBalancerShardName(newShard) || newShard == oldShard {
		t.Fatalf("profile edit did not persist a prospective replacement shard: old=%q new=%q annotations=%#v", oldShard, newShard, migrating.Annotations)
	}
	if migrating.Annotations[annotationNodeLoadBalancerPreviousShard] != oldShard ||
		migrating.Annotations[annotationNodeLoadBalancerDatapathActive] != oldShard {
		t.Fatalf("migration checkpoint lost the serving shard: %#v", migrating.Annotations)
	}
	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, newShard, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("prospective NodePool %s exists before its creation phase: %v", newShard, err)
	}

	// Keep another finalized owner so this regression stays focused on A/B
	// migration cleanup rather than cluster-wide ICMP teardown.
	survivor := nodeLoadBalancerTestService(
		"aggregate-cleanup-survivor",
		"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
		corev1.ProtocolTCP,
		13443,
	)
	survivor.Finalizers = []string{nodeLoadBalancerFinalizer}
	if _, err := harness.provider.kubeClient.CoreV1().Services(survivor.Namespace).Create(
		harness.ctx, survivor, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)

	deletingAt := metav1.Now()
	migrating.DeletionTimestamp = &deletingAt
	if _, err := harness.provider.kubeClient.CoreV1().Services(migrating.Namespace).Update(
		harness.ctx, migrating, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	harness.fixture.refreshListers(t)

	finalized := false
	for attempt := 0; attempt < 48; attempt++ {
		// Absence confirmations are deliberately spaced in production. Age only
		// the test clock evidence; do not weaken the controller contract.
		if pool, getErr := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
			harness.ctx, oldShard, metav1.GetOptions{},
		); getErr == nil {
			if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWCleanupCheck] != "" {
				aggregateSafetySetPoolAnnotation(
					t, harness.provider, oldShard,
					annotationNodeLoadBalancerShardFWCleanupCheck,
					time.Now().Add(-2*nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano),
				)
			}
			if pool.GetDeletionTimestamp() != nil && !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
				if err := dynamicClient.Tracker().Delete(nodePoolGVR, "", oldShard); err != nil && !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
			}
		} else if !apierrors.IsNotFound(getErr) {
			t.Fatal(getErr)
		}

		if err := harness.controller.sync(harness.ctx, harness.key); err != nil {
			t.Fatalf("cleanup sync attempt %d: %v", attempt, err)
		}
		harness.fixture.refreshListers(t)

		// Once deletion starts, model Karpenter completing the old NodePool's
		// owned capacity teardown. The CCM must then clean its aggregate edge.
		pool, poolErr := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
			harness.ctx, oldShard, metav1.GetOptions{},
		)
		if poolErr == nil && pool.GetDeletionTimestamp() != nil {
			claims, err := harness.provider.dynamicClient.Resource(nodeClaimGVR).List(harness.ctx, metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for index := range claims.Items {
				claim := &claims.Items[index]
				if claim.GetLabels()[karpenterNodePoolLabel] == oldShard {
					if err := harness.provider.dynamicClient.Resource(nodeClaimGVR).Delete(
						harness.ctx, claim.GetName(), metav1.DeleteOptions{},
					); err != nil && !apierrors.IsNotFound(err) {
						t.Fatal(err)
					}
				}
			}
			if node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(
				harness.ctx, harness.nodeName, metav1.GetOptions{},
			); err == nil {
				if err := harness.provider.kubeClient.CoreV1().Nodes().Delete(
					harness.ctx, node.Name, metav1.DeleteOptions{},
				); err != nil && !apierrors.IsNotFound(err) {
					t.Fatal(err)
				}
				if err := harness.fixture.nodeIndexer.Delete(node); err != nil {
					t.Fatal(err)
				}
			} else if !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
		} else if poolErr != nil && !apierrors.IsNotFound(poolErr) {
			t.Fatal(poolErr)
		}

		current, err := harness.provider.kubeClient.CoreV1().Services(migrating.Namespace).Get(
			harness.ctx, migrating.Name, metav1.GetOptions{},
		)
		if apierrors.IsNotFound(err) {
			finalized = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !containsString(current.Finalizers, nodeLoadBalancerFinalizer) {
			finalized = true
			break
		}
	}
	if !finalized {
		current := harness.service(t)
		t.Fatalf("deleting migration did not release its finalizer: %#v", current.ObjectMeta)
	}

	if _, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, newShard, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("cleanup created or retained prospective NodePool %s: %v", newShard, err)
	}
	if pool, err := harness.provider.dynamicClient.Resource(nodePoolGVR).Get(
		harness.ctx, oldShard, metav1.GetOptions{},
	); err == nil && (pool.GetDeletionTimestamp() == nil || containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer)) {
		t.Fatalf("old shard capacity anchor was not released: deletion=%v finalizers=%#v", pool.GetDeletionTimestamp(), pool.GetFinalizers())
	} else if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	for _, firewall := range harness.api.firewalls {
		if firewall.UUID == oldFirewall.UUID {
			t.Fatalf("old aggregate firewall survived migration cleanup: %#v", firewall)
		}
		name, nameErr := inspace.NodeLoadBalancerShardFirewallName(harness.provider.config.ClusterID, newShard)
		if nameErr != nil {
			t.Fatal(nameErr)
		}
		if firewall.EffectiveName() == name {
			t.Fatalf("prospective shard acquired a firewall during deletion: %#v", firewall)
		}
	}
}

type aggregateSafetySyncHarness struct {
	ctx            context.Context
	api            *fakeAPI
	provider       *Provider
	controller     *nodeLoadBalancerController
	fixture        aggregateSyncFixture
	serviceIndexer cache.Indexer
	serviceName    string
	key            string
	shard          string
	nodeName       string
}

func newAggregateSafetySyncHarness(t *testing.T, service *corev1.Service) *aggregateSafetySyncHarness {
	t.Helper()
	ctx := context.Background()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{
		Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1,
	}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())

	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	controller := &nodeLoadBalancerController{
		provider: provider,
		services: corelisters.NewServiceLister(serviceIndexer),
		nodes:    corelisters.NewNodeLister(nodeIndexer),
		queue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	fixture := aggregateSyncFixture{
		ctx: ctx, provider: provider, controller: controller,
		serviceIndexer: serviceIndexer, nodeIndexer: nodeIndexer,
	}
	key := service.Namespace + "/" + service.Name
	fixture.syncUntil(t, []string{key}, 24, func() bool {
		stored := aggregateSafetyService(t, ctx, provider, service.Name)
		shard := stored.Annotations[annotationNodeLoadBalancerShard]
		if shard == "" {
			return false
		}
		_, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		return err == nil
	}, nil)

	stored := aggregateSafetyService(t, ctx, provider, service.Name)
	shard := stored.Annotations[annotationNodeLoadBalancerShard]
	const vmUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	nodeName := "aggregate-safety-lb-0"
	node := readyNode(nodeName, "inspace://bkk01/"+vmUUID)
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	if _, err := provider.kubeClient.CoreV1().Nodes().Create(ctx, node.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	return &aggregateSafetySyncHarness{
		ctx: ctx, api: api, provider: provider, controller: controller, fixture: fixture,
		serviceIndexer: serviceIndexer, serviceName: service.Name, key: key, shard: shard, nodeName: nodeName,
	}
}

func (h *aggregateSafetySyncHarness) syncOne(t *testing.T) {
	t.Helper()
	if err := h.controller.sync(h.ctx, h.key); err != nil {
		t.Fatal(err)
	}
	h.fixture.refreshListers(t)
}

func (h *aggregateSafetySyncHarness) converge(t *testing.T) {
	t.Helper()
	h.fixture.syncUntil(t, []string{h.key}, 64, func() bool {
		node, err := h.provider.kubeClient.CoreV1().Nodes().Get(h.ctx, h.nodeName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return h.fixture.servicePublished(t, h.serviceName) &&
			h.fixture.shardPolicyStable(t, h.shard, 1) &&
			node.Labels[nodeLoadBalancerReadyLabel] == "true"
	}, nil)
}

func (h *aggregateSafetySyncHarness) ensureDatapathUID(t *testing.T) {
	t.Helper()
	parent := h.service(t)
	resource := h.provider.kubeClient.CoreV1().Services(parent.Namespace)
	child, err := resource.Get(h.ctx, nodeLoadBalancerDatapathName(parent), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if child.UID != "" {
		return
	}
	child.UID = types.UID("99999999-1111-4222-8333-555555555555")
	if _, err := resource.Update(h.ctx, child, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (h *aggregateSafetySyncHarness) service(t *testing.T) *corev1.Service {
	t.Helper()
	return aggregateSafetyService(t, h.ctx, h.provider, h.serviceName)
}

func (h *aggregateSafetySyncHarness) requireClosed(t *testing.T) {
	t.Helper()
	h.requireServiceClosed(t)
	node, err := h.provider.kubeClient.CoreV1().Nodes().Get(h.ctx, h.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if node.Labels[nodeLoadBalancerReadyLabel] == "true" {
		t.Fatalf("Node retained datapath-ready label before aggregate readback: %#v", node.Labels)
	}
}

func (h *aggregateSafetySyncHarness) requireServiceClosed(t *testing.T) {
	t.Helper()
	parent := h.service(t)
	if len(parent.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("parent Service advertised before aggregate readback: %#v", parent.Status.LoadBalancer)
	}
	child, err := h.provider.kubeClient.CoreV1().Services(parent.Namespace).Get(
		h.ctx, nodeLoadBalancerDatapathName(parent), metav1.GetOptions{},
	)
	if err == nil && len(child.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("functional Cilium child advertised before aggregate readback: %#v", child.Status.LoadBalancer)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}

func (h *aggregateSafetySyncHarness) aggregateFirewall(t *testing.T) inspace.Firewall {
	t.Helper()
	pool, err := h.provider.dynamicClient.Resource(nodePoolGVR).Get(h.ctx, h.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	uuid := pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID]
	if uuid == "" {
		t.Fatal("shard has no applied aggregate firewall UUID")
	}
	for _, firewall := range h.api.firewalls {
		if firewall.UUID == uuid {
			return firewall
		}
	}
	t.Fatalf("applied aggregate firewall %s is absent", uuid)
	return inspace.Firewall{}
}

func (h *aggregateSafetySyncHarness) appliedLedgerCovers(t *testing.T, uid types.UID, policyHash string) bool {
	t.Helper()
	pool, err := h.provider.dynamicClient.Resource(nodePoolGVR).Get(h.ctx, h.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	members, err := parseNodeLoadBalancerShardFirewallLedger(annotations[annotationNodeLoadBalancerShardFirewallLedger])
	if err != nil || members[string(uid)] != policyHash {
		return false
	}
	uuid := annotations[annotationNodeLoadBalancerShardFirewallUUID]
	for _, firewall := range h.api.firewalls {
		if firewall.UUID != uuid {
			continue
		}
		hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(firewall.Rules)
		return err == nil && hash == annotations[annotationNodeLoadBalancerShardFirewallHash]
	}
	return false
}

func aggregateSafetyService(t *testing.T, ctx context.Context, provider *Provider, name string) *corev1.Service {
	t.Helper()
	service, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func aggregateSafetySetPoolAnnotation(t *testing.T, provider *Provider, shard, key, value string) {
	t.Helper()
	resource := provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(context.Background(), shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	if value == "" {
		delete(annotations, key)
	} else {
		annotations[key] = value
	}
	pool.SetAnnotations(annotations)
	if _, err := resource.Update(context.Background(), pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func aggregateSafetyStageService(t *testing.T, service *corev1.Service, shard string) {
	t.Helper()
	service.Finalizers = []string{nodeLoadBalancerFinalizer}
	if service.Annotations == nil {
		service.Annotations = map[string]string{}
	}
	service.Annotations[annotationNodeLoadBalancerShard] = shard
	service.Annotations[annotationNodeLoadBalancerDatapathActive] = shard
	service.Annotations[annotationNodeLoadBalancerDatapathStaged] = shard
	hash, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy] = hash
}
