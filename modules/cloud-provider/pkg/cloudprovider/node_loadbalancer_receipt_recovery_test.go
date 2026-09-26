package cloudprovider

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func ambiguousNodeLoadBalancerMutationError(method string) error {
	return &inspace.APIError{StatusCode: 503, Method: method, Path: "/firewall", Retryable: true}
}

// ageAggregateShardPoolAnnotation moves one spaced-proof timestamp on the
// fixture NodePool far enough into the past for the next observation.
func ageAggregateShardPoolAnnotation(t *testing.T, fixture *aggregateShardFirewallTestFixture, key string) {
	t.Helper()
	resource := fixture.provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations[key] == "" {
		return
	}
	annotations[key] = time.Now().Add(-2 * nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano)
	pool.SetAnnotations(annotations)
	if _, err := resource.Update(fixture.ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// newAggregateShardWithIssuedUpdate returns a fixture whose applied shard
// firewall has an issued, unresolved PUT for a broader two-Service policy.
func newAggregateShardWithIssuedUpdate(t *testing.T) (*aggregateShardFirewallTestFixture, nodeLoadBalancerShardFirewallPolicy, *corev1.Service) {
	t.Helper()
	first := aggregateTestService("issued-update-a", "87878787-8787-4787-8787-878787878787", corev1.ProtocolTCP, 80)
	fixture := newAggregateShardFirewallTestFixture(t, first)
	initial, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || initial == nil {
		t.Fatalf("initial policy = %#v, err=%v", initial, err)
	}
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*initial, aggregateTestFirewallUUID)}
	if state := fixture.reconcile(t); !state.PolicyReady {
		t.Fatalf("initial adoption state = %#v", state)
	}
	second := aggregateTestService("issued-update-b", "88888888-8888-4888-8888-888888888888", corev1.ProtocolUDP, 443)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(second.Namespace).Create(
		fixture.ctx, second, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	fixture.reconcile(t)
	base := fixture.api
	fixture.provider.api = &nodeLoadBalancerPostErrorAPI{fakeAPI: base, updateErr: ambiguousNodeLoadBalancerMutationError("PUT")}
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
		t.Fatal("ambiguous shard update returned no error")
	}
	fixture.provider.api = base
	annotations := fixture.pool(t).GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
		annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
		annotations[annotationNodeLoadBalancerShardFirewallHash] != initial.Hash ||
		len(base.updatedFirewalls) != 1 {
		t.Fatalf("issued update fixture = annotations %#v updates %d", annotations, len(base.updatedFirewalls))
	}
	return fixture, *initial, second
}

func TestShardFirewallAbsenceProofClearsStaleIssuedUpdate(t *testing.T) {
	fixture, _, _ := newAggregateShardWithIssuedUpdate(t)
	// The applied firewall is deleted out of band while the PUT is unresolved.
	fixture.api.firewalls = nil
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err != nil {
			t.Fatalf("absence confirmation %d: %v", confirmation, err)
		}
		ageAggregateShardPoolAnnotation(t, fixture, annotationNodeLoadBalancerShardFWAbsentChecked)
	}
	// The final confirmation clears the proven-absent identity in its pass.
	annotations := fixture.pool(t).GetAnnotations()
	for _, key := range []string{
		annotationNodeLoadBalancerShardFirewallUUID,
		annotationNodeLoadBalancerShardFWIssuedAt,
		annotationNodeLoadBalancerShardFWPendingHash,
		annotationNodeLoadBalancerShardFWPendingLedger,
		annotationNodeLoadBalancerShardFWPendingAt,
	} {
		if annotations[key] != "" {
			t.Fatalf("proven-absent shard firewall retained %s: %#v", key, annotations)
		}
	}
	// The normal create path must now be able to recreate the policy.
	var lastErr error
	for attempt := 0; attempt < 4 && len(fixture.api.createdFirewalls) == 0; attempt++ {
		_, lastErr = fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
		if lastErr != nil && strings.Contains(lastErr.Error(), "remains ambiguous") {
			t.Fatalf("stale update receipt wedged recreation: %v", lastErr)
		}
	}
	if len(fixture.api.createdFirewalls) != 1 {
		t.Fatalf("shard firewall was not recreated: creates=%d err=%v annotations=%#v", len(fixture.api.createdFirewalls), lastErr, fixture.pool(t).GetAnnotations())
	}
}

func TestShardPolicyNotReadyWhileDifferentIssuedUpdateIsUnresolved(t *testing.T) {
	fixture, initial, second := newAggregateShardWithIssuedUpdate(t)
	// The Service that motivated the broader PUT goes away. Desired policy
	// again equals the applied policy, but the issued broader PUT may still
	// commit, so the shard must not report its policy ready.
	if err := fixture.provider.kubeClient.CoreV1().Services(second.Namespace).Delete(
		fixture.ctx, second.Name, metav1.DeleteOptions{},
	); err != nil {
		t.Fatal(err)
	}
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil || desired.Hash != initial.Hash {
		t.Fatalf("desired policy did not return to applied: %#v err=%v", desired, err)
	}
	state, _ := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
	if state.PolicyReady {
		t.Fatalf("shard reported ready while a different issued PUT is unresolved: %#v annotations=%#v", state, fixture.pool(t).GetAnnotations())
	}
}
