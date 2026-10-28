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

// backdateAggregateShardRejectedCreate moves the issued create receipt and its
// bound rejection marker past the in-flight window.
func backdateAggregateShardRejectedCreate(t *testing.T, fixture *aggregateShardFirewallTestFixture) {
	t.Helper()
	resource := fixture.provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := pool.GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFWCreateRejected] != annotations[annotationNodeLoadBalancerShardFWIssuedAt] {
		t.Fatalf("rejection marker is not bound to the issued receipt: %#v", annotations)
	}
	old := time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	annotations[annotationNodeLoadBalancerShardFWIssuedAt] = old
	annotations[annotationNodeLoadBalancerShardFWCreateRejected] = old
	pool.SetAnnotations(annotations)
	if _, err := resource.Update(fixture.ctx, pool, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestShardFirewallDefinitiveCreateRejectionRetriesAfterSpacedAbsence(t *testing.T) {
	fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
		"shard-create-400", "89898989-8989-4989-8989-898989898989", corev1.ProtocolTCP, 443,
	))
	fixture.reconcile(t)
	base := fixture.api
	fixture.provider.api = &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: definitiveNodeLoadBalancerPostError("POST")}
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
		t.Fatal("rejected shard create returned no error")
	}
	fixture.provider.api = base
	if annotations := fixture.pool(t).GetAnnotations(); annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
		annotations[annotationNodeLoadBalancerShardFWCreateRejected] != annotations[annotationNodeLoadBalancerShardFWIssuedAt] {
		t.Fatalf("definitive rejection was not bound to the issued receipt: %#v", annotations)
	}
	// Inside the in-flight window the receipt stays fenced.
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
		!strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
		t.Fatalf("early rejected-create retry = %v creates=%d", err, len(base.createdFirewalls))
	}
	backdateAggregateShardRejectedCreate(t, fixture)
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		_, _ = fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
		if len(base.createdFirewalls) != 1 {
			t.Fatalf("create replayed before proven absence at confirmation %d", confirmation)
		}
		ageAggregateShardPoolAnnotation(t, fixture, annotationNodeLoadBalancerShardFWCreateChecked)
	}
	if annotations := fixture.pool(t).GetAnnotations(); annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
		annotations[annotationNodeLoadBalancerShardFWCreateRejected] != "" ||
		annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" {
		t.Fatalf("proven-absent rejected create did not return to staged intent: %#v", annotations)
	}
	state := fixture.reconcile(t)
	if len(base.createdFirewalls) != 2 || !state.PolicyReady {
		t.Fatalf("staged intent did not retry create: creates=%d state=%#v", len(base.createdFirewalls), state)
	}
}

func TestShardFirewallAmbiguousCreateErrorStaysFenced(t *testing.T) {
	fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
		"shard-create-503", "8a8a8a8a-8a8a-4a8a-8a8a-8a8a8a8a8a8a", corev1.ProtocolTCP, 443,
	))
	fixture.reconcile(t)
	base := fixture.api
	fixture.provider.api = &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: ambiguousNodeLoadBalancerMutationError("POST")}
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
		t.Fatal("ambiguous shard create returned no error")
	}
	fixture.provider.api = base
	if annotations := fixture.pool(t).GetAnnotations(); annotations[annotationNodeLoadBalancerShardFWCreateRejected] != "" {
		t.Fatalf("ambiguous create was recorded as a definitive rejection: %#v", annotations)
	}
	for _, status := range []int{408, 409, 425, 429, 499, 500, 503} {
		if nodeLoadBalancerCreateDefinitivelyRejected(&inspace.APIError{StatusCode: status}) {
			t.Fatalf("HTTP %d was classified as a definitive create rejection", status)
		}
	}
	if nodeLoadBalancerCreateDefinitivelyRejected(&inspace.APIError{StatusCode: 400, ResponseBodyIncomplete: true}) {
		t.Fatal("incomplete HTTP 400 body was classified as a definitive create rejection")
	}
	if !nodeLoadBalancerCreateDefinitivelyRejected(&inspace.APIError{StatusCode: 422}) {
		t.Fatal("complete HTTP 422 was not classified as a definitive create rejection")
	}
}

func TestClusterICMPDefinitiveCreateRejectionRetriesAfterSpacedAbsence(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	provider.api = &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: definitiveNodeLoadBalancerPostError("POST")}
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil {
		t.Fatal("rejected ICMP create returned no error")
	}
	provider.api = base
	annotations := clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
	issued := annotations[annotationNodeLoadBalancerICMPCreateIssued]
	if issued == "" || annotations[annotationNodeLoadBalancerICMPCreateRejected] != issued {
		t.Fatalf("definitive ICMP rejection was not bound to the issued receipt: %#v", annotations)
	}
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil ||
		!strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
		t.Fatalf("early rejected ICMP retry = %v creates=%d", err, len(base.createdFirewalls))
	}
	old := time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPCreateIssued:   old,
		annotationNodeLoadBalancerICMPCreateRejected: old,
	})
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		_, _, _ = controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
		if len(base.createdFirewalls) != 1 {
			t.Fatalf("ICMP create replayed before proven absence at confirmation %d", confirmation)
		}
		ageClusterICMPSafetyAnnotation(t, ctx, provider, nodeClassName, annotationNodeLoadBalancerICMPAbsentChecked)
	}
	annotations = clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
	if annotations[annotationNodeLoadBalancerICMPCreateIssued] != "" || annotations[annotationNodeLoadBalancerICMPCreateRejected] != "" ||
		annotations[annotationNodeLoadBalancerICMPPendingName] != "" {
		t.Fatalf("proven-absent rejected ICMP create was not discarded: %#v", annotations)
	}
	for attempt := 0; attempt < 3 && len(base.createdFirewalls) == 1; attempt++ {
		_, _, _ = controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
	}
	if len(base.createdFirewalls) != 2 {
		t.Fatalf("discarded ICMP intent did not retry create: creates=%d", len(base.createdFirewalls))
	}
}

func TestServiceFirewallDefinitiveCreateRejectionRetriesAfterSpacedAbsence(t *testing.T) {
	ctx := t.Context()
	service := nodeLoadBalancerTestService("service-create-400", "service-create-400-uid", corev1.ProtocolTCP, 443)
	base := &fakeAPI{}
	provider := newTestProvider(t, &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: definitiveNodeLoadBalancerPostError("POST")})
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil {
		t.Fatal("rejected Service firewall create returned no error")
	}
	provider.api = base
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	token := stored.Annotations[annotationNodeLoadBalancerPendingFWIssued]
	if token == "" || stored.Annotations[annotationNodeLoadBalancerPendingFWRejected] != token {
		t.Fatalf("definitive Service rejection was not bound to the issued token: %#v", stored.Annotations)
	}
	if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err == nil ||
		!strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
		t.Fatalf("early rejected Service retry = %v creates=%d", err, len(base.createdFirewalls))
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] = time.Now().Add(-nodeLoadBalancerShardFirewallMutationTimeout - time.Minute).UTC().Format(time.RFC3339Nano)
	if _, err := provider.kubeClient.CoreV1().Services(stored.Namespace).Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		_, _, _, _ = controller.ensureServiceFirewall(ctx, stored, nil)
		if len(base.createdFirewalls) != 1 {
			t.Fatalf("Service create replayed before proven absence at confirmation %d", confirmation)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
			ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked)
		}
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" || stored.Annotations[annotationNodeLoadBalancerPendingFWRejected] != "" {
		t.Fatalf("proven-absent rejected Service create did not return to staged intent: %#v", stored.Annotations)
	}
	for attempt := 0; attempt < 6 && len(base.createdFirewalls) == 1; attempt++ {
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		_, _, _, _ = controller.ensureServiceFirewall(ctx, stored, nil)
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
			ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked)
		}
	}
	if len(base.createdFirewalls) != 2 {
		t.Fatalf("staged Service intent did not retry create: creates=%d annotations=%#v", len(base.createdFirewalls), stored.Annotations)
	}
}

func ageServiceFirewallIssuedCreate(t *testing.T, ctx context.Context, provider *Provider, service *corev1.Service, age time.Duration) *corev1.Service {
	t.Helper()
	copy := service.DeepCopy()
	copy.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] = time.Now().Add(-age).UTC().Format(time.RFC3339Nano)
	updated, err := provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

// An issued Service firewall create that never becomes visible is released
// after the relation retire delay and two spaced absence readbacks. Before that
// the receipt is kept, so no second paid create can be issued.
func TestServiceFirewallIssuedCreateRetiresAfterRetireDelay(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("service-late-create", "service-late-create-uid", corev1.ProtocolTCP, 443)
	base := &fakeAPI{}
	api := &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: errors.New("connection reset by peer")}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil {
		t.Fatal("the lost create returned no error")
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" || len(base.createdFirewalls) != 1 {
		t.Fatalf("no issued receipt after the lost create: %#v creates=%d", stored.Annotations, len(base.createdFirewalls))
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil)
		if err == nil || !strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
			t.Fatalf("early retry %d: err=%v creates=%d", attempt, err, len(base.createdFirewalls))
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	}

	stored = ageServiceFirewallIssuedCreate(t, ctx, provider, stored, nodeLoadBalancerFirewallRelationRetireDelay+time.Second)
	retired := false
	for attempt := 0; attempt < 6 && !retired; attempt++ {
		if stored.Annotations[annotationNodeLoadBalancerPendingFWChecked] != "" {
			stored = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, stored, annotationNodeLoadBalancerPendingFWChecked)
		}
		_, _, _, _ = controller.ensureServiceFirewall(ctx, stored, nil)
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		retired = stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == ""
		if !retired && len(base.createdFirewalls) != 1 {
			t.Fatalf("a second create was issued before the receipt retired: %d", len(base.createdFirewalls))
		}
	}
	if !retired {
		t.Fatalf("the receipt never retired: %#v", stored.Annotations)
	}
	// The create is issued again, once.
	api.createErr = nil
	for attempt := 0; attempt < 4; attempt++ {
		_, _, _, _ = controller.ensureServiceFirewall(ctx, stored, nil)
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	}
	if len(base.createdFirewalls) != 2 {
		t.Fatalf("creates = %d, want exactly one more", len(base.createdFirewalls))
	}
}
