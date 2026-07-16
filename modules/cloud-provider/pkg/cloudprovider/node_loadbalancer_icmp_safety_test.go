package cloudprovider

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestClusterICMPAmbiguousPOSTPermanentlyRetainsOneCreateFence(t *testing.T) {
	ctx, api, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	api.createFirewallErr = errors.New("transport timeout after request write")

	firewall, ready, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
	if err == nil || !strings.Contains(err.Error(), "transport timeout") || firewall != nil || ready {
		t.Fatalf("ambiguous create = firewall %#v, ready=%t, err=%v", firewall, ready, err)
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("ambiguous create calls = %d, want one", len(api.createdFirewalls))
	}
	api.createFirewallErr = nil

	for attempt := 1; attempt <= nodeLoadBalancerAbsenceConfirmations+2; attempt++ {
		firewall, ready, err = controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
		if err == nil || !strings.Contains(err.Error(), "remains ambiguous") || firewall != nil || ready {
			t.Fatalf("ambiguous retry %d = firewall %#v, ready=%t, err=%v", attempt, firewall, ready, err)
		}
		if len(api.createdFirewalls) != 1 {
			t.Fatalf("ambiguous retry %d issued %d creates, want one", attempt, len(api.createdFirewalls))
		}
	}

	done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err == nil || !strings.Contains(err.Error(), "remains ambiguous during cleanup") || done {
		t.Fatalf("ambiguous cleanup = done %t, err=%v", done, err)
	}
	stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if getErr != nil {
		t.Fatal(getErr)
	}
	annotations := stored.GetAnnotations()
	if annotations[annotationNodeLoadBalancerICMPPendingName] == "" ||
		annotations[annotationNodeLoadBalancerICMPPendingStarted] == "" ||
		annotations[annotationNodeLoadBalancerICMPCreateIssued] == "" {
		t.Fatalf("ambiguous cleanup cleared durable create fence: %#v", annotations)
	}
}

const (
	icmpSafetyPersistedUUID   = "11111111-1111-4111-8111-111111111111"
	icmpSafetyReplacementUUID = "22222222-2222-4222-8222-222222222222"
)

func TestClusterICMPPersistedUUIDRejectsSameNameReplacement(t *testing.T) {
	tests := map[string]map[string]string{
		"current UUID": {
			annotationNodeLoadBalancerICMPFirewallUUID: icmpSafetyPersistedUUID,
		},
		"pending UUID": {
			annotationNodeLoadBalancerICMPPendingUUID:    icmpSafetyPersistedUUID,
			annotationNodeLoadBalancerICMPPendingName:    "desired",
			annotationNodeLoadBalancerICMPPendingStarted: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}

	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
			if state[annotationNodeLoadBalancerICMPPendingName] == "desired" {
				state[annotationNodeLoadBalancerICMPPendingName] = desired.Request.DisplayName
			}
			setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, state)
			api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, icmpSafetyReplacementUUID)}

			firewall, ready, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
			if err == nil || !strings.Contains(err.Error(), "different UUID") {
				t.Fatalf("same-name replacement result = firewall %#v, ready=%t, err=%v", firewall, ready, err)
			}
			if len(api.createdFirewalls) != 0 || len(api.deletedFirewalls) != 0 || len(api.assignedFirewalls) != 0 {
				t.Fatalf("identity conflict mutated cloud state: creates=%d deletes=%#v assignments=%#v", len(api.createdFirewalls), api.deletedFirewalls, api.assignedFirewalls)
			}
			stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if getErr != nil {
				t.Fatal(getErr)
			}
			for key, value := range state {
				if got := stored.GetAnnotations()[key]; got != value {
					t.Fatalf("persisted identity %s changed from %q to %q", key, value, got)
				}
			}
		})
	}
}

func TestClusterICMPCleanupNeverDeletesSameNameReplacement(t *testing.T) {
	tests := map[string]map[string]string{
		"current UUID": {
			annotationNodeLoadBalancerICMPFirewallUUID: icmpSafetyPersistedUUID,
		},
		"pending UUID": {
			annotationNodeLoadBalancerICMPPendingUUID:    icmpSafetyPersistedUUID,
			annotationNodeLoadBalancerICMPPendingName:    "desired",
			annotationNodeLoadBalancerICMPPendingStarted: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}

	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
			if state[annotationNodeLoadBalancerICMPPendingName] == "desired" {
				state[annotationNodeLoadBalancerICMPPendingName] = desired.Request.DisplayName
			}
			setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, state)
			api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, icmpSafetyReplacementUUID)}

			done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
			if err == nil || !strings.Contains(err.Error(), "UUID") || done {
				t.Fatalf("same-name cleanup replacement = done %t, err=%v", done, err)
			}
			if len(api.deletedFirewalls) != 0 || len(api.unassignedFirewalls) != 0 {
				t.Fatalf("cleanup touched replacement firewall: deleted=%#v unassigned=%#v", api.deletedFirewalls, api.unassignedFirewalls)
			}
			stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if getErr != nil {
				t.Fatal(getErr)
			}
			for key, value := range state {
				if got := stored.GetAnnotations()[key]; got != value {
					t.Fatalf("cleanup orphaned persisted identity %s: got %q, want %q", key, got, value)
				}
			}
			if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCleanupAbsent] != "" {
				t.Fatalf("identity conflict accumulated absence proof: %#v", stored.GetAnnotations())
			}
		})
	}
}

func TestClusterICMPCleanupRequiresSpacedAbsenceProofBeforeClearingUUID(t *testing.T) {
	ctx, api, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: icmpSafetyPersistedUUID,
	})
	api.firewalls = nil

	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			ageClusterICMPSafetyAnnotation(t, ctx, provider, nodeClassName, annotationNodeLoadBalancerICMPCleanupChecked)
		}
		done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
		if err != nil || done {
			t.Fatalf("absence confirmation %d = done %t, err=%v", confirmation, done, err)
		}
		stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if got := stored.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]; got != icmpSafetyPersistedUUID {
			t.Fatalf("persisted UUID cleared after only %d observations: %q", confirmation, got)
		}
		if got := stored.GetAnnotations()[annotationNodeLoadBalancerICMPCleanupAbsent]; got != strconv.Itoa(confirmation) {
			t.Fatalf("absence count after observation %d = %q", confirmation, got)
		}
	}

	done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil || !done {
		t.Fatalf("proven cleanup absence = done %t, err=%v", done, err)
	}
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]; got != "" {
		t.Fatalf("proven-absent UUID remains: %q", got)
	}
	if len(api.deletedFirewalls) != 0 {
		t.Fatalf("empty-list cleanup issued a delete: %#v", api.deletedFirewalls)
	}
}

func TestClusterICMPCleanupPromotesPendingCreateBeforeDeleteAndCrashRecovery(t *testing.T) {
	ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPPendingUUID:    icmpSafetyPersistedUUID,
		annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
		annotationNodeLoadBalancerICMPPendingStarted: time.Now().UTC().Format(time.RFC3339Nano),
		annotationNodeLoadBalancerICMPCreateIssued:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, icmpSafetyPersistedUUID)}

	done, err := controller.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil || done || len(api.deletedFirewalls) != 0 {
		t.Fatalf("pending cleanup promotion = done %t, err=%v, deletes=%#v", done, err, api.deletedFirewalls)
	}
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := stored.GetAnnotations()
	if annotations[annotationNodeLoadBalancerICMPFirewallUUID] != icmpSafetyPersistedUUID ||
		annotations[annotationNodeLoadBalancerICMPPendingUUID] != "" ||
		annotations[annotationNodeLoadBalancerICMPCreateIssued] != "" {
		t.Fatalf("pending cleanup identity was not durably promoted: %#v", annotations)
	}

	// Model a restart at the handoff: the durable current UUID must authorize
	// exactly one delete and then ordinary spaced absence proof.
	restarted := &nodeLoadBalancerController{provider: provider}
	done, err = restarted.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil || done || len(api.deletedFirewalls) != 1 || api.deletedFirewalls[0] != icmpSafetyPersistedUUID {
		t.Fatalf("promoted cleanup delete = done %t, err=%v, deletes=%#v", done, err, api.deletedFirewalls)
	}
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if confirmation > 1 {
			ageClusterICMPSafetyAnnotation(t, ctx, provider, nodeClassName, annotationNodeLoadBalancerICMPCleanupChecked)
		}
		done, err = restarted.cleanupClusterICMPFirewall(ctx, nodeClassName)
		if err != nil || (confirmation < nodeLoadBalancerAbsenceConfirmations && done) {
			t.Fatalf("post-delete absence %d = done %t, err=%v", confirmation, done, err)
		}
	}
	done, err = restarted.cleanupClusterICMPFirewall(ctx, nodeClassName)
	if err != nil {
		t.Fatal(err)
	}
	if !done {
		t.Fatal("promoted pending cleanup did not complete after spaced absence proof")
	}
}

func TestAggregateRestageMissingICMPAssignmentClosesBeforeRepair(t *testing.T) {
	harness := newAggregateSafetySyncHarness(t, nodeLoadBalancerTestService(
		"aggregate-icmp-restage",
		"77777777-7777-4777-8777-777777777777",
		corev1.ProtocolTCP,
		443,
	))
	defer harness.controller.queue.ShutDown()
	harness.converge(t)

	// Enter the real sole-Service restage state: the first edit pass withdraws
	// both statuses and active/staged markers, then persists only the restage pair.
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
	harness.syncOne(t)
	restaging := harness.service(t)
	if restaging.Annotations[annotationNodeLoadBalancerDatapathActive] != "" ||
		restaging.Annotations[annotationNodeLoadBalancerDatapathRestage] != harness.shard {
		t.Fatalf("edit did not enter status-empty restage: %#v", restaging.Annotations)
	}
	// Reproduce the crash/restart edge precisely: the parent has already stored
	// only its restage marker, while the Node still carries the old ready label.
	node, err := harness.provider.kubeClient.CoreV1().Nodes().Get(harness.ctx, harness.nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	node.Labels[nodeLoadBalancerReadyLabel] = "true"
	node, err = harness.provider.kubeClient.CoreV1().Nodes().Update(harness.ctx, node, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.fixture.nodeIndexer.Update(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	nodeClassName := managedNodeLoadBalancerName(harness.provider.config.ClusterID, "node-lb")
	nodeClass, err := harness.provider.dynamicClient.Resource(nodeClassGVR).Get(harness.ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	icmpUUID := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
	if icmpUUID == "" {
		t.Fatal("restage fixture has no persisted ICMP firewall UUID")
	}
	for index := range harness.api.firewalls {
		if harness.api.firewalls[index].UUID == icmpUUID {
			harness.api.firewalls[index].ResourcesAssigned = nil
		}
	}
	assignmentsBefore := len(harness.api.assignedFirewalls)

	// The first pass cannot attach while the protected ready label remains. It
	// must fail-close cluster eligibility even though this parent has no active marker.
	err = harness.controller.sync(harness.ctx, harness.key)
	if err != nil {
		t.Fatalf("missing restage ICMP assignment close: %v", err)
	}
	harness.fixture.refreshListers(t)
	if len(harness.api.assignedFirewalls) != assignmentsBefore {
		t.Fatalf("ICMP assignment repaired before cluster close: before=%d after=%d", assignmentsBefore, len(harness.api.assignedFirewalls))
	}
	harness.requireClosed(t)

	// Once the close is authoritative, exactly one later pass may attach. Status
	// and eligibility remain closed until another List confirms that assignment.
	err = harness.controller.sync(harness.ctx, harness.key)
	if err != nil {
		t.Fatalf("ICMP repair pass: %v", err)
	}
	harness.fixture.refreshListers(t)
	if got := len(harness.api.assignedFirewalls) - assignmentsBefore; got != 1 {
		t.Fatalf("ICMP repair assignment calls = %d, want 1", got)
	}
	harness.requireClosed(t)
}

func newClusterICMPSafetyFixture(t *testing.T) (
	context.Context,
	*fakeAPI,
	*Provider,
	*nodeLoadBalancerController,
	string,
	desiredNodeLoadBalancerFirewall,
) {
	t.Helper()
	ctx := context.Background()
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeLoadBalancerSafetyBaseNodeClass())
	controller := &nodeLoadBalancerController{provider: provider}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	if err := controller.ensureNodeClass(ctx, nodeClassName); err != nil {
		t.Fatal(err)
	}
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(provider.config.ClusterID, provider.config.BillingAccountID)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, api, provider, controller, nodeClassName, desired
}

func clusterICMPSafetyFirewall(desired desiredNodeLoadBalancerFirewall, uuid string) inspace.Firewall {
	return inspace.Firewall{
		UUID:             uuid,
		DisplayName:      desired.Request.DisplayName,
		Description:      desired.Request.Description,
		BillingAccountID: desired.Request.BillingAccountID,
		Rules:            append([]inspace.FirewallRule(nil), desired.Request.Rules...),
	}
}

func setClusterICMPSafetyAnnotations(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	nodeClassName string,
	values map[string]string,
) {
	t.Helper()
	object, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	for key, value := range values {
		annotations[key] = value
	}
	object.SetAnnotations(annotations)
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, object, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func ageClusterICMPSafetyAnnotation(
	t *testing.T,
	ctx context.Context,
	provider *Provider,
	nodeClassName, key string,
) {
	t.Helper()
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		key: time.Now().Add(-2 * nodeLoadBalancerAbsenceConfirmationDelay).UTC().Format(time.RFC3339Nano),
	})
}
