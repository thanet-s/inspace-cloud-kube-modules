package cloudprovider

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// These tests model the last aggregate Service staging or issuing the cluster
// ICMP DELETE while its NodeClass stays live because a new Service arrived.

func TestLiveClusterICMPStagedDeleteFenceIsWithdrawn(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	const uuid = "45454545-2222-4333-8444-555555555555"
	base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: uuid,
		annotationNodeLoadBalancerICMPDeleteTarget: uuid,
	})
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err != nil {
		t.Fatalf("staged live delete fence: %v", err)
	}
	annotations := clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
	if annotations[annotationNodeLoadBalancerICMPDeleteTarget] != "" || annotations[annotationNodeLoadBalancerICMPFirewallUUID] != uuid {
		t.Fatalf("staged delete fence was not withdrawn: %#v", annotations)
	}
	firewall, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
	if err != nil || firewall == nil || firewall.UUID != uuid || len(base.deletedFirewalls) != 0 || len(base.createdFirewalls) != 0 {
		t.Fatalf("recovered ICMP ensure = %#v err=%v deletes=%d creates=%d", firewall, err, len(base.deletedFirewalls), len(base.createdFirewalls))
	}
}

func TestLiveClusterICMPIssuedDeleteReadoptsStillListedFirewall(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	const uuid = "56565656-2222-4333-8444-555555555555"
	base.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, uuid)}
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: uuid,
		annotationNodeLoadBalancerICMPDeleteTarget: uuid,
		annotationNodeLoadBalancerICMPDeleteIssued: time.Now().UTC().Format(time.RFC3339Nano),
	})
	// While the DELETE may still be in flight, the fence holds.
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("recent issued delete = %v, want in-flight wait", err)
	}
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPDeleteIssued: time.Now().Add(-nodeLoadBalancerFirewallDeleteResendDelay - time.Second).UTC().Format(time.RFC3339Nano),
	})
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err != nil {
		t.Fatalf("re-adopt still-listed firewall: %v", err)
	}
	annotations := clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
	if annotations[annotationNodeLoadBalancerICMPDeleteTarget] != "" || annotations[annotationNodeLoadBalancerICMPDeleteIssued] != "" ||
		annotations[annotationNodeLoadBalancerICMPFirewallUUID] != uuid {
		t.Fatalf("still-listed firewall was not re-adopted: %#v", annotations)
	}
	firewall, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
	if err != nil || firewall == nil || firewall.UUID != uuid || len(base.createdFirewalls) != 0 {
		t.Fatalf("re-adopted ICMP ensure = %#v err=%v creates=%d", firewall, err, len(base.createdFirewalls))
	}
}

func TestLiveClusterICMPIssuedDeleteRecreatesAfterSpacedAbsence(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	const uuid = "67676767-2222-4333-8444-555555555555"
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID: uuid,
		annotationNodeLoadBalancerICMPDeleteTarget: uuid,
		annotationNodeLoadBalancerICMPDeleteIssued: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	})
	for confirmation := 1; confirmation <= nodeLoadBalancerAbsenceConfirmations; confirmation++ {
		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err != nil {
			t.Fatalf("absence confirmation %d: %v", confirmation, err)
		}
		annotations := clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
		if confirmation < nodeLoadBalancerAbsenceConfirmations {
			if annotations[annotationNodeLoadBalancerICMPDeleteTarget] != uuid {
				t.Fatalf("delete fence retired after only %d absence observations: %#v", confirmation, annotations)
			}
			ageClusterICMPSafetyAnnotation(t, ctx, provider, nodeClassName, annotationNodeLoadBalancerICMPCleanupChecked)
		}
	}
	annotations := clusterICMPLiveFenceAnnotations(t, provider, nodeClassName)
	if annotations[annotationNodeLoadBalancerICMPDeleteTarget] != "" || annotations[annotationNodeLoadBalancerICMPDeleteIssued] != "" ||
		annotations[annotationNodeLoadBalancerICMPFirewallUUID] != "" {
		t.Fatalf("proven-absent delete fence was not retired: %#v", annotations)
	}
	var lastErr error
	for attempt := 0; attempt < 4 && len(base.createdFirewalls) == 0; attempt++ {
		_, _, lastErr = controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
		if lastErr != nil && strings.Contains(lastErr.Error(), "fenced") {
			t.Fatalf("live NodeClass remained fenced: %v", lastErr)
		}
	}
	if len(base.createdFirewalls) != 1 {
		t.Fatalf("cluster ICMP firewall was not recreated: creates=%d err=%v", len(base.createdFirewalls), lastErr)
	}
}

func clusterICMPLiveFenceAnnotations(t *testing.T, provider *Provider, nodeClassName string) map[string]string {
	t.Helper()
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(t.Context(), nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return stored.GetAnnotations()
}
