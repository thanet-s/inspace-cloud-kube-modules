package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// adoptStoredAnnotation copies an annotation the controller wrote to the stored
// Service into the local copy, like the informer cache catching up.
func adoptStoredAnnotation(t *testing.T, provider *Provider, service *corev1.Service, key string) {
	t.Helper()
	stored, err := provider.standardNLBServiceStore.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := stored.Annotations[key]; ok {
		service.Annotations[key] = value
	}
}

// releaseHeldStandardNLB opts a held Service in to release. The hold records
// the drop time on its first pass; only a release timestamp after it counts.
func releaseHeldStandardNLB(t *testing.T, provider *Provider, service *corev1.Service, nodes []*corev1.Node) {
	t.Helper()
	_, _ = provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	adoptStoredAnnotation(t, provider, service, annotationStandardNLBUnpublishedAt)
	service.Annotations[AnnotationReleasePublicLoadBalancer] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
}

func TestHeldStandardNLBStillReconcilesTargetsAndRules(t *testing.T) {
	api, provider, service, nodes := publishedStandardNLB(t)
	nodes = append(nodes, readyNode("worker-1", "inspace://bkk01/"+testVMUUIDB))
	setStandardNLBKubeNodes(provider, nodes...)
	api.lbs[0].ForwardingRules[0].UUID = "77777777-1111-4222-8333-444444444444"
	delete(service.Labels, LabelLoadBalancerScope)
	service.Spec.Ports[0].NodePort = 30444
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

	converged := func() bool {
		lb := api.lbs[0]
		return len(lb.Targets) == 2 && len(lb.ForwardingRules) == 1 && lb.ForwardingRules[0].TargetPort == 30444
	}
	for range 32 {
		_, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
		if err == nil || !strings.Contains(err.Error(), AnnotationReleasePublicLoadBalancer) {
			t.Fatalf("EnsureLoadBalancer() = %v, want the hold error", err)
		}
		if converged() {
			break
		}
	}
	if !converged() {
		t.Fatalf("held NLB did not follow the Service: targets=%v rules=%v", api.lbs[0].Targets, api.lbs[0].ForwardingRules)
	}
	if len(api.deletedLBs) != 0 || len(api.deletedIPs) != 0 || len(api.floatingIPs) != 1 {
		t.Fatalf("hold deleted resources: LBs=%v IPs=%v", api.deletedLBs, api.deletedIPs)
	}
}

func TestHeldStandardNLBNeverCreatesOrAssignsAnything(t *testing.T) {
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	service := testService()
	delete(service.Labels, LabelLoadBalancerScope)
	nodes := []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)}
	setStandardNLBKubeNodes(provider, nodes...)
	// A lone floating IP (no NLB) is still held, and the hold creates nothing.
	setOwnedLoadBalancer(api, provider, service, []string{testVMUUID})
	api.lbs = nil
	api.floatingIPs[0].AssignedTo, api.floatingIPs[0].AssignedToResourceType, api.floatingIPs[0].AssignedToPrivateIP = "", "", ""
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil {
		t.Fatal("want the hold error")
	}
	if len(api.creates) != 0 || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("hold created or assigned resources: creates=%d fips=%v", len(api.creates), api.floatingIPs)
	}
}

func TestReleaseOptInMustBeNewerThanTheMarkerDrop(t *testing.T) {
	for name, release := range map[string]string{
		"sticky true":     "true",
		"older than drop": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		"malformed":       "yes please",
		"empty":           "",
	} {
		t.Run(name, func(t *testing.T) {
			api, provider, service, nodes := publishedStandardNLB(t)
			service.Annotations[AnnotationReleasePublicLoadBalancer] = release
			delete(service.Labels, LabelLoadBalancerScope)
			syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

			for range 3 {
				if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil ||
					!strings.Contains(err.Error(), AnnotationReleasePublicLoadBalancer) {
					t.Fatalf("EnsureLoadBalancer() = %v, want the hold error", err)
				}
			}
			if len(api.deletedIPs) != 0 || len(api.lbs) != 1 || len(api.floatingIPs) != 1 {
				t.Fatalf("a stale opt-in released the IP: deleteIP=%v LBs=%d FIPs=%d", api.deletedIPs, len(api.lbs), len(api.floatingIPs))
			}
		})
	}
}

func TestRepublishingClearsTheDropMarker(t *testing.T) {
	_, provider, service, nodes := publishedStandardNLB(t)
	delete(service.Labels, LabelLoadBalancerScope)
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err == nil {
		t.Fatal("want the hold error")
	}
	adoptStoredAnnotation(t, provider, service, annotationStandardNLBUnpublishedAt)
	if service.Annotations[annotationStandardNLBUnpublishedAt] == "" {
		t.Fatal("the hold did not record when the markers were dropped")
	}

	service.Labels[LabelLoadBalancerScope] = LoadBalancerScopePublic
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)
	if _, err := provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.standardNLBServiceStore.GetExact(context.Background(), service)
	if err != nil || stored.Annotations[annotationStandardNLBUnpublishedAt] != "" {
		t.Fatalf("drop marker survived republishing: %v %v", err, stored.Annotations)
	}
}

func TestHoldRaisesOneEventAndUpdateStaysQuiet(t *testing.T) {
	_, provider, service, nodes := publishedStandardNLB(t)
	events := record.NewFakeRecorder(16)
	provider.standardNLBEvents = events
	delete(service.Labels, LabelLoadBalancerScope)
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

	for range 3 {
		_, _ = provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
		if err := provider.UpdateLoadBalancer(context.Background(), "ignored", service, nodes); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainEvents(events); len(got) != 1 {
		t.Fatalf("events = %v, want one per state change", got)
	}
}

func TestInFlightCleanupReceiptPassesTheHold(t *testing.T) {
	api, provider, service, nodes := publishedStandardNLB(t)
	delete(service.Labels, LabelLoadBalancerScope)
	syncMemoryStandardNLBServiceIntent(t, provider.standardNLBServiceStore, service)

	// A cleanup that was already issued (the owner had opted in) must be allowed
	// to finish even though the opt-in is gone now.
	hash, err := standardNLBRequestHash(struct {
		Address          string `json:"address"`
		LoadBalancerUUID string `json:"loadBalancerUUID"`
	}{Address: api.floatingIPs[0].Address, LoadBalancerUUID: api.lbs[0].UUID})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := provider.issueStandardNLBRemoval(context.Background(), service, standardNLBMutationFence{
		Operation: standardNLBUnassignFloatingIP, RequestHash: hash,
		ResourceName: api.floatingIPs[0].Address, LoadBalancerUUID: api.lbs[0].UUID,
	}); err != nil {
		t.Fatal(err)
	}

	_, err = provider.EnsureLoadBalancer(context.Background(), "ignored", service, nodes)
	if err == nil || strings.Contains(err.Error(), AnnotationReleasePublicLoadBalancer) {
		t.Fatalf("EnsureLoadBalancer() = %v, want the cleanup to continue past the hold", err)
	}
	if !errors.Is(err, errStandardNLBRemovalPending) {
		t.Fatalf("EnsureLoadBalancer() = %v, want the pending removal of the in-flight receipt", err)
	}
}
