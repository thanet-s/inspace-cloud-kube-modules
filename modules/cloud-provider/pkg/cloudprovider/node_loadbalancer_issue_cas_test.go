package cloudprovider

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type nodeLoadBalancerPostIssueFirewallListAPI struct {
	*fakeAPI
	hook func()
}

func (a *nodeLoadBalancerPostIssueFirewallListAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	if a.hook != nil {
		a.hook()
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func TestNodeLoadBalancerFirewallCreateRechecksNameAbsenceAfterIssue(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		label := "owned appears"
		if foreign {
			label = "foreign appears"
		}
		t.Run("service/"+label, func(t *testing.T) {
			ctx := context.Background()
			service := nodeLoadBalancerTestService("post-issue-service", "post-issue-service-uid", corev1.ProtocolTCP, 443)
			base := &fakeAPI{}
			provider := newTestProvider(t, base)
			provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
			controller := &nodeLoadBalancerController{provider: provider}
			desired, err := controller.desiredServiceFirewall(service)
			if err != nil {
				t.Fatal(err)
			}
			api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: base}
			fired := false
			api.hook = func() {
				if fired {
					return
				}
				stored, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
				if getErr != nil || stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" {
					return
				}
				fired = true
				billing := desired.Request.BillingAccountID
				if foreign {
					billing++
				}
				base.firewalls = append(base.firewalls, inspace.Firewall{
					UUID:        "91111111-2222-4333-8444-555555555555",
					DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
					BillingAccountID: billing, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
				})
			}
			provider.api = api

			_, _, _, err = controller.ensureServiceFirewall(ctx, service, nil)
			if foreign {
				if err == nil || !strings.Contains(err.Error(), "became foreign") {
					t.Fatalf("foreign post-issue Service firewall = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !fired || len(base.createdFirewalls) != 0 {
				t.Fatalf("Service post-issue absence fence: fired=%t creates=%d", fired, len(base.createdFirewalls))
			}
			stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if foreign {
				if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" ||
					stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != "" ||
					stored.Annotations[annotationNodeLoadBalancerPendingFWName] != desired.Request.DisplayName {
					t.Fatalf("foreign Service firewall did not reset to staged intent: %#v", stored.Annotations)
				}
			} else if stored.Annotations[annotationNodeLoadBalancerPendingFirewall] != base.firewalls[0].UUID ||
				stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" {
				t.Fatalf("owned Service firewall was not read-only promoted: %#v", stored.Annotations)
			}
		})

		t.Run("shard/"+label, func(t *testing.T) {
			fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
				"post-issue-shard",
				"92222222-2222-4333-8444-555555555555",
				corev1.ProtocolTCP,
				443,
			))
			fixture.reconcile(t)
			desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
			if err != nil || desired == nil {
				t.Fatalf("desired shard firewall = %#v, err=%v", desired, err)
			}
			api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: fixture.api}
			fired := false
			api.hook = func() {
				if fired {
					return
				}
				pool, getErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
					fixture.ctx,
					fixture.shard,
					metav1.GetOptions{},
				)
				if getErr != nil || pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
					return
				}
				fired = true
				billing := desired.Request.BillingAccountID
				if foreign {
					billing++
				}
				fixture.api.firewalls = append(fixture.api.firewalls, inspace.Firewall{
					UUID:        "93333333-2222-4333-8444-555555555555",
					DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
					BillingAccountID: billing, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
				})
			}
			fixture.provider.api = api
			state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
			if foreign {
				if err == nil || !strings.Contains(err.Error(), "became foreign") {
					t.Fatalf("foreign post-issue shard firewall = %v", err)
				}
			} else if err != nil || state.Firewall == nil || !state.PolicyReady {
				t.Fatalf("owned post-issue shard firewall = state %#v, err=%v", state, err)
			}
			if !fired || len(fixture.api.createdFirewalls) != 0 {
				t.Fatalf("shard post-issue absence fence: fired=%t creates=%d", fired, len(fixture.api.createdFirewalls))
			}
			pool := fixture.pool(t)
			if foreign {
				if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
					pool.GetAnnotations()[annotationNodeLoadBalancerShardFWPendingHash] != desired.Hash {
					t.Fatalf("foreign shard firewall did not reset to staged intent: %#v", pool.GetAnnotations())
				}
			} else if pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID] != fixture.api.firewalls[0].UUID ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
				t.Fatalf("owned shard firewall was not read-only promoted: %#v", pool.GetAnnotations())
			}
		})

		t.Run("icmp/"+label, func(t *testing.T) {
			ctx, base, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
			api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: base}
			fired := false
			api.hook = func() {
				if fired {
					return
				}
				nodeClass, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
				if getErr != nil || nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
					return
				}
				fired = true
				billing := desired.Request.BillingAccountID
				if foreign {
					billing++
				}
				base.firewalls = append(base.firewalls, inspace.Firewall{
					UUID:        "94444444-2222-4333-8444-555555555555",
					DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
					BillingAccountID: billing, Rules: append([]inspace.FirewallRule(nil), desired.Request.Rules...),
				})
			}
			provider.api = api
			_, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
			if foreign {
				if err == nil || !strings.Contains(err.Error(), "became foreign") {
					t.Fatalf("foreign post-issue ICMP firewall = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !fired || len(base.createdFirewalls) != 0 {
				t.Fatalf("ICMP post-issue absence fence: fired=%t creates=%d", fired, len(base.createdFirewalls))
			}
			nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if foreign {
				if nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] != "" ||
					nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPPendingName] != desired.Request.DisplayName {
					t.Fatalf("foreign ICMP firewall did not reset to staged intent: %#v", nodeClass.GetAnnotations())
				}
			} else if nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID] != base.firewalls[0].UUID ||
				nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] != "" {
				t.Fatalf("owned ICMP firewall was not read-only promoted: %#v", nodeClass.GetAnnotations())
			}
		})
	}
}

func TestShardFirewallUpdateRechecksAuthorityAfterIssue(t *testing.T) {
	existing := aggregateTestService(
		"update-authority-existing",
		"98888888-2222-4333-8444-555555555555",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil {
		t.Fatalf("initial desired shard firewall = %#v, err=%v", desired, err)
	}
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*desired, aggregateTestFirewallUUID)}
	fixture.reconcile(t)
	fixture.reconcile(t)

	newMember := aggregateTestService(
		"update-authority-new",
		"99999999-2222-4333-8444-555555555555",
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
	fixture.reconcile(t) // persist the pending update policy without cloud I/O

	api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: fixture.api}
	fired := false
	api.hook = func() {
		if fired {
			return
		}
		pool, getErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
			fixture.ctx,
			fixture.shard,
			metav1.GetOptions{},
		)
		if getErr == nil && pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			fired = true
			fixture.api.firewalls[0].BillingAccountID++
		}
	}
	fixture.provider.api = api
	if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
		t.Fatal("post-issue shard firewall drift allowed UpdateFirewall")
	}
	if !fired || len(fixture.api.updatedFirewalls) != 0 {
		t.Fatalf("shard update final authority: fired=%t updates=%d", fired, len(fixture.api.updatedFirewalls))
	}
	pool := fixture.pool(t)
	if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
		pool.GetAnnotations()[annotationNodeLoadBalancerShardFWPendingHash] == "" {
		t.Fatalf("shard update drift did not reset to staged intent: %#v", pool.GetAnnotations())
	}
}

func TestShardFirewallCreateRejectsLivePolicyOrOwnerDeletionAfterIssue(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*aggregateShardFirewallTestFixture, *corev1.Service) error
	}{
		{
			name: "Service policy changed",
			mutate: func(fixture *aggregateShardFirewallTestFixture, service *corev1.Service) error {
				stored, err := fixture.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
					fixture.ctx, service.Name, metav1.GetOptions{},
				)
				if err != nil {
					return err
				}
				stored.Spec.Ports[0].Port++
				_, err = fixture.provider.kubeClient.CoreV1().Services(stored.Namespace).Update(
					fixture.ctx, stored, metav1.UpdateOptions{},
				)
				return err
			},
		},
		{
			name: "NodePool deletion began",
			mutate: func(fixture *aggregateShardFirewallTestFixture, _ *corev1.Service) error {
				pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
					fixture.ctx, fixture.shard, metav1.GetOptions{},
				)
				if err != nil {
					return err
				}
				now := metav1.Now()
				pool.SetDeletionTimestamp(&now)
				_, err = fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
					fixture.ctx, pool, metav1.UpdateOptions{},
				)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := aggregateTestService(
				"post-issue-policy",
				"95555555-2222-4333-8444-555555555555",
				corev1.ProtocolTCP,
				443,
			)
			fixture := newAggregateShardFirewallTestFixture(t, service)
			fixture.reconcile(t) // durable staged create intent only
			api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: fixture.api}
			fired := false
			api.hook = func() {
				if fired {
					return
				}
				pool := fixture.pool(t)
				if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
					return
				}
				fired = true
				if err := test.mutate(fixture, service); err != nil {
					t.Fatalf("post-issue mutation: %v", err)
				}
			}
			fixture.provider.api = api
			state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
			if err == nil || state.MutationIssued {
				t.Fatalf("post-issue create authority = state %#v, err=%v", state, err)
			}
			if !fired || len(fixture.api.createdFirewalls) != 0 {
				t.Fatalf("post-issue drift crossed CreateFirewall: fired=%t creates=%d", fired, len(fixture.api.createdFirewalls))
			}
			if fixture.pool(t).GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
				t.Fatal("rejected create did not reset its issued receipt")
			}
		})
	}
}

func TestShardFirewallUpdateRejectsLiveServicePolicyChangeAfterIssue(t *testing.T) {
	existing := aggregateTestService(
		"post-issue-update-existing",
		"96666666-2222-4333-8444-555555555555",
		corev1.ProtocolTCP,
		80,
	)
	fixture := newAggregateShardFirewallTestFixture(t, existing)
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil {
		t.Fatalf("initial desired shard firewall = %#v, err=%v", desired, err)
	}
	fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*desired, aggregateTestFirewallUUID)}
	fixture.reconcile(t)
	fixture.reconcile(t)

	newMember := aggregateTestService(
		"post-issue-update-new",
		"97777777-2222-4333-8444-555555555555",
		corev1.ProtocolTCP,
		443,
	)
	if _, err := fixture.provider.kubeClient.CoreV1().Services(newMember.Namespace).Create(
		fixture.ctx, newMember, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	fixture.reconcile(t) // stage pending update

	api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: fixture.api}
	fired := false
	api.hook = func() {
		if fired || fixture.pool(t).GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
			return
		}
		fired = true
		stored, getErr := fixture.provider.kubeClient.CoreV1().Services(newMember.Namespace).Get(
			fixture.ctx, newMember.Name, metav1.GetOptions{},
		)
		if getErr != nil {
			t.Fatal(getErr)
		}
		stored.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"}
		if _, updateErr := fixture.provider.kubeClient.CoreV1().Services(stored.Namespace).Update(
			fixture.ctx, stored, metav1.UpdateOptions{},
		); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	fixture.provider.api = api
	state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err == nil || state.MutationIssued {
		t.Fatalf("post-issue update authority = state %#v, err=%v", state, err)
	}
	if !fired || len(fixture.api.updatedFirewalls) != 0 {
		t.Fatalf("post-issue Service drift crossed UpdateFirewall: fired=%t updates=%d", fired, len(fixture.api.updatedFirewalls))
	}
	if fixture.pool(t).GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
		t.Fatal("rejected update did not reset its issued receipt")
	}
}

func TestClusterICMPCreateRejectsNodeClassDeletionAfterIssue(t *testing.T) {
	ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
	api := &nodeLoadBalancerPostIssueFirewallListAPI{fakeAPI: base}
	fired := false
	api.hook = func() {
		if fired {
			return
		}
		nodeClass, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if getErr != nil || nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
			return
		}
		fired = true
		now := metav1.Now()
		nodeClass.SetDeletionTimestamp(&now)
		if _, updateErr := provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, nodeClass, metav1.UpdateOptions{}); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	provider.api = api
	if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil {
		t.Fatal("deleting NodeClass authorized cluster ICMP CreateFirewall")
	}
	if !fired || len(base.createdFirewalls) != 0 {
		t.Fatalf("NodeClass deletion crossed CreateFirewall: fired=%t creates=%d", fired, len(base.createdFirewalls))
	}
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] != "" {
		t.Fatal("rejected ICMP create did not reset its issued receipt")
	}
}

func TestClusterICMPCreateAuthorityRejectsStaleSecondController(t *testing.T) {
	ctx, api, provider, first, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	startedAt := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
		annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
		annotationNodeLoadBalancerICMPPendingStarted: startedAt,
	})

	// Both controller instances hold the same staged snapshot. Only the first
	// exact transition may persist POST authority; the stale controller must
	// observe the issued marker on its fresh read and stop before cloud I/O.
	expectedStaged := map[string]string{
		annotationNodeLoadBalancerICMPFirewallUUID:   "",
		annotationNodeLoadBalancerICMPPendingUUID:    "",
		annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
		annotationNodeLoadBalancerICMPPendingStarted: startedAt,
		annotationNodeLoadBalancerICMPCreateIssued:   "",
	}
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second := &nodeLoadBalancerController{provider: provider}
	attempt := func(controller *nodeLoadBalancerController, issuedAt string) error {
		if _, err := controller.issueManagedNodeClassICMPCreate(ctx, nodeClassName, nodeClass.GetUID(), expectedStaged, issuedAt); err != nil {
			return err
		}
		_, err := controller.provider.api.CreateFirewall(ctx, controller.provider.config.Location, desired.Request)
		return err
	}

	if err := attempt(first, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("first controller issue and POST: %v", err)
	}
	if err := attempt(second, time.Now().Add(time.Millisecond).UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("stale second controller acquired duplicate ICMP create authority")
	}
	if len(api.createdFirewalls) != 1 {
		t.Fatalf("ICMP CreateFirewall POSTs = %d, want exactly one", len(api.createdFirewalls))
	}
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
		t.Fatal("winning ICMP create authority was not retained")
	}
}

func TestFirewallCreateIssueRejectsSameNameOwnerReplacement(t *testing.T) {
	t.Run("cluster ICMP NodeClass", func(t *testing.T) {
		ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
		startedAt := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		setClusterICMPSafetyAnnotations(t, ctx, provider, nodeClassName, map[string]string{
			annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
			annotationNodeLoadBalancerICMPPendingStarted: startedAt,
		})
		resource := provider.dynamicClient.Resource(nodeClassGVR)
		original, err := resource.Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		originalUID := original.GetUID()
		replacement := original.DeepCopy()
		replacement.SetResourceVersion("")
		replacement.SetUID(types.UID("replacement-" + string(originalUID)))
		if err := resource.Delete(ctx, nodeClassName, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := resource.Create(ctx, replacement, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		expectedStaged := map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   "",
			annotationNodeLoadBalancerICMPPendingUUID:    "",
			annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
			annotationNodeLoadBalancerICMPPendingStarted: startedAt,
			annotationNodeLoadBalancerICMPCreateIssued:   "",
		}
		if _, issueErr := controller.issueManagedNodeClassICMPCreate(
			ctx,
			nodeClassName,
			originalUID,
			expectedStaged,
			time.Now().UTC().Format(time.RFC3339Nano),
		); issueErr == nil {
			_, _ = controller.provider.api.CreateFirewall(ctx, controller.provider.config.Location, desired.Request)
			t.Fatal("replacement NodeClass acquired the predecessor's create authority")
		}
		if len(api.createdFirewalls) != 0 {
			t.Fatalf("replacement NodeClass crossed CreateFirewall: %v", api.createdFirewalls)
		}
		stored, err := resource.Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if stored.GetUID() == originalUID ||
			stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] != "" {
			t.Fatalf("replacement NodeClass receipt changed: uid=%q annotations=%#v", stored.GetUID(), stored.GetAnnotations())
		}
	})

	t.Run("shard NodePool", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"replacement-owner",
			"18888888-2222-4333-8444-555555555555",
			corev1.ProtocolTCP,
			443,
		))
		fixture.reconcile(t)
		resource := fixture.provider.dynamicClient.Resource(nodePoolGVR)
		original, err := resource.Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		annotations, err := nodeLoadBalancerShardFirewallAnnotations(original)
		if err != nil {
			t.Fatal(err)
		}
		expectedStaged := nodeLoadBalancerShardFirewallMutationExpected(annotations, "")
		desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err != nil || desired == nil {
			t.Fatalf("desired shard policy = %#v, err=%v", desired, err)
		}
		originalUID := original.GetUID()
		replacement := original.DeepCopy()
		replacement.SetResourceVersion("")
		replacement.SetUID(types.UID("replacement-" + string(originalUID)))
		if err := resource.Delete(fixture.ctx, fixture.shard, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := resource.Create(fixture.ctx, replacement, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, issueErr := fixture.controller.issueShardFirewallMutation(
			fixture.ctx,
			fixture.shard,
			originalUID,
			expectedStaged,
			time.Now().UTC().Format(time.RFC3339Nano),
			true,
		); issueErr == nil {
			_, _ = fixture.controller.provider.api.CreateFirewall(
				fixture.ctx,
				fixture.controller.provider.config.Location,
				desired.Request,
			)
			t.Fatal("replacement NodePool acquired the predecessor's create authority")
		}
		if len(fixture.api.createdFirewalls) != 0 {
			t.Fatalf("replacement NodePool crossed CreateFirewall: %v", fixture.api.createdFirewalls)
		}
		stored, err := resource.Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if stored.GetUID() == originalUID ||
			stored.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
			t.Fatalf("replacement NodePool receipt changed: uid=%q annotations=%#v", stored.GetUID(), stored.GetAnnotations())
		}
	})
}

func TestShardFirewallCreateAuthorityRejectsStaleSecondController(t *testing.T) {
	fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
		"existing",
		"11111111-1111-4111-8111-111111111111",
		corev1.ProtocolTCP,
		80,
	))

	// The first pass persists only the staged policy receipt.
	state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil {
		t.Fatal(err)
	}
	if state.Firewall != nil || state.MutationIssued {
		t.Fatalf("staging pass unexpectedly issued cloud mutation: %#v", state)
	}
	pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(fixture.ctx, fixture.shard, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations, err := nodeLoadBalancerShardFirewallAnnotations(pool)
	if err != nil {
		t.Fatal(err)
	}
	expectedStaged := nodeLoadBalancerShardFirewallMutationExpected(annotations, "")
	desired, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
	if err != nil || desired == nil {
		t.Fatalf("desired shard policy = %#v, err=%v", desired, err)
	}

	second := &nodeLoadBalancerController{provider: fixture.provider, nodes: fixture.controller.nodes}
	attempt := func(controller *nodeLoadBalancerController, issuedAt string) error {
		if _, err := controller.issueShardFirewallMutation(
			fixture.ctx,
			fixture.shard,
			pool.GetUID(),
			expectedStaged,
			issuedAt,
			true,
		); err != nil {
			return err
		}
		_, err := controller.provider.api.CreateFirewall(
			fixture.ctx,
			controller.provider.config.Location,
			desired.Request,
		)
		return err
	}

	if err := attempt(fixture.controller, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("first controller issue and POST: %v", err)
	}
	if err := attempt(second, time.Now().Add(time.Millisecond).UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("stale second controller acquired duplicate shard-firewall create authority")
	}
	if len(fixture.api.createdFirewalls) != 1 {
		t.Fatalf("shard CreateFirewall POSTs = %d, want exactly one", len(fixture.api.createdFirewalls))
	}
}
