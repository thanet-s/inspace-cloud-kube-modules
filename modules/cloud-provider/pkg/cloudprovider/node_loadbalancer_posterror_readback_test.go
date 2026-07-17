package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type nodeLoadBalancerPostErrorAPI struct {
	*fakeAPI
	createCommit           bool
	updateCommit           bool
	createErr              error
	updateErr              error
	malformedCreateSuccess bool
	malformedUpdateSuccess bool
	failNextList           bool
	postMutationListErr    error
	hideListsAfterMutation int
	hiddenLists            int
	hiddenSnapshot         []inspace.Firewall
	mutateAfterCreate      func(*fakeAPI)
	mutateAfterUpdate      func(*fakeAPI)
}

func (a *nodeLoadBalancerPostErrorAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	if a.failNextList {
		a.failNextList = false
		return nil, a.postMutationListErr
	}
	if a.hiddenLists > 0 {
		a.hiddenLists--
		return cloneNodeLoadBalancerTestFirewalls(a.hiddenSnapshot), nil
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func (a *nodeLoadBalancerPostErrorAPI) CreateFirewall(
	ctx context.Context,
	location string,
	request inspace.CreateFirewallRequest,
) (*inspace.Firewall, error) {
	before := cloneNodeLoadBalancerTestFirewalls(a.fakeAPI.firewalls)
	var created *inspace.Firewall
	if a.createCommit {
		var err error
		created, err = a.fakeAPI.CreateFirewall(ctx, location, request)
		if err != nil {
			return nil, err
		}
	} else {
		a.fakeAPI.createdFirewalls = append(a.fakeAPI.createdFirewalls, request)
	}
	if a.postMutationListErr != nil {
		a.failNextList = true
	}
	if a.hideListsAfterMutation > 0 {
		a.hiddenLists = a.hideListsAfterMutation
		a.hiddenSnapshot = before
	}
	if a.mutateAfterCreate != nil {
		a.mutateAfterCreate(a.fakeAPI)
	}
	if a.createErr != nil {
		return nil, a.createErr
	}
	if a.malformedCreateSuccess {
		return nil, nil
	}
	return created, nil
}

func (a *nodeLoadBalancerPostErrorAPI) UpdateFirewall(
	ctx context.Context,
	location, uuid string,
	request inspace.UpdateFirewallRequest,
) (*inspace.Firewall, error) {
	before := cloneNodeLoadBalancerTestFirewalls(a.fakeAPI.firewalls)
	var updated *inspace.Firewall
	if a.updateCommit {
		var err error
		updated, err = a.fakeAPI.UpdateFirewall(ctx, location, uuid, request)
		if err != nil {
			return nil, err
		}
	} else {
		a.fakeAPI.updatedFirewalls = append(a.fakeAPI.updatedFirewalls, request)
	}
	if a.postMutationListErr != nil {
		a.failNextList = true
	}
	if a.hideListsAfterMutation > 0 {
		a.hiddenLists = a.hideListsAfterMutation
		a.hiddenSnapshot = before
	}
	if a.mutateAfterUpdate != nil {
		a.mutateAfterUpdate(a.fakeAPI)
	}
	if a.updateErr != nil {
		return nil, a.updateErr
	}
	if a.malformedUpdateSuccess {
		return nil, nil
	}
	return updated, nil
}

func definitiveNodeLoadBalancerPostError(method string) error {
	return &inspace.APIError{
		StatusCode: 400,
		Method:     method,
		Path:       "/firewall",
		Message:    "provider returned an error after accepting the mutation",
	}
}

func TestServiceFirewallHTTPCreateErrorRequiresExactReadback(t *testing.T) {
	for _, test := range []struct {
		name          string
		readErr       error
		malformed     bool
		hiddenLists   int
		wantFirstErr  bool
		wantCommitted bool
	}{
		{name: "hidden committed HTTP 400", wantCommitted: true},
		{name: "hidden committed HTTP 400 with delayed visibility", hiddenLists: 3, wantFirstErr: true, wantCommitted: true},
		{name: "post-error read failure", readErr: errors.New("fresh ListFirewalls failed"), wantFirstErr: true, wantCommitted: true},
		{name: "malformed success response", malformed: true, wantCommitted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service := nodeLoadBalancerTestService("service-readback", "service-readback-uid", corev1.ProtocolTCP, 443)
			base := &fakeAPI{}
			api := &nodeLoadBalancerPostErrorAPI{
				fakeAPI: base, createCommit: test.wantCommitted, postMutationListErr: test.readErr,
				malformedCreateSuccess: test.malformed, hideListsAfterMutation: test.hiddenLists,
			}
			if !test.malformed {
				api.createErr = definitiveNodeLoadBalancerPostError("POST")
			}
			provider := newTestProvider(t, api)
			provider.kubeClient = fake.NewSimpleClientset(service.DeepCopy())
			controller := &nodeLoadBalancerController{provider: provider}

			_, _, _, err := controller.ensureServiceFirewall(ctx, service, nil)
			if test.wantFirstErr != (err != nil) {
				t.Fatalf("first create error = %v, want error %t", err, test.wantFirstErr)
			}
			stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
			if test.readErr != nil && (!strings.Contains(err.Error(), test.readErr.Error()) ||
				stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" ||
				stored.Annotations[annotationNodeLoadBalancerPendingFirewall] != "") {
				t.Fatalf("failed readback released Service create receipt: err=%v annotations=%#v", err, stored.Annotations)
			}
			if test.readErr != nil || test.hiddenLists > 0 {
				resolved := false
				for attempt := 1; attempt <= test.hiddenLists+3; attempt++ {
					_, _, _, reconcileErr := controller.ensureServiceFirewall(ctx, stored, nil)
					stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
					if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" {
						if reconcileErr != nil {
							t.Fatalf("exact Service readback resolved receipt with error: %v", reconcileErr)
						}
						resolved = true
						break
					}
					if reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
						t.Fatalf("delayed Service readback %d crossed receipt: err=%v annotations=%#v creates=%d", attempt, reconcileErr, stored.Annotations, len(base.createdFirewalls))
					}
				}
				if !resolved {
					t.Fatal("Service firewall never became visible within the delayed-readback bound")
				}
			}
			if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" ||
				stored.Annotations[annotationNodeLoadBalancerPendingFirewall] == "" {
				t.Fatalf("exact Service readback did not resolve create receipt: %#v", stored.Annotations)
			}
			if len(base.createdFirewalls) != 1 {
				t.Fatalf("Service create calls = %d, want one", len(base.createdFirewalls))
			}
		})
	}
}

func TestClusterICMPHTTPCreateErrorRequiresExactReadback(t *testing.T) {
	for _, test := range []struct {
		name         string
		readErr      error
		malformed    bool
		hiddenLists  int
		wantFirstErr bool
	}{
		{name: "hidden committed HTTP 400"},
		{name: "hidden committed HTTP 400 with delayed visibility", hiddenLists: 3, wantFirstErr: true},
		{name: "post-error read failure", readErr: errors.New("fresh ICMP ListFirewalls failed"), wantFirstErr: true},
		{name: "malformed success response", malformed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
			api := &nodeLoadBalancerPostErrorAPI{
				fakeAPI: base, createCommit: true, postMutationListErr: test.readErr,
				malformedCreateSuccess: test.malformed, hideListsAfterMutation: test.hiddenLists,
			}
			if !test.malformed {
				api.createErr = definitiveNodeLoadBalancerPostError("POST")
			}
			provider.api = api

			_, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
			if test.wantFirstErr != (err != nil) {
				t.Fatalf("first ICMP create error = %v, want error %t", err, test.wantFirstErr)
			}
			stored, getErr := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
			if getErr != nil {
				t.Fatal(getErr)
			}
			if test.readErr != nil && (!strings.Contains(err.Error(), test.readErr.Error()) ||
				stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" ||
				stored.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID] != "") {
				t.Fatalf("failed readback released ICMP create receipt: err=%v annotations=%#v", err, stored.GetAnnotations())
			}
			if test.readErr != nil || test.hiddenLists > 0 {
				resolved := false
				for attempt := 1; attempt <= test.hiddenLists+5; attempt++ {
					_, _, reconcileErr := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil)
					stored, getErr = provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
					if getErr != nil {
						t.Fatal(getErr)
					}
					if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" {
						if reconcileErr != nil {
							t.Fatalf("exact ICMP readback resolved receipt with error: %v", reconcileErr)
						}
						resolved = true
						break
					}
					if reconcileErr != nil && !strings.Contains(reconcileErr.Error(), "remains ambiguous") {
						t.Fatalf("delayed ICMP readback %d returned unexpected error: %v", attempt, reconcileErr)
					}
					if len(base.createdFirewalls) != 1 {
						t.Fatalf("delayed ICMP readback %d replayed create: %d", attempt, len(base.createdFirewalls))
					}
				}
				if !resolved {
					t.Fatal("ICMP firewall never became visible within the delayed-readback bound")
				}
			}
			annotations := stored.GetAnnotations()
			if annotations[annotationNodeLoadBalancerICMPCreateIssued] != "" ||
				annotations[annotationNodeLoadBalancerICMPFirewallUUID] == "" {
				t.Fatalf("exact ICMP readback did not resolve create receipt: %#v", annotations)
			}
			if len(base.createdFirewalls) != 1 {
				t.Fatalf("ICMP create calls = %d, want one", len(base.createdFirewalls))
			}
		})
	}
}

func TestShardFirewallHTTPCreateErrorRequiresExactReadback(t *testing.T) {
	for _, test := range []struct {
		name         string
		readErr      error
		malformed    bool
		hiddenLists  int
		wantFirstErr bool
	}{
		{name: "hidden committed HTTP 400"},
		{name: "hidden committed HTTP 400 with delayed visibility", hiddenLists: 3, wantFirstErr: true},
		{name: "post-error read failure", readErr: errors.New("fresh shard create ListFirewalls failed"), wantFirstErr: true},
		{name: "malformed success response", malformed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
				"shard-create-readback", "81818181-8181-4181-8181-818181818181", corev1.ProtocolTCP, 443,
			))
			fixture.reconcile(t) // Persist pending policy before allowing the POST.
			api := &nodeLoadBalancerPostErrorAPI{
				fakeAPI: fixture.api, createCommit: true, postMutationListErr: test.readErr,
				malformedCreateSuccess: test.malformed, hideListsAfterMutation: test.hiddenLists,
			}
			if !test.malformed {
				api.createErr = definitiveNodeLoadBalancerPostError("POST")
			}
			fixture.provider.api = api

			state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
			if test.wantFirstErr != (err != nil) {
				t.Fatalf("first shard create error = %v, want error %t", err, test.wantFirstErr)
			}
			pool := fixture.pool(t)
			if test.readErr != nil && (!strings.Contains(err.Error(), test.readErr.Error()) ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID] != "") {
				t.Fatalf("failed readback released shard create receipt: err=%v annotations=%#v", err, pool.GetAnnotations())
			}
			if test.readErr != nil || test.hiddenLists > 0 {
				resolved := false
				for attempt := 1; attempt <= test.hiddenLists+3; attempt++ {
					state, err = fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
					pool = fixture.pool(t)
					if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
						if err != nil {
							t.Fatalf("exact shard create readback resolved receipt with error: %v", err)
						}
						resolved = true
						break
					}
					if err == nil || !strings.Contains(err.Error(), "remains ambiguous") || len(fixture.api.createdFirewalls) != 1 {
						t.Fatalf("delayed shard create readback %d crossed receipt: err=%v annotations=%#v creates=%d", attempt, err, pool.GetAnnotations(), len(fixture.api.createdFirewalls))
					}
				}
				if !resolved {
					t.Fatal("shard firewall create never became visible within the delayed-readback bound")
				}
			}
			if !state.PolicyReady || pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFirewallUUID] == "" {
				t.Fatalf("exact shard create readback did not promote receipt: state=%#v annotations=%#v", state, pool.GetAnnotations())
			}
			if len(fixture.api.createdFirewalls) != 1 {
				t.Fatalf("shard create calls = %d, want one", len(fixture.api.createdFirewalls))
			}
		})
	}
}

func TestShardFirewallHTTPUpdateErrorRequiresExactReadback(t *testing.T) {
	for _, test := range []struct {
		name         string
		readErr      error
		malformed    bool
		hiddenLists  int
		wantFirstErr bool
	}{
		{name: "hidden committed HTTP 400"},
		{name: "hidden committed HTTP 400 with delayed visibility", hiddenLists: 3, wantFirstErr: true},
		{name: "post-error read failure", readErr: errors.New("fresh shard update ListFirewalls failed"), wantFirstErr: true},
		{name: "malformed success response", malformed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := aggregateTestService(
				"shard-update-a", "82828282-8282-4282-8282-828282828282", corev1.ProtocolTCP, 80,
			)
			fixture := newAggregateShardFirewallTestFixture(t, first)
			initial, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
			if err != nil || initial == nil {
				t.Fatalf("initial policy = %#v, err=%v", initial, err)
			}
			fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*initial, aggregateTestFirewallUUID)}
			fixture.reconcile(t) // Adopt the initial policy.

			second := aggregateTestService(
				"shard-update-b", "83838383-8383-4383-8383-838383838383", corev1.ProtocolUDP, 443,
			)
			if _, err := fixture.provider.kubeClient.CoreV1().Services(second.Namespace).Create(
				fixture.ctx, second, metav1.CreateOptions{},
			); err != nil {
				t.Fatal(err)
			}
			fixture.reconcile(t) // Persist the pending replace policy.
			api := &nodeLoadBalancerPostErrorAPI{
				fakeAPI: fixture.api, updateCommit: true, postMutationListErr: test.readErr,
				malformedUpdateSuccess: test.malformed, hideListsAfterMutation: test.hiddenLists,
			}
			if !test.malformed {
				api.updateErr = definitiveNodeLoadBalancerPostError("PUT")
			}
			fixture.provider.api = api

			state, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
			if test.wantFirstErr != (err != nil) {
				t.Fatalf("first shard update error = %v, want error %t", err, test.wantFirstErr)
			}
			pool := fixture.pool(t)
			if test.readErr != nil && (!strings.Contains(err.Error(), test.readErr.Error()) ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "") {
				t.Fatalf("failed readback released shard update receipt: err=%v annotations=%#v", err, pool.GetAnnotations())
			}
			if test.readErr != nil || test.hiddenLists > 0 {
				resolved := false
				for attempt := 1; attempt <= test.hiddenLists+3; attempt++ {
					state, err = fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard)
					pool = fixture.pool(t)
					if pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
						if err != nil {
							t.Fatalf("exact shard update readback resolved receipt with error: %v", err)
						}
						resolved = true
						break
					}
					if err == nil || !strings.Contains(err.Error(), "remains ambiguous") || len(fixture.api.updatedFirewalls) != 1 {
						t.Fatalf("delayed shard update readback %d crossed receipt: err=%v annotations=%#v updates=%d", attempt, err, pool.GetAnnotations(), len(fixture.api.updatedFirewalls))
					}
				}
				if !resolved {
					t.Fatal("shard firewall update never became visible within the delayed-readback bound")
				}
			}
			if !state.PolicyReady || pool.GetAnnotations()[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
				pool.GetAnnotations()[annotationNodeLoadBalancerShardFWPendingHash] != "" {
				t.Fatalf("exact shard update readback did not promote receipt: state=%#v annotations=%#v", state, pool.GetAnnotations())
			}
			if len(fixture.api.updatedFirewalls) != 1 {
				t.Fatalf("shard update calls = %d, want one", len(fixture.api.updatedFirewalls))
			}
		})
	}
}

func TestHTTPFirewallErrorRetainsReceiptAcrossExactUnchangedOrAbsentReadback(t *testing.T) {
	t.Run("Service create absent", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("service-rejected", "service-rejected-uid", corev1.ProtocolTCP, 443)
		base := &fakeAPI{}
		api := &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: definitiveNodeLoadBalancerPostError("POST")}
		provider := newTestProvider(t, api)
		provider.kubeClient = fake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}

		if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil {
			t.Fatal("Service firewall HTTP error returned no error")
		}
		stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" ||
			stored.Annotations[annotationNodeLoadBalancerPendingFWName] == "" {
			t.Fatalf("exact absent Service readback released receipt: %#v", stored.Annotations)
		}
		if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err == nil ||
			!strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
			t.Fatalf("absent Service retry crossed issued fence: err=%v creates=%d", err, len(base.createdFirewalls))
		}
	})

	t.Run("cluster ICMP create absent", func(t *testing.T) {
		ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
		provider.api = &nodeLoadBalancerPostErrorAPI{fakeAPI: base, createErr: definitiveNodeLoadBalancerPostError("POST")}

		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil {
			t.Fatal("ICMP firewall HTTP error returned no error")
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" ||
			stored.GetAnnotations()[annotationNodeLoadBalancerICMPPendingName] == "" {
			t.Fatalf("exact absent ICMP readback released receipt: %#v", stored.GetAnnotations())
		}
		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil ||
			!strings.Contains(err.Error(), "remains ambiguous") || len(base.createdFirewalls) != 1 {
			t.Fatalf("absent ICMP retry crossed issued fence: err=%v creates=%d", err, len(base.createdFirewalls))
		}
	})

	t.Run("shard create absent", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"shard-create-rejected", "84848484-8484-4484-8484-848484848484", corev1.ProtocolTCP, 443,
		))
		fixture.reconcile(t)
		fixture.provider.api = &nodeLoadBalancerPostErrorAPI{
			fakeAPI: fixture.api, createErr: definitiveNodeLoadBalancerPostError("POST"),
		}

		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
			t.Fatal("shard firewall create HTTP error returned no error")
		}
		annotations := fixture.pool(t).GetAnnotations()
		if annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
			annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" {
			t.Fatalf("exact absent shard create readback released receipt: %#v", annotations)
		}
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			!strings.Contains(err.Error(), "remains ambiguous") || len(fixture.api.createdFirewalls) != 1 {
			t.Fatalf("absent shard create retry crossed issued fence: err=%v creates=%d", err, len(fixture.api.createdFirewalls))
		}
	})

	t.Run("shard update unchanged", func(t *testing.T) {
		first := aggregateTestService(
			"shard-update-rejected-a", "85858585-8585-4585-8585-858585858585", corev1.ProtocolTCP, 80,
		)
		fixture := newAggregateShardFirewallTestFixture(t, first)
		initial, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err != nil || initial == nil {
			t.Fatalf("initial policy = %#v, err=%v", initial, err)
		}
		fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*initial, aggregateTestFirewallUUID)}
		fixture.reconcile(t)
		second := aggregateTestService(
			"shard-update-rejected-b", "86868686-8686-4686-8686-868686868686", corev1.ProtocolUDP, 443,
		)
		if _, err := fixture.provider.kubeClient.CoreV1().Services(second.Namespace).Create(
			fixture.ctx, second, metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		fixture.reconcile(t)
		fixture.provider.api = &nodeLoadBalancerPostErrorAPI{
			fakeAPI: fixture.api, updateErr: definitiveNodeLoadBalancerPostError("PUT"),
		}

		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil {
			t.Fatal("shard firewall update HTTP error returned no error")
		}
		annotations := fixture.pool(t).GetAnnotations()
		if annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
			annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
			annotations[annotationNodeLoadBalancerShardFirewallHash] != initial.Hash {
			t.Fatalf("exact unchanged shard update readback released receipt: %#v", annotations)
		}
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			!strings.Contains(err.Error(), "remains ambiguous") || len(fixture.api.updatedFirewalls) != 1 {
			t.Fatalf("unchanged shard update retry crossed issued fence: err=%v updates=%d", err, len(fixture.api.updatedFirewalls))
		}
	})
}

func TestFirewallPostErrorThirdStateRetainsIssuedReceipt(t *testing.T) {
	corruptBilling := func(api *fakeAPI) {
		api.firewalls[len(api.firewalls)-1].BillingAccountID++
	}

	t.Run("Service create", func(t *testing.T) {
		ctx := context.Background()
		service := nodeLoadBalancerTestService("service-third-state", "service-third-state-uid", corev1.ProtocolTCP, 443)
		base := &fakeAPI{}
		api := &nodeLoadBalancerPostErrorAPI{
			fakeAPI: base, createCommit: true, createErr: definitiveNodeLoadBalancerPostError("POST"),
			mutateAfterCreate: corruptBilling,
		}
		provider := newTestProvider(t, api)
		provider.kubeClient = fake.NewSimpleClientset(service.DeepCopy())
		controller := &nodeLoadBalancerController{provider: provider}

		if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil || !strings.Contains(err.Error(), "third-state") {
			t.Fatalf("Service third-state readback error = %v", err)
		}
		stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" || len(base.createdFirewalls) != 1 {
			t.Fatalf("Service third-state released receipt: annotations=%#v creates=%d", stored.Annotations, len(base.createdFirewalls))
		}
		if _, _, _, err := controller.ensureServiceFirewall(ctx, stored, nil); err == nil || len(base.createdFirewalls) != 1 {
			t.Fatalf("Service third-state retry crossed receipt: err=%v creates=%d", err, len(base.createdFirewalls))
		}
	})

	t.Run("cluster ICMP create", func(t *testing.T) {
		ctx, base, provider, controller, nodeClassName, _ := newClusterICMPSafetyFixture(t)
		provider.api = &nodeLoadBalancerPostErrorAPI{
			fakeAPI: base, createCommit: true, createErr: definitiveNodeLoadBalancerPostError("POST"),
			mutateAfterCreate: corruptBilling,
		}

		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil || !strings.Contains(err.Error(), "third-state") {
			t.Fatalf("ICMP third-state readback error = %v", err)
		}
		stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if stored.GetAnnotations()[annotationNodeLoadBalancerICMPCreateIssued] == "" || len(base.createdFirewalls) != 1 {
			t.Fatalf("ICMP third-state released receipt: annotations=%#v creates=%d", stored.GetAnnotations(), len(base.createdFirewalls))
		}
		if _, _, err := controller.ensureClusterICMPFirewall(ctx, nodeClassName, nil); err == nil || len(base.createdFirewalls) != 1 {
			t.Fatalf("ICMP third-state retry crossed receipt: err=%v creates=%d", err, len(base.createdFirewalls))
		}
	})

	t.Run("shard create", func(t *testing.T) {
		fixture := newAggregateShardFirewallTestFixture(t, aggregateTestService(
			"shard-create-third-state", "87878787-8787-4787-8787-878787878787", corev1.ProtocolTCP, 443,
		))
		fixture.reconcile(t)
		fixture.provider.api = &nodeLoadBalancerPostErrorAPI{
			fakeAPI: fixture.api, createCommit: true, createErr: definitiveNodeLoadBalancerPostError("POST"),
			mutateAfterCreate: corruptBilling,
		}

		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			!strings.Contains(err.Error(), "third-state") {
			t.Fatalf("shard create third-state readback error = %v", err)
		}
		annotations := fixture.pool(t).GetAnnotations()
		if annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" || len(fixture.api.createdFirewalls) != 1 {
			t.Fatalf("shard create third-state released receipt: annotations=%#v creates=%d", annotations, len(fixture.api.createdFirewalls))
		}
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			len(fixture.api.createdFirewalls) != 1 {
			t.Fatalf("shard create third-state retry crossed receipt: err=%v creates=%d", err, len(fixture.api.createdFirewalls))
		}
	})

	t.Run("shard update", func(t *testing.T) {
		first := aggregateTestService(
			"shard-update-third-a", "88888888-8888-4888-8888-888888888888", corev1.ProtocolTCP, 80,
		)
		fixture := newAggregateShardFirewallTestFixture(t, first)
		initial, _, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
		if err != nil || initial == nil {
			t.Fatalf("initial policy = %#v, err=%v", initial, err)
		}
		fixture.api.firewalls = []inspace.Firewall{aggregateTestFirewall(*initial, aggregateTestFirewallUUID)}
		fixture.reconcile(t)
		second := aggregateTestService(
			"shard-update-third-b", "89898989-8989-4989-8989-898989898989", corev1.ProtocolUDP, 443,
		)
		if _, err := fixture.provider.kubeClient.CoreV1().Services(second.Namespace).Create(
			fixture.ctx, second, metav1.CreateOptions{},
		); err != nil {
			t.Fatal(err)
		}
		fixture.reconcile(t)
		fixture.provider.api = &nodeLoadBalancerPostErrorAPI{
			fakeAPI: fixture.api, updateCommit: true, updateErr: definitiveNodeLoadBalancerPostError("PUT"),
			mutateAfterUpdate: func(api *fakeAPI) {
				port := int32(8443)
				api.firewalls[0].Rules[0].PortStart = &port
				api.firewalls[0].Rules[0].PortEnd = &port
			},
		}

		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			!strings.Contains(err.Error(), "third policy state") {
			t.Fatalf("shard update third-state readback error = %v", err)
		}
		annotations := fixture.pool(t).GetAnnotations()
		if annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" || len(fixture.api.updatedFirewalls) != 1 {
			t.Fatalf("shard update third-state released receipt: annotations=%#v updates=%d", annotations, len(fixture.api.updatedFirewalls))
		}
		if _, err := fixture.controller.reconcileShardFirewallPolicy(fixture.ctx, fixture.shard); err == nil ||
			len(fixture.api.updatedFirewalls) != 1 {
			t.Fatalf("shard update third-state retry crossed receipt: err=%v updates=%d", err, len(fixture.api.updatedFirewalls))
		}
	})
}
