package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	sparseRecoveryFloatingIP     = "203.0.113.20"
	sparseRecoveryFloatingIPUUID = "dddddddd-4444-4444-8444-eeeeeeeeeeee"
)

type sparseFIPRecoverySnapshot struct {
	floatingIPPresent   bool
	loadBalancerPresent bool
	floatingIPPOSTs     int
	floatingIPDELETEs   int
	loadBalancerDELETEs int
	unexpectedRequests  int
	events              []string
}

// sparseFIPRecoveryAPI models the exact live shape behind the RC10 failure:
// floating-IP creation succeeds with HTTP 200, and every representation omits
// the complete assignment tuple for a clean unassigned address. Both deletes
// commit but return HTTP 500 so the CCM must resolve their durable receipts by
// readback without replaying either mutation.
type sparseFIPRecoveryAPI struct {
	mu sync.Mutex

	floatingIPName   string
	loadBalancerName string

	floatingIPPresent   bool
	loadBalancerPresent bool
	floatingIPPOSTs     int
	floatingIPDELETEs   int
	loadBalancerDELETEs int
	unexpectedRequests  int
	events              []string
}

func (a *sparseFIPRecoveryAPI) snapshot() sparseFIPRecoverySnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return sparseFIPRecoverySnapshot{
		floatingIPPresent:   a.floatingIPPresent,
		loadBalancerPresent: a.loadBalancerPresent,
		floatingIPPOSTs:     a.floatingIPPOSTs,
		floatingIPDELETEs:   a.floatingIPDELETEs,
		loadBalancerDELETEs: a.loadBalancerDELETEs,
		unexpectedRequests:  a.unexpectedRequests,
		events:              append([]string(nil), a.events...),
	}
}

func (a *sparseFIPRecoveryAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	response.Header().Set("Content-Type", "application/json")
	switch {
	case request.Method == http.MethodPost &&
		request.URL.Path == "/v1/bkk01/network/ip_addresses":
		var input inspace.CreateFloatingIPRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
			input.Name != a.floatingIPName || input.BillingAccountID != 42 {
			a.unexpectedRequests++
			writeSparseRecoveryJSON(response, http.StatusBadRequest, map[string]string{"message": "unexpected floating-IP create"})
			return
		}
		a.floatingIPPOSTs++
		a.floatingIPPresent = true
		a.events = append(a.events, "POST floating IP")
		writeSparseRecoveryJSON(response, http.StatusOK, a.floatingIP())
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/bkk01/network/ip_addresses":
		if !a.floatingIPPresent {
			writeSparseRecoveryJSON(response, http.StatusOK, []any{})
			return
		}
		writeSparseRecoveryJSON(response, http.StatusOK, []any{a.floatingIP()})
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/bkk01/network/ip_addresses/"+sparseRecoveryFloatingIP:
		if !a.floatingIPPresent {
			writeSparseRecoveryJSON(response, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		writeSparseRecoveryJSON(response, http.StatusOK, a.floatingIP())
	case request.Method == http.MethodDelete &&
		request.URL.Path == "/v1/bkk01/network/ip_addresses/"+sparseRecoveryFloatingIP:
		a.floatingIPDELETEs++
		a.floatingIPPresent = false
		a.events = append(a.events, "DELETE floating IP")
		writeSparseRecoveryJSON(response, http.StatusInternalServerError, map[string]string{"message": "committed before timeout"})
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/bkk01/network/load_balancers":
		if !a.loadBalancerPresent {
			writeSparseRecoveryJSON(response, http.StatusOK, []any{})
			return
		}
		writeSparseRecoveryJSON(response, http.StatusOK, []any{a.loadBalancer()})
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/bkk01/network/load_balancers/"+testLBUUID:
		if !a.loadBalancerPresent {
			writeSparseRecoveryJSON(response, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		writeSparseRecoveryJSON(response, http.StatusOK, a.loadBalancer())
	case request.Method == http.MethodDelete &&
		request.URL.Path == "/v1/bkk01/network/load_balancers/"+testLBUUID:
		a.loadBalancerDELETEs++
		a.loadBalancerPresent = false
		a.events = append(a.events, "DELETE load balancer")
		writeSparseRecoveryJSON(response, http.StatusInternalServerError, map[string]string{"message": "committed before timeout"})
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v1/bkk01/network/network/"+testNetworkUUID:
		writeSparseRecoveryJSON(response, http.StatusOK, map[string]any{
			"uuid": testNetworkUUID, "name": "e2e-vpc", "is_default": false,
		})
	default:
		a.unexpectedRequests++
		writeSparseRecoveryJSON(response, http.StatusNotFound, map[string]string{"message": "unexpected request"})
	}
}

func (a *sparseFIPRecoveryAPI) floatingIP() map[string]any {
	// Deliberately omit assigned_to, assigned_to_resource_type,
	// assigned_to_private_ip, and unassigned_at. The SDK must corroborate this
	// fully sparse tuple across exact and collection reads before CCM sees it.
	return map[string]any{
		"uuid":               sparseRecoveryFloatingIPUUID,
		"id":                 int64(101),
		"address":            sparseRecoveryFloatingIP,
		"user_id":            int64(7),
		"billing_account_id": int64(42),
		"type":               "public",
		"name":               a.floatingIPName,
		"enabled":            true,
		"is_deleted":         false,
		"is_ipv6":            false,
		"created_at":         "2026-07-17T00:00:00Z",
		"updated_at":         "2026-07-17T00:00:00Z",
	}
}

func (a *sparseFIPRecoveryAPI) loadBalancer() map[string]any {
	return map[string]any{
		"uuid":               testLBUUID,
		"display_name":       a.loadBalancerName,
		"network_uuid":       testNetworkUUID,
		"billing_account_id": int64(42),
		"private_address":    "10.0.0.50",
		"is_deleted":         false,
		"forwarding_rules":   []any{},
		"targets":            []any{},
	}
}

func writeSparseRecoveryJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func TestStandardNLBDeletingServiceRecoversIssuedSparseFloatingIPCreate(t *testing.T) {
	ctx := context.Background()
	apiState := &sparseFIPRecoveryAPI{loadBalancerPresent: true}
	server := httptest.NewServer(apiState)
	t.Cleanup(server.Close)

	api, err := inspace.NewClient(inspace.Options{
		BaseURL: server.URL,
		APIKey:  "literal-loopback-test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := testService()
	store := newMemoryStandardNLBServiceStore()
	provider := newStandardNLBProviderWithStore(t, api, store)
	provider.standardNLBAbsentDelay = 0
	apiState.mu.Lock()
	apiState.floatingIPName = provider.floatingIPName(service)
	apiState.loadBalancerName = provider.loadBalancerName(service)
	apiState.mu.Unlock()

	// Reproduce the committed live POST through the real shared client. A 200
	// response and two fully sparse readbacks must resolve to one authoritative,
	// clean unassigned floating IP.
	created, err := api.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{
		Name:             provider.floatingIPName(service),
		BillingAccountID: 42,
	})
	if err != nil || created == nil || created.Address != sparseRecoveryFloatingIP {
		t.Fatalf("live-shape HTTP 200 floating-IP create = %#v, %v", created, err)
	}

	request := inspace.CreateFloatingIPRequest{
		Name:             provider.floatingIPName(service),
		BillingAccountID: 42,
	}
	requestHash, err := standardNLBRequestHash(request)
	if err != nil {
		t.Fatal(err)
	}
	staged, raw, err := provider.stageStandardNLBMutation(ctx, service, standardNLBMutationFence{
		Operation:    standardNLBCreateFloatingIP,
		RequestHash:  requestHash,
		ResourceName: request.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.issueStandardNLBMutation(ctx, service, staged, raw); err != nil {
		t.Fatal(err)
	}
	assertIssuedStandardNLBFence(t, store, service, standardNLBCreateFloatingIP)

	// Model the Service-controller transition that happened after the committed
	// create but before CCM could clear its durable receipt.
	const cleanupFinalizer = "service.kubernetes.io/load-balancer-cleanup"
	deletingAt := metav1.Now()
	service.DeletionTimestamp = &deletingAt
	service.Finalizers = []string{cleanupFinalizer}
	syncMemoryStandardNLBServiceIntent(t, store, service)

	finished, err := runStockServiceControllerDeleteStep(ctx, provider, service)
	if finished || !errors.Is(err, errStandardNLBRemovalPending) {
		t.Fatalf("first cleanup step = finished %t, err %v; want retained finalizer and pending FIP delete", finished, err)
	}
	first := apiState.snapshot()
	if first.floatingIPPOSTs != 1 || first.floatingIPDELETEs != 1 ||
		first.loadBalancerDELETEs != 0 || first.floatingIPPresent || !first.loadBalancerPresent {
		t.Fatalf("first cleanup cloud state = %#v", first)
	}
	assertSparseRecoveryFence(t, store, service, standardNLBDeleteFloatingIP)
	assertSparseRecoveryFinalizer(t, store, service, cleanupFinalizer)

	finished, err = runStockServiceControllerDeleteStep(ctx, provider, service)
	if finished || !errors.Is(err, errStandardNLBRemovalPending) {
		t.Fatalf("second cleanup step = finished %t, err %v; want retained finalizer and pending NLB delete", finished, err)
	}
	second := apiState.snapshot()
	if second.floatingIPPOSTs != 1 || second.floatingIPDELETEs != 1 ||
		second.loadBalancerDELETEs != 1 || second.floatingIPPresent || second.loadBalancerPresent {
		t.Fatalf("second cleanup cloud state = %#v", second)
	}
	assertSparseRecoveryFence(t, store, service, standardNLBDeleteLoadBalancer)
	assertSparseRecoveryFinalizer(t, store, service, cleanupFinalizer)

	// GetLoadBalancer must keep exists=true for the still-issued delete receipt,
	// allowing its second exact absence observation instead of letting the stock
	// controller bypass provider cleanup and remove the finalizer early.
	finished, err = runStockServiceControllerDeleteStep(ctx, provider, service)
	if finished || err != nil {
		t.Fatalf("receipt-resolution cleanup step = finished %t, err %v", finished, err)
	}
	assertNoStandardNLBFence(t, store, service)
	assertSparseRecoveryFinalizer(t, store, service, cleanupFinalizer)

	finished, err = runStockServiceControllerDeleteStep(ctx, provider, service)
	if !finished || err != nil {
		t.Fatalf("terminal cleanup step = finished %t, err %v", finished, err)
	}
	final := apiState.snapshot()
	if final.floatingIPPOSTs != 1 || final.floatingIPDELETEs != 1 ||
		final.loadBalancerDELETEs != 1 || final.unexpectedRequests != 0 {
		t.Fatalf("terminal mutation counts = %#v", final)
	}
	if want := []string{"POST floating IP", "DELETE floating IP", "DELETE load balancer"}; !reflect.DeepEqual(final.events, want) {
		t.Fatalf("cloud mutation order = %v, want %v", final.events, want)
	}
}

func assertSparseRecoveryFence(
	t *testing.T,
	store standardNLBServiceStore,
	service *corev1.Service,
	operation string,
) {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := parseStandardNLBFence(current.Annotations[annotationStandardNLBMutation])
	if err != nil {
		t.Fatal(err)
	}
	if fence == nil || fence.Operation != operation || fence.Phase != standardNLBPhaseIssued ||
		fence.AbsenceObservedAt == "" {
		t.Fatalf("recovered deletion fence = %#v, want issued %s with exact absence evidence", fence, operation)
	}
}

func assertSparseRecoveryFinalizer(
	t *testing.T,
	store standardNLBServiceStore,
	service *corev1.Service,
	finalizer string,
) {
	t.Helper()
	current, err := store.GetExact(context.Background(), service)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(current.Finalizers, finalizer) {
		t.Fatalf("cleanup finalizer was bypassed before provider convergence: %#v", current.Finalizers)
	}
}
