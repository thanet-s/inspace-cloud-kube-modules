package inspace_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client/internal/testutil/fakeapi"
)

func TestSmoke(t *testing.T) {
	fake := fakeapi.New("test-key")
	t.Cleanup(fake.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: fake.URL(), APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	locations, err := client.ListLocations(ctx)
	if err != nil || len(locations) != 1 || locations[0].Slug != "bkk01" {
		t.Fatalf("ListLocations() = %#v, %v", locations, err)
	}
	pools, err := client.ListHostPools(ctx, "bkk01")
	if err != nil || len(pools) != 1 {
		t.Fatalf("ListHostPools() = %#v, %v", pools, err)
	}
	noPublicIP := false
	created, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
		Name:               "smoke-worker",
		OSName:             "ubuntu",
		OSVersion:          "24.04",
		DiskGiB:            40,
		VCPU:               4,
		MemoryMiB:          8192,
		DesignatedPoolUUID: pools[0].UUID,
		NetworkUUID:        "11111111-2222-3333-4444-555555555555",
		ReservePublicIP:    &noPublicIP,
	})
	if err != nil {
		t.Fatalf("CreateVM(): %v", err)
	}
	if created.UUID != fakeapi.VMUUID || created.VCPU != 4 || created.MemoryMiB != 8192 {
		t.Fatalf("CreateVM() = %#v", created)
	}
	if created.NetworkUUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("CreateVM() network UUID = %q", created.NetworkUUID)
	}
	got, err := client.GetVM(ctx, "bkk01", created.UUID)
	if err != nil || got.UUID != created.UUID {
		t.Fatalf("GetVM() = %#v, %v", got, err)
	}
	vms, err := client.ListVMs(ctx, "bkk01")
	if err != nil || len(vms) != 1 {
		t.Fatalf("ListVMs() = %#v, %v", vms, err)
	}
	if err := client.DeleteVM(ctx, "bkk01", created.UUID); err != nil {
		t.Fatalf("DeleteVM(): %v", err)
	}
	_, err = client.GetVM(ctx, "bkk01", created.UUID)
	if !inspace.IsNotFound(err) {
		t.Fatalf("GetVM() error = %v, want normalized not-found", err)
	}
}

func TestRemoteBaseURLRequiresHTTPS(t *testing.T) {
	_, err := inspace.NewClient(inspace.Options{BaseURL: "http://api.example.invalid", APIKey: "test-key"})
	if err == nil {
		t.Fatal("NewClient() accepted clear-text remote API URL")
	}
}

func TestCrossOriginRedirectNeverForwardsAPIKey(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if r.Header.Get("apikey") != "" {
			t.Error("redirect target received API key")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	client, err := inspace.NewClient(inspace.Options{BaseURL: source.URL, APIKey: "redirect-secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	if !errors.Is(err, inspace.ErrCrossOriginRedirect) {
		t.Fatalf("ListLocations() error = %v, want ErrCrossOriginRedirect", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestDefaultRedirectLimitIsRetained(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	if err == nil {
		t.Fatal("ListLocations() followed an unbounded redirect loop")
	}
}

func TestMutationGuardBlocksBeforeTransport(t *testing.T) {
	transport := &panicTransport{}
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateVM(context.Background(), "bkk01", inspace.CreateVMRequest{
		Name: "blocked", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
	})
	if !errors.Is(err, inspace.ErrMutationBlocked) {
		t.Fatalf("CreateVM() error = %v, want ErrMutationBlocked", err)
	}
}

func TestUpdateFloatingIPValidatesRequestBeforeTransport(t *testing.T) {
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: &panicTransport{}},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		address string
		request inspace.UpdateFloatingIPRequest
	}{
		{name: "private address", address: "10.0.0.10", request: inspace.UpdateFloatingIPRequest{Name: "owned-ip", BillingAccountID: 42}},
		{name: "missing name", address: "203.0.113.10", request: inspace.UpdateFloatingIPRequest{BillingAccountID: 42}},
		{name: "missing billing account", address: "203.0.113.10", request: inspace.UpdateFloatingIPRequest{Name: "owned-ip"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.UpdateFloatingIP(context.Background(), "bkk01", test.address, test.request); err == nil {
				t.Fatal("UpdateFloatingIP accepted invalid input")
			}
		})
	}
}

func TestUpdateFirewallValidatesRequestBeforeTransport(t *testing.T) {
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: &panicTransport{}},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	port := int32(443)
	validRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	tests := []struct {
		name         string
		location     string
		firewallUUID string
		request      inspace.UpdateFirewallRequest
	}{
		{name: "invalid firewall UUID", location: "bkk01", firewallUUID: "not-a-uuid", request: inspace.UpdateFirewallRequest{Name: "owned-firewall", Rules: []inspace.FirewallRule{validRule}}},
		{name: "missing name", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Rules: []inspace.FirewallRule{validRule}}},
		{name: "unsafe name", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "Owned Firewall", Rules: []inspace.FirewallRule{validRule}}},
		{name: "missing rules", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "owned-firewall"}},
		{name: "invalid rule UUID", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{
			Name: "owned-firewall",
			Rules: []inspace.FirewallRule{{
				UUID: "not-a-uuid", Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			}},
		}},
		{name: "invalid rule", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{
			Name: "owned-firewall",
			Rules: []inspace.FirewallRule{{
				Protocol: "sctp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			}},
		}},
		{name: "invalid location", location: "BKK 01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "owned-firewall", Rules: []inspace.FirewallRule{validRule}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.UpdateFirewall(context.Background(), test.location, test.firewallUUID, test.request); err == nil {
				t.Fatal("UpdateFirewall accepted invalid input")
			}
		})
	}
}

func TestReadRequestsHaveBoundedContext(t *testing.T) {
	var observedRemaining time.Duration
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("GET request reached transport without a context deadline")
		} else {
			observedRemaining = time.Until(deadline)
		}
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListLocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observedRemaining < 25*time.Second || observedRemaining > 31*time.Second {
		t.Fatalf("GET request deadline remaining = %s, want about 30s", observedRemaining)
	}
}

func TestReadRequestsPreserveShorterCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	callerDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("caller context has no deadline")
	}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		observedDeadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("GET request reached transport without a context deadline")
		} else if !observedDeadline.Equal(callerDeadline) {
			t.Errorf("GET request deadline = %s, want caller deadline %s", observedDeadline, callerDeadline)
		}
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListLocations(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMutationRequestsRetainLongerClientDeadline(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("mutation request did not retain the HTTP client deadline")
		} else if remaining := time.Until(deadline); remaining < 55*time.Second || remaining > 61*time.Second {
			t.Errorf("mutation request deadline remaining = %s, want about 1m", remaining)
		}
		return response(req, `{}`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: transport, Timeout: time.Minute},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateVM(context.Background(), "bkk01", inspace.CreateVMRequest{
		Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadRequestCancellationInterruptsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	_, err = client.ListLocations(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListLocations() error = %v, want context deadline exceeded", err)
	}
}

func TestReadDeadlineSurvivesSameOriginRedirect(t *testing.T) {
	var observedDeadline time.Time
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/redirected" {
			redirect := response(req, "")
			redirect.StatusCode = http.StatusTemporaryRedirect
			redirect.Header.Set("Location", "/redirected")
			return redirect, nil
		}
		var ok bool
		observedDeadline, ok = req.Context().Deadline()
		if !ok {
			t.Error("redirected GET request reached transport without a deadline")
		}
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	callerDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("caller context has no deadline")
	}
	if _, err := client.ListLocations(ctx); err != nil {
		t.Fatal(err)
	}
	if !observedDeadline.Equal(callerDeadline) {
		t.Fatalf("redirected GET deadline = %s, want caller deadline %s", observedDeadline, callerDeadline)
	}
}

func TestIsNotFoundNormalizesInSpaceMissingResourceResponse(t *testing.T) {
	if !inspace.IsNotFound(&inspace.APIError{StatusCode: http.StatusBadRequest, Message: "Error: No such virtual machine exists: deadbeef"}) {
		t.Fatal("expected InSpace's missing-VM HTTP 400 response to normalize as not found")
	}
	if inspace.IsNotFound(&inspace.APIError{StatusCode: http.StatusBadRequest, Message: "invalid request"}) {
		t.Fatal("generic HTTP 400 must not normalize as not found")
	}
}

type panicTransport struct{}

func (*panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("mutation guard allowed a request to reach transport")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func response(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
