package inspace_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/internal/testutil/fakeapi"
	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
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
