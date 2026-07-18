package inspace

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

func TestKubernetesNodeResolverOnlyMarksHTTP404AsMissing(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		body            string
		wantMissing     bool
		wantUnavailable bool
	}{
		{name: "not found", status: http.StatusNotFound, wantMissing: true},
		{name: "forbidden", status: http.StatusForbidden},
		{name: "too many requests", status: http.StatusTooManyRequests, wantUnavailable: true},
		{name: "internal server error", status: http.StatusInternalServerError, wantUnavailable: true},
		{name: "malformed success response", status: http.StatusOK, body: `{`, wantUnavailable: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != "/api/v1/nodes/worker-a" {
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			baseURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			resolver := &KubernetesNodeResolver{
				baseURL: baseURL,
				client:  server.Client(), tokenPath: tokenFile, namespace: "kube-system",
			}

			_, err = resolver.ProviderIDForNode(context.Background(), "worker-a")
			if err == nil {
				t.Fatal("ProviderIDForNode returned nil error")
			}
			if errors.Is(err, errKubernetesNodeNotFound) != test.wantMissing {
				t.Fatalf("ProviderIDForNode error = %v, missing sentinel = %t, want %t", err, errors.Is(err, errKubernetesNodeNotFound), test.wantMissing)
			}
			if errors.Is(err, cloud.ErrUnavailable) != test.wantUnavailable {
				t.Fatalf("ProviderIDForNode error = %v, unavailable = %t, want %t", err, errors.Is(err, cloud.ErrUnavailable), test.wantUnavailable)
			}
		})
	}
}

func TestKubernetesNodeResolverRejectsMalformedNameWithoutMissingSentinel(t *testing.T) {
	resolver := &KubernetesNodeResolver{}
	_, err := resolver.ProviderIDForNode(context.Background(), "INVALID NODE")
	if err == nil || errors.Is(err, errKubernetesNodeNotFound) {
		t.Fatalf("ProviderIDForNode error = %v, want non-missing validation error", err)
	}
}

func TestKubernetesNodeResolverPreservesCanceledContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Error(w, "request should have been canceled before dispatch", http.StatusInternalServerError)
	}))
	defer server.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &KubernetesNodeResolver{
		baseURL: baseURL,
		client:  server.Client(), tokenPath: tokenFile, namespace: "kube-system",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = resolver.ProviderIDForNode(ctx, "worker-a")
	if !errors.Is(err, context.Canceled) || errors.Is(err, cloud.ErrUnavailable) ||
		errors.Is(err, errKubernetesNodeNotFound) {
		t.Fatalf("ProviderIDForNode error = %v, want context.Canceled only", err)
	}
	_, _, err = resolver.kubernetesAPIRequestWithLimit(
		ctx,
		http.MethodGet,
		"/api/v1/nodes",
		nil,
		maxMissingNodeAuthorityResponseBytes,
	)
	if !errors.Is(err, context.Canceled) || errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("kubernetesAPIRequestWithLimit error = %v, want context.Canceled only", err)
	}
}
