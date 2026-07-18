package inspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestKubernetesMutationLeaseResponseRejectsExactLimitPlusJunk(t *testing.T) {
	fence, body := testMutationLeaseResponse(t)
	if len(body) >= maxKubernetesAPIResponseBytes {
		t.Fatalf("test Lease body is unexpectedly large: %d", len(body))
	}
	body = append(body, bytes.Repeat([]byte(" "), maxKubernetesAPIResponseBytes-len(body))...)
	body = append(body, 'x')

	resolver := newRawMutationLeaseResolver(t, body, -1)
	if _, err := resolver.Get(context.Background(), fence.Key); err == nil ||
		!errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("exact-limit-plus-junk Lease error = %v", err)
	}
}

func TestKubernetesMutationLeaseResponseRejectsDuplicateSecurityFields(t *testing.T) {
	fence, valid := testMutationLeaseResponse(t)
	fenceKeyJSON, err := json.Marshal(mutationFenceKeyAnnotation)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		body      []byte
		duplicate string
	}{
		{
			name: "resource version",
			body: bytes.Replace(
				valid,
				[]byte(`"resourceVersion":"1"`),
				[]byte(`"resourceVersion":"1","resourceVersion":"2"`),
				1,
			),
			duplicate: "resourceVersion",
		},
		{
			name: "annotations object",
			body: bytes.Replace(
				valid,
				[]byte(`"annotations":`),
				[]byte(`"annotations":{},"annotations":`),
				1,
			),
			duplicate: "annotations",
		},
		{
			name: "fence annotation",
			body: bytes.Replace(
				valid,
				append(append([]byte(nil), fenceKeyJSON...), ':'),
				append(append(append(append([]byte(nil), fenceKeyJSON...), []byte(`:"foreign",`)...), fenceKeyJSON...), ':'),
				1,
			),
			duplicate: mutationFenceKeyAnnotation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if bytes.Equal(test.body, valid) {
				t.Fatal("test did not inject a duplicate field")
			}
			resolver := newRawMutationLeaseResolver(t, test.body, int64(len(test.body)))
			if _, err := resolver.Get(context.Background(), fence.Key); err == nil ||
				!errors.Is(err, cloud.ErrUnavailable) ||
				!strings.Contains(err.Error(), `duplicate JSON object key "`+test.duplicate+`"`) {
				t.Fatalf("duplicate %s Lease error = %v", test.duplicate, err)
			}
		})
	}
}

func TestKubernetesMutationLeaseResponseRejectsCaseVariantSchemaFields(t *testing.T) {
	fence, valid := testMutationLeaseResponse(t)
	tests := []struct {
		name string
		body []byte
		call func(*KubernetesNodeResolver) error
	}{
		{
			name: "metadata",
			body: bytes.Replace(
				valid,
				[]byte(`"metadata":`),
				[]byte(`"Metadata":{},"metadata":`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "resource version",
			body: bytes.Replace(
				valid,
				[]byte(`"resourceVersion":"1"`),
				[]byte(`"ResourceVersion":"foreign","resourceVersion":"1"`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "annotations",
			body: bytes.Replace(
				valid,
				[]byte(`"annotations":`),
				[]byte(`"Annotations":{},"annotations":`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "spec",
			body: bytes.Replace(
				valid,
				[]byte(`"spec":`),
				[]byte(`"Spec":{},"spec":`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "lone metadata variant",
			body: bytes.Replace(
				valid,
				[]byte(`"metadata":`),
				[]byte(`"Metadata":`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "lone annotations variant",
			body: bytes.Replace(
				valid,
				[]byte(`"annotations":`),
				[]byte(`"Annotations":`),
				1,
			),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "lone list items variant",
			body: []byte(`{"Items":[]}`),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.List(context.Background(), "")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.call == nil || bytes.Equal(test.body, valid) {
				t.Fatal("test did not inject a case-variant schema field")
			}
			resolver := newRawMutationLeaseResolver(t, test.body, int64(len(test.body)))
			if err := test.call(resolver); err == nil ||
				!errors.Is(err, cloud.ErrUnavailable) ||
				!strings.Contains(err.Error(), "schema field") {
				t.Fatalf("case-variant %s Lease error = %v", test.name, err)
			}
		})
	}
}

func TestKubernetesMutationLeaseResponseKeepsAnnotationKeysCaseSensitive(t *testing.T) {
	fence, valid := testMutationLeaseResponse(t)
	body := bytes.Replace(
		valid,
		[]byte(`"annotations":{`),
		[]byte(`"annotations":{"Storage.Inspace.Cloud/Foreign":"preserved",`),
		1,
	)
	if bytes.Equal(body, valid) {
		t.Fatal("test did not inject a case-distinct annotation key")
	}
	resolver := newRawMutationLeaseResolver(t, body, int64(len(body)))
	got, err := resolver.Get(context.Background(), fence.Key)
	if err != nil {
		t.Fatalf("case-distinct annotation key was treated as a schema collision: %v", err)
	}
	if got == nil || got.Key != fence.Key {
		t.Fatalf("decoded fence = %#v, want key %q", got, fence.Key)
	}
}

func TestKubernetesMutationLeaseAndListResponsesRejectTrailingContent(t *testing.T) {
	fence, leaseBody := testMutationLeaseResponse(t)
	listBody, err := json.Marshal(kubernetesLeaseList{Items: []kubernetesLease{testMutationLease(t, fence)}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body []byte
		call func(*KubernetesNodeResolver) error
	}{
		{
			name: "Lease",
			body: append(append([]byte(nil), leaseBody...), []byte(`{"ignored":true}`)...),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "Lease list",
			body: append(append([]byte(nil), listBody...), []byte(`[]`)...),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.List(context.Background(), "")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newRawMutationLeaseResolver(t, test.body, int64(len(test.body)))
			if err := test.call(resolver); err == nil ||
				!errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "trailing JSON") {
				t.Fatalf("%s trailing-content error = %v", test.name, err)
			}
		})
	}
}

func TestKubernetesMutationLeaseResponsesRejectNullAndMissingListItems(t *testing.T) {
	fence, _ := testMutationLeaseResponse(t)
	tests := []struct {
		name string
		body []byte
		call func(*KubernetesNodeResolver) error
	}{
		{
			name: "null Lease",
			body: []byte(`null`),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.Get(context.Background(), fence.Key)
				return err
			},
		},
		{
			name: "null Lease list",
			body: []byte(`null`),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.List(context.Background(), "")
				return err
			},
		},
		{
			name: "missing Lease list items",
			body: []byte(`{}`),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.List(context.Background(), "")
				return err
			},
		},
		{
			name: "null Lease list items",
			body: []byte(`{"items":null}`),
			call: func(resolver *KubernetesNodeResolver) error {
				_, err := resolver.List(context.Background(), "")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newRawMutationLeaseResolver(t, test.body, int64(len(test.body)))
			if err := test.call(resolver); err == nil || !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("%s error = %v, want unavailable malformed-response error", test.name, err)
			}
		})
	}
}

func TestKubernetesMutationLeaseResponseRejectsDeclaredLengthMismatch(t *testing.T) {
	fence, body := testMutationLeaseResponse(t)
	resolver := newRawMutationLeaseResolver(t, body, int64(len(body)+1))
	if _, err := resolver.Get(context.Background(), fence.Key); err == nil ||
		!errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "does not match declared Content-Length") {
		t.Fatalf("declared-length mismatch error = %v", err)
	}
}

func TestKubernetesMutationLeaseListRejectsOversizedResponse(t *testing.T) {
	body := append([]byte(`{"items":[]}`), bytes.Repeat([]byte(" "), maxKubernetesAPIResponseBytes)...)
	resolver := newRawMutationLeaseResolver(t, body, -1)
	if _, err := resolver.List(context.Background(), ""); err == nil ||
		!errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized Lease list error = %v", err)
	}
}

func TestKubernetesMutationLeaseListRejectsItemCountAmplification(t *testing.T) {
	item := []byte(`{"metadata":{},"spec":{}}`)
	var body bytes.Buffer
	body.WriteString(`{"items":[`)
	for index := 0; index <= maxKubernetesLeaseListItems; index++ {
		if index != 0 {
			body.WriteByte(',')
		}
		body.Write(item)
	}
	body.WriteString(`]}`)
	if body.Len() >= maxKubernetesAPIResponseBytes {
		t.Fatalf("item-amplification test body is unexpectedly oversized: %d", body.Len())
	}
	resolver := newRawMutationLeaseResolver(t, body.Bytes(), int64(body.Len()))
	if _, err := resolver.List(context.Background(), ""); err == nil ||
		!errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "exceeds 4096 items") {
		t.Fatalf("item-amplification Lease list error = %v", err)
	}
}

func testMutationLeaseResponse(t *testing.T) (mutationFence, []byte) {
	t.Helper()
	intent := diskCreateIntent{
		Operation:        "create-disk",
		Location:         testLocation,
		Name:             "pvc-response-validation",
		SizeGiB:          1,
		BillingAccountID: 42,
	}
	fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}
	lease := testMutationLease(t, fence)
	body, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	return fence, body
}

func testMutationLease(t *testing.T, fence mutationFence) kubernetesLease {
	t.Helper()
	lease := mutationFenceLease(fence, "kube-system")
	lease.Metadata.UID = "lease-uid"
	lease.Metadata.ResourceVersion = "1"
	return lease
}

func newRawMutationLeaseResolver(t *testing.T, body []byte, declaredLength int64) *KubernetesNodeResolver {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseURL, err := url.Parse("https://kubernetes.test")
	if err != nil {
		t.Fatal(err)
	}
	return &KubernetesNodeResolver{
		baseURL: baseURL,
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Authorization") != "Bearer test-token" {
				t.Fatalf("Authorization header = %q", request.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(body)),
				ContentLength: declaredLength,
				Request:       request,
			}, nil
		})},
		tokenPath: tokenFile,
		namespace: "kube-system",
	}
}
