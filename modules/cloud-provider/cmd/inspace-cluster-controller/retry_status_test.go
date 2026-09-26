package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

// transportFailure wraps cause exactly as the SDK wraps an http.Client.Do
// failure: net/http returns a *url.Error whose Op is the request method.
func transportFailure(method string, cause error) error {
	op := method[:1] + strings.ToLower(method[1:])
	return fmt.Errorf("inspace: %s /v1/bkk01/user-resource/vm/list: %w", method,
		&url.Error{Op: op, URL: "https://api.inspace.cloud/v1/bkk01/user-resource/vm/list", Err: cause})
}

func TestIsRetryableClassifiesTransportFailuresOfIdempotentReads(t *testing.T) {
	for name, cause := range map[string]error{
		"EOF":                io.EOF,
		"unexpected EOF":     io.ErrUnexpectedEOF,
		"connection refused": &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"connection reset":   &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
		"no such host": &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{
			Err: "no such host", Name: "api.inspace.cloud", IsNotFound: true,
		}},
		"TLS handshake alert":  &net.OpError{Op: "remote error", Err: tls.AlertError(40)},
		"TLS record header":    tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
		"TLS handshake EOF":    fmt.Errorf("tls: handshake: %w", io.EOF),
		"read deadline":        &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		"SDK GET read timeout": context.DeadlineExceeded,
	} {
		if err := transportFailure("GET", cause); !isRetryable(err) {
			t.Errorf("%s: transport failure of an idempotent GET was classified permanent: %v", name, err)
		}
	}
}

func TestIsRetryableKeepsNonTransportAndUnsafeFailuresPermanent(t *testing.T) {
	for name, err := range map[string]error{
		"certificate authority": transportFailure("GET", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
		"certificate hostname":  transportFailure("GET", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "api.inspace.cloud"}),
		"caller cancellation":   transportFailure("GET", context.Canceled),
		"raw POST transport":    transportFailure("POST", io.EOF),
		"raw DELETE transport":  transportFailure("DELETE", os.NewSyscallError("connect", syscall.ECONNREFUSED)),
		"HTTP 400":              &inspace.APIError{StatusCode: 400, Method: "GET", Path: "/v1/x", Message: "bad request"},
		"ownership refusal":     errors.New("bootstrap: refusing to adopt VM \"unit-bastion\" with missing or mismatched ownership/spec hash"),
		"local file error":      &os.PathError{Op: "open", Path: "/state/cluster.yaml", Err: io.EOF},
	} {
		if isRetryable(err) {
			t.Errorf("%s: non-transport or unsafe failure was classified retryable: %v", name, err)
		}
	}
}

func TestUntilReadyAndDeleteLoopsRetryTransientTransportFailures(t *testing.T) {
	eof := transportFailure("GET", io.EOF)
	refused := transportFailure("GET", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	reconciler := &sequenceReconciler{
		reconcileResults: []bootstrap.Result{{}, {}, {Ready: true, Message: "ready"}},
		reconcileErrors:  []error{eof, refused, nil},
	}
	var stdout, stderr bytes.Buffer
	if err := runControllerLoop(ctx, reconciler, &v1alpha1.InSpaceCluster{}, "token", controllerLoopOptions{
		UntilReady: true, Interval: time.Nanosecond, OutputFormat: "json", StandardOutput: &stdout, StandardError: &stderr,
	}); err != nil || reconciler.reconcileCalls != 3 {
		t.Fatalf("--until-ready exited on a transient GET transport failure: err=%v calls=%d stderr=%q", err, reconciler.reconcileCalls, stderr.String())
	}

	destroyer := &sequenceReconciler{
		destroyResults: []bootstrap.DestroyResult{{}, {Done: true, Message: "absent"}},
		destroyErrors:  []error{eof, nil},
	}
	stdout.Reset()
	stderr.Reset()
	if err := runControllerLoop(ctx, destroyer, &v1alpha1.InSpaceCluster{}, "", controllerLoopOptions{
		DeleteOwned: true, Interval: time.Nanosecond, OutputFormat: "json", StandardOutput: &stdout, StandardError: &stderr,
	}); err != nil || destroyer.destroyCalls != 2 {
		t.Fatalf("--delete exited on a transient GET transport failure: err=%v calls=%d stderr=%q", err, destroyer.destroyCalls, stderr.String())
	}
}

// A config written by hand may spell empty collections explicitly. The first
// CAS rewrites the file with omitempty, which drops them; the second CAS must
// still recognize the unchanged identity and spec.
func TestFileStatusCompareAndSwapToleratesExplicitEmptyCollections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.yaml")
	config := fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: unit
  namespace: default
  labels: {}
spec:
  location: bkk01
  credentialsSecretRef: {name: inspace-api, key: apikey}
  controlPlane: {replicas: 3, machine: {vcpu: 4, memoryMiB: 8192, rootDiskGiB: 60, hostPoolUUID: aac7dd66-f390-4edd-80c0-dd7cae49bd99, image: {osName: ubuntu, osVersion: "26.04"}}}
  bootstrapCache: {}
  rke2:
    version: v1.36.4+rke2r1
    tokenSecretRef: {name: rke2-token, key: token}
    disable: []
    tlsSubjectAltNames: []
  network: {uuid: 11111111-2222-4333-8444-555555555555, podCIDR: 10.42.0.0/16, serviceCIDR: 10.43.0.0/16, privateLoadBalancerPool: {start: 10.20.30.200, stop: 10.20.30.239}}
  firewall: {managed: true}
  publicIPv4: {managed: true}
  endpoint: {virtualIPv4: 10.20.30.10, port: 6443}
`, v1alpha1.APIVersion, v1alpha1.Kind)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var cluster v1alpha1.InSpaceCluster
	if err := yaml.UnmarshalStrict([]byte(config), &cluster); err != nil {
		t.Fatal(err)
	}
	if cluster.Spec.RKE2.Disable == nil || cluster.Metadata.Labels == nil {
		t.Fatal("fixture did not decode explicit empty collections as empty non-nil values")
	}
	compareAndSwap := newFileStatusCompareAndSwap(path)
	first := v1alpha1.InSpaceClusterStatus{CreateAttempts: map[string]v1alpha1.ResourceCreateAttemptStatus{
		"firewall/bastion": {ResourceKind: "firewall", ResourceName: "unit-bastion", IntentHash: strings.Repeat("a", 64), Phase: "intent"},
	}}
	persisted, err := compareAndSwap(context.Background(), &cluster, cluster.Status, first)
	if err != nil {
		t.Fatalf("first status CAS: %v", err)
	}
	cluster.Status = persisted
	second := cloneTestStatus(persisted)
	attempt := second.CreateAttempts["firewall/bastion"]
	attempt.Phase = "issued"
	attempt.IssueID = strings.Repeat("b", 32)
	attempt.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	second.CreateAttempts["firewall/bastion"] = attempt
	if _, err := compareAndSwap(context.Background(), &cluster, cluster.Status, second); err != nil {
		t.Fatalf("second status CAS after omitempty rewrite: %v", err)
	}

	changed := cluster
	changed.Spec.RKE2.Disable = []string{"rke2-ingress-nginx"}
	if _, err := compareAndSwap(context.Background(), &changed, second, second); err == nil || !strings.Contains(err.Error(), "identity or spec changed") {
		t.Fatalf("real spec change was not detected: %v", err)
	}
}
