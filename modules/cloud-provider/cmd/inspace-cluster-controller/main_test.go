package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

func TestFileStatusCompareAndSwapPersistsAndRejectsStaleWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.yaml")
	cluster := &v1alpha1.InSpaceCluster{
		APIVersion: v1alpha1.APIVersion,
		Kind:       v1alpha1.Kind,
		Metadata:   v1alpha1.ObjectMeta{Name: "unit", Namespace: "default"},
	}
	data, err := json.Marshal(cluster)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	desired := v1alpha1.InSpaceClusterStatus{CreateAttempts: map[string]v1alpha1.ResourceCreateAttemptStatus{
		"firewall/bastion": {
			ResourceKind: "firewall", ResourceName: "unit-bastion", IntentHash: strings.Repeat("a", 64), Phase: "intent",
		},
	}}
	compareAndSwap := newFileStatusCompareAndSwap(path)
	readback, err := compareAndSwap(context.Background(), cluster, v1alpha1.InSpaceClusterStatus{}, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readback, desired) {
		t.Fatalf("status readback = %#v, want %#v", readback, desired)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cluster config mode = %o, want 0600", info.Mode().Perm())
	}
	persistedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted v1alpha1.InSpaceCluster
	if err := yaml.UnmarshalStrict(persistedData, &persisted); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted.Status, desired) {
		t.Fatalf("persisted status = %#v, want %#v", persisted.Status, desired)
	}
	// Model a process restart: the second writer knows only the cluster and
	// durable status loaded from disk, not any in-memory state from the first
	// controller instance.
	issued := cloneTestStatus(desired)
	attempt := issued.CreateAttempts["firewall/bastion"]
	attempt.Phase = "issued"
	attempt.IssueID = strings.Repeat("b", 32)
	attempt.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	issued.CreateAttempts["firewall/bastion"] = attempt
	restartedCompareAndSwap := newFileStatusCompareAndSwap(path)
	restartedReadback, err := restartedCompareAndSwap(context.Background(), &persisted, persisted.Status, issued)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restartedReadback, issued) {
		t.Fatalf("restarted status readback = %#v, want %#v", restartedReadback, issued)
	}
	restartedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var restarted v1alpha1.InSpaceCluster
	if err := yaml.UnmarshalStrict(restartedData, &restarted); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarted.Status, issued) {
		t.Fatalf("status after restart = %#v, want %#v", restarted.Status, issued)
	}
	if _, err := compareAndSwap(context.Background(), cluster, v1alpha1.InSpaceClusterStatus{}, desired); err == nil || !strings.Contains(err.Error(), "compare-and-swap conflict") {
		t.Fatalf("stale status CAS error = %v", err)
	}
}

func cloneTestStatus(status v1alpha1.InSpaceClusterStatus) v1alpha1.InSpaceClusterStatus {
	copy := status
	if status.CreateAttempts != nil {
		copy.CreateAttempts = make(map[string]v1alpha1.ResourceCreateAttemptStatus, len(status.CreateAttempts))
		for key, attempt := range status.CreateAttempts {
			copy.CreateAttempts[key] = attempt
		}
	}
	if status.DeleteAttempts != nil {
		copy.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus, len(status.DeleteAttempts))
		for key, attempt := range status.DeleteAttempts {
			copy.DeleteAttempts[key] = attempt
		}
	}
	return copy
}

type sequenceReconciler struct {
	reconcileResults []bootstrap.Result
	destroyResults   []bootstrap.DestroyResult
	destroyErrors    []error
	reconcileCalls   int
	destroyCalls     int
}

func (s *sequenceReconciler) Reconcile(context.Context, *v1alpha1.InSpaceCluster, string) (bootstrap.Result, error) {
	if s.reconcileCalls >= len(s.reconcileResults) {
		return bootstrap.Result{}, errors.New("unexpected extra reconcile call")
	}
	result := s.reconcileResults[s.reconcileCalls]
	s.reconcileCalls++
	return result, nil
}

func (s *sequenceReconciler) Destroy(context.Context, *v1alpha1.InSpaceCluster) (bootstrap.DestroyResult, error) {
	index := s.destroyCalls
	if index >= len(s.destroyResults) && index >= len(s.destroyErrors) {
		return bootstrap.DestroyResult{}, errors.New("unexpected extra destroy call")
	}
	s.destroyCalls++
	var result bootstrap.DestroyResult
	if index < len(s.destroyResults) {
		result = s.destroyResults[index]
	}
	var err error
	if index < len(s.destroyErrors) {
		err = s.destroyErrors[index]
	}
	return result, err
}

func TestParseTCPPorts(t *testing.T) {
	ports, err := parseTCPPorts("22, 6443,30080")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{22, 6443, 30080}) {
		t.Fatalf("ports = %v", ports)
	}
	if _, err := parseTCPPorts("22,not-a-port"); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestParseBootstrapCacheImageDigests(t *testing.T) {
	valid := map[string]string{
		"inspace-cloud-controller-manager": "sha256:" + strings.Repeat("a", 64),
		"inspace-csi-driver":               "sha256:" + strings.Repeat("b", 64),
		"karpenter-provider-inspace":       "sha256:" + strings.Repeat("c", 64),
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseBootstrapCacheImageDigests(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, valid) {
		t.Fatalf("parsed digests = %#v, want %#v", got, valid)
	}
	if got, err := parseBootstrapCacheImageDigests("  "); err != nil || got != nil {
		t.Fatalf("empty optional digest input = %#v, %v; want nil, nil", got, err)
	}
	for name, raw := range map[string]string{
		"malformed-json": "{",
		"missing":        `{"inspace-cloud-controller-manager":"sha256:` + strings.Repeat("a", 64) + `"}`,
		"uppercase":      strings.Replace(string(raw), strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"unknown":        strings.Replace(string(raw), "karpenter-provider-inspace", "unknown", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBootstrapCacheImageDigests(raw); err == nil {
				t.Fatal("invalid module image digest input was accepted")
			}
		})
	}
}

func TestLoadBootstrapCacheSettingsRequiresPersistedKeyAndRealInitializationTime(t *testing.T) {
	cluster := &v1alpha1.InSpaceCluster{}
	notBefore := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	t.Setenv("INSPACE_BOOTSTRAP_CACHE_KEY", strings.Repeat("ab", 32))
	t.Setenv("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE", notBefore.Format(time.RFC3339))
	key, gotNotBefore, err := loadBootstrapCacheSettings(cluster, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || gotNotBefore != notBefore {
		t.Fatalf("cache settings = %x %s", key, gotNotBefore)
	}

	cluster.Spec.BootstrapCache.DirectDownload = true
	t.Setenv("INSPACE_BOOTSTRAP_CACHE_KEY", "")
	t.Setenv("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE", "")
	if key, start, err := loadBootstrapCacheSettings(cluster, false); err != nil || key != nil || !start.IsZero() {
		t.Fatalf("direct-download settings = %x %s %v", key, start, err)
	}
	cluster.Spec.BootstrapCache.DirectDownload = false
	if key, start, err := loadBootstrapCacheSettings(cluster, true); err != nil || key != nil || !start.IsZero() {
		t.Fatalf("destroy settings = %x %s %v", key, start, err)
	}
}

func TestLoadBootstrapCacheSettingsRejectsUnstableOrExpiredInputs(t *testing.T) {
	cluster := &v1alpha1.InSpaceCluster{}
	validTime := time.Now().UTC().Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)
	for name, values := range map[string][2]string{
		"short key":        {"abcd", validTime},
		"uppercase key":    {strings.Repeat("AB", 32), validTime},
		"invalid key":      {strings.Repeat("zz", 32), validTime},
		"missing time":     {strings.Repeat("ab", 32), ""},
		"fractional time":  {strings.Repeat("ab", 32), time.Now().UTC().Format(time.RFC3339Nano)},
		"near-future time": {strings.Repeat("ab", 32), time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second).Format(time.RFC3339)},
		"future time":      {strings.Repeat("ab", 32), time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)},
		"expired time":     {strings.Repeat("ab", 32), time.Now().UTC().AddDate(-16, 0, 0).Truncate(time.Second).Format(time.RFC3339)},
	} {
		t.Run(name, func(t *testing.T) {
			key, start := values[0], values[1]
			t.Setenv("INSPACE_BOOTSTRAP_CACHE_KEY", key)
			t.Setenv("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE", start)
			if _, _, err := loadBootstrapCacheSettings(cluster, false); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEmitJSONResult(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "result-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := bootstrap.Result{
		Ready: true, MaxParallelControlPlaneCreates: 1, Owner: "owner",
		FirewallUUID: "nodes-fw", BastionFirewallUUID: "bastion-fw", BastionVMUUID: "bastion-vm",
		BastionPublicIPv4: "203.0.113.10", BastionPrivateIPv4: "10.0.0.2",
		PrivateControlPlaneEndpoint: "https://10.0.0.10:6443", PrivateRegistrationEndpoint: "https://10.0.0.10:9345",
	}
	if err := emitResult(file, "json", result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ready":true,"requeueAfter":0,"maxParallelControlPlaneCreates":1,"owner":"owner","firewallUUID":"nodes-fw","bastionFirewallUUID":"bastion-fw","bastionVMUUID":"bastion-vm","bastionPublicIPv4":"203.0.113.10","bastionPrivateIPv4":"10.0.0.2","privateControlPlaneEndpoint":"https://10.0.0.10:6443","privateRegistrationEndpoint":"https://10.0.0.10:9345"}` + "\n"
	if string(data) != want {
		t.Fatalf("JSON = %q, want %q", data, want)
	}
}

func TestEmitJSONDestroyResult(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "destroy-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := bootstrap.DestroyResult{Done: false, Owner: "owner", Remaining: []string{"vm/cp-0"}, Message: "deleting"}
	if err := emitDestroyResult(file, "json", result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"done":false,"owner":"owner","remaining":["vm/cp-0"],"message":"deleting"}` + "\n"
	if string(data) != want {
		t.Fatalf("JSON = %q, want %q", data, want)
	}
}

func TestUntilReadyLoopRetriesStaleVMDetailProgressAndConverges(t *testing.T) {
	reconciler := &sequenceReconciler{reconcileResults: []bootstrap.Result{
		{Owner: "owner", RequeueAfter: time.Nanosecond, Message: "waiting for stale VM list entry"},
		{Ready: true, Owner: "owner", Message: "ready"},
	}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControllerLoop(ctx, reconciler, &v1alpha1.InSpaceCluster{}, "token", controllerLoopOptions{
		UntilReady: true, Interval: time.Nanosecond, OutputFormat: "json",
		StandardOutput: &stdout, StandardError: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reconciler.reconcileCalls != 2 || reconciler.destroyCalls != 0 {
		t.Fatalf("loop calls: reconcile=%d destroy=%d", reconciler.reconcileCalls, reconciler.destroyCalls)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "stale VM list entry") || !strings.Contains(lines[1], `"ready":true`) {
		t.Fatalf("until-ready output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("until-ready wrote an error for non-error progress: %q", stderr.String())
	}
}

func TestDeleteLoopRetriesStaleVMDetailProgressAndConverges(t *testing.T) {
	reconciler := &sequenceReconciler{destroyResults: []bootstrap.DestroyResult{
		{Owner: "owner", Remaining: []string{"vm/rke2-owner-bastion"}, Message: "waiting for stale VM list entry"},
		{Done: true, Owner: "owner", Message: "absent"},
	}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControllerLoop(ctx, reconciler, &v1alpha1.InSpaceCluster{}, "", controllerLoopOptions{
		DeleteOwned: true, Interval: time.Nanosecond, OutputFormat: "json",
		StandardOutput: &stdout, StandardError: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reconciler.destroyCalls != 2 || reconciler.reconcileCalls != 0 {
		t.Fatalf("loop calls: reconcile=%d destroy=%d", reconciler.reconcileCalls, reconciler.destroyCalls)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "stale VM list entry") || !strings.Contains(lines[1], `"done":true`) {
		t.Fatalf("delete output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("delete wrote an error for non-error progress: %q", stderr.String())
	}
}

func TestDeleteLoopRetriesRawEOFAmbiguousOutcomeAndConverges(t *testing.T) {
	ambiguousErr := fmt.Errorf("%w: %w", bootstrap.ErrRetryableAmbiguousVMDelete, io.ErrUnexpectedEOF)
	reconciler := &sequenceReconciler{
		destroyResults: []bootstrap.DestroyResult{{}, {Done: true, Owner: "owner", Message: "absent"}},
		destroyErrors:  []error{ambiguousErr, nil},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControllerLoop(ctx, reconciler, &v1alpha1.InSpaceCluster{}, "", controllerLoopOptions{
		DeleteOwned: true, Interval: time.Nanosecond, OutputFormat: "json",
		StandardOutput: &stdout, StandardError: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reconciler.destroyCalls != 2 || !strings.Contains(stderr.String(), io.ErrUnexpectedEOF.Error()) || !strings.Contains(stdout.String(), `"done":true`) {
		t.Fatalf("raw EOF retry did not converge: calls=%d stdout=%q stderr=%q", reconciler.destroyCalls, stdout.String(), stderr.String())
	}
	if !errors.Is(ambiguousErr, io.ErrUnexpectedEOF) || !isRetryable(ambiguousErr) {
		t.Fatalf("ambiguous wrapper did not preserve or classify raw EOF: %v", ambiguousErr)
	}
}
