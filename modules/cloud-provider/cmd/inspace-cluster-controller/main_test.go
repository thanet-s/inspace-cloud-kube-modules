package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

type sequenceReconciler struct {
	reconcileResults []bootstrap.Result
	destroyResults   []bootstrap.DestroyResult
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
	if s.destroyCalls >= len(s.destroyResults) {
		return bootstrap.DestroyResult{}, errors.New("unexpected extra destroy call")
	}
	result := s.destroyResults[s.destroyCalls]
	s.destroyCalls++
	return result, nil
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

func TestEmitJSONResult(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "result-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := bootstrap.Result{
		Ready: true, MaxParallelControlPlaneCreates: 3, Owner: "owner",
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
	want := `{"ready":true,"requeueAfter":0,"maxParallelControlPlaneCreates":3,"owner":"owner","firewallUUID":"nodes-fw","bastionFirewallUUID":"bastion-fw","bastionVMUUID":"bastion-vm","bastionPublicIPv4":"203.0.113.10","bastionPrivateIPv4":"10.0.0.2","privateControlPlaneEndpoint":"https://10.0.0.10:6443","privateRegistrationEndpoint":"https://10.0.0.10:9345"}` + "\n"
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
