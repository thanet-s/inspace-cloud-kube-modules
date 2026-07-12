package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

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
