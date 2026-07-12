package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

func TestReconcileBuildsBastionThenExactlyThreeControlPlaneVMs(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)

	first, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if first.Ready || len(api.vmCreates) != 1 || api.vmCreates[0].Name != bastionName(ownerKey(cluster)) {
		t.Fatalf("first reconcile did not create only the bastion: result=%#v creates=%#v", first, api.vmCreates)
	}
	if api.vmCreates[0].VCPU != BastionVCPU || api.vmCreates[0].MemoryMiB != BastionMemoryMiB || api.vmCreates[0].DiskGiB != BastionRootDiskGiB ||
		api.vmCreates[0].OSName != "ubuntu" || api.vmCreates[0].OSVersion != "24.04" {
		t.Fatalf("bastion shape = %#v", api.vmCreates[0])
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("create response was trusted for firewall attachment: %#v", api.firewalls)
		}
	}
	if api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("create response was trusted for floating-IP attachment: %#v", api.floatingIPs[0])
	}

	result := reconcileUntilReady(t, reconciler, cluster)
	if len(api.vms) != 4 || len(api.vmCreates) != 4 {
		t.Fatalf("VMs=%d creates=%d, want bastion+3 control-plane", len(api.vms), len(api.vmCreates))
	}
	if len(api.firewalls) != 2 || len(api.floatingIPs) != 4 {
		t.Fatalf("firewalls=%#v floatingIPs=%#v", api.firewalls, api.floatingIPs)
	}
	owner := ownerKey(cluster)
	nodeFirewall := mustFirewall(t, api.firewalls, firewallName(owner))
	bastionFirewall := mustFirewall(t, api.firewalls, bastionFirewallName(owner))
	if err := validateFirewallPolicy(nodeFirewall, api.network.Subnet, cluster.Spec.Network.PodCIDR, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := validateBastionFirewallPolicy(bastionFirewall, reconciler.ManagementCIDR); err != nil {
		t.Fatal(err)
	}
	if len(nodeFirewall.ResourcesAssigned) != 3 || len(bastionFirewall.ResourcesAssigned) != 1 {
		t.Fatalf("separate firewall assignments: nodes=%#v bastion=%#v", nodeFirewall.ResourcesAssigned, bastionFirewall.ResourcesAssigned)
	}
	if got := result.ControlPlaneEndpoint; got != "https://10.20.30.10:6443" {
		t.Fatalf("controlPlaneEndpoint=%q", got)
	}
	if result.PrivateControlPlaneEndpoint != "https://10.20.30.10:6443" || result.PrivateRegistrationEndpoint != "https://10.20.30.10:9345" {
		t.Fatalf("private endpoints=%#v", result)
	}
	if result.BastionVMUUID == "" || result.BastionPublicIPv4 == "" || result.BastionPrivateIPv4 == "" || result.BastionFirewallUUID == "" {
		t.Fatalf("bastion result fields=%#v", result)
	}
	privateLoadBalancerManifest := ""
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		request := mustVMRequest(t, api.vmCreates, controlPlaneName(owner, slot))
		if request.ReservePublicIP == nil || *request.ReservePublicIP {
			t.Errorf("control-plane slot %d requested an implicit public IP", slot)
		}
		assertControlPlaneCloudInit(t, request.CloudInit, slot == 0)
		manifest := decodeWriteFiles(t, request.CloudInit)["/var/lib/inspace/rke2-cilium-private-load-balancer"]
		if slot == 0 {
			privateLoadBalancerManifest = manifest
		} else if manifest != privateLoadBalancerManifest {
			t.Fatalf("slot %d rendered a non-identical Cilium private load-balancer manifest", slot)
		}
	}
	assertBastionCloudInit(t, api.vmCreates[0].CloudInit)
	for _, floatingIP := range api.floatingIPs {
		if floatingIP.AssignedTo == "" || floatingIP.AssignedToResourceType != "virtual_machine" {
			t.Errorf("owned floating IP is not assigned to its VM: %#v", floatingIP)
		}
	}
	if result.MaxParallelControlPlaneCreates != ControlPlaneReplicas {
		t.Fatalf("parallel bound=%d", result.MaxParallelControlPlaneCreates)
	}
}

func TestReconcileAndDestroyWhenFirewallDescriptionsAreOmitted(t *testing.T) {
	api := newFakeAPI()
	api.omitFirewallDescriptions = true
	cluster := testCluster()
	reconciler := testReconciler(api)

	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || len(api.firewalls) != 2 {
		t.Fatalf("reconcile result=%#v firewalls=%#v", result, api.firewalls)
	}
	readback, err := api.ListFirewalls(context.Background(), cluster.Spec.Location)
	if err != nil {
		t.Fatal(err)
	}
	for _, firewall := range readback {
		if firewall.Description != "" || firewall.BillingAccountID != cluster.Spec.BillingAccountID {
			t.Fatalf("firewall readback contract=%#v", firewall)
		}
	}

	reconciler.SSHUsername = ""
	reconciler.SSHPublicKey = ""
	var destroyed DestroyResult
	for i := 0; i < 40; i++ {
		destroyed, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
		if destroyed.Done {
			break
		}
	}
	if !destroyed.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 || len(api.firewallDeletes) != 2 {
		t.Fatalf("destroy result=%#v VMs=%#v FIPs=%#v firewalls=%#v firewallDeletes=%#v", destroyed, api.vms, api.floatingIPs, api.firewalls, api.firewallDeletes)
	}
}

func TestReconcileAcceptsSparseFirewallCreateResponsesAfterAuthoritativeReadback(t *testing.T) {
	api := newFakeAPI()
	api.sparseFirewallCreateResponses = true
	cluster := testCluster()
	reconciler := testReconciler(api)

	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || len(api.firewallCreates) != 2 || len(api.firewallCreateResponses) != 2 {
		t.Fatalf("result=%#v firewallCreates=%#v responses=%#v", result, api.firewallCreates, api.firewallCreateResponses)
	}
	for _, response := range api.firewallCreateResponses {
		if response.UUID == "" || response.EffectiveName() != "" || response.Description != "" || response.BillingAccountID != 0 || len(response.Rules) != 0 || len(response.ResourcesAssigned) != 0 {
			t.Fatalf("firewall POST response was not sparse: %#v", response)
		}
	}
	owner := ownerKey(cluster)
	readback, err := api.ListFirewalls(context.Background(), cluster.Spec.Location)
	if err != nil {
		t.Fatal(err)
	}
	nodeFirewall := mustFirewall(t, readback, firewallName(owner))
	bastionFirewall := mustFirewall(t, readback, bastionFirewallName(owner))
	if len(nodeFirewall.Rules) != 6 || len(nodeFirewall.ResourcesAssigned) != ControlPlaneReplicas ||
		len(bastionFirewall.Rules) != 4 || len(bastionFirewall.ResourcesAssigned) != 1 {
		t.Fatalf("authoritative firewall readback was not fully validated: node=%#v bastion=%#v", nodeFirewall, bastionFirewall)
	}
}

func TestReconcileAndDestroyUseCanonicalVMDetailsWhenListIsSparse(t *testing.T) {
	api := newFakeAPI()
	api.sparseVMListResponses = true
	cluster := testCluster()
	reconciler := testReconciler(api)

	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || len(api.vms) != 1+ControlPlaneReplicas {
		t.Fatalf("result=%#v VMs=%#v", result, api.vms)
	}
	listed, err := api.ListVMs(context.Background(), cluster.Spec.Location)
	if err != nil {
		t.Fatal(err)
	}
	for _, vm := range listed {
		if vm.DesignatedPoolUUID != "" || vm.NetworkUUID != "" {
			t.Fatalf("VM list response was not sparse: %#v", vm)
		}
	}
	readUUIDs := make(map[string]bool, len(api.getVMCalls))
	for _, uuid := range api.getVMCalls {
		readUUIDs[uuid] = true
	}
	for _, vm := range api.vms {
		if vm.DesignatedPoolUUID == "" || vm.NetworkUUID == "" || !readUUIDs[vm.UUID] {
			t.Fatalf("VM %q was not validated through complete canonical detail: %#v calls=%#v", vm.Name, vm, api.getVMCalls)
		}
	}

	getCallsBeforeDestroy := len(api.getVMCalls)
	var destroyed DestroyResult
	for i := 0; i < 40; i++ {
		destroyed, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
		if destroyed.Done {
			break
		}
	}
	if !destroyed.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("destroy result=%#v VMs=%#v FIPs=%#v firewalls=%#v", destroyed, api.vms, api.floatingIPs, api.firewalls)
	}
	if len(api.getVMCalls) <= getCallsBeforeDestroy {
		t.Fatal("destroy did not re-read canonical VM details")
	}
}

func TestSparseVMListRetainsNetworkMembershipCollisionChecks(t *testing.T) {
	api := newFakeAPI()
	api.sparseVMListResponses = true
	cluster := testCluster()
	vm := inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "unrelated",
		PrivateIPv4: cluster.Spec.Endpoint.VirtualIPv4, NetworkUUID: cluster.Spec.Network.UUID,
	}
	api.vms = append(api.vms, vm)
	api.network.VMUUIDs = append(api.network.VMUUIDs, vm.UUID)

	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "already uses control-plane virtual IPv4") {
		t.Fatalf("sparse list membership collision error = %v", err)
	}
	if len(api.events) != 0 || len(api.getVMCalls) != 0 {
		t.Fatalf("location-wide list collision did not fail before owned-detail reads/mutation: calls=%#v events=%#v", api.getVMCalls, api.events)
	}
}

func TestReconcileRejectsMalformedCanonicalVMDetailBeforeMutation(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"UUID mismatch": func(api *fakeAPI, _ string) {
			api.mutateGetVMResponse = func(vm *inspace.VM) { vm.UUID = "99999999-1111-4222-8333-bbbbbbbbbbbb" }
		},
		"name mismatch": func(api *fakeAPI, _ string) {
			api.mutateGetVMResponse = func(vm *inspace.VM) { vm.Name = "foreign" }
		},
		"nil detail": func(api *fakeAPI, uuid string) { api.nilGetVMUUID = uuid },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			bastion := mustVM(t, api.vms, bastionName(ownerKey(cluster)))
			mutate(api, bastion.UUID)
			eventsBefore := len(api.events)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "authoritative detail") {
				t.Fatalf("canonical-detail error = %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("detail uncertainty mutated infrastructure: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestReconcileWaitsWithoutMutationWhenVMListDetailIsStale(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	bastion := mustVM(t, api.vms, bastionName(ownerKey(cluster)))
	api.getVMErrorByUUID = map[string]error{
		bastion.UUID: &inspace.APIError{StatusCode: 400, Method: "GET", Path: "/vm", Message: "Error: No such virtual machine exists: " + bastion.UUID},
	}
	eventsBefore := len(api.events)

	result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil {
		t.Fatalf("stale list/detail race must requeue without an error: %v", err)
	}
	if result.Ready || result.RequeueAfter <= 0 || result.Owner != ownerKey(cluster) || !strings.Contains(result.Message, "stale VM list entry") {
		t.Fatalf("stale list/detail progress result = %#v", result)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("stale list/detail race mutated infrastructure: %v", api.events[eventsBefore:])
	}

	delete(api.getVMErrorByUUID, bastion.UUID)
	ready := reconcileUntilReady(t, reconciler, cluster)
	if !ready.Ready {
		t.Fatalf("reconciliation did not converge after VM detail became visible: %#v", ready)
	}
}

func TestDestroyRejectsMalformedCanonicalVMDetailBeforeMutation(t *testing.T) {
	tests := map[string]func(*fakeAPI, string){
		"UUID mismatch": func(api *fakeAPI, _ string) {
			api.mutateGetVMResponse = func(vm *inspace.VM) { vm.UUID = "99999999-1111-4222-8333-bbbbbbbbbbbb" }
		},
		"name mismatch": func(api *fakeAPI, _ string) {
			api.mutateGetVMResponse = func(vm *inspace.VM) { vm.Name = "foreign" }
		},
		"missing detail": func(api *fakeAPI, uuid string) { api.nilGetVMUUID = uuid },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			bastion := mustVM(t, api.vms, bastionName(ownerKey(cluster)))
			mutate(api, bastion.UUID)
			eventsBefore := len(api.events)
			if _, err := reconciler.Destroy(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "authoritative detail") {
				t.Fatalf("canonical-detail error = %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("detail uncertainty mutated infrastructure during destroy: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyWaitsWithoutMutationUntilStaleVMListEntryDisappears(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	bastion := mustVM(t, api.vms, bastionName(ownerKey(cluster)))
	api.getVMErrorByUUID = map[string]error{
		bastion.UUID: &inspace.APIError{StatusCode: 404, Method: "GET", Path: "/vm", Message: "not found"},
	}
	eventsBefore := len(api.events)

	result, err := reconciler.Destroy(context.Background(), cluster)
	if err != nil {
		t.Fatalf("stale list/detail race must wait without an error: %v", err)
	}
	if result.Done || len(result.Remaining) != 1 || result.Remaining[0] != "vm/"+bastion.Name || !strings.Contains(result.Message, "stale VM list entry") {
		t.Fatalf("stale list/detail destroy result = %#v", result)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("stale list/detail race mutated infrastructure during destroy: %v", api.events[eventsBefore:])
	}

	api.removeVMFromReadback(bastion.UUID)
	var destroyed DestroyResult
	for i := 0; i < 40; i++ {
		destroyed, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy after list convergence %d: %v", i, err)
		}
		if destroyed.Done {
			break
		}
	}
	if !destroyed.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("destroy did not converge after stale list row disappeared: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", destroyed, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestReconcileRejectsSuppliedFirewallCreateIdentityDriftWithoutDeletion(t *testing.T) {
	tests := map[string]func(*inspace.Firewall){
		"invalid UUID":    func(firewall *inspace.Firewall) { firewall.UUID = "not-a-uuid" },
		"name":            func(firewall *inspace.Firewall) { firewall.Name = "foreign" },
		"display name":    func(firewall *inspace.Firewall) { firewall.DisplayName = "foreign" },
		"description":     func(firewall *inspace.Firewall) { firewall.Description = "foreign" },
		"billing account": func(firewall *inspace.Firewall) { firewall.BillingAccountID++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			api.mutateCreateFirewallResponse = func(_ inspace.CreateFirewallRequest, response *inspace.Firewall) {
				mutate(response)
			}
			cluster := testCluster()
			reconciler := testReconciler(api)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "create node firewall response") {
				t.Fatalf("expected provisional identity rejection, got %v", err)
			}
			if len(api.firewalls) != 1 || len(api.firewallCreates) != 1 || len(api.firewallDeletes) != 0 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("ambiguous POST response caused unsafe mutation or deletion: firewalls=%#v creates=%#v deletes=%#v VMs=%#v FIPs=%#v", api.firewalls, api.firewallCreates, api.firewallDeletes, api.vms, api.floatingIPs)
			}
			api.mutateCreateFirewallResponse = nil
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatalf("authoritative list readback could not safely recover: %v", err)
			}
			if len(api.firewallCreates) != 2 {
				t.Fatalf("existing node firewall was recreated instead of adopted: %#v", api.firewallCreates)
			}
		})
	}
}

func TestReconcileStartsAllThreeControlPlaneCreatesBehindOneBarrier(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	api.createVMBarrier = make(chan struct{})
	api.createVMStarted = make(chan string, ControlPlaneReplicas)

	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		done <- outcome{result: result, err: err}
	}()
	started := map[string]bool{}
	for len(started) < ControlPlaneReplicas {
		select {
		case name := <-api.createVMStarted:
			if name == bastionName(ownerKey(cluster)) {
				t.Fatal("bastion was recreated inside the control-plane barrier")
			}
			started[name] = true
		case got := <-done:
			t.Fatalf("reconcile completed before all three creates started: %#v %v", got.result, got.err)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/3 control-plane creates reached barrier", len(started))
		}
	}
	api.mu.Lock()
	finished := len(api.vms)
	api.mu.Unlock()
	if finished != 1 {
		t.Fatalf("VM creates crossed barrier early: finished VMs=%d", finished)
	}
	close(api.createVMBarrier)
	select {
	case got := <-done:
		if got.err != nil || len(got.result.ControlPlaneVMs) != 3 {
			t.Fatalf("barrier reconcile=%#v err=%v", got.result, got.err)
		}
		nodeFirewall := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
		if len(nodeFirewall.ResourcesAssigned) != 0 {
			t.Fatalf("create responses were trusted for control-plane firewall attachment: %#v", nodeFirewall.ResourcesAssigned)
		}
		for _, floatingIP := range api.floatingIPs {
			if floatingIP.Name != bastionFloatingIPName(ownerKey(cluster)) && floatingIP.AssignedTo != "" {
				t.Fatalf("create response was trusted for control-plane FIP attachment: %#v", floatingIP)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not complete after barrier release")
	}
}

func TestParallelControlPlaneErrorsAreSlotOrderedAndKeepSuccesses(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	owner := ownerKey(cluster)
	api.failVMCreateNames = map[string]error{
		controlPlaneName(owner, 2): errors.New("slot two"),
		controlPlaneName(owner, 0): errors.New("slot zero"),
	}
	result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || strings.Index(err.Error(), "slot 0") > strings.Index(err.Error(), "slot 2") {
		t.Fatalf("errors are not slot ordered: %v", err)
	}
	if len(result.ControlPlaneVMs) != 1 || len(api.vms) != 2 {
		t.Fatalf("successful bastion/CP state was not retained: result=%#v VMs=%#v", result, api.vms)
	}
}

func TestBastionFirewallFailureAfterAuthoritativeReadbackKeepsOwnedVM(t *testing.T) {
	api := newFakeAPI()
	api.failFirewallAssignmentForName = "bastion"
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != 1 || len(api.vmDeletes) != 0 || len(api.vms) != 1 {
		t.Fatalf("rollback error=%v creates=%#v deletes=%#v VMs=%#v", err, api.vmCreates, api.vmDeletes, api.vms)
	}
}

func TestReconcileRequiresExactBastionAccessBeforeMutation(t *testing.T) {
	for _, edit := range []func(*Reconciler){
		func(r *Reconciler) { r.SSHUsername = "" },
		func(r *Reconciler) { r.SSHPublicKey = "" },
		func(r *Reconciler) { r.ManagementCIDR = "198.51.100.0/24" },
		func(r *Reconciler) { r.ManagementTCPPorts = []int{22, 6443} },
		func(r *Reconciler) { r.ManagementTCPPorts = []int{2222} },
	} {
		api := newFakeAPI()
		reconciler := testReconciler(api)
		edit(reconciler)
		if _, err := reconciler.Reconcile(context.Background(), testCluster(), "token"); err == nil {
			t.Fatal("expected bastion access validation error")
		}
		if len(api.events) != 0 {
			t.Fatalf("invalid bastion access mutated infrastructure: %v", api.events)
		}
	}
}

func TestReconcileRefusesAutomaticSlotZeroReplacement(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	owner := ownerKey(cluster)
	api.vms = append(api.vms, inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: controlPlaneName(owner, 1), PrivateIPv4: "10.20.30.21",
	})
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "slot 0 is absent") {
		t.Fatalf("expected split-brain refusal, got %v", err)
	}
	if len(api.events) != 0 {
		t.Fatalf("split-brain preflight mutated infrastructure: %v", api.events)
	}
}

func TestReconcileRejectsLoadBalancerVIPCollisionBeforeMutation(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	api.loadBalancers = []inspace.LoadBalancer{{
		UUID: "88888888-1111-4222-8333-bbbbbbbbbbbb", DisplayName: "existing", NetworkUUID: cluster.Spec.Network.UUID,
		PrivateAddress: cluster.Spec.Endpoint.VirtualIPv4,
	}}
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("expected active same-VPC load-balancer VIP collision")
	}
	if len(api.events) != 0 {
		t.Fatalf("load-balancer collision preflight mutated infrastructure: %v", api.events)
	}
	api.loadBalancers[0].IsDeleted = true
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("deleted load balancer blocked VIP: %v", err)
	}
}

func TestReverseFirewallAuditRejectsForeignAttachment(t *testing.T) {
	for _, operation := range []string{"reconcile", "destroy"} {
		t.Run(operation, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			owner := ownerKey(cluster)
			ownedVM := mustVM(t, api.vms, controlPlaneName(owner, 0))
			api.firewalls = append(api.firewalls, inspace.Firewall{
				UUID: "66666666-1111-4222-8333-444444444444", DisplayName: "foreign",
				ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: ownedVM.UUID}},
			})
			eventsBefore := len(api.events)
			var err error
			if operation == "reconcile" {
				_, err = reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
			} else {
				_, err = reconciler.Destroy(context.Background(), cluster)
			}
			if err == nil {
				t.Fatal("expected reverse firewall attachment rejection")
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("reverse audit mutated infrastructure: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestMalformedCreateVMResponseRollsBackBeforeProtection(t *testing.T) {
	api := newFakeAPI()
	api.mutateCreateVMResponse = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("malformed create response was not rolled back: error=%v creates=%d deletes=%v VMs=%#v", err, len(api.vmCreates), api.vmDeletes, api.vms)
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("malformed create response reached firewall attachment: %#v", api.firewalls)
		}
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("malformed create response reached floating-IP attachment: %#v", api.floatingIPs)
	}
}

func TestAmbiguousMalformedCreateVMResponseIsNotDeleted(t *testing.T) {
	api := newFakeAPI()
	api.mutateCreateVMResponse = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.Name = "unexpected" }
	if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil {
		t.Fatal("expected ambiguous create-response rejection")
	}
	if len(api.vmDeletes) != 0 {
		t.Fatalf("ambiguous create response was used as deletion authority: %v", api.vmDeletes)
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("ambiguous create response reached firewall attachment: %#v", api.firewalls)
		}
	}
}

func TestAuthoritativeVMWithoutPrivateIPIsNotProtectedYet(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	api.vms[0].PrivateIPv4 = ""
	result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Message, "private networking") {
		t.Fatalf("unexpected progress result: %#v", result)
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("VM without authoritative private IP was attached to firewall: %#v", api.firewalls)
		}
	}
	if api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("VM without authoritative private IP received FIP: %#v", api.floatingIPs[0])
	}
}

func TestStrictFloatingIPContract(t *testing.T) {
	cluster := testCluster()
	vm := &inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "owned", PrivateIPv4: "10.20.30.21"}
	base := inspace.FloatingIP{
		Name: "owned-ip", Address: "203.0.113.21", BillingAccountID: cluster.Spec.BillingAccountID,
		Type: "public", Enabled: true, AssignedTo: vm.UUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
	}
	if err := validateOwnedFloatingIP(&base, cluster, base.Name, vm); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*inspace.FloatingIP){
		func(item *inspace.FloatingIP) { item.Enabled = false },
		func(item *inspace.FloatingIP) { item.IsDeleted = true },
		func(item *inspace.FloatingIP) { item.IsVirtual = true },
		func(item *inspace.FloatingIP) { item.Type = "private" },
		func(item *inspace.FloatingIP) { item.Address = "10.20.30.21" },
		func(item *inspace.FloatingIP) { item.BillingAccountID++ },
		func(item *inspace.FloatingIP) { item.Name = "other" },
		func(item *inspace.FloatingIP) { item.AssignedTo = "88888888-1111-4222-8333-bbbbbbbbbbbb" },
		func(item *inspace.FloatingIP) { item.AssignedToResourceType = "load_balancer" },
		func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.20.30.99" },
	}
	for index, mutate := range mutations {
		item := base
		mutate(&item)
		if err := validateOwnedFloatingIP(&item, cluster, base.Name, vm); err == nil {
			t.Errorf("strict floating-IP mutation %d was accepted: %#v", index, item)
		}
	}
	unassigned := base
	unassigned.AssignedTo = ""
	unassigned.AssignedToResourceType = ""
	unassigned.AssignedToPrivateIP = ""
	if err := validateOwnedFloatingIP(&unassigned, cluster, base.Name, nil); err != nil {
		t.Fatalf("valid unassigned floating IP rejected: %v", err)
	}
}

func TestInvalidFloatingIPCreateResponseBlocksVMCreation(t *testing.T) {
	api := newFakeAPI()
	api.mutateCreateFloatingIPResponse = func(item *inspace.FloatingIP) { item.Enabled = false }
	if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil {
		t.Fatal("expected strict floating-IP create-response rejection")
	}
	if len(api.vmCreates) != 0 {
		t.Fatalf("invalid floating IP allowed VM creation: %#v", api.vmCreates)
	}
}

func TestStrictFloatingIPValidatorCoversAssignmentResponseAndReadback(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprintf("uncertain=%t", uncertain), func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			api.mutateAssignFloatingIPResponse = func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.20.30.99" }
			if uncertain {
				api.floatingIPAssignError = errors.New("uncertain assignment response")
			}
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
				t.Fatal("expected strict assignment response/readback rejection")
			}
		})
	}
}

func TestReconcileRejectsVIPAndOwnershipDriftBeforeMutation(t *testing.T) {
	t.Run("VIP outside VPC", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		cluster.Spec.Endpoint.VirtualIPv4 = "10.99.0.10"
		_, err := testReconciler(api).Reconcile(context.Background(), cluster, "token")
		if err == nil || len(api.firewalls) != 0 || len(api.vmCreates) != 0 {
			t.Fatalf("error=%v mutations=%#v", err, api.events)
		}
	})
	t.Run("VIP collides with unrelated VM", func(t *testing.T) {
		api := newFakeAPI()
		vm := inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "unrelated", PrivateIPv4: "10.20.30.10", NetworkUUID: api.network.UUID}
		api.vms = append(api.vms, vm)
		api.network.VMUUIDs = append(api.network.VMUUIDs, vm.UUID)
		_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "token")
		if err == nil || len(api.firewalls) != 0 {
			t.Fatalf("collision error=%v firewalls=%#v", err, api.firewalls)
		}
	})
	t.Run("reserved pool collides with unrelated VM", func(t *testing.T) {
		api := newFakeAPI()
		vm := inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "unrelated", PrivateIPv4: "10.20.30.205", NetworkUUID: api.network.UUID}
		api.vms = append(api.vms, vm)
		api.network.VMUUIDs = append(api.network.VMUUIDs, vm.UUID)
		_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "token")
		if err == nil || len(api.firewalls) != 0 || len(api.vmCreates) != 0 {
			t.Fatalf("pool/VM collision error=%v mutations=%#v", err, api.events)
		}
	})
	t.Run("same RFC1918 addresses in another VPC are ignored", func(t *testing.T) {
		api := newFakeAPI()
		api.vms = append(api.vms,
			inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "other-vpc-vip", PrivateIPv4: "10.20.30.10", NetworkUUID: "aaaaaaaa-2222-4333-8444-555555555555"},
			inspace.VM{UUID: "99999998-1111-4222-8333-bbbbbbbbbbbb", Name: "other-vpc-pool", PrivateIPv4: "10.20.30.205", NetworkUUID: "aaaaaaaa-2222-4333-8444-555555555555"},
		)
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "token"); err != nil {
			t.Fatalf("other-VPC address reuse blocked reconciliation: %v", err)
		}
		if len(api.vmCreates) != 1 {
			t.Fatalf("expected normal bastion creation, got %#v", api.vmCreates)
		}
	})
	t.Run("VM network evidence disagreement fails closed", func(t *testing.T) {
		api := newFakeAPI()
		vm := inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "disagrees", PrivateIPv4: "10.20.30.205", NetworkUUID: "aaaaaaaa-2222-4333-8444-555555555555"}
		api.vms = append(api.vms, vm)
		api.network.VMUUIDs = append(api.network.VMUUIDs, vm.UUID)
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "token"); err == nil || len(api.events) != 0 {
			t.Fatalf("network disagreement error=%v mutations=%v", err, api.events)
		}
	})
	t.Run("reserved pool collides with same-VPC load balancer", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		api.loadBalancers = append(api.loadBalancers, inspace.LoadBalancer{
			UUID: "88888888-1111-4222-8333-bbbbbbbbbbbb", DisplayName: "unrelated", NetworkUUID: cluster.Spec.Network.UUID, PrivateAddress: "10.20.30.206",
		})
		_, err := testReconciler(api).Reconcile(context.Background(), cluster, "token")
		if err == nil || len(api.firewalls) != 0 || len(api.vmCreates) != 0 {
			t.Fatalf("pool/NLB collision error=%v mutations=%#v", err, api.events)
		}
	})
	t.Run("unknown cross-account FIP on owned VM", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		owner := ownerKey(cluster)
		api.vms = append(api.vms, inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: bastionName(owner), PrivateIPv4: "10.20.30.20"})
		api.network.VMUUIDs = append(api.network.VMUUIDs, api.vms[0].UUID)
		api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{Name: "foreign", Address: "203.0.113.99", BillingAccountID: 999, AssignedTo: api.vms[0].UUID, AssignedToResourceType: "virtual_machine"})
		_, err := testReconciler(api).Reconcile(context.Background(), cluster, "token")
		if err == nil || len(api.firewalls) != 0 || len(api.vmCreates) != 0 {
			t.Fatalf("ownership error=%v mutations=%#v", err, api.events)
		}
	})
}

func TestDHCPVIPCollisionRollsBackNewVM(t *testing.T) {
	t.Run("bastion", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		api.privateIPByName = map[string]string{bastionName(ownerKey(cluster)): cluster.Spec.Endpoint.VirtualIPv4}
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected bastion VIP collision")
		}
		if len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
			t.Fatalf("bastion collision rollback failed: creates=%#v deletes=%v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
		}
	})
	t.Run("control plane", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		prepareBastion(t, reconciler, cluster)
		owner := ownerKey(cluster)
		api.privateIPByName = map[string]string{controlPlaneName(owner, 1): cluster.Spec.Endpoint.VirtualIPv4}
		if _, err := reconciler.Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected control-plane VIP collision")
		}
		for _, vm := range api.vms {
			if vm.PrivateIPv4 == cluster.Spec.Endpoint.VirtualIPv4 {
				t.Fatalf("colliding VM survived rollback: %#v", vm)
			}
		}
	})
}

func TestDHCPPrivateLoadBalancerPoolCollisionRollsBackNewVM(t *testing.T) {
	t.Run("bastion create response", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		api.privateIPByName = map[string]string{bastionName(ownerKey(cluster)): "10.20.30.200"}
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected bastion private load-balancer pool collision")
		}
		if len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
			t.Fatalf("bastion pool collision rollback failed: creates=%#v deletes=%v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
		}
	})
	t.Run("control-plane create response", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		prepareBastion(t, reconciler, cluster)
		owner := ownerKey(cluster)
		api.privateIPByName = map[string]string{controlPlaneName(owner, 1): "10.20.30.201"}
		if _, err := reconciler.Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected control-plane private load-balancer pool collision")
		}
		for _, vm := range api.vms {
			if vm.PrivateIPv4 == "10.20.30.201" {
				t.Fatalf("colliding control-plane VM survived rollback: %#v", vm)
			}
		}
	})
	t.Run("authoritative readback", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		name := bastionName(ownerKey(cluster))
		api.privateIPByName = map[string]string{name: "10.20.30.202"}
		api.mutateCreateVMResponse = func(request inspace.CreateVMRequest, vm *inspace.VM) {
			if request.Name == name {
				vm.PrivateIPv4 = ""
			}
		}
		reconciler := testReconciler(api)
		if _, err := reconciler.Reconcile(context.Background(), cluster, "token"); err != nil {
			t.Fatal(err)
		}
		eventsBefore := len(api.events)
		if _, err := reconciler.Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected authoritative VM pool collision")
		}
		if len(api.events) != eventsBefore {
			t.Fatalf("authoritative pool collision mutated infrastructure: %v", api.events[eventsBefore:])
		}
	})
}

func TestDestroyRemovesOnlyOwnedResourcesInSafeOrder(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	reconciler.SSHUsername = ""
	reconciler.SSHPublicKey = ""
	api.vms = append(api.vms, inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "unrelated", Status: "running"})

	var result DestroyResult
	for i := 0; i < 40; i++ {
		var err error
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("destroy result=%#v FIPs=%#v firewalls=%#v", result, api.floatingIPs, api.firewalls)
	}
	if len(api.vms) != 1 || api.vms[0].Name != "unrelated" {
		t.Fatalf("destroy touched unrelated VM: %#v", api.vms)
	}
	lastFIPDelete, firstVMDelete, firstFirewallDelete := -1, -1, -1
	for i, event := range api.events {
		if strings.HasPrefix(event, "delete-fip/") {
			lastFIPDelete = i
		}
		if firstVMDelete == -1 && strings.HasPrefix(event, "delete-vm/") {
			firstVMDelete = i
		}
		if firstFirewallDelete == -1 && strings.HasPrefix(event, "delete-firewall/") {
			firstFirewallDelete = i
		}
	}
	if lastFIPDelete < 0 || firstVMDelete <= lastFIPDelete || firstFirewallDelete <= firstVMDelete {
		t.Fatalf("unsafe destroy order: %v", api.events)
	}
}

func TestDestroyConvergesThroughKnownFirewallAssignmentLag(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	for i := 0; i < 30 && len(api.vms) != 0; i++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("destroy with lagging assignments %d: %v", i, err)
		}
	}
	if len(api.vms) != 0 || len(api.vmDeletes) != 1+ControlPlaneReplicas {
		t.Fatalf("owned VMs did not delete while exact assignments lagged: VMs=%#v deletes=%#v", api.vms, api.vmDeletes)
	}
	waiting, err := reconciler.Destroy(context.Background(), cluster)
	if err != nil {
		t.Fatalf("exact pending assignments must wait without an error: %v", err)
	}
	if waiting.Done || !strings.Contains(waiting.Message, "waiting for firewall assignments to clear") || len(api.firewallDeletes) != 0 {
		t.Fatalf("lagging assignment result=%#v firewallDeletes=%#v", waiting, api.firewallDeletes)
	}

	api.clearAllFirewallAssignments()
	var result DestroyResult
	for i := 0; i < 10; i++ {
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy after assignment convergence %d: %v", i, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.firewalls) != 0 || len(reconciler.pendingVMDeletions) != 0 {
		t.Fatalf("destroy did not converge after assignments cleared: result=%#v firewalls=%#v pending=%#v", result, api.firewalls, reconciler.pendingVMDeletions)
	}
}

func TestDestroyRetainsDeletionIntentWhenAmbiguousErrorCommits(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	ambiguousErr := &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/vm", Message: "injected post-commit failure", Retryable: true}
	api.vmDeleteError = ambiguousErr
	api.vmDeleteErrorCommits = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	var deleteErr error
	for i := 0; i < 20; i++ {
		_, deleteErr = reconciler.Destroy(context.Background(), cluster)
		if deleteErr != nil {
			break
		}
	}
	if deleteErr != ambiguousErr || len(api.vmDeletes) != 1 || len(api.vms) != ControlPlaneReplicas {
		t.Fatalf("ambiguous committed delete state: error=%v deletes=%#v VMs=%#v", deleteErr, api.vmDeletes, api.vms)
	}
	if len(reconciler.pendingVMDeletions) != 1 {
		t.Fatalf("ambiguous committed delete lost its exact intent: %#v", reconciler.pendingVMDeletions)
	}

	api.vmDeleteError = nil
	api.vmDeleteErrorCommits = false
	for i := 0; i < 20 && len(api.vms) != 0; i++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("destroy after ambiguous commit %d: %v", i, err)
		}
	}
	waiting, err := reconciler.Destroy(context.Background(), cluster)
	if err != nil || !strings.Contains(waiting.Message, "waiting for firewall assignments to clear") || len(api.firewallDeletes) != 0 {
		t.Fatalf("ambiguous committed delete did not reach safe assignment wait: result=%#v error=%v", waiting, err)
	}
	api.clearAllFirewallAssignments()
	var result DestroyResult
	for i := 0; i < 10; i++ {
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy after ambiguous assignment convergence %d: %v", i, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.firewalls) != 0 || len(reconciler.pendingVMDeletions) != 0 {
		t.Fatalf("ambiguous committed delete did not converge: result=%#v firewalls=%#v pending=%#v", result, api.firewalls, reconciler.pendingVMDeletions)
	}
}

func TestDestroyDropsDeletionIntentAfterProvenNonCommitFailure(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	rejectedErr := &inspace.APIError{StatusCode: 400, Method: "DELETE", Path: "/vm", Message: "injected request rejection"}
	api.vmDeleteError = rejectedErr
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	var deleteErr error
	for i := 0; i < 20; i++ {
		_, deleteErr = reconciler.Destroy(context.Background(), cluster)
		if deleteErr != nil {
			break
		}
	}
	if deleteErr != rejectedErr || len(api.vmDeletes) != 1 || len(api.vms) != 1+ControlPlaneReplicas {
		t.Fatalf("proven non-commit delete state: error=%v deletes=%#v VMs=%#v", deleteErr, api.vmDeletes, api.vms)
	}
	if len(reconciler.pendingVMDeletions) != 0 {
		t.Fatalf("proven non-commit failure retained deletion authority: %#v", reconciler.pendingVMDeletions)
	}

	api.vmDeleteError = nil
	if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
		t.Fatalf("retry after proven non-commit rejection: %v", err)
	}
	if len(api.vms) != ControlPlaneReplicas || len(reconciler.pendingVMDeletions) != 1 {
		t.Fatalf("successful retry did not establish one exact transition: VMs=%#v pending=%#v", api.vms, reconciler.pendingVMDeletions)
	}
}

func TestDestroyPendingDeletionNeverAllowsForeignFirewallAssignment(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)

	nodeFirewall := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
	nodeFirewall.ResourcesAssigned = append(nodeFirewall.ResourcesAssigned, inspace.FirewallResource{
		ResourceType: "vm", ResourceUUID: "99999999-1111-4222-8333-bbbbbbbbbbbb",
	})
	mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "assignment drift") {
		t.Fatalf("foreign assignment was not rejected: %v", err)
	}
	if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
		t.Fatal("foreign assignment caused a teardown mutation")
	}
}

func TestDestroyPendingDeletionRejectsRememberedUUIDOnSecondFirewall(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)

	api.firewalls = append(api.firewalls, inspace.Firewall{
		UUID: "66666666-1111-4222-8333-444444444444", DisplayName: "foreign",
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: api.vmDeletes[0]}},
	})
	mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "assignment drift") {
		t.Fatalf("remembered UUID on a second firewall was not rejected: %v", err)
	}
	if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
		t.Fatal("second firewall assignment caused a teardown mutation")
	}
}

func TestDestroyRejectsExpiredPendingDeletionAssignment(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)

	reconciler.pendingDeletionMu.Lock()
	for key, deletion := range reconciler.pendingVMDeletions {
		deletion.ExpiresAt = time.Now().Add(-time.Second)
		reconciler.pendingVMDeletions[key] = deletion
	}
	reconciler.pendingDeletionMu.Unlock()
	mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
	if _, err := reconciler.Destroy(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "did not clear within") {
		t.Fatalf("expired pending assignment was not rejected: %v", err)
	}
	if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
		t.Fatal("expired pending assignment caused a teardown mutation")
	}
}

func destroyUntilFirstVMDelete(t *testing.T, reconciler *Reconciler, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	for i := 0; i < 20 && len(api.vmDeletes) == 0; i++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("destroy before first VM deletion %d: %v", i, err)
		}
	}
	if len(api.vmDeletes) != 1 {
		t.Fatalf("expected one owned VM deletion, got %#v", api.vmDeletes)
	}
}

func TestDestroyRejectsAssignmentAndPolicyDriftBeforeMutation(t *testing.T) {
	for _, mutate := range []func(*fakeAPI, *v1alpha1.InSpaceCluster){
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			owner := ownerKey(cluster)
			for i := range api.floatingIPs {
				if api.floatingIPs[i].Name == bastionFloatingIPName(owner) {
					api.floatingIPs[i].Enabled = false
				}
			}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			owner := ownerKey(cluster)
			for i := range api.floatingIPs {
				if api.floatingIPs[i].Name == bastionFloatingIPName(owner) {
					api.floatingIPs[i].AssignedTo = "99999999-1111-4222-8333-bbbbbbbbbbbb"
				}
			}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			fw := mustFirewall(t, api.firewalls, bastionFirewallName(ownerKey(cluster)))
			fw.Rules[0].EndpointSpec = []string{"0.0.0.0/0"}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			fw := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
			fw.Description = "not-owned"
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			fw := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
			fw.Rules = append(fw.Rules, fw.Rules[0])
		},
	} {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		reconcileUntilReady(t, reconciler, cluster)
		mutate(api, cluster)
		deletesBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
		if _, err := reconciler.Destroy(context.Background(), cluster); err == nil {
			t.Fatal("expected drift rejection")
		}
		if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != deletesBefore {
			t.Fatal("destroy mutated before rejecting drift")
		}
	}
}

func TestRenderControlPlaneCloudInitUsesVIPStaticPodAndBoundedBoot(t *testing.T) {
	raw, err := RenderCloudInitJSON(CloudInitInput{
		NodeName: "cp-1", NodeExternalIPv4: "203.0.113.11", PrivateSubnet: "10.20.30.0/24", VirtualIPv4: "10.20.30.10",
		RKE2Version: "v1.35.6+rke2r1", RKE2Token: "token", ServerAddress: "10.20.30.10",
		PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
		PrivateLoadBalancerPoolStart: "10.20.30.200", PrivateLoadBalancerPoolStop: "10.20.30.239",
		TLSSubjectAltNames: []string{"10.20.30.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertControlPlaneCloudInit(t, raw, false)
}

func TestVirtualIPv4HostValidation(t *testing.T) {
	for _, value := range []string{"10.20.30.0", "10.20.30.255", "10.20.31.10", "203.0.113.10", "bad"} {
		if err := validateVirtualIPv4("10.20.30.0/24", value); err == nil {
			t.Errorf("accepted unusable VIP %q", value)
		}
	}
	if err := validateVirtualIPv4("10.20.30.0/24", "10.20.30.10"); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateLoadBalancerPoolVPCValidationAndCiliumRateSizing(t *testing.T) {
	pool, err := validatePrivateLoadBalancerPool("10.20.30.0/24", "10.42.0.0/16", "10.43.0.0/16", "10.20.30.10", "10.20.30.200", "10.20.30.239")
	if err != nil || pool.AddressCount != 40 {
		t.Fatalf("valid pool = %#v, %v", pool, err)
	}
	for _, test := range []struct {
		name, subnet, start, stop string
	}{
		{name: "network address", subnet: "10.20.30.0/24", start: "10.20.30.0", stop: "10.20.30.15"},
		{name: "broadcast address", subnet: "10.20.30.0/24", start: "10.20.30.240", stop: "10.20.30.255"},
		{name: "outside vpc", subnet: "10.20.30.0/24", start: "10.20.31.1", stop: "10.20.31.16"},
		{name: "contains kube vip", subnet: "10.20.30.0/24", start: "10.20.30.1", stop: "10.20.30.16"},
		{name: "pod overlap", subnet: "10.0.0.0/8", start: "10.42.0.1", stop: "10.42.0.16"},
		{name: "service overlap", subnet: "10.0.0.0/8", start: "10.43.0.1", stop: "10.43.0.16"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validatePrivateLoadBalancerPool(test.subnet, "10.42.0.0/16", "10.43.0.0/16", "10.20.30.10", test.start, test.stop); err == nil {
				t.Fatalf("accepted invalid VPC pool %s-%s", test.start, test.stop)
			}
		})
	}
	minimumRate := renderRKE2CiliumConfig("10.42.0.0/16", 40)
	if !strings.Contains(minimumRate, "qps: 10\n      burst: 20") {
		t.Fatalf("minimum Cilium L2 rate limit is wrong: %s", minimumRate)
	}
	scaledRate := renderRKE2CiliumConfig("10.42.0.0/16", 51)
	if !strings.Contains(scaledRate, "qps: 11\n      burst: 22") {
		t.Fatalf("scaled Cilium L2 rate limit is wrong: %s", scaledRate)
	}
	maximumRate := renderRKE2CiliumConfig("10.42.0.0/16", 256)
	if !strings.Contains(maximumRate, "qps: 52\n      burst: 104") {
		t.Fatalf("maximum Cilium L2 rate limit is wrong: %s", maximumRate)
	}
}

func TestDisableUFWScriptFailsClosedAndChecksServiceIndependently(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "ufw"), `#!/bin/sh
case "$1" in
  --force) exit "${UFW_DISABLE_RC:-0}" ;;
  status) printf 'Status: %s\n' "${UFW_STATUS:-inactive}" ;;
  *) exit 1 ;;
esac
`)
	writeExecutable(t, filepath.Join(dir, "systemctl"), `#!/bin/sh
case "$1" in
  list-unit-files)
    [ "${UNIT_LIST_RC:-0}" -eq 0 ] || exit "${UNIT_LIST_RC}"
    [ "${UNIT_ABSENT:-false}" = true ] || printf 'ufw.service enabled enabled\n'
    ;;
  disable) exit "${UNIT_DISABLE_RC:-0}" ;;
  is-active) [ "${UNIT_ACTIVE:-false}" = true ] ;;
  is-enabled) printf '%s\n' "${UNIT_STATE:-disabled}"; [ "${UNIT_STATE:-disabled}" = enabled ] ;;
  *) exit 1 ;;
esac
`)
	run := func(env ...string) error {
		command := exec.Command("sh")
		command.Stdin = strings.NewReader(renderDisableUFWScript())
		command.Env = append(os.Environ(), append([]string{"PATH=" + dir + ":/usr/bin:/bin"}, env...)...)
		return command.Run()
	}
	if err := run(); err != nil {
		t.Fatalf("inactive+disabled UFW rejected: %v", err)
	}
	if err := run("UNIT_ABSENT=true"); err != nil {
		t.Fatalf("absent ufw.service rejected: %v", err)
	}
	for _, env := range [][]string{{"UFW_STATUS=active"}, {"UNIT_ACTIVE=true"}, {"UNIT_STATE=enabled"}, {"UNIT_DISABLE_RC=1"}, {"UFW_DISABLE_RC=1"}, {"UNIT_LIST_RC=1"}} {
		if err := run(env...); err == nil {
			t.Errorf("UFW disable accepted unsafe state %v", env)
		}
	}

	// A service must still be disabled when the ufw CLI itself is absent.
	serviceOnly := t.TempDir()
	writeExecutable(t, filepath.Join(serviceOnly, "systemctl"), `#!/bin/sh
case "$1" in
  list-unit-files) printf 'ufw.service enabled enabled\n' ;;
  disable) printf disabled > "$UFW_MARKER" ;;
  is-active) exit 1 ;;
  is-enabled) printf 'disabled\n'; exit 1 ;;
esac
`)
	marker := filepath.Join(serviceOnly, "marker")
	command := exec.Command("sh")
	command.Stdin = strings.NewReader(renderDisableUFWScript())
	command.Env = append(os.Environ(), "PATH="+serviceOnly+":/usr/bin:/bin", "UFW_MARKER="+marker)
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("ufw.service was not disabled when CLI was absent")
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

func reconcileUntilReady(t *testing.T, reconciler *Reconciler, cluster *v1alpha1.InSpaceCluster) Result {
	t.Helper()
	for i := 0; i < 20; i++ {
		result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
		if result.Ready {
			return result
		}
	}
	t.Fatal("infrastructure never became ready")
	return Result{}
}

func prepareBastion(t *testing.T, reconciler *Reconciler, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	owner := ownerKey(cluster)
	for i := 0; i < 10; i++ {
		if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
			t.Fatal(err)
		}
		var bastion *inspace.VM
		for index := range reconciler.API.(*fakeAPI).vms {
			candidate := &reconciler.API.(*fakeAPI).vms[index]
			if candidate.Name == bastionName(owner) {
				bastion = candidate
				break
			}
		}
		if bastion == nil {
			continue
		}
		firewall := mustFirewall(t, reconciler.API.(*fakeAPI).firewalls, bastionFirewallName(owner))
		floatingIP := reconciler.API.(*fakeAPI).floatingIPs[0]
		if firewallHasVM(firewall, bastion.UUID) && floatingIP.AssignedTo == bastion.UUID {
			return
		}
	}
	t.Fatal("bastion never became protected")
}

func testReconciler(api *fakeAPI) *Reconciler {
	return &Reconciler{
		API: api, SSHUsername: "inspacee2e", SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest unit@test",
		ManagementCIDR: "198.51.100.24/32", ManagementTCPPorts: []int{22},
	}
}

func testCluster() *v1alpha1.InSpaceCluster {
	return &v1alpha1.InSpaceCluster{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.Kind,
		Metadata: v1alpha1.ObjectMeta{Name: "unit", Namespace: "default"},
		Spec: v1alpha1.InSpaceClusterSpec{
			Location: "bkk01", BillingAccountID: 42,
			CredentialsSecretRef: v1alpha1.SecretKeyReference{Name: "inspace-api", Key: "apikey"},
			ControlPlane: v1alpha1.ControlPlaneSpec{Replicas: 3, Machine: v1alpha1.MachineSpec{
				VCPU: 4, MemoryMiB: 8192, RootDiskGiB: 60,
				HostPoolUUID: "aac7dd66-f390-4edd-80c0-dd7cae49bd99", Image: v1alpha1.ImageSpec{OSName: "ubuntu", OSVersion: "24.04"},
			}},
			RKE2: v1alpha1.RKE2Spec{Version: "v1.35.6+rke2r1", TokenSecretRef: v1alpha1.SecretKeyReference{Name: "rke2-token", Key: "token"}, Disable: []string{"rke2-ingress-nginx"}},
			Network: v1alpha1.NetworkSpec{
				UUID: "11111111-2222-4333-8444-555555555555", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
				PrivateLoadBalancerPool: v1alpha1.PrivateLoadBalancerPoolSpec{Start: "10.20.30.200", Stop: "10.20.30.239"},
			},
			Firewall: v1alpha1.FirewallSpec{Managed: true}, PublicIPv4: v1alpha1.PublicIPv4Spec{Managed: true},
			Endpoint: v1alpha1.ControlPlaneEndpoint{VirtualIPv4: "10.20.30.10", Port: 6443},
		},
	}
}

func assertControlPlaneCloudInit(t *testing.T, raw string, initialize bool) {
	t.Helper()
	files := decodeWriteFiles(t, raw)
	if len(files) != 5 {
		t.Fatalf("write_files=%d, want 5", len(files))
	}
	script := files["/usr/local/sbin/inspace-bootstrap-rke2"]
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid shell: %v: %s", err, output)
	}
	for _, required := range []string{
		`ip -o -4 addr show to "$vpc_subnet" scope global`, "PRIVATE_IF=", "PRIVATE_IP=", "systemctl list-unit-files --type=service", "systemctl disable --now ufw.service", "disabled|masked", "ufw status",
		"systemctl enable rke2-server.service", "systemctl start --no-block rke2-server.service", `"$attempt" -ge 180`,
		"--max-time 300 --retry 3 --retry-all-errors", "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml",
		"/var/lib/rancher/rke2/server/manifests/inspace-private-load-balancer.yaml",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("bootstrap script lacks %q", required)
		}
	}
	for _, forbidden := range []string{"iptables -F", "iptables --flush", "nft flush", "ufw --force enable", "ufw allow ", "find_private_ip"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("bootstrap script contains forbidden %q", forbidden)
		}
	}
	config := files["/var/lib/inspace/rke2-config"]
	for _, required := range []string{"node-ip: __PRIVATE_IP__", "advertise-address: __PRIVATE_IP__", "node-external-ip:", "disable-kube-proxy: true", `"10.20.30.10"`} {
		if !strings.Contains(config, required) {
			t.Errorf("RKE2 config lacks %q", required)
		}
	}
	if initialize == strings.Contains(config, "server: ") {
		t.Errorf("initialize/join config mismatch: %s", config)
	}
	if !initialize && !strings.Contains(config, `server: "https://10.20.30.10:9345"`) {
		t.Error("join does not use private VIP registration endpoint")
	}
	staticPod := files["/var/lib/inspace/rke2-kube-vip"]
	for _, required := range []string{kubeVIPImage, "vip_interface", "__PRIVATE_IFACE__", "vip_arp", "cp_enable", "svc_enable", `value: "false"`, "vip_leaderelection", "inspace-control-plane-vip", "k8s_config_file", "hostNetwork: true", "type: File", "app.kubernetes.io/component: control-plane-vip"} {
		if !strings.Contains(staticPod, required) {
			t.Errorf("kube-vip static Pod lacks %q", required)
		}
	}
	if strings.Contains(staticPod, "DaemonSet") || strings.Contains(staticPod, "servicesElection") {
		t.Errorf("kube-vip manifest enables an obsolete deployment/service path: %s", staticPod)
	}
	ciliumConfig := files["/var/lib/inspace/rke2-cilium-config"]
	for _, required := range []string{"l2announcements:\n      enabled: true", "defaultLBServiceIPAM: none", "nodeIPAM:\n      enabled: false", "k8sClientRateLimit:\n      qps: 10\n      burst: 20"} {
		if !strings.Contains(ciliumConfig, required) {
			t.Errorf("RKE2 Cilium config lacks %q", required)
		}
	}
	privateLoadBalancer := files["/var/lib/inspace/rke2-cilium-private-load-balancer"]
	for _, required := range []string{
		"apiVersion: cilium.io/v2\nkind: CiliumLoadBalancerIPPool", `start: "10.20.30.200"`, `stop: "10.20.30.239"`,
		"inspace.cloud/load-balancer-scope: private", "apiVersion: cilium.io/v2alpha1\nkind: CiliumL2AnnouncementPolicy",
		"key: kubernetes.io/os\n        operator: In\n        values:\n          - linux",
		"key: inspace.cloud/l2-announcement-disabled\n        operator: DoesNotExist", "externalIPs: false", "loadBalancerIPs: true",
	} {
		if !strings.Contains(privateLoadBalancer, required) {
			t.Errorf("Cilium private load-balancer manifest lacks %q", required)
		}
	}
	if strings.Contains(privateLoadBalancer, "interfaces:") || strings.Contains(privateLoadBalancer, "CiliumNodeConfig") || strings.Contains(ciliumConfig, "nodeIPAM:\n      enabled: true") {
		t.Errorf("Cilium private load-balancer contract enabled a forbidden interface or Node IPAM path: %s\n%s", privateLoadBalancer, ciliumConfig)
	}
}

func assertBastionCloudInit(t *testing.T, raw string) {
	t.Helper()
	files := decodeWriteFiles(t, raw)
	script := files["/usr/local/sbin/inspace-disable-ufw"]
	for _, required := range []string{"ufw --force disable", "systemctl list-unit-files --type=service", "systemctl disable --now ufw.service", "disabled|masked", "ufw status", "systemctl is-active", "systemctl is-enabled"} {
		if !strings.Contains(script, required) {
			t.Errorf("bastion UFW script lacks %q", required)
		}
	}
	if strings.Contains(script, "ufw --force disable || true") || strings.Contains(script, "systemctl disable --now ufw.service >/dev/null 2>&1 || true") || strings.Contains(script, "iptables") || strings.Contains(script, "nft ") {
		t.Errorf("bastion UFW disable is not fail-closed: %s", script)
	}
}

func decodeWriteFiles(t *testing.T, raw string) map[string]string {
	t.Helper()
	var payload struct {
		WriteFiles []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(payload.WriteFiles))
	for _, file := range payload.WriteFiles {
		decoded, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			t.Fatal(err)
		}
		result[file.Path] = string(decoded)
	}
	return result
}

func mustVMRequest(t *testing.T, requests []inspace.CreateVMRequest, name string) inspace.CreateVMRequest {
	t.Helper()
	for _, request := range requests {
		if request.Name == name {
			return request
		}
	}
	t.Fatalf("VM request %q not found", name)
	return inspace.CreateVMRequest{}
}

func mustVM(t *testing.T, vms []inspace.VM, name string) *inspace.VM {
	t.Helper()
	for i := range vms {
		if vms[i].Name == name {
			return &vms[i]
		}
	}
	t.Fatalf("VM %q not found", name)
	return nil
}

func mustFirewall(t *testing.T, firewalls []inspace.Firewall, name string) *inspace.Firewall {
	t.Helper()
	for i := range firewalls {
		if firewalls[i].EffectiveName() == name {
			return &firewalls[i]
		}
	}
	t.Fatalf("firewall %q not found", name)
	return nil
}

type fakeAPI struct {
	mu                      sync.Mutex
	network                 inspace.Network
	loadBalancers           []inspace.LoadBalancer
	vms                     []inspace.VM
	firewalls               []inspace.Firewall
	floatingIPs             []inspace.FloatingIP
	vmCreates               []inspace.CreateVMRequest
	vmDeletes               []string
	firewallCreates         []inspace.CreateFirewallRequest
	firewallCreateResponses []inspace.Firewall
	getVMCalls              []string

	floatingIPDeletes []string
	firewallDeletes   []string
	events            []string

	failFirewallAssignmentForName     string
	failVMCreateNames                 map[string]error
	privateIPByName                   map[string]string
	mutateCreateVMResponse            func(inspace.CreateVMRequest, *inspace.VM)
	mutateCreateFloatingIPResponse    func(*inspace.FloatingIP)
	mutateAssignFloatingIPResponse    func(*inspace.FloatingIP)
	mutateCreateFirewallResponse      func(inspace.CreateFirewallRequest, *inspace.Firewall)
	mutateGetVMResponse               func(*inspace.VM)
	getVMErrorByUUID                  map[string]error
	nilGetVMUUID                      string
	floatingIPAssignError             error
	omitFirewallDescriptions          bool
	sparseVMListResponses             bool
	sparseFirewallCreateResponses     bool
	retainFirewallAssignmentsOnDelete bool
	vmDeleteError                     error
	vmDeleteErrorCommits              bool
	createVMBarrier                   chan struct{}
	createVMStarted                   chan string
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{network: inspace.Network{UUID: "11111111-2222-4333-8444-555555555555", Name: "private", Type: "private", Subnet: "10.20.30.0/24"}}
}

func (f *fakeAPI) GetNetwork(context.Context, string, string) (*inspace.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := f.network
	copy.VMUUIDs = append([]string(nil), f.network.VMUUIDs...)
	return &copy, nil
}
func (f *fakeAPI) ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inspace.LoadBalancer(nil), f.loadBalancers...), nil
}
func (f *fakeAPI) ListVMs(context.Context, string) ([]inspace.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := append([]inspace.VM(nil), f.vms...)
	if f.sparseVMListResponses {
		for i := range items {
			items[i].DesignatedPoolUUID = ""
			items[i].NetworkUUID = ""
		}
	}
	return items, nil
}
func (f *fakeAPI) GetVM(_ context.Context, _, uuid string) (*inspace.VM, error) {
	f.mu.Lock()
	f.getVMCalls = append(f.getVMCalls, uuid)
	injected := f.getVMErrorByUUID[uuid]
	returnNil := f.nilGetVMUUID == uuid
	mutate := f.mutateGetVMResponse
	var found *inspace.VM
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			copy := f.vms[i]
			copy.Storage = append([]inspace.VMStorage(nil), f.vms[i].Storage...)
			found = &copy
			break
		}
	}
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	if returnNil {
		return nil, nil
	}
	if found == nil {
		return nil, &inspace.APIError{StatusCode: 404, Method: "GET", Path: "/vm", Message: "not found"}
	}
	if mutate != nil {
		mutate(found)
	}
	return found, nil
}
func (f *fakeAPI) CreateVM(ctx context.Context, _ string, request inspace.CreateVMRequest) (*inspace.VM, error) {
	f.mu.Lock()
	f.vmCreates = append(f.vmCreates, request)
	f.events = append(f.events, "create-vm/"+request.Name)
	index := len(f.vmCreates)
	barrier, started := f.createVMBarrier, f.createVMStarted
	mutateResponse := f.mutateCreateVMResponse
	injected := f.failVMCreateNames[request.Name]
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	if barrier != nil {
		select {
		case started <- request.Name:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	vm := inspace.VM{
		UUID: fmt.Sprintf("%08d-1111-4222-8333-bbbbbbbbbbbb", index), Name: request.Name, Description: request.Description,
		Status: "running", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB, OSName: request.OSName, OSVersion: request.OSVersion,
		PrivateIPv4: fmt.Sprintf("10.20.30.%d", 20+index), NetworkUUID: request.NetworkUUID, BillingAccountID: request.BillingAccountID,
		DesignatedPoolUUID: request.DesignatedPoolUUID,
		Storage:            []inspace.VMStorage{{UUID: fmt.Sprintf("%08d-9999-4222-8333-bbbbbbbbbbbb", index), Name: "vda", SizeGiB: request.DiskGiB, Primary: true}},
	}
	if privateIP := f.privateIPByName[request.Name]; privateIP != "" {
		vm.PrivateIPv4 = privateIP
	}
	response := vm
	if mutateResponse != nil {
		mutateResponse(request, &response)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vms = append(f.vms, vm)
	f.network.VMUUIDs = append(f.network.VMUUIDs, vm.UUID)
	return &response, nil
}
func (f *fakeAPI) DeleteVM(_ context.Context, _ string, uuid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vmDeletes = append(f.vmDeletes, uuid)
	f.events = append(f.events, "delete-vm/"+uuid)
	if f.vmDeleteError != nil && !f.vmDeleteErrorCommits {
		return f.vmDeleteError
	}
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			f.vms = append(f.vms[:i], f.vms[i+1:]...)
			break
		}
	}
	for i := range f.network.VMUUIDs {
		if f.network.VMUUIDs[i] == uuid {
			f.network.VMUUIDs = append(f.network.VMUUIDs[:i], f.network.VMUUIDs[i+1:]...)
			break
		}
	}
	if !f.retainFirewallAssignmentsOnDelete {
		for i := range f.firewalls {
			kept := f.firewalls[i].ResourcesAssigned[:0]
			for _, resource := range f.firewalls[i].ResourcesAssigned {
				if resource.ResourceUUID != uuid {
					kept = append(kept, resource)
				}
			}
			f.firewalls[i].ResourcesAssigned = kept
		}
	}
	return f.vmDeleteError
}

// removeVMFromReadback simulates eventual convergence after the per-VM
// endpoint has already reported absence while the location list was stale.
// It deliberately records no controller mutation event.
func (f *fakeAPI) removeVMFromReadback(uuid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.vms {
		if f.vms[i].UUID == uuid {
			f.vms = append(f.vms[:i], f.vms[i+1:]...)
			break
		}
	}
	for i := range f.network.VMUUIDs {
		if f.network.VMUUIDs[i] == uuid {
			f.network.VMUUIDs = append(f.network.VMUUIDs[:i], f.network.VMUUIDs[i+1:]...)
			break
		}
	}
	for i := range f.firewalls {
		kept := f.firewalls[i].ResourcesAssigned[:0]
		for _, resource := range f.firewalls[i].ResourcesAssigned {
			if resource.ResourceUUID != uuid {
				kept = append(kept, resource)
			}
		}
		f.firewalls[i].ResourcesAssigned = kept
	}
	for i := range f.floatingIPs {
		if f.floatingIPs[i].AssignedTo == uuid {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			f.floatingIPs[i].AssignedToPrivateIP = ""
		}
	}
}

func (f *fakeAPI) clearAllFirewallAssignments() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.firewalls {
		f.firewalls[i].ResourcesAssigned = nil
	}
}

func (f *fakeAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := append([]inspace.Firewall(nil), f.firewalls...)
	if f.omitFirewallDescriptions {
		for i := range items {
			items[i].Description = ""
		}
	}
	return items, nil
}
func (f *fakeAPI) CreateFirewall(_ context.Context, _ string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.firewallCreates = append(f.firewallCreates, request)
	item := inspace.Firewall{UUID: fmt.Sprintf("7777777%d-1111-4222-8333-444444444444", len(f.firewalls)), DisplayName: request.DisplayName, Description: request.Description, BillingAccountID: request.BillingAccountID, Rules: request.Rules}
	f.firewalls = append(f.firewalls, item)
	f.events = append(f.events, "create-firewall/"+request.DisplayName)
	response := item
	if f.sparseFirewallCreateResponses {
		response = inspace.Firewall{UUID: item.UUID}
	}
	if f.mutateCreateFirewallResponse != nil {
		f.mutateCreateFirewallResponse(request, &response)
	}
	if f.omitFirewallDescriptions {
		response.Description = ""
	}
	f.firewallCreateResponses = append(f.firewallCreateResponses, response)
	return &response, nil
}
func (f *fakeAPI) AssignFirewallToVM(_ context.Context, _ string, firewallUUID, vmUUID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.firewalls {
		if f.firewalls[i].UUID != firewallUUID {
			continue
		}
		if f.failFirewallAssignmentForName != "" && strings.Contains(f.firewalls[i].DisplayName, f.failFirewallAssignmentForName) {
			return errors.New("injected firewall failure")
		}
		for _, resource := range f.firewalls[i].ResourcesAssigned {
			if resource.ResourceUUID == vmUUID {
				return nil
			}
		}
		f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
		return nil
	}
	return errors.New("firewall not found")
}
func (f *fakeAPI) DeleteFirewall(_ context.Context, _, uuid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.firewallDeletes = append(f.firewallDeletes, uuid)
	f.events = append(f.events, "delete-firewall/"+uuid)
	for i := range f.firewalls {
		if f.firewalls[i].UUID == uuid {
			f.firewalls = append(f.firewalls[:i], f.firewalls[i+1:]...)
			break
		}
	}
	return nil
}
func (f *fakeAPI) ListFloatingIPs(_ context.Context, _ string, filters *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]inspace.FloatingIP, 0, len(f.floatingIPs))
	for _, item := range f.floatingIPs {
		if filters != nil && filters.BillingAccountID != 0 && item.BillingAccountID != filters.BillingAccountID {
			continue
		}
		result = append(result, item)
	}
	return result, nil
}
func (f *fakeAPI) CreateFloatingIP(_ context.Context, _ string, request inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item := inspace.FloatingIP{
		Name: request.Name, Address: fmt.Sprintf("203.0.113.%d", 10+len(f.floatingIPs)), BillingAccountID: request.BillingAccountID,
		Type: "public", Enabled: true,
	}
	if f.mutateCreateFloatingIPResponse != nil {
		f.mutateCreateFloatingIPResponse(&item)
	}
	f.floatingIPs = append(f.floatingIPs, item)
	f.events = append(f.events, "create-fip/"+request.Name)
	return &item, nil
}
func (f *fakeAPI) AssignFloatingIP(_ context.Context, _, address, resourceUUID, resourceType string) (*inspace.FloatingIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = resourceUUID
			f.floatingIPs[i].AssignedToResourceType = resourceType
			for j := range f.vms {
				if f.vms[j].UUID == resourceUUID {
					f.floatingIPs[i].AssignedToPrivateIP = f.vms[j].PrivateIPv4
					break
				}
			}
			if f.mutateAssignFloatingIPResponse != nil {
				f.mutateAssignFloatingIPResponse(&f.floatingIPs[i])
			}
			copy := f.floatingIPs[i]
			if f.floatingIPAssignError != nil {
				return &copy, f.floatingIPAssignError
			}
			return &copy, nil
		}
	}
	return nil, errors.New("floating IP not found")
}
func (f *fakeAPI) UnassignFloatingIP(_ context.Context, _, address string) (*inspace.FloatingIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			f.floatingIPs[i].AssignedToPrivateIP = ""
			copy := f.floatingIPs[i]
			f.events = append(f.events, "unassign-fip/"+address)
			return &copy, nil
		}
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "POST", Path: "/ip/unassign", Message: "not found"}
}
func (f *fakeAPI) DeleteFloatingIP(_ context.Context, _, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floatingIPDeletes = append(f.floatingIPDeletes, address)
	f.events = append(f.events, "delete-fip/"+address)
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs = append(f.floatingIPs[:i], f.floatingIPs[i+1:]...)
			break
		}
	}
	return nil
}

var _ API = (*fakeAPI)(nil)
