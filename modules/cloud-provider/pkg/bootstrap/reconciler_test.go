package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestReconcileBuildsBastionThenExactlyThreeControlPlaneVMs(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	wantBastionName := cluster.Metadata.Name + "-bastion"

	first, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if first.Ready || len(api.vmCreates) != 1 || api.vmCreates[0].Name != wantBastionName {
		t.Fatalf("first reconcile did not create only the bastion: result=%#v creates=%#v", first, api.vmCreates)
	}
	if api.vmCreates[0].VCPU != BastionVCPU || api.vmCreates[0].MemoryMiB != BastionMemoryMiB || api.vmCreates[0].DiskGiB != BastionRootDiskGiB ||
		api.vmCreates[0].OSName != "ubuntu" || api.vmCreates[0].OSVersion != "24.04" {
		t.Fatalf("bastion shape = %#v", api.vmCreates[0])
	}
	owner := ownerKey(cluster)
	if !strings.HasPrefix(api.vmCreates[0].Description, "inspace-rke2-bastion/v3 owner="+owner+" spec=") {
		t.Fatalf("bastion ownership description = %q", api.vmCreates[0].Description)
	}
	assertBastionCloudInit(t, api.vmCreates[0].CloudInit, wantBastionName)
	if len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID ||
		len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != "" || api.floatingIPs[0].AssignedTo == "" {
		t.Fatalf("first reconcile must return only after the bastion is firewalled with one nameless assigned auto FIP: firewalls=%#v FIPs=%#v", api.firewalls, api.floatingIPs)
	}
	if api.vmCreates[0].ReservePublicIP == nil || !*api.vmCreates[0].ReservePublicIP {
		t.Fatalf("bastion did not request an auto floating IP: %#v", api.vmCreates[0])
	}
	createFirewallIndex, createVMIndex, assignFirewallIndex := -1, -1, -1
	for index, event := range api.events {
		switch {
		case strings.HasPrefix(event, "create-firewall/"):
			createFirewallIndex = index
		case strings.HasPrefix(event, "create-vm/"):
			createVMIndex = index
		case strings.HasPrefix(event, "assign-firewall/"):
			assignFirewallIndex = index
		}
	}
	if createFirewallIndex < 0 || createVMIndex <= createFirewallIndex || assignFirewallIndex <= createVMIndex {
		t.Fatalf("bastion firewall/create/assignment order is unsafe: %v", api.events)
	}

	result := reconcileUntilReady(t, reconciler, cluster)
	if len(api.vms) != 4 || len(api.vmCreates) != 4 {
		t.Fatalf("VMs=%d creates=%d, want bastion+3 control-plane", len(api.vms), len(api.vmCreates))
	}
	if len(api.firewalls) != 2 || len(api.floatingIPs) != 4 {
		t.Fatalf("firewalls=%#v floatingIPs=%#v", api.firewalls, api.floatingIPs)
	}
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
	bastion := mustVM(t, api.vms, wantBastionName)
	if bastion.Hostname != wantBastionName {
		t.Fatalf("bastion authoritative hostname=%q", bastion.Hostname)
	}
	if mustFirewall(t, api.firewalls, bastionFirewallName(owner)).EffectiveName() != "rke2-"+owner+"-bastion" || api.floatingIPs[0].Name != bastionFloatingIPName(owner) {
		t.Fatalf("owner-derived bastion firewall/FIP changed: firewalls=%#v floatingIPs=%#v", api.firewalls, api.floatingIPs)
	}
	privateLoadBalancerManifest := ""
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		expectedName := fmt.Sprintf("unit-cp%d", slot)
		if got := controlPlaneName(cluster.Metadata.Name, slot); got != expectedName {
			t.Fatalf("control-plane slot %d name=%q, want %q", slot, got, expectedName)
		}
		request := mustVMRequest(t, api.vmCreates, expectedName)
		if request.ReservePublicIP == nil || !*request.ReservePublicIP {
			t.Errorf("control-plane slot %d did not request its auto floating IP", slot)
		}
		assertControlPlaneCloudInit(t, request.CloudInit, request.Name, slot == 0)
		files := decodeWriteFiles(t, request.CloudInit)
		if strings.Contains(files["/var/lib/inspace/rke2-config"], "node-external-ip:") {
			t.Errorf("control-plane slot %d configured an external IP before CCM discovery", slot)
		}
		manifest := files["/var/lib/inspace/rke2-cilium-private-load-balancer"]
		if slot == 0 {
			privateLoadBalancerManifest = manifest
		} else if manifest != privateLoadBalancerManifest {
			t.Fatalf("slot %d rendered a non-identical Cilium private load-balancer manifest", slot)
		}
	}
	for _, floatingIP := range api.floatingIPs {
		if floatingIP.Name == "" || floatingIP.AssignedTo == "" || floatingIP.AssignedToResourceType != "virtual_machine" {
			t.Errorf("owned floating IP is not assigned to its VM: %#v", floatingIP)
		}
	}
	for _, event := range api.events {
		if strings.HasPrefix(event, "create-fip/") || strings.HasPrefix(event, "assign-fip/") {
			t.Fatalf("bootstrap used the standalone floating-IP create/assign API: %v", api.events)
		}
	}
	if result.MaxParallelControlPlaneCreates != ControlPlaneReplicas {
		t.Fatalf("parallel bound=%d", result.MaxParallelControlPlaneCreates)
	}
}

func TestReconcileRejectsLegacyOrForeignBastionBeforeMutation(t *testing.T) {
	tests := map[string]func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster){
		"legacy name": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			convertBastionToLegacy(t, api, cluster)
		},
		"foreign owner record": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
			bastion.Description = strings.Replace(bastion.Description, "owner="+ownerKey(cluster), "owner="+strings.Repeat("f", 16), 1)
		},
		"foreign hostname": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
			bastion.Hostname = "foreign-bastion"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			mutate(t, api, cluster)
			eventsBefore := len(api.events)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
				t.Fatal("expected bastion adoption refusal")
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("bastion refusal mutated infrastructure: %v", api.events[eventsBefore:])
			}
		})
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
			bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
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
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
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
			bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
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
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
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
			var reconcileErr error
			for attempt := 0; attempt < 10 && reconcileErr == nil; attempt++ {
				_, reconcileErr = reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
			}
			if reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "create bastion firewall response") {
				t.Fatalf("expected provisional identity rejection, got %v", reconcileErr)
			}
			if len(api.firewalls) != 1 || len(api.firewallCreates) != 1 || len(api.firewallDeletes) != 0 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("ambiguous POST response caused unsafe mutation or deletion: firewalls=%#v creates=%#v deletes=%#v VMs=%#v FIPs=%#v", api.firewalls, api.firewallCreates, api.firewallDeletes, api.vms, api.floatingIPs)
			}
			api.mutateCreateFirewallResponse = nil
			reconcileUntilReady(t, reconciler, cluster)
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
			if name == currentBastionName(cluster.Metadata.Name) {
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
		if len(api.firewalls) != 2 {
			t.Fatalf("control-plane firewall was not created before VM launch: %#v", api.firewalls)
		}
		nodeFirewall := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
		if len(nodeFirewall.ResourcesAssigned) != ControlPlaneReplicas {
			t.Fatalf("control-plane create returned before every VM was firewalled: %#v", nodeFirewall.ResourcesAssigned)
		}
		for _, floatingIP := range api.floatingIPs {
			if floatingIP.Name != bastionFloatingIPName(ownerKey(cluster)) && (floatingIP.Name != "" || floatingIP.AssignedTo == "") {
				t.Fatalf("control-plane create did not retain its nameless assigned auto FIP: %#v", floatingIP)
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
	api.failVMCreateNames = map[string]error{
		controlPlaneName(cluster.Metadata.Name, 2): errors.New("slot two"),
		controlPlaneName(cluster.Metadata.Name, 0): errors.New("slot zero"),
	}
	result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || strings.Index(err.Error(), "slot 0") > strings.Index(err.Error(), "slot 2") {
		t.Fatalf("errors are not slot ordered: %v", err)
	}
	if len(result.ControlPlaneVMs) != 1 || len(api.vms) != 2 {
		t.Fatalf("successful bastion/CP state was not retained: result=%#v VMs=%#v", result, api.vms)
	}
}

func TestBastionFirewallFailureRollsBackNewPublicVM(t *testing.T) {
	api := newFakeAPI()
	api.failFirewallAssignmentForName = "bastion"
	cluster := testCluster()
	reconciler := testReconciler(api)
	_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("rollback error=%v creates=%#v deletes=%#v VMs=%#v", err, api.vmCreates, api.vmDeletes, api.vms)
	}
	assignIndex, fipDeleteIndex, vmDeleteIndex := -1, -1, -1
	for index, event := range api.events {
		switch {
		case strings.HasPrefix(event, "assign-firewall/"):
			assignIndex = index
		case strings.HasPrefix(event, "delete-fip/"):
			fipDeleteIndex = index
		case strings.HasPrefix(event, "delete-vm/"):
			vmDeleteIndex = index
		}
	}
	if assignIndex < 0 || fipDeleteIndex <= assignIndex || vmDeleteIndex <= fipDeleteIndex {
		t.Fatalf("unprotected VM rollback order is unsafe: %v", api.events)
	}
}

func TestAmbiguousCommittedFirewallAssignmentProtectsNewVM(t *testing.T) {
	api := newFakeAPI()
	api.firewallAssignmentError = io.ErrUnexpectedEOF
	api.firewallAssignmentErrorCommits = true
	cluster := testCluster()
	result, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err != nil {
		t.Fatalf("committed assignment ambiguity was not recovered by readback: %v", err)
	}
	if len(api.vms) != 1 || len(api.vmDeletes) != 0 || len(api.floatingIPs) != 1 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 {
		t.Fatalf("committed assignment was rolled back or left unprotected: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestControlPlaneFirewallFailureRollsBackEveryNewPublicVM(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	api.failFirewallAssignmentForName = "nodes"

	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("expected control-plane firewall assignment failure")
	}
	if len(api.vmCreates) != 1+ControlPlaneReplicas || len(api.vmDeletes) != ControlPlaneReplicas || len(api.vms) != 1 {
		t.Fatalf("unprotected control planes were retained: creates=%#v deletes=%#v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
	}
	if api.vms[0].Name != currentBastionName(cluster.Metadata.Name) || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != api.vms[0].UUID {
		t.Fatalf("control-plane rollback touched the protected bastion or leaked auto FIPs: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
	nodeFirewall := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
	if len(nodeFirewall.ResourcesAssigned) != 0 {
		t.Fatalf("failed control-plane firewall assignments appeared committed: %#v", nodeFirewall.ResourcesAssigned)
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
	api.vms = append(api.vms, inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: controlPlaneName(cluster.Metadata.Name, 1), PrivateIPv4: "10.20.30.21",
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

func TestReconcileFailsClosedOnLegacyOwnerNamedControlPlanes(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	owner := ownerKey(cluster)
	api.vms = append(api.vms, inspace.VM{
		UUID:        "99999999-1111-4222-8333-bbbbbbbbbbbb",
		Name:        fmt.Sprintf("rke2-%s-cp-0", owner),
		Hostname:    fmt.Sprintf("rke2-%s-cp-0", owner),
		Description: fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=0 spec=%s", owner, strings.Repeat("a", 64)),
	})
	_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || !strings.Contains(err.Error(), "unexpected VM") {
		t.Fatalf("expected explicit legacy-topology refusal, got %v", err)
	}
	if len(api.vmCreates) != 0 || len(api.vmDeletes) != 0 || len(api.floatingIPs) != 0 || len(api.firewallCreates) != 0 {
		t.Fatalf("legacy topology caused mutations: creates=%#v deletes=%#v FIPs=%#v firewalls=%#v", api.vmCreates, api.vmDeletes, api.floatingIPs, api.firewallCreates)
	}
}

func TestReconcileCanonicalControlPlaneHostnameAllowsOmissionButRejectsMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		hostname  string
		wantError bool
	}{
		{name: "API omission", hostname: ""},
		{name: "API mismatch", hostname: "foreign", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			cpName := controlPlaneName(cluster.Metadata.Name, 1)
			api.mutateGetVMResponse = func(vm *inspace.VM) {
				if vm.Name == cpName {
					vm.Hostname = test.hostname
				}
			}
			eventsBefore := len(api.events)
			_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
			if test.wantError && (err == nil || !strings.Contains(err.Error(), "authoritative hostname")) {
				t.Fatalf("expected hostname mismatch refusal, got %v", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("omitted API hostname must be tolerated: %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("hostname readback caused mutation: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestReverseFirewallAuditRejectsForeignAttachment(t *testing.T) {
	for _, operation := range []string{"reconcile", "destroy"} {
		t.Run(operation, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			ownedVM := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 0))
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

func TestResidualFloatingIPBlocksVMPost(t *testing.T) {
	ownedResidual := func(name string) inspace.FloatingIP {
		return inspace.FloatingIP{
			Address: "203.0.113.240", BillingAccountID: 42, Type: "public", Name: name, Enabled: true,
		}
	}
	t.Run("bastion initial snapshot", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		api.floatingIPs = append(api.floatingIPs, ownedResidual(bastionFloatingIPName(ownerKey(cluster))))
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "residual floating IP") {
			t.Fatalf("active bastion residual was accepted: %v", err)
		}
		if len(api.vmCreates) != 0 || len(api.firewallCreates) != 0 || len(api.events) != 0 {
			t.Fatalf("initial residual audit allowed mutation: creates=%#v firewalls=%#v events=%#v", api.vmCreates, api.firewallCreates, api.events)
		}
	})
	t.Run("bastion immediate pre-POST relist", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		residual := ownedResidual(bastionFloatingIPName(ownerKey(cluster)))
		api.floatingIPAfterFirewallCreate = &residual
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "active residual floating IP") {
			t.Fatalf("TOCTOU bastion residual was accepted: %v", err)
		}
		if len(api.vmCreates) != 0 {
			t.Fatalf("TOCTOU residual allowed a bastion VM POST: %#v", api.vmCreates)
		}
	})
	t.Run("control-plane initial snapshot", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		prepareBastion(t, reconciler, cluster)
		api.floatingIPs = append(api.floatingIPs, ownedResidual(nodeFloatingIPName(ownerKey(cluster), 1)))
		eventsBefore := len(api.events)
		if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "residual floating IP") {
			t.Fatalf("active control-plane residual was accepted: %v", err)
		}
		if len(api.vmCreates) != 1 || len(api.events) != eventsBefore {
			t.Fatalf("control-plane residual allowed mutation: creates=%#v events=%#v", api.vmCreates, api.events[eventsBefore:])
		}
	})
	t.Run("control-plane pre-batch relist", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		prepareBastion(t, reconciler, cluster)
		residual := ownedResidual(nodeFloatingIPName(ownerKey(cluster), 2))
		api.floatingIPAfterFirewallCreate = &residual
		if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "active residual floating IP") {
			t.Fatalf("TOCTOU control-plane residual was accepted: %v", err)
		}
		if len(api.vmCreates) != 1 {
			t.Fatalf("pre-batch residual allowed a control-plane VM POST: %#v", api.vmCreates)
		}
	})
	t.Run("deleted tombstone does not block", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		tombstone := ownedResidual(bastionFloatingIPName(ownerKey(cluster)))
		tombstone.IsDeleted = true
		api.floatingIPs = append(api.floatingIPs, tombstone)
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
			t.Fatalf("deleted residual tombstone blocked VM create: %v", err)
		}
		if len(api.vmCreates) != 1 {
			t.Fatalf("deleted tombstone unexpectedly blocked bastion POST: %#v", api.vmCreates)
		}
	})
}

func TestMalformedCreateVMResponseRollsBackBeforeProtection(t *testing.T) {
	api := newFakeAPI()
	api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("malformed create response was not rolled back: error=%v creates=%d deletes=%v VMs=%#v", err, len(api.vmCreates), api.vmDeletes, api.vms)
	}
	for _, firewall := range api.firewalls {
		if len(firewall.ResourcesAssigned) != 0 {
			t.Fatalf("malformed create response reached firewall attachment: %#v", api.firewalls)
		}
	}
	if len(api.floatingIPs) != 0 {
		t.Fatalf("malformed create response left its auto floating IP behind: %#v", api.floatingIPs)
	}
	unassignIndex, fipDeleteIndex, vmDeleteIndex := -1, -1, -1
	for index, event := range api.events {
		switch {
		case strings.HasPrefix(event, "unassign-fip/"):
			unassignIndex = index
		case strings.HasPrefix(event, "delete-fip/"):
			fipDeleteIndex = index
		case strings.HasPrefix(event, "delete-vm/"):
			vmDeleteIndex = index
		}
	}
	if unassignIndex < 0 || fipDeleteIndex <= unassignIndex || vmDeleteIndex <= fipDeleteIndex {
		t.Fatalf("malformed create rollback order was unsafe: %v", api.events)
	}
}

func TestSparseCreateVMResponseIsProtectedOrRolledBack(t *testing.T) {
	sparsify := func(_ inspace.CreateVMRequest, vm *inspace.VM) {
		*vm = inspace.VM{UUID: vm.UUID, Name: vm.Name}
	}
	t.Run("successful assignment", func(t *testing.T) {
		api := newFakeAPI()
		api.mutateCreateVMResponse = sparsify
		cluster := testCluster()
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
			t.Fatal(err)
		}
		if len(api.vms) != 1 || len(api.vmDeletes) != 0 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID {
			t.Fatalf("sparse create response returned without exact firewall protection: VMs=%#v deletes=%#v firewalls=%#v", api.vms, api.vmDeletes, api.firewalls)
		}
	})
	t.Run("assignment failure", func(t *testing.T) {
		api := newFakeAPI()
		api.mutateCreateVMResponse = sparsify
		api.failFirewallAssignmentForName = "bastion"
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil {
			t.Fatal("expected sparse-response assignment failure")
		}
		if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("sparse-response assignment failure retained an unprotected resource: deletes=%#v VMs=%#v FIPs=%#v", api.vmDeletes, api.vms, api.floatingIPs)
		}
	})
	t.Run("ambiguous committed assignment", func(t *testing.T) {
		api := newFakeAPI()
		api.mutateCreateVMResponse = sparsify
		api.firewallAssignmentError = io.ErrUnexpectedEOF
		api.firewallAssignmentErrorCommits = true
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err != nil {
			t.Fatalf("sparse-response committed assignment was not proven by readback: %v", err)
		}
		if len(api.vms) != 1 || len(api.vmDeletes) != 0 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 {
			t.Fatalf("sparse-response committed assignment was rolled back: VMs=%#v deletes=%#v firewalls=%#v", api.vms, api.vmDeletes, api.firewalls)
		}
	})
	t.Run("ambiguous committed create", func(t *testing.T) {
		api := newFakeAPI()
		api.mutateCreateVMResponse = sparsify
		cluster := testCluster()
		name := currentBastionName(cluster.Metadata.Name)
		api.failVMCreateNames = map[string]error{name: io.ErrUnexpectedEOF}
		api.commitVMCreateErrors = map[string]bool{name: true}
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ambiguous create error was not preserved: %v", err)
		}
		if len(api.vms) != 1 || len(api.vmDeletes) != 0 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 {
			t.Fatalf("sparse ambiguous create returned with an unprotected VM: VMs=%#v deletes=%#v firewalls=%#v", api.vms, api.vmDeletes, api.firewalls)
		}
	})
}

func TestUUIDLessCreateResponseDiscoversAndProtectsBeforeCanonicalReadback(t *testing.T) {
	for _, test := range []struct {
		name            string
		listDelay       int
		ambiguousCreate bool
	}{
		{name: "immediate discovery"},
		{name: "eventually consistent discovery", listDelay: 2},
		{name: "ambiguous committed create", ambiguousCreate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			bastionName := currentBastionName(cluster.Metadata.Name)
			api.mutateCreateVMResponse = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.UUID = "" }
			api.vmListReadbackDelay = test.listDelay
			api.requireProtectionBeforeGetVM = true
			if test.ambiguousCreate {
				api.failVMCreateNames = map[string]error{bastionName: io.ErrUnexpectedEOF}
				api.commitVMCreateErrors = map[string]bool{bastionName: true}
			}

			_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
			if test.ambiguousCreate {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("ambiguous create error was not preserved after secure recovery: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(api.vmCreates) != 1 || len(api.vms) != 1 || len(api.vmDeletes) != 0 {
				t.Fatalf("UUID-less recovery duplicated or deleted the committed VM: creates=%d VMs=%#v deletes=%#v", len(api.vmCreates), api.vms, api.vmDeletes)
			}
			if api.getVMBeforeProtectionCalls != 0 {
				t.Fatalf("canonical GetVM ran before protection %d times", api.getVMBeforeProtectionCalls)
			}
			if len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID {
				t.Fatalf("UUID-less response returned without exact firewall protection: %#v", api.firewalls)
			}
		})
	}
}

func TestUUIDLessUncommittedCreateDoesNotRetryPOST(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	bastionName := currentBastionName(cluster.Metadata.Name)
	api.failVMCreateNames = map[string]error{bastionName: io.ErrUnexpectedEOF}

	_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "protection is uncertain") {
		t.Fatalf("uncommitted UUID-less create did not report explicit uncertainty: %v", err)
	}
	if len(api.vmCreates) != 1 || len(api.vms) != 0 || len(api.vmDeletes) != 0 {
		t.Fatalf("uncommitted UUID-less create was retried or destructively guessed: creates=%d VMs=%#v deletes=%#v", len(api.vmCreates), api.vms, api.vmDeletes)
	}
}

func TestFirewallAssignmentRequiresExactAuthoritativeReadback(t *testing.T) {
	t.Run("nil without commit", func(t *testing.T) {
		api := newFakeAPI()
		api.firewallAssignmentNilWithoutCommit = true
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "without authoritative commit evidence") {
			t.Fatalf("nil uncommitted assignment was accepted: %v", err)
		}
		if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("nil uncommitted assignment retained public infrastructure: deletes=%#v VMs=%#v FIPs=%#v", api.vmDeletes, api.vms, api.floatingIPs)
		}
	})
	t.Run("delayed readback", func(t *testing.T) {
		api := newFakeAPI()
		api.firewallAssignmentReadbackDelay = 2
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err != nil {
			t.Fatalf("delayed committed assignment did not converge: %v", err)
		}
		if api.firewallAssignmentReadbackRemaining != 0 || len(api.vms) != 1 || len(api.vmDeletes) != 0 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 {
			t.Fatalf("delayed assignment was not authoritatively proven: remaining=%d VMs=%#v deletes=%#v firewalls=%#v", api.firewallAssignmentReadbackRemaining, api.vms, api.vmDeletes, api.firewalls)
		}
	})
	for _, drift := range []string{"duplicate", "wrong firewall"} {
		t.Run(drift, func(t *testing.T) {
			api := newFakeAPI()
			api.firewallAssignmentDuplicate = drift == "duplicate"
			api.firewallAssignmentWrongFirewall = drift == "wrong firewall"
			if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), drift) {
				t.Fatalf("%s assignment readback was accepted: %v", drift, err)
			}
			if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("%s assignment drift retained public infrastructure: deletes=%#v VMs=%#v FIPs=%#v", drift, api.vmDeletes, api.vms, api.floatingIPs)
			}
		})
	}
}

func TestFirewallPolicyDriftDuringAssignmentReadbackRollsBackVM(t *testing.T) {
	api := newFakeAPI()
	api.firewallAssignmentPolicyDrift = true
	_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || !strings.Contains(err.Error(), "policy drifted") {
		t.Fatalf("firewall rule TOCTOU drift was accepted: %v", err)
	}
	if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("policy drift retained a publicly addressed VM: deletes=%#v VMs=%#v FIPs=%#v", api.vmDeletes, api.vms, api.floatingIPs)
	}
}

func TestCanceledReconcileStillRollsBackUnprotectedCreatedVM(t *testing.T) {
	api := newFakeAPI()
	api.failFirewallAssignmentForName = "bastion"
	api.requireLiveSafetyContext = true
	ctx, cancel := context.WithCancel(context.Background())
	api.cancelAfterVMCreate = cancel

	if _, err := testReconciler(api).Reconcile(ctx, testCluster(), "unit-test-secret-token"); err == nil {
		t.Fatal("expected firewall assignment failure after caller cancellation")
	}
	if ctx.Err() == nil {
		t.Fatal("test did not cancel the caller context after VM creation")
	}
	if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("detached bounded safety cleanup did not run: deletes=%#v VMs=%#v FIPs=%#v", api.vmDeletes, api.vms, api.floatingIPs)
	}
}

func TestFloatingIPCleanupTimeoutDoesNotConsumeVMDeletePhase(t *testing.T) {
	api := newFakeAPI()
	api.failFirewallAssignmentForName = "bastion"
	api.blockFloatingIPCleanupAfterCreate = true
	api.requireLiveSafetyContext = true

	_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked floating-IP cleanup did not preserve its timeout: %v", err)
	}
	if len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("cleanup timeout consumed the detached VM-delete phase: deletes=%#v VMs=%#v", api.vmDeletes, api.vms)
	}
}

func TestMalformedCreateDeletesVMWhenAutoFloatingIPIsNotYetVisible(t *testing.T) {
	api := newFakeAPI()
	api.floatingIPReadbackDelay = 1
	api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	_, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token")
	if err == nil || !strings.Contains(err.Error(), "waiting for") {
		t.Fatalf("malformed response did not retain floating-IP cleanup uncertainty: %v", err)
	}
	if len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("invisible auto FIP prevented fail-closed VM deletion: deletes=%#v VMs=%#v", api.vmDeletes, api.vms)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("VM deletion contract was not reflected in delayed FIP state: %#v", api.floatingIPs)
	}
}

func TestMismatchedCreateVMResponseIsProtectedAndCanonicalized(t *testing.T) {
	api := newFakeAPI()
	api.mutateCreateVMResponse = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.Name = "unexpected" }
	if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err != nil {
		t.Fatalf("healthy canonical VM was rejected because its create response name drifted: %v", err)
	}
	if len(api.vmDeletes) != 0 {
		t.Fatalf("mismatched response was used as deletion authority despite healthy canonical readback: %v", api.vmDeletes)
	}
	if len(api.vms) != 1 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID {
		t.Fatalf("mismatched create response was not protected and canonicalized: VMs=%#v firewalls=%#v", api.vms, api.firewalls)
	}
}

func TestAuthoritativeVMWithoutPrivateIPIsFirewalledButNotAdoptedYet(t *testing.T) {
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
	if len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID {
		t.Fatalf("public VM without authoritative private IP was not already firewalled: %#v", api.firewalls)
	}
	if api.floatingIPs[0].Name != "" || api.floatingIPs[0].AssignedTo == "" {
		t.Fatalf("VM without authoritative private IP auto FIP was renamed or lost: %#v", api.floatingIPs[0])
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

func TestInvalidAutoFloatingIPBlocksRenameAndFirewall(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	api.floatingIPs[0].Enabled = false
	eventsBefore := len(api.events)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("expected strict auto floating-IP rejection")
	}
	if len(api.events) != eventsBefore || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.floatingIPs[0].Name != "" {
		t.Fatalf("invalid auto FIP was renamed or protected: events=%v firewalls=%#v FIP=%#v", api.events[eventsBefore:], api.firewalls, api.floatingIPs[0])
	}
}

func TestFloatingIPPatchResponseAndAmbiguousReadback(t *testing.T) {
	t.Run("malformed response", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
			t.Fatal(err)
		}
		api.mutateUpdateFloatingIPResponse = func(item *inspace.FloatingIP) { item.AssignedToPrivateIP = "10.20.30.99" }
		if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "update floating IP") {
			t.Fatalf("expected malformed PATCH response rejection, got %v", err)
		}
	})
	for _, commits := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous commits=%t", commits), func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			api.floatingIPUpdateError = errors.New("uncertain PATCH response")
			api.floatingIPUpdateErrorCommits = commits
			_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
			if commits && err != nil {
				t.Fatalf("committed PATCH ambiguity did not recover from readback: %v", err)
			}
			if !commits && err == nil {
				t.Fatal("non-committed PATCH ambiguity was accepted")
			}
			if commits && api.floatingIPs[0].Name != bastionFloatingIPName(ownerKey(cluster)) {
				t.Fatalf("committed PATCH name was not retained: %#v", api.floatingIPs[0])
			}
		})
	}
}

func TestAmbiguousVMCreateCommitConvergesWithoutDuplicate(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	bastionName := currentBastionName(cluster.Metadata.Name)
	createErr := io.ErrUnexpectedEOF
	api.failVMCreateNames = map[string]error{bastionName: createErr}
	api.commitVMCreateErrors = map[string]bool{bastionName: true}
	reconciler := testReconciler(api)

	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, createErr) {
		t.Fatalf("ambiguous committed create error was not preserved: %v", err)
	}
	if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != api.vms[0].UUID ||
		len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != api.vms[0].UUID {
		t.Fatalf("committed create did not retain exactly one protected VM/FIP pair: VMs=%#v FIPs=%#v firewalls=%#v", api.vms, api.floatingIPs, api.firewalls)
	}
	delete(api.failVMCreateNames, bastionName)
	delete(api.commitVMCreateErrors, bastionName)
	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || len(api.vmCreates) != 1+ControlPlaneReplicas || len(api.vms) != 1+ControlPlaneReplicas {
		t.Fatalf("ambiguous create recovery duplicated infrastructure: result=%#v creates=%#v VMs=%#v", result, api.vmCreates, api.vms)
	}
}

func TestAmbiguousMalformedCreateResponseRollsBackExactReturnedVM(t *testing.T) {
	t.Run("bastion", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		name := currentBastionName(cluster.Metadata.Name)
		createErr := io.ErrUnexpectedEOF
		api.failVMCreateNames = map[string]error{name: createErr}
		api.commitVMCreateErrors = map[string]bool{name: true}
		api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
		_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if !errors.Is(err, createErr) || !strings.Contains(err.Error(), "compute, image, or pool drift") {
			t.Fatalf("ambiguous malformed create evidence was not preserved: %v", err)
		}
		if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
			t.Fatalf("ambiguous malformed bastion remained public: deletes=%#v VMs=%#v FIPs=%#v", api.vmDeletes, api.vms, api.floatingIPs)
		}
	})
	t.Run("parallel control plane", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		reconciler := testReconciler(api)
		prepareBastion(t, reconciler, cluster)
		name := controlPlaneName(cluster.Metadata.Name, 1)
		createErr := io.ErrUnexpectedEOF
		api.failVMCreateNames = map[string]error{name: createErr}
		api.commitVMCreateErrors = map[string]bool{name: true}
		api.mutateStoredVM = func(request inspace.CreateVMRequest, vm *inspace.VM) {
			if request.Name == name {
				vm.VCPU++
			}
		}
		_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if !errors.Is(err, createErr) || !strings.Contains(err.Error(), "slot 1") {
			t.Fatalf("parallel ambiguous malformed error was not retained: %v", err)
		}
		if len(api.vmCreates) != 1+ControlPlaneReplicas || len(api.vmDeletes) != 1 || len(api.vms) != ControlPlaneReplicas || len(api.floatingIPs) != ControlPlaneReplicas {
			t.Fatalf("parallel malformed slot rollback touched successes or retained failure: creates=%#v deletes=%#v VMs=%#v FIPs=%#v", api.vmCreates, api.vmDeletes, api.vms, api.floatingIPs)
		}
		for _, vm := range api.vms {
			if vm.Name == name {
				t.Fatalf("malformed ambiguous slot survived rollback: %#v", vm)
			}
		}
	})
}

func TestFloatingIPInventoryRejectsAmbiguousOrForeignAssignmentBeforeMutation(t *testing.T) {
	tests := map[string]func(*fakeAPI){
		"multiple auto FIPs": func(api *fakeAPI) {
			duplicate := api.floatingIPs[0]
			duplicate.Address = "203.0.113.250"
			api.floatingIPs = append(api.floatingIPs, duplicate)
		},
		"foreign name assigned to owned VM": func(api *fakeAPI) {
			api.floatingIPs[0].Name = "foreign-ip"
		},
		"owned name assigned to foreign VM": func(api *fakeAPI) {
			api.floatingIPs[0].Name = bastionFloatingIPName(ownerKey(testCluster()))
			api.floatingIPs[0].AssignedTo = "99999999-1111-4222-8333-bbbbbbbbbbbb"
			api.floatingIPs[0].AssignedToPrivateIP = "10.20.30.99"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			mutate(api)
			eventsBefore := len(api.events)
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
				t.Fatal("expected floating-IP ownership refusal")
			}
			if len(api.events) != eventsBefore || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 {
				t.Fatalf("floating-IP refusal mutated infrastructure: %v", api.events[eventsBefore:])
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
		api.vms = append(api.vms, inspace.VM{UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: currentBastionName(cluster.Metadata.Name), PrivateIPv4: "10.20.30.20"})
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
		api.privateIPByName = map[string]string{currentBastionName(cluster.Metadata.Name): cluster.Spec.Endpoint.VirtualIPv4}
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
		api.privateIPByName = map[string]string{controlPlaneName(cluster.Metadata.Name, 1): cluster.Spec.Endpoint.VirtualIPv4}
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
		api.privateIPByName = map[string]string{currentBastionName(cluster.Metadata.Name): "10.20.30.200"}
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
		api.privateIPByName = map[string]string{controlPlaneName(cluster.Metadata.Name, 1): "10.20.30.201"}
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
		name := currentBastionName(cluster.Metadata.Name)
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

func TestDestroyNamesAutoFloatingIPBeforeUnassignAcrossRestarts(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != "" || api.floatingIPs[0].AssignedTo == "" {
		t.Fatalf("test setup does not contain one assigned nameless auto FIP: %#v", api.floatingIPs)
	}

	firstProcess := testReconciler(api)
	first, err := firstProcess.Destroy(context.Background(), cluster)
	if err != nil || !strings.Contains(first.Message, "named ") {
		t.Fatalf("first destroy pass did not name the auto FIP: result=%#v error=%v", first, err)
	}
	wantName := bastionFloatingIPName(ownerKey(cluster))
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != wantName || api.floatingIPs[0].AssignedTo == "" {
		t.Fatalf("first destroy pass did not retain a named assigned FIP: %#v", api.floatingIPs)
	}
	for _, event := range api.events {
		if strings.HasPrefix(event, "unassign-fip/") {
			t.Fatalf("first destroy pass unassigned before returning after PATCH: %v", api.events)
		}
	}

	secondProcess := testReconciler(api)
	second, err := secondProcess.Destroy(context.Background(), cluster)
	if err != nil || !strings.Contains(second.Message, "unassigned ") {
		t.Fatalf("second destroy pass did not unassign the named FIP: result=%#v error=%v", second, err)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != wantName || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("second destroy pass produced a nameless or assigned leak: %#v", api.floatingIPs)
	}

	thirdProcess := testReconciler(api)
	third, err := thirdProcess.Destroy(context.Background(), cluster)
	if err != nil || !strings.Contains(third.Message, "deleted ") || len(api.floatingIPs) != 0 {
		t.Fatalf("third destroy pass did not delete the named unassigned FIP: result=%#v error=%v FIPs=%#v", third, err, api.floatingIPs)
	}
	result := destroyUntilDone(t, testReconciler(api), cluster)
	if !result.Done || len(api.vms) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("restart-safe destroy did not converge: result=%#v VMs=%#v firewalls=%#v", result, api.vms, api.firewalls)
	}
}

func TestDestroyAutoFloatingIPPatchAmbiguityNeverUnassignsNameless(t *testing.T) {
	for _, commits := range []bool{false, true} {
		t.Run(fmt.Sprintf("commits=%t", commits), func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatal(err)
			}
			api.floatingIPUpdateError = io.ErrUnexpectedEOF
			api.floatingIPUpdateErrorCommits = commits
			_, err := testReconciler(api).Destroy(context.Background(), cluster)
			if commits && err != nil {
				t.Fatalf("committed PATCH ambiguity was not recovered by readback: %v", err)
			}
			if !commits && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("non-committed PATCH ambiguity was accepted: %v", err)
			}
			if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo == "" {
				t.Fatalf("PATCH ambiguity unassigned or lost the auto FIP: %#v", api.floatingIPs)
			}
			if commits != (api.floatingIPs[0].Name == bastionFloatingIPName(ownerKey(cluster))) {
				t.Fatalf("PATCH commits=%t left unexpected name %q", commits, api.floatingIPs[0].Name)
			}
			for _, event := range api.events {
				if strings.HasPrefix(event, "unassign-fip/") {
					t.Fatalf("PATCH ambiguity unassigned in the naming pass: %v", api.events)
				}
			}
		})
	}
}

func TestDestroyRecoversOnlyCommittedAmbiguousFloatingIPMutation(t *testing.T) {
	for _, operation := range []string{"unassign", "delete"} {
		for _, commits := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s commits=%t", operation, commits), func(t *testing.T) {
				api := newFakeAPI()
				cluster := testCluster()
				reconciler := testReconciler(api)
				reconcileUntilReady(t, reconciler, cluster)
				ambiguousErr := io.ErrUnexpectedEOF
				if operation == "unassign" {
					api.floatingIPUnassignError = ambiguousErr
					api.floatingIPUnassignErrorCommits = commits
				} else {
					for i := range api.floatingIPs {
						api.floatingIPs[i].AssignedTo = ""
						api.floatingIPs[i].AssignedToResourceType = ""
						api.floatingIPs[i].AssignedToPrivateIP = ""
					}
					api.floatingIPDeleteError = ambiguousErr
					api.floatingIPDeleteErrorCommits = commits
				}

				_, err := reconciler.Destroy(context.Background(), cluster)
				if commits && err != nil {
					t.Fatalf("committed ambiguous %s did not recover from authoritative readback: %v", operation, err)
				}
				if !commits && !errors.Is(err, ambiguousErr) {
					t.Fatalf("non-committed ambiguous %s was accepted: %v", operation, err)
				}
				if operation == "unassign" {
					if gotAssigned := api.floatingIPs[0].AssignedTo != ""; gotAssigned == commits {
						t.Fatalf("unassign commits=%t left assigned=%t", commits, gotAssigned)
					}
				} else if gotDeleted := len(api.floatingIPs) == ControlPlaneReplicas; gotDeleted != commits {
					t.Fatalf("delete commits=%t left %d floating IPs", commits, len(api.floatingIPs))
				}
				if len(api.vmDeletes) != 0 {
					t.Fatalf("ambiguous floating-IP cleanup reached VM deletion: %v", api.vmDeletes)
				}
			})
		}
	}
}

func TestCloudVMDeletionUnassignsButDoesNotDeleteNamedFloatingIP(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	vm := api.vms[0]
	wantName := bastionFloatingIPName(ownerKey(cluster))
	if api.floatingIPs[0].Name != wantName {
		t.Fatalf("floating IP was not renamed before VM deletion: %#v", api.floatingIPs[0])
	}
	if err := api.DeleteVM(context.Background(), cluster.Spec.Location, vm.UUID); err != nil {
		t.Fatal(err)
	}
	var preserved *inspace.FloatingIP
	for index := range api.floatingIPs {
		if api.floatingIPs[index].Name == wantName {
			preserved = &api.floatingIPs[index]
			break
		}
	}
	if preserved == nil || preserved.AssignedTo != "" {
		t.Fatalf("VM deletion did not preserve the named, unassigned floating IP: %#v", api.floatingIPs)
	}
}

func TestDestroyDoesNotUseClusterDerivedControlPlaneNameAsDeletionAuthority(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	cp := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 1))
	cp.Description = fmt.Sprintf(
		"inspace-rke2-cp/v2 owner=%s slot=1 spec=%s",
		strings.Repeat("f", 16), strings.Repeat("a", 64),
	)
	mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
	_, err := reconciler.Destroy(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "expected ownership record") {
		t.Fatalf("expected owner-record refusal for same-name control plane, got %v", err)
	}
	if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
		t.Fatal("same-name foreign-owner collision became deletion authority")
	}
}

func TestDestroyConvergesForExactLegacyControlPlaneTopology(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	convertTopologyToLegacy(t, api, cluster)

	var result DestroyResult
	for attempt := 0; attempt < 40; attempt++ {
		var err error
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("legacy destroy %d: %v", attempt, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("legacy destroy did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyConvergesForRC4BastionWithCurrentControlPlanes(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	convertBastionToLegacy(t, api, cluster)
	convertControlPlaneOwnershipToV2(t, api, cluster)

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("RC4 topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyRejectsIncoherentOwnershipSchemaTopology(t *testing.T) {
	tests := map[string]func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster){
		"v3 bastion with v2 control planes": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			convertControlPlaneOwnershipToV2(t, api, cluster)
		},
		"v1 bastion with v3 control planes": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			convertBastionToLegacy(t, api, cluster)
		},
		"mixed v2 and v3 control planes without bastion": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			api.removeVMFromReadback(mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name)).UUID)
			vm := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 1))
			hash := vm.Description[strings.LastIndex(vm.Description, "=")+1:]
			vm.Description = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=1 spec=%s", ownerKey(cluster), hash)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			mutate(t, api, cluster)
			eventsBefore := len(api.events)
			_, err := reconciler.Destroy(context.Background(), cluster)
			if err == nil || !strings.Contains(err.Error(), "incoherent teardown ownership schema") {
				t.Fatalf("expected incoherent schema refusal, got %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("incoherent schema caused teardown mutation: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyConvergesFromPartialSupportedTopologies(t *testing.T) {
	tests := map[string]struct {
		convert func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster)
		remove  func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster)
	}{
		"current": {
			remove: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				api.removeVMFromReadback(mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 1)).UUID)
			},
		},
		"current without bastion": {
			remove: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				api.removeVMFromReadback(mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name)).UUID)
			},
		},
		"RC4": {
			convert: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				convertBastionToLegacy(t, api, cluster)
				convertControlPlaneOwnershipToV2(t, api, cluster)
			},
			remove: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				api.removeVMFromReadback(mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 0)).UUID)
			},
		},
		"RC4 without bastion": {
			convert: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				convertBastionToLegacy(t, api, cluster)
				convertControlPlaneOwnershipToV2(t, api, cluster)
			},
			remove: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				api.removeVMFromReadback(mustVM(t, api.vms, legacyBastionName(ownerKey(cluster))).UUID)
			},
		},
		"full legacy": {
			convert: convertTopologyToLegacy,
			remove: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				api.removeVMFromReadback(mustVM(t, api.vms, legacyBastionName(ownerKey(cluster))).UUID)
				api.removeVMFromReadback(mustVM(t, api.vms, legacyControlPlaneName(ownerKey(cluster), 2)).UUID)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			if test.convert != nil {
				test.convert(t, api, cluster)
			}
			test.remove(t, api, cluster)
			result := destroyUntilDone(t, reconciler, cluster)
			if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
				t.Fatalf("partial %s topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", name, result, api.vms, api.floatingIPs, api.firewalls)
			}
		})
	}
}

func TestDestroyRejectsBothBastionsBeforeMutation(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	current := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	legacy := *current
	legacy.UUID = "99999999-1111-4222-8333-bbbbbbbbbbbb"
	legacy.Name = legacyBastionName(ownerKey(cluster))
	legacy.Hostname = legacy.Name
	legacy.Description = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=%s", ownerKey(cluster), strings.Repeat("a", 64))
	api.vms = append(api.vms, legacy)
	api.network.VMUUIDs = append(api.network.VMUUIDs, legacy.UUID)
	eventsBefore := len(api.events)
	_, err := reconciler.Destroy(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "both current and legacy bastion") {
		t.Fatalf("expected both-bastions refusal, got %v", err)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("both-bastions refusal mutated infrastructure: %v", api.events[eventsBefore:])
	}
}

func TestDestroyRejectsBastionNameVersionMismatchBeforeMutation(t *testing.T) {
	tests := map[string]struct {
		legacy  bool
		version string
	}{
		"current name with v1": {version: "v1"},
		"current name with v2": {version: "v2"},
		"legacy name with v2":  {legacy: true, version: "v2"},
		"legacy name with v3":  {legacy: true, version: "v3"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			if test.legacy {
				convertBastionToLegacy(t, api, cluster)
			}
			bastionName := currentBastionName(cluster.Metadata.Name)
			if test.legacy {
				bastionName = legacyBastionName(ownerKey(cluster))
			}
			bastion := mustVM(t, api.vms, bastionName)
			hash := bastion.Description[strings.LastIndex(bastion.Description, "=")+1:]
			bastion.Description = fmt.Sprintf("inspace-rke2-bastion/%s owner=%s spec=%s", test.version, ownerKey(cluster), hash)
			eventsBefore := len(api.events)
			_, err := reconciler.Destroy(context.Background(), cluster)
			if err == nil || !strings.Contains(err.Error(), "expected ownership record") {
				t.Fatalf("expected name/version refusal, got %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("name/version refusal mutated infrastructure: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyRejectsControlPlaneNameVersionMismatchBeforeMutation(t *testing.T) {
	tests := map[string]struct {
		legacy  bool
		version string
	}{
		"current name with v1": {version: "v1"},
		"legacy name with v1":  {legacy: true, version: "v1"},
		"legacy name with v3":  {legacy: true, version: "v3"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			vmName := controlPlaneName(cluster.Metadata.Name, 0)
			if test.legacy {
				convertTopologyToLegacy(t, api, cluster)
				vmName = legacyControlPlaneName(ownerKey(cluster), 0)
			}
			vm := mustVM(t, api.vms, vmName)
			hash := vm.Description[strings.LastIndex(vm.Description, "=")+1:]
			vm.Description = fmt.Sprintf("inspace-rke2-cp/%s owner=%s slot=0 spec=%s", test.version, ownerKey(cluster), hash)
			eventsBefore := len(api.events)
			if _, err := reconciler.Destroy(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "expected ownership record") {
				t.Fatalf("expected control-plane name/version refusal, got %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("control-plane name/version refusal mutated infrastructure: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyRejectsLegacyAuthorityDriftBeforeMutation(t *testing.T) {
	tests := map[string]struct {
		mutate func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster)
		want   string
	}{
		"ownership record": {
			mutate: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				legacy := mustVM(t, api.vms, legacyControlPlaneName(ownerKey(cluster), 1))
				legacy.Description = fmt.Sprintf(
					"inspace-rke2-cp/v2 owner=%s slot=2 spec=%s",
					ownerKey(cluster), strings.Repeat("a", 64),
				)
			},
			want: "expected ownership record",
		},
		"floating IP billing": {
			mutate: func(_ *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				owner := ownerKey(cluster)
				for i := range api.floatingIPs {
					if api.floatingIPs[i].Name == nodeFloatingIPName(owner, 1) {
						api.floatingIPs[i].BillingAccountID++
					}
				}
			},
			want: "billing-account ownership",
		},
		"node firewall assignment": {
			mutate: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				firewall := mustFirewall(t, api.firewalls, firewallName(ownerKey(cluster)))
				firewall.ResourcesAssigned = append(firewall.ResourcesAssigned, inspace.FirewallResource{
					ResourceType: "vm", ResourceUUID: "99999999-1111-4222-8333-bbbbbbbbbbbb",
				})
			},
			want: "node firewall assignment drift",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			convertTopologyToLegacy(t, api, cluster)
			test.mutate(t, api, cluster)
			mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
			_, err := reconciler.Destroy(context.Background(), cluster)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected legacy %s refusal, got %v", name, err)
			}
			if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
				t.Fatalf("legacy %s drift caused a teardown mutation", name)
			}
		})
	}
}

func TestDestroyRejectsMixedCurrentAndLegacyControlPlaneTopology(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	owner := ownerKey(cluster)
	current := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, 0))
	current.Name = legacyControlPlaneName(owner, 0)
	current.Hostname = current.Name
	mutationsBefore := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes)
	_, err := reconciler.Destroy(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "mixed current and legacy") {
		t.Fatalf("expected mixed-topology refusal, got %v", err)
	}
	if got := len(api.vmDeletes) + len(api.floatingIPDeletes) + len(api.firewallDeletes); got != mutationsBefore {
		t.Fatal("mixed topology caused a teardown mutation")
	}
}

func TestDestroyDoesNotApplyCurrentHostnameLengthConstraint(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	oldOwner := ownerKey(cluster)
	oldClusterName := cluster.Metadata.Name
	cluster.Metadata.Name = strings.Repeat("a", 60)
	newOwner := ownerKey(cluster)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := mustVM(t, api.vms, controlPlaneName(oldClusterName, slot))
		hash := vm.Description[strings.LastIndex(vm.Description, "=")+1:]
		vm.Name = legacyControlPlaneName(newOwner, slot)
		vm.Hostname = vm.Name
		vm.Description = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=%s", newOwner, slot, hash)
	}
	bastion := mustVM(t, api.vms, currentBastionName(oldClusterName))
	bastionHash := bastion.Description[strings.LastIndex(bastion.Description, "=")+1:]
	bastion.Name = legacyBastionName(newOwner)
	bastion.Hostname = bastion.Name
	bastion.Description = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=%s", newOwner, bastionHash)
	for i := range api.floatingIPs {
		api.floatingIPs[i].Name = strings.Replace(api.floatingIPs[i].Name, "rke2-"+oldOwner+"-", "rke2-"+newOwner+"-", 1)
	}
	for i := range api.firewalls {
		api.firewalls[i].Name = strings.Replace(api.firewalls[i].Name, oldOwner, newOwner, 1)
		api.firewalls[i].DisplayName = strings.Replace(api.firewalls[i].DisplayName, oldOwner, newOwner, 1)
		api.firewalls[i].Description = strings.Replace(api.firewalls[i].Description, oldOwner, newOwner, 1)
	}

	var result DestroyResult
	for attempt := 0; attempt < 40; attempt++ {
		var err error
		result, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("long-name legacy destroy %d: %v", attempt, err)
		}
		if result.Done {
			break
		}
	}
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("long legacy cluster name blocked teardown: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
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

func TestDestroyRetainsDeletionIntentWhenAPIErrorCommits(t *testing.T) {
	tests := map[string]*inspace.APIError{
		"retryable API response": {
			StatusCode: 500, Method: "DELETE", Path: "/vm", Message: "injected post-commit failure", Retryable: true,
		},
		"non-retryable API response": {
			StatusCode: 400, Method: "DELETE", Path: "/vm", Message: "injected post-commit rejection wording", Retryable: false,
		},
	}
	for name, ambiguousErr := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			api.retainFirewallAssignmentsOnDelete = true
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
			if !errors.Is(deleteErr, ErrRetryableAmbiguousVMDelete) || !errors.Is(deleteErr, ambiguousErr) || len(api.vmDeletes) != 1 || len(api.vms) != ControlPlaneReplicas {
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
		})
	}
}

func TestDestroyRefreshesDeletionIntentAfterSlowDeleteOutcome(t *testing.T) {
	tests := map[string]struct {
		deleteErr error
		ambiguous bool
	}{
		"success":   {},
		"not found": {deleteErr: &inspace.APIError{StatusCode: 404, Method: "DELETE", Path: "/vm", Message: "not found"}},
		"raw EOF":   {deleteErr: io.ErrUnexpectedEOF, ambiguous: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			api.retainFirewallAssignmentsOnDelete = true
			api.vmDeleteError = test.deleteErr
			api.vmDeleteErrorCommits = test.deleteErr != nil
			cluster := testCluster()
			reconciler := testReconciler(api)
			current := time.Unix(1_800_000_000, 0)
			reconciler.now = func() time.Time { return current }
			reconcileUntilReady(t, reconciler, cluster)
			api.vmDeleteHook = func() { current = current.Add(ownedVMDeletionTransitionTTL + time.Minute) }

			var deleteErr error
			for i := 0; i < 20 && len(api.vmDeletes) == 0; i++ {
				_, deleteErr = reconciler.Destroy(context.Background(), cluster)
			}
			if len(api.vmDeletes) != 1 || len(reconciler.pendingVMDeletions) != 1 {
				t.Fatalf("slow delete did not retain one exact intent: deletes=%#v pending=%#v", api.vmDeletes, reconciler.pendingVMDeletions)
			}
			if test.ambiguous {
				if !errors.Is(deleteErr, ErrRetryableAmbiguousVMDelete) || !errors.Is(deleteErr, test.deleteErr) {
					t.Fatalf("raw ambiguous error was not wrapped and preserved: %v", deleteErr)
				}
			} else if deleteErr != nil {
				t.Fatalf("definitive delete outcome returned an error: %v", deleteErr)
			}
			for _, deletion := range reconciler.pendingVMDeletions {
				wantExpiry := current.Add(ownedVMDeletionTransitionTTL)
				if !deletion.ExpiresAt.Equal(wantExpiry) {
					t.Fatalf("transition expiry=%s, want refresh from DELETE return %s", deletion.ExpiresAt, wantExpiry)
				}
			}
		})
	}
}

func TestDestroyDropsDeletionIntentAfterLocalMutationGuard(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	rejectedErr := fmt.Errorf("injected pre-dispatch guard: %w", inspace.ErrMutationBlocked)
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
		t.Fatalf("local pre-dispatch rejection state: error=%v deletes=%#v VMs=%#v", deleteErr, api.vmDeletes, api.vms)
	}
	if len(reconciler.pendingVMDeletions) != 0 {
		t.Fatalf("local pre-dispatch rejection retained deletion authority: %#v", reconciler.pendingVMDeletions)
	}

	api.vmDeleteError = nil
	if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
		t.Fatalf("retry after local pre-dispatch rejection: %v", err)
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
	assertControlPlaneCloudInit(t, raw, "cp-1", false)
}

func TestRenderControlPlaneCloudInitRejectsInvalidGuestHostname(t *testing.T) {
	for _, nodeName := range []string{"UPPER", "contains.dot", strings.Repeat("a", 64)} {
		_, err := RenderCloudInitJSON(CloudInitInput{
			NodeName: nodeName, NodeExternalIPv4: "203.0.113.11", PrivateSubnet: "10.20.30.0/24", VirtualIPv4: "10.20.30.10",
			RKE2Version: "v1.35.6+rke2r1", RKE2Token: "token", ServerAddress: "10.20.30.10",
			PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
			PrivateLoadBalancerPoolStart: "10.20.30.200", PrivateLoadBalancerPoolStop: "10.20.30.239",
		})
		if err == nil || !strings.Contains(err.Error(), "lowercase DNS label") {
			t.Errorf("node name %q: expected DNS-label error, got %v", nodeName, err)
		}
	}
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

func destroyUntilDone(t *testing.T, reconciler *Reconciler, cluster *v1alpha1.InSpaceCluster) DestroyResult {
	t.Helper()
	for attempt := 0; attempt < 40; attempt++ {
		result, err := reconciler.Destroy(context.Background(), cluster)
		if err != nil {
			t.Fatalf("destroy %d: %v", attempt, err)
		}
		if result.Done {
			return result
		}
	}
	t.Fatal("destroy did not converge")
	return DestroyResult{}
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
			if candidate.Name == currentBastionName(cluster.Metadata.Name) {
				bastion = candidate
				break
			}
		}
		if bastion == nil {
			continue
		}
		var firewall *inspace.Firewall
		for index := range reconciler.API.(*fakeAPI).firewalls {
			candidate := &reconciler.API.(*fakeAPI).firewalls[index]
			if candidate.EffectiveName() == bastionFirewallName(owner) {
				firewall = candidate
				break
			}
		}
		if firewall == nil {
			continue
		}
		floatingIP := reconciler.API.(*fakeAPI).floatingIPs[0]
		if firewallHasVM(firewall, bastion.UUID) && floatingIP.AssignedTo == bastion.UUID {
			return
		}
	}
	t.Fatal("bastion never became protected")
}

func convertTopologyToLegacy(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	convertBastionToLegacy(t, api, cluster)
	owner := ownerKey(cluster)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		vm.Name = legacyControlPlaneName(owner, slot)
		vm.Hostname = vm.Name
		hash := vm.Description[strings.LastIndex(vm.Description, "=")+1:]
		vm.Description = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=%s", owner, slot, hash)
	}
}

func convertControlPlaneOwnershipToV2(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	owner := ownerKey(cluster)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		vm := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		hash := vm.Description[strings.LastIndex(vm.Description, "=")+1:]
		vm.Description = fmt.Sprintf("inspace-rke2-cp/v2 owner=%s slot=%d spec=%s", owner, slot, hash)
	}
}

func convertBastionToLegacy(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	owner := ownerKey(cluster)
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastionHash := bastion.Description[strings.LastIndex(bastion.Description, "=")+1:]
	bastion.Name = legacyBastionName(owner)
	bastion.Hostname = bastion.Name
	bastion.Description = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=%s", owner, bastionHash)
}

func testReconciler(api *fakeAPI) *Reconciler {
	return &Reconciler{
		API: api, SSHUsername: "inspacee2e", SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest unit@test",
		ManagementCIDR: "198.51.100.24/32", ManagementTCPPorts: []int{22},
		protectionAuditTimeout: 100 * time.Millisecond, protectionRequestTimeout: 25 * time.Millisecond,
		protectionReadbackMinInterval: time.Millisecond, protectionReadbackMaxInterval: 5 * time.Millisecond,
		createdVMRecoveryTimeout: 100 * time.Millisecond, createdVMFloatingIPCleanupTimeout: 25 * time.Millisecond,
		createdVMDeleteTimeout: 25 * time.Millisecond,
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

func assertControlPlaneCloudInit(t *testing.T, raw, expectedNodeName string, initialize bool) {
	t.Helper()
	var identity struct {
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal([]byte(raw), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Hostname != expectedNodeName || !strings.Contains(raw, `"preserve_hostname":false`) {
		t.Errorf("cloud-init guest identity hostname=%q, want %q with preserve_hostname=false", identity.Hostname, expectedNodeName)
	}
	files := decodeWriteFiles(t, raw)
	if len(files) != 8 {
		t.Fatalf("write_files=%d, want 8", len(files))
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
		"swapoff -a", `sed -Ei '/^[[:space:]]*#/!`, "/etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list", "http://th.archive.ubuntu.com",
		"NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y", "ca-certificates curl iproute2 procps tar",
		"package_deadline=$(( $(date +%s) + 600 ))", "timeout --kill-after=30s",
		"sysctl --system", "sysctl -n net.ipv4.ip_forward", "sysctl -n fs.inotify.max_user_instances", "sysctl -n fs.inotify.max_user_watches",
		"swapon --show --noheadings", "/var/lib/inspace/kubernetes-node-prepared-v1",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("bootstrap script lacks %q", required)
		}
	}
	if got := files["/etc/sysctl.d/90-inspace-kubernetes.conf"]; got != kubernetesSysctlConfig {
		t.Errorf("sysctl config mismatch:\n%s", got)
	}
	if got := files["/etc/security/limits.d/90-inspace-kubernetes.conf"]; got != kubernetesLimitsConfig {
		t.Errorf("PAM limits config mismatch:\n%s", got)
	}
	if got := files["/etc/systemd/system/rke2-server.service.d/20-inspace-node-limits.conf"]; got != rke2ServerLimitsConfig {
		t.Errorf("rke2-server limits mismatch:\n%s", got)
	}
	for before, after := range map[string]string{
		"swapoff -a":                                   "apt-get -o Acquire::Retries=3",
		"http://th.archive.ubuntu.com":                 "apt-get -o Acquire::Retries=3",
		"apt-get -o Acquire::Retries=3":                "apt-get -o DPkg::Lock::Timeout=30 upgrade -y",
		"apt-get -o DPkg::Lock::Timeout=30 upgrade -y": "install -y --no-install-recommends",
		"install -y --no-install-recommends":           "sysctl --system",
		"sysctl --system":                              "systemctl daemon-reload",
		"systemctl daemon-reload":                      "systemctl start --no-block rke2-server.service",
	} {
		if beforeIndex, afterIndex := strings.Index(script, before), strings.Index(script, after); beforeIndex < 0 || afterIndex <= beforeIndex {
			t.Errorf("bootstrap order %q -> %q is not enforced", before, after)
		}
	}
	for _, forbidden := range []string{"iptables -F", "iptables --flush", "nft flush", "ufw --force enable", "ufw allow ", "find_private_ip"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("bootstrap script contains forbidden %q", forbidden)
		}
	}
	config := files["/var/lib/inspace/rke2-config"]
	if !strings.Contains(config, `node-name: "`+expectedNodeName+`"`+"\n") {
		t.Errorf("RKE2 config node-name does not equal guest hostname %q:\n%s", expectedNodeName, config)
	}
	for _, required := range []string{"node-ip: __PRIVATE_IP__", "advertise-address: __PRIVATE_IP__", "disable-kube-proxy: true", `"10.20.30.10"`} {
		if !strings.Contains(config, required) {
			t.Errorf("RKE2 config lacks %q", required)
		}
	}
	var rke2Config struct {
		CNI              string `json:"cni"`
		ClusterCIDR      string `json:"cluster-cidr"`
		DisableKubeProxy bool   `json:"disable-kube-proxy"`
	}
	if err := yaml.Unmarshal([]byte(config), &rke2Config); err != nil {
		t.Fatalf("parse generated RKE2 config: %v", err)
	}
	if rke2Config.CNI != "cilium" || rke2Config.ClusterCIDR != "10.42.0.0/16" || !rke2Config.DisableKubeProxy {
		t.Fatalf("generated RKE2 CNI/kube-proxy contract=%#v", rke2Config)
	}
	if initialize == strings.Contains(config, "server: ") {
		t.Errorf("initialize/join config mismatch: %s", config)
	}
	if !initialize && !strings.Contains(config, `server: "https://10.20.30.10:9345"`) {
		t.Error("join does not use private VIP registration endpoint")
	}
	staticPod := files["/var/lib/inspace/rke2-kube-vip"]
	for _, required := range []string{kubeVIPImage, "vip_interface", "__PRIVATE_IFACE__", "vip_arp", "cp_enable", "svc_enable", `value: "false"`, "vip_leaderelection", "inspace-control-plane-vip", "hostNetwork: true", "type: File", "app.kubernetes.io/component: control-plane-vip"} {
		if !strings.Contains(staticPod, required) {
			t.Errorf("kube-vip static Pod lacks %q", required)
		}
	}
	assertKubeVIPStaticPodContract(t, staticPod)
	if strings.Contains(staticPod, "DaemonSet") || strings.Contains(staticPod, "servicesElection") {
		t.Errorf("kube-vip manifest enables an obsolete deployment/service path: %s", staticPod)
	}
	ciliumConfig := files["/var/lib/inspace/rke2-cilium-config"]
	var helmChartConfig struct {
		Spec struct {
			ValuesContent string `json:"valuesContent"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(ciliumConfig), &helmChartConfig); err != nil {
		t.Fatalf("parse generated RKE2 Cilium HelmChartConfig: %v", err)
	}
	var ciliumValues struct {
		RoutingMode           string `json:"routingMode"`
		IPv4NativeRoutingCIDR string `json:"ipv4NativeRoutingCIDR"`
		AutoDirectNodeRoutes  bool   `json:"autoDirectNodeRoutes"`
		KubeProxyReplacement  bool   `json:"kubeProxyReplacement"`
		EnableIPv4Masquerade  bool   `json:"enableIPv4Masquerade"`
		BPF                   struct {
			Masquerade bool `json:"masquerade"`
		} `json:"bpf"`
	}
	if err := yaml.Unmarshal([]byte(helmChartConfig.Spec.ValuesContent), &ciliumValues); err != nil {
		t.Fatalf("parse generated RKE2 Cilium values: %v", err)
	}
	if ciliumValues.RoutingMode != "native" || ciliumValues.IPv4NativeRoutingCIDR != "10.42.0.0/16" ||
		!ciliumValues.AutoDirectNodeRoutes || !ciliumValues.KubeProxyReplacement || !ciliumValues.EnableIPv4Masquerade ||
		!ciliumValues.BPF.Masquerade {
		t.Fatalf("generated Cilium native-routing contract=%#v", ciliumValues)
	}
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

func assertKubeVIPStaticPodContract(t *testing.T, manifest string) {
	t.Helper()

	var pod corev1.Pod
	if err := yaml.Unmarshal([]byte(manifest), &pod); err != nil {
		t.Fatalf("parse generated kube-vip static Pod: %v", err)
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Namespace != "kube-system" {
		t.Fatalf("generated kube-vip object identity=%s/%s namespace=%q", pod.APIVersion, pod.Kind, pod.Namespace)
	}
	if !pod.Spec.HostNetwork {
		t.Fatal("generated kube-vip Pod must use the host network")
	}
	if len(pod.Spec.HostAliases) != 1 || pod.Spec.HostAliases[0].IP != "127.0.0.1" ||
		len(pod.Spec.HostAliases[0].Hostnames) != 1 || pod.Spec.HostAliases[0].Hostnames[0] != "kubernetes" {
		t.Fatalf("generated kube-vip kubernetes host alias=%#v, want kubernetes -> 127.0.0.1", pod.Spec.HostAliases)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("generated kube-vip containers=%d, want 1", len(pod.Spec.Containers))
	}
	container := pod.Spec.Containers[0]
	if container.Name != "kube-vip" {
		t.Fatalf("generated kube-vip container name=%q", container.Name)
	}
	vipNodeNameEnvs := make([]corev1.EnvVar, 0, 1)
	for _, env := range container.Env {
		if env.Name == "k8s_config_file" {
			t.Fatalf("generated kube-vip Pod sets ignored k8s_config_file environment variable to %q", env.Value)
		}
		if env.Name == "vip_nodename" {
			vipNodeNameEnvs = append(vipNodeNameEnvs, env)
		}
	}
	wantVIPNodeNameEnv := corev1.EnvVar{
		Name: "vip_nodename",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
		},
	}
	if len(vipNodeNameEnvs) != 1 || !reflect.DeepEqual(vipNodeNameEnvs[0], wantVIPNodeNameEnv) {
		t.Fatalf("generated kube-vip vip_nodename env=%#v, want exactly %#v", vipNodeNameEnvs, wantVIPNodeNameEnv)
	}
	wantCapabilities := &corev1.Capabilities{
		Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW"},
		Drop: []corev1.Capability{"ALL"},
	}
	var gotCapabilities *corev1.Capabilities
	if container.SecurityContext != nil {
		gotCapabilities = container.SecurityContext.Capabilities
	}
	if !reflect.DeepEqual(gotCapabilities, wantCapabilities) {
		t.Fatalf("generated kube-vip capabilities=%#v, want exactly %#v", gotCapabilities, wantCapabilities)
	}
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "kubeconfig" ||
		container.VolumeMounts[0].MountPath != "/etc/kubernetes/admin.conf" || !container.VolumeMounts[0].ReadOnly {
		t.Fatalf("generated kube-vip kubeconfig mount=%#v, want read-only /etc/kubernetes/admin.conf", container.VolumeMounts)
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].Name != "kubeconfig" || pod.Spec.Volumes[0].HostPath == nil ||
		pod.Spec.Volumes[0].HostPath.Path != "/etc/rancher/rke2/rke2.yaml" || pod.Spec.Volumes[0].HostPath.Type == nil ||
		*pod.Spec.Volumes[0].HostPath.Type != corev1.HostPathFile {
		t.Fatalf("generated kube-vip kubeconfig host volume=%#v, want RKE2 kubeconfig File", pod.Spec.Volumes)
	}
}

func assertBastionCloudInit(t *testing.T, raw, expectedHostname string) {
	t.Helper()
	var payload struct {
		Hostname         string `json:"hostname"`
		PreserveHostname bool   `json:"preserve_hostname"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Hostname != expectedHostname || payload.PreserveHostname {
		t.Fatalf("bastion cloud-init hostname contract=%#v, want hostname %q and preserve_hostname=false", payload, expectedHostname)
	}
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

	failFirewallAssignmentForName       string
	firewallAssignmentError             error
	firewallAssignmentErrorCommits      bool
	firewallAssignmentNilWithoutCommit  bool
	firewallAssignmentReadbackDelay     int
	firewallAssignmentReadbackRemaining int
	firewallAssignmentDuplicate         bool
	firewallAssignmentWrongFirewall     bool
	firewallAssignmentPolicyDrift       bool
	failVMCreateNames                   map[string]error
	commitVMCreateErrors                map[string]bool
	privateIPByName                     map[string]string
	mutateStoredVM                      func(inspace.CreateVMRequest, *inspace.VM)
	mutateCreateVMResponse              func(inspace.CreateVMRequest, *inspace.VM)
	mutateUpdateFloatingIPResponse      func(*inspace.FloatingIP)
	mutateCreateFirewallResponse        func(inspace.CreateFirewallRequest, *inspace.Firewall)
	mutateGetVMResponse                 func(*inspace.VM)
	getVMErrorByUUID                    map[string]error
	nilGetVMUUID                        string
	floatingIPUpdateError               error
	floatingIPUpdateErrorCommits        bool
	floatingIPUnassignError             error
	floatingIPUnassignErrorCommits      bool
	floatingIPDeleteError               error
	floatingIPDeleteErrorCommits        bool
	floatingIPReadbackDelay             int
	floatingIPReadbackRemaining         int
	floatingIPAfterFirewallCreate       *inspace.FloatingIP
	blockFloatingIPCleanupAfterCreate   bool
	floatingIPCleanupBlocked            bool
	omitFirewallDescriptions            bool
	sparseVMListResponses               bool
	vmListReadbackDelay                 int
	vmListReadbackRemaining             int
	sparseFirewallCreateResponses       bool
	retainFirewallAssignmentsOnDelete   bool
	vmDeleteError                       error
	vmDeleteErrorCommits                bool
	vmDeleteHook                        func()
	cancelAfterVMCreate                 func()
	requireLiveSafetyContext            bool
	requireProtectionBeforeGetVM        bool
	getVMBeforeProtectionCalls          int
	createVMBarrier                     chan struct{}
	createVMStarted                     chan string
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
	if f.vmListReadbackRemaining > 0 {
		f.vmListReadbackRemaining--
		return nil, nil
	}
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
	if f.requireProtectionBeforeGetVM {
		protected := false
		for i := range f.firewalls {
			for _, resource := range f.firewalls[i].ResourcesAssigned {
				if resource.ResourceType == "vm" && resource.ResourceUUID == uuid {
					protected = true
					break
				}
			}
		}
		if !protected {
			f.getVMBeforeProtectionCalls++
			f.mu.Unlock()
			return nil, errors.New("GetVM called before firewall protection")
		}
	}
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
	mutateStored := f.mutateStoredVM
	mutateResponse := f.mutateCreateVMResponse
	injected := f.failVMCreateNames[request.Name]
	commitInjected := f.commitVMCreateErrors[request.Name]
	f.mu.Unlock()
	if injected != nil && !commitInjected {
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
		UUID: fmt.Sprintf("%08d-1111-4222-8333-bbbbbbbbbbbb", index), Name: request.Name, Hostname: request.Name, Description: request.Description,
		Status: "running", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB, OSName: request.OSName, OSVersion: request.OSVersion,
		PrivateIPv4: fmt.Sprintf("10.20.30.%d", 20+index), NetworkUUID: request.NetworkUUID, BillingAccountID: request.BillingAccountID,
		DesignatedPoolUUID: request.DesignatedPoolUUID,
		Storage:            []inspace.VMStorage{{UUID: fmt.Sprintf("%08d-9999-4222-8333-bbbbbbbbbbbb", index), Name: "vda", SizeGiB: request.DiskGiB, Primary: true}},
	}
	if privateIP := f.privateIPByName[request.Name]; privateIP != "" {
		vm.PrivateIPv4 = privateIP
	}
	if mutateStored != nil {
		mutateStored(request, &vm)
	}
	response := vm
	if mutateResponse != nil {
		mutateResponse(request, &response)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vms = append(f.vms, vm)
	f.network.VMUUIDs = append(f.network.VMUUIDs, vm.UUID)
	if request.ReservePublicIP != nil && *request.ReservePublicIP {
		floatingIP := inspace.FloatingIP{
			Address: fmt.Sprintf("203.0.113.%d", 10+len(f.floatingIPs)), BillingAccountID: request.BillingAccountID,
			Type: "public", Enabled: true, AssignedTo: vm.UUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
		}
		f.floatingIPs = append(f.floatingIPs, floatingIP)
		f.events = append(f.events, "auto-fip/"+floatingIP.Address)
		f.floatingIPReadbackRemaining = f.floatingIPReadbackDelay
	}
	f.vmListReadbackRemaining = f.vmListReadbackDelay
	f.floatingIPCleanupBlocked = f.blockFloatingIPCleanupAfterCreate
	if f.cancelAfterVMCreate != nil {
		f.cancelAfterVMCreate()
	}
	return &response, injected
}
func (f *fakeAPI) DeleteVM(ctx context.Context, _ string, uuid string) error {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vmDeletes = append(f.vmDeletes, uuid)
	f.events = append(f.events, "delete-vm/"+uuid)
	if f.vmDeleteHook != nil {
		f.vmDeleteHook()
	}
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
	for i := range f.floatingIPs {
		if f.floatingIPs[i].AssignedTo == uuid {
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			f.floatingIPs[i].AssignedToPrivateIP = ""
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

func (f *fakeAPI) ListFirewalls(ctx context.Context, _ string) ([]inspace.Firewall, error) {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]inspace.Firewall, len(f.firewalls))
	for i := range f.firewalls {
		items[i] = f.firewalls[i]
		items[i].Rules = append([]inspace.FirewallRule(nil), f.firewalls[i].Rules...)
		items[i].ResourcesAssigned = append([]inspace.FirewallResource(nil), f.firewalls[i].ResourcesAssigned...)
	}
	if f.firewallAssignmentReadbackRemaining > 0 {
		f.firewallAssignmentReadbackRemaining--
		for i := range items {
			items[i].ResourcesAssigned = nil
		}
	}
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
	if f.floatingIPAfterFirewallCreate != nil {
		f.floatingIPs = append(f.floatingIPs, *f.floatingIPAfterFirewallCreate)
		f.floatingIPAfterFirewallCreate = nil
	}
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
func (f *fakeAPI) AssignFirewallToVM(ctx context.Context, _ string, firewallUUID, vmUUID string) error {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "assign-firewall/"+firewallUUID+"/"+vmUUID)
	for i := range f.firewalls {
		if f.firewalls[i].UUID != firewallUUID {
			continue
		}
		assignmentErr := f.firewallAssignmentError
		assignmentCommits := f.firewallAssignmentErrorCommits
		if f.failFirewallAssignmentForName != "" && strings.Contains(f.firewalls[i].DisplayName, f.failFirewallAssignmentForName) {
			assignmentErr = errors.New("injected firewall failure")
			assignmentCommits = false
		}
		if f.firewallAssignmentNilWithoutCommit {
			return nil
		}
		if assignmentErr != nil && !assignmentCommits {
			return assignmentErr
		}
		for _, resource := range f.firewalls[i].ResourcesAssigned {
			if resource.ResourceUUID == vmUUID {
				return assignmentErr
			}
		}
		f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
		if f.firewallAssignmentDuplicate {
			f.firewalls[i].ResourcesAssigned = append(f.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmUUID})
		}
		if f.firewallAssignmentWrongFirewall {
			f.firewalls = append(f.firewalls, inspace.Firewall{
				UUID: "66666666-1111-4222-8333-444444444444", DisplayName: "foreign",
				ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
			})
		}
		if f.firewallAssignmentPolicyDrift {
			f.firewalls[i].Rules = nil
		}
		f.firewallAssignmentReadbackRemaining = f.firewallAssignmentReadbackDelay
		return assignmentErr
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
func (f *fakeAPI) ListFloatingIPs(ctx context.Context, _ string, filters *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error) {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f.mu.Lock()
	blocked := f.floatingIPCleanupBlocked
	f.mu.Unlock()
	if blocked {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.floatingIPReadbackRemaining > 0 {
		f.floatingIPReadbackRemaining--
		return nil, nil
	}
	result := make([]inspace.FloatingIP, 0, len(f.floatingIPs))
	for _, item := range f.floatingIPs {
		if filters != nil && filters.BillingAccountID != 0 && item.BillingAccountID != filters.BillingAccountID {
			continue
		}
		if filters != nil && filters.VMUUID != "" && item.AssignedTo != filters.VMUUID {
			continue
		}
		result = append(result, item)
	}
	return result, nil
}
func (f *fakeAPI) UpdateFloatingIP(_ context.Context, _, address string, request inspace.UpdateFloatingIPRequest) (*inspace.FloatingIP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address != address {
			continue
		}
		if f.floatingIPUpdateError != nil && !f.floatingIPUpdateErrorCommits {
			return nil, f.floatingIPUpdateError
		}
		f.floatingIPs[i].Name = request.Name
		f.floatingIPs[i].BillingAccountID = request.BillingAccountID
		f.events = append(f.events, "update-fip/"+address+"/"+request.Name)
		copy := f.floatingIPs[i]
		if f.mutateUpdateFloatingIPResponse != nil {
			f.mutateUpdateFloatingIPResponse(&copy)
		}
		return &copy, f.floatingIPUpdateError
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "PATCH", Path: "/ip", Message: "not found"}
}
func (f *fakeAPI) UnassignFloatingIP(ctx context.Context, _, address string) (*inspace.FloatingIP, error) {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			if f.floatingIPUnassignError != nil && !f.floatingIPUnassignErrorCommits {
				return nil, f.floatingIPUnassignError
			}
			f.floatingIPs[i].AssignedTo = ""
			f.floatingIPs[i].AssignedToResourceType = ""
			f.floatingIPs[i].AssignedToPrivateIP = ""
			copy := f.floatingIPs[i]
			f.events = append(f.events, "unassign-fip/"+address)
			return &copy, f.floatingIPUnassignError
		}
	}
	return nil, &inspace.APIError{StatusCode: 404, Method: "POST", Path: "/ip/unassign", Message: "not found"}
}
func (f *fakeAPI) DeleteFloatingIP(ctx context.Context, _, address string) error {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floatingIPDeletes = append(f.floatingIPDeletes, address)
	f.events = append(f.events, "delete-fip/"+address)
	if f.floatingIPDeleteError != nil && !f.floatingIPDeleteErrorCommits {
		return f.floatingIPDeleteError
	}
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address == address {
			f.floatingIPs = append(f.floatingIPs[:i], f.floatingIPs[i+1:]...)
			break
		}
	}
	return f.floatingIPDeleteError
}

var _ API = (*fakeAPI)(nil)
