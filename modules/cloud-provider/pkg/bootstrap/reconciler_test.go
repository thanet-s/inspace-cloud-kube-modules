package bootstrap

import (
	"context"
	"crypto/sha256"
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
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	if !strings.HasPrefix(api.vmCreates[0].Description, "inspace-rke2-bastion/v6 owner="+owner+" spec=") {
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
	nodeFirewall := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
	bastionFirewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := validateFirewallPolicy(nodeFirewall, api.network.Subnet, cluster.Spec.Network.PodCIDR, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := validateBastionFirewallPolicy(bastionFirewall, reconciler.ManagementCIDR, api.network.Subnet, false); err != nil {
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
	if mustFirewall(t, api.firewalls, resourceNames.BastionFirewall).EffectiveName() != resourceNames.BastionFirewall || api.floatingIPs[0].Name != resourceNames.BastionFloatingIP {
		t.Fatalf("cluster-prefixed bastion firewall/FIP changed: firewalls=%#v floatingIPs=%#v", api.firewalls, api.floatingIPs)
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
	if result.MaxParallelControlPlaneCreates != 1 {
		t.Fatalf("ordered create concurrency=%d, want 1", result.MaxParallelControlPlaneCreates)
	}
}

func TestManagedBastionFirewallAllowsOnlyManagementICMP(t *testing.T) {
	const managementCIDR = "203.0.113.10/32"
	const privateSubnet = "10.20.30.0/24"
	rules := managedBastionFirewallRules(managementCIDR, privateSubnet, false)
	if err := validateBastionFirewallPolicy(&inspace.Firewall{Rules: rules}, managementCIDR, privateSubnet, false); err != nil {
		t.Fatal(err)
	}
	icmpIngress := 0
	for _, rule := range rules {
		if rule.Direction != "inbound" || rule.Protocol != "icmp" {
			continue
		}
		icmpIngress++
		if rule.PortStart != nil || rule.PortEnd != nil || rule.EndpointSpecType != "ip_prefixes" ||
			!reflect.DeepEqual(rule.EndpointSpec, []string{managementCIDR}) {
			t.Fatalf("bastion ICMP ingress = %#v", rule)
		}
	}
	if icmpIngress != 1 {
		t.Fatalf("bastion ICMP ingress rule count = %d, want 1", icmpIngress)
	}
	defaultRules := managedBastionFirewallRules("", privateSubnet, false)
	if err := validateBastionFirewallPolicy(&inspace.Firewall{Rules: defaultRules}, "", privateSubnet, false); err != nil {
		t.Fatalf("default-Any bastion policy rejected: %v", err)
	}
	defaultManagementRules := 0
	for _, rule := range defaultRules {
		if rule.Direction == "inbound" && (rule.Protocol == "tcp" || rule.Protocol == "icmp") {
			defaultManagementRules++
			if rule.EndpointSpecType != "any" || len(rule.EndpointSpec) != 0 {
				t.Fatalf("default management rule is not canonical Any: %#v", rule)
			}
		}
	}
	if defaultManagementRules != 2 {
		t.Fatalf("default management rule count = %d, want SSH and ICMP", defaultManagementRules)
	}

	findICMP := func(rules []inspace.FirewallRule) int {
		for index, rule := range rules {
			if rule.Direction == "inbound" && rule.Protocol == "icmp" {
				return index
			}
		}
		return -1
	}
	invalid := map[string]func(*[]inspace.FirewallRule){
		"missing": func(rules *[]inspace.FirewallRule) {
			index := findICMP(*rules)
			*rules = append((*rules)[:index], (*rules)[index+1:]...)
		},
		"public source": func(rules *[]inspace.FirewallRule) {
			(*rules)[findICMP(*rules)].EndpointSpec = []string{"0.0.0.0/0"}
		},
		"port-bearing": func(rules *[]inspace.FirewallRule) {
			port := int32(8)
			(*rules)[findICMP(*rules)].PortStart = &port
		},
		"duplicate": func(rules *[]inspace.FirewallRule) {
			*rules = append(*rules, (*rules)[findICMP(*rules)])
		},
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			rules := managedBastionFirewallRules(managementCIDR, privateSubnet, false)
			mutate(&rules)
			if err := validateBastionFirewallPolicy(&inspace.Firewall{Rules: rules}, managementCIDR, privateSubnet, false); err == nil {
				t.Fatal("invalid bastion ICMP policy was accepted")
			}
		})
	}
	for _, cacheEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("exact legacy cache=%t", cacheEnabled), func(t *testing.T) {
			rules := managedBastionFirewallRules(managementCIDR, privateSubnet, cacheEnabled)
			legacy := make([]inspace.FirewallRule, 0, len(rules)-1)
			for _, rule := range rules {
				if rule.Direction != "inbound" || rule.Protocol != "icmp" {
					legacy = append(legacy, rule)
				}
			}
			firewall := &inspace.Firewall{Rules: legacy}
			if err := validateLegacyBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, cacheEnabled); err != nil {
				t.Fatal(err)
			}
			if err := validateBastionFirewallPolicy(firewall, managementCIDR, privateSubnet, cacheEnabled); err == nil {
				t.Fatal("current policy accepted exact legacy rules")
			}
		})
	}
}

func TestReconcileAndDestroyDefaultOmittedBastionManagementCIDRToAny(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconciler.ManagementCIDR = ""

	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || reconciler.ManagementCIDR != DefaultManagementCIDR {
		t.Fatalf("omitted management CIDR did not default to Any: result=%#v CIDR=%q", result, reconciler.ManagementCIDR)
	}
	bastionFirewall := mustFirewall(t, api.firewalls, currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFirewall)
	if err := validateBastionFirewallPolicy(bastionFirewall, DefaultManagementCIDR, api.network.Subnet, false); err != nil {
		t.Fatalf("reconciled default-Any bastion firewall is invalid: %v", err)
	}

	reconciler.ManagementCIDR = ""
	destroyed := destroyUntilDone(t, reconciler, cluster)
	if !destroyed.Done || len(api.vms) != 0 || len(api.firewalls) != 0 || len(api.floatingIPs) != 0 {
		t.Fatalf("default-Any teardown leaked resources: result=%#v VMs=%#v firewalls=%#v FIPs=%#v", destroyed, api.vms, api.firewalls, api.floatingIPs)
	}
}

func TestBootstrapResourceNamesUseClusterPrefixAndOwnerQualifiedFirewalls(t *testing.T) {
	cluster := testCluster()
	owner := ownerKey(cluster)
	names := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	if names.NodeFirewall != "unit-nodes-"+owner || names.BastionFirewall != "unit-bastion-"+owner ||
		names.BastionFloatingIP != "unit-bastion-ip" || names.ControlPlaneFIP != [ControlPlaneReplicas]string{"unit-cp0-ip", "unit-cp1-ip", "unit-cp2-ip"} {
		t.Fatalf("cluster-prefixed bootstrap names = %#v", names)
	}
	otherNamespace := testCluster()
	otherNamespace.Metadata.Namespace = "other"
	otherNames := currentBootstrapResourceNames(otherNamespace.Metadata.Name, ownerKey(otherNamespace))
	if otherNames.NodeFirewall == names.NodeFirewall || otherNames.BastionFirewall == names.BastionFirewall {
		t.Fatalf("same cluster name in another namespace reused firewall identity: first=%#v second=%#v", names, otherNames)
	}
	if otherNames.BastionFloatingIP != names.BastionFloatingIP || otherNames.ControlPlaneFIP != names.ControlPlaneFIP {
		t.Fatalf("VM-bound FIP names should mirror the cluster/VM names: first=%#v second=%#v", names, otherNames)
	}
}

func TestReconcileRejectsLegacyBootstrapResourceNamesBeforeMutation(t *testing.T) {
	for _, resource := range []string{"floating IP", "firewall"} {
		t.Run(resource, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			legacy := legacyBootstrapResourceNames(ownerKey(cluster))
			if resource == "floating IP" {
				api.floatingIPs = append(api.floatingIPs, inspace.FloatingIP{Name: legacy.ControlPlaneFIP[0]})
			} else {
				api.firewalls = append(api.firewalls, inspace.Firewall{DisplayName: legacy.NodeFirewall})
			}
			eventsBefore := len(api.events)
			_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
			if err == nil || !strings.Contains(err.Error(), "legacy owner-prefixed") {
				t.Fatalf("legacy %s topology was accepted: %v", resource, err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("legacy %s topology caused mutation: %v", resource, api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyRejectsMixedCurrentAndLegacyBootstrapResourceNamesBeforeMutation(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	legacy := legacyBootstrapResourceNames(ownerKey(cluster))
	api.firewalls = append(api.firewalls, inspace.Firewall{DisplayName: legacy.NodeFirewall})
	eventsBefore := len(api.events)
	_, err := reconciler.Destroy(context.Background(), cluster)
	if err == nil || !strings.Contains(err.Error(), "mixed cluster-prefixed and legacy owner-prefixed") {
		t.Fatalf("mixed bootstrap resource topology was accepted: %v", err)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("mixed bootstrap resource topology caused mutation: %v", api.events[eventsBefore:])
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

func TestDestroyAcceptsExactPreICMPBastionFirewallPolicy(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	bastionFirewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	legacyRules := make([]inspace.FirewallRule, 0, len(bastionFirewall.Rules)-1)
	for _, rule := range bastionFirewall.Rules {
		if rule.Direction == "inbound" && rule.Protocol == "icmp" {
			continue
		}
		legacyRules = append(legacyRules, rule)
	}
	bastionFirewall.Rules = legacyRules
	if err := validateLegacyBastionFirewallPolicy(bastionFirewall, reconciler.ManagementCIDR, api.network.Subnet, false); err != nil {
		t.Fatalf("exact v0.4.1 bastion policy rejected: %v", err)
	}
	if err := validateBastionFirewallPolicy(bastionFirewall, reconciler.ManagementCIDR, api.network.Subnet, false); err == nil {
		t.Fatal("normal reconciliation accepted a pre-ICMP bastion policy")
	}

	eventsBefore := len(api.events)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("normal reconciliation did not require the current bastion ICMP policy")
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("failed current-policy reconciliation mutated infrastructure: %v", api.events[eventsBefore:])
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("legacy-policy teardown leaked resources: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
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
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	readback, err := api.ListFirewalls(context.Background(), cluster.Spec.Location)
	if err != nil {
		t.Fatal(err)
	}
	nodeFirewall := mustFirewall(t, readback, resourceNames.NodeFirewall)
	bastionFirewall := mustFirewall(t, readback, resourceNames.BastionFirewall)
	if len(nodeFirewall.Rules) != 6 || len(nodeFirewall.ResourcesAssigned) != ControlPlaneReplicas ||
		len(bastionFirewall.Rules) != 5 || len(bastionFirewall.ResourcesAssigned) != 1 {
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

func TestReconcileTreatsFirewallCreateResponseIdentityAsProvisional(t *testing.T) {
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
			result := reconcileUntilReady(t, reconciler, cluster)
			if !result.Ready || len(api.firewalls) != 2 || len(api.firewallCreates) != 2 || len(api.firewallDeletes) != 0 {
				t.Fatalf("provisional POST response overrode canonical firewall readback: result=%#v firewalls=%#v creates=%#v deletes=%#v", result, api.firewalls, api.firewallCreates, api.firewallDeletes)
			}
			for _, key := range []string{createAttemptBastionFirewall, createAttemptNodeFirewall} {
				attempt := cluster.Status.CreateAttempts[key]
				if attempt.Phase != createAttemptPhaseMaterialized || !vmUUIDPattern.MatchString(attempt.ResourceUUID) {
					t.Fatalf("canonical firewall receipt %q was not materialized: %#v", key, attempt)
				}
			}
		})
	}
}

func TestFirewallCreateForeignResponseUUIDAdoptsActualNamedFirewall(t *testing.T) {
	api := newFakeAPI()
	foreign := inspace.Firewall{
		UUID: "66666666-1111-4222-8333-444444444444", DisplayName: "pre-existing-foreign", BillingAccountID: 999,
	}
	api.firewalls = append(api.firewalls, foreign)
	api.mutateCreateFirewallResponse = func(_ inspace.CreateFirewallRequest, response *inspace.Firewall) {
		response.UUID = foreign.UUID
	}
	cluster := testCluster()
	reconciler := testReconciler(api)
	owner := ownerKey(cluster)
	actual, err := reconciler.ensureManagedBastionFirewall(context.Background(), cluster, api.network.Subnet, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if actual == nil || actual.UUID == foreign.UUID || actual.EffectiveName() != currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFirewall {
		t.Fatalf("foreign response UUID was promoted instead of canonical named firewall: foreign=%#v actual=%#v", foreign, actual)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewall]
	if attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != actual.UUID {
		t.Fatalf("canonical firewall UUID was not durably promoted: %#v", attempt)
	}
	if len(api.firewallCreates) != 1 || len(api.firewallDeletes) != 0 || !reflect.DeepEqual(api.firewalls[0], foreign) {
		t.Fatalf("foreign firewall was mutated or actual firewall was duplicated: creates=%#v deletes=%#v firewalls=%#v", api.firewallCreates, api.firewallDeletes, api.firewalls)
	}
	readback := mustFirewall(t, api.firewalls, actual.EffectiveName())
	reconciler = testReconciler(api)
	if _, err := reconciler.ensureManagedBastionFirewall(context.Background(), cluster, api.network.Subnet, owner, readback); err != nil {
		t.Fatalf("restart did not adopt canonical firewall: %v", err)
	}
	if len(api.firewallCreates) != 1 || len(api.firewallDeletes) != 0 {
		t.Fatalf("restart replayed or deleted a firewall: creates=%#v deletes=%#v", api.firewallCreates, api.firewallDeletes)
	}
}

func TestReconcileSequencesControlPlaneCreatesAfterPriorFirewallReadback(t *testing.T) {
	base := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(base)
	prepareBastion(t, reconciler, cluster)
	api := &postAssignmentReadBarrierAPI{
		fakeAPI:         base,
		readbackStarted: make(chan struct{}),
		releaseReadback: make(chan struct{}),
	}
	reconciler.API = api
	reconciler.protectionAuditTimeout = 2 * time.Second
	reconciler.protectionRequestTimeout = 2 * time.Second

	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		done <- outcome{result: result, err: err}
	}()
	select {
	case <-api.readbackStarted:
	case got := <-done:
		t.Fatalf("reconcile completed before slot 0 firewall readback was released: %#v %v", got.result, got.err)
	case <-time.After(2 * time.Second):
		t.Fatal("slot 0 assignment never reached authoritative firewall readback")
	}
	base.mu.Lock()
	createsWhileReadbackBlocked := append([]inspace.CreateVMRequest(nil), base.vmCreates...)
	base.mu.Unlock()
	if countVMCreatesByName(createsWhileReadbackBlocked, controlPlaneName(cluster.Metadata.Name, 0)) != 1 ||
		countVMCreatesByName(createsWhileReadbackBlocked, controlPlaneName(cluster.Metadata.Name, 1)) != 0 ||
		countVMCreatesByName(createsWhileReadbackBlocked, controlPlaneName(cluster.Metadata.Name, 2)) != 0 {
		t.Fatalf("later VM POST crossed slot 0 firewall readback: %#v", createsWhileReadbackBlocked)
	}
	close(api.releaseReadback)
	select {
	case got := <-done:
		if got.err != nil || len(got.result.ControlPlaneVMs) != 3 {
			t.Fatalf("ordered reconcile=%#v err=%v", got.result, got.err)
		}
		if len(base.firewalls) != 2 {
			t.Fatalf("control-plane firewall was not created before VM launch: %#v", base.firewalls)
		}
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		nodeFirewall := mustFirewall(t, base.firewalls, resourceNames.NodeFirewall)
		if len(nodeFirewall.ResourcesAssigned) != ControlPlaneReplicas {
			t.Fatalf("ordered create returned before every VM was firewalled: %#v", nodeFirewall.ResourcesAssigned)
		}
		for _, floatingIP := range base.floatingIPs {
			if floatingIP.Name != resourceNames.BastionFloatingIP && (floatingIP.Name != "" || floatingIP.AssignedTo == "") {
				t.Fatalf("ordered control-plane create did not retain its nameless assigned auto FIP: %#v", floatingIP)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordered reconcile did not complete after firewall readback release")
	}
}

func TestFirstControlPlaneHidden500StopsLaterVMPosts(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	hidden500 := &inspace.APIError{
		StatusCode: 500,
		Method:     "POST",
		Path:       "/core/v2/firewalls/assignment",
		Message:    "injected hidden committed assignment",
		Retryable:  true,
	}
	api.firewallAssignmentError = hidden500
	api.firewallAssignmentErrorCommits = true
	api.firewallAssignmentReadbackDelay = 1_000
	reconciler.protectionAuditTimeout = 20 * time.Millisecond

	_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if !errors.Is(err, hidden500) || !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("hidden-500 assignment error = %v, want API error plus durable pending", err)
	}
	if countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 0)) != 1 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 1)) != 0 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 2)) != 0 {
		t.Fatalf("hidden first assignment allowed later VM POSTs: %#v", api.vmCreates)
	}
	if len(api.vmCreates) != 2 || len(api.vmDeletes) != 1 || len(api.vms) != 1 || api.vms[0].Name != currentBastionName(cluster.Metadata.Name) {
		t.Fatalf("hidden first assignment containment: creates=%#v deletes=%#v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
	}
	attempt := cluster.Status.CreateAttempts[controlPlaneFirewallAssignmentAttemptKey(0)]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" {
		t.Fatalf("hidden first assignment lost its unresolved durable receipt: %#v", attempt)
	}
}

func TestFirewallAssignmentGateSerializesThroughAuthoritativeReadback(t *testing.T) {
	base := newFakeAPI()
	cluster := testCluster()
	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "shared-node-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	base.firewalls = []inspace.Firewall{firewall}
	api := &postAssignmentReadBarrierAPI{
		fakeAPI:         base,
		readbackStarted: make(chan struct{}),
		releaseReadback: make(chan struct{}),
	}
	reconciler := testReconciler(base)
	reconciler.API = api
	reconciler.protectionAuditTimeout = 2 * time.Second
	reconciler.protectionRequestTimeout = 2 * time.Second

	const (
		firstKey  = "firewall-assignment/gate-first"
		secondKey = "firewall-assignment/gate-second"
		firstVM   = "bbbbbbbb-1111-4222-8333-444444444444"
		secondVM  = "cccccccc-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, base, cluster, firstVM, secondVM)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- reconciler.ensureExactFirewallAssignment(ctx, cluster, firstKey, &firewall, firstVM)
	}()
	select {
	case <-api.readbackStarted:
	case err := <-firstDone:
		t.Fatalf("first assignment returned before its authoritative readback was released: %v", err)
	case <-ctx.Done():
		t.Fatal("first assignment never reached its authoritative readback")
	}

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- reconciler.ensureExactFirewallAssignment(ctx, cluster, secondKey, &firewall, secondVM)
	}()
	<-secondStarted

	// Simulate an independent actor attaching the second VM while its stale
	// caller snapshot is queued behind the first assignment's readback. The
	// in-gate authority must observe and adopt this relation without a POST.
	base.mu.Lock()
	base.firewalls[0].ResourcesAssigned = append(base.firewalls[0].ResourcesAssigned, inspace.FirewallResource{
		ResourceType: "vm",
		ResourceUUID: secondVM,
	})
	base.mu.Unlock()
	close(api.releaseReadback)

	for name, done := range map[string]<-chan error{"first": firstDone, "second": secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s assignment: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s assignment did not complete", name)
		}
	}
	base.mu.Lock()
	assignmentCalls := base.firewallAssignmentCalls
	base.mu.Unlock()
	if assignmentCalls != 1 {
		t.Fatalf("serialized stale snapshots issued %d assignment POSTs, want only the first", assignmentCalls)
	}
	firstAttempt := cluster.Status.CreateAttempts[firstKey]
	secondAttempt := cluster.Status.CreateAttempts[secondKey]
	if firstAttempt.Phase != createAttemptPhaseMaterialized || firstAttempt.ResourceUUID != firstVM {
		t.Fatalf("first assignment receipt = %#v", firstAttempt)
	}
	if secondAttempt.Phase != createAttemptPhaseAdopted || secondAttempt.ResourceUUID != secondVM {
		t.Fatalf("second assignment did not adopt the fresh in-gate readback: %#v", secondAttempt)
	}
}

func TestFirewallAssignmentGatesKeepDifferentFirewallsParallel(t *testing.T) {
	base := newFakeAPI()
	cluster := testCluster()
	firstFirewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "first-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	secondFirewall := inspace.Firewall{
		UUID:             "dddddddd-1111-4222-8333-444444444444",
		DisplayName:      "second-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	base.firewalls = []inspace.Firewall{firstFirewall, secondFirewall}
	api := &parallelFirewallAssignmentAPI{
		fakeAPI: base,
		started: make(chan string, 2),
		release: make(chan struct{}),
	}
	reconciler := testReconciler(base)
	reconciler.API = api
	reconciler.protectionAuditTimeout = 2 * time.Second
	reconciler.protectionRequestTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type assignment struct {
		key      string
		firewall *inspace.Firewall
		vmUUID   string
	}
	assignments := []assignment{
		{key: "firewall-assignment/parallel-first", firewall: &firstFirewall, vmUUID: "bbbbbbbb-1111-4222-8333-444444444444"},
		{key: "firewall-assignment/parallel-second", firewall: &secondFirewall, vmUUID: "cccccccc-1111-4222-8333-444444444444"},
	}
	seedOwnedMutationVMs(t, base, cluster, assignments[0].vmUUID, assignments[1].vmUUID)
	done := make(chan error, len(assignments))
	for _, item := range assignments {
		item := item
		go func() {
			done <- reconciler.ensureExactFirewallAssignment(ctx, cluster, item.key, item.firewall, item.vmUUID)
		}()
	}
	started := map[string]bool{}
	for len(started) < len(assignments) {
		select {
		case firewallUUID := <-api.started:
			started[firewallUUID] = true
		case err := <-done:
			t.Fatalf("assignment returned before both independent gates reached their POST: %v", err)
		case <-ctx.Done():
			t.Fatalf("only %d/%d independent firewall assignments ran in parallel", len(started), len(assignments))
		}
	}
	close(api.release)
	for range assignments {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("parallel firewall assignments did not complete")
		}
	}
}

func TestFirewallAssignmentGateWaitDoesNotConsumeRequestTimeoutOrIssue(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "shared-node-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firewall}
	reconciler := testReconciler(api)
	reconciler.protectionRequestTimeout = 10 * time.Millisecond
	reconciler.protectionAuditTimeout = 500 * time.Millisecond

	releaseGate := reconciler.acquireFirewallAssignmentGate(cluster.Spec.Location, firewall.UUID)
	const (
		attemptKey = "firewall-assignment/wait-timeout"
		vmUUID     = "bbbbbbbb-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, api, cluster, vmUUID)
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- reconciler.ensureExactFirewallAssignment(context.Background(), cluster, attemptKey, &firewall, vmUUID)
	}()
	<-started
	// Hold the gate for several complete per-request timeout windows. No read,
	// durable issue, or cloud mutation may begin until this unrelated holder
	// releases the shared-firewall critical section.
	time.Sleep(5 * reconciler.protectionRequestTimeout)
	if _, exists := cluster.Status.CreateAttempts[attemptKey]; exists {
		releaseGate()
		t.Fatalf("gate wait consumed durable issue authority: %#v", cluster.Status.CreateAttempts[attemptKey])
	}
	api.mu.Lock()
	assignmentCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if assignmentCalls != 0 {
		releaseGate()
		t.Fatalf("gate wait dispatched %d assignment POSTs", assignmentCalls)
	}
	releaseGate()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fresh request timeout was not available after gate wait: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("assignment did not complete after gate release")
	}
	attempt := cluster.Status.CreateAttempts[attemptKey]
	if attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != vmUUID {
		t.Fatalf("post-wait assignment receipt = %#v", attempt)
	}
}

func TestUnresolvedFirewallAssignmentBlocksSameFirewallAcrossRestart(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "shared-node-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firewall}
	api.firewallAssignmentNilWithoutCommit = true
	first := testReconciler(api)
	first.protectionAuditTimeout = 20 * time.Millisecond

	const (
		firstKey  = "firewall-assignment/restart-first"
		secondKey = "firewall-assignment/restart-second"
		firstVM   = "bbbbbbbb-1111-4222-8333-444444444444"
		secondVM  = "cccccccc-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, api, cluster, firstVM, secondVM)
	if err := first.ensureExactFirewallAssignment(context.Background(), cluster, firstKey, &firewall, firstVM); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("first unresolved assignment error = %v, want durable pending", err)
	}
	if attempt := cluster.Status.CreateAttempts[firstKey]; attempt.Phase != createAttemptPhaseIssued {
		t.Fatalf("first unresolved assignment receipt = %#v", attempt)
	}
	api.mu.Lock()
	firstCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if firstCalls != 1 {
		t.Fatalf("first unresolved assignment POSTs = %d, want 1", firstCalls)
	}

	cluster = restartClusterFromJSON(t, cluster)
	restarted := testReconciler(api)
	restarted.protectionAuditTimeout = 20 * time.Millisecond
	err := restarted.ensureExactFirewallAssignment(context.Background(), cluster, secondKey, &firewall, secondVM)
	if !errors.Is(err, ErrCreateAttemptPending) || !strings.Contains(err.Error(), firstKey) {
		t.Fatalf("same-firewall restart guard error = %v, want reference to unresolved %q", err, firstKey)
	}
	api.mu.Lock()
	secondCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if secondCalls != firstCalls {
		t.Fatalf("same-firewall restart dispatched a second POST: before=%d after=%d", firstCalls, secondCalls)
	}
	if attempt := cluster.Status.CreateAttempts[secondKey]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("blocked second assignment consumed issue authority: %#v", attempt)
	}
}

func TestUnresolvedFirewallAssignmentDoesNotBlockDifferentFirewall(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	firstFirewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "first-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	secondFirewall := inspace.Firewall{
		UUID:             "dddddddd-1111-4222-8333-444444444444",
		DisplayName:      "second-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firstFirewall, secondFirewall}
	api.firewallAssignmentNilWithoutCommit = true
	reconciler := testReconciler(api)
	reconciler.protectionAuditTimeout = 20 * time.Millisecond

	const (
		firstKey  = "firewall-assignment/different-first"
		secondKey = "firewall-assignment/different-second"
		firstVM   = "bbbbbbbb-1111-4222-8333-444444444444"
		secondVM  = "cccccccc-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, api, cluster, firstVM, secondVM)
	if err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, firstKey, &firstFirewall, firstVM); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("first unresolved assignment error = %v, want durable pending", err)
	}
	api.firewallAssignmentNilWithoutCommit = false
	if err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, secondKey, &secondFirewall, secondVM); err != nil {
		t.Fatalf("different firewall was blocked by unrelated unresolved receipt: %v", err)
	}
	api.mu.Lock()
	assignmentCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if assignmentCalls != 2 {
		t.Fatalf("different firewall assignment POSTs = %d, want one unresolved plus one committed", assignmentCalls)
	}
	if attempt := cluster.Status.CreateAttempts[firstKey]; attempt.Phase != createAttemptPhaseIssued {
		t.Fatalf("first unresolved receipt changed: %#v", attempt)
	}
	if attempt := cluster.Status.CreateAttempts[secondKey]; attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != secondVM {
		t.Fatalf("different firewall receipt = %#v", attempt)
	}
}

func TestConcurrentFirewallAssignmentIssueCASAllowsAtMostOnePerFirewall(t *testing.T) {
	api := newFakeAPI()
	firstCluster := testCluster()
	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "shared-node-firewall",
		BillingAccountID: firstCluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firewall}
	api.firewallAssignmentNilWithoutCommit = true

	const (
		firstKey  = "firewall-assignment/cas-first"
		secondKey = "firewall-assignment/cas-second"
		firstVM   = "bbbbbbbb-1111-4222-8333-444444444444"
		secondVM  = "cccccccc-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, api, firstCluster, firstVM, secondVM)
	initialAttempts := make(map[string]v1alpha1.ResourceCreateAttemptStatus, 2)
	for _, item := range []struct {
		key, vmUUID string
	}{{firstKey, firstVM}, {secondKey, secondVM}} {
		resourceName := firewall.UUID + "/" + item.vmUUID
		intentHash, err := createIntentHash(createAttemptKindFirewallAssignment, resourceName, firewallAssignmentIntent{
			Location: firstCluster.Spec.Location, FirewallUUID: firewall.UUID, VMUUID: item.vmUUID,
		})
		if err != nil {
			t.Fatal(err)
		}
		initialAttempts[item.key] = v1alpha1.ResourceCreateAttemptStatus{
			ResourceKind: createAttemptKindFirewallAssignment,
			ResourceName: resourceName,
			IntentHash:   intentHash,
			Phase:        createAttemptPhaseIntent,
		}
	}
	firstCluster.Status.CreateAttempts = initialAttempts
	secondCluster := restartClusterFromJSON(t, firstCluster)
	store := &issueBarrierStatusStore{
		status:  cloneClusterStatus(firstCluster.Status),
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	first := testReconciler(api)
	second := testReconciler(api)
	first.StatusCompareAndSwap = store.compareAndSwap
	second.StatusCompareAndSwap = store.compareAndSwap
	first.protectionAuditTimeout = 20 * time.Millisecond
	second.protectionAuditTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() {
		done <- first.ensureExactFirewallAssignment(ctx, firstCluster, firstKey, &firewall, firstVM)
	}()
	go func() {
		done <- second.ensureExactFirewallAssignment(ctx, secondCluster, secondKey, &firewall, secondVM)
	}()
	for range 2 {
		select {
		case <-store.started:
		case err := <-done:
			t.Fatalf("assignment returned before both stale snapshots reached issue CAS: %v", err)
		case <-ctx.Done():
			t.Fatal("both stale snapshots did not reach issue CAS")
		}
	}
	close(store.release)
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("ambiguous or CAS-conflicted assignment unexpectedly succeeded")
			}
		case <-ctx.Done():
			t.Fatal("concurrent assignment did not return")
		}
	}

	status := store.snapshot()
	issued := 0
	intents := 0
	for _, key := range []string{firstKey, secondKey} {
		switch status.CreateAttempts[key].Phase {
		case createAttemptPhaseIssued:
			issued++
		case createAttemptPhaseIntent:
			intents++
		default:
			t.Fatalf("concurrent assignment receipt %q = %#v", key, status.CreateAttempts[key])
		}
	}
	if issued != 1 || intents != 1 {
		t.Fatalf("concurrent issue CAS status = %#v, want exactly one issued and one intent", status.CreateAttempts)
	}
	api.mu.Lock()
	assignmentCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if assignmentCalls != 1 {
		t.Fatalf("concurrent stale snapshots dispatched %d assignment POSTs, want at most one", assignmentCalls)
	}
}

func TestAmbiguousFirewallAssignmentReadbackStillBlocksAfterGateRelease(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	firewall := inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      "shared-node-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firewall}
	api.firewallAssignmentNilWithoutCommit = true
	reconciler := testReconciler(api)
	reconciler.protectionAuditTimeout = 20 * time.Millisecond

	const (
		firstKey  = "firewall-assignment/released-first"
		secondKey = "firewall-assignment/released-second"
		firstVM   = "bbbbbbbb-1111-4222-8333-444444444444"
		secondVM  = "cccccccc-1111-4222-8333-444444444444"
	)
	seedOwnedMutationVMs(t, api, cluster, firstVM, secondVM)
	if err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, firstKey, &firewall, firstVM); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("first ambiguous assignment error = %v, want durable pending", err)
	}
	// The first call has returned and therefore released its process-local
	// mutex. Only the durable active-Issued receipt can prevent this stale
	// second snapshot from dispatching another same-firewall relationship POST.
	if err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, secondKey, &firewall, secondVM); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("second same-firewall assignment error = %v, want durable pending", err)
	}
	api.mu.Lock()
	assignmentCalls := api.firewallAssignmentCalls
	api.mu.Unlock()
	if assignmentCalls != 1 {
		t.Fatalf("released process-local gate allowed %d assignment POSTs, want 1", assignmentCalls)
	}
	if attempt := cluster.Status.CreateAttempts[firstKey]; attempt.Phase != createAttemptPhaseIssued {
		t.Fatalf("ambiguous first receipt changed: %#v", attempt)
	}
	if attempt := cluster.Status.CreateAttempts[secondKey]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("blocked second receipt consumed issue authority: %#v", attempt)
	}
}

func TestControlPlaneCreateErrorStopsAtFirstSlot(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	api.failVMCreateNames = map[string]error{
		controlPlaneName(cluster.Metadata.Name, 2): errors.New("slot two"),
		controlPlaneName(cluster.Metadata.Name, 0): errors.New("slot zero"),
	}
	result, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || !strings.Contains(err.Error(), "slot 0") || strings.Contains(err.Error(), "slot two") {
		t.Fatalf("ordered create did not stop at slot 0: %v", err)
	}
	if len(result.ControlPlaneVMs) != 0 || len(api.vms) != 1 || len(api.vmCreates) != 2 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 1)) != 0 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 2)) != 0 {
		t.Fatalf("slot 0 error allowed later creates: result=%#v creates=%#v VMs=%#v", result, api.vmCreates, api.vms)
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
	if assignIndex < 0 || vmDeleteIndex <= assignIndex || fipDeleteIndex <= vmDeleteIndex {
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

func TestControlPlaneFirewallFailureStopsBeforeLaterPublicVMs(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	prepareBastion(t, reconciler, cluster)
	api.failFirewallAssignmentForName = "nodes"

	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("expected control-plane firewall assignment failure")
	}
	if len(api.vmCreates) != 2 || len(api.vmDeletes) != 1 || len(api.vms) != 1 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 1)) != 0 ||
		countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 2)) != 0 {
		t.Fatalf("failed first firewall protection allowed later control-plane POSTs: creates=%#v deletes=%#v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
	}
	if api.vms[0].Name != currentBastionName(cluster.Metadata.Name) || len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != api.vms[0].UUID {
		t.Fatalf("control-plane rollback touched the protected bastion or leaked auto FIPs: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
	}
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	nodeFirewall := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
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
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		api.floatingIPs = append(api.floatingIPs, ownedResidual(resourceNames.BastionFloatingIP))
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
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		residual := ownedResidual(resourceNames.BastionFloatingIP)
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
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		api.floatingIPs = append(api.floatingIPs, ownedResidual(resourceNames.ControlPlaneFIP[1]))
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
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		residual := ownedResidual(resourceNames.ControlPlaneFIP[2])
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
		resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
		tombstone := ownedResidual(resourceNames.BastionFloatingIP)
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
	fipDeleteIndex, vmDeleteIndex := -1, -1
	for index, event := range api.events {
		switch {
		case strings.HasPrefix(event, "delete-fip/"):
			fipDeleteIndex = index
		case strings.HasPrefix(event, "delete-vm/"):
			vmDeleteIndex = index
		}
	}
	if vmDeleteIndex < 0 || fipDeleteIndex <= vmDeleteIndex {
		t.Fatalf("malformed create rollback order was unsafe: %v", api.events)
	}
}

func TestCreateVMResponseForeignUUIDNeverAuthorizesFollowUpMutation(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	foreign := inspace.VM{
		UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "pre-existing-foreign", Description: "not managed by this cluster",
		BillingAccountID: 999, NetworkUUID: "aaaaaaaa-2222-4333-8444-555555555555",
	}
	api.vms = append(api.vms, foreign)
	api.mutateCreateVMResponse = func(_ inspace.CreateVMRequest, response *inspace.VM) {
		response.UUID = foreign.UUID
	}

	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("foreign response UUID prevented canonical exact-name recovery: %v", err)
	}
	owned := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	if api.firewallAssignmentCalls != 1 || len(api.vmDeletes) != 0 || api.floatingIPUpdateCalls != 0 || len(api.floatingIPDeletes) != 0 {
		t.Fatalf("foreign response UUID did not confine follow-up mutation to the recovered VM: assignments=%d deletes=%#v FIP updates=%d FIP deletes=%#v events=%#v",
			api.firewallAssignmentCalls, api.vmDeletes, api.floatingIPUpdateCalls, api.floatingIPDeletes, api.events)
	}
	if len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 1 || api.firewalls[0].ResourcesAssigned[0].ResourceUUID != owned.UUID || api.firewalls[0].ResourcesAssigned[0].ResourceUUID == foreign.UUID {
		t.Fatalf("foreign response VM was mutated instead of the canonically owned VM: foreign=%#v owned=%#v firewalls=%#v", foreign, owned, api.firewalls)
	}
	if attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]; attempt.Phase != createAttemptPhaseMaterialized || !strings.EqualFold(attempt.ResourceUUID, owned.UUID) {
		t.Fatalf("canonical owned identity was not durably retained: %#v", attempt)
	}
	if len(api.vmCreates) != 1 {
		t.Fatalf("initial create count=%d, want one", len(api.vmCreates))
	}
	_, _ = reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
	foreignAssignments := 0
	for _, firewall := range api.firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			if resource.ResourceUUID == foreign.UUID {
				foreignAssignments++
			}
		}
	}
	if countVMCreatesByName(api.vmCreates, currentBastionName(cluster.Metadata.Name)) != 1 || foreignAssignments != 0 || len(api.vmDeletes) != 0 {
		t.Fatalf("restart replayed the bastion or mutated the foreign response identity: creates=%#v foreignAssignments=%d deletes=%#v", api.vmCreates, foreignAssignments, api.vmDeletes)
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

func TestUUIDLessCreateResponseProvesCanonicalOwnershipBeforeProtection(t *testing.T) {
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
			if len(api.getVMCalls) == 0 {
				t.Fatal("UUID-less response was protected without canonical GetVM ownership proof")
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
	if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "ownership is uncertain") {
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
	t.Run("duplicate exact rows are set semantics", func(t *testing.T) {
		api := newFakeAPI()
		api.firewallAssignmentDuplicate = true
		if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err != nil {
			t.Fatalf("duplicate exact assignment rows were rejected: %v", err)
		}
		if len(api.vmDeletes) != 0 || len(api.vms) != 1 || len(api.firewalls) != 1 || len(api.firewalls[0].ResourcesAssigned) != 2 {
			t.Fatalf("duplicate exact rows did not normalize as one relation: deletes=%#v VMs=%#v firewalls=%#v", api.vmDeletes, api.vms, api.firewalls)
		}
	})
	for _, drift := range []struct {
		name, want string
	}{
		{name: "wrong firewall", want: "wrong firewall"},
		{name: "non-VM", want: "resource type"},
	} {
		t.Run(drift.name, func(t *testing.T) {
			api := newFakeAPI()
			api.firewallAssignmentWrongFirewall = drift.name == "wrong firewall"
			api.firewallAssignmentWrongType = drift.name == "non-VM"
			if _, err := testReconciler(api).Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), drift.want) {
				t.Fatalf("%s assignment readback was accepted: %v", drift.name, err)
			}
			if len(api.vmDeletes) != 1 || len(api.vms) != 0 || len(api.floatingIPs) != 0 {
				t.Fatalf("%s assignment drift retained public infrastructure: deletes=%#v VMs=%#v FIPs=%#v", drift.name, api.vmDeletes, api.vms, api.floatingIPs)
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
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("malformed response did not retain floating-IP cleanup uncertainty: %v", err)
	}
	if len(api.vmDeletes) != 1 || len(api.vms) != 0 {
		t.Fatalf("invisible auto FIP prevented fail-closed VM deletion: deletes=%#v VMs=%#v", api.vmDeletes, api.vms)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].AssignedTo != "" {
		t.Fatalf("VM deletion contract was not reflected in delayed FIP state: %#v", api.floatingIPs)
	}
}

func TestRollbackPostVMFloatingIPAbsenceRequiresTwoObservationsAndResetsOnPresence(t *testing.T) {
	api := newFakeAPI()
	api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	api.vmDeleteHook = func() {
		// The exact address was discovered before VM deletion. Hide it only from
		// the first post-delete list to model an eventually consistent omission.
		api.floatingIPReadbackRemaining = 1
	}
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("stale post-VM floating-IP readback error = %v, want durable pending", err)
	}
	attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]
	if attempt.Phase != deletePhaseRollbackFIPAfterVM || attempt.FloatingIPAddress == "" || attempt.AbsenceObservedAt == "" {
		t.Fatalf("single stale omission cleared rollback identity: %#v", attempt)
	}
	if len(api.floatingIPs) != 1 || len(api.floatingIPDeletes) != 0 {
		t.Fatalf("single stale omission lost or deleted the anchored FIP: FIPs=%#v deletes=%#v", api.floatingIPs, api.floatingIPDeletes)
	}

	api.vmDeleteHook = nil
	if _, err := reconciler.rollbackFloatingIP(context.Background(), cluster, deleteAttemptBastion); err != nil {
		t.Fatalf("reappearing exact FIP did not resume rollback: %v", err)
	}
	attempt = cluster.Status.DeleteAttempts[deleteAttemptBastion]
	if attempt.Phase != deletePhaseRollbackFIPDeleteIntent || attempt.AbsenceObservedAt != "" {
		t.Fatalf("positive reappearance did not clear absence evidence: %#v", attempt)
	}

	var done bool
	var err error
	for observation := 0; observation < 2 && !done; observation++ {
		reconciler = testReconciler(api)
		done, err = reconciler.reconcileRollbackDelete(context.Background(), cluster, deleteAttemptBastion)
		if err != nil && !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("rollback FIP cleanup observation %d: %v", observation+1, err)
		}
	}
	if !done || len(api.floatingIPs) != 0 || len(api.floatingIPDeletes) != 1 {
		t.Fatalf("two-observation rollback cleanup did not converge: done=%t error=%v FIPs=%#v deletes=%#v", done, err, api.floatingIPs, api.floatingIPDeletes)
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
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			if commits && api.floatingIPs[0].Name != resourceNames.BastionFloatingIP {
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

func TestReconcileRequiresDurableStatusStoreBeforePaidCreate(t *testing.T) {
	api := newFakeAPI()
	reconciler := testReconciler(api)
	reconciler.StatusCompareAndSwap = nil
	if _, err := reconciler.Reconcile(context.Background(), testCluster(), "unit-test-secret-token"); err == nil || !strings.Contains(err.Error(), "durable InSpaceCluster status") {
		t.Fatalf("Reconcile() error = %v, want missing durable status store", err)
	}
	if len(api.events) != 0 || len(api.firewallCreates) != 0 || len(api.vmCreates) != 0 {
		t.Fatalf("missing status store reached cloud mutation: events=%v firewallPOSTs=%d VMPOSTs=%d", api.events, len(api.firewallCreates), len(api.vmCreates))
	}
}

func TestBootstrapMutationFailureProvesNoDispatchOnlyForLocalBlock(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		definitive bool
	}{
		{name: "validation", err: &inspace.APIError{StatusCode: 422}},
		{name: "bad request", err: &inspace.APIError{StatusCode: 400}},
		{name: "request timeout", err: &inspace.APIError{StatusCode: 408}},
		{name: "conflict", err: &inspace.APIError{StatusCode: 409}},
		{name: "too early", err: &inspace.APIError{StatusCode: 425}},
		{name: "rate limit", err: &inspace.APIError{StatusCode: 429}},
		{name: "client closed request", err: &inspace.APIError{StatusCode: 499}},
		{name: "server error", err: &inspace.APIError{StatusCode: 500}},
		{name: "transport", err: io.ErrUnexpectedEOF},
		{name: "preflight block", err: inspace.ErrMutationBlocked, definitive: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := bootstrapMutationFailureProvesNoDispatch(test.err); got != test.definitive {
				t.Fatalf("bootstrapMutationFailureProvesNoDispatch(%v) = %t, want %t", test.err, got, test.definitive)
			}
		})
	}
}

func TestDefinitiveCreateRejectionRequiresPostErrorProofAcrossRestart(t *testing.T) {
	t.Run("firewall", func(t *testing.T) {
		api := newFakeAPI()
		api.firewallCreateError = inspace.ErrMutationBlocked
		api.firewallListErrorAfterCreate = io.ErrUnexpectedEOF
		cluster := testCluster()
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("first Reconcile() error = %v, want durable pending rejection proof", err)
		}
		attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewall]
		if attempt.Phase != createAttemptPhaseRejected || len(api.firewallCreates) != 1 {
			t.Fatalf("firewall rejection attempt=%#v creates=%d", attempt, len(api.firewallCreates))
		}

		cluster = restartClusterFromJSON(t, cluster)
		api.firewallListErrorAfterCreate = nil
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("restart Reconcile() error = %v, want cleared rejection requeue", err)
		}
		if _, exists := cluster.Status.CreateAttempts[createAttemptBastionFirewall]; exists || len(api.firewallCreates) != 1 {
			t.Fatalf("post-error absence did not clear without replay: attempts=%#v creates=%d", cluster.Status.CreateAttempts, len(api.firewallCreates))
		}
	})

	t.Run("virtual machine", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		name := currentBastionName(cluster.Metadata.Name)
		api.failVMCreateNames = map[string]error{name: inspace.ErrMutationBlocked}
		api.vmListErrorAfterCreate = io.ErrUnexpectedEOF
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("first Reconcile() error = %v, want durable pending rejection proof", err)
		}
		attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]
		if attempt.Phase != createAttemptPhaseRejected || countVMCreatesByName(api.vmCreates, name) != 1 {
			t.Fatalf("VM rejection attempt=%#v creates=%#v", attempt, api.vmCreates)
		}

		cluster = restartClusterFromJSON(t, cluster)
		api.vmListErrorAfterCreate = nil
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("restart Reconcile() error = %v, want cleared rejection requeue", err)
		}
		if _, exists := cluster.Status.CreateAttempts[createAttemptBastionVM]; exists || countVMCreatesByName(api.vmCreates, name) != 1 {
			t.Fatalf("post-error VM absence did not clear without replay: attempts=%#v creates=%#v", cluster.Status.CreateAttempts, api.vmCreates)
		}
	})

	t.Run("visible VM wins over rejection", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		name := currentBastionName(cluster.Metadata.Name)
		createErr := &inspace.APIError{StatusCode: 422, Method: "POST", Path: "/vm", Message: "late rejection"}
		api.failVMCreateNames = map[string]error{name: createErr}
		api.commitVMCreateErrors = map[string]bool{name: true}
		api.mutateCreateVMResponse = func(request inspace.CreateVMRequest, response *inspace.VM) {
			if request.Name == name {
				response.UUID = ""
			}
		}
		if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, createErr) || !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("Reconcile() error = %v, want visible rejected-response recovery", err)
		}
		attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]
		if attempt.Phase != createAttemptPhaseMaterialized || !vmUUIDPattern.MatchString(attempt.ResourceUUID) || countVMCreatesByName(api.vmCreates, name) != 1 {
			t.Fatalf("visible post-error VM was not durably adopted: attempt=%#v creates=%#v", attempt, api.vmCreates)
		}
	})
}

func TestFloatingIPUpdateFenceNeverReplaysAmbiguousPATCHAcrossRestart(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	updateErr := &inspace.APIError{StatusCode: 400, Method: "PATCH", Path: "/ip", Message: "post-dispatch error"}
	api.floatingIPUpdateError = updateErr
	api.floatingIPUpdateErrorCommits = true
	api.floatingIPReadbackDelay = 1000
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("ambiguous PATCH error = %v, want durable pending", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]
	if attempt.Phase != createAttemptPhaseIssued || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("ambiguous PATCH attempt=%#v calls=%d", attempt, api.floatingIPUpdateCalls)
	}

	cluster = restartClusterFromJSON(t, cluster)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil && !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("restart PATCH recovery error = %v, want reads-only reconciliation", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]
	if attempt.Phase != createAttemptPhaseIssued || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("restart changed/replayed ambiguous PATCH: attempt=%#v calls=%d", attempt, api.floatingIPUpdateCalls)
	}

	api.mu.Lock()
	api.floatingIPUpdateError = nil
	api.floatingIPReadbackRemaining = 0
	api.floatingIPReadbackDelay = 0
	api.mu.Unlock()
	cluster = restartClusterFromJSON(t, cluster)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("late visible PATCH did not recover: %v", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]
	if attempt.Phase != createAttemptPhaseMaterialized || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("late PATCH recovery attempt=%#v calls=%d", attempt, api.floatingIPUpdateCalls)
	}
}

func TestFloatingIPDefinitiveRejectionClearsOnlyAfterRestartReadback(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatal(err)
	}
	api.floatingIPUpdateError = inspace.ErrMutationBlocked
	api.floatingIPListErrorAfterUpdate = io.ErrUnexpectedEOF
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("definitive PATCH error = %v, want pending proof", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]
	if attempt.Phase != createAttemptPhaseRejected || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("definitive PATCH attempt=%#v calls=%d", attempt, api.floatingIPUpdateCalls)
	}

	cluster = restartClusterFromJSON(t, cluster)
	api.floatingIPListErrorAfterUpdate = nil
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("post-error unchanged readback did not clear receipt: %v", err)
	}
	if _, exists := cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]; exists || api.floatingIPUpdateCalls != 1 {
		t.Fatalf("unchanged proof did not clear without replay: attempts=%#v calls=%d", cluster.Status.CreateAttempts, api.floatingIPUpdateCalls)
	}

	api.floatingIPUpdateError = nil
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("cleared PATCH did not retry safely: %v", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]
	if attempt.Phase != createAttemptPhaseMaterialized || api.floatingIPUpdateCalls != 2 {
		t.Fatalf("retried PATCH attempt=%#v calls=%d", attempt, api.floatingIPUpdateCalls)
	}
}

func TestFirewallAssignmentDefinitiveRejectionClearsOnlyAfterRestartReadback(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconcileUntilReady(t, testReconciler(api), cluster)
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastionFirewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	bastionFirewall.ResourcesAssigned = nil
	delete(cluster.Status.CreateAttempts, createAttemptBastionFirewallAssignment)

	api.firewallAssignmentError = inspace.ErrMutationBlocked
	api.firewallListErrorAfterAssignment = io.ErrUnexpectedEOF
	api.firewallListErrorAfterAssignmentCall = api.firewallAssignmentCalls + 1
	before := api.firewallAssignmentCalls
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("definitive assignment error = %v, want pending proof", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if attempt.Phase != createAttemptPhaseRejected || api.firewallAssignmentCalls != before+1 {
		t.Fatalf("definitive assignment attempt=%#v calls=%d before=%d", attempt, api.firewallAssignmentCalls, before)
	}

	cluster = restartClusterFromJSON(t, cluster)
	api.firewallListErrorAfterAssignment = nil
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("post-error assignment absence error = %v, want cleared rejection requeue", err)
	}
	if _, exists := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]; exists || api.firewallAssignmentCalls != before+1 {
		t.Fatalf("assignment absence did not clear without replay: attempts=%#v calls=%d", cluster.Status.CreateAttempts, api.firewallAssignmentCalls)
	}

	api.firewallAssignmentError = nil
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("cleared assignment did not retry safely: %v", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != bastion.UUID || api.firewallAssignmentCalls != before+2 {
		t.Fatalf("retried assignment attempt=%#v calls=%d", attempt, api.firewallAssignmentCalls)
	}
}

func TestCreateAttemptLedgerCoversAllPaidCreatesAndClearsAfterDestroy(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready || len(cluster.Status.CreateAttempts) != 2+3*(1+ControlPlaneReplicas) {
		t.Fatalf("ready result=%#v create attempts=%#v", result, cluster.Status.CreateAttempts)
	}
	for key, attempt := range cluster.Status.CreateAttempts {
		if attempt.Phase != createAttemptPhaseMaterialized || !vmUUIDPattern.MatchString(attempt.ResourceUUID) {
			t.Fatalf("create attempt %q = %#v, want materialized exact UUID", key, attempt)
		}
	}
	destroyed := destroyUntilDone(t, reconciler, cluster)
	if !destroyed.Done || len(cluster.Status.CreateAttempts) != 0 {
		t.Fatalf("destroy result=%#v retained attempts=%#v", destroyed, cluster.Status.CreateAttempts)
	}
}

func TestAmbiguousFirewallCreateLateVisibilityNeverReplaysAcrossRestart(t *testing.T) {
	createErr := &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/firewall", Message: "post-dispatch error"}
	api := newFakeAPI()
	api.firewallCreateError = createErr
	api.firewallCreateErrorCommits = true
	api.mutateCreateFirewallResponse = func(_ inspace.CreateFirewallRequest, response *inspace.Firewall) {
		response.UUID = ""
	}
	api.firewallListReadbackRemaining = 1000
	cluster := testCluster()

	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, createErr) {
		t.Fatalf("first Reconcile() error = %v, want ambiguous firewall create", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewall]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" || len(api.firewallCreates) != 1 {
		t.Fatalf("first firewall attempt = %#v creates=%d", attempt, len(api.firewallCreates))
	}
	cluster = restartClusterFromJSON(t, cluster)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("restart Reconcile() error = %v, want read-only pending recovery", err)
	}
	if len(api.firewallCreates) != 1 || len(api.firewalls) != 1 {
		t.Fatalf("hidden committed firewall was replayed: creates=%d firewalls=%#v", len(api.firewallCreates), api.firewalls)
	}

	api.firewallCreateError = nil
	api.firewallListReadbackRemaining = 0
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("visible committed firewall did not recover: %v", err)
	}
	if len(api.firewallCreates) != 1 {
		t.Fatalf("authoritative recovery issued %d firewall creates, want one", len(api.firewallCreates))
	}
}

func TestAmbiguousVMCreateLateVisibilityNeverReplaysAcrossRestart(t *testing.T) {
	createErr := &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/vm", Message: "post-dispatch error"}
	api := newFakeAPI()
	cluster := testCluster()
	bastionName := currentBastionName(cluster.Metadata.Name)
	api.failVMCreateNames = map[string]error{bastionName: createErr}
	api.commitVMCreateErrors = map[string]bool{bastionName: true}
	api.mutateCreateVMResponse = func(request inspace.CreateVMRequest, vm *inspace.VM) {
		if request.Name == bastionName {
			vm.UUID = ""
		}
	}
	api.vmListReadbackDelay = 1000

	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, createErr) {
		t.Fatalf("first Reconcile() error = %v, want ambiguous VM create", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" || countVMCreatesByName(api.vmCreates, bastionName) != 1 {
		t.Fatalf("first VM attempt = %#v creates=%#v", attempt, api.vmCreates)
	}
	cluster = restartClusterFromJSON(t, cluster)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("restart Reconcile() error = %v, want read-only pending recovery", err)
	}
	if countVMCreatesByName(api.vmCreates, bastionName) != 1 || len(api.vms) != 1 {
		t.Fatalf("hidden committed VM was replayed: creates=%#v VMs=%#v", api.vmCreates, api.vms)
	}

	delete(api.failVMCreateNames, bastionName)
	delete(api.commitVMCreateErrors, bastionName)
	api.vmListReadbackRemaining = 0
	api.vmListReadbackDelay = 0
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("visible committed VM did not recover: %v", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionVM]
	if attempt.Phase != createAttemptPhaseMaterialized || !vmUUIDPattern.MatchString(attempt.ResourceUUID) || countVMCreatesByName(api.vmCreates, bastionName) != 1 {
		t.Fatalf("recovered VM attempt = %#v creates=%#v", attempt, api.vmCreates)
	}
}

func TestAmbiguousFirewallAssignmentLateVisibilityNeverReplaysAcrossRestart(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconcileUntilReady(t, testReconciler(api), cluster)
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastionFirewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	bastionFirewall.ResourcesAssigned = nil
	delete(cluster.Status.CreateAttempts, createAttemptBastionFirewallAssignment)

	api.firewallAssignmentError = &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/firewall/assign", Message: "post-dispatch error"}
	api.firewallAssignmentErrorCommits = true
	api.firewallAssignmentReadbackDelay = 1000
	assignmentPrefix := "assign-firewall/" + bastionFirewall.UUID + "/" + bastion.UUID
	before := countEventsWithPrefix(api.events, assignmentPrefix)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("first Reconcile() error = %v, want durable pending assignment", err)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" {
		t.Fatalf("ambiguous assignment attempt = %#v, want issued without materialized UUID", attempt)
	}
	if got := countEventsWithPrefix(api.events, assignmentPrefix); got != before+1 {
		t.Fatalf("first ambiguous assignment issued %d POSTs, want one", got-before)
	}

	// A fresh reconciler receives only the durably persisted cluster status.
	// Although the committed row is still hidden, it must perform reads only.
	cluster = restartClusterFromJSON(t, cluster)
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("restart Reconcile() error = %v, want read-only pending recovery", err)
	}
	if got := countEventsWithPrefix(api.events, assignmentPrefix); got != before+1 {
		t.Fatalf("restart replayed ambiguous assignment: POST count=%d, want %d", got, before+1)
	}

	api.firewallAssignmentError = nil
	api.firewallAssignmentReadbackRemaining = 0
	if _, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
		t.Fatalf("visible committed assignment did not recover: %v", err)
	}
	attempt = cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != bastion.UUID {
		t.Fatalf("recovered assignment attempt = %#v", attempt)
	}
	if got := countEventsWithPrefix(api.events, assignmentPrefix); got != before+1 {
		t.Fatalf("authoritative recovery issued %d assignment POSTs, want one", got-before)
	}
}

func countVMCreatesByName(requests []inspace.CreateVMRequest, name string) int {
	count := 0
	for _, request := range requests {
		if request.Name == name {
			count++
		}
	}
	return count
}

func countEventsWithPrefix(events []string, prefix string) int {
	count := 0
	for _, event := range events {
		if strings.HasPrefix(event, prefix) {
			count++
		}
	}
	return count
}

func restartClusterFromJSON(t *testing.T, cluster *v1alpha1.InSpaceCluster) *v1alpha1.InSpaceCluster {
	t.Helper()
	encoded, err := json.Marshal(cluster)
	if err != nil {
		t.Fatal(err)
	}
	var restarted v1alpha1.InSpaceCluster
	if err := json.Unmarshal(encoded, &restarted); err != nil {
		t.Fatal(err)
	}
	return &restarted
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
	t.Run("ordered control plane", func(t *testing.T) {
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
			t.Fatalf("ordered ambiguous malformed error was not retained: %v", err)
		}
		if len(api.vmCreates) != 3 || len(api.vmDeletes) != 1 || len(api.vms) != 2 || len(api.floatingIPs) != 2 ||
			countVMCreatesByName(api.vmCreates, controlPlaneName(cluster.Metadata.Name, 2)) != 0 {
			t.Fatalf("ordered malformed slot rollback touched successes or launched slot 2: creates=%#v deletes=%#v VMs=%#v FIPs=%#v", api.vmCreates, api.vmDeletes, api.vms, api.floatingIPs)
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
			cluster := testCluster()
			api.floatingIPs[0].Name = currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
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
		if _, err := reconciler.Reconcile(context.Background(), cluster, "token"); err == nil {
			t.Fatal("expected authoritative VM pool collision")
		}
		if len(api.vmCreates) != 1 || len(api.vmDeletes) != 1 || len(api.vms) != 0 {
			t.Fatalf("authoritative pool collision was not confined to its canonically owned VM: creates=%#v deletes=%#v VMs=%#v", api.vmCreates, api.vmDeletes, api.vms)
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
	wantName := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
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
			wantName := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
			if commits != (api.floatingIPs[0].Name == wantName) {
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
	wantName := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
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

func TestDestroyConvergesForV4OwnershipRecords(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastion.Description = strings.Replace(bastion.Description, "inspace-rke2-bastion/v6 ", "inspace-rke2-bastion/v4 ", 1)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		controlPlane := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		controlPlane.Description = strings.Replace(controlPlane.Description, "inspace-rke2-cp/v8 ", "inspace-rke2-cp/v4 ", 1)
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("v4 ownership topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyConvergesForV5OwnershipRecords(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastion.Description = strings.Replace(bastion.Description, "inspace-rke2-bastion/v6 ", "inspace-rke2-bastion/v5 ", 1)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		controlPlane := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		controlPlane.Description = strings.Replace(controlPlane.Description, "inspace-rke2-cp/v8 ", "inspace-rke2-cp/v5 ", 1)
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("v5 ownership topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyConvergesForV6OwnershipRecords(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		controlPlane := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		controlPlane.Description = strings.Replace(controlPlane.Description, "inspace-rke2-cp/v8 ", "inspace-rke2-cp/v6 ", 1)
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("v6 ownership topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyConvergesForV7OwnershipRecords(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		controlPlane := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		controlPlane.Description = strings.Replace(controlPlane.Description, "inspace-rke2-cp/v8 ", "inspace-rke2-cp/v7 ", 1)
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("v7 ownership topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyConvergesForCurrentV6BastionV8ControlPlanes(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	if !strings.HasPrefix(bastion.Description, "inspace-rke2-bastion/v6 ") {
		t.Fatalf("current bastion ownership = %q", bastion.Description)
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		controlPlane := mustVM(t, api.vms, controlPlaneName(cluster.Metadata.Name, slot))
		if !strings.HasPrefix(controlPlane.Description, "inspace-rke2-cp/v8 ") {
			t.Fatalf("current control-plane %d ownership = %q", slot, controlPlane.Description)
		}
	}

	result := destroyUntilDone(t, reconciler, cluster)
	if !result.Done || len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("current ownership topology did not converge: result=%#v VMs=%#v FIPs=%#v firewalls=%#v", result, api.vms, api.floatingIPs, api.firewalls)
	}
}

func TestDestroyRejectsIncoherentOwnershipSchemaTopology(t *testing.T) {
	tests := map[string]func(*testing.T, *fakeAPI, *v1alpha1.InSpaceCluster){
		"v6 bastion with v2 control planes": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			convertControlPlaneOwnershipToV2(t, api, cluster)
		},
		"v1 bastion with v8 control planes": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			convertBastionToLegacy(t, api, cluster)
		},
		"mixed v2 and v8 control planes without bastion": func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
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
				resourceNames := legacyBootstrapResourceNames(owner)
				for i := range api.floatingIPs {
					if api.floatingIPs[i].Name == resourceNames.ControlPlaneFIP[1] {
						api.floatingIPs[i].BillingAccountID++
					}
				}
			},
			want: "billing-account ownership",
		},
		"node firewall assignment": {
			mutate: func(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				resourceNames := legacyBootstrapResourceNames(ownerKey(cluster))
				firewall := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
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
	oldResourceNames := currentBootstrapResourceNames(oldClusterName, oldOwner)
	newResourceNames := legacyBootstrapResourceNames(newOwner)
	floatingIPNames := map[string]string{oldResourceNames.BastionFloatingIP: newResourceNames.BastionFloatingIP}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		floatingIPNames[oldResourceNames.ControlPlaneFIP[slot]] = newResourceNames.ControlPlaneFIP[slot]
	}
	for i := range api.floatingIPs {
		api.floatingIPs[i].Name = floatingIPNames[api.floatingIPs[i].Name]
	}
	firewallNames := map[string]string{
		oldResourceNames.NodeFirewall:    newResourceNames.NodeFirewall,
		oldResourceNames.BastionFirewall: newResourceNames.BastionFirewall,
	}
	for i := range api.firewalls {
		name := firewallNames[api.firewalls[i].EffectiveName()]
		api.firewalls[i].Name = name
		api.firewalls[i].DisplayName = name
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
	var waiting DestroyResult
	var err error
	for i := 0; i < 10; i++ {
		waiting, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil || strings.Contains(waiting.Message, "waiting for firewall assignments to clear") {
			break
		}
	}
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
	if !result.Done || len(api.firewalls) != 0 || len(cluster.Status.DeleteAttempts) != 0 {
		t.Fatalf("destroy did not converge after assignments cleared: result=%#v firewalls=%#v pending=%#v", result, api.firewalls, cluster.Status.DeleteAttempts)
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
				if len(api.vmDeletes) != 0 {
					break
				}
			}
			if !errors.Is(deleteErr, ambiguousErr) || len(api.vmDeletes) != 1 || len(api.vms) != ControlPlaneReplicas {
				t.Fatalf("ambiguous committed delete state: error=%v deletes=%#v VMs=%#v", deleteErr, api.vmDeletes, api.vms)
			}
			if attempt, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]; !exists || attempt.Phase != deletePhaseVMIssued || attempt.AbsenceObservedAt == "" {
				t.Fatalf("ambiguous committed delete lost its exact intent: %#v", cluster.Status.DeleteAttempts)
			}
			firstDeleted := api.vmDeletes[0]
			reconciler = testReconciler(api)

			api.vmDeleteError = nil
			api.vmDeleteErrorCommits = false
			if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
				t.Fatalf("restart did not complete the second corroborated absence observation: %v", err)
			}
			if attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]; attempt.Phase != deletePhaseAbsent {
				t.Fatalf("restart did not establish durable VM absence: %#v", attempt)
			}
			for i := 0; i < 20 && len(api.vms) != 0; i++ {
				if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
					t.Fatalf("destroy after ambiguous commit %d: %v", i, err)
				}
			}
			var waiting DestroyResult
			var err error
			for i := 0; i < 10; i++ {
				waiting, err = reconciler.Destroy(context.Background(), cluster)
				if err != nil || strings.Contains(waiting.Message, "waiting for firewall assignments to clear") {
					break
				}
			}
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
			if !result.Done || len(api.firewalls) != 0 || len(cluster.Status.DeleteAttempts) != 0 || countStrings(api.vmDeletes, firstDeleted) != 1 {
				t.Fatalf("ambiguous committed delete did not converge exactly once: result=%#v firewalls=%#v pending=%#v deletes=%#v", result, api.firewalls, cluster.Status.DeleteAttempts, api.vmDeletes)
			}
		})
	}
}

func TestDestroyDeleteReceiptSurvivesControllerRestartWithoutTimeout(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)
	if attempt, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]; !exists || attempt.Phase != deletePhaseAbsent {
		t.Fatalf("durable delete receipt=%#v", cluster.Status.DeleteAttempts)
	}
	firstDeleted := api.vmDeletes[0]
	reconciler = testReconciler(api)
	for i := 0; i < 20 && len(api.vms) != 0; i++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("destroy after reconstructed controller %d: %v", i, err)
		}
	}
	if countStrings(api.vmDeletes, firstDeleted) != 1 {
		t.Fatalf("reconstructed controller replayed exact DELETE: %#v", api.vmDeletes)
	}
}

func TestDestroyCommittedHTTP500AndReadbackOutageNeverReplaysVMDelete(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastionUUID := bastion.UUID
	http500 := &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/vm", Message: "committed but response failed"}
	readbackOutage := io.ErrUnexpectedEOF
	api.vmDeleteError = http500
	api.vmDeleteErrorCommits = true
	api.vmDeleteHook = func() {
		api.getVMErrorByUUID = map[string]error{bastionUUID: readbackOutage}
	}

	var destroyErr error
	for i := 0; i < 30 && len(api.vmDeletes) == 0; i++ {
		_, destroyErr = reconciler.Destroy(context.Background(), cluster)
	}
	if len(api.vmDeletes) != 1 || !errors.Is(destroyErr, http500) || !errors.Is(destroyErr, readbackOutage) {
		t.Fatalf("committed HTTP500/readback outage state: deletes=%#v error=%v", api.vmDeletes, destroyErr)
	}
	attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]
	if attempt.Phase != deletePhaseVMIssued || attempt.AbsenceObservedAt != "" {
		t.Fatalf("ambiguous delete did not retain an unresolved issued lock: %#v", attempt)
	}

	reconciler = testReconciler(api)
	if _, err := reconciler.Destroy(context.Background(), cluster); !errors.Is(err, readbackOutage) {
		t.Fatalf("reconstructed controller did not remain read-only during outage: %v", err)
	}
	if len(api.vmDeletes) != 1 {
		t.Fatalf("reconstructed controller replayed DELETE during outage: %#v", api.vmDeletes)
	}
	delete(api.getVMErrorByUUID, bastionUUID)
	api.vmDeleteError = nil
	api.vmDeleteErrorCommits = false
	api.vmDeleteHook = nil
	var recoveryErr error
	for i := 0; i < 3; i++ {
		reconciler = testReconciler(api)
		_, recoveryErr = reconciler.Destroy(context.Background(), cluster)
	}
	if countStrings(api.vmDeletes, bastionUUID) != 1 || cluster.Status.DeleteAttempts[deleteAttemptBastion].Phase != deletePhaseAbsent {
		t.Fatalf("two absence observations did not resolve without replay: deletes=%#v receipt=%#v lastError=%v", api.vmDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion], recoveryErr)
	}
}

func TestDestroyCommittedHTTP500SplitVMReadbackRequiresListAndVPCAbsence(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	bastion := *mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastion.Storage = append([]inspace.VMStorage(nil), bastion.Storage...)
	http500 := &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/vm", Message: "committed with split readback"}
	api.vmDeleteError = http500
	api.vmDeleteErrorCommits = true
	api.retainVMInventoryOnDelete = true
	api.vmDeleteHook = func() {
		api.getVMErrorByUUID = map[string]error{bastion.UUID: &inspace.APIError{
			StatusCode: 404, Method: "GET", Path: "/vm", Message: "detail already absent",
		}}
	}

	var destroyErr error
	for attempt := 0; attempt < 30 && len(api.vmDeletes) == 0; attempt++ {
		_, destroyErr = reconciler.Destroy(context.Background(), cluster)
	}
	if len(api.vmDeletes) != 1 || !errors.Is(destroyErr, http500) {
		t.Fatalf("committed split-view delete: deletes=%#v error=%v", api.vmDeletes, destroyErr)
	}
	receipt := cluster.Status.DeleteAttempts[deleteAttemptBastion]
	if receipt.Phase != deletePhaseVMIssued || receipt.AbsenceObservedAt != "" || len(api.firewallDeletes) != 0 {
		t.Fatalf("split-view readback advanced deletion: receipt=%#v firewallDeletes=%#v", receipt, api.firewallDeletes)
	}

	reconciler = testReconciler(api)
	if _, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err != nil {
		t.Fatalf("restart split-view observation: %v", err)
	}
	if len(api.vmDeletes) != 1 || cluster.Status.DeleteAttempts[deleteAttemptBastion].AbsenceObservedAt != "" {
		t.Fatalf("restart replayed or trusted split view: deletes=%#v receipt=%#v", api.vmDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion])
	}

	api.removeVMFromReadback(bastion.UUID)
	delete(api.getVMErrorByUUID, bastion.UUID)
	if absent, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err != nil || absent {
		t.Fatalf("first corroborated absence: absent=%t error=%v", absent, err)
	}
	if cluster.Status.DeleteAttempts[deleteAttemptBastion].AbsenceObservedAt == "" {
		t.Fatal("first corroborated absence was not persisted")
	}

	api.mu.Lock()
	api.vms = append(api.vms, bastion)
	api.network.VMUUIDs = append(api.network.VMUUIDs, bastion.UUID)
	api.mu.Unlock()
	if absent, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err != nil || absent {
		t.Fatalf("positive reappearance reset: absent=%t error=%v", absent, err)
	}
	if cluster.Status.DeleteAttempts[deleteAttemptBastion].AbsenceObservedAt != "" {
		t.Fatalf("positive reappearance did not reset evidence: %#v", cluster.Status.DeleteAttempts[deleteAttemptBastion])
	}

	api.removeVMFromReadback(bastion.UUID)
	for observation := 0; observation < 2; observation++ {
		reconciler = testReconciler(api)
		if _, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err != nil {
			t.Fatalf("corroborated absence observation %d: %v", observation+1, err)
		}
	}
	if len(api.vmDeletes) != 1 || cluster.Status.DeleteAttempts[deleteAttemptBastion].Phase != deletePhaseAbsent || len(api.firewallDeletes) != 0 {
		t.Fatalf("corroborated convergence: deletes=%#v receipt=%#v firewallDeletes=%#v", api.vmDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion], api.firewallDeletes)
	}
}

func TestDestroyCommittedHTTP500AndReadbackOutageNeverReplaysFloatingIPMutations(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	owner := ownerKey(cluster)
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	vmUUID := "10000000-1111-4222-8333-bbbbbbbbbbbb"
	item := inspace.FloatingIP{
		Name: resourceNames.BastionFloatingIP, Address: "203.0.113.90", BillingAccountID: cluster.Spec.BillingAccountID,
		Type: "public", Enabled: true, AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: "10.20.30.20",
	}
	seedOwnedMutationVMs(t, api, cluster, vmUUID)
	api.floatingIPs = []inspace.FloatingIP{item}
	reconciler := testReconciler(api)
	if err := reconciler.ensureDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey, &item); err != nil {
		t.Fatal(err)
	}

	http500 := &inspace.APIError{StatusCode: 500, Method: "POST", Path: "/ip/unassign", Message: "committed but response failed"}
	readbackOutage := io.ErrUnexpectedEOF
	api.floatingIPUnassignError = http500
	api.floatingIPUnassignErrorCommits = true
	api.floatingIPListErrorAfterUnassign = readbackOutage
	if _, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); !errors.Is(err, http500) || !errors.Is(err, readbackOutage) {
		t.Fatalf("ambiguous unassign error = %v", err)
	}
	if got := countEvents(api.events, "unassign-fip/"+item.Address); got != 1 {
		t.Fatalf("unassign calls = %d, want 1", got)
	}
	if attempt := cluster.Status.DeleteAttempts[destroyFIPBastionKey]; attempt.Phase != deletePhaseFIPUnassignIssued || attempt.AbsenceObservedAt != "" {
		t.Fatalf("unassign receipt = %#v", attempt)
	}

	reconciler = testReconciler(api)
	if _, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); !errors.Is(err, readbackOutage) {
		t.Fatalf("restart unassign readback error = %v", err)
	}
	if got := countEvents(api.events, "unassign-fip/"+item.Address); got != 1 {
		t.Fatalf("restart replayed unassign: %d calls", got)
	}
	api.floatingIPUnassignError = nil
	api.floatingIPUnassignErrorCommits = false
	api.floatingIPListErrorAfterUnassign = nil
	if terminal, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); err != nil || terminal {
		t.Fatalf("unassign convergence: terminal=%t error=%v", terminal, err)
	}
	if attempt := cluster.Status.DeleteAttempts[destroyFIPBastionKey]; attempt.Phase != deletePhaseFIPDeleteIntent {
		t.Fatalf("unassign did not advance to delete intent: %#v", attempt)
	}

	http500 = &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/ip", Message: "committed but response failed"}
	api.floatingIPDeleteError = http500
	api.floatingIPDeleteErrorCommits = true
	api.floatingIPListErrorAfterDelete = readbackOutage
	if _, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); !errors.Is(err, http500) || !errors.Is(err, readbackOutage) {
		t.Fatalf("ambiguous floating-IP delete error = %v", err)
	}
	if got := countStrings(api.floatingIPDeletes, item.Address); got != 1 {
		t.Fatalf("floating-IP delete calls = %d, want 1", got)
	}
	if attempt := cluster.Status.DeleteAttempts[destroyFIPBastionKey]; attempt.Phase != deletePhaseFIPDeleteIssued || attempt.AbsenceObservedAt != "" {
		t.Fatalf("floating-IP delete receipt = %#v", attempt)
	}

	reconciler = testReconciler(api)
	if _, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); !errors.Is(err, readbackOutage) {
		t.Fatalf("restart delete readback error = %v", err)
	}
	if got := countStrings(api.floatingIPDeletes, item.Address); got != 1 {
		t.Fatalf("restart replayed floating-IP delete: %d calls", got)
	}
	api.floatingIPDeleteError = nil
	api.floatingIPDeleteErrorCommits = false
	api.floatingIPListErrorAfterDelete = nil
	terminal, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey)
	if err != nil || !terminal {
		t.Fatalf("floating-IP delete convergence: terminal=%t error=%v", terminal, err)
	}
	if got := countStrings(api.floatingIPDeletes, item.Address); got != 1 {
		t.Fatalf("convergence replayed floating-IP delete: %d calls", got)
	}
}

func TestDestroyCommittedHTTP500AndReadbackOutageNeverReplaysFirewallDelete(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	item := inspace.Firewall{
		UUID: "77777770-1111-4222-8333-444444444444", DisplayName: resourceNames.BastionFirewall,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules:            managedBastionFirewallRules("198.51.100.24/32", api.network.Subnet, false),
	}
	api.firewalls = []inspace.Firewall{item}
	reconciler := testReconciler(api)
	if err := reconciler.ensureDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey, &item); err != nil {
		t.Fatal(err)
	}

	http500 := &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/firewall", Message: "committed but response failed"}
	readbackOutage := io.ErrUnexpectedEOF
	api.firewallDeleteError = http500
	api.firewallDeleteErrorCommits = true
	api.firewallListErrorAfterDelete = readbackOutage
	if _, err := reconciler.reconcileDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey); !errors.Is(err, http500) || !errors.Is(err, readbackOutage) {
		t.Fatalf("ambiguous firewall delete error = %v", err)
	}
	if got := countStrings(api.firewallDeletes, item.UUID); got != 1 {
		t.Fatalf("firewall delete calls = %d, want 1", got)
	}
	if attempt := cluster.Status.DeleteAttempts[destroyFirewallBastionKey]; attempt.Phase != deletePhaseFirewallDeleteIssued || attempt.AbsenceObservedAt != "" {
		t.Fatalf("firewall delete receipt = %#v", attempt)
	}

	reconciler = testReconciler(api)
	if _, err := reconciler.reconcileDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey); !errors.Is(err, readbackOutage) {
		t.Fatalf("restart firewall readback error = %v", err)
	}
	if got := countStrings(api.firewallDeletes, item.UUID); got != 1 {
		t.Fatalf("restart replayed firewall delete: %d calls", got)
	}
	api.firewallDeleteError = nil
	api.firewallDeleteErrorCommits = false
	api.firewallListErrorAfterDelete = nil
	terminal, err := reconciler.reconcileDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey)
	if err != nil || !terminal {
		t.Fatalf("firewall delete convergence: terminal=%t error=%v", terminal, err)
	}
	if got := countStrings(api.firewallDeletes, item.UUID); got != 1 {
		t.Fatalf("convergence replayed firewall delete: %d calls", got)
	}
}

func TestDestroyRemovalIntentsRevalidateCloudOwnershipAfterIssueCAS(t *testing.T) {
	t.Run("floating IP", func(t *testing.T) {
		tests := map[string]func(*inspace.FloatingIP){
			"name":       func(item *inspace.FloatingIP) { item.Name = "foreign" },
			"billing":    func(item *inspace.FloatingIP) { item.BillingAccountID = 999 },
			"assignment": func(item *inspace.FloatingIP) { item.AssignedTo = "99999999-1111-4222-8333-bbbbbbbbbbbb" },
			"type":       func(item *inspace.FloatingIP) { item.Type = "private" },
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				api := newFakeAPI()
				cluster := testCluster()
				resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
				vmUUID := "10000000-1111-4222-8333-bbbbbbbbbbbb"
				item := inspace.FloatingIP{
					Name: resourceNames.BastionFloatingIP, Address: "203.0.113.91", BillingAccountID: cluster.Spec.BillingAccountID,
					Type: "public", Enabled: true, AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: "10.20.30.20",
				}
				seedOwnedMutationVMs(t, api, cluster, vmUUID)
				api.floatingIPs = []inspace.FloatingIP{item}
				reconciler := testReconciler(api)
				if err := reconciler.ensureDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey, &item); err != nil {
					t.Fatal(err)
				}
				mutate(&api.floatingIPs[0])
				if _, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey); err == nil {
					t.Fatal("drifted floating-IP receipt authorized a cloud mutation")
				}
				attempt := cluster.Status.DeleteAttempts[destroyFIPBastionKey]
				if countEventsWithPrefix(api.events, "unassign-fip/") != 0 || len(api.floatingIPDeletes) != 0 || attempt.Phase != deletePhaseFIPUnassignIssued {
					t.Fatalf("floating-IP drift mutated cloud state or lost its durable issue lock: events=%#v deletes=%#v attempt=%#v", api.events, api.floatingIPDeletes, attempt)
				}
			})
		}
	})

	t.Run("firewall", func(t *testing.T) {
		tests := map[string]func(*inspace.Firewall){
			"name":    func(item *inspace.Firewall) { item.DisplayName = "foreign" },
			"billing": func(item *inspace.Firewall) { item.BillingAccountID = 999 },
			"policy":  func(item *inspace.Firewall) { item.Rules = nil },
			"assignments": func(item *inspace.Firewall) {
				item.ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: "99999999-1111-4222-8333-bbbbbbbbbbbb"}}
			},
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				api := newFakeAPI()
				cluster := testCluster()
				resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
				item := inspace.Firewall{
					UUID: "77777770-1111-4222-8333-444444444444", DisplayName: resourceNames.BastionFirewall,
					BillingAccountID: cluster.Spec.BillingAccountID,
					Rules:            managedBastionFirewallRules("198.51.100.24/32", api.network.Subnet, false),
				}
				api.firewalls = []inspace.Firewall{item}
				reconciler := testReconciler(api)
				if err := reconciler.ensureDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey, &item); err != nil {
					t.Fatal(err)
				}
				mutate(&api.firewalls[0])
				if _, err := reconciler.reconcileDestroyFirewallRemoval(context.Background(), cluster, destroyFirewallBastionKey); err == nil {
					t.Fatal("drifted firewall receipt authorized a cloud mutation")
				}
				attempt := cluster.Status.DeleteAttempts[destroyFirewallBastionKey]
				if len(api.firewallDeletes) != 0 || attempt.Phase != deletePhaseFirewallDeleteIssued {
					t.Fatalf("firewall drift mutated cloud state or lost its durable issue lock: deletes=%#v attempt=%#v", api.firewallDeletes, attempt)
				}
			})
		}
	})
}

func TestMalformedCreateRollbackRestartRecreatesOnlyAfterVMAndFIPAbsence(t *testing.T) {
	api := newFakeAPI()
	api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	api.vmDeleteHook = func() { api.floatingIPListError = io.ErrUnexpectedEOF }
	cluster := testCluster()
	reconciler := testReconciler(api)
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err == nil {
		t.Fatal("expected malformed first VM to enter durable rollback")
	}
	if len(api.vmDeletes) != 1 || len(api.vmCreates) != 1 {
		t.Fatalf("malformed containment did not issue exactly one create/delete: creates=%#v deletes=%#v", api.vmCreates, api.vmDeletes)
	}
	oldUUID := api.vmDeletes[0]
	if len(api.floatingIPs) != 1 {
		t.Fatalf("test requires the old auto floating IP to remain for durable cleanup: %#v", api.floatingIPs)
	}
	api.vmDeleteHook = nil
	api.floatingIPListError = nil
	api.mutateStoredVM = nil
	for i := 0; i < 20 && len(api.vmCreates) < 2; i++ {
		reconciler = testReconciler(api)
		_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
		if err != nil && !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("rollback/replacement reconcile %d: %v", i, err)
		}
	}
	if len(api.vmCreates) != 2 || countStrings(api.vmDeletes, oldUUID) != 1 || len(api.floatingIPs) != 1 {
		t.Fatalf("rollback replacement was not exact: creates=%#v deletes=%#v FIPs=%#v", api.vmCreates, api.vmDeletes, api.floatingIPs)
	}
	newVM := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	if newVM.UUID == oldUUID {
		t.Fatal("replacement reused the deleted VM UUID")
	}
	create := cluster.Status.CreateAttempts[createAttemptBastionVM]
	assignment := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if !strings.EqualFold(create.ResourceUUID, newVM.UUID) || strings.Contains(assignment.ResourceName, oldUUID) {
		t.Fatalf("replacement receipts retained deleted identity: create=%#v assignment=%#v", create, assignment)
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
	if !errors.Is(deleteErr, rejectedErr) || len(api.vmDeletes) != 1 || len(api.vms) != 1+ControlPlaneReplicas {
		t.Fatalf("local pre-dispatch rejection state: error=%v deletes=%#v VMs=%#v", deleteErr, api.vmDeletes, api.vms)
	}
	if _, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]; !exists {
		t.Fatalf("local pre-dispatch rejection lost durable intent: %#v", cluster.Status.DeleteAttempts)
	}
	deletion := cluster.Status.DeleteAttempts[deleteAttemptBastion]
	if deletion.Phase != deletePhaseVMIntent || deletion.IssueID != "" {
		t.Fatalf("local pre-dispatch rejection did not reset safely: %#v", deletion)
	}

	api.vmDeleteError = nil
	for observation := 0; observation < 2; observation++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("retry after local pre-dispatch rejection observation %d: %v", observation+1, err)
		}
	}
	if len(api.vms) != ControlPlaneReplicas || cluster.Status.DeleteAttempts[deleteAttemptBastion].Phase != deletePhaseAbsent {
		t.Fatalf("successful retry did not establish one exact transition: VMs=%#v pending=%#v", api.vms, cluster.Status.DeleteAttempts)
	}
}

func TestDestroyVMIntentRevalidatesCanonicalOwnershipBeforeDispatch(t *testing.T) {
	tests := map[string]func(*inspace.VM){
		"billing":     func(vm *inspace.VM) { vm.BillingAccountID = 999 },
		"network":     func(vm *inspace.VM) { vm.NetworkUUID = "aaaaaaaa-2222-4333-8444-555555555555" },
		"description": func(vm *inspace.VM) { vm.Description = "foreign ownership" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			reconcileUntilReady(t, reconciler, cluster)
			bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			firewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
			if err := reconciler.ensureVMDeleteAttempt(context.Background(), cluster, deleteAttemptBastion, deletePurposeDestroy, bastion, firewall.UUID, ""); err != nil {
				t.Fatal(err)
			}
			api.mu.Lock()
			for index := range api.vms {
				if api.vms[index].UUID == bastion.UUID {
					mutate(&api.vms[index])
				}
			}
			api.mu.Unlock()

			if _, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err == nil {
				t.Fatal("drifted durable VM intent became deletion authority")
			}
			if len(api.vmDeletes) != 0 || cluster.Status.DeleteAttempts[deleteAttemptBastion].Phase != deletePhaseVMIssued {
				t.Fatalf("drifted durable VM intent mutated cloud state or lost its durable issue lock: deletes=%#v receipt=%#v", api.vmDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion])
			}
		})
	}
}

func TestDestroyPendingDeletionNeverAllowsForeignFirewallAssignment(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)

	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	nodeFirewall := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
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

func TestDestroyDurablePendingDeletionHasNoExpiry(t *testing.T) {
	api := newFakeAPI()
	api.retainFirewallAssignmentsOnDelete = true
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	destroyUntilFirstVMDelete(t, reconciler, api, cluster)

	reconciler = testReconciler(api)
	var waiting DestroyResult
	var err error
	for i := 0; i < 10; i++ {
		waiting, err = reconciler.Destroy(context.Background(), cluster)
		if err != nil || strings.Contains(waiting.Message, "waiting for firewall assignments to clear") {
			break
		}
	}
	if err != nil || !strings.Contains(waiting.Message, "waiting for firewall assignments to clear") {
		t.Fatalf("durable pending assignment did not survive restart: result=%#v error=%v", waiting, err)
	}
}

func countStrings(items []string, target string) int {
	count := 0
	for _, item := range items {
		if item == target {
			count++
		}
	}
	return count
}

func countEvents(items []string, target string) int {
	return countStrings(items, target)
}

func destroyUntilFirstVMDelete(t *testing.T, reconciler *Reconciler, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	for i := 0; i < 30; i++ {
		if _, err := reconciler.Destroy(context.Background(), cluster); err != nil {
			t.Fatalf("destroy before first VM deletion %d: %v", i, err)
		}
		attempt, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]
		if len(api.vmDeletes) == 1 && exists && attempt.Phase == deletePhaseAbsent {
			return
		}
	}
	t.Fatalf("expected one corroborated owned VM deletion, got deletes=%#v receipt=%#v", api.vmDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion])
}

func TestDestroyRejectsAssignmentAndPolicyDriftBeforeMutation(t *testing.T) {
	for _, mutate := range []func(*fakeAPI, *v1alpha1.InSpaceCluster){
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			for i := range api.floatingIPs {
				if api.floatingIPs[i].Name == resourceNames.BastionFloatingIP {
					api.floatingIPs[i].Enabled = false
				}
			}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			for i := range api.floatingIPs {
				if api.floatingIPs[i].Name == resourceNames.BastionFloatingIP {
					api.floatingIPs[i].AssignedTo = "99999999-1111-4222-8333-bbbbbbbbbbbb"
				}
			}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			fw := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
			fw.Rules[0].EndpointSpec = []string{"0.0.0.0/0"}
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			fw := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
			fw.Description = "not-owned"
		},
		func(api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
			resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
			fw := mustFirewall(t, api.firewalls, resourceNames.NodeFirewall)
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
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
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
			if candidate.EffectiveName() == resourceNames.BastionFirewall {
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
	convertBootstrapResourceNamesToLegacy(t, api, cluster)
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	bastionHash := bastion.Description[strings.LastIndex(bastion.Description, "=")+1:]
	bastion.Name = legacyBastionName(owner)
	bastion.Hostname = bastion.Name
	bastion.Description = fmt.Sprintf("inspace-rke2-bastion/v1 owner=%s spec=%s", owner, bastionHash)
}

func convertBootstrapResourceNamesToLegacy(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	current := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	legacy := legacyBootstrapResourceNames(ownerKey(cluster))
	floatingIPNames := map[string]string{current.BastionFloatingIP: legacy.BastionFloatingIP}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		floatingIPNames[current.ControlPlaneFIP[slot]] = legacy.ControlPlaneFIP[slot]
	}
	for i := range api.floatingIPs {
		if name, ok := floatingIPNames[api.floatingIPs[i].Name]; ok {
			api.floatingIPs[i].Name = name
		}
	}
	firewallNames := map[string]string{
		current.NodeFirewall:    legacy.NodeFirewall,
		current.BastionFirewall: legacy.BastionFirewall,
	}
	for i := range api.firewalls {
		if name, ok := firewallNames[api.firewalls[i].EffectiveName()]; ok {
			api.firewalls[i].Name = name
			api.firewalls[i].DisplayName = name
		}
	}
}

func testReconciler(api *fakeAPI) *Reconciler {
	return &Reconciler{
		API: api, SSHUsername: "inspacee2e", SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest unit@test",
		StatusCompareAndSwap: func(_ context.Context, _ *v1alpha1.InSpaceCluster, _ v1alpha1.InSpaceClusterStatus, desired v1alpha1.InSpaceClusterStatus) (v1alpha1.InSpaceClusterStatus, error) {
			return desired, nil
		},
		ManagementCIDR: "198.51.100.24/32", ManagementTCPPorts: []int{22},
		protectionAuditTimeout: 100 * time.Millisecond, protectionRequestTimeout: 25 * time.Millisecond,
		protectionReadbackMinInterval: time.Millisecond, protectionReadbackMaxInterval: 5 * time.Millisecond,
		createdVMRecoveryTimeout: 100 * time.Millisecond, createdVMFloatingIPCleanupTimeout: 25 * time.Millisecond,
		createdVMDeleteTimeout: 25 * time.Millisecond, vmAbsenceObservationMinInterval: time.Nanosecond,
	}
}

func testCluster() *v1alpha1.InSpaceCluster {
	return &v1alpha1.InSpaceCluster{
		APIVersion: v1alpha1.APIVersion, Kind: v1alpha1.Kind,
		Metadata: v1alpha1.ObjectMeta{Name: "unit", Namespace: "default"},
		Spec: v1alpha1.InSpaceClusterSpec{
			Location: "bkk01", BillingAccountID: 42,
			BootstrapCache:       v1alpha1.BootstrapCacheSpec{DirectDownload: true},
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
	if len(files) != 12 {
		t.Fatalf("write_files=%d, want 12", len(files))
	}
	script := files["/usr/local/sbin/inspace-bootstrap-rke2"]
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid shell: %v: %s", err, output)
	}
	for _, required := range []string{
		`node_name='` + expectedNodeName + `'`, `printf '127.0.1.1\t%s\n' "$node_name" >>/etc/hosts`, `getent hosts "$node_name" | grep -Eq '^127\.0\.1\.1[[:space:]]'`,
		`hostname_attempt=$((hostname_attempt + 1))`, `[ "$hostname_attempt" -ge 30 ]`, `generated hostname did not resolve to 127.0.1.1`,
		`ip -o -4 addr show to "$vpc_subnet" scope global`, "PRIVATE_IF=", "PRIVATE_IP=", "systemctl list-unit-files --type=service", "systemctl disable --now ufw.service", "disabled|masked", "ufw status",
		"systemctl enable rke2-server.service", "systemctl start --no-block rke2-server.service", `"$attempt" -ge 180`,
		"--max-time 300 --retry 3 --retry-all-errors", "/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml",
		"/var/lib/rancher/rke2/server/manifests/inspace-private-load-balancer.yaml",
		"swapoff -a", `sed -Ei '/^[[:space:]]*#/!`, "/etc/apt/mirrors/inspace-ubuntu.list", "http://mirror1.totbb.net/ubuntu/", "https://mirror.kku.ac.th/ubuntu/",
		"systemctl disable --now systemd-resolved.service", "nameserver 8.8.8.8", "nameserver 8.8.4.4",
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
	assertAutomaticAPTUpdatesDisabled(t, files, script)
	assertUbuntuRepositoryAndResolver(t, files, script)
	for before, after := range map[string]string{
		"swapoff -a": "apt-get -o Acquire::Retries=3",
		"systemctl mask systemd-resolved.service":      "apt-get -o Acquire::Retries=3",
		"apt-get -o Acquire::Retries=3":                "apt-get -o DPkg::Lock::Timeout=30 upgrade -y",
		"apt-get -o DPkg::Lock::Timeout=30 upgrade -y": "install -y --no-install-recommends",
		"install -y --no-install-recommends":           "/etc/apt/apt.conf.d/99-inspace-disable-periodic",
		"test \"$apt_unit_state\" = masked":            "sysctl --system",
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
	for _, required := range []string{kubeVIPImage, "vip_interface", "__PRIVATE_IFACE__", "vip_arp", "vip_arpRate", "cp_enable", "svc_enable", `value: "false"`, "vip_leaderelection", "vip_leaseduration", "vip_renewdeadline", "vip_retryperiod", "inspace-control-plane-vip", "hostNetwork: true", "type: File", "app.kubernetes.io/component: control-plane-vip"} {
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
	for _, required := range []string{"l2announcements:\n      enabled: true", "defaultLBServiceIPAM: none", "k8sClientRateLimit:\n      qps: 10\n      burst: 20"} {
		if !strings.Contains(ciliumConfig, required) {
			t.Errorf("RKE2 Cilium config lacks %q", required)
		}
	}
	if strings.Contains(ciliumConfig, "nodeIPAM:") {
		t.Error("RKE2 Cilium config unexpectedly enables the retired Node IPAM controller")
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
	if strings.Contains(privateLoadBalancer, "interfaces:") || strings.Contains(privateLoadBalancer, "CiliumNodeConfig") {
		t.Errorf("Cilium private load-balancer contract enabled a forbidden interface path: %s\n%s", privateLoadBalancer, ciliumConfig)
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
	plainEnvs := make(map[string][]corev1.EnvVar)
	for _, env := range container.Env {
		if env.Name == "k8s_config_file" {
			t.Fatalf("generated kube-vip Pod sets ignored k8s_config_file environment variable to %q", env.Value)
		}
		if env.Name == "vip_nodename" {
			vipNodeNameEnvs = append(vipNodeNameEnvs, env)
		}
		plainEnvs[env.Name] = append(plainEnvs[env.Name], env)
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
	for name, value := range map[string]string{
		"vip_arpRate":       "500",
		"vip_leaseduration": "5",
		"vip_renewdeadline": "3",
		"vip_retryperiod":   "1",
	} {
		want := corev1.EnvVar{Name: name, Value: value}
		if len(plainEnvs[name]) != 1 || !reflect.DeepEqual(plainEnvs[name][0], want) {
			t.Fatalf("generated kube-vip %s env=%#v, want exactly %#v", name, plainEnvs[name], want)
		}
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
		Hostname         string   `json:"hostname"`
		PreserveHostname bool     `json:"preserve_hostname"`
		RunCmd           []string `json:"runcmd"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Hostname != expectedHostname || payload.PreserveHostname {
		t.Fatalf("bastion cloud-init hostname contract=%#v, want hostname %q and preserve_hostname=false", payload, expectedHostname)
	}
	if !reflect.DeepEqual(payload.RunCmd, []string{"/usr/local/sbin/inspace-bootstrap-bastion"}) {
		t.Fatalf("bastion cloud-init runcmd=%#v", payload.RunCmd)
	}
	files := decodeWriteFiles(t, raw)
	if len(files) != 5 {
		t.Fatalf("bastion write_files=%d, want 5", len(files))
	}
	script := files["/usr/local/sbin/inspace-bootstrap-bastion"]
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid bastion bootstrap shell: %v: %s", err, output)
	}
	for _, required := range []string{
		`node_name='` + expectedHostname + `'`, `printf '127.0.1.1\t%s\n' "$node_name" >>/etc/hosts`, `getent hosts "$node_name" | grep -Eq '^127\.0\.1\.1[[:space:]]'`,
		`hostname_attempt=$((hostname_attempt + 1))`, `[ "$hostname_attempt" -ge 30 ]`, `generated hostname did not resolve to 127.0.1.1`,
		"/etc/apt/mirrors/inspace-ubuntu.list", "http://mirror1.totbb.net/ubuntu/", "https://mirror.kku.ac.th/ubuntu/",
		"systemctl disable --now systemd-resolved.service", "nameserver 8.8.8.8", "nameserver 8.8.4.4",
		"apt-get -o Acquire::Retries=3", "NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y",
		"package_deadline=$(( $(date +%s) + 600 ))", "timeout --kill-after=30s",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("bastion bootstrap script lacks %q", required)
		}
	}
	assertAutomaticAPTUpdatesDisabled(t, files, script)
	assertUbuntuRepositoryAndResolver(t, files, script)
	for _, required := range []string{"ufw --force disable", "systemctl list-unit-files --type=service", "systemctl disable --now ufw.service", "disabled|masked", "ufw status", "systemctl is-active", "systemctl is-enabled"} {
		if !strings.Contains(script, required) {
			t.Errorf("bastion UFW script lacks %q", required)
		}
	}
	if strings.Contains(script, "ufw --force disable || true") || strings.Contains(script, "systemctl disable --now ufw.service >/dev/null 2>&1 || true") || strings.Contains(script, "iptables") || strings.Contains(script, "nft ") {
		t.Errorf("bastion UFW disable is not fail-closed: %s", script)
	}
	for before, after := range map[string]string{
		"systemctl mask systemd-resolved.service":      "apt-get -o Acquire::Retries=3",
		"apt-get -o Acquire::Retries=3":                "apt-get -o DPkg::Lock::Timeout=30 upgrade -y",
		"apt-get -o DPkg::Lock::Timeout=30 upgrade -y": "/etc/apt/apt.conf.d/99-inspace-disable-periodic",
		"test \"$apt_unit_state\" = masked":            "ufw --force disable",
	} {
		if beforeIndex, afterIndex := strings.Index(script, before), strings.Index(script, after); beforeIndex < 0 || afterIndex <= beforeIndex {
			t.Errorf("bastion bootstrap order %q -> %q is not enforced", before, after)
		}
	}
}

func assertUbuntuRepositoryAndResolver(t *testing.T, files map[string]string, script string) {
	t.Helper()
	if got := files["/var/lib/inspace/ubuntu-mirrors.list"]; got != ubuntuAPTMirrorListConfig {
		t.Errorf("Ubuntu mirror list mismatch:\n%s", got)
	}
	if got := files["/var/lib/inspace/ubuntu.sources"]; got != ubuntuAPTSourcesConfig {
		t.Errorf("Ubuntu sources mismatch:\n%s", got)
	}
	if got := files["/var/lib/inspace/static-resolv.conf"]; got != staticGoogleResolverConfig {
		t.Errorf("static resolver mismatch:\n%s", got)
	}
	for _, required := range []string{
		"install -m 0644 /var/lib/inspace/ubuntu-mirrors.list /etc/apt/mirrors/inspace-ubuntu.list",
		"install -m 0644 /var/lib/inspace/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources",
		"install -m 0644 /var/lib/inspace/static-resolv.conf /etc/resolv.conf",
		"systemctl disable --now systemd-resolved.service", "systemctl mask systemd-resolved.service",
		"test ! -L /etc/resolv.conf", "nameserver 8.8.8.8", "nameserver 8.8.4.4",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Ubuntu repository/resolver setup lacks %q", required)
		}
	}
}

func assertAutomaticAPTUpdatesDisabled(t *testing.T, files map[string]string, script string) {
	t.Helper()
	if got := files["/var/lib/inspace/apt-periodic-disabled"]; got != automaticAPTUpdatesDisabledConfig {
		t.Errorf("automatic APT update config mismatch:\n%s", got)
	}
	for _, required := range []string{
		"install -D -m 0644 /var/lib/inspace/apt-periodic-disabled /etc/apt/apt.conf.d/99-inspace-disable-periodic",
		"cmp -s /var/lib/inspace/apt-periodic-disabled /etc/apt/apt.conf.d/99-inspace-disable-periodic",
		"systemctl mask --now \"$apt_unit\"", "systemctl is-active --quiet \"$apt_unit\"",
		"systemctl is-enabled \"$apt_unit\"", "test \"$apt_unit_state\" = masked",
		"apt-daily.service", "apt-daily-upgrade.service", "apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("automatic APT update shutdown lacks %q", required)
		}
	}
	for before, after := range map[string]string{
		"apt-get -o DPkg::Lock::Timeout=30 upgrade -y": "/etc/apt/apt.conf.d/99-inspace-disable-periodic",
		"systemctl mask --now \"$apt_unit\"":           "systemctl is-active --quiet \"$apt_unit\"",
		"systemctl is-active --quiet \"$apt_unit\"":    "systemctl is-enabled \"$apt_unit\"",
	} {
		if beforeIndex, afterIndex := strings.Index(script, before), strings.Index(script, after); beforeIndex < 0 || afterIndex <= beforeIndex {
			t.Errorf("automatic APT update shutdown order %q -> %q is not enforced", before, after)
		}
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

func seedOwnedMutationVMs(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster, uuids ...string) {
	t.Helper()
	api.mu.Lock()
	defer api.mu.Unlock()
	owner := ownerKey(cluster)
	for index, uuid := range uuids {
		if !vmUUIDPattern.MatchString(uuid) {
			t.Fatalf("invalid seeded VM UUID %q", uuid)
		}
		name := currentBastionName(cluster.Metadata.Name)
		description := fmt.Sprintf("inspace-rke2-bastion/v6 owner=%s spec=%s", owner, strings.Repeat("0", sha256.Size*2))
		if index > 0 {
			slot := index - 1
			name = controlPlaneName(cluster.Metadata.Name, slot)
			description = fmt.Sprintf("inspace-rke2-cp/v8 owner=%s slot=%d spec=%s", owner, slot, strings.Repeat("0", sha256.Size*2))
		}
		vm := inspace.VM{
			UUID: uuid, Name: name, Hostname: name, Description: description,
			BillingAccountID: cluster.Spec.BillingAccountID, NetworkUUID: cluster.Spec.Network.UUID,
			PrivateIPv4: fmt.Sprintf("10.20.30.%d", 20+index),
		}
		api.vms = append(api.vms, vm)
		api.network.VMUUIDs = append(api.network.VMUUIDs, uuid)
	}
}

type fakeAPI struct {
	mu                      sync.Mutex
	network                 inspace.Network
	getNetworkError         error
	hostPools               []inspace.HostPool
	listHostPoolsError      error
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

	failFirewallAssignmentForName        string
	firewallAssignmentError              error
	firewallAssignmentErrorCommits       bool
	firewallAssignmentCalls              int
	firewallListErrorAfterAssignment     error
	firewallListErrorAfterAssignmentCall int
	firewallAssignmentNilWithoutCommit   bool
	firewallAssignmentReadbackDelay      int
	firewallAssignmentReadbackRemaining  int
	firewallAssignmentDuplicate          bool
	firewallAssignmentWrongFirewall      bool
	firewallAssignmentWrongType          bool
	firewallAssignmentPolicyDrift        bool
	failVMCreateNames                    map[string]error
	commitVMCreateErrors                 map[string]bool
	privateIPByName                      map[string]string
	mutateStoredVM                       func(inspace.CreateVMRequest, *inspace.VM)
	mutateCreateVMResponse               func(inspace.CreateVMRequest, *inspace.VM)
	mutateUpdateFloatingIPResponse       func(*inspace.FloatingIP)
	mutateCreateFirewallResponse         func(inspace.CreateFirewallRequest, *inspace.Firewall)
	firewallCreateError                  error
	firewallCreateErrorCommits           bool
	firewallListError                    error
	firewallListErrorAfterCreate         error
	firewallListReadbackRemaining        int
	mutateGetVMResponse                  func(*inspace.VM)
	getVMErrorByUUID                     map[string]error
	nilGetVMUUID                         string
	floatingIPUpdateError                error
	floatingIPUpdateErrorCommits         bool
	floatingIPUpdateCalls                int
	floatingIPListError                  error
	floatingIPListErrorAfterUpdate       error
	floatingIPListErrorAfterUnassign     error
	floatingIPListErrorAfterDelete       error
	floatingIPUnassignError              error
	floatingIPUnassignErrorCommits       bool
	floatingIPUnassignCalls              int
	floatingIPDeleteError                error
	floatingIPDeleteErrorCommits         bool
	floatingIPReadbackDelay              int
	floatingIPReadbackRemaining          int
	floatingIPAfterFirewallCreate        *inspace.FloatingIP
	blockFloatingIPCleanupAfterCreate    bool
	floatingIPCleanupBlocked             bool
	omitFirewallDescriptions             bool
	sparseVMListResponses                bool
	vmListReadbackDelay                  int
	vmListReadbackRemaining              int
	vmListErrorAfterCreate               error
	sparseFirewallCreateResponses        bool
	retainFirewallAssignmentsOnDelete    bool
	vmDeleteError                        error
	vmDeleteErrorCommits                 bool
	retainVMInventoryOnDelete            bool
	vmDeleteHook                         func()
	firewallDeleteError                  error
	firewallDeleteErrorCommits           bool
	firewallListErrorAfterDelete         error
	cancelAfterVMCreate                  func()
	requireLiveSafetyContext             bool
	requireProtectionBeforeGetVM         bool
	getVMBeforeProtectionCalls           int
}

// postAssignmentReadBarrierAPI pauses the first ListFirewalls call after an
// assignment POST has returned. It exposes the boundary where the per-firewall
// gate must remain held until authoritative commit readback completes.
type postAssignmentReadBarrierAPI struct {
	*fakeAPI
	mu                 sync.Mutex
	assignmentReturned bool
	readbackBlocked    bool
	readbackStarted    chan struct{}
	releaseReadback    chan struct{}
}

func (f *postAssignmentReadBarrierAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	err := f.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
	f.mu.Lock()
	f.assignmentReturned = true
	f.mu.Unlock()
	return err
}

func (f *postAssignmentReadBarrierAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	f.mu.Lock()
	block := f.assignmentReturned && !f.readbackBlocked
	if block {
		f.readbackBlocked = true
	}
	f.mu.Unlock()
	if block {
		close(f.readbackStarted)
		select {
		case <-f.releaseReadback:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.fakeAPI.ListFirewalls(ctx, location)
}

// parallelFirewallAssignmentAPI holds each assignment before dispatch so a
// test can prove different per-firewall keys enter the cloud call together.
type parallelFirewallAssignmentAPI struct {
	*fakeAPI
	started chan string
	release chan struct{}
}

func (f *parallelFirewallAssignmentAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	select {
	case f.started <- firewallUUID:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-f.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return f.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

// issueBarrierStatusStore models two controllers that read the same durable
// status version and then race their firewall-assignment issue transitions.
// The compare-and-swap itself is the only serialization shared across them.
type issueBarrierStatusStore struct {
	mu      sync.Mutex
	status  v1alpha1.InSpaceClusterStatus
	started chan struct{}
	release chan struct{}
}

func (s *issueBarrierStatusStore) compareAndSwap(
	ctx context.Context,
	_ *v1alpha1.InSpaceCluster,
	expected v1alpha1.InSpaceClusterStatus,
	desired v1alpha1.InSpaceClusterStatus,
) (v1alpha1.InSpaceClusterStatus, error) {
	if countIssuedFirewallAssignments(desired) > countIssuedFirewallAssignments(expected) {
		select {
		case s.started <- struct{}{}:
		case <-ctx.Done():
			return v1alpha1.InSpaceClusterStatus{}, ctx.Err()
		}
		select {
		case <-s.release:
		case <-ctx.Done():
			return v1alpha1.InSpaceClusterStatus{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.status, expected) {
		return cloneClusterStatus(s.status), errors.New("injected status resourceVersion conflict")
	}
	s.status = cloneClusterStatus(desired)
	return cloneClusterStatus(s.status), nil
}

func (s *issueBarrierStatusStore) snapshot() v1alpha1.InSpaceClusterStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneClusterStatus(s.status)
}

func countIssuedFirewallAssignments(status v1alpha1.InSpaceClusterStatus) int {
	count := 0
	for _, attempt := range status.CreateAttempts {
		if attempt.ResourceKind == createAttemptKindFirewallAssignment && attempt.Phase == createAttemptPhaseIssued {
			count++
		}
	}
	return count
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		network: inspace.Network{UUID: "11111111-2222-4333-8444-555555555555", Name: "private", Type: "private", Subnet: "10.20.30.0/24"},
		hostPools: []inspace.HostPool{{
			UUID: "aac7dd66-f390-4edd-80c0-dd7cae49bd99", Name: "AMD EPYC", IsVisible: true,
		}},
	}
}

func (f *fakeAPI) GetNetwork(context.Context, string, string) (*inspace.Network, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getNetworkError != nil {
		return nil, f.getNetworkError
	}
	copy := f.network
	copy.VMUUIDs = append([]string(nil), f.network.VMUUIDs...)
	return &copy, nil
}
func (f *fakeAPI) ListHostPools(context.Context, string) ([]inspace.HostPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listHostPoolsError != nil {
		return nil, f.listHostPoolsError
	}
	return append([]inspace.HostPool(nil), f.hostPools...), nil
}
func (f *fakeAPI) ListLoadBalancers(context.Context, string) ([]inspace.LoadBalancer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inspace.LoadBalancer(nil), f.loadBalancers...), nil
}
func (f *fakeAPI) ListVMs(context.Context, string) ([]inspace.VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vmListErrorAfterCreate != nil && len(f.vmCreates) != 0 {
		return nil, f.vmListErrorAfterCreate
	}
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
	mutateStored := f.mutateStoredVM
	mutateResponse := f.mutateCreateVMResponse
	injected := f.failVMCreateNames[request.Name]
	commitInjected := f.commitVMCreateErrors[request.Name]
	f.mu.Unlock()
	if injected != nil && !commitInjected {
		return nil, injected
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
	if !f.retainVMInventoryOnDelete {
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
	if f.firewallListError != nil {
		return nil, f.firewallListError
	}
	if f.firewallListErrorAfterCreate != nil && len(f.firewallCreates) != 0 {
		return nil, f.firewallListErrorAfterCreate
	}
	if f.firewallListErrorAfterAssignment != nil && f.firewallListErrorAfterAssignmentCall > 0 && f.firewallAssignmentCalls >= f.firewallListErrorAfterAssignmentCall {
		return nil, f.firewallListErrorAfterAssignment
	}
	if f.firewallListErrorAfterDelete != nil && len(f.firewallDeletes) != 0 {
		return nil, f.firewallListErrorAfterDelete
	}
	if f.firewallListReadbackRemaining > 0 {
		f.firewallListReadbackRemaining--
		return nil, nil
	}
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
	if f.firewallCreateError != nil && !f.firewallCreateErrorCommits {
		return nil, f.firewallCreateError
	}
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
	return &response, f.firewallCreateError
}
func (f *fakeAPI) AssignFirewallToVM(ctx context.Context, _ string, firewallUUID, vmUUID string) error {
	if f.requireLiveSafetyContext && ctx.Err() != nil {
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.firewallAssignmentCalls++
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
		if f.firewallAssignmentWrongType {
			f.firewalls[i].ResourcesAssigned[len(f.firewalls[i].ResourcesAssigned)-1].ResourceType = "disk"
		}
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
	if f.firewallDeleteError != nil && !f.firewallDeleteErrorCommits {
		return f.firewallDeleteError
	}
	for i := range f.firewalls {
		if f.firewalls[i].UUID == uuid {
			f.firewalls = append(f.firewalls[:i], f.firewalls[i+1:]...)
			break
		}
	}
	return f.firewallDeleteError
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
	if f.floatingIPListError != nil {
		return nil, f.floatingIPListError
	}
	if f.floatingIPListErrorAfterUpdate != nil && f.floatingIPUpdateCalls != 0 {
		return nil, f.floatingIPListErrorAfterUpdate
	}
	if f.floatingIPListErrorAfterUnassign != nil && f.floatingIPUnassignCalls != 0 {
		return nil, f.floatingIPListErrorAfterUnassign
	}
	if f.floatingIPListErrorAfterDelete != nil && len(f.floatingIPDeletes) != 0 {
		return nil, f.floatingIPListErrorAfterDelete
	}
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
	f.floatingIPUpdateCalls++
	for i := range f.floatingIPs {
		if f.floatingIPs[i].Address != address {
			continue
		}
		if f.floatingIPUpdateError != nil && !f.floatingIPUpdateErrorCommits {
			return nil, f.floatingIPUpdateError
		}
		f.floatingIPs[i].Name = request.Name
		f.floatingIPs[i].BillingAccountID = request.BillingAccountID
		f.floatingIPReadbackRemaining = f.floatingIPReadbackDelay
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
	f.floatingIPUnassignCalls++
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
