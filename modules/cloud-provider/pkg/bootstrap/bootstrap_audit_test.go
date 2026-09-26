package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const auditTestToken = "unit-test-secret-token"

func TestMalformedCreateRollbackKeepsVMUntilAutoFloatingIPIsIdentified(t *testing.T) {
	api := newFakeAPI()
	api.floatingIPReadbackDelay = 1000
	api.mutateStoredVM = func(_ inspace.CreateVMRequest, vm *inspace.VM) { vm.VCPU++ }
	cluster := testCluster()
	ctx := context.Background()

	if _, err := testReconciler(api).Reconcile(ctx, cluster, auditTestToken); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("malformed create with an invisible auto FIP = %v, want durable pending rollback", err)
	}
	api.mu.Lock()
	api.mutateStoredVM = nil
	if len(api.floatingIPs) != 1 || len(api.vmCreates) != 1 {
		api.mu.Unlock()
		t.Fatalf("fixture did not create exactly one VM and auto FIP: creates=%d FIPs=%#v", len(api.vmCreates), api.floatingIPs)
	}
	autoAddress := api.floatingIPs[0].Address
	api.mu.Unlock()
	malformedVM := cluster.Status.CreateAttempts[createAttemptBastionVM].ResourceUUID
	if !vmUUIDPattern.MatchString(malformedVM) {
		t.Fatalf("malformed create was not durably anchored: %#v", cluster.Status.CreateAttempts)
	}

	// While the address stays invisible, no pass (Reconcile or Destroy, across
	// restarts) may delete the VM: that would strand a nameless, unassigned IP.
	for pass := 0; pass < 3; pass++ {
		cluster = restartClusterFromJSON(t, cluster)
		if pass > 0 {
			if _, err := testReconciler(api).Reconcile(ctx, cluster, auditTestToken); !errors.Is(err, ErrCreateAttemptPending) {
				t.Fatalf("pass %d reconcile = %v, want pending rollback", pass, err)
			}
			if result, err := testReconciler(api).Destroy(ctx, cluster); !errors.Is(err, ErrCreateAttemptPending) || result.Done {
				t.Fatalf("pass %d destroy = %#v, %v, want pending rollback", pass, result, err)
			}
		}
		attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]
		if len(api.vmDeletes) != 0 || len(api.vms) != 1 || attempt.Phase != deletePhaseRollbackFIPDiscovery || attempt.FloatingIPAddress != "" {
			t.Fatalf("pass %d deleted the VM before its auto FIP was identified: deletes=%#v attempt=%#v", pass, api.vmDeletes, attempt)
		}
	}

	api.mu.Lock()
	api.floatingIPReadbackRemaining = 0
	api.floatingIPReadbackDelay = 0
	api.mu.Unlock()
	converged := false
	for pass := 0; pass < 10 && !converged; pass++ {
		cluster = restartClusterFromJSON(t, cluster)
		_, err := testReconciler(api).Reconcile(ctx, cluster, auditTestToken)
		if err != nil && !errors.Is(err, ErrCreateAttemptPending) && !errors.Is(err, ErrRetryableAmbiguousVMDelete) {
			t.Fatalf("rollback pass %d: %v", pass, err)
		}
		_, rollbackActive := cluster.Status.DeleteAttempts[deleteAttemptBastion]
		converged = !rollbackActive && len(api.vmDeletes) == 1
	}
	if !converged {
		t.Fatalf("rollback never converged after the auto FIP became visible: deletes=%#v attempts=%#v", api.vmDeletes, cluster.Status.DeleteAttempts)
	}
	if api.vmDeletes[0] != malformedVM || len(api.floatingIPDeletes) != 1 || api.floatingIPDeletes[0] != autoAddress {
		t.Fatalf("rollback did not delete exactly the malformed VM and its auto FIP: VM deletes=%#v FIP deletes=%#v", api.vmDeletes, api.floatingIPDeletes)
	}
	// The fake reuses freed addresses, so a leak is a nameless address that is
	// unassigned or still bound to the deleted VM, not the address itself.
	for _, item := range api.floatingIPs {
		if item.Name == "" && (item.AssignedTo == "" || item.AssignedTo == malformedVM) {
			t.Fatalf("rollback leaked the malformed VM's auto FIP: %#v", api.floatingIPs)
		}
	}
}

func TestDestroyKeepsVMUntilItsAutoFloatingIPIsObserved(t *testing.T) {
	api, cluster := clusterWithInvisibleBastionFloatingIP(t)
	ctx := context.Background()
	destroyer := testReconciler(api)
	destroyer.destroyFloatingIPObservationWait = time.Hour
	for pass := 0; pass < 4; pass++ {
		result, err := destroyer.Destroy(ctx, cluster)
		if err != nil {
			t.Fatalf("destroy pass %d: %v", pass, err)
		}
		if result.Done || len(api.vmDeletes) != 0 || !strings.Contains(result.Message, "auto floating IP") {
			t.Fatalf("destroy pass %d deleted a VM whose auto FIP was never observed: result=%#v deletes=%#v", pass, result, api.vmDeletes)
		}
	}

	api.mu.Lock()
	api.floatingIPReadbackRemaining = 0
	api.floatingIPReadbackDelay = 0
	api.mu.Unlock()
	destroyUntilDone(t, destroyer, cluster)
	if len(api.vms) != 0 || len(api.floatingIPs) != 0 || len(api.floatingIPDeletes) != 1 || len(api.firewalls) != 0 {
		t.Fatalf("destroy leaked resources after the auto FIP appeared: VMs=%#v FIPs=%#v FIP deletes=%#v firewalls=%#v",
			api.vms, api.floatingIPs, api.floatingIPDeletes, api.firewalls)
	}
}

func TestDestroyBoundsTheWaitForAnExternallyReleasedFloatingIP(t *testing.T) {
	api, cluster := clusterWithInvisibleBastionFloatingIP(t)
	api.mu.Lock()
	api.floatingIPs = nil
	api.floatingIPReadbackRemaining = 0
	api.floatingIPReadbackDelay = 0
	api.mu.Unlock()
	destroyer := testReconciler(api)
	destroyer.destroyFloatingIPObservationWait = time.Nanosecond
	result, err := destroyer.Destroy(context.Background(), cluster)
	if err != nil || result.Done || len(api.vmDeletes) != 0 || !strings.Contains(result.Message, "auto floating IP") {
		t.Fatalf("first destroy pass did not start the bounded wait: result=%#v err=%v deletes=%#v", result, err, api.vmDeletes)
	}
	time.Sleep(time.Millisecond)
	destroyUntilDone(t, destroyer, cluster)
	if len(api.vms) != 0 || len(api.vmDeletes) != 1 || len(api.firewalls) != 0 {
		t.Fatalf("bounded wait did not let teardown finish: VMs=%#v deletes=%#v firewalls=%#v", api.vms, api.vmDeletes, api.firewalls)
	}
}

// clusterWithInvisibleBastionFloatingIP reconciles until the bastion exists and
// is firewalled while its auto floating IP is not yet listed ("waiting for the
// bastion auto floating IP assignment").
func clusterWithInvisibleBastionFloatingIP(t *testing.T) (*fakeAPI, *v1alpha1.InSpaceCluster) {
	t.Helper()
	api := newFakeAPI()
	api.floatingIPReadbackDelay = 1000
	cluster := testCluster()
	reconciler := testReconciler(api)
	for pass := 0; pass < 5; pass++ {
		result, err := reconciler.Reconcile(context.Background(), cluster, auditTestToken)
		if err != nil {
			t.Fatalf("reconcile %d: %v", pass, err)
		}
		if strings.Contains(result.Message, "auto floating IP assignment") {
			if len(api.vms) != 1 || len(api.floatingIPs) != 1 || api.floatingIPs[0].Name != "" || api.floatingIPs[0].AssignedTo != api.vms[0].UUID {
				t.Fatalf("unexpected fixture: VMs=%#v FIPs=%#v", api.vms, api.floatingIPs)
			}
			return api, cluster
		}
	}
	t.Fatal("reconcile never waited for the bastion auto floating IP")
	return nil, nil
}

func addKarpenterWorker(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster, firewallUUID string, mutate func(*inspace.VM, map[string]any)) *inspace.VM {
	t.Helper()
	nodeClaim := "default-abcde"
	name := cluster.Metadata.Name + "-karp-" + nodeClaim
	record := map[string]any{
		"schema": "karpenter.inspace.cloud/v3", "cluster": cluster.Metadata.Name, "nodePool": "default",
		"nodeClaim": nodeClaim, "vmName": name, "keyHash": "0123456789abcdef", "hostClass": "standard",
		"instanceType": "c4-m8", "rootDiskGiB": 60, "specHash": "spec", "bootstrapHash": "bootstrap",
		"firewallUUID": firewallUUID, "networkUUID": cluster.Spec.Network.UUID, "osName": "ubuntu",
		"osVersion": "26.04", "billingAccountID": cluster.Spec.BillingAccountID,
		"floatingIPName": "karpenter-default-abcde-0123456789",
	}
	vm := inspace.VM{
		UUID: "abcdef01-1111-4222-8333-bbbbbbbbbbbb", Name: name, Hostname: name, Status: "running",
		PrivateIPv4: "10.20.30.100", NetworkUUID: cluster.Spec.Network.UUID, BillingAccountID: cluster.Spec.BillingAccountID,
	}
	if mutate != nil {
		mutate(&vm, record)
	}
	description, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	vm.Description = string(description)
	api.mu.Lock()
	defer api.mu.Unlock()
	api.vms = append(api.vms, vm)
	api.network.VMUUIDs = append(api.network.VMUUIDs, vm.UUID)
	for i := range api.firewalls {
		if api.firewalls[i].UUID == firewallUUID {
			api.firewalls[i].ResourcesAssigned = append(api.firewalls[i].ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm.UUID})
			return &api.vms[len(api.vms)-1]
		}
	}
	t.Fatalf("firewall %s not found", firewallUUID)
	return nil
}

func bootstrapFirewallUUIDs(t *testing.T, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) (string, string) {
	t.Helper()
	names := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	nodeUUID, bastionUUID := "", ""
	for _, firewall := range api.firewalls {
		switch firewall.EffectiveName() {
		case names.NodeFirewall:
			nodeUUID = firewall.UUID
		case names.BastionFirewall:
			bastionUUID = firewall.UUID
		}
	}
	if nodeUUID == "" || bastionUUID == "" {
		t.Fatalf("managed firewalls missing: %#v", api.firewalls)
	}
	return nodeUUID, bastionUUID
}

func TestReconcileToleratesThisClustersKarpenterWorkersOnTheNodeFirewall(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	nodeUUID, _ := bootstrapFirewallUUIDs(t, api, cluster)
	addKarpenterWorker(t, api, cluster, nodeUUID, nil)
	eventsBefore := len(api.events)

	result, err := testReconciler(api).Reconcile(context.Background(), cluster, auditTestToken)
	if err != nil || !result.Ready {
		t.Fatalf("re-running bootstrap with a Karpenter worker on the node firewall = %#v, %v; want ready", result, err)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("re-running bootstrap mutated cloud state: %v", api.events[eventsBefore:])
	}
}

func TestReconcileRejectsUnprovenNodeFirewallAssignments(t *testing.T) {
	for _, test := range []struct {
		name    string
		bastion bool
		mutate  func(*inspace.VM, map[string]any)
	}{
		{name: "another cluster's record", mutate: func(_ *inspace.VM, record map[string]any) { record["cluster"] = "other" }},
		{name: "another firewall in the record", mutate: func(_ *inspace.VM, record map[string]any) {
			record["firewallUUID"] = "66666666-1111-4222-8333-444444444444"
		}},
		{name: "non-Karpenter description", mutate: func(_ *inspace.VM, record map[string]any) { record["schema"] = "something/v1" }},
		{name: "name outside the worker prefix", mutate: func(vm *inspace.VM, record map[string]any) {
			vm.Name, vm.Hostname = "unit-cp9", "unit-cp9"
			record["vmName"] = "unit-cp9"
		}},
		{name: "name and node claim disagree", mutate: func(_ *inspace.VM, record map[string]any) { record["nodeClaim"] = "default-zzzzz" }},
		{name: "another billing account", mutate: func(vm *inspace.VM, _ map[string]any) { vm.BillingAccountID = 7 }},
		{name: "worker on the bastion firewall", bastion: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconcileUntilReady(t, testReconciler(api), cluster)
			nodeUUID, bastionUUID := bootstrapFirewallUUIDs(t, api, cluster)
			target := nodeUUID
			if test.bastion {
				target = bastionUUID
			}
			addKarpenterWorker(t, api, cluster, target, func(vm *inspace.VM, record map[string]any) {
				record["firewallUUID"] = nodeUUID
				if test.mutate != nil {
					test.mutate(vm, record)
				}
			})
			eventsBefore := len(api.events)
			_, err := testReconciler(api).Reconcile(context.Background(), cluster, auditTestToken)
			if err == nil || !strings.Contains(err.Error(), "foreign or non-VM assignment") || errors.Is(err, ErrCreateAttemptPending) {
				t.Fatalf("unproven firewall assignment accepted or made retryable: %v", err)
			}
			if len(api.events) != eventsBefore {
				t.Fatalf("unproven assignment led to mutation: %v", api.events[eventsBefore:])
			}
		})
	}
}

func TestDestroyNeverTouchesKarpenterWorkersOnTheNodeFirewall(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconcileUntilReady(t, testReconciler(api), cluster)
	nodeUUID, _ := bootstrapFirewallUUIDs(t, api, cluster)
	worker := addKarpenterWorker(t, api, cluster, nodeUUID, nil)
	workerUUID := worker.UUID
	eventsBefore := len(api.events)

	for pass := 0; pass < 3; pass++ {
		result, err := testReconciler(api).Destroy(context.Background(), cluster)
		if err == nil || result.Done {
			t.Fatalf("destroy with a live worker on the node firewall = %#v, %v; want fail-closed refusal", result, err)
		}
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("destroy mutated cloud state while a worker was attached: %v", api.events[eventsBefore:])
	}
	if !firewallHasVM(firewallByUUID(t, api, nodeUUID), workerUUID) {
		t.Fatal("destroy detached a worker it does not own")
	}
}

func firewallByUUID(t *testing.T, api *fakeAPI, uuid string) *inspace.Firewall {
	t.Helper()
	for i := range api.firewalls {
		if api.firewalls[i].UUID == uuid {
			return &api.firewalls[i]
		}
	}
	t.Fatalf("firewall %s not found", uuid)
	return nil
}

func TestSameNamedClusterInAnotherNamespaceFailsFastBeforeCreate(t *testing.T) {
	api := newFakeAPI()
	other := testCluster()
	other.Metadata.Namespace = "other"
	reconcileUntilReady(t, testReconciler(api), other)
	eventsBefore := len(api.events)

	cluster := testCluster()
	_, err := testReconciler(api).Reconcile(context.Background(), cluster, auditTestToken)
	if err == nil || errors.Is(err, ErrCreateAttemptPending) || errors.Is(err, ErrRetryableAmbiguousVMDelete) {
		t.Fatalf("same-name cluster collision = %v, want an immediate non-retryable error", err)
	}
	if !strings.Contains(err.Error(), "owned by a different InSpaceCluster") {
		t.Fatalf("same-name cluster collision error is unclear: %v", err)
	}
	if len(api.events) != eventsBefore {
		t.Fatalf("same-name cluster collision mutated cloud state: %v", api.events[eventsBefore:])
	}
}
