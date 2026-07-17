package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

func installCreateIssueCASHook(t *testing.T, reconciler *Reconciler, key string, hook func()) *bool {
	t.Helper()
	base := reconciler.StatusCompareAndSwap
	fired := false
	reconciler.StatusCompareAndSwap = func(
		ctx context.Context,
		cluster *v1alpha1.InSpaceCluster,
		expected, desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		persisted, err := base(ctx, cluster, expected, desired)
		if err == nil && !fired && expected.CreateAttempts[key].Phase != createAttemptPhaseIssued &&
			persisted.CreateAttempts[key].Phase == createAttemptPhaseIssued {
			fired = true
			hook()
		}
		return persisted, err
	}
	return &fired
}

func installDeleteIssueCASHook(t *testing.T, reconciler *Reconciler, key, issuedPhase string, hook func()) *bool {
	t.Helper()
	base := reconciler.StatusCompareAndSwap
	fired := false
	reconciler.StatusCompareAndSwap = func(
		ctx context.Context,
		cluster *v1alpha1.InSpaceCluster,
		expected, desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		persisted, err := base(ctx, cluster, expected, desired)
		if err == nil && !fired && expected.DeleteAttempts[key].Phase != issuedPhase &&
			persisted.DeleteAttempts[key].Phase == issuedPhase {
			fired = true
			hook()
		}
		return persisted, err
	}
	return &fired
}

func testVMFromCreateRequest(uuid string, request inspace.CreateVMRequest) inspace.VM {
	return inspace.VM{
		UUID: uuid, Name: request.Name, Hostname: request.Name, Description: request.Description,
		Status: "running", VCPU: request.VCPU, MemoryMiB: request.MemoryMiB,
		OSName: request.OSName, OSVersion: request.OSVersion, DesignatedPoolUUID: request.DesignatedPoolUUID,
		BillingAccountID: request.BillingAccountID, NetworkUUID: request.NetworkUUID, PrivateIPv4: "10.20.30.20",
		Storage: []inspace.VMStorage{{
			UUID: "99999999-1111-4222-8333-bbbbbbbbbbbb", Name: "vda", SizeGiB: request.DiskGiB, Primary: true,
		}},
	}
}

func testManagedBastionFirewall(reconciler *Reconciler, api *fakeAPI, cluster *v1alpha1.InSpaceCluster) inspace.Firewall {
	owner := ownerKey(cluster)
	return inspace.Firewall{
		UUID:             "aaaaaaaa-1111-4222-8333-444444444444",
		DisplayName:      currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFirewall,
		Description:      "Managed RKE2 bastion firewall for " + owner,
		BillingAccountID: cluster.Spec.BillingAccountID,
		Rules: managedBastionFirewallRules(
			reconciler.ManagementCIDR, api.network.Subnet, !cluster.Spec.BootstrapCache.DirectDownload,
		),
	}
}

func TestVMCreatePostCASAdoptsExactConcurrentObjectWithoutPOST(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	desired, err := reconciler.desiredBastionVMRequest(cluster, &api.network, ownerKey(cluster), cacheTLSMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	firewall := testManagedBastionFirewall(reconciler, api, cluster)
	api.firewalls = []inspace.Firewall{firewall}
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionVM, func() {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.vms = append(api.vms, testVMFromCreateRequest(vmUUID, desired))
		api.network.VMUUIDs = append(api.network.VMUUIDs, vmUUID)
	})

	vm, created, err := reconciler.ensureManagedVMCreate(
		context.Background(), cluster, createAttemptBastionVM, &firewall, nil, desired,
		currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP,
		api.network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privateIPv4Range{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !*fired || created || vm == nil || vm.UUID != vmUUID || len(api.vmCreates) != 0 {
		t.Fatalf("post-CAS VM adoption = fired=%t created=%t vm=%#v POSTs=%#v", *fired, created, vm, api.vmCreates)
	}
	if attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]; attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != vmUUID {
		t.Fatalf("post-CAS VM adoption receipt = %#v", attempt)
	}
}

func TestVMCreatePostCASForeignCollisionResetsUndispatchedIssue(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconciler.createdVMRecoveryTimeout = 10 * time.Millisecond
	firewall := testManagedBastionFirewall(reconciler, api, cluster)
	api.firewalls = []inspace.Firewall{firewall}
	desired, err := reconciler.desiredBastionVMRequest(cluster, &api.network, ownerKey(cluster), cacheTLSMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionVM, func() {
		foreign := testVMFromCreateRequest(vmUUID, desired)
		foreign.BillingAccountID = 999
		api.mu.Lock()
		defer api.mu.Unlock()
		api.vms = append(api.vms, foreign)
		api.network.VMUUIDs = append(api.network.VMUUIDs, vmUUID)
	})

	_, _, err = reconciler.ensureManagedVMCreate(
		context.Background(), cluster, createAttemptBastionVM, &firewall, nil, desired,
		currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP,
		api.network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privateIPv4Range{},
	)
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || len(api.vmCreates) != 0 {
		t.Fatalf("foreign post-CAS VM collision = fired=%t error=%v POSTs=%#v", *fired, err, api.vmCreates)
	}
	if attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("foreign post-CAS VM collision did not reset undispatched issue: %#v", attempt)
	}

	cluster = restartClusterFromJSON(t, cluster)
	restarted := testReconciler(api)
	restarted.createdVMRecoveryTimeout = 10 * time.Millisecond
	_, _, _ = restarted.ensureManagedVMCreate(
		context.Background(), cluster, createAttemptBastionVM, &firewall, nil, desired,
		currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP,
		api.network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privateIPv4Range{},
	)
	if len(api.vmCreates) != 0 || cluster.Status.CreateAttempts[createAttemptBastionVM].Phase != createAttemptPhaseIntent {
		t.Fatalf("restart replayed foreign VM collision: POSTs=%#v receipt=%#v", api.vmCreates, cluster.Status.CreateAttempts[createAttemptBastionVM])
	}
}

func TestVMCreatePostCASDeletedTombstoneResetsUndispatchedIssue(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	desired, err := reconciler.desiredBastionVMRequest(cluster, &api.network, ownerKey(cluster), cacheTLSMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	firewall := testManagedBastionFirewall(reconciler, api, cluster)
	api.firewalls = []inspace.Firewall{firewall}
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionVM, func() {
		tombstone := testVMFromCreateRequest(vmUUID, desired)
		tombstone.Status = "Deleted"
		api.mu.Lock()
		defer api.mu.Unlock()
		api.vms = append(api.vms, tombstone)
		api.network.VMUUIDs = append(api.network.VMUUIDs, vmUUID)
	})

	_, _, err = reconciler.ensureManagedVMCreate(
		context.Background(), cluster, createAttemptBastionVM, &firewall, nil, desired,
		currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP,
		api.network.Subnet, cluster.Spec.Endpoint.VirtualIPv4, privateIPv4Range{},
	)
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || len(api.vmCreates) != 0 {
		t.Fatalf("deleted post-CAS VM collision = fired=%t error=%v POSTs=%#v", *fired, err, api.vmCreates)
	}
	if attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("deleted post-CAS VM collision did not reset undispatched issue: %#v", attempt)
	}
}

func TestVMCreatePostCASRevalidatesEveryCloudAuthorityBeforePOST(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeAPI, *v1alpha1.InSpaceCluster)
	}{
		{
			name: "VPC read error",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.getNetworkError = errors.New("injected VPC read failure")
			},
		},
		{
			name: "VPC subnet drift",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.network.Subnet = "10.20.31.0/24"
			},
		},
		{
			name: "host-pool read error",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.listHostPoolsError = errors.New("injected host-pool read failure")
			},
		},
		{
			name: "host-pool identity disappeared",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.hostPools = nil
			},
		},
		{
			name: "firewall read error",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.firewallListError = errors.New("injected firewall read failure")
			},
		},
		{
			name: "firewall billing drift",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.firewalls[0].BillingAccountID++
			},
		},
		{
			name: "firewall policy drift",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.firewalls[0].Rules = api.firewalls[0].Rules[:len(api.firewalls[0].Rules)-1]
			},
		},
		{
			name: "firewall assignment drift",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.firewalls[0].ResourcesAssigned = append(api.firewalls[0].ResourcesAssigned, inspace.FirewallResource{
					ResourceType: "vm", ResourceUUID: "cccccccc-1111-4222-8333-bbbbbbbbbbbb",
				})
			},
		},
		{
			name: "cluster billing drift",
			mutate: func(_ *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				cluster.Spec.BillingAccountID++
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			desired, err := reconciler.desiredBastionVMRequest(cluster, &api.network, ownerKey(cluster), cacheTLSMaterial{})
			if err != nil {
				t.Fatal(err)
			}
			firewall := testManagedBastionFirewall(reconciler, api, cluster)
			api.firewalls = []inspace.Firewall{firewall}
			fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionVM, func() {
				api.mu.Lock()
				defer api.mu.Unlock()
				test.mutate(api, cluster)
			})

			_, _, err = reconciler.ensureManagedVMCreate(
				context.Background(), cluster, createAttemptBastionVM, &firewall, nil, desired,
				currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP,
				"10.20.30.0/24", cluster.Spec.Endpoint.VirtualIPv4, privateIPv4Range{},
			)
			if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired {
				t.Fatalf("post-CAS authority drift = fired=%t error=%v", *fired, err)
			}
			if len(api.vmCreates) != 0 {
				t.Fatalf("post-CAS authority drift dispatched VM POST: %#v", api.vmCreates)
			}
			if attempt := cluster.Status.CreateAttempts[createAttemptBastionVM]; attempt.Phase != createAttemptPhaseIntent {
				t.Fatalf("post-CAS authority drift did not reset undispatched issue: %#v", attempt)
			}
		})
	}
}

func TestCreatedVMOwnershipRecoveryRequiresUniqueUnfilteredInventory(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconciler.createdVMRecoveryTimeout = 10 * time.Millisecond
	desired, err := reconciler.desiredBastionVMRequest(cluster, &api.network, ownerKey(cluster), cacheTLSMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	vm := testVMFromCreateRequest(vmUUID, desired)
	api.vms = []inspace.VM{vm, vm}
	api.network.VMUUIDs = []string{vmUUID}
	if _, err := reconciler.recoverCreatedVMOwnership(context.Background(), cluster, desired, vmUUID); err == nil {
		t.Fatal("duplicate unfiltered VM rows became response recovery authority")
	}
}

func TestFirewallCreatePostCASAdoptsExactObjectAndRejectsDrift(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*inspace.Firewall)
		wantAdopt bool
	}{
		{name: "exact", wantAdopt: true},
		{name: "billing drift", mutate: func(item *inspace.Firewall) { item.BillingAccountID = 999 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			owner := ownerKey(cluster)
			request := inspace.CreateFirewallRequest{
				DisplayName:      currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFirewall,
				Description:      "Managed RKE2 bastion firewall for " + owner,
				BillingAccountID: cluster.Spec.BillingAccountID,
				Rules:            managedBastionFirewallRules(reconciler.ManagementCIDR, api.network.Subnet, false),
			}
			validate := func(item *inspace.Firewall) error {
				if item.EffectiveName() != request.DisplayName || item.BillingAccountID != request.BillingAccountID ||
					!sameFirewallPolicy(item.Rules, request.Rules) {
					return errors.New("foreign firewall authority")
				}
				return nil
			}
			fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionFirewall, func() {
				item := inspace.Firewall{
					UUID: "aaaaaaaa-1111-4222-8333-444444444444", DisplayName: request.DisplayName,
					Description: request.Description, BillingAccountID: request.BillingAccountID,
					Rules: append([]inspace.FirewallRule(nil), request.Rules...),
				}
				if test.mutate != nil {
					test.mutate(&item)
				}
				api.mu.Lock()
				defer api.mu.Unlock()
				api.firewalls = append(api.firewalls, item)
			})

			item, err := reconciler.ensureManagedFirewallCreate(
				context.Background(), cluster, createAttemptBastionFirewall, "bastion", request, nil, api.network.Subnet, validate,
			)
			if !*fired || len(api.firewallCreates) != 0 {
				t.Fatalf("post-CAS firewall path = fired=%t creates=%#v", *fired, api.firewallCreates)
			}
			attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewall]
			if test.wantAdopt {
				if err != nil || item == nil || attempt.Phase != createAttemptPhaseMaterialized {
					t.Fatalf("exact firewall was not adopted: item=%#v error=%v receipt=%#v", item, err, attempt)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrCreateAttemptPending) || attempt.Phase != createAttemptPhaseIntent {
				t.Fatalf("drifted firewall did not reset undispatched issue: error=%v receipt=%#v", err, attempt)
			}
			cluster = restartClusterFromJSON(t, cluster)
			_, _ = testReconciler(api).ensureManagedFirewallCreate(
				context.Background(), cluster, createAttemptBastionFirewall, "bastion", request, nil, api.network.Subnet, validate,
			)
			if len(api.firewallCreates) != 0 || cluster.Status.CreateAttempts[createAttemptBastionFirewall].Phase != createAttemptPhaseIntent {
				t.Fatalf("restart replayed drifted firewall create: creates=%#v receipt=%#v", api.firewallCreates, cluster.Status.CreateAttempts[createAttemptBastionFirewall])
			}
		})
	}
}

func TestFirewallCreatePostCASRecomputesFreshVPCPolicyBeforePOST(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeAPI, *v1alpha1.InSpaceCluster)
	}{
		{
			name: "VPC read error",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.getNetworkError = errors.New("injected VPC read failure")
			},
		},
		{
			name: "VPC subnet changed",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.network.Subnet = "10.20.31.0/24"
			},
		},
		{
			name: "pod prefix changed",
			mutate: func(_ *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				cluster.Spec.Network.PodCIDR = "10.44.0.0/16"
			},
		},
		{
			name: "billing changed",
			mutate: func(_ *fakeAPI, cluster *v1alpha1.InSpaceCluster) {
				cluster.Spec.BillingAccountID++
			},
		},
		{
			name: "post-authority firewall read error",
			mutate: func(api *fakeAPI, _ *v1alpha1.InSpaceCluster) {
				api.firewallListError = errors.New("injected firewall list failure")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			reconciler := testReconciler(api)
			owner := ownerKey(cluster)
			request := inspace.CreateFirewallRequest{
				DisplayName:      currentBootstrapResourceNames(cluster.Metadata.Name, owner).NodeFirewall,
				Description:      "Managed RKE2 node firewall for " + owner,
				BillingAccountID: cluster.Spec.BillingAccountID,
				Rules: managedFirewallRules(
					api.network.Subnet, cluster.Spec.Network.PodCIDR, "", nil,
				),
			}
			validate := func(item *inspace.Firewall) error {
				return validateManagedNodeFirewall(item, cluster, &api.network, owner, request.DisplayName)
			}
			fired := installCreateIssueCASHook(t, reconciler, createAttemptNodeFirewall, func() {
				api.mu.Lock()
				defer api.mu.Unlock()
				test.mutate(api, cluster)
			})

			_, err := reconciler.ensureManagedFirewallCreate(
				context.Background(), cluster, createAttemptNodeFirewall, "node", request, nil,
				"10.20.30.0/24", validate,
			)
			if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired {
				t.Fatalf("post-CAS firewall authority = fired=%t error=%v", *fired, err)
			}
			if len(api.firewallCreates) != 0 {
				t.Fatalf("post-CAS firewall authority dispatched POST: %#v", api.firewallCreates)
			}
			if attempt := cluster.Status.CreateAttempts[createAttemptNodeFirewall]; attempt.Phase != createAttemptPhaseIntent {
				t.Fatalf("post-CAS firewall authority did not reset undispatched issue: %#v", attempt)
			}
		})
	}
}

func TestFloatingIPRenamePostCASDriftResetsUndispatchedIssue(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	seedOwnedMutationVMs(t, api, cluster, vmUUID)
	vm := api.vms[0]
	name := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
	item := inspace.FloatingIP{
		Address: "203.0.113.40", BillingAccountID: cluster.Spec.BillingAccountID, Type: "public", Enabled: true,
		AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
	}
	api.floatingIPs = []inspace.FloatingIP{item}
	reconciler := testReconciler(api)
	fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionFloatingIPUpdate, func() {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.floatingIPs[0].BillingAccountID = 999
	})

	_, _, err := reconciler.ensureOwnedAutoFloatingIP(context.Background(), cluster, name, &vm, &item)
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.floatingIPUpdateCalls != 0 {
		t.Fatalf("post-CAS FIP drift = fired=%t error=%v PATCHes=%d", *fired, err, api.floatingIPUpdateCalls)
	}
	if attempt := cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("post-CAS FIP drift did not reset undispatched issue: %#v", attempt)
	}

	cluster = restartClusterFromJSON(t, cluster)
	_, _, _ = testReconciler(api).ensureOwnedAutoFloatingIP(context.Background(), cluster, name, &vm, &item)
	if api.floatingIPUpdateCalls != 0 || cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate].Phase != createAttemptPhaseIntent {
		t.Fatalf("restart replayed drifted FIP PATCH: calls=%d receipt=%#v", api.floatingIPUpdateCalls, cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate])
	}
}

func TestFirewallAssignmentPostCASDriftResetsUndispatchedIssue(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	seedOwnedMutationVMs(t, api, cluster, vmUUID)
	firewall := inspace.Firewall{
		UUID: "aaaaaaaa-1111-4222-8333-444444444444", DisplayName: "unit-assignment-firewall",
		BillingAccountID: cluster.Spec.BillingAccountID,
	}
	api.firewalls = []inspace.Firewall{firewall}
	const key = "firewall-assignment/post-cas-drift"
	reconciler := testReconciler(api)
	fired := installCreateIssueCASHook(t, reconciler, key, func() {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.firewalls[0].BillingAccountID = 999
	})

	err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, key, &firewall, vmUUID)
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.firewallAssignmentCalls != 0 {
		t.Fatalf("post-CAS assignment drift = fired=%t error=%v POSTs=%d", *fired, err, api.firewallAssignmentCalls)
	}
	if attempt := cluster.Status.CreateAttempts[key]; attempt.Phase != createAttemptPhaseIntent {
		t.Fatalf("post-CAS assignment drift did not reset undispatched issue: %#v", attempt)
	}

	cluster = restartClusterFromJSON(t, cluster)
	_ = testReconciler(api).ensureExactFirewallAssignment(context.Background(), cluster, key, &firewall, vmUUID)
	if api.firewallAssignmentCalls != 0 || cluster.Status.CreateAttempts[key].Phase != createAttemptPhaseIntent {
		t.Fatalf("restart replayed drifted firewall assignment: calls=%d receipt=%#v", api.firewallAssignmentCalls, cluster.Status.CreateAttempts[key])
	}
}

func TestDeletedVMTombstoneNeverAuthorizesRelatedMutation(t *testing.T) {
	t.Run("firewall assignment", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
		seedOwnedMutationVMs(t, api, cluster, vmUUID)
		firewall := inspace.Firewall{
			UUID: "aaaaaaaa-1111-4222-8333-444444444444", DisplayName: "unit-assignment-firewall",
			BillingAccountID: cluster.Spec.BillingAccountID,
		}
		api.firewalls = []inspace.Firewall{firewall}
		const key = "firewall-assignment/deleted-vm"
		reconciler := testReconciler(api)
		fired := installCreateIssueCASHook(t, reconciler, key, func() {
			api.mu.Lock()
			defer api.mu.Unlock()
			api.vms[0].Status = "Deleted"
		})

		err := reconciler.ensureExactFirewallAssignment(context.Background(), cluster, key, &firewall, vmUUID)
		if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.firewallAssignmentCalls != 0 {
			t.Fatalf("deleted VM assignment authority = fired=%t error=%v POSTs=%d", *fired, err, api.firewallAssignmentCalls)
		}
		if attempt := cluster.Status.CreateAttempts[key]; attempt.Phase != createAttemptPhaseIntent {
			t.Fatalf("deleted VM assignment did not reset undispatched issue: %#v", attempt)
		}
	})

	t.Run("floating IP update", func(t *testing.T) {
		api := newFakeAPI()
		cluster := testCluster()
		const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
		seedOwnedMutationVMs(t, api, cluster, vmUUID)
		vm := api.vms[0]
		name := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
		item := inspace.FloatingIP{
			Address: "203.0.113.40", BillingAccountID: cluster.Spec.BillingAccountID, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
		}
		api.floatingIPs = []inspace.FloatingIP{item}
		reconciler := testReconciler(api)
		fired := installCreateIssueCASHook(t, reconciler, createAttemptBastionFloatingIPUpdate, func() {
			api.mu.Lock()
			defer api.mu.Unlock()
			api.vms[0].Status = "Deleted"
		})

		_, _, err := reconciler.ensureOwnedAutoFloatingIP(context.Background(), cluster, name, &vm, &item)
		if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.floatingIPUpdateCalls != 0 {
			t.Fatalf("deleted VM floating-IP authority = fired=%t error=%v PATCHes=%d", *fired, err, api.floatingIPUpdateCalls)
		}
		if attempt := cluster.Status.CreateAttempts[createAttemptBastionFloatingIPUpdate]; attempt.Phase != createAttemptPhaseIntent {
			t.Fatalf("deleted VM floating-IP update did not reset undispatched issue: %#v", attempt)
		}
	})
}

func TestRollbackFloatingIPPostCASDriftResetsUndispatchedRemoval(t *testing.T) {
	for _, test := range []struct {
		name        string
		intentPhase string
		issuedPhase string
		assigned    bool
	}{
		{name: "unassign", intentPhase: deletePhaseRollbackFIPUnassignIntent, issuedPhase: deletePhaseRollbackFIPUnassignIssued, assigned: true},
		{name: "delete", intentPhase: deletePhaseRollbackFIPDeleteIntent, issuedPhase: deletePhaseRollbackFIPDeleteIssued},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			owner := ownerKey(cluster)
			const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
			name := currentBootstrapResourceNames(cluster.Metadata.Name, owner).BastionFloatingIP
			item := inspace.FloatingIP{
				Name: name, Address: "203.0.113.41", BillingAccountID: cluster.Spec.BillingAccountID,
				Type: "public", Enabled: true,
			}
			if test.assigned {
				item.AssignedTo = vmUUID
				item.AssignedToResourceType = "virtual_machine"
				item.AssignedToPrivateIP = "10.20.30.20"
			}
			api.floatingIPs = []inspace.FloatingIP{item}
			cluster.Status.DeleteAttempts = map[string]v1alpha1.ResourceDeleteAttemptStatus{
				deleteAttemptBastion: {
					ResourceKind: deleteAttemptKindVM, ResourceName: currentBastionName(cluster.Metadata.Name), ResourceUUID: vmUUID,
					Location: cluster.Spec.Location, Owner: owner, Purpose: deletePurposeRollback, Phase: test.intentPhase,
					FloatingIPName: name, FloatingIPAddress: item.Address,
				},
			}
			reconciler := testReconciler(api)
			fired := installDeleteIssueCASHook(t, reconciler, deleteAttemptBastion, test.issuedPhase, func() {
				api.mu.Lock()
				defer api.mu.Unlock()
				api.floatingIPs[0].BillingAccountID = 999
			})

			_, err := reconciler.rollbackFloatingIP(context.Background(), cluster, deleteAttemptBastion)
			if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.floatingIPUnassignCalls != 0 || len(api.floatingIPDeletes) != 0 {
				t.Fatalf("post-CAS rollback %s drift = fired=%t error=%v unassign=%d deletes=%#v", test.name, *fired, err, api.floatingIPUnassignCalls, api.floatingIPDeletes)
			}
			if attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]; attempt.Phase != test.intentPhase {
				t.Fatalf("post-CAS rollback %s did not reset undispatched issue: %#v", test.name, attempt)
			}

			cluster = restartClusterFromJSON(t, cluster)
			_, _ = testReconciler(api).rollbackFloatingIP(context.Background(), cluster, deleteAttemptBastion)
			if api.floatingIPUnassignCalls != 0 || len(api.floatingIPDeletes) != 0 || cluster.Status.DeleteAttempts[deleteAttemptBastion].Phase != test.intentPhase {
				t.Fatalf("restart replayed rollback %s: unassign=%d deletes=%#v receipt=%#v", test.name, api.floatingIPUnassignCalls, api.floatingIPDeletes, cluster.Status.DeleteAttempts[deleteAttemptBastion])
			}
		})
	}
}

func TestDestroyFloatingIPPostCASVMDriftResetsUndispatchedUnassign(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	const vmUUID = "bbbbbbbb-1111-4222-8333-bbbbbbbbbbbb"
	seedOwnedMutationVMs(t, api, cluster, vmUUID)
	vm := api.vms[0]
	name := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster)).BastionFloatingIP
	item := inspace.FloatingIP{
		Name: name, Address: "203.0.113.42", BillingAccountID: cluster.Spec.BillingAccountID,
		Type: "public", Enabled: true, AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: vm.PrivateIPv4,
	}
	api.floatingIPs = []inspace.FloatingIP{item}
	reconciler := testReconciler(api)
	if err := reconciler.ensureDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey, &item); err != nil {
		t.Fatal(err)
	}
	fired := installDeleteIssueCASHook(t, reconciler, destroyFIPBastionKey, deletePhaseFIPUnassignIssued, func() {
		api.mu.Lock()
		defer api.mu.Unlock()
		api.vms[0].BillingAccountID = 999
	})

	_, err := reconciler.reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey)
	if err == nil || !errors.Is(err, ErrCreateAttemptPending) || !*fired || api.floatingIPUnassignCalls != 0 {
		t.Fatalf("post-CAS destroy target drift = fired=%t error=%v unassign=%d", *fired, err, api.floatingIPUnassignCalls)
	}
	if attempt := cluster.Status.DeleteAttempts[destroyFIPBastionKey]; attempt.Phase != deletePhaseFIPUnassignIntent {
		t.Fatalf("post-CAS destroy target drift did not reset undispatched issue: %#v", attempt)
	}

	cluster = restartClusterFromJSON(t, cluster)
	_, _ = testReconciler(api).reconcileDestroyFloatingIPRemoval(context.Background(), cluster, destroyFIPBastionKey)
	if api.floatingIPUnassignCalls != 0 || cluster.Status.DeleteAttempts[destroyFIPBastionKey].Phase != deletePhaseFIPUnassignIntent {
		t.Fatalf("restart replayed drifted destroy unassign: calls=%d receipt=%#v", api.floatingIPUnassignCalls, cluster.Status.DeleteAttempts[destroyFIPBastionKey])
	}
}
