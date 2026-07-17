package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

type vmTombstoneAPI struct {
	API
	uuid      string
	tombstone inspace.VM
}

func (a *vmTombstoneAPI) GetVM(ctx context.Context, location, uuid string) (*inspace.VM, error) {
	if strings.EqualFold(uuid, a.uuid) {
		copy := a.tombstone
		return &copy, nil
	}
	return a.API.GetVM(ctx, location, uuid)
}

type overriddenVPCMembershipAPI struct {
	API
	members []string
	omit    bool
}

func (a *overriddenVPCMembershipAPI) GetNetwork(ctx context.Context, location, uuid string) (*inspace.Network, error) {
	network, err := a.API.GetNetwork(ctx, location, uuid)
	if network != nil {
		copy := *network
		if a.omit {
			copy.VMUUIDs = nil
		} else {
			copy.VMUUIDs = append([]string{}, a.members...)
		}
		network = &copy
	}
	return network, err
}

type boundedVMDeleteAPI struct {
	API

	mu       sync.Mutex
	calls    int
	deadline time.Time
}

func (a *boundedVMDeleteAPI) DeleteVM(ctx context.Context, _, _ string) error {
	a.mu.Lock()
	a.calls++
	a.deadline, _ = ctx.Deadline()
	a.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func TestVMDeleteAcceptsExactHTTP200DeletedTombstoneOnlyWithListAndVPCAbsence(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	vm := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	vmCopy := *vm
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	firewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := reconciler.ensureVMDeleteAttempt(context.Background(), cluster, deleteAttemptBastion, deletePurposeDestroy, &vmCopy, firewall.UUID, ""); err != nil {
		t.Fatal(err)
	}
	api.removeVMFromReadback(vmCopy.UUID)
	tombstone := vmCopy
	tombstone.Status = "Deleted"
	reconciler.API = &vmTombstoneAPI{API: api, uuid: vmCopy.UUID, tombstone: tombstone}

	terminal, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion)
	if err != nil || terminal {
		t.Fatalf("first tombstone observation: terminal=%t error=%v", terminal, err)
	}
	terminal, err = reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion)
	if err != nil || !terminal {
		t.Fatalf("second tombstone observation: terminal=%t error=%v", terminal, err)
	}
	if attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]; attempt.Phase != deletePhaseAbsent {
		t.Fatalf("tombstone did not converge to durable absence: %#v", attempt)
	}
	if len(api.vmDeletes) != 0 {
		t.Fatalf("tombstone recovery replayed DELETE: %#v", api.vmDeletes)
	}
}

func TestVMDeleteRejectsForeignHTTP200DeletedTombstone(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	vm := *mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	firewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := reconciler.ensureVMDeleteAttempt(context.Background(), cluster, deleteAttemptBastion, deletePurposeDestroy, &vm, firewall.UUID, ""); err != nil {
		t.Fatal(err)
	}
	if allowed, err := reconciler.issueDeleteAttempt(context.Background(), cluster, deleteAttemptBastion, deletePhaseVMIntent, deletePhaseVMIssued); err != nil || !allowed {
		t.Fatalf("issue VM deletion: allowed=%t error=%v", allowed, err)
	}
	api.removeVMFromReadback(vm.UUID)
	vm.Status = "deleted"
	vm.BillingAccountID++
	reconciler.API = &vmTombstoneAPI{API: api, uuid: vm.UUID, tombstone: vm}

	if _, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("foreign tombstone error = %v", err)
	}
	if attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]; attempt.Phase != deletePhaseVMIssued || attempt.AbsenceObservedAt != "" {
		t.Fatalf("foreign tombstone advanced deletion: %#v", attempt)
	}
}

func TestVMDeleteAbsenceRejectsInvalidVPCMembershipSnapshot(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	vm := *mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	firewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := reconciler.ensureVMDeleteAttempt(
		context.Background(),
		cluster,
		deleteAttemptBastion,
		deletePurposeDestroy,
		&vm,
		firewall.UUID,
		"",
	); err != nil {
		t.Fatal(err)
	}
	api.removeVMFromReadback(vm.UUID)
	const unrelated = "cccccccc-1111-4222-8333-dddddddddddd"
	tests := []struct {
		name    string
		members []string
		omit    bool
	}{
		{name: "omitted collection", omit: true},
		{name: "empty or null member", members: []string{""}},
		{name: "malformed unrelated member", members: []string{"bad"}},
		{name: "case-fold duplicate unrelated member", members: []string{unrelated, strings.ToUpper(unrelated)}},
		{name: "duplicate target member", members: []string{vm.UUID, vm.UUID}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler.API = &overriddenVPCMembershipAPI{API: api, members: test.members, omit: test.omit}
			attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]
			absent, err := reconciler.corroborateVMDeletionAbsence(
				context.Background(),
				cluster,
				deleteAttemptBastion,
				attempt,
			)
			if err == nil || absent {
				t.Fatalf("corroborateVMDeletionAbsence() = absent=%t error=%v, want fail-closed membership rejection", absent, err)
			}
			if current := cluster.Status.DeleteAttempts[deleteAttemptBastion]; current.AbsenceObservedAt != "" {
				t.Fatalf("invalid VPC membership advanced absence receipt: %#v", current)
			}
		})
	}
}

func TestVMDeleteUsesBoundedMutationContext(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	vm := *mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	firewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := reconciler.ensureVMDeleteAttempt(context.Background(), cluster, deleteAttemptBastion, deletePurposeDestroy, &vm, firewall.UUID, ""); err != nil {
		t.Fatal(err)
	}
	reconciler.createdVMDeleteTimeout = 20 * time.Millisecond
	blocking := &boundedVMDeleteAPI{API: api}
	reconciler.API = blocking
	started := time.Now()
	terminal, err := reconciler.reconcileVMDelete(context.Background(), cluster, deleteAttemptBastion)
	elapsed := time.Since(started)
	if terminal || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded delete result: terminal=%t error=%v", terminal, err)
	}
	blocking.mu.Lock()
	calls, deadline := blocking.calls, blocking.deadline
	blocking.mu.Unlock()
	if calls != 1 || deadline.IsZero() {
		t.Fatalf("bounded delete calls=%d deadline=%s", calls, deadline)
	}
	if budget := deadline.Sub(started); budget < 5*time.Millisecond || budget > 100*time.Millisecond {
		t.Fatalf("VM delete deadline budget=%s, want about 20ms", budget)
	}
	if elapsed > time.Second {
		t.Fatalf("VM delete ignored its bounded context: elapsed=%s", elapsed)
	}
	if attempt := cluster.Status.DeleteAttempts[deleteAttemptBastion]; attempt.Phase != deletePhaseVMIssued {
		t.Fatalf("timed-out post-dispatch outcome lost durable issue: %#v", attempt)
	}
}

func TestPreDispatchCreateResetSurvivesCanceledReconcileContext(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconciler.protectionRequestTimeout = 50 * time.Millisecond
	baseCAS := reconciler.StatusCompareAndSwap
	var persistenceDeadline time.Time
	reconciler.StatusCompareAndSwap = func(
		ctx context.Context,
		cluster *v1alpha1.InSpaceCluster,
		expected, desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		if err := ctx.Err(); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			persistenceDeadline = deadline
		}
		return baseCAS(ctx, cluster, expected, desired)
	}
	const key = "firewall/test-reset"
	const name = "unit-firewall"
	intentHash, err := createIntentHash(createAttemptKindFirewall, name, struct{ Name string }{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := reconciler.authorizeCreate(context.Background(), cluster, key, createAttemptKindFirewall, name, intentHash)
	if err != nil || !allowed {
		t.Fatalf("issue create: allowed=%t error=%v", allowed, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reconciler.resetPreDispatchCreateIssue(canceled, cluster, key, createAttemptKindFirewall, name, intentHash); err != nil {
		t.Fatalf("reset with canceled reconcile context: %v", err)
	}
	if attempt := cluster.Status.CreateAttempts[key]; attempt.Phase != createAttemptPhaseIntent || attempt.IssueID != "" || attempt.IssuedAt != "" {
		t.Fatalf("canceled-context reset left issued authority: %#v", attempt)
	}
	if persistenceDeadline.IsZero() || time.Until(persistenceDeadline) > time.Second {
		t.Fatalf("detached create-reset persistence deadline = %s, want a finite short bound", persistenceDeadline)
	}
}

func TestPreDispatchDeleteResetRequiresExactIssuedPhaseAndSurvivesCanceledContext(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	reconciler := testReconciler(api)
	reconciler.protectionRequestTimeout = 50 * time.Millisecond
	baseCAS := reconciler.StatusCompareAndSwap
	var persistenceDeadline time.Time
	reconciler.StatusCompareAndSwap = func(
		ctx context.Context,
		cluster *v1alpha1.InSpaceCluster,
		expected, desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		if err := ctx.Err(); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			persistenceDeadline = deadline
		}
		return baseCAS(ctx, cluster, expected, desired)
	}
	const key = "vm/test-delete-reset"
	cluster.Status.DeleteAttempts = map[string]v1alpha1.ResourceDeleteAttemptStatus{
		key: {
			Phase:    deletePhaseRollbackFIPUnassignIssued,
			IssueID:  strings.Repeat("a", 32),
			IssuedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reconciler.resetPreDispatchDeleteIssue(
		canceled,
		cluster,
		key,
		deletePhaseRollbackFIPUnassignIssued,
		deletePhaseRollbackFIPUnassignIntent,
	); err != nil {
		t.Fatalf("reset with canceled reconcile context: %v", err)
	}
	if attempt := cluster.Status.DeleteAttempts[key]; attempt.Phase != deletePhaseRollbackFIPUnassignIntent || attempt.IssueID != "" || attempt.IssuedAt != "" {
		t.Fatalf("canceled-context reset left issued delete authority: %#v", attempt)
	}
	if persistenceDeadline.IsZero() || time.Until(persistenceDeadline) > time.Second {
		t.Fatalf("detached delete-reset persistence deadline = %s, want a finite short bound", persistenceDeadline)
	}

	drifted := cluster.Status.DeleteAttempts[key]
	drifted.Phase = deletePhaseRollbackFIPDeleteIssued
	drifted.IssueID = strings.Repeat("b", 32)
	drifted.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	cluster.Status.DeleteAttempts[key] = drifted
	err := reconciler.resetPreDispatchDeleteIssue(
		context.Background(),
		cluster,
		key,
		deletePhaseRollbackFIPUnassignIssued,
		deletePhaseRollbackFIPUnassignIntent,
	)
	if err == nil || !strings.Contains(err.Error(), "changed before pre-dispatch reset") {
		t.Fatalf("unexpected-phase reset error = %v", err)
	}
	if attempt := cluster.Status.DeleteAttempts[key]; attempt.Phase != drifted.Phase || attempt.IssueID != drifted.IssueID || attempt.IssuedAt != drifted.IssuedAt {
		t.Fatalf("unexpected-phase reset changed newer delete authority: %#v", attempt)
	}
}
