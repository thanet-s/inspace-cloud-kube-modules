package bootstrap

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

type establishedBastionAssignmentFixture struct {
	cluster       *v1alpha1.InSpaceCluster
	api           *fakeAPI
	vm            inspace.VM
	firewall      inspace.Firewall
	assignmentKey string
	postCount     int
}

func establishAmbiguousBastionAssignment(
	t *testing.T,
	commit bool,
) establishedBastionAssignmentFixture {
	t.Helper()
	api := newFakeAPI()
	cluster := testCluster()
	reconcileUntilReady(t, testReconciler(api), cluster)
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	vm := *mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))

	api.mu.Lock()
	firewallIndex := -1
	for index := range api.firewalls {
		if api.firewalls[index].EffectiveName() == resourceNames.BastionFirewall {
			firewallIndex = index
			break
		}
	}
	if firewallIndex < 0 {
		api.mu.Unlock()
		t.Fatal("managed bastion firewall not found")
	}
	kept := api.firewalls[firewallIndex].ResourcesAssigned[:0]
	for _, resource := range api.firewalls[firewallIndex].ResourcesAssigned {
		if !strings.EqualFold(resource.ResourceUUID, vm.UUID) {
			kept = append(kept, resource)
		}
	}
	api.firewalls[firewallIndex].ResourcesAssigned = kept
	firewall := api.firewalls[firewallIndex]
	before := api.firewallAssignmentCalls
	api.firewallAssignmentError = &inspace.APIError{
		StatusCode: 500,
		Method:     "POST",
		Path:       "/core/v2/firewalls/assignment",
		Message:    "injected ambiguous assignment",
		Retryable:  true,
	}
	api.firewallAssignmentErrorCommits = commit
	if commit {
		api.firewallAssignmentReadbackDelay = 1_000
	}
	api.mu.Unlock()
	delete(cluster.Status.CreateAttempts, createAttemptBastionFirewallAssignment)

	reconciler := testReconciler(api)
	reconciler.firewallAssignmentProtectionDeadline = time.Hour
	reconciler.protectionAuditTimeout = 10 * time.Millisecond
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("establish ambiguous assignment: %v", err)
	}
	api.mu.Lock()
	posts := api.firewallAssignmentCalls
	api.mu.Unlock()
	if posts != before+1 {
		t.Fatalf("ambiguous assignment POST count=%d, want %d", posts, before+1)
	}
	attempt := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" {
		t.Fatalf("ambiguous assignment receipt=%#v", attempt)
	}
	return establishedBastionAssignmentFixture{
		cluster:       cluster,
		api:           api,
		vm:            vm,
		firewall:      firewall,
		assignmentKey: createAttemptBastionFirewallAssignment,
		postCount:     posts,
	}
}

func ageBastionAssignment(t *testing.T, cluster *v1alpha1.InSpaceCluster) {
	t.Helper()
	attempt, exists := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	if !exists || attempt.Phase != createAttemptPhaseIssued {
		t.Fatalf("cannot age assignment receipt %#v", attempt)
	}
	attempt.IssuedAt = time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment] = attempt
}

func TestEstablishedAssignmentHTTPErrorRollsBackOnlyAfterDurableDeadline(t *testing.T) {
	fixture := establishAmbiguousBastionAssignment(t, false)

	cluster := restartClusterFromJSON(t, fixture.cluster)
	beforeDeadline := testReconciler(fixture.api)
	beforeDeadline.firewallAssignmentProtectionDeadline = 2 * time.Minute
	beforeDeadline.protectionAuditTimeout = 10 * time.Millisecond
	if _, err := beforeDeadline.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("restart before deadline: %v", err)
	}
	if fixture.api.firewallAssignmentCalls != fixture.postCount || len(fixture.api.vmDeletes) != 0 {
		t.Fatalf("restart replayed or prematurely rolled back: POSTs=%d deletes=%#v", fixture.api.firewallAssignmentCalls, fixture.api.vmDeletes)
	}

	ageBastionAssignment(t, cluster)
	cluster = restartClusterFromJSON(t, cluster)
	afterDeadline := testReconciler(fixture.api)
	afterDeadline.firewallAssignmentProtectionDeadline = 2 * time.Minute
	afterDeadline.protectionAuditTimeout = 10 * time.Millisecond
	if _, err := afterDeadline.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, errFirewallAssignmentProtectionRollback) {
		t.Fatalf("deadline rollback error=%v", err)
	}
	if fixture.api.firewallAssignmentCalls != fixture.postCount {
		t.Fatalf("deadline replayed assignment POST: got %d want %d", fixture.api.firewallAssignmentCalls, fixture.postCount)
	}
	if len(fixture.api.vmDeletes) != 1 || fixture.api.vmDeletes[0] != fixture.vm.UUID {
		t.Fatalf("deadline rollback did not delete only the exact VM: %#v", fixture.api.vmDeletes)
	}
	if attempt, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]; !exists ||
		attempt.Purpose != deletePurposeRollback || attempt.ResourceUUID != fixture.vm.UUID {
		t.Fatalf("deadline rollback receipt=%#v exists=%t", attempt, exists)
	}
}

func TestEstablishedAssignmentVisibleAtDeadlineIsMaterialized(t *testing.T) {
	for _, test := range []struct {
		name string
		age  bool
	}{
		{name: "before deadline"},
		{name: "after deadline", age: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := establishAmbiguousBastionAssignment(t, true)
			if test.age {
				ageBastionAssignment(t, fixture.cluster)
			}
			fixture.api.mu.Lock()
			fixture.api.firewallAssignmentReadbackRemaining = 0
			fixture.api.mu.Unlock()

			cluster := restartClusterFromJSON(t, fixture.cluster)
			reconciler := testReconciler(fixture.api)
			reconciler.firewallAssignmentProtectionDeadline = 2 * time.Minute
			reconciler.protectionAuditTimeout = 10 * time.Millisecond
			if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil {
				t.Fatalf("visible relation recovery: %v", err)
			}
			attempt := cluster.Status.CreateAttempts[fixture.assignmentKey]
			if attempt.Phase != createAttemptPhaseMaterialized || attempt.ResourceUUID != fixture.vm.UUID {
				t.Fatalf("visible relation receipt=%#v", attempt)
			}
			if fixture.api.firewallAssignmentCalls != fixture.postCount || len(fixture.api.vmDeletes) != 0 || len(cluster.Status.DeleteAttempts) != 0 {
				t.Fatalf("visible relation was replayed or rolled back: POSTs=%d deletes=%#v status=%#v",
					fixture.api.firewallAssignmentCalls, fixture.api.vmDeletes, cluster.Status.DeleteAttempts)
			}
		})
	}
}

func TestLateFirewallRelationAfterRollbackPersistenceIsContained(t *testing.T) {
	fixture := establishAmbiguousBastionAssignment(t, false)
	ageBastionAssignment(t, fixture.cluster)
	cluster := restartClusterFromJSON(t, fixture.cluster)
	reconciler := testReconciler(fixture.api)
	reconciler.firewallAssignmentProtectionDeadline = 2 * time.Minute
	reconciler.protectionAuditTimeout = 10 * time.Millisecond

	injected := false
	reconciler.StatusCompareAndSwap = func(
		_ context.Context,
		_ *v1alpha1.InSpaceCluster,
		expected v1alpha1.InSpaceClusterStatus,
		desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		if !injected && expected.DeleteAttempts[deleteAttemptBastion].ResourceUUID == "" &&
			desired.DeleteAttempts[deleteAttemptBastion].ResourceUUID == fixture.vm.UUID {
			fixture.api.mu.Lock()
			for index := range fixture.api.firewalls {
				if strings.EqualFold(fixture.api.firewalls[index].UUID, fixture.firewall.UUID) {
					fixture.api.firewalls[index].ResourcesAssigned = append(
						fixture.api.firewalls[index].ResourcesAssigned,
						inspace.FirewallResource{ResourceType: "vm", ResourceUUID: fixture.vm.UUID},
					)
				}
			}
			fixture.api.mu.Unlock()
			injected = true
		}
		return desired, nil
	}
	if _, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token"); !errors.Is(err, errFirewallAssignmentProtectionRollback) {
		t.Fatalf("late relation rollback: %v", err)
	}
	if !injected || len(fixture.api.vmDeletes) != 1 || fixture.api.vmDeletes[0] != fixture.vm.UUID {
		t.Fatalf("late relation was not contained: injected=%t deletes=%#v", injected, fixture.api.vmDeletes)
	}
	if fixture.api.firewallAssignmentCalls != fixture.postCount {
		t.Fatalf("late relation caused assignment replay: POSTs=%d want=%d", fixture.api.firewallAssignmentCalls, fixture.postCount)
	}
	fixture.api.mu.Lock()
	defer fixture.api.mu.Unlock()
	for _, firewall := range fixture.api.firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			if strings.EqualFold(resource.ResourceUUID, fixture.vm.UUID) {
				t.Fatalf("late relation survived exact VM rollback: %#v", firewall.ResourcesAssigned)
			}
		}
	}
}

func TestPersistentFirewallListErrorsPreserveIssuedProtectionAuthority(t *testing.T) {
	fixture := establishAmbiguousBastionAssignment(t, false)
	ageBastionAssignment(t, fixture.cluster)
	cluster := restartClusterFromJSON(t, fixture.cluster)
	fixture.api.firewallListError = io.ErrUnexpectedEOF
	reconciler := testReconciler(fixture.api)
	reconciler.firewallAssignmentProtectionDeadline = 2 * time.Minute
	reconciler.protectionAuditTimeout = 10 * time.Millisecond

	for pass := 0; pass < 2; pass++ {
		_, err := reconciler.ensureVMProtection(
			context.Background(),
			cluster,
			fixture.assignmentKey,
			&fixture.firewall,
			&fixture.vm,
		)
		if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrCreateAttemptPending) {
			t.Fatalf("persistent list error pass %d: %v", pass, err)
		}
		cluster = restartClusterFromJSON(t, cluster)
		reconciler = testReconciler(fixture.api)
		reconciler.firewallAssignmentProtectionDeadline = 2 * time.Minute
		reconciler.protectionAuditTimeout = 10 * time.Millisecond
	}
	if fixture.api.firewallAssignmentCalls != fixture.postCount || len(fixture.api.vmDeletes) != 0 || len(cluster.Status.DeleteAttempts) != 0 {
		t.Fatalf("list errors consumed mutation authority: POSTs=%d deletes=%#v status=%#v",
			fixture.api.firewallAssignmentCalls, fixture.api.vmDeletes, cluster.Status.DeleteAttempts)
	}
	attempt := cluster.Status.CreateAttempts[fixture.assignmentKey]
	if attempt.Phase != createAttemptPhaseIssued || attempt.ResourceUUID != "" {
		t.Fatalf("persistent list errors changed issued receipt: %#v", attempt)
	}
}

func TestCrashAfterFirewallProtectionRollbackPersistenceResumes(t *testing.T) {
	fixture := establishAmbiguousBastionAssignment(t, false)
	ageBastionAssignment(t, fixture.cluster)
	cluster := restartClusterFromJSON(t, fixture.cluster)
	reconciler := testReconciler(fixture.api)
	reconciler.firewallAssignmentProtectionDeadline = 2 * time.Minute

	present, err := reconciler.readExactFirewallAssignment(
		context.Background(),
		cluster.Spec.Location,
		&fixture.firewall,
		fixture.vm.UUID,
	)
	if err != nil || present {
		t.Fatalf("pre-crash final assignment authority: present=%t error=%v", present, err)
	}
	candidate, err := reconciler.expiredFixedFirewallAssignmentRollback(cluster, time.Now().UTC())
	if err != nil || candidate == nil {
		t.Fatalf("expired rollback candidate=%#v error=%v", candidate, err)
	}
	if err := reconciler.persistExpiredFirewallAssignmentRollback(context.Background(), cluster, candidate); err != nil {
		t.Fatalf("persist rollback before simulated crash: %v", err)
	}
	if len(fixture.api.vmDeletes) != 0 {
		t.Fatalf("simulated crash boundary already cleaned cloud state: %#v", fixture.api.vmDeletes)
	}

	cluster = restartClusterFromJSON(t, cluster)
	restarted := testReconciler(fixture.api)
	restarted.firewallAssignmentProtectionDeadline = 2 * time.Minute
	if _, err := restarted.Reconcile(context.Background(), cluster, "unit-test-secret-token"); err != nil && !errors.Is(err, ErrCreateAttemptPending) {
		t.Fatalf("resume persisted rollback: %v", err)
	}
	if len(fixture.api.vmDeletes) != 1 || fixture.api.vmDeletes[0] != fixture.vm.UUID {
		t.Fatalf("restart did not resume exact rollback: %#v", fixture.api.vmDeletes)
	}
	if fixture.api.firewallAssignmentCalls != fixture.postCount {
		t.Fatalf("restart replayed assignment before rollback: POSTs=%d want=%d", fixture.api.firewallAssignmentCalls, fixture.postCount)
	}
}

func TestCompletedFirewallProtectionRollbackClearsMixedCaseUUIDReceipts(t *testing.T) {
	fixture := establishAmbiguousBastionAssignment(t, false)
	cluster := restartClusterFromJSON(t, fixture.cluster)
	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))

	vmCreate := cluster.Status.CreateAttempts[createAttemptBastionVM]
	vmCreate.ResourceUUID = strings.ToUpper(vmCreate.ResourceUUID)
	cluster.Status.CreateAttempts[createAttemptBastionVM] = vmCreate
	assignment := cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment]
	assignment.ResourceName = strings.ToUpper(assignment.ResourceName)
	cluster.Status.CreateAttempts[createAttemptBastionFirewallAssignment] = assignment

	normalizedAssignmentName := strings.ToLower(fixture.firewall.UUID) + "/" + strings.ToLower(fixture.vm.UUID)
	if assignment.ResourceName == normalizedAssignmentName {
		t.Fatalf("test fixture did not create a mixed-case assignment identity: %q", assignment.ResourceName)
	}
	cluster.Status.DeleteAttempts = map[string]v1alpha1.ResourceDeleteAttemptStatus{
		deleteAttemptBastion: {
			ResourceKind:   deleteAttemptKindVM,
			ResourceName:   fixture.vm.Name,
			ResourceUUID:   strings.ToLower(fixture.vm.UUID),
			FirewallUUID:   strings.ToLower(fixture.firewall.UUID),
			Location:       cluster.Spec.Location,
			Owner:          ownerKey(cluster),
			Purpose:        deletePurposeRollback,
			Phase:          deletePhaseAbsent,
			FloatingIPName: resourceNames.BastionFloatingIP,
		},
	}

	reconciler := testReconciler(fixture.api)
	if err := reconciler.clearCompletedRollback(context.Background(), cluster, deleteAttemptBastion); err != nil {
		t.Fatalf("clear mixed-case rollback receipt: %v", err)
	}
	for _, key := range []string{
		createAttemptBastionVM,
		createAttemptBastionFirewallAssignment,
		createAttemptBastionFloatingIPUpdate,
	} {
		if _, exists := cluster.Status.CreateAttempts[key]; exists {
			t.Fatalf("completed mixed-case rollback retained create receipt %q", key)
		}
	}
	if _, exists := cluster.Status.DeleteAttempts[deleteAttemptBastion]; exists {
		t.Fatalf("completed mixed-case rollback retained delete receipt")
	}
}
