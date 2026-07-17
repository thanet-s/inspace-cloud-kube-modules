package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const defaultFirewallAssignmentProtectionDeadline = 2 * time.Minute

var errFirewallAssignmentProtectionRollback = errors.New("bootstrap: expired firewall protection is being rolled back")

type fixedFirewallAssignmentSlot struct {
	assignmentKey string
	vmCreateKey   string
	vmDeleteKey   string
	firewallKey   string
	currentVMName string
	legacyVMName  string
	currentFWName string
	legacyFWName  string
	currentFIP    string
	legacyFIP     string
}

type expiredFirewallAssignmentRollback struct {
	slot       fixedFirewallAssignmentSlot
	assignment v1alpha1.ResourceCreateAttemptStatus
	vmCreate   v1alpha1.ResourceCreateAttemptStatus
	firewall   v1alpha1.ResourceCreateAttemptStatus
	vmName     string
	vmUUID     string
	firewallID string
	fipName    string
}

func fixedFirewallAssignmentSlots(cluster *v1alpha1.InSpaceCluster) []fixedFirewallAssignmentSlot {
	owner := ownerKey(cluster)
	current := currentBootstrapResourceNames(cluster.Metadata.Name, owner)
	legacy := legacyBootstrapResourceNames(owner)
	slots := make([]fixedFirewallAssignmentSlot, 0, ControlPlaneReplicas+1)
	slots = append(slots, fixedFirewallAssignmentSlot{
		assignmentKey: createAttemptBastionFirewallAssignment,
		vmCreateKey:   createAttemptBastionVM,
		vmDeleteKey:   deleteAttemptBastion,
		firewallKey:   createAttemptBastionFirewall,
		currentVMName: currentBastionName(cluster.Metadata.Name),
		legacyVMName:  legacyBastionName(owner),
		currentFWName: current.BastionFirewall,
		legacyFWName:  legacy.BastionFirewall,
		currentFIP:    current.BastionFloatingIP,
		legacyFIP:     legacy.BastionFloatingIP,
	})
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		slots = append(slots, fixedFirewallAssignmentSlot{
			assignmentKey: controlPlaneFirewallAssignmentAttemptKey(slot),
			vmCreateKey:   controlPlaneCreateAttemptKey(slot),
			vmDeleteKey:   controlPlaneDeleteAttemptKey(slot),
			firewallKey:   createAttemptNodeFirewall,
			currentVMName: controlPlaneName(cluster.Metadata.Name, slot),
			legacyVMName:  legacyControlPlaneName(owner, slot),
			currentFWName: current.NodeFirewall,
			legacyFWName:  legacy.NodeFirewall,
			currentFIP:    current.ControlPlaneFIP[slot],
			legacyFIP:     legacy.ControlPlaneFIP[slot],
		})
	}
	return slots
}

func fixedSlotTopology(slot fixedFirewallAssignmentSlot, vmName, firewallName string) (string, bool) {
	switch {
	case vmName == slot.currentVMName && firewallName == slot.currentFWName:
		return slot.currentFIP, true
	case vmName == slot.legacyVMName && firewallName == slot.legacyFWName:
		return slot.legacyFIP, true
	default:
		return "", false
	}
}

// expiredFixedFirewallAssignmentRollback recognizes only a controller-created
// fixed bootstrap VM with a materialized exact UUID. Adopted VMs are excluded:
// an unresolved relationship write is never authority to delete infrastructure
// that this create ledger did not materialize.
func (r *Reconciler) expiredFixedFirewallAssignmentRollback(
	cluster *v1alpha1.InSpaceCluster,
	now time.Time,
) (*expiredFirewallAssignmentRollback, error) {
	if cluster == nil {
		return nil, errors.New("bootstrap: firewall protection rollback requires a cluster")
	}
	r.statusMu.Lock()
	status := cloneClusterStatus(cluster.Status)
	r.statusMu.Unlock()

	deadline := configuredDuration(
		r.firewallAssignmentProtectionDeadline,
		defaultFirewallAssignmentProtectionDeadline,
	)
	var candidate *expiredFirewallAssignmentRollback
	for _, slot := range fixedFirewallAssignmentSlots(cluster) {
		assignment, exists := status.CreateAttempts[slot.assignmentKey]
		if !exists || assignment.Phase != createAttemptPhaseIssued {
			continue
		}
		firewallUUID, parseErr := firewallAssignmentResourceFirewallUUID(assignment.ResourceName)
		if parseErr != nil {
			return nil, fmt.Errorf("bootstrap: fixed firewall assignment %q: %w", slot.assignmentKey, parseErr)
		}
		parts := strings.Split(assignment.ResourceName, "/")
		vmUUID := strings.ToLower(parts[1])
		expectedAssignmentHash, hashErr := createIntentHash(
			createAttemptKindFirewallAssignment,
			assignment.ResourceName,
			firewallAssignmentIntent{
				Location:     cluster.Spec.Location,
				FirewallUUID: parts[0],
				VMUUID:       parts[1],
			},
		)
		if hashErr != nil {
			return nil, hashErr
		}
		if err := validateCreateAttempt(
			assignment,
			createAttemptKindFirewallAssignment,
			assignment.ResourceName,
			expectedAssignmentHash,
		); err != nil {
			return nil, fmt.Errorf("bootstrap: fixed firewall assignment %q: %w", slot.assignmentKey, err)
		}
		issuedAt, parseErr := time.Parse(time.RFC3339Nano, assignment.IssuedAt)
		if parseErr != nil || issuedAt.Location() != time.UTC {
			return nil, fmt.Errorf("bootstrap: fixed firewall assignment %q has invalid durable issue time", slot.assignmentKey)
		}
		if now.Before(issuedAt.Add(deadline)) {
			continue
		}

		vmCreate, exists := status.CreateAttempts[slot.vmCreateKey]
		if !exists {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q lacks its exact VM create receipt", slot.assignmentKey)
		}
		if err := validateCreateAttempt(
			vmCreate,
			createAttemptKindVM,
			vmCreate.ResourceName,
			vmCreate.IntentHash,
		); err != nil {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q VM receipt: %w", slot.assignmentKey, err)
		}
		if vmCreate.Phase != createAttemptPhaseMaterialized {
			// An adopted VM is deliberately not eligible for automatic
			// containment. Its issued relationship receipt remains a read-only
			// lock for explicit operator recovery.
			continue
		}
		if !strings.EqualFold(vmCreate.ResourceUUID, vmUUID) ||
			(vmCreate.ResourceName != slot.currentVMName && vmCreate.ResourceName != slot.legacyVMName) {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q changed exact VM slot identity", slot.assignmentKey)
		}

		firewall, exists := status.CreateAttempts[slot.firewallKey]
		if !exists {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q lacks its exact firewall create receipt", slot.assignmentKey)
		}
		if err := validateCreateAttempt(
			firewall,
			createAttemptKindFirewall,
			firewall.ResourceName,
			firewall.IntentHash,
		); err != nil {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q firewall receipt: %w", slot.assignmentKey, err)
		}
		if firewall.Phase != createAttemptPhaseMaterialized && firewall.Phase != createAttemptPhaseAdopted {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q firewall is not anchored", slot.assignmentKey)
		}
		if !strings.EqualFold(firewall.ResourceUUID, firewallUUID) {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q changed exact firewall UUID", slot.assignmentKey)
		}
		fipName, topologyOK := fixedSlotTopology(slot, vmCreate.ResourceName, firewall.ResourceName)
		if !topologyOK {
			return nil, fmt.Errorf("bootstrap: expired firewall assignment %q has mixed fixed-bootstrap topology", slot.assignmentKey)
		}
		if candidate != nil {
			return nil, errors.New("bootstrap: multiple fixed firewall assignments crossed the protection deadline")
		}
		candidate = &expiredFirewallAssignmentRollback{
			slot:       slot,
			assignment: assignment,
			vmCreate:   vmCreate,
			firewall:   firewall,
			vmName:     vmCreate.ResourceName,
			vmUUID:     vmUUID,
			firewallID: strings.ToLower(firewallUUID),
			fipName:    fipName,
		}
	}
	return candidate, nil
}

// persistExpiredFirewallAssignmentRollback converts an unchanged, expired
// assignment issue into the existing exact VM rollback state machine in one
// status CAS. A concurrent assignment readback that materializes the receipt
// wins the CAS and prevents deletion.
func (r *Reconciler) persistExpiredFirewallAssignmentRollback(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	candidate *expiredFirewallAssignmentRollback,
) error {
	if candidate == nil {
		return errors.New("bootstrap: expired firewall protection rollback candidate is required")
	}
	deadline := configuredDuration(
		r.firewallAssignmentProtectionDeadline,
		defaultFirewallAssignmentProtectionDeadline,
	)
	persistCtx, cancel := r.detachedStatusMutationContext(ctx)
	defer cancel()
	return r.compareAndSwapClusterStatus(persistCtx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		assignment, exists := status.CreateAttempts[candidate.slot.assignmentKey]
		if !exists || assignment != candidate.assignment || assignment.Phase != createAttemptPhaseIssued {
			return fmt.Errorf("%w: firewall assignment %q changed before rollback persistence", ErrCreateAttemptPending, candidate.slot.assignmentKey)
		}
		vmCreate, exists := status.CreateAttempts[candidate.slot.vmCreateKey]
		if !exists || vmCreate != candidate.vmCreate || vmCreate.Phase != createAttemptPhaseMaterialized ||
			!strings.EqualFold(vmCreate.ResourceUUID, candidate.vmUUID) {
			return fmt.Errorf("%w: VM create receipt changed before firewall protection rollback", ErrCreateAttemptPending)
		}
		firewall, exists := status.CreateAttempts[candidate.slot.firewallKey]
		if !exists || firewall != candidate.firewall ||
			!strings.EqualFold(firewall.ResourceUUID, candidate.firewallID) {
			return fmt.Errorf("%w: firewall create receipt changed before protection rollback", ErrCreateAttemptPending)
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, assignment.IssuedAt)
		if err != nil || issuedAt.Location() != time.UTC || time.Now().UTC().Before(issuedAt.Add(deadline)) {
			return fmt.Errorf("%w: firewall assignment %q has not retained expired issue authority", ErrCreateAttemptPending, candidate.slot.assignmentKey)
		}

		desired := v1alpha1.ResourceDeleteAttemptStatus{
			ResourceKind:   deleteAttemptKindVM,
			ResourceName:   candidate.vmName,
			ResourceUUID:   candidate.vmUUID,
			FirewallUUID:   candidate.firewallID,
			Location:       cluster.Spec.Location,
			Owner:          ownerKey(cluster),
			Purpose:        deletePurposeRollback,
			Phase:          deletePhaseRollbackFIPDiscovery,
			FloatingIPName: candidate.fipName,
		}
		if status.DeleteAttempts == nil {
			status.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus)
		}
		if current, exists := status.DeleteAttempts[candidate.slot.vmDeleteKey]; exists {
			if err := validateVMDeleteAttempt(cluster, candidate.slot.vmDeleteKey, current); err != nil {
				return err
			}
			if current.ResourceName != desired.ResourceName ||
				!strings.EqualFold(current.ResourceUUID, desired.ResourceUUID) ||
				!strings.EqualFold(current.FirewallUUID, desired.FirewallUUID) ||
				current.Purpose != desired.Purpose ||
				current.FloatingIPName != desired.FloatingIPName {
				return fmt.Errorf("bootstrap: firewall protection rollback slot %q is anchored to another deletion", candidate.slot.vmDeleteKey)
			}
			return nil
		}
		status.DeleteAttempts[candidate.slot.vmDeleteKey] = desired
		return nil
	})
}

// containExpiredFirewallAssignment persists rollback before performing any
// cleanup. Returning started=true always stops normal bootstrap reconciliation,
// including when the first bounded rollback step happens to complete.
func (r *Reconciler) containExpiredFirewallAssignment(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
) (bool, error) {
	candidate, err := r.expiredFixedFirewallAssignmentRollback(cluster, time.Now().UTC())
	if err != nil || candidate == nil {
		return false, err
	}
	if err := r.persistExpiredFirewallAssignmentRollback(ctx, cluster, candidate); err != nil {
		return true, errors.Join(errFirewallAssignmentProtectionRollback, err)
	}
	_, rollbackErr := r.reconcileRollbackDelete(context.WithoutCancel(ctx), cluster, candidate.slot.vmDeleteKey)
	return true, errors.Join(
		errFirewallAssignmentProtectionRollback,
		rollbackErr,
		fmt.Errorf(
			"%w: firewall assignment %q exceeded its durable protection deadline",
			ErrCreateAttemptPending,
			candidate.slot.assignmentKey,
		),
	)
}
