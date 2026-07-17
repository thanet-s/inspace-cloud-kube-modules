package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const (
	deleteAttemptKindVM         = "virtual-machine"
	deleteAttemptKindFloatingIP = "floating-ip"
	deleteAttemptKindFirewall   = "firewall"

	deletePurposeDestroy  = "destroy"
	deletePurposeRollback = "malformed-create-rollback"

	deletePhaseRollbackFIPDiscovery      = "rollback-fip-discovery"
	deletePhaseRollbackFIPAfterVM        = "rollback-fip-after-vm"
	deletePhaseRollbackFIPUnassignIntent = "rollback-fip-unassign-intent"
	deletePhaseRollbackFIPUnassignIssued = "rollback-fip-unassign-issued"
	deletePhaseRollbackFIPDeleteIntent   = "rollback-fip-delete-intent"
	deletePhaseRollbackFIPDeleteIssued   = "rollback-fip-delete-issued"
	deletePhaseVMIntent                  = "vm-delete-intent"
	deletePhaseVMIssued                  = "vm-delete-issued"
	deletePhaseAbsent                    = "absent"
	deletePhaseFIPUnassignIntent         = "floating-ip-unassign-intent"
	deletePhaseFIPUnassignIssued         = "floating-ip-unassign-issued"
	deletePhaseFIPDeleteIntent           = "floating-ip-delete-intent"
	deletePhaseFIPDeleteIssued           = "floating-ip-delete-issued"
	deletePhaseFirewallDeleteIntent      = "firewall-delete-intent"
	deletePhaseFirewallDeleteIssued      = "firewall-delete-issued"

	deleteAttemptBastion = "vm-delete/bastion"
	// InSpace exposes several independently converging read models. Destructive
	// absence may only advance after a fresh exact-detail + location inventory +
	// configured-VPC observation separated by a real convergence window.
	defaultVMAbsenceObservationMinInterval = 30 * time.Second
)

func controlPlaneDeleteAttemptKey(slot int) string {
	return fmt.Sprintf("vm-delete/control-plane-%d", slot)
}

func vmDeleteAttemptKeyForCreateKey(createKey string) (string, error) {
	if createKey == createAttemptBastionVM {
		return deleteAttemptBastion, nil
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if createKey == controlPlaneCreateAttemptKey(slot) {
			return controlPlaneDeleteAttemptKey(slot), nil
		}
	}
	return "", fmt.Errorf("bootstrap: VM create-attempt key %q has no delete slot", createKey)
}

func createKeyForVMDeleteAttempt(deleteKey string) (string, string, error) {
	if deleteKey == deleteAttemptBastion {
		return createAttemptBastionVM, createAttemptBastionFirewallAssignment, nil
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if deleteKey == controlPlaneDeleteAttemptKey(slot) {
			return controlPlaneCreateAttemptKey(slot), controlPlaneFirewallAssignmentAttemptKey(slot), nil
		}
	}
	return "", "", fmt.Errorf("bootstrap: unknown VM delete-attempt key %q", deleteKey)
}

func expectedVMNameForDeleteKey(cluster *v1alpha1.InSpaceCluster, key string) (string, error) {
	if cluster == nil {
		return "", errors.New("bootstrap: VM delete attempt requires a cluster")
	}
	if key == deleteAttemptBastion {
		return currentBastionName(cluster.Metadata.Name), nil
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if key == controlPlaneDeleteAttemptKey(slot) {
			return controlPlaneName(cluster.Metadata.Name, slot), nil
		}
	}
	return "", fmt.Errorf("bootstrap: unknown VM delete-attempt key %q", key)
}

func deleteKeyForVMName(cluster *v1alpha1.InSpaceCluster, name string) (string, error) {
	if name == currentBastionName(cluster.Metadata.Name) || name == legacyBastionName(ownerKey(cluster)) {
		return deleteAttemptBastion, nil
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if name == controlPlaneName(cluster.Metadata.Name, slot) || name == legacyControlPlaneName(ownerKey(cluster), slot) {
			return controlPlaneDeleteAttemptKey(slot), nil
		}
	}
	return "", fmt.Errorf("bootstrap: VM %q has no owned delete slot", name)
}

func validDeleteIssue(attempt v1alpha1.ResourceDeleteAttemptStatus) bool {
	if len(attempt.IssueID) != 32 {
		return false
	}
	if _, err := newCreateIssueIDFromHex(attempt.IssueID); err != nil {
		return false
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, attempt.IssuedAt)
	return err == nil && issuedAt.Location() == time.UTC
}

// newCreateIssueIDFromHex shares the create-fence issue format without
// accepting arbitrary strings as a destructive-mutation authority.
func newCreateIssueIDFromHex(value string) ([]byte, error) {
	if len(value) != 32 {
		return nil, errors.New("invalid issue ID length")
	}
	decoded := make([]byte, 16)
	for i := 0; i < len(decoded); i++ {
		hi := strings.IndexByte("0123456789abcdef", value[i*2])
		lo := strings.IndexByte("0123456789abcdef", value[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("invalid issue ID encoding")
		}
		decoded[i] = byte(hi<<4 | lo)
	}
	return decoded, nil
}

func validateVMDeleteAttempt(cluster *v1alpha1.InSpaceCluster, key string, attempt v1alpha1.ResourceDeleteAttemptStatus) error {
	if cluster == nil {
		return errors.New("bootstrap: VM delete attempt requires a cluster")
	}
	expectedName, err := expectedVMNameForDeleteKey(cluster, key)
	if err != nil {
		return err
	}
	legacyName := ""
	if key == deleteAttemptBastion {
		legacyName = legacyBastionName(ownerKey(cluster))
	} else {
		for slot := 0; slot < ControlPlaneReplicas; slot++ {
			if key == controlPlaneDeleteAttemptKey(slot) {
				legacyName = legacyControlPlaneName(ownerKey(cluster), slot)
			}
		}
	}
	if attempt.ResourceKind != deleteAttemptKindVM || (attempt.ResourceName != expectedName && attempt.ResourceName != legacyName) ||
		!vmUUIDPattern.MatchString(attempt.ResourceUUID) || attempt.Location != cluster.Spec.Location || attempt.Owner != ownerKey(cluster) {
		return fmt.Errorf("bootstrap: durable VM delete attempt %q does not match the exact cluster/slot identity", key)
	}
	if attempt.FirewallUUID != "" && !vmUUIDPattern.MatchString(attempt.FirewallUUID) {
		return fmt.Errorf("bootstrap: durable VM delete attempt %q has invalid firewall UUID", key)
	}
	switch attempt.Purpose {
	case deletePurposeDestroy:
		if attempt.FloatingIPName != "" || attempt.FloatingIPAddress != "" {
			return fmt.Errorf("bootstrap: destroy VM delete attempt %q contains rollback floating-IP identity", key)
		}
	case deletePurposeRollback:
		if attempt.FloatingIPName == "" {
			return fmt.Errorf("bootstrap: rollback VM delete attempt %q lacks its floating-IP name", key)
		}
	default:
		return fmt.Errorf("bootstrap: VM delete attempt %q has unknown purpose %q", key, attempt.Purpose)
	}
	issued := attempt.Phase == deletePhaseRollbackFIPUnassignIssued || attempt.Phase == deletePhaseRollbackFIPDeleteIssued || attempt.Phase == deletePhaseVMIssued
	if issued {
		if !validDeleteIssue(attempt) {
			return fmt.Errorf("bootstrap: issued VM delete attempt %q has invalid issue identity", key)
		}
	} else if attempt.IssueID != "" || attempt.IssuedAt != "" {
		return fmt.Errorf("bootstrap: non-issued VM delete attempt %q contains issue identity", key)
	}
	switch attempt.Phase {
	case deletePhaseRollbackFIPDiscovery:
		if attempt.Purpose != deletePurposeRollback || attempt.FloatingIPAddress != "" {
			return fmt.Errorf("bootstrap: invalid rollback discovery receipt %q", key)
		}
	case deletePhaseRollbackFIPAfterVM:
		if attempt.Purpose != deletePurposeRollback {
			return fmt.Errorf("bootstrap: invalid post-VM rollback receipt %q", key)
		}
	case deletePhaseRollbackFIPUnassignIntent, deletePhaseRollbackFIPUnassignIssued,
		deletePhaseRollbackFIPDeleteIntent, deletePhaseRollbackFIPDeleteIssued:
		if attempt.Purpose != deletePurposeRollback || attempt.FloatingIPAddress == "" {
			return fmt.Errorf("bootstrap: rollback receipt %q lacks exact floating-IP identity", key)
		}
	case deletePhaseVMIntent, deletePhaseVMIssued, deletePhaseAbsent:
	default:
		return fmt.Errorf("bootstrap: VM delete attempt %q has unknown phase %q", key, attempt.Phase)
	}
	if attempt.AbsenceObservedAt != "" {
		observedAt, err := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
		allowedPhase := attempt.Phase == deletePhaseVMIntent || attempt.Phase == deletePhaseVMIssued ||
			attempt.Phase == deletePhaseRollbackFIPAfterVM || attempt.Phase == deletePhaseRollbackFIPUnassignIssued ||
			attempt.Phase == deletePhaseRollbackFIPDeleteIssued
		if err != nil || observedAt.Location() != time.UTC || !allowedPhase {
			return fmt.Errorf("bootstrap: VM delete attempt %q has invalid first-absence observation", key)
		}
	}
	return nil
}

func (r *Reconciler) deleteAttempt(cluster *v1alpha1.InSpaceCluster, key string) (v1alpha1.ResourceDeleteAttemptStatus, bool) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	attempt, ok := cluster.Status.DeleteAttempts[key]
	return attempt, ok
}

func (r *Reconciler) mutateDeleteAttempt(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string, mutate func(*v1alpha1.ResourceDeleteAttemptStatus) error) error {
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		if status.DeleteAttempts == nil {
			status.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus)
		}
		attempt, ok := status.DeleteAttempts[key]
		if !ok {
			return fmt.Errorf("bootstrap: VM delete attempt %q disappeared", key)
		}
		if err := mutate(&attempt); err != nil {
			return err
		}
		status.DeleteAttempts[key] = attempt
		return nil
	})
}

func (r *Reconciler) ensureVMDeleteAttempt(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key, purpose string, vm *inspace.VM, firewallUUID, floatingIPName string) error {
	if vm == nil || !vmUUIDPattern.MatchString(vm.UUID) {
		return errors.New("bootstrap: cannot persist VM deletion without an exact VM UUID")
	}
	initialPhase := deletePhaseVMIntent
	if purpose == deletePurposeRollback {
		initialPhase = deletePhaseRollbackFIPDiscovery
	}
	desired := v1alpha1.ResourceDeleteAttemptStatus{
		ResourceKind: deleteAttemptKindVM, ResourceName: vm.Name, ResourceUUID: strings.ToLower(vm.UUID),
		FirewallUUID: strings.ToLower(firewallUUID), Location: cluster.Spec.Location, Owner: ownerKey(cluster),
		Purpose: purpose, Phase: initialPhase, FloatingIPName: floatingIPName,
	}
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		if status.DeleteAttempts == nil {
			status.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus)
		}
		if current, ok := status.DeleteAttempts[key]; ok {
			if err := validateVMDeleteAttempt(cluster, key, current); err != nil {
				return err
			}
			if current.ResourceUUID != desired.ResourceUUID || current.ResourceName != desired.ResourceName ||
				current.FirewallUUID != desired.FirewallUUID || current.Purpose != purpose || current.FloatingIPName != floatingIPName {
				return fmt.Errorf("bootstrap: VM delete slot %q is already anchored to another exact deletion", key)
			}
			return nil
		}
		status.DeleteAttempts[key] = desired
		return nil
	})
}

func setDeleteAttemptPhase(attempt *v1alpha1.ResourceDeleteAttemptStatus, phase string) {
	attempt.Phase = phase
	attempt.IssueID = ""
	attempt.IssuedAt = ""
	attempt.AbsenceObservedAt = ""
}

func (r *Reconciler) issueDeleteAttempt(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key, expectedPhase, issuedPhase string) (bool, error) {
	issueID, err := newCreateIssueID()
	if err != nil {
		return false, err
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	err = r.mutateDeleteAttempt(ctx, cluster, key, func(attempt *v1alpha1.ResourceDeleteAttemptStatus) error {
		if err := validateVMDeleteAttempt(cluster, key, *attempt); err != nil {
			return err
		}
		if attempt.Phase != expectedPhase {
			return fmt.Errorf("%w: VM delete attempt %q is already in phase %q", ErrCreateAttemptPending, key, attempt.Phase)
		}
		attempt.Phase = issuedPhase
		attempt.IssueID = issueID
		attempt.IssuedAt = issuedAt
		return nil
	})
	return err == nil, err
}

func (r *Reconciler) observeExactVMDeletion(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: VM delete attempt %q disappeared before readback", key)
	}
	if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
		return false, err
	}
	detail, err := r.API.GetVM(ctx, attempt.Location, attempt.ResourceUUID)
	deletedTombstone := err == nil && detail != nil && strings.EqualFold(strings.TrimSpace(detail.Status), "deleted")
	if err != nil || deletedTombstone {
		if !inspace.IsNotFound(err) {
			if !deletedTombstone {
				return false, fmt.Errorf("bootstrap: read back VM %s after delete: %w", attempt.ResourceUUID, err)
			}
			if !strings.EqualFold(detail.UUID, attempt.ResourceUUID) || detail.Name != attempt.ResourceName ||
				detail.BillingAccountID != cluster.Spec.BillingAccountID ||
				(detail.NetworkUUID != "" && !strings.EqualFold(detail.NetworkUUID, cluster.Spec.Network.UUID)) {
				return false, fmt.Errorf("bootstrap: deleted VM tombstone for %q changed exact UUID/name/billing/VPC identity", attempt.ResourceName)
			}
		}
		corroborated, corroborateErr := r.corroborateVMDeletionAbsence(ctx, cluster, key, attempt)
		if corroborateErr != nil || !corroborated {
			return false, corroborateErr
		}
		now := time.Now().UTC()
		if attempt.AbsenceObservedAt == "" {
			if casErr := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
				if current.ResourceUUID != attempt.ResourceUUID || current.Phase != attempt.Phase || current.AbsenceObservedAt != "" {
					return fmt.Errorf("bootstrap: VM delete attempt %q changed before first absence observation", key)
				}
				current.AbsenceObservedAt = now.Format(time.RFC3339Nano)
				return nil
			}); casErr != nil {
				return false, casErr
			}
			return false, fmt.Errorf("%w: VM %s requires a second spaced authoritative absence observation", ErrRetryableAmbiguousVMDelete, attempt.ResourceUUID)
		}
		firstObserved, parseErr := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
		if parseErr != nil || firstObserved.Location() != time.UTC {
			return false, fmt.Errorf("bootstrap: VM delete attempt %q has invalid absence observation time", key)
		}
		spacing := configuredDuration(r.vmAbsenceObservationMinInterval, defaultVMAbsenceObservationMinInterval)
		if now.Before(firstObserved.Add(spacing)) {
			return false, fmt.Errorf("%w: VM %s second absence observation was not spaced after the first", ErrRetryableAmbiguousVMDelete, attempt.ResourceUUID)
		}
		if casErr := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.ResourceUUID != attempt.ResourceUUID || current.Phase != attempt.Phase || current.AbsenceObservedAt != attempt.AbsenceObservedAt {
				return fmt.Errorf("bootstrap: VM delete attempt %q changed before absence persistence", key)
			}
			if current.Purpose == deletePurposeRollback {
				setDeleteAttemptPhase(current, deletePhaseRollbackFIPAfterVM)
			} else {
				setDeleteAttemptPhase(current, deletePhaseAbsent)
			}
			return nil
		}); casErr != nil {
			return false, casErr
		}
		return true, nil
	}
	if detail == nil || !strings.EqualFold(detail.UUID, attempt.ResourceUUID) || detail.Name != attempt.ResourceName {
		return false, fmt.Errorf("bootstrap: VM delete readback for %q changed exact UUID/name identity", attempt.ResourceName)
	}
	if attempt.AbsenceObservedAt != "" {
		if err := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.ResourceUUID != attempt.ResourceUUID || current.Phase != attempt.Phase {
				return fmt.Errorf("bootstrap: VM delete attempt %q changed before clearing transient absence", key)
			}
			current.AbsenceObservedAt = ""
			return nil
		}); err != nil {
			return false, err
		}
	}
	// Presence never grants a second DELETE. Once a request was dispatched the
	// issued receipt remains a permanent safety lock until exact absence is
	// observed (or an operator deliberately repairs the receipt).
	return false, nil
}

func (r *Reconciler) corroborateVMDeletionAbsence(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	attempt v1alpha1.ResourceDeleteAttemptStatus,
) (bool, error) {
	vms, err := r.API.ListVMs(ctx, attempt.Location)
	if err != nil {
		return false, fmt.Errorf("bootstrap: list VMs while corroborating deletion of %s: %w", attempt.ResourceUUID, err)
	}
	listMatches := 0
	for index := range vms {
		vm := &vms[index]
		if strings.EqualFold(vm.UUID, attempt.ResourceUUID) {
			listMatches++
			if vm.Name != attempt.ResourceName ||
				(vm.BillingAccountID != 0 && vm.BillingAccountID != cluster.Spec.BillingAccountID) ||
				(vm.NetworkUUID != "" && !strings.EqualFold(vm.NetworkUUID, cluster.Spec.Network.UUID)) {
				return false, fmt.Errorf("bootstrap: VM %s location inventory changed exact ownership while deletion is pending", attempt.ResourceUUID)
			}
			continue
		}
		if vm.Name == attempt.ResourceName {
			return false, fmt.Errorf("bootstrap: VM name %q was reused by UUID %q while exact deletion is pending", attempt.ResourceName, vm.UUID)
		}
	}
	if listMatches > 1 {
		return false, fmt.Errorf("bootstrap: VM %s appears multiple times in the location inventory", attempt.ResourceUUID)
	}
	network, err := r.API.GetNetwork(ctx, attempt.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return false, fmt.Errorf("bootstrap: read configured VPC while corroborating deletion of %s: %w", attempt.ResourceUUID, err)
	}
	if network == nil || !strings.EqualFold(network.UUID, cluster.Spec.Network.UUID) {
		return false, fmt.Errorf("bootstrap: configured VPC identity changed while corroborating deletion of %s", attempt.ResourceUUID)
	}
	members, membershipErr := canonicalConfiguredVPCVMUUIDs(network)
	if membershipErr != nil {
		return false, fmt.Errorf(
			"bootstrap: configured VPC membership while corroborating deletion of %s: %w",
			attempt.ResourceUUID,
			membershipErr,
		)
	}
	networkMatches := 0
	if _, present := members[strings.ToLower(attempt.ResourceUUID)]; present {
		networkMatches = 1
	}
	if listMatches == 0 && networkMatches == 0 {
		return true, nil
	}
	if attempt.AbsenceObservedAt != "" {
		if clearErr := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.ResourceUUID != attempt.ResourceUUID || current.Phase != attempt.Phase || current.AbsenceObservedAt != attempt.AbsenceObservedAt {
				return fmt.Errorf("bootstrap: VM delete attempt %q changed before clearing split-view absence", key)
			}
			current.AbsenceObservedAt = ""
			return nil
		}); clearErr != nil {
			return false, clearErr
		}
	}
	return false, fmt.Errorf("%w: VM %s detail was absent while location/VPC inventory still reported it", ErrRetryableAmbiguousVMDelete, attempt.ResourceUUID)
}

func (r *Reconciler) reconcileVMDelete(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: VM delete attempt %q is missing", key)
	}
	if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
		return false, err
	}
	switch attempt.Phase {
	case deletePhaseAbsent:
		return true, nil
	case deletePhaseVMIssued:
		absent, observeErr := r.observeExactVMDeletion(ctx, cluster, key)
		if !absent && errors.Is(observeErr, ErrRetryableAmbiguousVMDelete) {
			return false, nil
		}
		return absent, observeErr
	case deletePhaseVMIntent:
	default:
		return false, fmt.Errorf("bootstrap: VM delete attempt %q is not ready for VM deletion from phase %q", key, attempt.Phase)
	}
	allowed, err := r.issueDeleteAttempt(ctx, cluster, key, deletePhaseVMIntent, deletePhaseVMIssued)
	if err != nil || !allowed {
		return false, err
	}
	issuedAttempt, issuedExists := r.deleteAttempt(cluster, key)
	if !issuedExists {
		return false, fmt.Errorf("bootstrap: VM delete attempt %q disappeared after issue persistence", key)
	}
	present, ownershipErr := r.authorizeVMDeleteDispatch(ctx, cluster, key, issuedAttempt)
	if ownershipErr != nil {
		resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseVMIssued, deletePhaseVMIntent)
		return false, errors.Join(ownershipErr, resetErr,
			fmt.Errorf("%w: VM delete %q lacks post-CAS ownership authority", ErrCreateAttemptPending, key))
	}
	if !present {
		// Do not dispatch DELETE for an already-absent object. Preserve the
		// issued resolution lock while the same multi-source, spaced absence
		// contract used for ambiguous DELETE outcomes converges.
		absent, observeErr := r.observeExactVMDeletion(ctx, cluster, key)
		if !absent && errors.Is(observeErr, ErrRetryableAmbiguousVMDelete) {
			return false, nil
		}
		return absent, observeErr
	}
	deleteCtx, deleteCancel := context.WithTimeout(context.WithoutCancel(ctx), configuredDuration(r.createdVMDeleteTimeout, defaultCreatedVMDeleteTimeout))
	deleteErr := r.API.DeleteVM(deleteCtx, attempt.Location, attempt.ResourceUUID)
	deleteCancel()
	if deleteVMFailureProvesNoDispatch(deleteErr) {
		resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseVMIssued, deletePhaseVMIntent)
		return false, errors.Join(deleteErr, resetErr)
	}
	absent, readErr := r.observeExactVMDeletion(ctx, cluster, key)
	if absent {
		return true, readErr
	}
	if deleteErr == nil && errors.Is(readErr, ErrRetryableAmbiguousVMDelete) {
		return false, nil
	}
	if deleteErr == nil {
		deleteErr = errors.New("bootstrap: VM DELETE returned success without authoritative absence")
	}
	return false, errors.Join(fmt.Errorf("%w: VM %s delete outcome is unresolved", ErrRetryableAmbiguousVMDelete, attempt.ResourceUUID), deleteErr, readErr)
}

// authorizeVMDeleteDispatch re-proves the exact live VM immediately before the
// irreversible request. A durable UUID/name receipt is not permanent cloud
// mutation authority: API responses can be stale or malformed, and the object
// behind a UUID can drift while a controller is down. Exact detail, location
// inventory, controller ownership metadata, billing, and configured-VPC
// membership must all agree in the same reconciliation pass.
func (r *Reconciler) authorizeVMDeleteDispatch(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	attempt v1alpha1.ResourceDeleteAttemptStatus,
) (bool, error) {
	if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
		return false, err
	}
	detail, err := r.API.GetVM(ctx, attempt.Location, attempt.ResourceUUID)
	if err != nil {
		if inspace.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("bootstrap: pre-delete exact VM read for %s: %w", attempt.ResourceUUID, err)
	}
	if detail == nil || !strings.EqualFold(detail.UUID, attempt.ResourceUUID) || detail.Name != attempt.ResourceName {
		return false, fmt.Errorf("bootstrap: pre-delete exact VM identity for %q does not match its durable receipt", attempt.ResourceName)
	}
	if detail.BillingAccountID != cluster.Spec.BillingAccountID {
		return false, fmt.Errorf("bootstrap: refusing to delete VM %q without exact billing-account ownership", attempt.ResourceName)
	}
	if detail.NetworkUUID != "" && !strings.EqualFold(detail.NetworkUUID, cluster.Spec.Network.UUID) {
		return false, fmt.Errorf("bootstrap: refusing to delete VM %q from another private network", attempt.ResourceName)
	}
	if strings.EqualFold(strings.TrimSpace(detail.Status), "deleted") {
		corroborated, corroborateErr := r.corroborateVMDeletionAbsence(ctx, cluster, key, attempt)
		if corroborateErr != nil || !corroborated {
			return false, errors.Join(corroborateErr,
				fmt.Errorf("bootstrap: deleted VM tombstone %s lacks List/VPC absence", attempt.ResourceUUID))
		}
		return false, nil
	}

	listed, err := r.API.ListVMs(ctx, attempt.Location)
	if err != nil {
		return false, fmt.Errorf("bootstrap: pre-delete location inventory for VM %s: %w", attempt.ResourceUUID, err)
	}
	exactMatches := 0
	for index := range listed {
		candidate := &listed[index]
		if strings.EqualFold(candidate.UUID, attempt.ResourceUUID) {
			exactMatches++
			if candidate.Name != attempt.ResourceName ||
				(candidate.BillingAccountID != 0 && candidate.BillingAccountID != cluster.Spec.BillingAccountID) ||
				(candidate.NetworkUUID != "" && !strings.EqualFold(candidate.NetworkUUID, cluster.Spec.Network.UUID)) {
				return false, fmt.Errorf("bootstrap: pre-delete location inventory changed ownership for VM %s", attempt.ResourceUUID)
			}
			continue
		}
		if candidate.Name == attempt.ResourceName {
			return false, fmt.Errorf("bootstrap: pre-delete VM name %q is also held by UUID %q", attempt.ResourceName, candidate.UUID)
		}
	}
	if exactMatches != 1 {
		return false, fmt.Errorf("bootstrap: pre-delete location inventory contains %d exact rows for VM %s", exactMatches, attempt.ResourceUUID)
	}

	network, err := r.API.GetNetwork(ctx, attempt.Location, cluster.Spec.Network.UUID)
	if err != nil {
		return false, fmt.Errorf("bootstrap: pre-delete configured-VPC read for VM %s: %w", attempt.ResourceUUID, err)
	}
	if network == nil || !strings.EqualFold(network.UUID, cluster.Spec.Network.UUID) {
		return false, fmt.Errorf("bootstrap: configured VPC identity changed before deleting VM %s", attempt.ResourceUUID)
	}
	members, membershipErr := canonicalConfiguredVPCVMUUIDs(network)
	if membershipErr != nil {
		return false, fmt.Errorf("bootstrap: pre-delete configured-VPC membership for VM %s: %w", attempt.ResourceUUID, membershipErr)
	}
	if _, present := members[strings.ToLower(attempt.ResourceUUID)]; !present {
		return false, fmt.Errorf("bootstrap: refusing to delete VM %q without exactly one configured-VPC membership", attempt.ResourceName)
	}

	owned, controlPlaneNames, bastionName, err := uniqueDestroyVMs([]inspace.VM{*detail}, ownerKey(cluster), cluster.Metadata.Name)
	if err != nil {
		return false, err
	}
	if ownedVM := owned[attempt.ResourceName]; ownedVM == nil || !strings.EqualFold(ownedVM.UUID, attempt.ResourceUUID) {
		return false, fmt.Errorf("bootstrap: refusing to delete VM %q outside its owned bootstrap slot", attempt.ResourceName)
	}
	if err := validateDestroyVMOwnership(owned, ownerKey(cluster), cluster.Metadata.Name, bastionName, controlPlaneNames); err != nil {
		return false, err
	}
	return true, nil
}

// durableVMDeleteAssignments validates that every residual firewall relation
// covered by a deletion receipt is the one exact VM/firewall tuple persisted
// before DELETE. The receipt has no expiry: dependent firewall teardown waits
// for authoritative VM absence and relation withdrawal across restarts.
func durableVMDeleteAssignments(cluster *v1alpha1.InSpaceCluster, firewalls []inspace.Firewall) (map[string]v1alpha1.ResourceDeleteAttemptStatus, error) {
	if err := validateFirewallAssignmentCollections(firewalls); err != nil {
		return nil, fmt.Errorf("bootstrap: durable VM deletion firewall inventory: %w", err)
	}
	result := make(map[string]v1alpha1.ResourceDeleteAttemptStatus, len(cluster.Status.DeleteAttempts))
	for key, attempt := range cluster.Status.DeleteAttempts {
		if attempt.ResourceKind != deleteAttemptKindVM {
			continue
		}
		if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
			return nil, err
		}
		assignmentCount := 0
		for i := range firewalls {
			for _, resource := range firewalls[i].ResourcesAssigned {
				if !strings.EqualFold(resource.ResourceUUID, attempt.ResourceUUID) {
					continue
				}
				assignmentCount++
				if resource.ResourceType != "vm" || attempt.FirewallUUID == "" || !strings.EqualFold(firewalls[i].UUID, attempt.FirewallUUID) {
					return nil, fmt.Errorf("bootstrap: durable deletion for VM %q has firewall-assignment drift", attempt.ResourceName)
				}
			}
		}
		if assignmentCount > 1 {
			return nil, fmt.Errorf("bootstrap: durable deletion for VM %q has duplicate firewall assignments", attempt.ResourceName)
		}
		result[key] = attempt
	}
	return result, nil
}

func (r *Reconciler) rollbackFloatingIPContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.WithoutCancel(ctx),
		configuredDuration(r.createdVMFloatingIPCleanupTimeout, defaultCreatedVMFloatingIPCleanupTimeout),
	)
}

func (r *Reconciler) rollbackFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: rollback delete attempt %q disappeared", key)
	}
	if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
		return false, err
	}
	vm := &inspace.VM{UUID: attempt.ResourceUUID, Name: attempt.ResourceName}
	switch attempt.Phase {
	case deletePhaseRollbackFIPDiscovery:
		discoveryCtx, cancel := r.rollbackFloatingIPContext(ctx)
		items, discoveryErr := r.API.ListFloatingIPs(discoveryCtx, attempt.Location, nil)
		cancel()
		var found *inspace.FloatingIP
		if discoveryErr == nil {
			for i := range items {
				item := &items[i]
				if item.IsDeleted || (item.AssignedTo != attempt.ResourceUUID && item.Name != attempt.FloatingIPName) {
					continue
				}
				if found != nil {
					return false, fmt.Errorf("bootstrap: rollback found multiple floating IPs for VM %q", attempt.ResourceName)
				}
				found = item
			}
		}
		if found != nil {
			if found.Name == "" {
				if err := validateAutoAssignedFloatingIP(found, cluster, vm); err != nil {
					return false, err
				}
			} else if err := validateOwnedFloatingIP(found, cluster, attempt.FloatingIPName, vm); err != nil {
				return false, err
			}
		}
		err := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.Phase != deletePhaseRollbackFIPDiscovery {
				return fmt.Errorf("bootstrap: rollback delete attempt %q changed during floating-IP discovery", key)
			}
			if found != nil {
				current.FloatingIPAddress = found.Address
			}
			setDeleteAttemptPhase(current, deletePhaseVMIntent)
			return nil
		})
		return true, errors.Join(discoveryErr, err)
	case deletePhaseRollbackFIPAfterVM:
		readCtx, cancel := r.rollbackFloatingIPContext(ctx)
		defer cancel()
		var found *inspace.FloatingIP
		var err error
		if attempt.FloatingIPAddress != "" {
			found, err = r.findFloatingIPByAddress(readCtx, attempt.Location, attempt.FloatingIPAddress)
		} else {
			items, listErr := r.API.ListFloatingIPs(readCtx, attempt.Location, nil)
			err = listErr
			for i := range items {
				item := &items[i]
				if item.IsDeleted || (item.AssignedTo != attempt.ResourceUUID && item.Name != attempt.FloatingIPName) {
					continue
				}
				if found != nil {
					return false, fmt.Errorf("bootstrap: rollback found multiple residual floating IPs for VM %q", attempt.ResourceName)
				}
				found = item
			}
		}
		if err != nil {
			return false, errors.Join(
				ErrCreateAttemptPending,
				fmt.Errorf("bootstrap: rollback floating-IP readback is not yet authoritative: %w", err),
			)
		}
		if found == nil {
			if attempt.FloatingIPAddress == "" {
				return false, fmt.Errorf("%w: rollback cannot prove absence of a previously undiscovered unnamed floating IP", ErrCreateAttemptPending)
			}
			return r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseAbsent)
		}
		if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
			return false, err
		}
		if found.Address == "" || found.BillingAccountID != cluster.Spec.BillingAccountID ||
			(found.Name != "" && found.Name != attempt.FloatingIPName) ||
			(found.AssignedTo != "" && found.AssignedTo != attempt.ResourceUUID) {
			return false, errors.New("bootstrap: rollback residual floating IP changed exact ownership identity")
		}
		next := deletePhaseRollbackFIPDeleteIntent
		if found.AssignedTo != "" {
			next = deletePhaseRollbackFIPUnassignIntent
		}
		return false, r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.Phase != deletePhaseRollbackFIPAfterVM {
				return fmt.Errorf("bootstrap: rollback delete attempt %q changed during post-VM floating-IP readback", key)
			}
			if current.FloatingIPAddress == "" {
				current.FloatingIPAddress = found.Address
			}
			setDeleteAttemptPhase(current, next)
			return nil
		})
	case deletePhaseRollbackFIPUnassignIntent:
		allowed, err := r.issueDeleteAttempt(ctx, cluster, key, deletePhaseRollbackFIPUnassignIntent, deletePhaseRollbackFIPUnassignIssued)
		if err != nil || !allowed {
			return false, err
		}
		fresh, authorityErr := r.authorizeRollbackFloatingIPDispatch(ctx, cluster, key, deletePhaseRollbackFIPUnassignIssued)
		if authorityErr != nil {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseRollbackFIPUnassignIssued, deletePhaseRollbackFIPUnassignIntent)
			return false, errors.Join(authorityErr, resetErr,
				fmt.Errorf("%w: rollback floating-IP unassign %q lacks post-CAS authority", ErrCreateAttemptPending, key))
		}
		if fresh == nil || fresh.AssignedTo == "" {
			return false, r.observeRollbackFloatingIP(ctx, cluster, key)
		}
		mutationCtx, cancel := r.rollbackFloatingIPContext(ctx)
		_, mutationErr := r.API.UnassignFloatingIP(mutationCtx, cluster.Spec.Location, fresh.Address)
		cancel()
		if deleteVMFailureProvesNoDispatch(mutationErr) {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseRollbackFIPUnassignIssued, deletePhaseRollbackFIPUnassignIntent)
			return false, errors.Join(mutationErr, resetErr)
		}
		return false, errors.Join(mutationErr, r.observeRollbackFloatingIP(ctx, cluster, key))
	case deletePhaseRollbackFIPUnassignIssued:
		return false, r.observeRollbackFloatingIP(ctx, cluster, key)
	case deletePhaseRollbackFIPDeleteIntent:
		allowed, err := r.issueDeleteAttempt(ctx, cluster, key, deletePhaseRollbackFIPDeleteIntent, deletePhaseRollbackFIPDeleteIssued)
		if err != nil || !allowed {
			return false, err
		}
		fresh, authorityErr := r.authorizeRollbackFloatingIPDispatch(ctx, cluster, key, deletePhaseRollbackFIPDeleteIssued)
		if authorityErr != nil {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseRollbackFIPDeleteIssued, deletePhaseRollbackFIPDeleteIntent)
			return false, errors.Join(authorityErr, resetErr,
				fmt.Errorf("%w: rollback floating-IP delete %q lacks post-CAS authority", ErrCreateAttemptPending, key))
		}
		if fresh == nil {
			return false, r.observeRollbackFloatingIP(ctx, cluster, key)
		}
		mutationCtx, cancel := r.rollbackFloatingIPContext(ctx)
		mutationErr := r.API.DeleteFloatingIP(mutationCtx, cluster.Spec.Location, fresh.Address)
		cancel()
		if deleteVMFailureProvesNoDispatch(mutationErr) {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseRollbackFIPDeleteIssued, deletePhaseRollbackFIPDeleteIntent)
			return false, errors.Join(mutationErr, resetErr)
		}
		return false, errors.Join(mutationErr, r.observeRollbackFloatingIP(ctx, cluster, key))
	case deletePhaseRollbackFIPDeleteIssued:
		return false, r.observeRollbackFloatingIP(ctx, cluster, key)
	case deletePhaseVMIntent, deletePhaseVMIssued, deletePhaseAbsent:
		return true, nil
	default:
		return false, fmt.Errorf("bootstrap: unsupported rollback phase %q", attempt.Phase)
	}
}

// authorizeRollbackFloatingIPDispatch re-reads the exact residual floating IP
// after the rollback issue CAS. The rollback phase itself is durable evidence
// that the exact VM passed two spaced Get/List/VPC absence observations; one
// additional fresh absence read prevents a VM that reappeared during the CAS
// window from authorizing an unassign or delete against stale state.
func (r *Reconciler) authorizeRollbackFloatingIPDispatch(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, issuedPhase string,
) (*inspace.FloatingIP, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok || attempt.Phase != issuedPhase || attempt.Purpose != deletePurposeRollback {
		return nil, fmt.Errorf("bootstrap: rollback attempt %q changed before floating-IP dispatch authority", key)
	}
	if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
		return nil, err
	}

	detail, detailErr := r.API.GetVM(ctx, attempt.Location, attempt.ResourceUUID)
	if detailErr == nil {
		if detail == nil || !strings.EqualFold(detail.UUID, attempt.ResourceUUID) || detail.Name != attempt.ResourceName {
			return nil, fmt.Errorf("bootstrap: rollback VM %s reappeared with changed exact identity", attempt.ResourceUUID)
		}
		return nil, fmt.Errorf("bootstrap: rollback VM %s reappeared before floating-IP cleanup", attempt.ResourceUUID)
	}
	if !inspace.IsNotFound(detailErr) {
		return nil, fmt.Errorf("bootstrap: fresh rollback VM absence read for %s: %w", attempt.ResourceUUID, detailErr)
	}
	absent, absenceErr := r.corroborateVMDeletionAbsence(ctx, cluster, key, attempt)
	if absenceErr != nil || !absent {
		return nil, errors.Join(absenceErr,
			fmt.Errorf("bootstrap: rollback VM %s lacks fresh List/VPC absence", attempt.ResourceUUID))
	}

	item, err := r.findFloatingIPByAddress(ctx, attempt.Location, attempt.FloatingIPAddress)
	if err != nil || item == nil {
		return item, err
	}
	if item.Address != attempt.FloatingIPAddress || item.BillingAccountID != cluster.Spec.BillingAccountID ||
		(item.Name != "" && item.Name != attempt.FloatingIPName) {
		return nil, errors.New("bootstrap: rollback floating-IP pre-dispatch identity changed")
	}
	copy := *item
	copy.Name = attempt.FloatingIPName
	switch issuedPhase {
	case deletePhaseRollbackFIPUnassignIssued:
		if item.AssignedTo == "" {
			if err := validateFloatingIPCleanupReadback(item, cluster, attempt.FloatingIPName, attempt.FloatingIPAddress); err != nil {
				return nil, err
			}
			return item, nil
		}
		vm := &inspace.VM{UUID: attempt.ResourceUUID, Name: attempt.ResourceName}
		if err := validateOwnedFloatingIP(&copy, cluster, attempt.FloatingIPName, vm); err != nil {
			return nil, err
		}
		if item.AssignedTo != attempt.ResourceUUID {
			return nil, errors.New("bootstrap: rollback floating IP is no longer assigned to its exact durable VM")
		}
	case deletePhaseRollbackFIPDeleteIssued:
		if err := validateFloatingIPCleanupReadback(item, cluster, attempt.FloatingIPName, attempt.FloatingIPAddress); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("bootstrap: unsupported rollback floating-IP authority phase %q", issuedPhase)
	}
	return item, nil
}

func (r *Reconciler) observeRollbackFloatingIP(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) error {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return fmt.Errorf("bootstrap: rollback delete attempt %q disappeared before floating-IP readback", key)
	}
	readCtx, cancel := r.rollbackFloatingIPContext(ctx)
	item, err := r.findFloatingIPByAddress(readCtx, attempt.Location, attempt.FloatingIPAddress)
	cancel()
	if err != nil {
		return errors.Join(
			ErrCreateAttemptPending,
			fmt.Errorf("bootstrap: read back floating IP %s after rollback mutation: %w", attempt.FloatingIPAddress, err),
		)
	}
	if item == nil {
		_, err := r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseAbsent)
		return err
	}
	if (item.Name != "" && item.Name != attempt.FloatingIPName) || item.BillingAccountID != cluster.Spec.BillingAccountID || item.Address != attempt.FloatingIPAddress {
		return fmt.Errorf("bootstrap: rollback floating-IP readback changed exact ownership identity")
	}
	switch attempt.Phase {
	case deletePhaseRollbackFIPUnassignIssued:
		if item.AssignedTo == "" {
			if err := validateFloatingIPCleanupReadback(item, cluster, attempt.FloatingIPName, attempt.FloatingIPAddress); err != nil {
				return err
			}
			_, err := r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseRollbackFIPDeleteIntent)
			return err
		}
		if item.AssignedTo != attempt.ResourceUUID {
			return fmt.Errorf("bootstrap: rollback floating IP became assigned to another resource")
		}
		if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
			return err
		}
		return fmt.Errorf("%w: floating-IP unassign %s remains issued with the exact original relation visible", ErrCreateAttemptPending, attempt.FloatingIPAddress)
	case deletePhaseRollbackFIPDeleteIssued:
		if err := validateFloatingIPCleanupReadback(item, cluster, attempt.FloatingIPName, attempt.FloatingIPAddress); err != nil {
			return err
		}
		if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
			return err
		}
		return fmt.Errorf("%w: floating-IP delete %s remains issued with the exact object visible", ErrCreateAttemptPending, attempt.FloatingIPAddress)
	default:
		return fmt.Errorf("bootstrap: floating-IP readback is invalid from phase %q", attempt.Phase)
	}
}

func (r *Reconciler) clearCompletedRollback(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) error {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok || attempt.Purpose != deletePurposeRollback || attempt.Phase != deletePhaseAbsent {
		return fmt.Errorf("bootstrap: rollback delete attempt %q is not durably absent", key)
	}
	createKey, assignmentKey, err := createKeyForVMDeleteAttempt(key)
	if err != nil {
		return err
	}
	fipKey, err := floatingIPUpdateAttemptKey(cluster, attempt.FloatingIPName)
	if err != nil {
		return err
	}
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		current, exists := status.DeleteAttempts[key]
		if !exists || current != attempt {
			return fmt.Errorf("bootstrap: rollback delete attempt %q changed before reset", key)
		}
		if create, exists := status.CreateAttempts[createKey]; exists {
			if create.ResourceKind != createAttemptKindVM || create.ResourceName != attempt.ResourceName ||
				!strings.EqualFold(create.ResourceUUID, attempt.ResourceUUID) {
				return fmt.Errorf("bootstrap: refusing to reset VM create slot %q with mismatched exact identity", createKey)
			}
		}
		if assignment, exists := status.CreateAttempts[assignmentKey]; exists {
			resourceName := attempt.FirewallUUID + "/" + attempt.ResourceUUID
			if assignment.ResourceKind != createAttemptKindFirewallAssignment || assignment.ResourceName != resourceName {
				return fmt.Errorf("bootstrap: refusing to reset firewall assignment slot %q with mismatched exact identity", assignmentKey)
			}
		}
		if update, exists := status.CreateAttempts[fipKey]; exists {
			if update.ResourceKind != createAttemptKindFloatingIPUpdate || !strings.HasSuffix(update.ResourceName, "/"+attempt.FloatingIPName) {
				return fmt.Errorf("bootstrap: refusing to reset floating-IP update slot %q with mismatched exact identity", fipKey)
			}
		}
		delete(status.CreateAttempts, createKey)
		delete(status.CreateAttempts, assignmentKey)
		delete(status.CreateAttempts, fipKey)
		delete(status.DeleteAttempts, key)
		return nil
	})
}

func (r *Reconciler) reconcileRollbackDelete(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	var accumulated error
	for step := 0; step < 8; step++ {
		attempt, ok := r.deleteAttempt(cluster, key)
		if !ok {
			return false, fmt.Errorf("bootstrap: rollback delete attempt %q disappeared", key)
		}
		switch attempt.Phase {
		case deletePhaseRollbackFIPDiscovery:
			readyForVM, rollbackErr := r.rollbackFloatingIP(ctx, cluster, key)
			accumulated = errors.Join(accumulated, rollbackErr)
			if !readyForVM {
				return false, accumulated
			}
			continue
		case deletePhaseVMIntent, deletePhaseVMIssued:
			vmAbsent, vmErr := r.reconcileVMDelete(ctx, cluster, key)
			accumulated = errors.Join(accumulated, vmErr)
			if !vmAbsent {
				return false, accumulated
			}
			continue
		case deletePhaseRollbackFIPAfterVM, deletePhaseRollbackFIPUnassignIntent,
			deletePhaseRollbackFIPUnassignIssued, deletePhaseRollbackFIPDeleteIntent, deletePhaseRollbackFIPDeleteIssued:
			_, rollbackErr := r.rollbackFloatingIP(ctx, cluster, key)
			if rollbackErr != nil {
				return false, errors.Join(accumulated, rollbackErr)
			}
			continue
		case deletePhaseAbsent:
			if err := r.clearCompletedRollback(ctx, cluster, key); err != nil {
				return false, errors.Join(accumulated, err)
			}
			return true, accumulated
		default:
			return false, errors.Join(accumulated, fmt.Errorf("bootstrap: unsupported rollback delete phase %q", attempt.Phase))
		}
	}
	return false, errors.Join(accumulated, fmt.Errorf("%w: rollback state machine exceeded its bounded transition count", ErrCreateAttemptPending))
}

func (r *Reconciler) resumeRollbackDeletes(ctx context.Context, cluster *v1alpha1.InSpaceCluster) (bool, error) {
	activeKey := ""
	for key, attempt := range cluster.Status.DeleteAttempts {
		if attempt.ResourceKind != deleteAttemptKindVM {
			continue
		}
		if err := validateVMDeleteAttempt(cluster, key, attempt); err != nil {
			return false, err
		}
		if attempt.Purpose != deletePurposeRollback {
			continue
		}
		if activeKey != "" {
			return false, errors.New("bootstrap: multiple malformed-create rollback receipts are active")
		}
		activeKey = key
	}
	if activeKey == "" {
		return false, nil
	}
	done, err := r.reconcileRollbackDelete(ctx, cluster, activeKey)
	return !done, err
}

func (r *Reconciler) clearAllMutationAttempts(ctx context.Context, cluster *v1alpha1.InSpaceCluster) error {
	if len(cluster.Status.CreateAttempts) == 0 && len(cluster.Status.DeleteAttempts) == 0 {
		return nil
	}
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		status.CreateAttempts = nil
		status.DeleteAttempts = nil
		return nil
	})
}
