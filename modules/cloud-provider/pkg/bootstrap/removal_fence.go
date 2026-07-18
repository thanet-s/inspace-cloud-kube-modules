package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const (
	destroyFIPBastionKey      = "floating-ip-delete/bastion"
	destroyFirewallBastionKey = "firewall-delete/bastion"
	destroyFirewallNodesKey   = "firewall-delete/nodes"
)

func destroyFIPControlPlaneKey(slot int) string {
	return fmt.Sprintf("floating-ip-delete/control-plane-%d", slot)
}

func expectedDestroyRemovalNames(cluster *v1alpha1.InSpaceCluster, key, kind string) (string, string, error) {
	current := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	legacy := legacyBootstrapResourceNames(ownerKey(cluster))
	switch {
	case kind == deleteAttemptKindFloatingIP && key == destroyFIPBastionKey:
		return current.BastionFloatingIP, legacy.BastionFloatingIP, nil
	case kind == deleteAttemptKindFirewall && key == destroyFirewallBastionKey:
		return current.BastionFirewall, legacy.BastionFirewall, nil
	case kind == deleteAttemptKindFirewall && key == destroyFirewallNodesKey:
		return current.NodeFirewall, legacy.NodeFirewall, nil
	}
	for slot := 0; slot < controlPlaneReplicaCount(cluster); slot++ {
		if kind == deleteAttemptKindFloatingIP && key == destroyFIPControlPlaneKey(slot) {
			return current.ControlPlaneFIP[slot], legacy.ControlPlaneFIP[slot], nil
		}
	}
	return "", "", fmt.Errorf("bootstrap: removal attempt %q is not a valid %s slot", key, kind)
}

func validateDestroyRemovalAttempt(cluster *v1alpha1.InSpaceCluster, key string, attempt v1alpha1.ResourceDeleteAttemptStatus) error {
	if cluster == nil || attempt.Location != cluster.Spec.Location || attempt.Owner != ownerKey(cluster) || attempt.Purpose != deletePurposeDestroy || attempt.ResourceName == "" {
		return fmt.Errorf("bootstrap: durable removal attempt %q does not match the exact cluster identity", key)
	}
	currentName, legacyName, err := expectedDestroyRemovalNames(cluster, key, attempt.ResourceKind)
	if err != nil || (attempt.ResourceName != currentName && attempt.ResourceName != legacyName) {
		return fmt.Errorf("bootstrap: durable removal attempt %q does not match its deterministic resource name", key)
	}
	issued := false
	switch attempt.ResourceKind {
	case deleteAttemptKindFloatingIP:
		if attempt.ResourceUUID != "" || attempt.FirewallUUID != "" || attempt.FloatingIPAddress == "" {
			return fmt.Errorf("bootstrap: floating-IP removal attempt %q has invalid exact identity", key)
		}
		address, err := netip.ParseAddr(attempt.FloatingIPAddress)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != attempt.FloatingIPAddress {
			return fmt.Errorf("bootstrap: floating-IP removal attempt %q has invalid public IPv4", key)
		}
		if attempt.RelatedResourceUUID != "" && !vmUUIDPattern.MatchString(attempt.RelatedResourceUUID) {
			return fmt.Errorf("bootstrap: floating-IP removal attempt %q has invalid assigned VM UUID", key)
		}
		switch attempt.Phase {
		case deletePhaseFIPUnassignIntent, deletePhaseFIPDeleteIntent, deletePhaseAbsent:
		case deletePhaseFIPUnassignIssued, deletePhaseFIPDeleteIssued:
			issued = true
		default:
			return fmt.Errorf("bootstrap: floating-IP removal attempt %q has invalid phase %q", key, attempt.Phase)
		}
	case deleteAttemptKindFirewall:
		if !vmUUIDPattern.MatchString(attempt.ResourceUUID) || attempt.FirewallUUID != "" || attempt.RelatedResourceUUID != "" || attempt.FloatingIPAddress != "" || attempt.FloatingIPName != "" {
			return fmt.Errorf("bootstrap: firewall removal attempt %q has invalid exact identity", key)
		}
		switch attempt.Phase {
		case deletePhaseFirewallDeleteIntent, deletePhaseAbsent:
		case deletePhaseFirewallDeleteIssued:
			issued = true
		default:
			return fmt.Errorf("bootstrap: firewall removal attempt %q has invalid phase %q", key, attempt.Phase)
		}
	default:
		return fmt.Errorf("bootstrap: removal attempt %q has unsupported resource kind %q", key, attempt.ResourceKind)
	}
	if issued {
		if !validDeleteIssue(attempt) {
			return fmt.Errorf("bootstrap: issued removal attempt %q has invalid issue identity", key)
		}
	} else if attempt.IssueID != "" || attempt.IssuedAt != "" {
		return fmt.Errorf("bootstrap: non-issued removal attempt %q contains issue identity", key)
	}
	if attempt.AbsenceObservedAt != "" {
		absencePhase := attempt.Phase == deletePhaseFIPUnassignIntent || attempt.Phase == deletePhaseFIPUnassignIssued ||
			attempt.Phase == deletePhaseFIPDeleteIntent || attempt.Phase == deletePhaseFIPDeleteIssued ||
			attempt.Phase == deletePhaseFirewallDeleteIntent || attempt.Phase == deletePhaseFirewallDeleteIssued
		if !absencePhase {
			return fmt.Errorf("bootstrap: removal attempt %q contains absence evidence in phase %q", key, attempt.Phase)
		}
		observedAt, err := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
		if err != nil || observedAt.Location() != time.UTC {
			return fmt.Errorf("bootstrap: removal attempt %q has invalid absence observation", key)
		}
	}
	return nil
}

func (r *Reconciler) ensureDestroyFloatingIPRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string, item *inspace.FloatingIP) error {
	if item == nil {
		return errors.New("bootstrap: cannot fence a missing floating IP")
	}
	phase := deletePhaseFIPDeleteIntent
	if item.AssignedTo != "" {
		phase = deletePhaseFIPUnassignIntent
	}
	desired := v1alpha1.ResourceDeleteAttemptStatus{
		ResourceKind: deleteAttemptKindFloatingIP, ResourceName: item.Name, Location: cluster.Spec.Location,
		Owner: ownerKey(cluster), Purpose: deletePurposeDestroy, Phase: phase,
		FloatingIPName: item.Name, FloatingIPAddress: item.Address, RelatedResourceUUID: strings.ToLower(item.AssignedTo),
	}
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		if status.DeleteAttempts == nil {
			status.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus)
		}
		if current, ok := status.DeleteAttempts[key]; ok {
			if err := validateDestroyRemovalAttempt(cluster, key, current); err != nil {
				return err
			}
			if current.ResourceName != desired.ResourceName || current.FloatingIPAddress != desired.FloatingIPAddress || current.RelatedResourceUUID != desired.RelatedResourceUUID {
				return fmt.Errorf("bootstrap: floating-IP removal slot %q is anchored to another exact resource", key)
			}
			return nil
		}
		status.DeleteAttempts[key] = desired
		return nil
	})
}

func (r *Reconciler) ensureDestroyFirewallRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string, firewall *inspace.Firewall) error {
	if firewall == nil || !vmUUIDPattern.MatchString(firewall.UUID) {
		return errors.New("bootstrap: cannot fence a missing or invalid firewall")
	}
	desired := v1alpha1.ResourceDeleteAttemptStatus{
		ResourceKind: deleteAttemptKindFirewall, ResourceName: firewall.EffectiveName(), ResourceUUID: strings.ToLower(firewall.UUID),
		Location: cluster.Spec.Location, Owner: ownerKey(cluster), Purpose: deletePurposeDestroy, Phase: deletePhaseFirewallDeleteIntent,
	}
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		if status.DeleteAttempts == nil {
			status.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus)
		}
		if current, ok := status.DeleteAttempts[key]; ok {
			if err := validateDestroyRemovalAttempt(cluster, key, current); err != nil {
				return err
			}
			if current.ResourceName != desired.ResourceName || !strings.EqualFold(current.ResourceUUID, desired.ResourceUUID) {
				return fmt.Errorf("bootstrap: firewall removal slot %q is anchored to another exact resource", key)
			}
			return nil
		}
		status.DeleteAttempts[key] = desired
		return nil
	})
}

func (r *Reconciler) issueDestroyRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key, intentPhase, issuedPhase string) error {
	issueID, err := newCreateIssueID()
	if err != nil {
		return err
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	return r.mutateDeleteAttempt(ctx, cluster, key, func(attempt *v1alpha1.ResourceDeleteAttemptStatus) error {
		if err := validateDestroyRemovalAttempt(cluster, key, *attempt); err != nil {
			return err
		}
		if attempt.Phase != intentPhase {
			return fmt.Errorf("%w: removal attempt %q is already in phase %q", ErrCreateAttemptPending, key, attempt.Phase)
		}
		attempt.Phase = issuedPhase
		attempt.IssueID = issueID
		attempt.IssuedAt = issuedAt
		return nil
	})
}

func (r *Reconciler) resetPreDispatchDeleteIssue(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key, issuedPhase, intentPhase string) error {
	persistCtx, cancel := r.detachedStatusMutationContext(ctx)
	defer cancel()
	return r.mutateDeleteAttempt(persistCtx, cluster, key, func(attempt *v1alpha1.ResourceDeleteAttemptStatus) error {
		if attempt.Phase != issuedPhase {
			return fmt.Errorf("bootstrap: removal attempt %q changed before pre-dispatch reset", key)
		}
		setDeleteAttemptPhase(attempt, intentPhase)
		return nil
	})
}

func (r *Reconciler) advanceDestroyRemovalAbsence(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	attempt v1alpha1.ResourceDeleteAttemptStatus,
	nextPhase string,
) (bool, error) {
	now := time.Now().UTC()
	if attempt.AbsenceObservedAt == "" {
		err := r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
			if current.ResourceKind != attempt.ResourceKind || current.ResourceName != attempt.ResourceName ||
				current.ResourceUUID != attempt.ResourceUUID || current.FloatingIPAddress != attempt.FloatingIPAddress ||
				current.Phase != attempt.Phase || current.AbsenceObservedAt != "" {
				return fmt.Errorf("bootstrap: removal attempt %q changed before first absence observation", key)
			}
			current.AbsenceObservedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		return false, errors.Join(err, fmt.Errorf("%w: removal %q requires a second spaced authoritative absence observation", ErrCreateAttemptPending, key))
	}
	firstObserved, err := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
	if err != nil || firstObserved.Location() != time.UTC {
		return false, fmt.Errorf("bootstrap: removal attempt %q has invalid absence observation", key)
	}
	spacing := configuredDuration(r.vmAbsenceObservationMinInterval, defaultVMAbsenceObservationMinInterval)
	if now.Before(firstObserved.Add(spacing)) {
		return false, fmt.Errorf("%w: removal %q second absence observation was not spaced after the first", ErrCreateAttemptPending, key)
	}
	err = r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
		if current.ResourceKind != attempt.ResourceKind || current.ResourceName != attempt.ResourceName ||
			current.ResourceUUID != attempt.ResourceUUID || current.FloatingIPAddress != attempt.FloatingIPAddress ||
			current.Phase != attempt.Phase || current.AbsenceObservedAt != attempt.AbsenceObservedAt {
			return fmt.Errorf("bootstrap: removal attempt %q changed before terminal absence persistence", key)
		}
		setDeleteAttemptPhase(current, nextPhase)
		return nil
	})
	return err == nil && nextPhase == deletePhaseAbsent, err
}

func (r *Reconciler) clearDestroyRemovalAbsence(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	attempt v1alpha1.ResourceDeleteAttemptStatus,
) error {
	if attempt.AbsenceObservedAt == "" {
		return nil
	}
	return r.mutateDeleteAttempt(ctx, cluster, key, func(current *v1alpha1.ResourceDeleteAttemptStatus) error {
		if current.ResourceKind != attempt.ResourceKind || current.ResourceName != attempt.ResourceName ||
			current.ResourceUUID != attempt.ResourceUUID || current.FloatingIPAddress != attempt.FloatingIPAddress ||
			current.Phase != attempt.Phase {
			return fmt.Errorf("bootstrap: removal attempt %q changed before clearing transient absence", key)
		}
		current.AbsenceObservedAt = ""
		return nil
	})
}

// observeDestroyRemovalTwice converts a first authoritative absence into a
// second, separately fetched observation after the configured convergence
// interval.  The second call is important: merely sleeping and advancing the
// receipt would not detect an eventually-consistent object that reappeared.
func (r *Reconciler) observeDestroyRemovalTwice(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	observe func() (bool, error),
) (bool, error) {
	terminal, err := observe()
	if terminal || err == nil || !errors.Is(err, ErrCreateAttemptPending) {
		return terminal, err
	}
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok || attempt.AbsenceObservedAt == "" {
		return false, err
	}
	firstObserved, parseErr := time.Parse(time.RFC3339Nano, attempt.AbsenceObservedAt)
	if parseErr != nil || firstObserved.Location() != time.UTC {
		return false, fmt.Errorf("bootstrap: removal attempt %q has invalid absence observation", key)
	}
	spacing := configuredDuration(r.vmAbsenceObservationMinInterval, defaultVMAbsenceObservationMinInterval)
	wait := time.Until(firstObserved.Add(spacing))
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
	return observe()
}

func (r *Reconciler) observeDestroyFloatingIPRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: floating-IP removal attempt %q disappeared", key)
	}
	if err := validateDestroyRemovalAttempt(cluster, key, attempt); err != nil {
		return false, err
	}
	item, err := r.findFloatingIPByAddress(ctx, attempt.Location, attempt.FloatingIPAddress)
	if err != nil {
		return false, err
	}
	if item == nil {
		return r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseAbsent)
	}
	if item.Name != attempt.ResourceName || item.Address != attempt.FloatingIPAddress || item.BillingAccountID != cluster.Spec.BillingAccountID {
		return false, errors.New("bootstrap: floating-IP removal readback changed exact ownership identity")
	}
	switch attempt.Phase {
	case deletePhaseFIPUnassignIssued:
		if item.AssignedTo == "" {
			if err := validateFloatingIPCleanupReadback(item, cluster, attempt.ResourceName, attempt.FloatingIPAddress); err != nil {
				return false, err
			}
			return r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseFIPDeleteIntent)
		}
		if item.AssignedTo != attempt.RelatedResourceUUID {
			return false, errors.New("bootstrap: floating IP became assigned to another resource during removal")
		}
		if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
			return false, err
		}
		return false, fmt.Errorf("%w: floating-IP unassign remains durably issued", ErrCreateAttemptPending)
	case deletePhaseFIPDeleteIssued:
		if err := validateFloatingIPCleanupReadback(item, cluster, attempt.ResourceName, attempt.FloatingIPAddress); err != nil {
			return false, err
		}
		if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
			return false, err
		}
		return false, fmt.Errorf("%w: floating-IP delete remains durably issued", ErrCreateAttemptPending)
	case deletePhaseFIPUnassignIntent, deletePhaseFIPDeleteIntent:
		return false, nil
	case deletePhaseAbsent:
		return true, nil
	default:
		return false, fmt.Errorf("bootstrap: invalid floating-IP removal phase %q", attempt.Phase)
	}
}

func (r *Reconciler) reconcileDestroyFloatingIPRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: floating-IP removal attempt %q is missing", key)
	}
	switch attempt.Phase {
	case deletePhaseAbsent:
		return true, nil
	case deletePhaseFIPUnassignIssued, deletePhaseFIPDeleteIssued:
		return r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
			return r.observeDestroyFloatingIPRemoval(ctx, cluster, key)
		})
	case deletePhaseFIPUnassignIntent:
		if err := r.issueDestroyRemoval(ctx, cluster, key, deletePhaseFIPUnassignIntent, deletePhaseFIPUnassignIssued); err != nil {
			return false, err
		}
		item, authorityErr := r.authorizeDestroyFloatingIPDispatch(ctx, cluster, key, deletePhaseFIPUnassignIssued)
		if authorityErr != nil {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFIPUnassignIssued, deletePhaseFIPUnassignIntent)
			return false, errors.Join(authorityErr, resetErr,
				fmt.Errorf("%w: floating-IP unassign %q lacks post-CAS authority", ErrCreateAttemptPending, key))
		}
		if item == nil || item.AssignedTo == "" {
			return r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
				return r.observeDestroyFloatingIPRemoval(ctx, cluster, key)
			})
		}
		_, mutationErr := r.API.UnassignFloatingIP(ctx, cluster.Spec.Location, item.Address)
		if deleteVMFailureProvesNoDispatch(mutationErr) {
			return false, errors.Join(mutationErr, r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFIPUnassignIssued, deletePhaseFIPUnassignIntent))
		}
		terminal, observeErr := r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
			return r.observeDestroyFloatingIPRemoval(ctx, cluster, key)
		})
		if observeErr == nil || terminal {
			return terminal, observeErr
		}
		return false, errors.Join(mutationErr, observeErr)
	case deletePhaseFIPDeleteIntent:
		if err := r.issueDestroyRemoval(ctx, cluster, key, deletePhaseFIPDeleteIntent, deletePhaseFIPDeleteIssued); err != nil {
			return false, err
		}
		item, authorityErr := r.authorizeDestroyFloatingIPDispatch(ctx, cluster, key, deletePhaseFIPDeleteIssued)
		if authorityErr != nil {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFIPDeleteIssued, deletePhaseFIPDeleteIntent)
			return false, errors.Join(authorityErr, resetErr,
				fmt.Errorf("%w: floating-IP delete %q lacks post-CAS authority", ErrCreateAttemptPending, key))
		}
		if item == nil {
			return r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
				return r.observeDestroyFloatingIPRemoval(ctx, cluster, key)
			})
		}
		mutationErr := r.API.DeleteFloatingIP(ctx, cluster.Spec.Location, item.Address)
		if deleteVMFailureProvesNoDispatch(mutationErr) {
			return false, errors.Join(mutationErr, r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFIPDeleteIssued, deletePhaseFIPDeleteIntent))
		}
		terminal, observeErr := r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
			return r.observeDestroyFloatingIPRemoval(ctx, cluster, key)
		})
		if terminal {
			return true, observeErr
		}
		return false, errors.Join(mutationErr, observeErr)
	default:
		return false, fmt.Errorf("bootstrap: invalid floating-IP removal phase %q", attempt.Phase)
	}
}

func (r *Reconciler) authorizeDestroyFloatingIPDispatch(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, issuedPhase string,
) (*inspace.FloatingIP, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok || attempt.Phase != issuedPhase {
		return nil, fmt.Errorf("bootstrap: floating-IP removal attempt %q changed before pre-dispatch authority", key)
	}
	if err := validateDestroyRemovalAttempt(cluster, key, attempt); err != nil {
		return nil, err
	}
	item, err := r.findFloatingIPByAddress(ctx, attempt.Location, attempt.FloatingIPAddress)
	if err != nil || item == nil {
		return item, err
	}
	if item.Address != attempt.FloatingIPAddress || item.Name != attempt.ResourceName || item.BillingAccountID != cluster.Spec.BillingAccountID {
		return nil, errors.New("bootstrap: floating-IP pre-dispatch readback changed exact address/name/billing ownership")
	}
	switch issuedPhase {
	case deletePhaseFIPUnassignIssued:
		if item.AssignedTo == "" {
			if err := validateFloatingIPCleanupReadback(item, cluster, attempt.ResourceName, attempt.FloatingIPAddress); err != nil {
				return nil, err
			}
			return item, nil
		}
		vm, vmErr := r.readExactOwnedVMMutationAuthority(ctx, cluster, attempt.RelatedResourceUUID, "")
		if vmErr != nil {
			return nil, fmt.Errorf("bootstrap: floating-IP unassign target %s lacks exact VM/Get/List/VPC authority: %w", attempt.RelatedResourceUUID, vmErr)
		}
		if err := validateOwnedFloatingIP(item, cluster, attempt.ResourceName, vm); err != nil {
			return nil, err
		}
		if item.AssignedTo != attempt.RelatedResourceUUID {
			return nil, errors.New("bootstrap: floating IP is no longer assigned to its exact durable VM")
		}
	case deletePhaseFIPDeleteIssued:
		if err := validateFloatingIPCleanupReadback(item, cluster, attempt.ResourceName, attempt.FloatingIPAddress); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("bootstrap: unsupported floating-IP authority phase %q", issuedPhase)
	}
	return item, nil
}

func (r *Reconciler) observeDestroyFirewallRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: firewall removal attempt %q disappeared", key)
	}
	found, err := r.readDestroyFirewallAuthority(ctx, cluster, key, attempt)
	if err != nil {
		return false, err
	}
	if found == nil {
		return r.advanceDestroyRemovalAbsence(ctx, cluster, key, attempt, deletePhaseAbsent)
	}
	if err := r.clearDestroyRemovalAbsence(ctx, cluster, key, attempt); err != nil {
		return false, err
	}
	return false, fmt.Errorf("%w: firewall delete remains durably issued", ErrCreateAttemptPending)
}

func (r *Reconciler) reconcileDestroyFirewallRemoval(ctx context.Context, cluster *v1alpha1.InSpaceCluster, key string) (bool, error) {
	attempt, ok := r.deleteAttempt(cluster, key)
	if !ok {
		return false, fmt.Errorf("bootstrap: firewall removal attempt %q is missing", key)
	}
	switch attempt.Phase {
	case deletePhaseAbsent:
		return true, nil
	case deletePhaseFirewallDeleteIssued:
		return r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
			return r.observeDestroyFirewallRemoval(ctx, cluster, key)
		})
	case deletePhaseFirewallDeleteIntent:
		if err := r.issueDestroyRemoval(ctx, cluster, key, deletePhaseFirewallDeleteIntent, deletePhaseFirewallDeleteIssued); err != nil {
			return false, err
		}
		issuedAttempt, exists := r.deleteAttempt(cluster, key)
		if !exists {
			return false, fmt.Errorf("bootstrap: firewall removal attempt %q disappeared after issue persistence", key)
		}
		firewall, authorityErr := r.readDestroyFirewallAuthority(ctx, cluster, key, issuedAttempt)
		if authorityErr != nil {
			resetErr := r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFirewallDeleteIssued, deletePhaseFirewallDeleteIntent)
			return false, errors.Join(authorityErr, resetErr,
				fmt.Errorf("%w: firewall delete %q lacks post-CAS authority", ErrCreateAttemptPending, key))
		}
		if firewall == nil {
			return r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
				return r.observeDestroyFirewallRemoval(ctx, cluster, key)
			})
		}
		mutationErr := r.API.DeleteFirewall(ctx, cluster.Spec.Location, firewall.UUID)
		if deleteVMFailureProvesNoDispatch(mutationErr) {
			return false, errors.Join(mutationErr, r.resetPreDispatchDeleteIssue(ctx, cluster, key, deletePhaseFirewallDeleteIssued, deletePhaseFirewallDeleteIntent))
		}
		terminal, observeErr := r.observeDestroyRemovalTwice(ctx, cluster, key, func() (bool, error) {
			return r.observeDestroyFirewallRemoval(ctx, cluster, key)
		})
		if terminal {
			return true, observeErr
		}
		return false, errors.Join(mutationErr, observeErr)
	default:
		return false, fmt.Errorf("bootstrap: invalid firewall removal phase %q", attempt.Phase)
	}
}

func (r *Reconciler) readDestroyFirewallAuthority(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key string,
	attempt v1alpha1.ResourceDeleteAttemptStatus,
) (*inspace.Firewall, error) {
	if err := validateDestroyRemovalAttempt(cluster, key, attempt); err != nil {
		return nil, err
	}
	items, err := r.API.ListFirewalls(ctx, attempt.Location)
	if err != nil {
		return nil, err
	}
	if err := validateFirewallAssignmentCollections(items); err != nil {
		return nil, fmt.Errorf("bootstrap: firewall removal authority: %w", err)
	}
	var found *inspace.Firewall
	for index := range items {
		if !strings.EqualFold(items[index].UUID, attempt.ResourceUUID) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("bootstrap: duplicate firewall UUID %s during removal authority readback", attempt.ResourceUUID)
		}
		found = &items[index]
	}
	if found == nil {
		return nil, nil
	}
	if found.EffectiveName() != attempt.ResourceName || found.BillingAccountID != cluster.Spec.BillingAccountID || len(found.ResourcesAssigned) != 0 {
		return nil, errors.New("bootstrap: firewall removal authority changed exact name/billing identity or regained assignments")
	}
	network, err := r.API.GetNetwork(ctx, attempt.Location, cluster.Spec.Network.UUID)
	if err != nil || network == nil || !strings.EqualFold(network.UUID, cluster.Spec.Network.UUID) {
		return nil, errors.Join(errors.New("bootstrap: configured VPC is not authoritative before firewall deletion"), err)
	}
	owner := ownerKey(cluster)
	switch key {
	case destroyFirewallNodesKey:
		if err := validateManagedNodeFirewall(found, cluster, network, owner, attempt.ResourceName); err != nil {
			return nil, err
		}
	case destroyFirewallBastionKey:
		if err := validateManagedBastionFirewallForDestroy(found, cluster, network.Subnet, owner, attempt.ResourceName, r.ManagementCIDR); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("bootstrap: firewall removal slot %q has no managed policy authority", key)
	}
	return found, nil
}
