package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	annotationFirewallMutationSlot       = "karpenter.inspace.cloud/firewall-mutation-slot"
	firewallMutationSlotSchema           = "karpenter.inspace.cloud/firewall-mutation-slot-v1"
	firewallMutationLedgerSchema         = "karpenter.inspace.cloud/firewall-mutation-ledger-v1"
	firewallMutationCoordinatorLeaseName = "karpenter-inspace-firewall-mutations"
	firewallMutationCoordinatorHolder    = "karpenter-inspace-firewall-mutations"
	maxFirewallMutationLedgerBytes       = 128 * 1024
	firewallMutationAssign               = "assign"
	firewallMutationDetach               = "detach"
)

// firewallMutationLedger keeps one independent, non-expiring receipt per
// firewall in a fixed-name Lease. The fixed object name lets RBAC restrict
// update/patch authority without weakening the per-firewall serialization:
// Kubernetes resourceVersion CAS protects every map update from lost writes.
type firewallMutationLedger struct {
	Schema string                                `json:"schema"`
	Slots  map[string]firewallMutationSlotRecord `json:"slots"`
}

// firewallMutationSlotRecord is a non-expiring distributed mutex and mutation
// receipt. It deliberately has no time-based lease expiry: after a cloud
// request may have been dispatched, elapsed time can never prove no commit.
type firewallMutationSlotRecord struct {
	Schema        string                           `json:"schema"`
	Location      string                           `json:"location"`
	FirewallUUID  string                           `json:"firewallUUID"`
	VMUUID        string                           `json:"vmUUID"`
	NodeClaimName string                           `json:"nodeClaimName"`
	NodeClaimUID  string                           `json:"nodeClaimUID"`
	Operation     string                           `json:"operation"`
	Phase         cloudapi.FirewallAssignmentPhase `json:"phase"`
	IssueID       string                           `json:"issueID"`
	AcquisitionID string                           `json:"acquisitionID"`
}

func firewallMutationSlotName(location, firewallUUID string) string {
	hash := createFenceHash(strings.TrimSpace(location) + "\x00" + strings.ToLower(strings.TrimSpace(firewallUUID)))
	return "inspace-fw-" + hash[:32]
}

func newFirewallMutationSlotRecord(current *karpv1.NodeClaim, record createFenceRecord, vmUUID, operation, issueID, acquisitionID string) (firewallMutationSlotRecord, error) {
	value := firewallMutationSlotRecord{
		Schema: firewallMutationSlotSchema, Location: record.Cleanup.Location,
		FirewallUUID: strings.ToLower(record.Cleanup.FirewallUUID), VMUUID: strings.ToLower(vmUUID),
		NodeClaimName: current.Name, NodeClaimUID: string(current.UID), Operation: operation,
		Phase: cloudapi.FirewallAssignmentIssued, IssueID: issueID, AcquisitionID: acquisitionID,
	}
	if err := validateFirewallMutationSlot(value); err != nil {
		return firewallMutationSlotRecord{}, err
	}
	return value, nil
}

func validateFirewallMutationSlot(value firewallMutationSlotRecord) error {
	if value.Schema != firewallMutationSlotSchema || strings.TrimSpace(value.Location) == "" ||
		!createFenceVMUUIDPattern.MatchString(value.FirewallUUID) || !createFenceVMUUIDPattern.MatchString(value.VMUUID) ||
		value.NodeClaimName == "" || value.NodeClaimUID == "" || !createFenceKeyHashPattern.MatchString(value.IssueID) ||
		!createFenceKeyHashPattern.MatchString(value.AcquisitionID) {
		return fmt.Errorf("durable firewall mutation slot has invalid identity")
	}
	if value.Operation != firewallMutationAssign && value.Operation != firewallMutationDetach {
		return fmt.Errorf("durable firewall mutation slot has invalid operation %q", value.Operation)
	}
	if value.Phase != cloudapi.FirewallAssignmentIssued && value.Phase != cloudapi.FirewallAssignmentObserved && value.Phase != cloudapi.FirewallAssignmentRejected {
		return fmt.Errorf("durable firewall mutation slot has invalid phase %q", value.Phase)
	}
	return nil
}

func validateFirewallMutationLedger(value firewallMutationLedger) error {
	if value.Schema != firewallMutationLedgerSchema || value.Slots == nil {
		return fmt.Errorf("durable firewall mutation ledger has invalid schema")
	}
	for key, slot := range value.Slots {
		if err := validateFirewallMutationSlot(slot); err != nil {
			return fmt.Errorf("durable firewall mutation ledger slot %q: %w", key, err)
		}
		if key != firewallMutationSlotName(slot.Location, slot.FirewallUUID) {
			return fmt.Errorf("durable firewall mutation ledger slot %q has identity drift", key)
		}
	}
	return nil
}

func encodeFirewallMutationLedger(value firewallMutationLedger) (string, error) {
	if err := validateFirewallMutationLedger(value); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encoding durable firewall mutation ledger: %w", err)
	}
	if len(encoded) > maxFirewallMutationLedgerBytes {
		return "", fmt.Errorf("durable firewall mutation ledger exceeds %d-byte safety bound", maxFirewallMutationLedgerBytes)
	}
	return string(encoded), nil
}

func decodeFirewallMutationLedger(lease *coordinationv1.Lease) (firewallMutationLedger, error) {
	if lease == nil || lease.Spec.HolderIdentity == nil {
		return firewallMutationLedger{}, fmt.Errorf("durable firewall mutation Lease has no holder identity")
	}
	if lease.Name != firewallMutationCoordinatorLeaseName || *lease.Spec.HolderIdentity != firewallMutationCoordinatorHolder {
		return firewallMutationLedger{}, fmt.Errorf("durable firewall mutation Lease has invalid fixed identity")
	}
	encoded := lease.Annotations[annotationFirewallMutationSlot]
	if encoded == "" || len(encoded) > maxFirewallMutationLedgerBytes {
		return firewallMutationLedger{}, fmt.Errorf("durable firewall mutation Lease has no bounded ledger")
	}
	var value firewallMutationLedger
	if err := json.Unmarshal([]byte(encoded), &value); err != nil {
		return firewallMutationLedger{}, fmt.Errorf("decoding durable firewall mutation ledger: %w", err)
	}
	if err := validateFirewallMutationLedger(value); err != nil {
		return firewallMutationLedger{}, err
	}
	return value, nil
}

func (s *kubernetesCreateFenceStore) getFirewallMutationLedger(ctx context.Context) (*coordinationv1.Lease, firewallMutationLedger, error) {
	var lease coordinationv1.Lease
	err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: firewallMutationCoordinatorLeaseName}, &lease)
	if err != nil {
		return nil, firewallMutationLedger{}, err
	}
	value, err := decodeFirewallMutationLedger(&lease)
	if err != nil {
		return nil, firewallMutationLedger{}, err
	}
	return &lease, value, nil
}

func firewallMutationSlotMatches(a, b firewallMutationSlotRecord) bool {
	return a == b
}

func (s *kubernetesCreateFenceStore) readbackOwnFirewallMutationSlot(ctx context.Context, desired firewallMutationSlotRecord) (*coordinationv1.Lease, bool, error) {
	readCtx, cancel := detachedCreateFenceContext(ctx)
	defer cancel()
	lease, ledger, err := s.getFirewallMutationLedger(readCtx)
	if err != nil {
		return nil, false, err
	}
	stored, exists := ledger.Slots[firewallMutationSlotName(desired.Location, desired.FirewallUUID)]
	return lease, exists && firewallMutationSlotMatches(stored, desired), nil
}

func (s *kubernetesCreateFenceStore) firewallMutationSlotTerminal(ctx context.Context, value firewallMutationSlotRecord) (bool, error) {
	if value.Phase == cloudapi.FirewallAssignmentObserved || value.Phase == cloudapi.FirewallAssignmentRejected {
		return true, nil
	}
	if value.Operation == firewallMutationDetach {
		return false, nil
	}
	var claim karpv1.NodeClaim
	err := s.reader.Get(ctx, types.NamespacedName{Name: value.NodeClaimName}, &claim)
	if apierrors.IsNotFound(err) {
		// The provider finalizer prevents disappearance until cloud cleanup has
		// converged. Exact object absence therefore retires this old owner.
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading prior firewall-slot NodeClaim %q: %w", value.NodeClaimName, err)
	}
	if string(claim.UID) != value.NodeClaimUID {
		return true, nil
	}
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		return false, fmt.Errorf("prior firewall-slot NodeClaim %q has invalid durable fence: %w", value.NodeClaimName, err)
	}
	assignment := record.BaseFirewallAssignment
	if record.Binding.NodeClaimUID != value.NodeClaimUID || record.Cleanup.NodeClaimName != value.NodeClaimName ||
		record.Cleanup.Location != value.Location || strings.ToLower(record.Cleanup.FirewallUUID) != value.FirewallUUID ||
		assignment == nil || strings.ToLower(assignment.FirewallUUID) != value.FirewallUUID || assignment.IssueID != value.IssueID {
		return false, fmt.Errorf("prior firewall-slot NodeClaim %q no longer carries the exact owned assignment receipt", value.NodeClaimName)
	}
	return assignment.Phase == cloudapi.FirewallAssignmentObserved || assignment.Phase == cloudapi.FirewallAssignmentRejected, nil
}

// auditUnresolvedLegacyFirewallMutationOwners bridges the upgrade boundary
// from the v2 per-NodeClaim receipt to the v3 shared Lease. A newly issued v3
// claim must not win an empty ledger while an older controller's same-firewall
// assignment can still be in flight. The APIReader is uncached, and malformed
// provider receipts fail closed because their firewall ownership is unknown.
//
// The exact legacy owner is allowed to install its own read-only Lease slot.
// That slot never grants POST authority, but it lets authoritative Observe or
// Reject terminalize the shared coordinator before another claim can proceed.
func (s *kubernetesCreateFenceStore) auditUnresolvedLegacyFirewallMutationOwners(ctx context.Context, desired firewallMutationSlotRecord) error {
	var claims karpv1.NodeClaimList
	if err := s.reader.List(ctx, &claims); err != nil {
		return fmt.Errorf("listing NodeClaims for legacy firewall-mutation migration: %w", err)
	}
	desiredKey := firewallMutationSlotName(desired.Location, desired.FirewallUUID)
	for i := range claims.Items {
		claim := &claims.Items[i]
		encoded := claim.Annotations[AnnotationCreateFence]
		if encoded == "" {
			continue
		}
		record, err := decodeCreateFence(encoded)
		if err != nil {
			return fmt.Errorf("NodeClaim %q has an invalid durable fence during legacy firewall-mutation migration: %w", claim.Name, err)
		}
		if record.Binding.NodeClaimUID != string(claim.UID) || record.Cleanup.NodeClaimName != claim.Name {
			return fmt.Errorf("NodeClaim %q has drifted durable identity during legacy firewall-mutation migration", claim.Name)
		}
		assignment := record.BaseFirewallAssignment
		if !record.LegacyV2BaseFirewallMayBeIssued || assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIssued ||
			firewallMutationSlotName(record.Cleanup.Location, record.Cleanup.FirewallUUID) != desiredKey {
			continue
		}
		if claim.Name == desired.NodeClaimName && string(claim.UID) == desired.NodeClaimUID &&
			strings.EqualFold(assignment.VMUUID, desired.VMUUID) && assignment.IssueID == desired.IssueID {
			continue
		}
		return fmt.Errorf("%w: firewall %s still has unresolved legacy-v2 assignment issue %s owned by NodeClaim %q",
			cloudapi.ErrCreateAttemptPending, desired.FirewallUUID, assignment.IssueID, claim.Name)
	}
	return nil
}

// acquireFirewallMutationSlot performs the one shared-object CAS which makes
// independent NodeClaim receipts mutually exclusive for a firewall. The
// unique acquisition ID is process-local authority: an existing matching
// owner after restart is always read-only.
func (s *kubernetesCreateFenceStore) acquireFirewallMutationSlot(ctx context.Context, desired firewallMutationSlotRecord) (bool, error) {
	key := firewallMutationSlotName(desired.Location, desired.FirewallUUID)
	for attempt := 0; attempt < 6; attempt++ {
		if err := s.auditUnresolvedLegacyFirewallMutationOwners(ctx, desired); err != nil {
			return false, err
		}
		lease, ledger, readErr := s.getFirewallMutationLedger(ctx)
		if apierrors.IsNotFound(readErr) {
			ledger = firewallMutationLedger{Schema: firewallMutationLedgerSchema, Slots: map[string]firewallMutationSlotRecord{key: desired}}
			encoded, encodeErr := encodeFirewallMutationLedger(ledger)
			if encodeErr != nil {
				return false, encodeErr
			}
			holder := firewallMutationCoordinatorHolder
			lease = &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: firewallMutationCoordinatorLeaseName, Namespace: s.namespace,
					Annotations: map[string]string{annotationFirewallMutationSlot: encoded}},
				Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
			}
			writeErr := s.writer.Create(ctx, lease)
			_, own, exactErr := s.readbackOwnFirewallMutationSlot(ctx, desired)
			if exactErr == nil && own {
				return true, nil
			}
			if exactErr != nil && !apierrors.IsNotFound(exactErr) {
				return false, fmt.Errorf("creating and exactly reading back firewall mutation slot: %w", errors.Join(writeErr, exactErr))
			}
			continue
		}
		if readErr != nil {
			return false, fmt.Errorf("reading durable firewall mutation ledger: %w", readErr)
		}
		current, exists := ledger.Slots[key]
		if exists && firewallMutationSlotMatches(current, desired) {
			// desired.AcquisitionID was generated once at this method entry and is
			// never persisted anywhere else before this CAS. Reaching this branch
			// can therefore only recover this invocation's ambiguous Kubernetes
			// write/readback, not a controller restart (which has a fresh nonce).
			return true, nil
		}
		if exists && current.NodeClaimUID == desired.NodeClaimUID && current.NodeClaimName == desired.NodeClaimName &&
			current.Operation == desired.Operation && current.VMUUID == desired.VMUUID && current.IssueID == desired.IssueID {
			return false, nil
		}
		if exists {
			terminal, terminalErr := s.firewallMutationSlotTerminal(ctx, current)
			if terminalErr != nil {
				return false, fmt.Errorf("auditing prior durable firewall mutation owner: %w", terminalErr)
			}
			if !terminal {
				return false, fmt.Errorf("%w: firewall %s still has active %s issue %s owned by NodeClaim %q",
					cloudapi.ErrCreateAttemptPending, desired.FirewallUUID, current.Operation, current.IssueID, current.NodeClaimName)
			}
		}
		ledger.Slots[key] = desired
		encoded, encodeErr := encodeFirewallMutationLedger(ledger)
		if encodeErr != nil {
			return false, encodeErr
		}
		copy := lease.DeepCopy()
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationFirewallMutationSlot] = encoded
		writeErr := s.writer.Update(ctx, copy)
		_, own, exactErr := s.readbackOwnFirewallMutationSlot(ctx, desired)
		if exactErr == nil && own {
			return true, nil
		}
		if exactErr != nil {
			return false, fmt.Errorf("updating and exactly reading back firewall mutation slot: %w", errors.Join(writeErr, exactErr))
		}
	}
	return false, fmt.Errorf("%w: firewall %s mutation-slot CAS did not converge", cloudapi.ErrCreateAttemptPending, desired.FirewallUUID)
}

func (s *kubernetesCreateFenceStore) authorizeBaseFirewallAssignmentSlot(ctx context.Context, current *karpv1.NodeClaim, record createFenceRecord, vmUUID string) (cloudapi.FirewallAssignmentAuthorization, error) {
	assignment := record.BaseFirewallAssignment
	if !baseFirewallAssignmentMatches(assignment, vmUUID, record.Cleanup.FirewallUUID) || assignment.Phase != cloudapi.FirewallAssignmentIssued ||
		!createFenceKeyHashPattern.MatchString(assignment.IssueID) {
		return cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("NodeClaim %q lacks an exact issued base-firewall assignment receipt", current.Name)
	}
	acquisitionID, err := s.nonce()
	if err != nil {
		return cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("generating base-firewall assignment acquisition identity: %w", err)
	}
	desired, err := newFirewallMutationSlotRecord(current, record, vmUUID, firewallMutationAssign, assignment.IssueID, acquisitionID)
	if err != nil {
		return cloudapi.FirewallAssignmentAuthorization{}, err
	}
	allow, err := s.acquireFirewallMutationSlot(ctx, desired)
	fence := firewallAssignmentFenceFromRecord(record)
	if err != nil {
		return cloudapi.FirewallAssignmentAuthorization{Fence: fence}, err
	}
	if record.LegacyV2BaseFirewallMayBeIssued {
		// v2 had no shared firewall slot. Materialize this exact issued owner so it
		// blocks new same-firewall claims, but never convert that migration write
		// into cloud POST authority: the old operation may already have dispatched.
		return cloudapi.FirewallAssignmentAuthorization{Fence: fence}, nil
	}
	return cloudapi.FirewallAssignmentAuthorization{Fence: fence, AllowPOST: allow}, nil
}

func (s *kubernetesCreateFenceStore) finishFirewallMutationSlot(ctx context.Context, current *karpv1.NodeClaim, record createFenceRecord, operation, vmUUID, issueID string, terminal cloudapi.FirewallAssignmentPhase) error {
	if terminal != cloudapi.FirewallAssignmentObserved && terminal != cloudapi.FirewallAssignmentRejected {
		return fmt.Errorf("invalid terminal firewall mutation phase %q", terminal)
	}
	key := firewallMutationSlotName(record.Cleanup.Location, record.Cleanup.FirewallUUID)
	for attempt := 0; attempt < 4; attempt++ {
		lease, ledger, err := s.getFirewallMutationLedger(ctx)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading firewall mutation ledger for terminal receipt: %w", err)
		}
		value, exists := ledger.Slots[key]
		if !exists {
			return nil
		}
		if value.NodeClaimUID != string(current.UID) || value.NodeClaimName != current.Name || value.Operation != operation ||
			value.VMUUID != strings.ToLower(vmUUID) || value.IssueID != issueID {
			// A different operation can own the slot only after this receipt was
			// authoritatively terminal, so it must not be overwritten.
			return nil
		}
		if value.Phase == terminal {
			return nil
		}
		if value.Phase != cloudapi.FirewallAssignmentIssued {
			return fmt.Errorf("firewall mutation slot issue %s has conflicting terminal phase %q", issueID, value.Phase)
		}
		value.Phase = terminal
		ledger.Slots[key] = value
		encoded, encodeErr := encodeFirewallMutationLedger(ledger)
		if encodeErr != nil {
			return encodeErr
		}
		copy := lease.DeepCopy()
		copy.Annotations[annotationFirewallMutationSlot] = encoded
		writeErr := s.writer.Update(ctx, copy)
		readCtx, cancel := detachedCreateFenceContext(ctx)
		_, storedLedger, readErr := s.getFirewallMutationLedger(readCtx)
		cancel()
		stored, exists := storedLedger.Slots[key]
		if readErr == nil && exists && firewallMutationSlotMatches(stored, value) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("writing and reading back terminal firewall mutation slot: %w", errors.Join(writeErr, readErr))
		}
	}
	return fmt.Errorf("%w: terminal firewall mutation slot did not converge", cloudapi.ErrCreateAttemptPending)
}

func createFenceOwnsVM(record createFenceRecord, vmUUID string) bool {
	vmUUID = strings.ToLower(vmUUID)
	if record.CreatedVMUUID == vmUUID || record.ObservedVMUUID == vmUUID || record.CleanupVMUUID == vmUUID {
		return true
	}
	for _, resolution := range record.CleanupResolutions {
		if strings.EqualFold(resolution.VMUUID, vmUUID) {
			return true
		}
	}
	return false
}

func (s *kubernetesCreateFenceStore) AuthorizeBaseFirewallDetach(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID string) (cloudapi.FirewallDetachmentAuthorization, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("base-firewall detachment requires a canonical VM UUID")
	}
	current, err := s.getProtectedExact(ctx, claim, "authorize base-firewall detachment")
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	record, err := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	if token == "" || record.Token != token || !createFenceOwnsVM(record, vmUUID) {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("NodeClaim %q does not durably own VM %s for base-firewall detachment", claim.Name, vmUUID)
	}
	_, ledger, ledgerErr := s.getFirewallMutationLedger(ctx)
	existing, exists := ledger.Slots[firewallMutationSlotName(record.Cleanup.Location, record.Cleanup.FirewallUUID)]
	if ledgerErr == nil && exists && existing.NodeClaimUID == string(current.UID) && existing.NodeClaimName == current.Name && existing.Operation == firewallMutationDetach && existing.VMUUID == vmUUID {
		fence := cloudapi.FirewallDetachmentFence{VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: existing.Phase, IssueID: existing.IssueID}
		if existing.Phase == cloudapi.FirewallAssignmentIssued || existing.Phase == cloudapi.FirewallAssignmentObserved {
			return cloudapi.FirewallDetachmentAuthorization{Fence: fence}, nil
		}
	} else if ledgerErr != nil && !apierrors.IsNotFound(ledgerErr) {
		return cloudapi.FirewallDetachmentAuthorization{}, ledgerErr
	}
	issueID, err := s.nonce()
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("generating base-firewall detachment issue identity: %w", err)
	}
	acquisitionID, err := s.nonce()
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("generating base-firewall detachment acquisition identity: %w", err)
	}
	desired, err := newFirewallMutationSlotRecord(current, record, vmUUID, firewallMutationDetach, issueID, acquisitionID)
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	allow, err := s.acquireFirewallMutationSlot(ctx, desired)
	fence := cloudapi.FirewallDetachmentFence{VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: cloudapi.FirewallAssignmentIssued, IssueID: issueID}
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{Fence: fence}, err
	}
	return cloudapi.FirewallDetachmentAuthorization{Fence: fence, AllowDELETE: allow}, nil
}

func (s *kubernetesCreateFenceStore) finishBaseFirewallDetach(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence, terminal cloudapi.FirewallAssignmentPhase) error {
	current, err := s.getProtectedExact(ctx, claim, "finish base-firewall detachment")
	if err != nil {
		return err
	}
	record, err := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
	if err != nil {
		return err
	}
	if token == "" || record.Token != token || !createFenceOwnsVM(record, fence.VMUUID) ||
		strings.ToLower(record.Cleanup.FirewallUUID) != strings.ToLower(fence.FirewallUUID) || !createFenceKeyHashPattern.MatchString(fence.IssueID) {
		return fmt.Errorf("NodeClaim %q base-firewall detachment identity changed", claim.Name)
	}
	return s.finishFirewallMutationSlot(ctx, current, record, firewallMutationDetach, fence.VMUUID, fence.IssueID, terminal)
}

func (s *kubernetesCreateFenceStore) ObserveBaseFirewallDetach(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence) error {
	return s.finishBaseFirewallDetach(ctx, claim, binding, token, fence, cloudapi.FirewallAssignmentObserved)
}

func (s *kubernetesCreateFenceStore) RejectBaseFirewallDetach(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence) error {
	return s.finishBaseFirewallDetach(ctx, claim, binding, token, fence, cloudapi.FirewallAssignmentRejected)
}

func (s *memoryCreateFenceStore) acquireFirewallMutationSlot(current *karpv1.NodeClaim, record createFenceRecord, vmUUID, operation, issueID string) (firewallMutationSlotRecord, bool, error) {
	acquisitionID, err := s.nonce()
	if err != nil {
		return firewallMutationSlotRecord{}, false, err
	}
	desired, err := newFirewallMutationSlotRecord(current, record, vmUUID, operation, issueID, acquisitionID)
	if err != nil {
		return firewallMutationSlotRecord{}, false, err
	}
	key := firewallMutationSlotName(desired.Location, desired.FirewallUUID)
	if existing, ok := s.firewallMutationSlots[key]; ok {
		if existing.NodeClaimUID == desired.NodeClaimUID && existing.Operation == desired.Operation && existing.VMUUID == desired.VMUUID && existing.IssueID == desired.IssueID {
			return existing, false, nil
		}
		if existing.Phase == cloudapi.FirewallAssignmentIssued {
			return firewallMutationSlotRecord{}, false, fmt.Errorf("%w: firewall %s still has active %s issue %s", cloudapi.ErrCreateAttemptPending, desired.FirewallUUID, existing.Operation, existing.IssueID)
		}
	}
	s.firewallMutationSlots[key] = desired
	return desired, true, nil
}

func (s *memoryCreateFenceStore) finishFirewallMutationSlot(record createFenceRecord, claim *karpv1.NodeClaim, operation, vmUUID, issueID string, terminal cloudapi.FirewallAssignmentPhase) error {
	key := firewallMutationSlotName(record.Cleanup.Location, record.Cleanup.FirewallUUID)
	value, ok := s.firewallMutationSlots[key]
	if !ok || value.NodeClaimUID != string(claim.UID) || value.Operation != operation || value.VMUUID != strings.ToLower(vmUUID) || value.IssueID != issueID {
		return nil
	}
	if value.Phase != cloudapi.FirewallAssignmentIssued && value.Phase != terminal {
		return fmt.Errorf("firewall mutation slot has conflicting terminal phase %q", value.Phase)
	}
	value.Phase = terminal
	s.firewallMutationSlots[key] = value
	return nil
}

func (s *memoryCreateFenceStore) AuthorizeBaseFirewallDetach(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID string) (cloudapi.FirewallDetachmentAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vmUUID = strings.ToLower(vmUUID)
	record, ok := s.records[claim.UID]
	if !ok {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	if token == "" || record.Token != token || !createFenceOwnsVM(record, vmUUID) {
		return cloudapi.FirewallDetachmentAuthorization{}, fmt.Errorf("base-firewall detachment lacks exact VM ownership")
	}
	key := firewallMutationSlotName(record.Cleanup.Location, record.Cleanup.FirewallUUID)
	if existing, exists := s.firewallMutationSlots[key]; exists && existing.NodeClaimUID == string(claim.UID) &&
		existing.Operation == firewallMutationDetach && existing.VMUUID == vmUUID &&
		(existing.Phase == cloudapi.FirewallAssignmentIssued || existing.Phase == cloudapi.FirewallAssignmentObserved) {
		return cloudapi.FirewallDetachmentAuthorization{Fence: cloudapi.FirewallDetachmentFence{
			VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: existing.Phase, IssueID: existing.IssueID,
		}}, nil
	}
	issueID, err := s.nonce()
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	value, allow, err := s.acquireFirewallMutationSlot(claim, record, vmUUID, firewallMutationDetach, issueID)
	if err != nil {
		return cloudapi.FirewallDetachmentAuthorization{}, err
	}
	return cloudapi.FirewallDetachmentAuthorization{Fence: cloudapi.FirewallDetachmentFence{
		VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: value.Phase, IssueID: value.IssueID,
	}, AllowDELETE: allow}, nil
}

func (s *memoryCreateFenceStore) finishBaseFirewallDetach(claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence, terminal cloudapi.FirewallAssignmentPhase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[claim.UID]
	if !ok {
		return fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return err
	}
	if token == "" || record.Token != token || !createFenceOwnsVM(record, fence.VMUUID) || record.Cleanup.FirewallUUID != fence.FirewallUUID {
		return fmt.Errorf("base-firewall detachment identity changed")
	}
	return s.finishFirewallMutationSlot(record, claim, firewallMutationDetach, fence.VMUUID, fence.IssueID, terminal)
}

func (s *memoryCreateFenceStore) ObserveBaseFirewallDetach(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence) error {
	return s.finishBaseFirewallDetach(claim, binding, token, fence, cloudapi.FirewallAssignmentObserved)
}

func (s *memoryCreateFenceStore) RejectBaseFirewallDetach(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FirewallDetachmentFence) error {
	return s.finishBaseFirewallDetach(claim, binding, token, fence, cloudapi.FirewallAssignmentRejected)
}
