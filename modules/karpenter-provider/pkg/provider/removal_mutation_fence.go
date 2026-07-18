package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const maxRemovalMutationEncodedBytes = 64 * 1024

type observedFloatingIPDeleteRecord struct {
	Location   string    `json:"location"`
	VMUUID     string    `json:"vmUUID"`
	Address    string    `json:"address"`
	Name       string    `json:"name"`
	BillingID  int64     `json:"billingAccountID"`
	IssueID    string    `json:"issueID"`
	IssuedAt   time.Time `json:"issuedAt"`
	ObservedAt time.Time `json:"observedAt"`
}

// removalMutationRecord is a single serialized journal for all destructive
// mutations owned by one NodeClaim. Keeping one active receipt prevents the VM
// and either floating-IP operation from overlapping across controller replicas.
// Observed Floating-IP DELETE receipts are retained as a bounded history so
// final audits can distinguish later address reuse for every cleanup
// resolution, not just the most recently deleted duplicate VM.
type removalMutationRecord struct {
	Schema                    string                            `json:"schema"`
	Binding                   createFenceBinding                `json:"binding"`
	AttemptToken              string                            `json:"attemptToken"`
	ReadyAt                   time.Time                         `json:"readyAt"`
	Operation                 cloudapi.RemovalMutationOperation `json:"operation,omitempty"`
	Location                  string                            `json:"location,omitempty"`
	VMUUID                    string                            `json:"vmUUID,omitempty"`
	Address                   string                            `json:"address,omitempty"`
	Name                      string                            `json:"name,omitempty"`
	BillingID                 int64                             `json:"billingAccountID,omitempty"`
	Phase                     cloudapi.RemovalMutationPhase     `json:"phase"`
	IssueID                   string                            `json:"issueID,omitempty"`
	IssuedAt                  *time.Time                        `json:"issuedAt,omitempty"`
	RejectedAt                *time.Time                        `json:"rejectedAt,omitempty"`
	ObservedAt                *time.Time                        `json:"observedAt,omitempty"`
	ObservedFloatingIPDeletes []observedFloatingIPDeleteRecord  `json:"observedFloatingIPDeletes,omitempty"`
}

func newRemovalMutationReadyRecord(binding createFenceBinding, token string, now time.Time) removalMutationRecord {
	return removalMutationRecord{
		Schema: removalMutationFenceSchema, Binding: binding, AttemptToken: token,
		ReadyAt: now.UTC(), Phase: cloudapi.RemovalMutationReady,
	}
}

func removalMutationFromRecord(record removalMutationRecord) cloudapi.RemovalMutation {
	return cloudapi.RemovalMutation{
		Operation: record.Operation, Location: record.Location, VMUUID: record.VMUUID,
		Address: record.Address, Name: record.Name, BillingAccountID: record.BillingID,
	}
}

func removalMutationFenceFromRecord(record removalMutationRecord) cloudapi.RemovalMutationFence {
	var issuedAt time.Time
	if record.IssuedAt != nil {
		issuedAt = record.IssuedAt.UTC()
	}
	var observedAt time.Time
	if record.ObservedAt != nil {
		observedAt = record.ObservedAt.UTC()
	}
	return cloudapi.RemovalMutationFence{
		RemovalMutation: removalMutationFromRecord(record), Phase: record.Phase, IssueID: record.IssueID,
		IssuedAt: issuedAt, ObservedAt: observedAt,
	}
}

func observedFloatingIPDeleteFence(record observedFloatingIPDeleteRecord) cloudapi.RemovalMutationFence {
	return cloudapi.RemovalMutationFence{
		RemovalMutation: cloudapi.RemovalMutation{
			Operation:        cloudapi.RemovalMutationFloatingIPDelete,
			Location:         record.Location,
			VMUUID:           record.VMUUID,
			Address:          record.Address,
			Name:             record.Name,
			BillingAccountID: record.BillingID,
		},
		Phase:      cloudapi.RemovalMutationObserved,
		IssueID:    record.IssueID,
		IssuedAt:   record.IssuedAt.UTC(),
		ObservedAt: record.ObservedAt.UTC(),
	}
}

func historicalObservedFloatingIPDelete(
	record removalMutationRecord,
	desired cloudapi.RemovalMutation,
) (cloudapi.RemovalMutationFence, bool) {
	if desired.Operation != cloudapi.RemovalMutationFloatingIPDelete {
		return cloudapi.RemovalMutationFence{}, false
	}
	for i := range record.ObservedFloatingIPDeletes {
		fence := observedFloatingIPDeleteFence(record.ObservedFloatingIPDeletes[i])
		if fence.RemovalMutation == desired {
			return fence, true
		}
	}
	return cloudapi.RemovalMutationFence{}, false
}

func appendObservedFloatingIPDelete(
	record *removalMutationRecord,
	fence cloudapi.RemovalMutationFence,
	observedAt time.Time,
) error {
	if fence.Operation != cloudapi.RemovalMutationFloatingIPDelete {
		return nil
	}
	for i := range record.ObservedFloatingIPDeletes {
		current := observedFloatingIPDeleteFence(record.ObservedFloatingIPDeletes[i])
		if current.RemovalMutation != fence.RemovalMutation {
			continue
		}
		if current.IssueID != fence.IssueID ||
			!current.IssuedAt.Equal(fence.IssuedAt) ||
			!current.ObservedAt.Equal(observedAt) {
			return fmt.Errorf("observed floating-IP DELETE history changed for %s", fence.Address)
		}
		return nil
	}
	if len(record.ObservedFloatingIPDeletes) >= cloudapi.MaxCreateCleanupResolutions {
		return fmt.Errorf("observed floating-IP DELETE history exceeds %d entries", cloudapi.MaxCreateCleanupResolutions)
	}
	record.ObservedFloatingIPDeletes = append(record.ObservedFloatingIPDeletes, observedFloatingIPDeleteRecord{
		Location:   fence.Location,
		VMUUID:     fence.VMUUID,
		Address:    fence.Address,
		Name:       fence.Name,
		BillingID:  fence.BillingAccountID,
		IssueID:    fence.IssueID,
		IssuedAt:   fence.IssuedAt.UTC(),
		ObservedAt: observedAt.UTC(),
	})
	return nil
}

func archiveCurrentObservedFloatingIPDelete(record *removalMutationRecord) error {
	if record.Phase != cloudapi.RemovalMutationObserved ||
		record.Operation != cloudapi.RemovalMutationFloatingIPDelete {
		return nil
	}
	fence := removalMutationFenceFromRecord(*record)
	return appendObservedFloatingIPDelete(record, fence, fence.ObservedAt)
}

func normalizeRemovalMutation(value cloudapi.RemovalMutation) (cloudapi.RemovalMutation, error) {
	value.Location = strings.TrimSpace(value.Location)
	value.VMUUID = strings.ToLower(strings.TrimSpace(value.VMUUID))
	if value.Location == "" || len(value.Location) > 128 || !createFenceVMUUIDPattern.MatchString(value.VMUUID) {
		return cloudapi.RemovalMutation{}, fmt.Errorf("removal mutation requires a location and canonical VM UUID")
	}
	switch value.Operation {
	case cloudapi.RemovalMutationVMDelete:
		if value.Address != "" || value.Name != "" || value.BillingAccountID != 0 {
			return cloudapi.RemovalMutation{}, fmt.Errorf("VM delete receipt cannot contain floating-IP identity")
		}
	case cloudapi.RemovalMutationFloatingIPUnassign, cloudapi.RemovalMutationFloatingIPDelete:
		if value.Name == "" || len(value.Name) > 255 || value.BillingAccountID <= 0 {
			return cloudapi.RemovalMutation{}, fmt.Errorf("floating-IP removal receipt requires exact name and billing identity")
		}
		address, err := netip.ParseAddr(value.Address)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != value.Address {
			return cloudapi.RemovalMutation{}, fmt.Errorf("floating-IP removal receipt requires canonical public IPv4")
		}
	default:
		return cloudapi.RemovalMutation{}, fmt.Errorf("unsupported removal operation %q", value.Operation)
	}
	return value, nil
}

func validateRemovalMutationFence(fence cloudapi.RemovalMutationFence) error {
	desired, err := normalizeRemovalMutation(fence.RemovalMutation)
	if err != nil {
		return err
	}
	if desired != fence.RemovalMutation || !createFenceKeyHashPattern.MatchString(fence.IssueID) {
		return fmt.Errorf("removal receipt identity or issue ID is not canonical")
	}
	if fence.IssuedAt.IsZero() {
		return fmt.Errorf("removal receipt has no issue time")
	}
	switch fence.Phase {
	case cloudapi.RemovalMutationIssued, cloudapi.RemovalMutationRejected:
		if !fence.ObservedAt.IsZero() {
			return fmt.Errorf("non-observed removal receipt contains an observation time")
		}
		return nil
	case cloudapi.RemovalMutationObserved:
		if fence.ObservedAt.IsZero() || fence.ObservedAt.Before(fence.IssuedAt) {
			return fmt.Errorf("observed removal receipt has an invalid observation time")
		}
		return nil
	default:
		return fmt.Errorf("removal receipt has invalid phase %q", fence.Phase)
	}
}

func removalMutationIdentityMatches(record removalMutationRecord, desired cloudapi.RemovalMutation) bool {
	return removalMutationFromRecord(record) == desired
}

func decodeRemovalMutationRecord(value string, binding createFenceBinding, token string) (removalMutationRecord, error) {
	var record removalMutationRecord
	if value == "" || len(value) > maxRemovalMutationEncodedBytes || json.Unmarshal([]byte(value), &record) != nil {
		return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence is missing or malformed")
	}
	if record.Schema != removalMutationFenceSchema || record.Binding != binding || token == "" || record.AttemptToken != token || record.ReadyAt.IsZero() {
		return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence has incomplete or changed NodeClaim identity")
	}
	if len(record.ObservedFloatingIPDeletes) > cloudapi.MaxCreateCleanupResolutions {
		return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence has too many observed floating-IP DELETE receipts")
	}
	seenHistoricalMutations := make(map[cloudapi.RemovalMutation]struct{}, len(record.ObservedFloatingIPDeletes))
	seenHistoricalIssues := make(map[string]struct{}, len(record.ObservedFloatingIPDeletes))
	for i := range record.ObservedFloatingIPDeletes {
		fence := observedFloatingIPDeleteFence(record.ObservedFloatingIPDeletes[i])
		if err := validateRemovalMutationFence(fence); err != nil {
			return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence has invalid observed floating-IP DELETE receipt %d: %w", i, err)
		}
		if _, duplicate := seenHistoricalMutations[fence.RemovalMutation]; duplicate {
			return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence repeats an observed floating-IP DELETE identity")
		}
		if _, duplicate := seenHistoricalIssues[fence.IssueID]; duplicate {
			return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence repeats an observed floating-IP DELETE issue")
		}
		seenHistoricalMutations[fence.RemovalMutation] = struct{}{}
		seenHistoricalIssues[fence.IssueID] = struct{}{}
	}
	if record.Phase == cloudapi.RemovalMutationReady {
		if record.Operation != "" || record.Location != "" || record.VMUUID != "" || record.Address != "" || record.Name != "" || record.BillingID != 0 ||
			record.IssueID != "" || record.IssuedAt != nil || record.RejectedAt != nil || record.ObservedAt != nil ||
			len(record.ObservedFloatingIPDeletes) != 0 {
			return removalMutationRecord{}, fmt.Errorf("durable removal mutation ready fence contains mutation state")
		}
		return record, nil
	}
	fence := removalMutationFenceFromRecord(record)
	if validateRemovalMutationFence(fence) != nil || record.IssuedAt == nil || record.IssuedAt.IsZero() {
		return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence has incomplete mutation identity")
	}
	validPhase := (record.Phase == cloudapi.RemovalMutationIssued && record.RejectedAt == nil && record.ObservedAt == nil) ||
		(record.Phase == cloudapi.RemovalMutationRejected && record.RejectedAt != nil && !record.RejectedAt.IsZero() && record.ObservedAt == nil) ||
		(record.Phase == cloudapi.RemovalMutationObserved && record.ObservedAt != nil && !record.ObservedAt.IsZero() && record.RejectedAt == nil)
	if !validPhase {
		return removalMutationRecord{}, fmt.Errorf("durable removal mutation fence has contradictory phase timestamps")
	}
	return record, nil
}

func (s *kubernetesCreateFenceStore) EnsureRemovalFence(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string) (*karpv1.NodeClaim, error) {
	for attempt := 0; attempt < 4; attempt++ {
		current, err := s.getProtectedExact(ctx, claim, "initialize removal mutation fence")
		if err != nil {
			return nil, err
		}
		createRecord, err := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if err != nil {
			return nil, err
		}
		if token == "" || createRecord.Token != token {
			return nil, fmt.Errorf("NodeClaim %q removal fence token changed", claim.Name)
		}
		if encoded := current.Annotations[AnnotationRemovalMutationFence]; encoded != "" {
			if _, err := decodeRemovalMutationRecord(encoded, binding, token); err != nil {
				return nil, err
			}
			return current, nil
		}
		if !current.DeletionTimestamp.IsZero() || createRecord.RollbackAt != nil {
			return nil, fmt.Errorf("NodeClaim %q lacks a pre-removal fence after deletion or rollback began", claim.Name)
		}
		record := newRemovalMutationReadyRecord(binding, token, s.now())
		written, writeErr := s.persistRemovalMutation(ctx, current, record, func(stored removalMutationRecord) bool {
			return stored.Phase == cloudapi.RemovalMutationReady && stored.ReadyAt.Equal(record.ReadyAt)
		})
		if writeErr == nil {
			return written, nil
		}
		claim = current
	}
	return nil, fmt.Errorf("NodeClaim %q initial removal mutation fence did not converge", claim.Name)
}

func (s *kubernetesCreateFenceStore) AuthorizeRemovalMutation(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	mutation cloudapi.RemovalMutation,
	present bool,
) (*karpv1.NodeClaim, cloudapi.RemovalMutationAuthorization, error) {
	desired, err := normalizeRemovalMutation(mutation)
	if err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "authorize removal mutation")
		if readErr != nil {
			return nil, cloudapi.RemovalMutationAuthorization{}, readErr
		}
		createRecord, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, cloudapi.RemovalMutationAuthorization{}, parseErr
		}
		if token == "" || createRecord.Token != token {
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q removal mutation token changed", claim.Name)
		}
		record, decodeErr := decodeRemovalMutationRecord(current.Annotations[AnnotationRemovalMutationFence], binding, token)
		if decodeErr != nil {
			return nil, cloudapi.RemovalMutationAuthorization{}, decodeErr
		}
		if historical, found := historicalObservedFloatingIPDelete(record, desired); found {
			if present {
				return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q observed removal resource reappeared", claim.Name)
			}
			return current, cloudapi.RemovalMutationAuthorization{Fence: historical, Active: true}, nil
		}
		exact := removalMutationIdentityMatches(record, desired)
		switch record.Phase {
		case cloudapi.RemovalMutationReady:
			if !present {
				return current, cloudapi.RemovalMutationAuthorization{}, nil
			}
		case cloudapi.RemovalMutationIssued:
			if exact {
				return current, cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
			}
			if !present {
				return current, cloudapi.RemovalMutationAuthorization{}, nil
			}
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q has an unresolved different removal mutation", claim.Name)
		case cloudapi.RemovalMutationRejected:
			if exact && !present {
				return current, cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
			}
			if !exact {
				if !present {
					return current, cloudapi.RemovalMutationAuthorization{}, nil
				}
				return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q has an unresolved rejected removal mutation", claim.Name)
			}
		case cloudapi.RemovalMutationObserved:
			if exact {
				if present {
					return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q observed removal resource reappeared", claim.Name)
				}
				return current, cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
			}
			if !present {
				return current, cloudapi.RemovalMutationAuthorization{}, nil
			}
		default:
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("NodeClaim %q has invalid removal mutation phase %q", claim.Name, record.Phase)
		}

		issueID, nonceErr := s.nonce()
		if nonceErr != nil {
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("generating removal mutation issue identity: %w", nonceErr)
		}
		if err := archiveCurrentObservedFloatingIPDelete(&record); err != nil {
			return nil, cloudapi.RemovalMutationAuthorization{}, err
		}
		now := s.now().UTC()
		issued := removalMutationRecord{
			Schema: removalMutationFenceSchema, Binding: binding, AttemptToken: token, ReadyAt: record.ReadyAt,
			Operation: desired.Operation, Location: desired.Location, VMUUID: desired.VMUUID,
			Address: desired.Address, Name: desired.Name, BillingID: desired.BillingAccountID,
			Phase: cloudapi.RemovalMutationIssued, IssueID: issueID, IssuedAt: &now,
			ObservedFloatingIPDeletes: append([]observedFloatingIPDeleteRecord(nil), record.ObservedFloatingIPDeletes...),
		}
		written, writeErr := s.persistRemovalMutation(ctx, current, issued, func(stored removalMutationRecord) bool {
			return stored.Phase == cloudapi.RemovalMutationIssued && stored.IssueID == issueID && removalMutationIdentityMatches(stored, desired)
		})
		if writeErr == nil {
			return written, cloudapi.RemovalMutationAuthorization{
				Fence: removalMutationFenceFromRecord(issued), Active: true, AllowMutation: true,
			}, nil
		}
		lastErr = writeErr
		claim = current
	}
	return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("persisting issued removal mutation for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) ObserveRemovalMutation(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error) {
	return s.finishRemovalMutation(ctx, claim, binding, token, fence, cloudapi.RemovalMutationObserved)
}

func (s *kubernetesCreateFenceStore) RejectRemovalMutation(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error) {
	return s.finishRemovalMutation(ctx, claim, binding, token, fence, cloudapi.RemovalMutationRejected)
}

func (s *kubernetesCreateFenceStore) finishRemovalMutation(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	fence cloudapi.RemovalMutationFence,
	terminal cloudapi.RemovalMutationPhase,
) (*karpv1.NodeClaim, error) {
	if err := validateRemovalMutationFence(fence); err != nil {
		return nil, err
	}
	if terminal != cloudapi.RemovalMutationObserved && terminal != cloudapi.RemovalMutationRejected {
		return nil, fmt.Errorf("invalid removal terminal phase %q", terminal)
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "finish removal mutation")
		if readErr != nil {
			return nil, readErr
		}
		if _, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding); parseErr != nil {
			return nil, parseErr
		}
		record, decodeErr := decodeRemovalMutationRecord(current.Annotations[AnnotationRemovalMutationFence], binding, token)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if !removalMutationIdentityMatches(record, fence.RemovalMutation) || record.IssueID != fence.IssueID {
			return nil, fmt.Errorf("NodeClaim %q removal mutation identity changed", claim.Name)
		}
		durableFence := removalMutationFenceFromRecord(record)
		if !durableFence.IssuedAt.Equal(fence.IssuedAt) {
			return nil, fmt.Errorf("NodeClaim %q removal mutation issue time changed", claim.Name)
		}
		if record.Phase == terminal {
			if terminal != cloudapi.RemovalMutationObserved || fence.Operation != cloudapi.RemovalMutationFloatingIPDelete {
				return current, nil
			}
			if _, found := historicalObservedFloatingIPDelete(record, fence.RemovalMutation); found {
				return current, nil
			}
			if record.ObservedAt == nil || record.ObservedAt.IsZero() {
				return nil, fmt.Errorf("NodeClaim %q observed floating-IP DELETE has no observation time", claim.Name)
			}
			if err := appendObservedFloatingIPDelete(&record, durableFence, record.ObservedAt.UTC()); err != nil {
				return nil, err
			}
			written, writeErr := s.persistRemovalMutation(ctx, current, record, func(stored removalMutationRecord) bool {
				_, found := historicalObservedFloatingIPDelete(stored, fence.RemovalMutation)
				return stored.Phase == terminal && stored.IssueID == fence.IssueID &&
					removalMutationIdentityMatches(stored, fence.RemovalMutation) && found
			})
			if writeErr == nil {
				return written, nil
			}
			lastErr = writeErr
			claim = current
			continue
		}
		if terminal == cloudapi.RemovalMutationRejected && record.Phase != cloudapi.RemovalMutationIssued {
			return nil, fmt.Errorf("NodeClaim %q removal mutation is not issued", claim.Name)
		}
		if terminal == cloudapi.RemovalMutationObserved && record.Phase != cloudapi.RemovalMutationIssued && record.Phase != cloudapi.RemovalMutationRejected {
			return nil, fmt.Errorf("NodeClaim %q removal mutation has no observable receipt", claim.Name)
		}
		if fence.Phase != record.Phase {
			return nil, fmt.Errorf("NodeClaim %q removal mutation phase changed", claim.Name)
		}
		now := s.now().UTC()
		record.Phase = terminal
		if terminal == cloudapi.RemovalMutationObserved {
			record.ObservedAt = &now
			record.RejectedAt = nil
			if err := appendObservedFloatingIPDelete(&record, durableFence, now); err != nil {
				return nil, err
			}
		} else {
			record.RejectedAt = &now
			record.ObservedAt = nil
		}
		written, writeErr := s.persistRemovalMutation(ctx, current, record, func(stored removalMutationRecord) bool {
			if stored.Phase != terminal || stored.IssueID != fence.IssueID ||
				!removalMutationIdentityMatches(stored, fence.RemovalMutation) {
				return false
			}
			if terminal == cloudapi.RemovalMutationObserved && fence.Operation == cloudapi.RemovalMutationFloatingIPDelete {
				_, found := historicalObservedFloatingIPDelete(stored, fence.RemovalMutation)
				return found
			}
			return true
		})
		if writeErr == nil {
			return written, nil
		}
		lastErr = writeErr
		claim = current
	}
	return nil, fmt.Errorf("persisting terminal removal mutation for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) persistRemovalMutation(
	ctx context.Context,
	current *karpv1.NodeClaim,
	record removalMutationRecord,
	accept func(removalMutationRecord) bool,
) (*karpv1.NodeClaim, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encoding NodeClaim %q removal mutation fence: %w", current.Name, err)
	}
	if len(encoded) > maxRemovalMutationEncodedBytes {
		return nil, fmt.Errorf(
			"encoding NodeClaim %q removal mutation fence exceeds %d bytes",
			current.Name,
			maxRemovalMutationEncodedBytes,
		)
	}
	copy := current.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[AnnotationRemovalMutationFence] = string(encoded)
	updateErr := s.writer.Update(ctx, copy)
	readCtx, cancel := detachedCreateFenceContext(ctx)
	defer cancel()
	var readback karpv1.NodeClaim
	if readErr := s.reader.Get(readCtx, types.NamespacedName{Name: current.Name}, &readback); readErr != nil {
		return nil, fmt.Errorf("writing and reading back NodeClaim %q removal mutation fence: %w", current.Name, errors.Join(updateErr, readErr))
	}
	if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection during removal mutation fencing", current.Name)
	}
	stored, decodeErr := decodeRemovalMutationRecord(readback.Annotations[AnnotationRemovalMutationFence], record.Binding, record.AttemptToken)
	if decodeErr != nil {
		return nil, errors.Join(updateErr, decodeErr)
	}
	if accept(stored) {
		return &readback, nil
	}
	if updateErr != nil {
		return nil, updateErr
	}
	return nil, fmt.Errorf("NodeClaim %q removal mutation fence changed during readback", current.Name)
}

func claimWithRemovalMutation(claim *karpv1.NodeClaim, record removalMutationRecord) *karpv1.NodeClaim {
	copy := claim.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	copy.Annotations[AnnotationRemovalMutationFence] = string(encoded)
	return copy
}

func (s *memoryCreateFenceStore) EnsureRemovalFence(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	createRecord, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(createRecord), binding); err != nil {
		return nil, err
	}
	if token == "" || createRecord.Token != token {
		return nil, fmt.Errorf("removal fence token changed")
	}
	if record, ok := s.removalMutations[claim.UID]; ok {
		if _, err := decodeRemovalMutationRecord(mustEncodeRemovalMutation(record), binding, token); err != nil {
			return nil, err
		}
		return claimWithRemovalMutation(claimWithCreateFence(claim, createRecord), record), nil
	}
	if claim.DeletionTimestamp != nil || createRecord.RollbackAt != nil {
		return nil, fmt.Errorf("NodeClaim lacks a pre-removal fence after deletion or rollback began")
	}
	record := newRemovalMutationReadyRecord(binding, token, s.now())
	s.removalMutations[claim.UID] = record
	return claimWithRemovalMutation(claimWithCreateFence(claim, createRecord), record), nil
}

func (s *memoryCreateFenceStore) AuthorizeRemovalMutation(
	_ context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	mutation cloudapi.RemovalMutation,
	present bool,
) (*karpv1.NodeClaim, cloudapi.RemovalMutationAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	desired, err := normalizeRemovalMutation(mutation)
	if err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, err
	}
	createRecord, ok := s.records[claim.UID]
	if !ok {
		return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(createRecord), binding); err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("removal mutation create identity changed: %w", err)
	}
	if token == "" || createRecord.Token != token {
		return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("removal mutation create token changed")
	}
	record, ok := s.removalMutations[claim.UID]
	if !ok {
		return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("durable removal mutation fence is missing")
	}
	if _, err := decodeRemovalMutationRecord(mustEncodeRemovalMutation(record), binding, token); err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, err
	}
	if historical, found := historicalObservedFloatingIPDelete(record, desired); found {
		if present {
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("observed removal resource reappeared")
		}
		return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{Fence: historical, Active: true}, nil
	}
	exact := removalMutationIdentityMatches(record, desired)
	switch record.Phase {
	case cloudapi.RemovalMutationReady:
		if !present {
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{}, nil
		}
	case cloudapi.RemovalMutationIssued:
		if exact {
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
		}
		if !present {
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{}, nil
		}
		return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("unresolved different removal mutation")
	case cloudapi.RemovalMutationRejected:
		if exact && !present {
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
		}
		if !exact {
			if !present {
				return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{}, nil
			}
			return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("unresolved rejected removal mutation")
		}
	case cloudapi.RemovalMutationObserved:
		if exact {
			if present {
				return nil, cloudapi.RemovalMutationAuthorization{}, fmt.Errorf("observed removal resource reappeared")
			}
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true}, nil
		}
		if !present {
			return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{}, nil
		}
	}
	issueID, err := s.nonce()
	if err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, err
	}
	if err := archiveCurrentObservedFloatingIPDelete(&record); err != nil {
		return nil, cloudapi.RemovalMutationAuthorization{}, err
	}
	now := s.now().UTC()
	record = removalMutationRecord{
		Schema: removalMutationFenceSchema, Binding: binding, AttemptToken: token, ReadyAt: record.ReadyAt,
		Operation: desired.Operation, Location: desired.Location, VMUUID: desired.VMUUID,
		Address: desired.Address, Name: desired.Name, BillingID: desired.BillingAccountID,
		Phase: cloudapi.RemovalMutationIssued, IssueID: issueID, IssuedAt: &now,
		ObservedFloatingIPDeletes: append([]observedFloatingIPDeleteRecord(nil), record.ObservedFloatingIPDeletes...),
	}
	s.removalMutations[claim.UID] = record
	return claimWithRemovalMutation(claim, record), cloudapi.RemovalMutationAuthorization{Fence: removalMutationFenceFromRecord(record), Active: true, AllowMutation: true}, nil
}

func (s *memoryCreateFenceStore) ObserveRemovalMutation(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error) {
	return s.finishMemoryRemovalMutation(claim, binding, token, fence, cloudapi.RemovalMutationObserved)
}

func (s *memoryCreateFenceStore) RejectRemovalMutation(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error) {
	return s.finishMemoryRemovalMutation(claim, binding, token, fence, cloudapi.RemovalMutationRejected)
}

func (s *memoryCreateFenceStore) finishMemoryRemovalMutation(claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.RemovalMutationFence, terminal cloudapi.RemovalMutationPhase) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateRemovalMutationFence(fence); err != nil {
		return nil, err
	}
	createRecord, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(createRecord), binding); err != nil {
		return nil, fmt.Errorf("removal mutation create identity changed: %w", err)
	}
	if token == "" || createRecord.Token != token {
		return nil, fmt.Errorf("removal mutation create token changed")
	}
	record, ok := s.removalMutations[claim.UID]
	if !ok || !removalMutationIdentityMatches(record, fence.RemovalMutation) || record.IssueID != fence.IssueID {
		return nil, fmt.Errorf("removal mutation identity changed")
	}
	durableFence := removalMutationFenceFromRecord(record)
	if !durableFence.IssuedAt.Equal(fence.IssuedAt) {
		return nil, fmt.Errorf("removal mutation issue time changed")
	}
	if record.Phase == terminal {
		if terminal == cloudapi.RemovalMutationObserved && fence.Operation == cloudapi.RemovalMutationFloatingIPDelete {
			if _, found := historicalObservedFloatingIPDelete(record, fence.RemovalMutation); !found {
				if record.ObservedAt == nil || record.ObservedAt.IsZero() {
					return nil, fmt.Errorf("observed floating-IP DELETE has no observation time")
				}
				if err := appendObservedFloatingIPDelete(&record, durableFence, record.ObservedAt.UTC()); err != nil {
					return nil, err
				}
				s.removalMutations[claim.UID] = record
			}
		}
		return claimWithRemovalMutation(claim, record), nil
	}
	if terminal == cloudapi.RemovalMutationRejected && record.Phase != cloudapi.RemovalMutationIssued {
		return nil, fmt.Errorf("removal mutation is not issued")
	}
	if terminal == cloudapi.RemovalMutationObserved && record.Phase != cloudapi.RemovalMutationIssued && record.Phase != cloudapi.RemovalMutationRejected {
		return nil, fmt.Errorf("removal mutation has no observable receipt")
	}
	if fence.Phase != record.Phase {
		return nil, fmt.Errorf("removal mutation phase changed")
	}
	now := s.now().UTC()
	record.Phase = terminal
	if terminal == cloudapi.RemovalMutationObserved {
		record.ObservedAt = &now
		record.RejectedAt = nil
		if err := appendObservedFloatingIPDelete(&record, durableFence, now); err != nil {
			return nil, err
		}
	} else {
		record.RejectedAt = &now
		record.ObservedAt = nil
	}
	s.removalMutations[claim.UID] = record
	return claimWithRemovalMutation(claim, record), nil
}

func mustEncodeRemovalMutation(record removalMutationRecord) string {
	encoded, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
