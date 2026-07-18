package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

const (
	createAttemptPhaseIntent       = "intent"
	createAttemptPhaseIssued       = "issued"
	createAttemptPhaseRejected     = "rejection-pending"
	createAttemptPhaseMaterialized = "materialized"
	createAttemptPhaseAdopted      = "adopted"

	createAttemptKindVM                 = "virtual-machine"
	createAttemptKindFirewall           = "firewall"
	createAttemptKindFirewallAssignment = "firewall-assignment"
	createAttemptKindFloatingIPUpdate   = "floating-ip-update"

	createAttemptBastionFirewall           = "firewall/bastion"
	createAttemptNodeFirewall              = "firewall/nodes"
	createAttemptBastionVM                 = "vm/bastion"
	createAttemptBastionFirewallAssignment = "firewall-assignment/bastion"
	createAttemptBastionFloatingIPUpdate   = "floating-ip-update/bastion"
)

var ErrCreateAttemptPending = errors.New("bootstrap: cloud mutation is durably issued and awaiting authoritative recovery")

// IssuedVMCreateAbsentError identifies one durably issued VM POST whose exact
// deterministic-name result is still absent from authoritative inventory.
// It remains ErrCreateAttemptPending so callers must never replay the POST.
// IssuedAt is the durable issue time, allowing a supervising one-shot command
// to enforce a restart-stable deadline without changing reconciliation safety.
type IssuedVMCreateAbsentError struct {
	AttemptKey   string
	ResourceName string
	IssuedAt     time.Time
}

func (e *IssuedVMCreateAbsentError) Error() string {
	return fmt.Sprintf(
		"bootstrap: issued VM create %q (attempt %q, issued %s) remains authoritatively absent",
		e.ResourceName,
		e.AttemptKey,
		e.IssuedAt.UTC().Format(time.RFC3339Nano),
	)
}

func (e *IssuedVMCreateAbsentError) Unwrap() error { return ErrCreateAttemptPending }

func issuedVMCreateAbsentError(
	attemptKey string,
	attempt v1alpha1.ResourceCreateAttemptStatus,
) error {
	issuedAt, err := time.Parse(time.RFC3339Nano, attempt.IssuedAt)
	if err != nil || issuedAt.Location() != time.UTC {
		return errors.Join(
			ErrCreateAttemptPending,
			fmt.Errorf("bootstrap: issued VM create attempt %q has an invalid durable issue time", attemptKey),
		)
	}
	return &IssuedVMCreateAbsentError{
		AttemptKey:   attemptKey,
		ResourceName: attempt.ResourceName,
		IssuedAt:     issuedAt,
	}
}

// StatusCompareAndSwapFunc persists one InSpaceCluster status transition and
// returns its authoritative readback. Kubernetes-backed controllers implement
// this with status resourceVersion CAS; the standalone bootstrap command uses
// an atomic, locked YAML-file CAS.
type StatusCompareAndSwapFunc func(
	context.Context,
	*v1alpha1.InSpaceCluster,
	v1alpha1.InSpaceClusterStatus,
	v1alpha1.InSpaceClusterStatus,
) (v1alpha1.InSpaceClusterStatus, error)

func controlPlaneCreateAttemptKey(slot int) string { return fmt.Sprintf("vm/control-plane-%d", slot) }

func controlPlaneFirewallAssignmentAttemptKey(slot int) string {
	return fmt.Sprintf("firewall-assignment/control-plane-%d", slot)
}

func controlPlaneFloatingIPUpdateAttemptKey(slot int) string {
	return fmt.Sprintf("floating-ip-update/control-plane-%d", slot)
}

func floatingIPUpdateAttemptKey(cluster *v1alpha1.InSpaceCluster, name string) (string, error) {
	if cluster == nil {
		return "", errors.New("bootstrap: floating-IP update attempt requires a cluster")
	}
	current := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	legacy := legacyBootstrapResourceNames(ownerKey(cluster))
	if name == current.BastionFloatingIP || name == legacy.BastionFloatingIP {
		return createAttemptBastionFloatingIPUpdate, nil
	}
	for slot := 0; slot < controlPlaneReplicaCount(cluster); slot++ {
		if name == current.ControlPlaneFIP[slot] || name == legacy.ControlPlaneFIP[slot] {
			return controlPlaneFloatingIPUpdateAttemptKey(slot), nil
		}
	}
	return "", fmt.Errorf("bootstrap: floating IP %q has no managed update-attempt slot", name)
}

func firewallAssignmentAttemptKey(vmCreateAttemptKey string) (string, error) {
	if vmCreateAttemptKey == createAttemptBastionVM {
		return createAttemptBastionFirewallAssignment, nil
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		if vmCreateAttemptKey == controlPlaneCreateAttemptKey(slot) {
			return controlPlaneFirewallAssignmentAttemptKey(slot), nil
		}
	}
	return "", fmt.Errorf("bootstrap: VM create-attempt key %q has no firewall-assignment slot", vmCreateAttemptKey)
}

func createIntentHash(kind, name string, request any) (string, error) {
	payload := struct {
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		Request any    `json:"request"`
	}{Kind: kind, Name: name, Request: request}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("bootstrap: encode %s %q create intent: %w", kind, name, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func cloneClusterStatus(status v1alpha1.InSpaceClusterStatus) v1alpha1.InSpaceClusterStatus {
	copy := status
	if status.CreateAttempts != nil {
		copy.CreateAttempts = make(map[string]v1alpha1.ResourceCreateAttemptStatus, len(status.CreateAttempts))
		for key, attempt := range status.CreateAttempts {
			copy.CreateAttempts[key] = attempt
		}
	}
	if status.DeleteAttempts != nil {
		copy.DeleteAttempts = make(map[string]v1alpha1.ResourceDeleteAttemptStatus, len(status.DeleteAttempts))
		for key, attempt := range status.DeleteAttempts {
			copy.DeleteAttempts[key] = attempt
		}
	}
	return copy
}

func (r *Reconciler) compareAndSwapClusterStatus(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	mutate func(*v1alpha1.InSpaceClusterStatus) error,
) error {
	if r.StatusCompareAndSwap == nil {
		return errors.New("bootstrap: a durable InSpaceCluster status compare-and-swap store is required before cloud mutation")
	}
	r.statusMu.Lock()
	defer r.statusMu.Unlock()

	expected := cloneClusterStatus(cluster.Status)
	desired := cloneClusterStatus(cluster.Status)
	if err := mutate(&desired); err != nil {
		return err
	}
	if len(desired.CreateAttempts) == 0 {
		desired.CreateAttempts = nil
	}
	if len(desired.DeleteAttempts) == 0 {
		desired.DeleteAttempts = nil
	}
	if reflect.DeepEqual(expected, desired) {
		return nil
	}
	persisted, err := r.StatusCompareAndSwap(ctx, cluster, expected, desired)
	if err != nil {
		return fmt.Errorf("bootstrap: persist mutation-attempt status CAS: %w", err)
	}
	if !reflect.DeepEqual(persisted, desired) {
		return errors.New("bootstrap: mutation-attempt status CAS readback did not match the requested transition")
	}
	cluster.Status = cloneClusterStatus(persisted)
	return nil
}

func (r *Reconciler) createAttempt(cluster *v1alpha1.InSpaceCluster, key string) (v1alpha1.ResourceCreateAttemptStatus, bool) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	attempt, ok := cluster.Status.CreateAttempts[key]
	return attempt, ok
}

func (r *Reconciler) hasUnresolvedVMCreate(cluster *v1alpha1.InSpaceCluster) bool {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	for _, attempt := range cluster.Status.CreateAttempts {
		if attempt.ResourceKind == createAttemptKindVM && attempt.Phase != createAttemptPhaseIntent {
			return true
		}
	}
	return false
}

func (r *Reconciler) compareAndSwapStatus(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	mutate func(map[string]v1alpha1.ResourceCreateAttemptStatus) error,
) error {
	return r.compareAndSwapClusterStatus(ctx, cluster, func(status *v1alpha1.InSpaceClusterStatus) error {
		if status.CreateAttempts == nil {
			status.CreateAttempts = make(map[string]v1alpha1.ResourceCreateAttemptStatus)
		}
		return mutate(status.CreateAttempts)
	})
}

// detachedStatusMutationContext lets the controller finish one receipt
// transition after its reconcile context is canceled, while retaining the
// same finite request budget used for other bootstrap protection writes.
// Without this bound a stalled Kubernetes API write could pin a reconcile
// goroutine forever during error recovery.
func (r *Reconciler) detachedStatusMutationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.WithoutCancel(ctx),
		configuredDuration(r.protectionRequestTimeout, defaultProtectionRequestTimeout),
	)
}

func validateCreateAttempt(attempt v1alpha1.ResourceCreateAttemptStatus, kind, name, intentHash string) error {
	if attempt.ResourceKind != kind || attempt.ResourceName != name || attempt.IntentHash != intentHash {
		return fmt.Errorf("bootstrap: durable create attempt for %s %q does not match the current immutable intent", kind, name)
	}
	switch attempt.Phase {
	case createAttemptPhaseIntent:
		if attempt.IssueID != "" || attempt.IssuedAt != "" || attempt.ResourceUUID != "" {
			return errors.New("bootstrap: intent-phase create attempt contains issued or materialized fields")
		}
	case createAttemptPhaseIssued:
		if !validCreateIssue(attempt) || attempt.ResourceUUID != "" {
			return errors.New("bootstrap: issued create attempt has invalid durable issue identity")
		}
	case createAttemptPhaseRejected:
		if !validCreateIssue(attempt) || attempt.ResourceUUID != "" {
			return errors.New("bootstrap: rejection-pending create attempt has invalid durable issue identity")
		}
	case createAttemptPhaseMaterialized:
		if !validCreateIssue(attempt) || !vmUUIDPattern.MatchString(attempt.ResourceUUID) {
			return errors.New("bootstrap: materialized create attempt has invalid issue or resource identity")
		}
	case createAttemptPhaseAdopted:
		if attempt.IssueID != "" || attempt.IssuedAt != "" || !vmUUIDPattern.MatchString(attempt.ResourceUUID) {
			return errors.New("bootstrap: adopted create attempt has invalid resource identity")
		}
	default:
		return fmt.Errorf("bootstrap: create attempt has unknown phase %q", attempt.Phase)
	}
	return nil
}

func validCreateIssue(attempt v1alpha1.ResourceCreateAttemptStatus) bool {
	if len(attempt.IssueID) != 32 {
		return false
	}
	if _, err := hex.DecodeString(attempt.IssueID); err != nil {
		return false
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, attempt.IssuedAt)
	return err == nil && issuedAt.Location() == time.UTC
}

func newCreateIssueID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("bootstrap: generate cloud-mutation issue ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// authorizeCreate persists intent and then issued authority before the caller
// may send exactly one POST. An existing issued/materialized/adopted entry is
// read/adopt-only and therefore returns false.
func (r *Reconciler) authorizeCreate(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash string,
) (bool, error) {
	assignmentFirewallUUID := ""
	if kind == createAttemptKindFirewallAssignment {
		var parseErr error
		assignmentFirewallUUID, parseErr = firewallAssignmentResourceFirewallUUID(name)
		if parseErr != nil {
			return false, parseErr
		}
	}
	attempt, exists := r.createAttempt(cluster, key)
	if exists {
		if err := validateCreateAttempt(attempt, kind, name, intentHash); err != nil {
			return false, err
		}
		if attempt.Phase != createAttemptPhaseIntent {
			return false, nil
		}
	} else {
		if err := r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
			if _, occupied := attempts[key]; occupied {
				return fmt.Errorf("bootstrap: create-attempt key %q changed before intent persistence", key)
			}
			attempts[key] = v1alpha1.ResourceCreateAttemptStatus{
				ResourceKind: kind, ResourceName: name, IntentHash: intentHash, Phase: createAttemptPhaseIntent,
			}
			return nil
		}); err != nil {
			return false, err
		}
	}
	issueID, err := newCreateIssueID()
	if err != nil {
		return false, err
	}
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if err := r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		current, ok := attempts[key]
		if !ok {
			return fmt.Errorf("bootstrap: create intent %q disappeared before issue", key)
		}
		if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
			return err
		}
		if current.Phase != createAttemptPhaseIntent {
			return fmt.Errorf("bootstrap: create intent %q was already issued", key)
		}
		if assignmentFirewallUUID != "" {
			for otherKey, other := range attempts {
				if otherKey == key || other.ResourceKind != createAttemptKindFirewallAssignment || other.Phase != createAttemptPhaseIssued {
					continue
				}
				otherFirewallUUID, parseErr := firewallAssignmentResourceFirewallUUID(other.ResourceName)
				if parseErr != nil || !validCreateIssue(other) || other.ResourceUUID != "" {
					return fmt.Errorf("bootstrap: malformed unresolved firewall-assignment receipt %q: %v", otherKey, parseErr)
				}
				if strings.EqualFold(otherFirewallUUID, assignmentFirewallUUID) {
					return fmt.Errorf("%w: firewall %s already has unresolved assignment %q", ErrCreateAttemptPending, assignmentFirewallUUID, otherKey)
				}
			}
		}
		current.Phase = createAttemptPhaseIssued
		current.IssueID = issueID
		current.IssuedAt = issuedAt
		attempts[key] = current
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

func firewallAssignmentResourceFirewallUUID(resourceName string) (string, error) {
	parts := strings.Split(resourceName, "/")
	if len(parts) != 2 || !vmUUIDPattern.MatchString(parts[0]) || !vmUUIDPattern.MatchString(parts[1]) {
		return "", fmt.Errorf("bootstrap: invalid firewall-assignment resource identity %q", resourceName)
	}
	return strings.ToLower(parts[0]), nil
}

func (r *Reconciler) recordMaterializedCreate(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash, resourceUUID string,
) error {
	if !vmUUIDPattern.MatchString(resourceUUID) {
		return fmt.Errorf("bootstrap: cannot materialize %s %q with invalid UUID %q", kind, name, resourceUUID)
	}
	return r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		current, ok := attempts[key]
		if !ok {
			return fmt.Errorf("bootstrap: create attempt %q disappeared before materialization", key)
		}
		if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
			return err
		}
		if current.Phase == createAttemptPhaseMaterialized {
			if !strings.EqualFold(current.ResourceUUID, resourceUUID) {
				return fmt.Errorf("bootstrap: create attempt %q is already anchored to another UUID", key)
			}
			return nil
		}
		if current.Phase != createAttemptPhaseIssued && current.Phase != createAttemptPhaseRejected {
			return fmt.Errorf("bootstrap: create attempt %q cannot materialize from phase %q", key, current.Phase)
		}
		current.Phase = createAttemptPhaseMaterialized
		current.ResourceUUID = strings.ToLower(resourceUUID)
		attempts[key] = current
		return nil
	})
}

// recordPreDispatchCreateRejection durably records the shared client's typed
// local mutation block. This phase must never be entered from an HTTP/API
// response because every network response is post-dispatch ambiguous.
func (r *Reconciler) recordPreDispatchCreateRejection(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash string,
) error {
	persistCtx, cancel := r.detachedStatusMutationContext(ctx)
	defer cancel()
	return r.compareAndSwapStatus(persistCtx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		current, ok := attempts[key]
		if !ok {
			return fmt.Errorf("bootstrap: create attempt %q disappeared before rejection persistence", key)
		}
		if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
			return err
		}
		if current.Phase == createAttemptPhaseRejected {
			return nil
		}
		if current.Phase != createAttemptPhaseIssued {
			return fmt.Errorf("bootstrap: create attempt %q cannot record rejection from phase %q", key, current.Phase)
		}
		current.Phase = createAttemptPhaseRejected
		attempts[key] = current
		return nil
	})
}

// resetPreDispatchCreateIssue releases an issued one-shot mutation receipt
// only when the caller has not invoked the cloud mutation API. Post-CAS
// authority reads can fail or reject stale identity, but neither outcome is a
// dispatched POST/PATCH. Keeping the receipt issued in that case would turn a
// transient read-model failure into a permanent controller deadlock.
//
// The exact kind/name/intent tuple is revalidated inside the status CAS. Any
// concurrent transition therefore fails closed instead of clearing another
// controller's issue.
func (r *Reconciler) resetPreDispatchCreateIssue(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash string,
) error {
	persistCtx, cancel := r.detachedStatusMutationContext(ctx)
	defer cancel()
	return r.compareAndSwapStatus(persistCtx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		current, ok := attempts[key]
		if !ok {
			return fmt.Errorf("bootstrap: create attempt %q disappeared before pre-dispatch reset", key)
		}
		if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
			return err
		}
		if current.Phase != createAttemptPhaseIssued {
			return fmt.Errorf("bootstrap: create attempt %q changed before pre-dispatch reset", key)
		}
		current.Phase = createAttemptPhaseIntent
		current.IssueID = ""
		current.IssuedAt = ""
		current.ResourceUUID = ""
		attempts[key] = current
		return nil
	})
}

func (r *Reconciler) recordAdoptedCreate(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash, resourceUUID string,
) error {
	if !vmUUIDPattern.MatchString(resourceUUID) {
		return fmt.Errorf("bootstrap: cannot adopt %s %q with invalid UUID %q", kind, name, resourceUUID)
	}
	return r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		if current, ok := attempts[key]; ok {
			if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
				return err
			}
			if (current.Phase == createAttemptPhaseAdopted || current.Phase == createAttemptPhaseMaterialized) && strings.EqualFold(current.ResourceUUID, resourceUUID) {
				return nil
			}
			if current.Phase == createAttemptPhaseIntent {
				current.Phase = createAttemptPhaseAdopted
				current.ResourceUUID = strings.ToLower(resourceUUID)
				attempts[key] = current
				return nil
			}
			return fmt.Errorf("bootstrap: create attempt %q cannot adopt a different observed resource", key)
		}
		attempts[key] = v1alpha1.ResourceCreateAttemptStatus{
			ResourceKind: kind, ResourceName: name, IntentHash: intentHash,
			Phase: createAttemptPhaseAdopted, ResourceUUID: strings.ToLower(resourceUUID),
		}
		return nil
	})
}

func (r *Reconciler) clearPreDispatchCreateRejection(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	key, kind, name, intentHash string,
) error {
	return r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		current, ok := attempts[key]
		if !ok {
			return nil
		}
		if err := validateCreateAttempt(current, kind, name, intentHash); err != nil {
			return err
		}
		if current.Phase != createAttemptPhaseRejected {
			return fmt.Errorf("bootstrap: refusing to clear create attempt %q before its rejection and non-commit proof are durable", key)
		}
		delete(attempts, key)
		return nil
	})
}

func (r *Reconciler) clearAllCreateAttempts(ctx context.Context, cluster *v1alpha1.InSpaceCluster) error {
	if len(cluster.Status.CreateAttempts) == 0 {
		return nil
	}
	return r.compareAndSwapStatus(ctx, cluster, func(attempts map[string]v1alpha1.ResourceCreateAttemptStatus) error {
		for key := range attempts {
			delete(attempts, key)
		}
		return nil
	})
}
