package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	AnnotationCreateFence           = "karpenter.inspace.cloud/create-fence"
	AnnotationCreateFenceResolution = "karpenter.inspace.cloud/create-fence-resolution"
	AnnotationFloatingIPUpdateFence = "karpenter.inspace.cloud/floating-ip-update-fence"
	AnnotationRemovalMutationFence  = "karpenter.inspace.cloud/removal-mutation-fence"
	CreateFenceFinalizer            = "karpenter.inspace.cloud/create-protection"
	createFenceSchema               = "karpenter.inspace.cloud/create-fence-v3"
	legacyCreateFenceSchema         = "karpenter.inspace.cloud/create-fence-v2"
	createFenceResolutionSchema     = "karpenter.inspace.cloud/create-fence-resolution-v1"
	createFenceResolutionVM         = "vm"
	createFenceResolutionNoResult   = "no-result"
	floatingIPUpdateFenceSchema     = "karpenter.inspace.cloud/floating-ip-update-fence-v1"
	removalMutationFenceSchema      = "karpenter.inspace.cloud/removal-mutation-fence-v1"
	createFenceReserved             = "reserved"
	createFenceIssued               = "issued"
	createFenceRejected             = "rejected"
	createFenceMaterialized         = "materialized"
	createFenceTerminalWriteTimeout = 30 * time.Second
)

var (
	createFenceVMUUIDPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	createFenceKeyHashPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type createFenceBinding struct {
	NodeClaimUID       string `json:"nodeClaimUID"`
	IdempotencyKeyHash string `json:"idempotencyKeyHash"`
	RequestHash        string `json:"requestHash"`
	SpecHash           string `json:"specHash"`
	BootstrapHash      string `json:"bootstrapHash"`
}

type createFenceCleanupIdentity struct {
	ClusterName                  string                    `json:"clusterName"`
	Location                     string                    `json:"location"`
	NetworkUUID                  string                    `json:"networkUUID"`
	NodePoolName                 string                    `json:"nodePoolName"`
	ControlPlaneVIP              string                    `json:"controlPlaneVIP"`
	PrivateLoadBalancerPoolStart string                    `json:"privateLoadBalancerPoolStart"`
	PrivateLoadBalancerPoolStop  string                    `json:"privateLoadBalancerPoolStop"`
	FirewallUUID                 string                    `json:"firewallUUID"`
	FirewallProfile              inspacev1.FirewallProfile `json:"firewallProfile"`
	NodeClaimName                string                    `json:"nodeClaimName"`
	VMName                       string                    `json:"vmName"`
	BillingAccountID             int64                     `json:"billingAccountID"`
	OwnershipKeyHash             string                    `json:"ownershipKeyHash"`
}

type createFenceRecord struct {
	Schema    string                           `json:"schema"`
	Binding   createFenceBinding               `json:"binding"`
	Cleanup   createFenceCleanupIdentity       `json:"cleanup"`
	Baseline  cloudapi.CreateInventory         `json:"baseline"`
	Token     string                           `json:"token"`
	Phase     string                           `json:"phase"`
	Intent    cloudapi.CreateAuthorizationKind `json:"intent,omitempty"`
	IssueID   string                           `json:"issueID,omitempty"`
	StartedAt time.Time                        `json:"startedAt"`
	IssuedAt  *time.Time                       `json:"issuedAt,omitempty"`
	// CreatedVMUUID is the canonically verified launch identity anchored only
	// after full v3, billing-account, and configured-VPC proof. An SDK response
	// UUID is provisional until then. RollbackAt is an independent, irreversible
	// decision which races materialization for this same UUID.
	LaunchObservedAt *time.Time `json:"launchObservedAt,omitempty"`
	CreatedVMUUID    string     `json:"createdVMUUID,omitempty"`
	// ProtectionFailureAt starts a durable, restart-stable grace period when
	// protection readback reports pending but no dependent mutation remains
	// issued. It prevents an observed-then-drifted firewall or floating IP from
	// leaving the anchored public VM exposed forever.
	ProtectionFailureAt  *time.Time `json:"protectionFailureAt,omitempty"`
	RollbackAt           *time.Time `json:"rollbackAt,omitempty"`
	DependentUnresolved  bool       `json:"dependentUnresolved,omitempty"`
	DependentsResolvedAt *time.Time `json:"dependentsResolvedAt,omitempty"`
	ObservedAt           *time.Time `json:"observedAt,omitempty"`
	ObservedVMUUID       string     `json:"observedVMUUID,omitempty"`
	FloatingIPName       string     `json:"floatingIPName,omitempty"`
	PublicIPv4           string     `json:"publicIPv4,omitempty"`
	// Cleanup* is a controller-persisted receipt for an exact orphan found
	// during finalization. It is written and read back before the cloud adapter
	// is permitted to delete that VM, and may advance across legacy duplicates.
	CleanupResolvedAt      *time.Time                               `json:"cleanupResolvedAt,omitempty"`
	CleanupVMUUID          string                                   `json:"cleanupVMUUID,omitempty"`
	CleanupFloatingIPName  string                                   `json:"cleanupFloatingIPName,omitempty"`
	CleanupPublicIPv4      string                                   `json:"cleanupPublicIPv4,omitempty"`
	CleanupResolutions     []cloudapi.FencedCreateCleanupResolution `json:"cleanupResolutions,omitempty"`
	BaseFirewallAssignment *baseFirewallAssignmentRecord            `json:"baseFirewallAssignment,omitempty"`
	// LegacyV2 remains persisted after migration so newly added mutation
	// fences can conservatively treat a pre-upgrade attempt as possibly issued.
	LegacyV2                        bool `json:"legacyV2MutationFence,omitempty"`
	LegacyV2BaseFirewallMayBeIssued bool `json:"legacyV2BaseFirewallMayBeIssued,omitempty"`
	LegacyV2FloatingIPMayBeIssued   bool `json:"legacyV2FloatingIPMayBeIssued,omitempty"`
}

type baseFirewallAssignmentRecord struct {
	VMUUID       string                           `json:"vmUUID"`
	FirewallUUID string                           `json:"firewallUUID"`
	Phase        cloudapi.FirewallAssignmentPhase `json:"phase"`
	IssueID      string                           `json:"issueID,omitempty"`
	IntentAt     time.Time                        `json:"intentAt"`
	IssuedAt     *time.Time                       `json:"issuedAt,omitempty"`
	RejectedAt   *time.Time                       `json:"rejectedAt,omitempty"`
	ObservedAt   *time.Time                       `json:"observedAt,omitempty"`
}

type floatingIPUpdateRecord struct {
	Schema           string                         `json:"schema"`
	Binding          createFenceBinding             `json:"binding"`
	AttemptToken     string                         `json:"attemptToken"`
	VMUUID           string                         `json:"vmUUID"`
	Address          string                         `json:"address"`
	Name             string                         `json:"name"`
	BillingAccountID int64                          `json:"billingAccountID"`
	Phase            cloudapi.FloatingIPUpdatePhase `json:"phase"`
	IssueID          string                         `json:"issueID"`
	IssuedAt         time.Time                      `json:"issuedAt"`
	RejectedAt       *time.Time                     `json:"rejectedAt,omitempty"`
	ObservedAt       *time.Time                     `json:"observedAt,omitempty"`
}

type createFence struct {
	Token                  string
	StartedAt              time.Time
	Baseline               cloudapi.CreateInventory
	Issued                 bool
	IssuedAt               time.Time
	Intent                 cloudapi.CreateAuthorizationKind
	IssueID                string
	CreatedVMUUID          string
	HasCleanupHistory      bool
	RollbackChosen         bool
	BaseFirewallAssignment cloudapi.FirewallAssignmentFence
}

type createFenceOperatorResolution struct {
	Schema  string `json:"schema"`
	IssueID string `json:"issueID"`
	Result  string `json:"result"`
	VMUUID  string `json:"vmUUID,omitempty"`
}

func decodeCreateFenceOperatorResolution(value string) (createFenceOperatorResolution, error) {
	if value == "" || len(value) > 1024 {
		return createFenceOperatorResolution{}, fmt.Errorf("create-fence operator resolution is empty or oversized")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &fields); err != nil {
		return createFenceOperatorResolution{}, fmt.Errorf("decoding create-fence operator resolution: %w", err)
	}
	if fields == nil {
		return createFenceOperatorResolution{}, fmt.Errorf("create-fence operator resolution must be a JSON object")
	}
	for field := range fields {
		switch field {
		case "schema", "issueID", "result", "vmUUID":
		default:
			return createFenceOperatorResolution{}, fmt.Errorf("create-fence operator resolution contains unknown field %q", field)
		}
	}
	var resolution createFenceOperatorResolution
	if err := json.Unmarshal([]byte(value), &resolution); err != nil {
		return createFenceOperatorResolution{}, fmt.Errorf("decoding create-fence operator resolution: %w", err)
	}
	if resolution.Schema != createFenceResolutionSchema || !createFenceKeyHashPattern.MatchString(resolution.IssueID) {
		return createFenceOperatorResolution{}, fmt.Errorf("create-fence operator resolution has invalid schema or issue identity")
	}
	switch resolution.Result {
	case createFenceResolutionVM:
		resolution.VMUUID = strings.ToLower(resolution.VMUUID)
		if !createFenceVMUUIDPattern.MatchString(resolution.VMUUID) {
			return createFenceOperatorResolution{}, fmt.Errorf("VM create-fence resolution requires a canonical VM UUID")
		}
	case createFenceResolutionNoResult:
		if resolution.VMUUID != "" {
			return createFenceOperatorResolution{}, fmt.Errorf("no-result create-fence resolution cannot include a VM UUID")
		}
	default:
		return createFenceOperatorResolution{}, fmt.Errorf("unsupported create-fence operator result %q", resolution.Result)
	}
	return resolution, nil
}

// CreateFenceStore atomically persists a provider finalizer, immutable POST
// token, exact launch binding, and bounded pre-POST cloud inventory. Ensure
// returns acquired=true only to the invocation that created that record.
// Authorize is an uncached exact read used immediately before the SDK POST.
// A token is never rotated after POST authority has been granted.
type CreateFenceStore interface {
	Get(context.Context, *karpv1.NodeClaim, createFenceBinding, createFenceCleanupIdentity) (*karpv1.NodeClaim, createFence, bool, error)
	Ensure(context.Context, *karpv1.NodeClaim, createFenceBinding, createFenceCleanupIdentity, cloudapi.CreateInventory) (*karpv1.NodeClaim, createFence, bool, error)
	Authorize(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.CreateAuthorizationKind) (*karpv1.NodeClaim, error)
	RecordCreatedVM(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string, string) (*karpv1.NodeClaim, error)
	AuthorizeBaseFirewall(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string) (*karpv1.NodeClaim, cloudapi.FirewallAssignmentAuthorization, error)
	ObserveBaseFirewall(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string, string) (*karpv1.NodeClaim, error)
	RejectBaseFirewall(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string, string) (*karpv1.NodeClaim, error)
	AuthorizeBaseFirewallDetach(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string) (cloudapi.FirewallDetachmentAuthorization, error)
	ObserveBaseFirewallDetach(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.FirewallDetachmentFence) error
	RejectBaseFirewallDetach(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.FirewallDetachmentFence) error
	AuthorizeFloatingIPUpdate(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string, string, string, int64) (*karpv1.NodeClaim, cloudapi.FloatingIPUpdateAuthorization, error)
	ObserveFloatingIPUpdate(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.FloatingIPUpdateFence) (*karpv1.NodeClaim, error)
	RejectFloatingIPUpdate(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.FloatingIPUpdateFence) (*karpv1.NodeClaim, error)
	EnsureRemovalFence(context.Context, *karpv1.NodeClaim, createFenceBinding, string) (*karpv1.NodeClaim, error)
	AuthorizeRemovalMutation(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.RemovalMutation, bool) (*karpv1.NodeClaim, cloudapi.RemovalMutationAuthorization, error)
	ObserveRemovalMutation(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error)
	RejectRemovalMutation(context.Context, *karpv1.NodeClaim, createFenceBinding, string, cloudapi.RemovalMutationFence) (*karpv1.NodeClaim, error)
	ChooseRollback(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string, string, *cloudapi.FencedCreateCleanupResolution) (*karpv1.NodeClaim, error)
	MarkRejected(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string) (*karpv1.NodeClaim, error)
	MarkMaterialized(context.Context, *karpv1.NodeClaim, createFenceBinding, string, *cloudapi.VM) (*karpv1.NodeClaim, error)
}

type kubernetesCreateFenceStore struct {
	writer    client.Client
	reader    client.Reader
	namespace string
	now       func() time.Time
	nonce     func() (string, error)
}

func NewKubernetesCreateFenceStore(writer client.Client, reader client.Reader, namespaces ...string) (CreateFenceStore, error) {
	if writer == nil || reader == nil {
		return nil, fmt.Errorf("Kubernetes writer and uncached reader are required for durable VM create fencing")
	}
	if len(namespaces) > 1 {
		return nil, fmt.Errorf("at most one controller namespace may be supplied for durable firewall coordination")
	}
	namespace := "karpenter"
	if len(namespaces) == 1 {
		namespace = strings.TrimSpace(namespaces[0])
	}
	if namespace == "" {
		return nil, fmt.Errorf("controller namespace is required for durable firewall coordination")
	}
	return &kubernetesCreateFenceStore{writer: writer, reader: reader, namespace: namespace, now: time.Now, nonce: createFenceNonce}, nil
}

func detachedCreateFenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), createFenceTerminalWriteTimeout)
}

func (s *kubernetesCreateFenceStore) Get(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, cleanup createFenceCleanupIdentity) (*karpv1.NodeClaim, createFence, bool, error) {
	current, err := s.getExact(ctx, claim)
	if err != nil {
		return nil, createFence{}, false, err
	}
	encoded := current.Annotations[AnnotationCreateFence]
	if encoded == "" {
		return current, createFence{}, false, nil
	}
	record, err := parseCreateFence(encoded, binding)
	if err != nil {
		return nil, createFence{}, false, err
	}
	if record.Cleanup != cleanup || !controllerutil.ContainsFinalizer(current, CreateFenceFinalizer) {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q durable VM create protection changed", claim.Name)
	}
	return current, fenceFromRecord(record), true, nil
}

func (s *kubernetesCreateFenceStore) Ensure(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	cleanup createFenceCleanupIdentity,
	baseline cloudapi.CreateInventory,
) (*karpv1.NodeClaim, createFence, bool, error) {
	current, err := s.getExact(ctx, claim)
	if err != nil {
		return nil, createFence{}, false, err
	}
	if encoded := current.Annotations[AnnotationCreateFence]; encoded != "" {
		record, err := parseCreateFence(encoded, binding)
		if err != nil {
			return nil, createFence{}, false, err
		}
		if record.Cleanup != cleanup || !controllerutil.ContainsFinalizer(current, CreateFenceFinalizer) {
			return nil, createFence{}, false, fmt.Errorf("NodeClaim %q durable VM create protection changed", claim.Name)
		}
		return current, fenceFromRecord(record), !fenceFromRecord(record).Issued, nil
	}
	if !controllerutil.ContainsFinalizer(current, karpv1.TerminationFinalizer) {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q lacks Karpenter termination finalizer before VM create", claim.Name)
	}
	if err := validateCreateInventory(baseline); err != nil {
		return nil, createFence{}, false, fmt.Errorf("pre-POST cloud inventory: %w", err)
	}
	record, err := newCreateFenceRecord(binding, cleanup, baseline, s.now(), s.nonce)
	if err != nil {
		return nil, createFence{}, false, err
	}
	return s.persist(ctx, current, binding, record)
}

func (s *kubernetesCreateFenceStore) Authorize(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, intent cloudapi.CreateAuthorizationKind) (*karpv1.NodeClaim, error) {
	current, err := s.getExact(ctx, claim)
	if err != nil {
		return nil, err
	}
	if !controllerutil.ContainsFinalizer(current, karpv1.TerminationFinalizer) || !controllerutil.ContainsFinalizer(current, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim %q lost required create-protection finalizers before VM POST", claim.Name)
	}
	record, err := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
	if err != nil {
		return nil, err
	}
	if token == "" || record.Token != token {
		return nil, fmt.Errorf("NodeClaim %q durable VM create token changed before VM POST", claim.Name)
	}
	if intent != cloudapi.CreateAuthorizationPost && intent != cloudapi.CreateAuthorizationAdoption {
		return nil, fmt.Errorf("NodeClaim %q VM create authorization has invalid intent %q", claim.Name, intent)
	}
	if record.Phase != createFenceReserved || record.IssuedAt != nil || record.RollbackAt != nil || len(record.CleanupResolutions) != 0 {
		return nil, fmt.Errorf("%w: NodeClaim %q immutable VM create attempt was already issued", cloudapi.ErrCreateAttemptPending, claim.Name)
	}
	now := s.now().UTC()
	issueID, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("generating VM create authorization identity: %w", err)
	}
	assignmentIssueID, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("generating base-firewall assignment authorization identity: %w", err)
	}
	if assignment := record.BaseFirewallAssignment; assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIntent ||
		assignment.VMUUID != "" || assignment.FirewallUUID != record.Cleanup.FirewallUUID || assignment.IntentAt.IsZero() {
		return nil, fmt.Errorf("NodeClaim %q lacks its durable pre-VM base-firewall assignment intent", claim.Name)
	}
	record.Phase = createFenceIssued
	record.Intent = intent
	record.IssueID = issueID
	record.IssuedAt = &now
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentIssued
	record.BaseFirewallAssignment.IssueID = assignmentIssueID
	record.BaseFirewallAssignment.IssuedAt = &now
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encoding issued VM create fence: %w", err)
	}
	copy := current.DeepCopy()
	copy.Annotations[AnnotationCreateFence] = string(encoded)
	if err := s.writer.Update(ctx, copy); err != nil {
		// Update can apply remotely and still return a transport error. Only this
		// invocation's unique issue ID proves that no other reconciler owns the
		// issued POST authority; never mark a concurrent winner rejected.
		readCtx, cancel := detachedCreateFenceContext(ctx)
		defer cancel()
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(readCtx, types.NamespacedName{Name: claim.Name}, &readback); readErr == nil && readback.UID == current.UID {
			if stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding); parseErr == nil &&
				stored.Token == token && stored.Phase == createFenceIssued && stored.Intent == intent && stored.IssueID == issueID && stored.IssuedAt != nil && stored.IssuedAt.Equal(now) &&
				stored.BaseFirewallAssignment != nil && stored.BaseFirewallAssignment.Phase == cloudapi.FirewallAssignmentIssued && stored.BaseFirewallAssignment.IssueID == assignmentIssueID {
				return &readback, fmt.Errorf("%w: this invocation's issue CAS committed but its response failed before SDK dispatch: %w", cloudapi.ErrCreateAttemptRejected, err)
			}
		}
		return nil, fmt.Errorf("%w: NodeClaim %q VM create issue CAS outcome belongs to another invocation or remains uncertain: %v", cloudapi.ErrCreateAttemptPending, claim.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); err != nil {
		return copy, fmt.Errorf("%w: reading back NodeClaim %q issued VM create attempt before SDK dispatch: %w", cloudapi.ErrCreateAttemptRejected, claim.Name, err)
	}
	if readback.UID != current.UID || readback.DeletionTimestamp != nil ||
		!controllerutil.ContainsFinalizer(&readback, karpv1.TerminationFinalizer) || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return copy, fmt.Errorf("%w: NodeClaim %q changed identity, finalizers, or deletion state after issue CAS and before SDK dispatch", cloudapi.ErrCreateAttemptRejected, claim.Name)
	}
	issued, err := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
	if err != nil {
		return copy, fmt.Errorf("%w: issued NodeClaim %q readback is invalid before SDK dispatch: %w", cloudapi.ErrCreateAttemptRejected, claim.Name, err)
	}
	if issued.Token != token || issued.Phase != createFenceIssued || issued.Intent != intent || issued.IssueID != issueID || issued.IssuedAt == nil || !issued.IssuedAt.Equal(now) ||
		issued.BaseFirewallAssignment == nil || issued.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentIssued || issued.BaseFirewallAssignment.IssueID != assignmentIssueID {
		return nil, fmt.Errorf("%w: NodeClaim %q immutable VM create issue is owned by another invocation or changed before SDK dispatch", cloudapi.ErrCreateAttemptPending, claim.Name)
	}
	return &readback, nil
}

func (s *kubernetesCreateFenceStore) RecordCreatedVM(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, issueID, vmUUID string,
) (*karpv1.NodeClaim, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) || !createFenceKeyHashPattern.MatchString(issueID) {
		return nil, fmt.Errorf("recording a created VM requires canonical VM and issue identities")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "anchor created VM identity")
		if readErr != nil {
			return nil, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		if token == "" || record.Token != token || record.IssueID != issueID || record.IssuedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q created VM does not match its exact issued attempt", claim.Name)
		}
		if record.CreatedVMUUID != "" {
			if record.CreatedVMUUID == vmUUID && record.LaunchObservedAt != nil && !record.LaunchObservedAt.IsZero() {
				if baseFirewallAssignmentMatches(record.BaseFirewallAssignment, vmUUID, record.Cleanup.FirewallUUID) {
					return current, nil
				}
				return nil, fmt.Errorf("NodeClaim %q created VM lacks its pre-issued base-firewall assignment receipt", claim.Name)
			} else {
				return nil, fmt.Errorf("NodeClaim %q created VM identity changed from %s to %s", claim.Name, record.CreatedVMUUID, vmUUID)
			}
		} else {
			if record.Phase != createFenceIssued || record.RollbackAt != nil {
				return nil, fmt.Errorf("NodeClaim %q cannot anchor a created VM from phase %q or after rollback", claim.Name, record.Phase)
			}
			if assignment := record.BaseFirewallAssignment; assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.VMUUID != "" ||
				assignment.FirewallUUID != record.Cleanup.FirewallUUID || !createFenceKeyHashPattern.MatchString(assignment.IssueID) {
				return nil, fmt.Errorf("NodeClaim %q cannot anchor a VM without its pre-issued base-firewall assignment", claim.Name)
			}
			now := s.now().UTC()
			record.CreatedVMUUID = vmUUID
			record.LaunchObservedAt = &now
			if record.BaseFirewallAssignment.VMUUID == "" {
				record.BaseFirewallAssignment.VMUUID = vmUUID
			}
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding NodeClaim %q created VM anchor: %w", claim.Name, err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		lastErr = s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(lastErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection while anchoring created VM", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(lastErr, parseErr)
			continue
		}
		if stored.Token == token && stored.IssueID == issueID && stored.CreatedVMUUID == vmUUID && stored.LaunchObservedAt != nil && !stored.LaunchObservedAt.IsZero() &&
			baseFirewallAssignmentMatches(stored.BaseFirewallAssignment, vmUUID, stored.Cleanup.FirewallUUID) {
			return &readback, nil
		}
		if stored.CreatedVMUUID != "" || stored.Phase != createFenceIssued || stored.RollbackAt != nil {
			return nil, fmt.Errorf("NodeClaim %q changed terminal state before the created VM anchor committed", claim.Name)
		}
	}
	return nil, fmt.Errorf("persisting exact created VM anchor for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) AuthorizeBaseFirewall(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID string,
) (*karpv1.NodeClaim, cloudapi.FirewallAssignmentAuthorization, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("base-firewall authorization requires a canonical VM UUID")
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "authorize base-firewall assignment")
		if readErr != nil {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, parseErr
		}
		if token == "" || record.Token != token || record.Phase != createFenceIssued || record.IssuedAt == nil ||
			record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("NodeClaim %q base-firewall assignment lacks the exact anchored VM attempt", claim.Name)
		}
		assignment := record.BaseFirewallAssignment
		if assignment == nil {
			now := s.now().UTC()
			record.BaseFirewallAssignment = newBaseFirewallAssignmentIntent(record, vmUUID, now)
			written, writeErr := s.persistBaseFirewallAssignment(ctx, current, binding, record, func(stored createFenceRecord) bool {
				return stored.BaseFirewallAssignment != nil && stored.BaseFirewallAssignment.Phase == cloudapi.FirewallAssignmentIntent &&
					baseFirewallAssignmentMatches(stored.BaseFirewallAssignment, vmUUID, stored.Cleanup.FirewallUUID)
			})
			if writeErr != nil {
				lastErr = writeErr
				continue
			}
			claim = written
			continue
		}
		if !baseFirewallAssignmentMatches(assignment, vmUUID, record.Cleanup.FirewallUUID) {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("NodeClaim %q base-firewall assignment identity changed", claim.Name)
		}
		switch assignment.Phase {
		case cloudapi.FirewallAssignmentIssued:
			authorization, slotErr := s.authorizeBaseFirewallAssignmentSlot(ctx, current, record, vmUUID)
			return current, authorization, slotErr
		case cloudapi.FirewallAssignmentObserved:
			return current, cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, nil
		case cloudapi.FirewallAssignmentIntent, cloudapi.FirewallAssignmentRejected:
		default:
			return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("NodeClaim %q has invalid base-firewall assignment phase %q", claim.Name, assignment.Phase)
		}
		if assignment.Phase == cloudapi.FirewallAssignmentRejected {
			// Retire this exact terminal issue in the shared Lease before replacing
			// the per-NodeClaim receipt. Otherwise a crash between replacement and
			// slot takeover would erase the only durable proof that the old owner
			// was safe to supersede.
			if slotErr := s.finishFirewallMutationSlot(ctx, current, record, firewallMutationAssign, vmUUID, assignment.IssueID, cloudapi.FirewallAssignmentRejected); slotErr != nil {
				return current, cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, slotErr
			}
		}
		issueID, nonceErr := s.nonce()
		if nonceErr != nil {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("generating base-firewall assignment issue identity: %w", nonceErr)
		}
		now := s.now().UTC()
		assignment.Phase = cloudapi.FirewallAssignmentIssued
		assignment.IssueID = issueID
		assignment.IssuedAt = &now
		assignment.RejectedAt = nil
		assignment.ObservedAt = nil
		written, writeErr := s.persistBaseFirewallAssignment(ctx, current, binding, record, func(stored createFenceRecord) bool {
			value := stored.BaseFirewallAssignment
			return baseFirewallAssignmentMatches(value, vmUUID, stored.Cleanup.FirewallUUID) && value.Phase == cloudapi.FirewallAssignmentIssued &&
				value.IssueID == issueID && value.IssuedAt != nil && value.IssuedAt.Equal(now)
		})
		if writeErr == nil {
			authorization, slotErr := s.authorizeBaseFirewallAssignmentSlot(ctx, written, record, vmUUID)
			return written, authorization, slotErr
		}
		lastErr = writeErr
		// A competing issued receipt must never receive a second POST authority.
		var latest karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &latest); readErr == nil && latest.UID == current.UID {
			if stored, decodeErr := parseCreateFence(latest.Annotations[AnnotationCreateFence], binding); decodeErr == nil && stored.BaseFirewallAssignment != nil &&
				stored.BaseFirewallAssignment.Phase == cloudapi.FirewallAssignmentIssued && stored.BaseFirewallAssignment.IssueID != issueID {
				return &latest, cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(stored)}, nil
			}
		}
	}
	return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("persisting issued base-firewall assignment for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) ObserveBaseFirewall(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID, issueID string,
) (*karpv1.NodeClaim, error) {
	return s.finishBaseFirewallAssignment(ctx, claim, binding, token, vmUUID, issueID, cloudapi.FirewallAssignmentObserved)
}

func (s *kubernetesCreateFenceStore) RejectBaseFirewall(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID, issueID string,
) (*karpv1.NodeClaim, error) {
	return s.finishBaseFirewallAssignment(ctx, claim, binding, token, vmUUID, issueID, cloudapi.FirewallAssignmentRejected)
}

func (s *kubernetesCreateFenceStore) finishBaseFirewallAssignment(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID, issueID string,
	terminal cloudapi.FirewallAssignmentPhase,
) (*karpv1.NodeClaim, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) || !createFenceKeyHashPattern.MatchString(issueID) ||
		(terminal != cloudapi.FirewallAssignmentObserved && terminal != cloudapi.FirewallAssignmentRejected) {
		return nil, fmt.Errorf("finishing base-firewall assignment requires canonical identity and terminal phase")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "finish base-firewall assignment")
		if readErr != nil {
			return nil, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		assignment := record.BaseFirewallAssignment
		if token == "" || record.Token != token || !baseFirewallAssignmentMatches(assignment, vmUUID, record.Cleanup.FirewallUUID) {
			return nil, fmt.Errorf("NodeClaim %q base-firewall assignment identity changed", claim.Name)
		}
		if assignment.Phase == terminal && assignment.IssueID == issueID {
			if slotErr := s.finishFirewallMutationSlot(ctx, current, record, firewallMutationAssign, vmUUID, issueID, terminal); slotErr != nil {
				return current, slotErr
			}
			return current, nil
		}
		if assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.IssueID != issueID || assignment.IssuedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q base-firewall assignment does not match issued receipt %s", claim.Name, issueID)
		}
		now := s.now().UTC()
		assignment.Phase = terminal
		if terminal == cloudapi.FirewallAssignmentObserved {
			assignment.ObservedAt = &now
			assignment.RejectedAt = nil
		} else {
			assignment.RejectedAt = &now
			assignment.ObservedAt = nil
		}
		written, writeErr := s.persistBaseFirewallAssignment(ctx, current, binding, record, func(stored createFenceRecord) bool {
			value := stored.BaseFirewallAssignment
			return baseFirewallAssignmentMatches(value, vmUUID, stored.Cleanup.FirewallUUID) && value.Phase == terminal && value.IssueID == issueID
		})
		if writeErr == nil {
			stored, parseErr := parseCreateFence(written.Annotations[AnnotationCreateFence], binding)
			if parseErr != nil {
				return written, parseErr
			}
			if slotErr := s.finishFirewallMutationSlot(ctx, written, stored, firewallMutationAssign, vmUUID, issueID, terminal); slotErr != nil {
				return written, slotErr
			}
			return written, nil
		}
		lastErr = writeErr
	}
	return nil, fmt.Errorf("persisting terminal base-firewall assignment for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) persistBaseFirewallAssignment(
	ctx context.Context,
	current *karpv1.NodeClaim,
	binding createFenceBinding,
	record createFenceRecord,
	accept func(createFenceRecord) bool,
) (*karpv1.NodeClaim, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encoding NodeClaim %q base-firewall assignment fence: %w", current.Name, err)
	}
	copy := current.DeepCopy()
	copy.Annotations[AnnotationCreateFence] = string(encoded)
	updateErr := s.writer.Update(ctx, copy)
	readCtx, cancel := detachedCreateFenceContext(ctx)
	defer cancel()
	var readback karpv1.NodeClaim
	if readErr := s.reader.Get(readCtx, types.NamespacedName{Name: current.Name}, &readback); readErr != nil {
		return nil, fmt.Errorf("writing and reading back NodeClaim %q base-firewall assignment fence: %w", current.Name, errors.Join(updateErr, readErr))
	}
	if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection during base-firewall assignment fencing", current.Name)
	}
	stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
	if parseErr != nil {
		return nil, errors.Join(updateErr, parseErr)
	}
	if accept(stored) {
		return &readback, nil
	}
	if updateErr != nil {
		return nil, updateErr
	}
	return nil, fmt.Errorf("NodeClaim %q base-firewall assignment fence changed during readback", current.Name)
}

func (s *kubernetesCreateFenceStore) AuthorizeFloatingIPUpdate(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID, address, name string,
	billingAccountID int64,
) (*karpv1.NodeClaim, cloudapi.FloatingIPUpdateAuthorization, error) {
	desired, err := newFloatingIPUpdateFence(vmUUID, address, name, billingAccountID)
	if err != nil {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "authorize floating-IP metadata update")
		if readErr != nil {
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, readErr
		}
		createRecord, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, parseErr
		}
		if token == "" || createRecord.Token != token || createRecord.CreatedVMUUID != desired.VMUUID || createRecord.LaunchObservedAt == nil {
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("NodeClaim %q floating-IP update lacks the exact anchored VM attempt", claim.Name)
		}

		encoded := current.Annotations[AnnotationFloatingIPUpdateFence]
		if encoded != "" {
			record, decodeErr := decodeFloatingIPUpdateRecord(encoded, binding, token)
			if decodeErr != nil {
				return nil, cloudapi.FloatingIPUpdateAuthorization{}, decodeErr
			}
			if !floatingIPUpdateIdentityMatches(record, desired) {
				return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("NodeClaim %q floating-IP update identity changed", claim.Name)
			}
			switch record.Phase {
			case cloudapi.FloatingIPUpdateIssued, cloudapi.FloatingIPUpdateObserved:
				return current, cloudapi.FloatingIPUpdateAuthorization{Fence: floatingIPUpdateFenceFromRecord(record)}, nil
			case cloudapi.FloatingIPUpdateRejected:
			default:
				return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("NodeClaim %q has invalid floating-IP update phase %q", claim.Name, record.Phase)
			}
		}

		issueID, nonceErr := s.nonce()
		if nonceErr != nil {
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("generating floating-IP update issue identity: %w", nonceErr)
		}
		now := s.now().UTC()
		record := floatingIPUpdateRecord{
			Schema: floatingIPUpdateFenceSchema, Binding: binding, AttemptToken: token,
			VMUUID: desired.VMUUID, Address: desired.Address, Name: desired.Name, BillingAccountID: desired.BillingAccountID,
			Phase: cloudapi.FloatingIPUpdateIssued, IssueID: issueID, IssuedAt: now,
		}
		written, writeErr := s.persistFloatingIPUpdate(ctx, current, record, func(stored floatingIPUpdateRecord) bool {
			return stored.Phase == cloudapi.FloatingIPUpdateIssued && stored.IssueID == issueID && stored.IssuedAt.Equal(now)
		})
		if writeErr == nil {
			// A live v2 attempt may have dispatched this PATCH before the new
			// receipt existed. Synthesize an issued read-only receipt and wait for
			// desired-state visibility rather than risk replaying it.
			allowPOST := !createRecord.LegacyV2FloatingIPMayBeIssued
			return written, cloudapi.FloatingIPUpdateAuthorization{Fence: floatingIPUpdateFenceFromRecord(record), AllowPOST: allowPOST}, nil
		}
		lastErr = writeErr
		claim = current
	}
	return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("persisting issued floating-IP update for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) ObserveFloatingIPUpdate(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	fence cloudapi.FloatingIPUpdateFence,
) (*karpv1.NodeClaim, error) {
	return s.finishFloatingIPUpdate(ctx, claim, binding, token, fence, cloudapi.FloatingIPUpdateObserved)
}

func (s *kubernetesCreateFenceStore) RejectFloatingIPUpdate(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	fence cloudapi.FloatingIPUpdateFence,
) (*karpv1.NodeClaim, error) {
	return s.finishFloatingIPUpdate(ctx, claim, binding, token, fence, cloudapi.FloatingIPUpdateRejected)
}

func (s *kubernetesCreateFenceStore) finishFloatingIPUpdate(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	fence cloudapi.FloatingIPUpdateFence,
	terminal cloudapi.FloatingIPUpdatePhase,
) (*karpv1.NodeClaim, error) {
	if err := validateFloatingIPUpdateFence(fence); err != nil {
		return nil, fmt.Errorf("finishing floating-IP update requires exact identity: %w", err)
	}
	if terminal != cloudapi.FloatingIPUpdateObserved && terminal != cloudapi.FloatingIPUpdateRejected {
		return nil, fmt.Errorf("finishing floating-IP update requires a terminal phase, got %q", terminal)
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "finish floating-IP metadata update")
		if readErr != nil {
			return nil, readErr
		}
		record, decodeErr := decodeFloatingIPUpdateRecord(current.Annotations[AnnotationFloatingIPUpdateFence], binding, token)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if !floatingIPUpdateIdentityMatches(record, fence) || record.IssueID != fence.IssueID {
			return nil, fmt.Errorf("NodeClaim %q floating-IP update identity changed", claim.Name)
		}
		if record.Phase == terminal {
			return current, nil
		}
		if record.Phase != cloudapi.FloatingIPUpdateIssued {
			return nil, fmt.Errorf("NodeClaim %q floating-IP update does not match its issued receipt", claim.Name)
		}
		now := s.now().UTC()
		record.Phase = terminal
		if terminal == cloudapi.FloatingIPUpdateObserved {
			record.ObservedAt = &now
			record.RejectedAt = nil
		} else {
			record.RejectedAt = &now
			record.ObservedAt = nil
		}
		written, writeErr := s.persistFloatingIPUpdate(ctx, current, record, func(stored floatingIPUpdateRecord) bool {
			return stored.Phase == terminal && stored.IssueID == fence.IssueID && floatingIPUpdateIdentityMatches(stored, fence)
		})
		if writeErr == nil {
			return written, nil
		}
		lastErr = writeErr
		claim = current
	}
	return nil, fmt.Errorf("persisting terminal floating-IP update for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) persistFloatingIPUpdate(
	ctx context.Context,
	current *karpv1.NodeClaim,
	record floatingIPUpdateRecord,
	accept func(floatingIPUpdateRecord) bool,
) (*karpv1.NodeClaim, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encoding NodeClaim %q floating-IP update fence: %w", current.Name, err)
	}
	copy := current.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[AnnotationFloatingIPUpdateFence] = string(encoded)
	updateErr := s.writer.Update(ctx, copy)
	readCtx, cancel := detachedCreateFenceContext(ctx)
	defer cancel()
	var readback karpv1.NodeClaim
	if readErr := s.reader.Get(readCtx, types.NamespacedName{Name: current.Name}, &readback); readErr != nil {
		return nil, fmt.Errorf("writing and reading back NodeClaim %q floating-IP update fence: %w", current.Name, errors.Join(updateErr, readErr))
	}
	if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection during floating-IP update fencing", current.Name)
	}
	stored, decodeErr := decodeFloatingIPUpdateRecord(readback.Annotations[AnnotationFloatingIPUpdateFence], record.Binding, record.AttemptToken)
	if decodeErr != nil {
		return nil, errors.Join(updateErr, decodeErr)
	}
	if accept(stored) {
		return &readback, nil
	}
	if updateErr != nil {
		return nil, updateErr
	}
	return nil, fmt.Errorf("NodeClaim %q floating-IP update fence changed during readback", current.Name)
}

func newFloatingIPUpdateFence(vmUUID, address, name string, billingAccountID int64) (cloudapi.FloatingIPUpdateFence, error) {
	fence := cloudapi.FloatingIPUpdateFence{
		VMUUID: strings.ToLower(vmUUID), Address: address, Name: name, BillingAccountID: billingAccountID,
	}
	if !createFenceVMUUIDPattern.MatchString(fence.VMUUID) || fence.Name == "" || len(fence.Name) > 128 || fence.BillingAccountID <= 0 {
		return cloudapi.FloatingIPUpdateFence{}, fmt.Errorf("floating-IP update requires canonical VM, name, and billing identity")
	}
	parsed, err := netip.ParseAddr(fence.Address)
	if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.String() != fence.Address {
		return cloudapi.FloatingIPUpdateFence{}, fmt.Errorf("floating-IP update requires canonical public IPv4 address")
	}
	return fence, nil
}

func validateFloatingIPUpdateFence(fence cloudapi.FloatingIPUpdateFence) error {
	desired, err := newFloatingIPUpdateFence(fence.VMUUID, fence.Address, fence.Name, fence.BillingAccountID)
	if err != nil {
		return err
	}
	if !createFenceKeyHashPattern.MatchString(fence.IssueID) ||
		(fence.Phase != cloudapi.FloatingIPUpdateIssued && fence.Phase != cloudapi.FloatingIPUpdateRejected && fence.Phase != cloudapi.FloatingIPUpdateObserved) ||
		desired.VMUUID != fence.VMUUID {
		return fmt.Errorf("floating-IP update receipt has invalid phase or issue identity")
	}
	return nil
}

func decodeFloatingIPUpdateRecord(value string, binding createFenceBinding, token string) (floatingIPUpdateRecord, error) {
	var record floatingIPUpdateRecord
	if value == "" || json.Unmarshal([]byte(value), &record) != nil {
		return floatingIPUpdateRecord{}, fmt.Errorf("durable floating-IP update fence is missing or malformed")
	}
	fence := floatingIPUpdateFenceFromRecord(record)
	validTerminal := (record.Phase == cloudapi.FloatingIPUpdateIssued && record.RejectedAt == nil && record.ObservedAt == nil) ||
		(record.Phase == cloudapi.FloatingIPUpdateRejected && record.RejectedAt != nil && !record.RejectedAt.IsZero() && record.ObservedAt == nil) ||
		(record.Phase == cloudapi.FloatingIPUpdateObserved && record.ObservedAt != nil && !record.ObservedAt.IsZero() && record.RejectedAt == nil)
	if record.Schema != floatingIPUpdateFenceSchema || record.Binding != binding || token == "" || record.AttemptToken != token ||
		record.IssuedAt.IsZero() || !validTerminal || validateFloatingIPUpdateFence(fence) != nil {
		return floatingIPUpdateRecord{}, fmt.Errorf("durable floating-IP update fence has incomplete or changed identity")
	}
	return record, nil
}

func floatingIPUpdateFenceFromRecord(record floatingIPUpdateRecord) cloudapi.FloatingIPUpdateFence {
	return cloudapi.FloatingIPUpdateFence{
		VMUUID: record.VMUUID, Address: record.Address, Name: record.Name, BillingAccountID: record.BillingAccountID,
		Phase: record.Phase, IssueID: record.IssueID,
	}
}

func floatingIPUpdateIdentityMatches(record floatingIPUpdateRecord, fence cloudapi.FloatingIPUpdateFence) bool {
	return record.VMUUID == strings.ToLower(fence.VMUUID) && record.Address == fence.Address && record.Name == fence.Name && record.BillingAccountID == fence.BillingAccountID
}

func (s *kubernetesCreateFenceStore) RecordProtectionFailure(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, issueID, vmUUID string,
) (*karpv1.NodeClaim, time.Time, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) || !createFenceKeyHashPattern.MatchString(issueID) {
		return nil, time.Time{}, fmt.Errorf("recording protection failure requires canonical VM and issue identities")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "record protection failure")
		if readErr != nil {
			return nil, time.Time{}, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, time.Time{}, parseErr
		}
		if token == "" || record.Token != token || record.IssueID != issueID || record.Phase != createFenceIssued ||
			record.IssuedAt == nil || record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil || record.RollbackAt != nil {
			return nil, time.Time{}, fmt.Errorf("NodeClaim %q protection failure does not match its exact live anchored create attempt", claim.Name)
		}
		if record.ProtectionFailureAt != nil {
			return current, record.ProtectionFailureAt.UTC(), nil
		}
		now := s.now().UTC()
		record.ProtectionFailureAt = &now
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("encoding NodeClaim %q protection failure: %w", claim.Name, err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		writeErr := s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(writeErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, time.Time{}, fmt.Errorf("NodeClaim %q changed identity or lost protection while recording protection failure", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(writeErr, parseErr)
			continue
		}
		if stored.Token == token && stored.IssueID == issueID && stored.Phase == createFenceIssued &&
			stored.CreatedVMUUID == vmUUID && stored.RollbackAt == nil && stored.ProtectionFailureAt != nil {
			return &readback, stored.ProtectionFailureAt.UTC(), nil
		}
		if stored.RollbackAt != nil || stored.Phase != createFenceIssued || stored.CreatedVMUUID != vmUUID {
			return nil, time.Time{}, fmt.Errorf("NodeClaim %q changed terminal state before protection failure committed", claim.Name)
		}
		lastErr = errors.Join(writeErr, fmt.Errorf("protection failure readback did not contain the durable marker"))
	}
	return nil, time.Time{}, fmt.Errorf("persisting protection failure for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) ClearProtectionFailure(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, issueID, vmUUID string,
) (*karpv1.NodeClaim, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) || !createFenceKeyHashPattern.MatchString(issueID) {
		return nil, fmt.Errorf("clearing protection failure requires canonical VM and issue identities")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "clear protection failure")
		if readErr != nil {
			return nil, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		if token == "" || record.Token != token || record.IssueID != issueID || record.Phase != createFenceIssued ||
			record.IssuedAt == nil || record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil || record.RollbackAt != nil {
			return nil, fmt.Errorf("NodeClaim %q protection recovery does not match its exact live anchored create attempt", claim.Name)
		}
		if record.ProtectionFailureAt == nil {
			return current, nil
		}
		record.ProtectionFailureAt = nil
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding NodeClaim %q protection recovery: %w", claim.Name, err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		writeErr := s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(writeErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection while clearing protection failure", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(writeErr, parseErr)
			continue
		}
		if stored.Token == token && stored.IssueID == issueID && stored.Phase == createFenceIssued &&
			stored.CreatedVMUUID == vmUUID && stored.RollbackAt == nil && stored.ProtectionFailureAt == nil {
			return &readback, nil
		}
		if stored.RollbackAt != nil || stored.Phase != createFenceIssued || stored.CreatedVMUUID != vmUUID {
			return nil, fmt.Errorf("NodeClaim %q changed terminal state before protection recovery committed", claim.Name)
		}
		lastErr = errors.Join(writeErr, fmt.Errorf("protection failure marker remained after recovery CAS"))
	}
	return nil, fmt.Errorf("clearing protection failure for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) ChooseRollback(
	ctx context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, issueID, vmUUID string,
	resolution *cloudapi.FencedCreateCleanupResolution,
) (*karpv1.NodeClaim, error) {
	vmUUID = strings.ToLower(vmUUID)
	if !createFenceVMUUIDPattern.MatchString(vmUUID) || !createFenceKeyHashPattern.MatchString(issueID) {
		return nil, fmt.Errorf("choosing rollback requires canonical VM and issue identities")
	}
	var canonical *cloudapi.FencedCreateCleanupResolution
	if resolution != nil {
		value, err := normalizeCleanupResolution(*resolution)
		if err != nil {
			return nil, err
		}
		if value.VMUUID != vmUUID {
			return nil, fmt.Errorf("rollback receipt VM %s does not match anchored VM %s", value.VMUUID, vmUUID)
		}
		canonical = &value
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "choose created VM rollback")
		if readErr != nil {
			return nil, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		if token == "" || record.Token != token || record.IssueID != issueID || record.IssuedAt == nil ||
			record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q rollback does not match its exact anchored create attempt", claim.Name)
		}
		if record.Phase == createFenceMaterialized {
			return nil, fmt.Errorf("NodeClaim %q VM %s was already materialized and cannot be rolled back", claim.Name, vmUUID)
		}
		if record.Phase != createFenceIssued {
			return nil, fmt.Errorf("NodeClaim %q cannot choose rollback from phase %q", claim.Name, record.Phase)
		}
		if record.RollbackAt != nil && (canonical == nil || cleanupResolutionStored(record, *canonical)) {
			return current, nil
		}
		if record.RollbackAt == nil {
			now := s.now().UTC()
			record.RollbackAt = &now
		}
		record.ProtectionFailureAt = nil
		if canonical != nil {
			if err := applyCleanupResolution(&record, *canonical); err != nil {
				return nil, err
			}
			record.DependentUnresolved = false
			record.DependentsResolvedAt = nil
		} else {
			record.DependentUnresolved = true
			record.DependentsResolvedAt = nil
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding NodeClaim %q rollback choice: %w", claim.Name, err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		lastErr = s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(lastErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection while choosing rollback", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(lastErr, parseErr)
			continue
		}
		if stored.Token == token && stored.IssueID == issueID && stored.CreatedVMUUID == vmUUID && stored.RollbackAt != nil &&
			(canonical == nil || cleanupResolutionStored(stored, *canonical)) {
			return &readback, nil
		}
		if stored.Phase == createFenceMaterialized || stored.CreatedVMUUID != vmUUID {
			return nil, fmt.Errorf("NodeClaim %q changed terminal state before rollback committed", claim.Name)
		}
	}
	return nil, fmt.Errorf("persisting rollback choice for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) MarkRejected(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, issueID string) (*karpv1.NodeClaim, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "reject VM create")
		if readErr != nil {
			return nil, readErr
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		if token == "" || issueID == "" || record.Token != token || record.IssueID != issueID || record.IssuedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q cannot reject a VM create attempt without its exact issued token", claim.Name)
		}
		if record.Phase == createFenceRejected {
			return current, nil
		}
		if record.CreatedVMUUID != "" || record.RollbackAt != nil || len(record.CleanupResolutions) != 0 {
			return nil, fmt.Errorf("NodeClaim %q accepted VM %s and cannot be marked as a rejected POST", claim.Name, record.CreatedVMUUID)
		}
		if record.Phase != createFenceIssued {
			return nil, fmt.Errorf("NodeClaim %q cannot reject VM create from phase %q", claim.Name, record.Phase)
		}
		assignment := record.BaseFirewallAssignment
		if assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.VMUUID != "" {
			return nil, fmt.Errorf("NodeClaim %q VM rejection lacks its unused base-firewall assignment issue", claim.Name)
		}
		now := s.now().UTC()
		record.Phase = createFenceRejected
		assignment.Phase = cloudapi.FirewallAssignmentRejected
		assignment.RejectedAt = &now
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding rejected VM create fence: %w", err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		lastErr = s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(lastErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection while rejecting create", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(lastErr, parseErr)
			continue
		}
		if stored.Token == token && stored.IssueID == issueID && stored.Phase == createFenceRejected && stored.IssuedAt != nil {
			return &readback, nil
		}
		if stored.Token != token || stored.IssueID != issueID || stored.Phase != createFenceIssued {
			return nil, fmt.Errorf("NodeClaim %q changed state before create rejection committed", claim.Name)
		}
	}
	return nil, fmt.Errorf("persisting rejected create state for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) MarkMaterialized(ctx context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, vm *cloudapi.VM) (*karpv1.NodeClaim, error) {
	vmUUID := ""
	if vm != nil {
		vmUUID = strings.ToLower(vm.UUID)
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		current, readErr := s.getProtectedExact(ctx, claim, "materialize VM identity")
		if readErr != nil {
			return nil, readErr
		}
		if current.DeletionTimestamp == nil && (!controllerutil.ContainsFinalizer(current, karpv1.TerminationFinalizer) ||
			current.Generation != claim.Generation || !reflect.DeepEqual(current.Spec, claim.Spec) || current.Labels[karpv1.NodePoolLabelKey] != claim.Labels[karpv1.NodePoolLabelKey]) {
			return nil, fmt.Errorf("NodeClaim %q changed spec, NodePool identity, or Karpenter finalizer before materializing VM identity", claim.Name)
		}
		record, parseErr := parseCreateFence(current.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			return nil, parseErr
		}
		if token == "" || record.Token != token {
			return nil, fmt.Errorf("NodeClaim %q durable VM create token changed before materialization", claim.Name)
		}
		if err := validateMaterializedVM(record, vm); err != nil {
			return nil, err
		}
		if !(record.LegacyV2 && record.Phase == createFenceMaterialized) {
			update, updateErr := decodeFloatingIPUpdateRecord(current.Annotations[AnnotationFloatingIPUpdateFence], binding, token)
			if updateErr != nil {
				return nil, fmt.Errorf("NodeClaim %q cannot materialize without its durable floating-IP update receipt: %w", claim.Name, updateErr)
			}
			if update.Phase != cloudapi.FloatingIPUpdateObserved || update.VMUUID != vmUUID || update.Address != vm.PublicIPv4 ||
				update.Name != vm.FloatingIPName || update.BillingAccountID != vm.BillingAccountID {
				return nil, fmt.Errorf("NodeClaim %q floating-IP update receipt does not match materialized VM %s", claim.Name, vmUUID)
			}
		}
		if record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q cannot materialize VM %s before the exact launch UUID is durable", claim.Name, vmUUID)
		}
		if record.Phase == createFenceMaterialized {
			return current, nil
		}
		if record.Phase != createFenceIssued || record.IssuedAt == nil {
			return nil, fmt.Errorf("NodeClaim %q VM create attempt must be durably issued before materialization", claim.Name)
		}
		if record.RollbackAt != nil || record.CleanupVMUUID != "" || len(record.CleanupResolutions) != 0 {
			return nil, fmt.Errorf("NodeClaim %q VM create rollback is already durably chosen and cannot be materialized", claim.Name)
		}
		now := s.now().UTC()
		record.Phase = createFenceMaterialized
		record.ProtectionFailureAt = nil
		record.ObservedAt = &now
		record.ObservedVMUUID = vmUUID
		record.FloatingIPName = vm.FloatingIPName
		publicIP, _ := netip.ParseAddr(vm.PublicIPv4)
		record.PublicIPv4 = publicIP.String()
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encoding materialized VM create fence: %w", err)
		}
		copy := current.DeepCopy()
		copy.Annotations[AnnotationCreateFence] = string(encoded)
		lastErr = s.writer.Update(ctx, copy)
		var readback karpv1.NodeClaim
		if readErr := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &readback); readErr != nil {
			lastErr = errors.Join(lastErr, readErr)
			continue
		}
		if readback.UID != current.UID || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
			return nil, fmt.Errorf("NodeClaim %q changed identity or lost protection while materializing VM identity", claim.Name)
		}
		stored, parseErr := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
		if parseErr != nil {
			lastErr = errors.Join(lastErr, parseErr)
			continue
		}
		if stored.Phase == createFenceMaterialized && stored.CreatedVMUUID == vmUUID && stored.ObservedVMUUID == vmUUID &&
			stored.PublicIPv4 == publicIP.String() && stored.ObservedAt != nil && stored.RollbackAt == nil {
			return &readback, nil
		}
		if stored.RollbackAt != nil || stored.Phase != createFenceIssued || stored.CreatedVMUUID != vmUUID {
			return nil, fmt.Errorf("NodeClaim %q rollback or another terminal state won before materialization", claim.Name)
		}
	}
	return nil, fmt.Errorf("persisting materialized VM identity for NodeClaim %q did not converge: %w", claim.Name, lastErr)
}

func (s *kubernetesCreateFenceStore) getExact(ctx context.Context, claim *karpv1.NodeClaim) (*karpv1.NodeClaim, error) {
	if claim == nil || claim.Name == "" || claim.UID == "" {
		return nil, fmt.Errorf("durable VM create fencing requires a named NodeClaim with UID")
	}
	var current karpv1.NodeClaim
	if err := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &current); err != nil {
		return nil, fmt.Errorf("reading NodeClaim %q for durable VM create fence: %w", claim.Name, err)
	}
	if current.UID != claim.UID || current.DeletionTimestamp != nil {
		return nil, fmt.Errorf("NodeClaim %q changed identity or is deleting before VM create", claim.Name)
	}
	if current.Generation != claim.Generation || !reflect.DeepEqual(current.Spec, claim.Spec) || current.Labels[karpv1.NodePoolLabelKey] != claim.Labels[karpv1.NodePoolLabelKey] {
		return nil, fmt.Errorf("NodeClaim %q spec or NodePool identity changed before VM create", claim.Name)
	}
	return &current, nil
}

// getProtectedExact is used only after an attempt has been issued. A deleting
// NodeClaim still needs terminal identity/rollback receipts, so this read is
// deliberately deletion-tolerant while requiring the exact UID and provider
// finalizer that make the subsequent CAS safe.
func (s *kubernetesCreateFenceStore) getProtectedExact(ctx context.Context, claim *karpv1.NodeClaim, action string) (*karpv1.NodeClaim, error) {
	if claim == nil || claim.Name == "" || claim.UID == "" {
		return nil, fmt.Errorf("%s requires a named NodeClaim with UID", action)
	}
	var current karpv1.NodeClaim
	if err := s.reader.Get(ctx, types.NamespacedName{Name: claim.Name}, &current); err != nil {
		return nil, fmt.Errorf("exact-reading NodeClaim %q to %s: %w", claim.Name, action, err)
	}
	if current.UID != claim.UID || !controllerutil.ContainsFinalizer(&current, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim %q changed identity or lost create protection before attempting to %s", claim.Name, action)
	}
	return &current, nil
}

func (s *kubernetesCreateFenceStore) persist(
	ctx context.Context,
	current *karpv1.NodeClaim,
	binding createFenceBinding,
	record createFenceRecord,
) (*karpv1.NodeClaim, createFence, bool, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, createFence{}, false, fmt.Errorf("encoding durable VM create fence: %w", err)
	}
	copy := current.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[AnnotationCreateFence] = string(encoded)
	removalRecord := newRemovalMutationReadyRecord(binding, record.Token, record.StartedAt)
	removalEncoded, err := json.Marshal(removalRecord)
	if err != nil {
		return nil, createFence{}, false, fmt.Errorf("encoding initial durable removal mutation fence: %w", err)
	}
	copy.Annotations[AnnotationRemovalMutationFence] = string(removalEncoded)
	controllerutil.AddFinalizer(copy, CreateFenceFinalizer)
	if err := s.writer.Update(ctx, copy); err != nil {
		if apierrors.IsConflict(err) {
			return nil, createFence{}, false, fmt.Errorf("NodeClaim %q durable VM create fence CAS conflicted: %w", current.Name, err)
		}
		return nil, createFence{}, false, fmt.Errorf("persisting NodeClaim %q durable VM create fence: %w", current.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := s.reader.Get(ctx, types.NamespacedName{Name: current.Name}, &readback); err != nil {
		return nil, createFence{}, false, fmt.Errorf("reading back NodeClaim %q durable VM create fence: %w", current.Name, err)
	}
	if readback.UID != current.UID || readback.DeletionTimestamp != nil {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q changed identity or began deletion during durable VM create fence readback", current.Name)
	}
	if !controllerutil.ContainsFinalizer(&readback, karpv1.TerminationFinalizer) || !controllerutil.ContainsFinalizer(&readback, CreateFenceFinalizer) {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q durable VM create protection finalizers did not survive readback", current.Name)
	}
	stored, err := parseCreateFence(readback.Annotations[AnnotationCreateFence], binding)
	if err != nil {
		return nil, createFence{}, false, err
	}
	if stored.Token != record.Token {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q durable VM create fence token changed during readback", current.Name)
	}
	if _, err := decodeRemovalMutationRecord(readback.Annotations[AnnotationRemovalMutationFence], binding, record.Token); err != nil {
		return nil, createFence{}, false, fmt.Errorf("NodeClaim %q initial removal fence did not survive readback: %w", current.Name, err)
	}
	return &readback, fenceFromRecord(stored), true, nil
}

func decodeCreateFence(value string) (createFenceRecord, error) {
	var record createFenceRecord
	if value == "" || json.Unmarshal([]byte(value), &record) != nil {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence is missing or malformed")
	}
	if record.Schema == legacyCreateFenceSchema {
		record = migrateLegacyCreateFence(record)
	}
	validPhase := (record.Phase == createFenceReserved && record.IssueID == "" && record.IssuedAt == nil && record.ObservedAt == nil && record.ObservedVMUUID == "") ||
		(record.Phase == createFenceIssued && createFenceKeyHashPattern.MatchString(record.IssueID) && record.IssuedAt != nil && !record.IssuedAt.IsZero() && record.ObservedAt == nil && record.ObservedVMUUID == "") ||
		(record.Phase == createFenceRejected && createFenceKeyHashPattern.MatchString(record.IssueID) && record.IssuedAt != nil && !record.IssuedAt.IsZero() && record.ObservedAt == nil && record.ObservedVMUUID == "") ||
		(record.Phase == createFenceMaterialized && createFenceKeyHashPattern.MatchString(record.IssueID) && record.IssuedAt != nil && !record.IssuedAt.IsZero() && record.ObservedAt != nil && !record.ObservedAt.IsZero() && createFenceVMUUIDPattern.MatchString(record.ObservedVMUUID) && record.FloatingIPName != "" && record.PublicIPv4 != "")
	validIntent := (record.Phase == createFenceReserved && record.Intent == "") ||
		(record.Phase != createFenceReserved && (record.Intent == cloudapi.CreateAuthorizationPost || record.Intent == cloudapi.CreateAuthorizationAdoption))
	validCreatedIdentity := (record.LaunchObservedAt == nil && record.CreatedVMUUID == "") ||
		(record.LaunchObservedAt != nil && !record.LaunchObservedAt.IsZero() && createFenceVMUUIDPattern.MatchString(record.CreatedVMUUID) && record.CreatedVMUUID == strings.ToLower(record.CreatedVMUUID))
	validBaseFirewallAssignment := false
	if assignment := record.BaseFirewallAssignment; assignment != nil {
		validIdentity := assignment.FirewallUUID == record.Cleanup.FirewallUUID && !assignment.IntentAt.IsZero() &&
			((record.CreatedVMUUID == "" && assignment.VMUUID == "") || (record.CreatedVMUUID != "" && assignment.VMUUID == record.CreatedVMUUID))
		switch assignment.Phase {
		case cloudapi.FirewallAssignmentIntent:
			validBaseFirewallAssignment = validIdentity && assignment.IssueID == "" && assignment.IssuedAt == nil && assignment.RejectedAt == nil && assignment.ObservedAt == nil
		case cloudapi.FirewallAssignmentIssued:
			validBaseFirewallAssignment = validIdentity && createFenceKeyHashPattern.MatchString(assignment.IssueID) && assignment.IssuedAt != nil && !assignment.IssuedAt.IsZero() && assignment.RejectedAt == nil && assignment.ObservedAt == nil
		case cloudapi.FirewallAssignmentRejected:
			validBaseFirewallAssignment = validIdentity && createFenceKeyHashPattern.MatchString(assignment.IssueID) && assignment.IssuedAt != nil && !assignment.IssuedAt.IsZero() && assignment.RejectedAt != nil && !assignment.RejectedAt.IsZero() && assignment.ObservedAt == nil
		case cloudapi.FirewallAssignmentObserved:
			validBaseFirewallAssignment = validIdentity && assignment.VMUUID != "" && createFenceKeyHashPattern.MatchString(assignment.IssueID) && assignment.IssuedAt != nil && !assignment.IssuedAt.IsZero() && assignment.RejectedAt == nil && assignment.ObservedAt != nil && !assignment.ObservedAt.IsZero()
		default:
			validBaseFirewallAssignment = false
		}
	}
	validRollback := record.RollbackAt == nil || (!record.RollbackAt.IsZero() && record.Phase == createFenceIssued && record.CreatedVMUUID != "")
	validProtectionFailure := record.ProtectionFailureAt == nil ||
		(!record.ProtectionFailureAt.IsZero() && record.Phase == createFenceIssued && record.CreatedVMUUID != "" && record.RollbackAt == nil)
	validCleanupResolution := (record.CleanupResolvedAt == nil && record.CleanupVMUUID == "" && record.CleanupFloatingIPName == "" && record.CleanupPublicIPv4 == "") ||
		(record.CleanupResolvedAt != nil && !record.CleanupResolvedAt.IsZero() && createFenceVMUUIDPattern.MatchString(record.CleanupVMUUID) && record.CleanupFloatingIPName != "" && record.CleanupPublicIPv4 != "")
	if record.Schema != createFenceSchema || !validPhase || !validIntent || !validCreatedIdentity || !validBaseFirewallAssignment || !validRollback || !validProtectionFailure || !validCleanupResolution || record.Binding.NodeClaimUID == "" || record.Binding.IdempotencyKeyHash == "" ||
		record.Binding.RequestHash == "" || record.Binding.SpecHash == "" || record.Binding.BootstrapHash == "" ||
		record.Cleanup.ClusterName == "" || record.Cleanup.Location == "" || record.Cleanup.NetworkUUID == "" ||
		record.Cleanup.ControlPlaneVIP == "" || record.Cleanup.PrivateLoadBalancerPoolStart == "" || record.Cleanup.PrivateLoadBalancerPoolStop == "" ||
		record.Cleanup.FirewallUUID == "" || record.Cleanup.FirewallProfile != inspacev1.EffectiveFirewallProfile(record.Cleanup.FirewallProfile) || record.Cleanup.NodeClaimName == "" ||
		record.Cleanup.VMName == "" || record.Cleanup.BillingAccountID <= 0 || !createFenceKeyHashPattern.MatchString(record.Cleanup.OwnershipKeyHash) || record.Token == "" || record.StartedAt.IsZero() {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence has incomplete launch identity")
	}
	if (record.Cleanup.FirewallProfile == inspacev1.FirewallProfilePrivateWorker && record.Cleanup.NodePoolName != "") ||
		((record.Cleanup.FirewallProfile == inspacev1.FirewallProfilePublicNodeLoadBalancer || record.Cleanup.FirewallProfile == inspacev1.FirewallProfilePublicNodeLocal) && record.Cleanup.NodePoolName == "") {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence has invalid firewall-profile/NodePool binding")
	}
	if record.Cleanup.FirewallProfile == inspacev1.FirewallProfilePublicNodeLoadBalancer || record.Cleanup.FirewallProfile == inspacev1.FirewallProfilePublicNodeLocal {
		if err := validateNodePoolClaimIdentity(record.Cleanup.NodePoolName, record.Cleanup.NodeClaimName); err != nil {
			return createFenceRecord{}, fmt.Errorf("durable VM create fence has invalid NodePool/NodeClaim binding: %w", err)
		}
	}
	if err := validateCreateInventory(record.Baseline); err != nil {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence baseline: %w", err)
	}
	if record.Phase == createFenceMaterialized {
		if record.CreatedVMUUID == "" || record.CreatedVMUUID != record.ObservedVMUUID || record.RollbackAt != nil || record.BaseFirewallAssignment == nil || record.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentObserved {
			return createFenceRecord{}, fmt.Errorf("materialized VM create fence does not match its launch anchor")
		}
		canonical, err := normalizeCleanupResolution(cloudapi.FencedCreateCleanupResolution{
			VMUUID: record.ObservedVMUUID, FloatingIPName: record.FloatingIPName, PublicIPv4: record.PublicIPv4,
		})
		if err != nil || canonical.VMUUID != record.ObservedVMUUID || canonical.PublicIPv4 != record.PublicIPv4 {
			return createFenceRecord{}, fmt.Errorf("durable VM create fence has non-canonical materialized identity")
		}
	}
	if record.Phase == createFenceIssued && record.BaseFirewallAssignment != nil && record.BaseFirewallAssignment.Phase == cloudapi.FirewallAssignmentIntent {
		return createFenceRecord{}, fmt.Errorf("issued VM create fence retains an unissued base-firewall intent")
	}
	if len(record.CleanupResolutions) > cloudapi.MaxCreateCleanupResolutions {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence cleanup history exceeds %d exact receipts", cloudapi.MaxCreateCleanupResolutions)
	}
	if len(record.CleanupResolutions) != 0 && record.CleanupVMUUID == "" {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence cleanup history lacks an active exact receipt")
	}
	if record.Phase == createFenceReserved && (record.CreatedVMUUID != "" || record.RollbackAt != nil || record.BaseFirewallAssignment == nil || record.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentIntent) {
		return createFenceRecord{}, fmt.Errorf("reserved VM create fence cannot contain accepted-launch identities")
	}
	if record.Phase == createFenceRejected && (record.CreatedVMUUID != "" || record.RollbackAt != nil || record.BaseFirewallAssignment == nil || record.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentRejected) {
		return createFenceRecord{}, fmt.Errorf("rejected VM create fence cannot contain an accepted-launch identity")
	}
	for i, resolution := range record.CleanupResolutions {
		canonical, err := normalizeCleanupResolution(resolution)
		if err != nil || canonical != resolution || (i > 0 && record.CleanupResolutions[i-1].VMUUID >= resolution.VMUUID) {
			return createFenceRecord{}, fmt.Errorf("durable VM create fence cleanup history contains a malformed, non-canonical, unsorted, or duplicate receipt")
		}
	}
	if record.CleanupVMUUID != "" {
		found := false
		for _, resolution := range record.CleanupResolutions {
			if resolution.VMUUID == record.CleanupVMUUID && resolution.FloatingIPName == record.CleanupFloatingIPName && resolution.PublicIPv4 == record.CleanupPublicIPv4 {
				found = true
				break
			}
		}
		if !found {
			return createFenceRecord{}, fmt.Errorf("durable VM create fence active cleanup identity is absent from exact receipt history")
		}
	}
	createdReceipt := false
	for _, resolution := range record.CleanupResolutions {
		if resolution.VMUUID == record.CreatedVMUUID {
			createdReceipt = true
			break
		}
	}
	if record.RollbackAt == nil && (record.DependentUnresolved || record.DependentsResolvedAt != nil) {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence has dependent disposition without a rollback decision")
	}
	if record.DependentsResolvedAt != nil && record.DependentsResolvedAt.IsZero() {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence has an invalid dependent absence time")
	}
	if record.RollbackAt != nil {
		states := 0
		if createdReceipt {
			states++
		}
		if record.DependentUnresolved {
			states++
		}
		if record.DependentsResolvedAt != nil {
			states++
		}
		if states != 1 {
			return createFenceRecord{}, fmt.Errorf("durable VM create fence rollback dependent state does not have exactly one durable disposition")
		}
	}
	return record, nil
}

func migrateLegacyCreateFence(record createFenceRecord) createFenceRecord {
	record.Schema = createFenceSchema
	record.LegacyV2 = true
	record.LegacyV2BaseFirewallMayBeIssued = record.Phase == createFenceIssued
	record.LegacyV2FloatingIPMayBeIssued = record.Phase == createFenceIssued && record.CreatedVMUUID != ""
	intentAt := record.StartedAt.UTC()
	issueID := legacyBaseFirewallIssueID(record)
	copyTime := func(value *time.Time, fallback time.Time) *time.Time {
		if value != nil && !value.IsZero() {
			copy := value.UTC()
			return &copy
		}
		copy := fallback.UTC()
		return &copy
	}
	switch record.Phase {
	case createFenceReserved:
		record.BaseFirewallAssignment = &baseFirewallAssignmentRecord{
			FirewallUUID: record.Cleanup.FirewallUUID, Phase: cloudapi.FirewallAssignmentIntent, IntentAt: intentAt,
		}
	case createFenceIssued:
		record.BaseFirewallAssignment = &baseFirewallAssignmentRecord{
			VMUUID: record.CreatedVMUUID, FirewallUUID: record.Cleanup.FirewallUUID,
			Phase: cloudapi.FirewallAssignmentIssued, IssueID: issueID, IntentAt: intentAt,
			IssuedAt: copyTime(record.IssuedAt, intentAt),
		}
	case createFenceRejected:
		rejectedAt := copyTime(record.IssuedAt, intentAt)
		record.BaseFirewallAssignment = &baseFirewallAssignmentRecord{
			FirewallUUID: record.Cleanup.FirewallUUID, Phase: cloudapi.FirewallAssignmentRejected,
			IssueID: issueID, IntentAt: intentAt, IssuedAt: copyTime(record.IssuedAt, intentAt), RejectedAt: rejectedAt,
		}
	case createFenceMaterialized:
		observedAt := copyTime(record.ObservedAt, intentAt)
		record.BaseFirewallAssignment = &baseFirewallAssignmentRecord{
			VMUUID: record.CreatedVMUUID, FirewallUUID: record.Cleanup.FirewallUUID,
			Phase: cloudapi.FirewallAssignmentObserved, IssueID: issueID, IntentAt: intentAt,
			IssuedAt: copyTime(record.IssuedAt, intentAt), ObservedAt: observedAt,
		}
	}
	return record
}

func legacyBaseFirewallIssueID(record createFenceRecord) string {
	sum := sha256.Sum256([]byte("legacy-base-firewall\x00" + record.Token + "\x00" + record.CreatedVMUUID + "\x00" + record.Cleanup.FirewallUUID))
	return hex.EncodeToString(sum[:16])
}

func parseCreateFence(value string, expected createFenceBinding) (createFenceRecord, error) {
	record, err := decodeCreateFence(value)
	if err != nil {
		return createFenceRecord{}, err
	}
	if record.Binding != expected {
		return createFenceRecord{}, fmt.Errorf("durable VM create fence does not match the exact NodeClaim launch identity")
	}
	return record, nil
}

func newCreateFenceRecord(binding createFenceBinding, cleanup createFenceCleanupIdentity, baseline cloudapi.CreateInventory, now time.Time, nonce func() (string, error)) (createFenceRecord, error) {
	token, err := nonce()
	if err != nil {
		return createFenceRecord{}, fmt.Errorf("generating durable VM create fence token: %w", err)
	}
	now = now.UTC()
	return createFenceRecord{
		Schema: createFenceSchema, Binding: binding, Cleanup: cleanup,
		Baseline: cloneCreateInventory(baseline), Token: token, Phase: createFenceReserved, StartedAt: now,
		BaseFirewallAssignment: &baseFirewallAssignmentRecord{
			FirewallUUID: cleanup.FirewallUUID, Phase: cloudapi.FirewallAssignmentIntent, IntentAt: now,
		},
	}, nil
}

func newBaseFirewallAssignmentIntent(record createFenceRecord, vmUUID string, now time.Time) *baseFirewallAssignmentRecord {
	return &baseFirewallAssignmentRecord{
		VMUUID: strings.ToLower(vmUUID), FirewallUUID: record.Cleanup.FirewallUUID,
		Phase: cloudapi.FirewallAssignmentIntent, IntentAt: now.UTC(),
	}
}

func baseFirewallAssignmentMatches(value *baseFirewallAssignmentRecord, vmUUID, firewallUUID string) bool {
	return value != nil && value.VMUUID == strings.ToLower(vmUUID) && value.FirewallUUID == firewallUUID
}

func firewallAssignmentFenceFromRecord(record createFenceRecord) cloudapi.FirewallAssignmentFence {
	if record.BaseFirewallAssignment == nil {
		return cloudapi.FirewallAssignmentFence{}
	}
	return cloudapi.FirewallAssignmentFence{
		VMUUID: record.BaseFirewallAssignment.VMUUID, FirewallUUID: record.BaseFirewallAssignment.FirewallUUID,
		Phase: record.BaseFirewallAssignment.Phase, IssueID: record.BaseFirewallAssignment.IssueID,
	}
}

func fenceFromRecord(record createFenceRecord) createFence {
	fence := createFence{
		Token: record.Token, StartedAt: record.StartedAt, Baseline: cloneCreateInventory(record.Baseline),
		Issued: record.Phase != createFenceReserved, Intent: record.Intent, IssueID: record.IssueID, CreatedVMUUID: record.CreatedVMUUID,
		HasCleanupHistory:      len(record.CleanupResolutions) != 0,
		RollbackChosen:         record.Phase == createFenceIssued && record.RollbackAt != nil,
		BaseFirewallAssignment: firewallAssignmentFenceFromRecord(record),
	}
	if record.IssuedAt != nil {
		fence.IssuedAt = *record.IssuedAt
	}
	return fence
}

func validateCreateInventory(inventory cloudapi.CreateInventory) error {
	encoded, err := json.Marshal(inventory)
	if err != nil || len(encoded) > cloudapi.MaxCreateInventoryEncodedBytes {
		return fmt.Errorf("create inventory exceeds the safe encoded bound of %d bytes", cloudapi.MaxCreateInventoryEncodedBytes)
	}
	for name, entries := range map[string][]string{"VM": inventory.VMs, "potential VM": inventory.PotentialVMs, "target VM": inventory.TargetVMs, "floating IP": inventory.FloatingIPs} {
		if len(entries) > cloudapi.MaxCreateInventoryEntries {
			return fmt.Errorf("%s inventory has %d entries; maximum is %d", name, len(entries), cloudapi.MaxCreateInventoryEntries)
		}
		if !sort.StringsAreSorted(entries) {
			return fmt.Errorf("%s inventory is not sorted", name)
		}
		for i, value := range entries {
			if value == "" || len(value) > 128 || (i > 0 && entries[i-1] == value) {
				return fmt.Errorf("%s inventory contains an empty, oversized, or duplicate identity", name)
			}
		}
	}
	vmSet := make(map[string]struct{}, len(inventory.VMs))
	for _, value := range inventory.VMs {
		vmSet[value] = struct{}{}
	}
	for _, value := range inventory.PotentialVMs {
		if _, ok := vmSet[value]; !ok {
			return fmt.Errorf("potential VM identity %q is absent from the complete VM baseline", value)
		}
	}
	potentialSet := make(map[string]struct{}, len(inventory.PotentialVMs))
	for _, value := range inventory.PotentialVMs {
		potentialSet[value] = struct{}{}
	}
	for _, value := range inventory.TargetVMs {
		if _, ok := potentialSet[value]; !ok {
			return fmt.Errorf("target VM identity %q is absent from the potential VM baseline", value)
		}
	}
	targetSet := make(map[string]struct{}, len(inventory.TargetVMs))
	for _, value := range inventory.TargetVMs {
		targetSet[value] = struct{}{}
	}
	floatingIPSet := make(map[string]struct{}, len(inventory.FloatingIPs))
	for _, value := range inventory.FloatingIPs {
		floatingIPSet[value] = struct{}{}
	}
	if len(inventory.TargetFloatingIPs) > cloudapi.MaxCreateTargetFloatingIPAssignments {
		return fmt.Errorf("target floating-IP inventory exceeds %d entries", cloudapi.MaxCreateTargetFloatingIPAssignments)
	}
	for i, assignment := range inventory.TargetFloatingIPs {
		address, addressErr := netip.ParseAddr(assignment.Address)
		if assignment.Identity == "" || len(assignment.Identity) > 128 ||
			!createFenceVMUUIDPattern.MatchString(assignment.VMUUID) || assignment.VMUUID != strings.ToLower(assignment.VMUUID) ||
			addressErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != assignment.Address ||
			assignment.BillingAccountID <= 0 || len(assignment.Name) > 128 {
			return fmt.Errorf("target floating-IP inventory contains a malformed assignment")
		}
		if _, ok := targetSet[assignment.VMUUID]; !ok {
			return fmt.Errorf("target floating-IP assignment references non-target VM %q", assignment.VMUUID)
		}
		if _, ok := floatingIPSet[assignment.Identity]; !ok {
			return fmt.Errorf("target floating-IP assignment %q is absent from the complete floating-IP baseline", assignment.Identity)
		}
		if i > 0 {
			previous := inventory.TargetFloatingIPs[i-1]
			if previous.VMUUID > assignment.VMUUID || (previous.VMUUID == assignment.VMUUID && previous.Identity >= assignment.Identity) {
				return fmt.Errorf("target floating-IP inventory is unsorted or contains a duplicate assignment")
			}
		}
	}
	return nil
}

func cloneCreateInventory(inventory cloudapi.CreateInventory) cloudapi.CreateInventory {
	return cloudapi.CreateInventory{
		VMs: append([]string(nil), inventory.VMs...), PotentialVMs: append([]string(nil), inventory.PotentialVMs...),
		TargetVMs:         append([]string(nil), inventory.TargetVMs...),
		FloatingIPs:       append([]string(nil), inventory.FloatingIPs...),
		TargetFloatingIPs: append([]cloudapi.CreateFloatingIPAssignment(nil), inventory.TargetFloatingIPs...),
	}
}

func createFenceNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func createFenceHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type memoryCreateFenceStore struct {
	mu                    sync.Mutex
	records               map[types.UID]createFenceRecord
	floatingIPUpdates     map[types.UID]floatingIPUpdateRecord
	removalMutations      map[types.UID]removalMutationRecord
	firewallMutationSlots map[string]firewallMutationSlotRecord
	now                   func() time.Time
	nonce                 func() (string, error)
}

func NewMemoryCreateFenceStore() CreateFenceStore {
	return &memoryCreateFenceStore{
		records: map[types.UID]createFenceRecord{}, floatingIPUpdates: map[types.UID]floatingIPUpdateRecord{},
		removalMutations:      map[types.UID]removalMutationRecord{},
		firewallMutationSlots: map[string]firewallMutationSlotRecord{}, now: time.Now, nonce: createFenceNonce,
	}
}

func (s *memoryCreateFenceStore) Get(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, cleanup createFenceCleanupIdentity) (*karpv1.NodeClaim, createFence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[claim.UID]
	if !ok {
		return claim.DeepCopy(), createFence{}, false, nil
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, createFence{}, false, err
	}
	if record.Cleanup != cleanup {
		return nil, createFence{}, false, fmt.Errorf("durable VM create cleanup identity changed")
	}
	return claimWithCreateFence(claim, record), fenceFromRecord(record), true, nil
}

func (s *memoryCreateFenceStore) Ensure(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, cleanup createFenceCleanupIdentity, baseline cloudapi.CreateInventory) (*karpv1.NodeClaim, createFence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if claim == nil || claim.UID == "" || claim.Name == "" || claim.DeletionTimestamp != nil {
		return nil, createFence{}, false, fmt.Errorf("durable VM create fencing requires a live named NodeClaim with UID")
	}
	if record, ok := s.records[claim.UID]; ok {
		if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
			return nil, createFence{}, false, err
		}
		if record.Cleanup != cleanup {
			return nil, createFence{}, false, fmt.Errorf("durable VM create cleanup identity changed")
		}
		return claimWithCreateFence(claim, record), fenceFromRecord(record), !fenceFromRecord(record).Issued, nil
	}
	if err := validateCreateInventory(baseline); err != nil {
		return nil, createFence{}, false, err
	}
	record, err := newCreateFenceRecord(binding, cleanup, baseline, s.now(), s.nonce)
	if err != nil {
		return nil, createFence{}, false, err
	}
	s.records[claim.UID] = record
	s.removalMutations[claim.UID] = newRemovalMutationReadyRecord(binding, record.Token, record.StartedAt)
	return claimWithRemovalMutation(claimWithCreateFence(claim, record), s.removalMutations[claim.UID]), fenceFromRecord(record), true, nil
}

func (s *memoryCreateFenceStore) Authorize(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, intent cloudapi.CreateAuthorizationKind) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if claim == nil || claim.DeletionTimestamp != nil || !controllerutil.ContainsFinalizer(claim, CreateFenceFinalizer) {
		return nil, fmt.Errorf("NodeClaim is deleting or lacks create-protection finalizer before VM POST")
	}
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	if record.Token != token {
		return nil, fmt.Errorf("durable VM create fence token changed before VM POST")
	}
	if intent != cloudapi.CreateAuthorizationPost && intent != cloudapi.CreateAuthorizationAdoption {
		return nil, fmt.Errorf("invalid VM create authorization intent %q", intent)
	}
	if record.Phase != createFenceReserved || record.IssuedAt != nil || record.RollbackAt != nil || len(record.CleanupResolutions) != 0 {
		return nil, fmt.Errorf("%w: immutable VM create attempt was already issued", cloudapi.ErrCreateAttemptPending)
	}
	now := s.now().UTC()
	issueID, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("generating VM create authorization identity: %w", err)
	}
	assignmentIssueID, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("generating base-firewall assignment authorization identity: %w", err)
	}
	if assignment := record.BaseFirewallAssignment; assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIntent || assignment.VMUUID != "" || assignment.FirewallUUID != record.Cleanup.FirewallUUID {
		return nil, fmt.Errorf("durable pre-VM base-firewall assignment intent is missing")
	}
	record.Phase = createFenceIssued
	record.Intent = intent
	record.IssueID = issueID
	record.IssuedAt = &now
	record.BaseFirewallAssignment.Phase = cloudapi.FirewallAssignmentIssued
	record.BaseFirewallAssignment.IssueID = assignmentIssueID
	record.BaseFirewallAssignment.IssuedAt = &now
	s.records[claim.UID] = record
	return claimWithCreateFence(claim, record), nil
}

func (s *memoryCreateFenceStore) RecordCreatedVM(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, issueID, vmUUID string) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vmUUID = strings.ToLower(vmUUID)
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	if record.Token != token || record.IssueID != issueID || record.IssuedAt == nil || !createFenceVMUUIDPattern.MatchString(vmUUID) {
		return nil, fmt.Errorf("created VM anchor requires an exactly issued attempt")
	}
	if record.CreatedVMUUID != "" {
		if record.CreatedVMUUID == vmUUID {
			if !baseFirewallAssignmentMatches(record.BaseFirewallAssignment, vmUUID, record.Cleanup.FirewallUUID) {
				return nil, fmt.Errorf("created VM lacks its pre-issued base-firewall assignment receipt")
			}
			return claimWithCreateFence(claim, record), nil
		}
		return nil, fmt.Errorf("created VM identity changed")
	}
	if record.Phase != createFenceIssued || record.RollbackAt != nil {
		return nil, fmt.Errorf("created VM anchor requires an exactly issued attempt")
	}
	if assignment := record.BaseFirewallAssignment; assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.VMUUID != "" ||
		assignment.FirewallUUID != record.Cleanup.FirewallUUID || !createFenceKeyHashPattern.MatchString(assignment.IssueID) {
		return nil, fmt.Errorf("created VM anchor lacks its pre-issued base-firewall assignment")
	}
	now := s.now().UTC()
	record.CreatedVMUUID = vmUUID
	record.LaunchObservedAt = &now
	record.BaseFirewallAssignment.VMUUID = vmUUID
	s.records[claim.UID] = record
	return claimWithCreateFence(claim, record), nil
}

func (s *memoryCreateFenceStore) AuthorizeBaseFirewall(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID string) (*karpv1.NodeClaim, cloudapi.FirewallAssignmentAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vmUUID = strings.ToLower(vmUUID)
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, err
	}
	if record.Token != token || record.Phase != createFenceIssued || record.IssuedAt == nil || record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("base-firewall assignment requires the exact anchored VM attempt")
	}
	if record.BaseFirewallAssignment == nil {
		now := s.now().UTC()
		record.BaseFirewallAssignment = newBaseFirewallAssignmentIntent(record, vmUUID, now)
	}
	assignment := record.BaseFirewallAssignment
	if !baseFirewallAssignmentMatches(assignment, vmUUID, record.Cleanup.FirewallUUID) {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("base-firewall assignment identity changed")
	}
	if assignment.Phase == cloudapi.FirewallAssignmentIssued {
		if record.LegacyV2BaseFirewallMayBeIssued {
			return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, nil
		}
		value, allow, err := s.acquireFirewallMutationSlot(claim, record, vmUUID, firewallMutationAssign, assignment.IssueID)
		if err != nil {
			return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, err
		}
		return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{
			Fence:     cloudapi.FirewallAssignmentFence{VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: value.Phase, IssueID: value.IssueID},
			AllowPOST: allow,
		}, nil
	}
	if assignment.Phase == cloudapi.FirewallAssignmentObserved {
		return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, nil
	}
	if assignment.Phase != cloudapi.FirewallAssignmentIntent && assignment.Phase != cloudapi.FirewallAssignmentRejected {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, fmt.Errorf("invalid base-firewall assignment phase %q", assignment.Phase)
	}
	if assignment.Phase == cloudapi.FirewallAssignmentRejected {
		if err := s.finishFirewallMutationSlot(record, claim, firewallMutationAssign, vmUUID, assignment.IssueID, cloudapi.FirewallAssignmentRejected); err != nil {
			return nil, cloudapi.FirewallAssignmentAuthorization{}, err
		}
	}
	issueID, err := s.nonce()
	if err != nil {
		return nil, cloudapi.FirewallAssignmentAuthorization{}, err
	}
	now := s.now().UTC()
	assignment.Phase = cloudapi.FirewallAssignmentIssued
	assignment.IssueID = issueID
	assignment.IssuedAt = &now
	assignment.RejectedAt = nil
	assignment.ObservedAt = nil
	s.records[claim.UID] = record
	value, allow, err := s.acquireFirewallMutationSlot(claim, record, vmUUID, firewallMutationAssign, issueID)
	if err != nil {
		return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{Fence: firewallAssignmentFenceFromRecord(record)}, err
	}
	return claimWithCreateFence(claim, record), cloudapi.FirewallAssignmentAuthorization{
		Fence:     cloudapi.FirewallAssignmentFence{VMUUID: vmUUID, FirewallUUID: record.Cleanup.FirewallUUID, Phase: value.Phase, IssueID: value.IssueID},
		AllowPOST: allow,
	}, nil
}

func (s *memoryCreateFenceStore) ObserveBaseFirewall(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID, issueID string) (*karpv1.NodeClaim, error) {
	return s.finishBaseFirewallAssignment(claim, binding, token, vmUUID, issueID, cloudapi.FirewallAssignmentObserved)
}

func (s *memoryCreateFenceStore) RejectBaseFirewall(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID, issueID string) (*karpv1.NodeClaim, error) {
	return s.finishBaseFirewallAssignment(claim, binding, token, vmUUID, issueID, cloudapi.FirewallAssignmentRejected)
}

func (s *memoryCreateFenceStore) AuthorizeFloatingIPUpdate(
	_ context.Context,
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token, vmUUID, address, name string,
	billingAccountID int64,
) (*karpv1.NodeClaim, cloudapi.FloatingIPUpdateAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	desired, err := newFloatingIPUpdateFence(vmUUID, address, name, billingAccountID)
	if err != nil {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, err
	}
	createRecord, ok := s.records[claim.UID]
	if !ok {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(createRecord), binding); err != nil {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, err
	}
	if token == "" || createRecord.Token != token || createRecord.CreatedVMUUID != desired.VMUUID || createRecord.LaunchObservedAt == nil {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("floating-IP update lacks the exact anchored VM attempt")
	}
	if record, exists := s.floatingIPUpdates[claim.UID]; exists {
		if !floatingIPUpdateIdentityMatches(record, desired) {
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("floating-IP update identity changed")
		}
		switch record.Phase {
		case cloudapi.FloatingIPUpdateIssued, cloudapi.FloatingIPUpdateObserved:
			return claimWithFloatingIPUpdate(claim, createRecord, record), cloudapi.FloatingIPUpdateAuthorization{Fence: floatingIPUpdateFenceFromRecord(record)}, nil
		case cloudapi.FloatingIPUpdateRejected:
		default:
			return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("invalid floating-IP update phase %q", record.Phase)
		}
	}
	issueID, err := s.nonce()
	if err != nil {
		return nil, cloudapi.FloatingIPUpdateAuthorization{}, fmt.Errorf("generating floating-IP update issue identity: %w", err)
	}
	now := s.now().UTC()
	record := floatingIPUpdateRecord{
		Schema: floatingIPUpdateFenceSchema, Binding: binding, AttemptToken: token,
		VMUUID: desired.VMUUID, Address: desired.Address, Name: desired.Name, BillingAccountID: desired.BillingAccountID,
		Phase: cloudapi.FloatingIPUpdateIssued, IssueID: issueID, IssuedAt: now,
	}
	s.floatingIPUpdates[claim.UID] = record
	return claimWithFloatingIPUpdate(claim, createRecord, record), cloudapi.FloatingIPUpdateAuthorization{
		Fence: floatingIPUpdateFenceFromRecord(record), AllowPOST: !createRecord.LegacyV2FloatingIPMayBeIssued,
	}, nil
}

func (s *memoryCreateFenceStore) ObserveFloatingIPUpdate(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FloatingIPUpdateFence) (*karpv1.NodeClaim, error) {
	return s.finishFloatingIPUpdate(claim, binding, token, fence, cloudapi.FloatingIPUpdateObserved)
}

func (s *memoryCreateFenceStore) RejectFloatingIPUpdate(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, fence cloudapi.FloatingIPUpdateFence) (*karpv1.NodeClaim, error) {
	return s.finishFloatingIPUpdate(claim, binding, token, fence, cloudapi.FloatingIPUpdateRejected)
}

func (s *memoryCreateFenceStore) finishFloatingIPUpdate(
	claim *karpv1.NodeClaim,
	binding createFenceBinding,
	token string,
	fence cloudapi.FloatingIPUpdateFence,
	terminal cloudapi.FloatingIPUpdatePhase,
) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateFloatingIPUpdateFence(fence); err != nil {
		return nil, err
	}
	if terminal != cloudapi.FloatingIPUpdateObserved && terminal != cloudapi.FloatingIPUpdateRejected {
		return nil, fmt.Errorf("invalid floating-IP update terminal phase %q", terminal)
	}
	createRecord, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(createRecord), binding); err != nil {
		return nil, err
	}
	record, ok := s.floatingIPUpdates[claim.UID]
	if !ok || createRecord.Token != token || !floatingIPUpdateIdentityMatches(record, fence) || record.IssueID != fence.IssueID {
		return nil, fmt.Errorf("floating-IP update identity changed")
	}
	if record.Phase == terminal {
		return claimWithFloatingIPUpdate(claim, createRecord, record), nil
	}
	if record.Phase != cloudapi.FloatingIPUpdateIssued {
		return nil, fmt.Errorf("floating-IP update does not match its issued receipt")
	}
	now := s.now().UTC()
	record.Phase = terminal
	if terminal == cloudapi.FloatingIPUpdateObserved {
		record.ObservedAt = &now
		record.RejectedAt = nil
	} else {
		record.RejectedAt = &now
		record.ObservedAt = nil
	}
	s.floatingIPUpdates[claim.UID] = record
	return claimWithFloatingIPUpdate(claim, createRecord, record), nil
}

func (s *memoryCreateFenceStore) finishBaseFirewallAssignment(claim *karpv1.NodeClaim, binding createFenceBinding, token, vmUUID, issueID string, terminal cloudapi.FirewallAssignmentPhase) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vmUUID = strings.ToLower(vmUUID)
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	assignment := record.BaseFirewallAssignment
	if record.Token != token || !baseFirewallAssignmentMatches(assignment, vmUUID, record.Cleanup.FirewallUUID) {
		return nil, fmt.Errorf("base-firewall assignment identity changed")
	}
	if assignment.Phase == terminal && assignment.IssueID == issueID {
		if err := s.finishFirewallMutationSlot(record, claim, firewallMutationAssign, vmUUID, issueID, terminal); err != nil {
			return nil, err
		}
		return claimWithCreateFence(claim, record), nil
	}
	if assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.IssueID != issueID || assignment.IssuedAt == nil {
		return nil, fmt.Errorf("base-firewall assignment does not match its issued receipt")
	}
	now := s.now().UTC()
	assignment.Phase = terminal
	if terminal == cloudapi.FirewallAssignmentObserved {
		assignment.ObservedAt = &now
		assignment.RejectedAt = nil
	} else if terminal == cloudapi.FirewallAssignmentRejected {
		assignment.RejectedAt = &now
		assignment.ObservedAt = nil
	} else {
		return nil, fmt.Errorf("invalid base-firewall assignment terminal phase %q", terminal)
	}
	s.records[claim.UID] = record
	if err := s.finishFirewallMutationSlot(record, claim, firewallMutationAssign, vmUUID, issueID, terminal); err != nil {
		return nil, err
	}
	return claimWithCreateFence(claim, record), nil
}

func (s *memoryCreateFenceStore) ChooseRollback(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, issueID, vmUUID string, resolution *cloudapi.FencedCreateCleanupResolution) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vmUUID = strings.ToLower(vmUUID)
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	if record.Token != token || record.IssueID != issueID || record.Phase != createFenceIssued || record.IssuedAt == nil ||
		record.CreatedVMUUID != vmUUID || record.LaunchObservedAt == nil {
		return nil, fmt.Errorf("rollback requires the exact anchored create attempt")
	}
	if record.RollbackAt == nil {
		now := s.now().UTC()
		record.RollbackAt = &now
		record.DependentUnresolved = resolution == nil
		record.DependentsResolvedAt = nil
	}
	record.ProtectionFailureAt = nil
	if resolution != nil {
		canonical, err := normalizeCleanupResolution(*resolution)
		if err != nil {
			return nil, err
		}
		if canonical.VMUUID != vmUUID {
			return nil, fmt.Errorf("rollback receipt does not match the anchored VM")
		}
		if err := applyCleanupResolution(&record, canonical); err != nil {
			return nil, err
		}
		record.DependentUnresolved = false
		record.DependentsResolvedAt = nil
	}
	s.records[claim.UID] = record
	return claimWithCreateFence(claim, record), nil
}

func (s *memoryCreateFenceStore) MarkRejected(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token, issueID string) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	if record.Token != token || record.IssueID != issueID || record.Phase != createFenceIssued || record.IssuedAt == nil || record.CreatedVMUUID != "" || record.RollbackAt != nil || len(record.CleanupResolutions) != 0 {
		return nil, fmt.Errorf("VM create attempt cannot be rejected unless it is exactly issued")
	}
	assignment := record.BaseFirewallAssignment
	if assignment == nil || assignment.Phase != cloudapi.FirewallAssignmentIssued || assignment.VMUUID != "" {
		return nil, fmt.Errorf("VM rejection lacks its unused base-firewall assignment issue")
	}
	now := s.now().UTC()
	record.Phase = createFenceRejected
	assignment.Phase = cloudapi.FirewallAssignmentRejected
	assignment.RejectedAt = &now
	s.records[claim.UID] = record
	return claimWithCreateFence(claim, record), nil
}

func (s *memoryCreateFenceStore) MarkMaterialized(_ context.Context, claim *karpv1.NodeClaim, binding createFenceBinding, token string, vm *cloudapi.VM) (*karpv1.NodeClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[claim.UID]
	if !ok {
		return nil, fmt.Errorf("durable VM create fence is missing")
	}
	if _, err := parseCreateFence(mustEncodeCreateFence(record), binding); err != nil {
		return nil, err
	}
	if record.Token != token {
		return nil, fmt.Errorf("durable VM create fence token changed before materialization")
	}
	if err := validateMaterializedVM(record, vm); err != nil {
		return nil, err
	}
	if !(record.LegacyV2 && record.Phase == createFenceMaterialized) {
		update, ok := s.floatingIPUpdates[claim.UID]
		if !ok || update.Phase != cloudapi.FloatingIPUpdateObserved || update.VMUUID != strings.ToLower(vm.UUID) ||
			update.Address != vm.PublicIPv4 || update.Name != vm.FloatingIPName || update.BillingAccountID != vm.BillingAccountID {
			return nil, fmt.Errorf("materialized VM lacks its exact observed floating-IP update receipt")
		}
	}
	if record.Phase == createFenceMaterialized {
		return claimWithCreateFence(claim, record), nil
	}
	if record.Phase != createFenceIssued || record.IssuedAt == nil {
		return nil, fmt.Errorf("VM create attempt must be durably issued before materialization")
	}
	if record.CreatedVMUUID != strings.ToLower(vm.UUID) || record.LaunchObservedAt == nil {
		return nil, fmt.Errorf("VM create result must be durably anchored before materialization")
	}
	if record.RollbackAt != nil || record.CleanupVMUUID != "" || len(record.CleanupResolutions) != 0 {
		return nil, fmt.Errorf("VM create rollback is already durably chosen and cannot be materialized")
	}
	if record.Phase != createFenceMaterialized {
		now := s.now().UTC()
		record.Phase = createFenceMaterialized
		record.ProtectionFailureAt = nil
		record.ObservedAt = &now
		record.ObservedVMUUID = strings.ToLower(vm.UUID)
		record.FloatingIPName = vm.FloatingIPName
		publicIP, _ := netip.ParseAddr(vm.PublicIPv4)
		record.PublicIPv4 = publicIP.String()
		s.records[claim.UID] = record
	}
	return claimWithCreateFence(claim, record), nil
}

func validateMaterializedVM(record createFenceRecord, vm *cloudapi.VM) error {
	if vm == nil || !createFenceVMUUIDPattern.MatchString(vm.UUID) || vm.Name != record.Cleanup.VMName || vm.ClusterName != record.Cleanup.ClusterName ||
		vm.NodeClaimName != record.Cleanup.NodeClaimName || vm.Location != record.Cleanup.Location || vm.BillingAccountID != record.Cleanup.BillingAccountID {
		return fmt.Errorf("materialized VM does not match the exact durable create identity")
	}
	if vm.FloatingIPName == "" || vm.PublicIPv4 == "" {
		return fmt.Errorf("materialized VM lacks durable floating-IP name or address")
	}
	if record.BaseFirewallAssignment == nil || record.BaseFirewallAssignment.Phase != cloudapi.FirewallAssignmentObserved ||
		record.BaseFirewallAssignment.VMUUID != strings.ToLower(vm.UUID) || record.BaseFirewallAssignment.FirewallUUID != record.Cleanup.FirewallUUID {
		return fmt.Errorf("materialized VM lacks a durable observed base-firewall assignment")
	}
	publicIP, err := netip.ParseAddr(vm.PublicIPv4)
	if err != nil || !publicIP.Is4() || !publicIP.IsGlobalUnicast() || publicIP.IsPrivate() {
		return fmt.Errorf("materialized VM has invalid public IPv4 %q", vm.PublicIPv4)
	}
	if record.ObservedVMUUID != "" && (record.ObservedVMUUID != strings.ToLower(vm.UUID) || record.FloatingIPName != vm.FloatingIPName || record.PublicIPv4 != publicIP.String()) {
		return fmt.Errorf("materialized VM identity changed")
	}
	return nil
}

func applyCleanupResolution(record *createFenceRecord, resolution cloudapi.FencedCreateCleanupResolution) error {
	if record == nil {
		return fmt.Errorf("internal rollback cleanup record is nil")
	}
	resolution, err := normalizeCleanupResolution(resolution)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	record.CleanupResolvedAt = &now
	record.CleanupVMUUID = resolution.VMUUID
	record.CleanupFloatingIPName = resolution.FloatingIPName
	record.CleanupPublicIPv4 = resolution.PublicIPv4
	record.CleanupResolutions, err = appendCleanupResolution(record.CleanupResolutions, resolution)
	return err
}

func appendCleanupResolution(resolutions []cloudapi.FencedCreateCleanupResolution, resolution cloudapi.FencedCreateCleanupResolution) ([]cloudapi.FencedCreateCleanupResolution, error) {
	resolution, err := normalizeCleanupResolution(resolution)
	if err != nil {
		return nil, err
	}
	for _, existing := range resolutions {
		if existing.VMUUID == resolution.VMUUID {
			if existing != resolution {
				return nil, fmt.Errorf("cleanup receipt for VM %s changed dependent identity", resolution.VMUUID)
			}
			return resolutions, nil
		}
	}
	if len(resolutions) >= cloudapi.MaxCreateCleanupResolutions {
		return nil, fmt.Errorf("internal rollback cleanup history exceeds its safe bound")
	}
	resolutions = append(resolutions, resolution)
	sort.Slice(resolutions, func(i, j int) bool {
		return resolutions[i].VMUUID < resolutions[j].VMUUID
	})
	return resolutions, nil
}

func cleanupResolutionStored(record createFenceRecord, resolution cloudapi.FencedCreateCleanupResolution) bool {
	for _, existing := range record.CleanupResolutions {
		if existing == resolution {
			return true
		}
	}
	return false
}

func normalizeCleanupResolution(resolution cloudapi.FencedCreateCleanupResolution) (cloudapi.FencedCreateCleanupResolution, error) {
	resolution.VMUUID = strings.ToLower(resolution.VMUUID)
	if !createFenceVMUUIDPattern.MatchString(resolution.VMUUID) || resolution.FloatingIPName == "" || len(resolution.FloatingIPName) > 255 {
		return cloudapi.FencedCreateCleanupResolution{}, fmt.Errorf("cleanup resolution is missing a canonical VM UUID or floating-IP name")
	}
	publicIP, err := netip.ParseAddr(resolution.PublicIPv4)
	if err != nil || !publicIP.Is4() || !publicIP.IsGlobalUnicast() || publicIP.IsPrivate() {
		return cloudapi.FencedCreateCleanupResolution{}, fmt.Errorf("cleanup resolution has invalid public IPv4 %q", resolution.PublicIPv4)
	}
	resolution.PublicIPv4 = publicIP.String()
	return resolution, nil
}

func claimWithCreateFence(claim *karpv1.NodeClaim, record createFenceRecord) *karpv1.NodeClaim {
	copy := claim.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	controllerutil.AddFinalizer(copy, CreateFenceFinalizer)
	return copy
}

func claimWithFloatingIPUpdate(claim *karpv1.NodeClaim, createRecord createFenceRecord, update floatingIPUpdateRecord) *karpv1.NodeClaim {
	copy := claimWithCreateFence(claim, createRecord)
	encoded, err := json.Marshal(update)
	if err != nil {
		panic(err)
	}
	copy.Annotations[AnnotationFloatingIPUpdateFence] = string(encoded)
	return copy
}

func mustEncodeCreateFence(record createFenceRecord) string {
	encoded, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
