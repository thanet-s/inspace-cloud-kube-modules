package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/providerid"
)

const (
	AnnotationTerminationRecovery      = "karpenter.inspace.cloud/termination-recovery"
	terminationRecoverySchema          = "karpenter.inspace.cloud/termination-recovery-v1"
	terminationRecoveryConfirmationGap = 30 * time.Second
	terminationRecoveryNodePoll        = 5 * time.Second
	terminationRecoveryMaxRecordBytes  = 4 * 1024
)

type nodeClaimDeleter interface {
	Delete(context.Context, *karpv1.NodeClaim) error
}

// terminationRecoveryObservation is a restart-stable first proof that the
// registered Node associated with a deleting NodeClaim is absent. It is bound
// to the immutable NodeClaim UID, canonical ProviderID, and exact durable
// create fence that authorizes the provider's deletion audit.
type terminationRecoveryObservation struct {
	Schema            string    `json:"schema"`
	NodeClaimUID      string    `json:"nodeClaimUID"`
	ProviderID        string    `json:"providerID"`
	CreateFenceSHA256 string    `json:"createFenceSHA256"`
	FirstAbsentAt     time.Time `json:"firstAbsentAt"`
}

// TerminationRecoveryController closes a Karpenter lifecycle missed-wakeup
// race. Upstream waits for a registered Node to disappear but relies on the
// corresponding Node event to enqueue the NodeClaim again. If that event is
// consumed before the cache observes Node absence, the Karpenter termination
// finalizer can otherwise remain indefinitely.
//
// This controller does not replace normal lifecycle finalization. It acts only
// after two spaced, uncached Node-absence proofs and an exact terminal cloud
// absence result from the undecorated InSpace provider.
type TerminationRecoveryController struct {
	kubeClient client.Client
	apiReader  client.Reader
	provider   nodeClaimDeleter
	now        func() time.Time
	wait       time.Duration
}

func NewTerminationRecoveryController(kubeClient client.Client, apiReader client.Reader, provider nodeClaimDeleter) (*TerminationRecoveryController, error) {
	if kubeClient == nil || apiReader == nil || provider == nil {
		return nil, fmt.Errorf("Kubernetes client, uncached API reader, and undecorated provider are required for NodeClaim termination recovery")
	}
	return &TerminationRecoveryController{
		kubeClient: kubeClient,
		apiReader:  apiReader,
		provider:   provider,
		now:        time.Now,
		wait:       terminationRecoveryConfirmationGap,
	}, nil
}

func (c *TerminationRecoveryController) Name() string {
	return "inspace.nodeclaim.termination-recovery"
}

func (c *TerminationRecoveryController) Reconcile(ctx context.Context, nodeClaim *karpv1.NodeClaim) (reconcile.Result, error) {
	var exact karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &exact); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if exact.UID != nodeClaim.UID {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q UID changed before termination recovery", nodeClaim.Name)
	}
	if !terminationRecoveryEligible(&exact) {
		return reconcile.Result{}, nil
	}
	binding, err := terminationRecoveryBindingFor(&exact)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery identity: %w", exact.Name, err)
	}

	var observation *terminationRecoveryObservation
	if encoded := exact.Annotations[AnnotationTerminationRecovery]; encoded != "" {
		decoded, decodeErr := decodeTerminationRecoveryObservation(encoded)
		if decodeErr != nil {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery observation: %w", exact.Name, decodeErr)
		}
		if decoded.NodeClaimUID != binding.NodeClaimUID || decoded.ProviderID != binding.ProviderID ||
			decoded.CreateFenceSHA256 != binding.CreateFenceSHA256 {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery observation drifted from its exact launch identity", exact.Name)
		}
		if decoded.FirstAbsentAt.Before(exact.DeletionTimestamp.Time.UTC()) {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery observation predates deletion", exact.Name)
		}
		if decoded.FirstAbsentAt.After(c.now().UTC()) {
			return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery observation is from the future", exact.Name)
		}
		observation = &decoded
	}

	present, err := c.matchingNodePresent(ctx, binding.ProviderID)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("reading uncached Nodes for NodeClaim %q termination recovery: %w", exact.Name, err)
	}
	if present {
		if observation == nil {
			return reconcile.Result{RequeueAfter: terminationRecoveryNodePoll}, nil
		}
		if err := c.resetObservation(ctx, &exact, *observation); err != nil {
			if apierrors.IsConflict(err) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, err
		}
		return reconcile.Result{RequeueAfter: terminationRecoveryNodePoll}, nil
	}

	if observation == nil {
		first := terminationRecoveryObservation{
			Schema:            terminationRecoverySchema,
			NodeClaimUID:      binding.NodeClaimUID,
			ProviderID:        binding.ProviderID,
			CreateFenceSHA256: binding.CreateFenceSHA256,
			FirstAbsentAt:     c.now().UTC(),
		}
		if err := c.persistObservation(ctx, &exact, first); err != nil {
			if apierrors.IsConflict(err) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, err
		}
		return reconcile.Result{RequeueAfter: c.wait}, nil
	}

	notBefore := observation.FirstAbsentAt.Add(c.wait)
	if remaining := notBefore.Sub(c.now().UTC()); remaining > 0 {
		return reconcile.Result{RequeueAfter: remaining}, nil
	}

	deleteErr := c.provider.Delete(ctx, exact.DeepCopy())
	if !cloudprovider.IsNodeClaimNotFoundError(deleteErr) {
		if deleteErr == nil {
			deleteErr = fmt.Errorf("undecorated provider returned nil instead of a typed NodeClaimNotFound result")
		}
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery cloud audit was not terminal: %w", exact.Name, deleteErr)
	}

	// The cloud audit can write durable removal receipts. Re-read both identity
	// and Node absence after it completes, and only then CAS-remove Karpenter's
	// finalizer. The provider create-protection finalizer remains for its
	// independent location-wide dependent audit.
	var readback karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: exact.Name}, &readback); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if readback.UID != exact.UID || !terminationRecoveryEligible(&readback) {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q identity or lifecycle state changed after termination recovery cloud audit", exact.Name)
	}
	readbackBinding, err := terminationRecoveryBindingFor(&readback)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery readback identity: %w", exact.Name, err)
	}
	if readbackBinding != binding {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q launch identity changed after termination recovery cloud audit", exact.Name)
	}
	readbackObservation, err := decodeTerminationRecoveryObservation(readback.Annotations[AnnotationTerminationRecovery])
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery proof after cloud audit: %w", exact.Name, err)
	}
	if readbackObservation != *observation {
		return reconcile.Result{}, fmt.Errorf("NodeClaim %q termination recovery proof changed after cloud audit", exact.Name)
	}
	present, err = c.matchingNodePresent(ctx, binding.ProviderID)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("re-reading uncached Nodes for NodeClaim %q termination recovery: %w", exact.Name, err)
	}
	if present {
		if err := c.resetObservation(ctx, &readback, readbackObservation); err != nil {
			if apierrors.IsConflict(err) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, err
		}
		return reconcile.Result{RequeueAfter: terminationRecoveryNodePoll}, nil
	}
	if err := c.removeTerminationFinalizer(ctx, &readback); err != nil {
		if apierrors.IsConflict(err) {
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func terminationRecoveryEligible(nodeClaim *karpv1.NodeClaim) bool {
	return nodeClaim != nil &&
		!nodeClaim.DeletionTimestamp.IsZero() &&
		nodeClaim.Status.ProviderID != "" &&
		controllerutil.ContainsFinalizer(nodeClaim, karpv1.TerminationFinalizer) &&
		controllerutil.ContainsFinalizer(nodeClaim, CreateFenceFinalizer) &&
		nodeClaim.StatusConditions().Get(karpv1.ConditionTypeRegistered).IsTrue() &&
		!nodeClaimHasCondition(nodeClaim, karpv1.ConditionTypeInstanceTerminating)
}

func nodeClaimHasCondition(nodeClaim *karpv1.NodeClaim, conditionType string) bool {
	for _, condition := range nodeClaim.Status.Conditions {
		if condition.Type == conditionType {
			return true
		}
	}
	return false
}

func terminationRecoveryBindingFor(nodeClaim *karpv1.NodeClaim) (terminationRecoveryObservation, error) {
	id, err := providerid.Parse(nodeClaim.Status.ProviderID)
	if err != nil {
		return terminationRecoveryObservation{}, err
	}
	canonicalProviderID := providerid.New(id.Location, strings.ToLower(id.VMUUID))
	if nodeClaim.Status.ProviderID != canonicalProviderID {
		return terminationRecoveryObservation{}, fmt.Errorf("ProviderID %q is not canonical", nodeClaim.Status.ProviderID)
	}
	encodedFence := nodeClaim.Annotations[AnnotationCreateFence]
	record, err := decodeCreateFence(encodedFence)
	if err != nil {
		return terminationRecoveryObservation{}, err
	}
	if record.Binding.NodeClaimUID != string(nodeClaim.UID) ||
		record.Cleanup.NodeClaimName != nodeClaim.Name ||
		record.Cleanup.Location != id.Location ||
		record.Phase != createFenceMaterialized ||
		record.ObservedVMUUID != strings.ToLower(id.VMUUID) {
		return terminationRecoveryObservation{}, fmt.Errorf("durable create fence does not match the exact materialized ProviderID")
	}
	if _, err := decodeRemovalMutationRecord(nodeClaim.Annotations[AnnotationRemovalMutationFence], record.Binding, record.Token); err != nil {
		return terminationRecoveryObservation{}, err
	}
	sum := sha256.Sum256([]byte(encodedFence))
	return terminationRecoveryObservation{
		NodeClaimUID:      string(nodeClaim.UID),
		ProviderID:        canonicalProviderID,
		CreateFenceSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func decodeTerminationRecoveryObservation(value string) (terminationRecoveryObservation, error) {
	if value == "" || len(value) > terminationRecoveryMaxRecordBytes {
		return terminationRecoveryObservation{}, fmt.Errorf("observation is missing or oversized")
	}
	if err := validateTerminationRecoveryJSON([]byte(value)); err != nil {
		return terminationRecoveryObservation{}, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	var observation terminationRecoveryObservation
	if err := decoder.Decode(&observation); err != nil {
		return terminationRecoveryObservation{}, fmt.Errorf("decoding observation: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return terminationRecoveryObservation{}, fmt.Errorf("observation contains trailing JSON")
	}
	if observation.Schema != terminationRecoverySchema ||
		observation.NodeClaimUID == "" ||
		observation.ProviderID == "" ||
		len(observation.CreateFenceSHA256) != sha256.Size*2 ||
		observation.FirstAbsentAt.IsZero() {
		return terminationRecoveryObservation{}, fmt.Errorf("observation has incomplete identity")
	}
	if _, err := hex.DecodeString(observation.CreateFenceSHA256); err != nil {
		return terminationRecoveryObservation{}, fmt.Errorf("observation has invalid create-fence digest")
	}
	if observation.CreateFenceSHA256 != strings.ToLower(observation.CreateFenceSHA256) {
		return terminationRecoveryObservation{}, fmt.Errorf("observation has non-canonical create-fence digest")
	}
	if id, err := providerid.Parse(observation.ProviderID); err != nil ||
		observation.ProviderID != providerid.New(id.Location, strings.ToLower(id.VMUUID)) {
		return terminationRecoveryObservation{}, fmt.Errorf("observation has invalid canonical ProviderID")
	}
	return observation, nil
}

func validateTerminationRecoveryJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateTerminationRecoveryJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("observation contains invalid trailing JSON: %w", err)
		}
		return fmt.Errorf("observation contains unexpected trailing JSON token %v", token)
	}
	return nil
}

func validateTerminationRecoveryJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("observation contains invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("observation contains an invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("observation contains a non-string JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("observation contains duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateTerminationRecoveryJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("observation contains an invalid JSON object terminator: %w", err)
		}
		if end != json.Delim('}') {
			return fmt.Errorf("observation contains an invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := validateTerminationRecoveryJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("observation contains an invalid JSON array terminator: %w", err)
		}
		if end != json.Delim(']') {
			return fmt.Errorf("observation contains an invalid JSON array terminator")
		}
	}
	return nil
}

func (c *TerminationRecoveryController) matchingNodePresent(ctx context.Context, providerID string) (bool, error) {
	var nodes corev1.NodeList
	if err := c.apiReader.List(ctx, &nodes); err != nil {
		return false, err
	}
	for i := range nodes.Items {
		if nodes.Items[i].Spec.ProviderID == providerID {
			return true, nil
		}
	}
	return false, nil
}

func (c *TerminationRecoveryController) persistObservation(ctx context.Context, nodeClaim *karpv1.NodeClaim, observation terminationRecoveryObservation) error {
	encoded, err := json.Marshal(observation)
	if err != nil {
		return fmt.Errorf("encoding NodeClaim %q termination recovery observation: %w", nodeClaim.Name, err)
	}
	stored := nodeClaim.DeepCopy()
	updated := nodeClaim.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[AnnotationTerminationRecovery] = string(encoded)
	if err := c.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("persisting NodeClaim %q first uncached Node-absence proof: %w", nodeClaim.Name, err)
	}
	var readback karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &readback); err != nil {
		return fmt.Errorf("reading back NodeClaim %q first uncached Node-absence proof: %w", nodeClaim.Name, err)
	}
	if readback.UID != nodeClaim.UID || readback.Annotations[AnnotationTerminationRecovery] != string(encoded) {
		return fmt.Errorf("NodeClaim %q first uncached Node-absence proof did not survive exact readback", nodeClaim.Name)
	}
	return nil
}

func (c *TerminationRecoveryController) resetObservation(ctx context.Context, nodeClaim *karpv1.NodeClaim, observation terminationRecoveryObservation) error {
	encoded := nodeClaim.Annotations[AnnotationTerminationRecovery]
	storedObservation, err := decodeTerminationRecoveryObservation(encoded)
	if err != nil {
		return fmt.Errorf("NodeClaim %q termination recovery proof before reset: %w", nodeClaim.Name, err)
	}
	if storedObservation != observation {
		return fmt.Errorf("NodeClaim %q termination recovery proof changed before reset", nodeClaim.Name)
	}
	stored := nodeClaim.DeepCopy()
	updated := nodeClaim.DeepCopy()
	delete(updated.Annotations, AnnotationTerminationRecovery)
	if err := c.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("resetting NodeClaim %q termination recovery proof after Node reappeared: %w", nodeClaim.Name, err)
	}
	return nil
}

func (c *TerminationRecoveryController) removeTerminationFinalizer(ctx context.Context, nodeClaim *karpv1.NodeClaim) error {
	if !controllerutil.ContainsFinalizer(nodeClaim, CreateFenceFinalizer) {
		return fmt.Errorf("NodeClaim %q lost create protection before termination finalizer recovery", nodeClaim.Name)
	}
	stored := nodeClaim.DeepCopy()
	updated := nodeClaim.DeepCopy()
	controllerutil.RemoveFinalizer(updated, karpv1.TerminationFinalizer)
	if err := c.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("CAS-removing only NodeClaim %q Karpenter termination finalizer: %w", nodeClaim.Name, err)
	}
	return nil
}

func (c *TerminationRecoveryController) Register(_ context.Context, m manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(m).
		Named(c.Name()).
		For(&karpv1.NodeClaim{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 5}).
		Complete(reconcile.AsReconciler(m.GetClient(), c))
}
