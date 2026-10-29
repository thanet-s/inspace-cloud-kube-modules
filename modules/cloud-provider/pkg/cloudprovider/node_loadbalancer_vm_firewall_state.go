package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	vmFirewallAnchorPrefix    = "inlb-vmfw-"
	vmFirewallAnchorLabel     = "inspace.cloud/node-lb-vm-firewall"
	vmFirewallAnchorFinalizer = "service.inspace.cloud/vm-firewall-state"

	vmFirewallAnnotationPrefix = "service.inspace.cloud/vmfw-"

	annotationVMFirewallVM               = vmFirewallAnnotationPrefix + "vm"
	annotationVMFirewallUUID             = vmFirewallAnnotationPrefix + "uuid"
	annotationVMFirewallApplied          = vmFirewallAnnotationPrefix + "applied"
	annotationVMFirewallAppliedHash      = vmFirewallAnnotationPrefix + "applied-hash"
	annotationVMFirewallAppliedAt        = vmFirewallAnnotationPrefix + "applied-at"
	annotationVMFirewallPending          = vmFirewallAnnotationPrefix + "pending"
	annotationVMFirewallPendingHash      = vmFirewallAnnotationPrefix + "pending-hash"
	annotationVMFirewallPendingOp        = vmFirewallAnnotationPrefix + "pending-op"
	annotationVMFirewallPendingAt        = vmFirewallAnnotationPrefix + "pending-at"
	annotationVMFirewallIssuedAt         = vmFirewallAnnotationPrefix + "issued-at"
	annotationVMFirewallIssueID          = vmFirewallAnnotationPrefix + "issue-id"
	annotationVMFirewallAdoptUUID        = vmFirewallAnnotationPrefix + "adopt-uuid"
	annotationVMFirewallMigration        = vmFirewallAnnotationPrefix + "migration"
	annotationVMFirewallDeleteTarget     = vmFirewallAnnotationPrefix + "delete-target"
	annotationVMFirewallDeleteIssued     = vmFirewallAnnotationPrefix + "delete-issued"
	annotationVMFirewallAbsenceCount     = vmFirewallAnnotationPrefix + "absence-count"
	annotationVMFirewallAbsenceCheckedAt = vmFirewallAnnotationPrefix + "absence-checked-at"
	annotationVMFirewallRepair           = vmFirewallAnnotationPrefix + "repair"
)

var errVMFirewallNamespaceMissing = errors.New("public-node-local: CCM namespace is not configured")

// vmFirewallAnchorName is the name of the anchor ConfigMap of one VM.
func vmFirewallAnchorName(vmUUID string) string { return vmFirewallAnchorPrefix + vmUUID }

func (c *nodeLoadBalancerController) vmFirewallNamespace() (string, error) {
	namespace := strings.TrimSpace(c.provider.config.NodeLoadBalancer.ControllerNamespace)
	if namespace == "" {
		return "", errVMFirewallNamespaceMissing
	}
	return namespace, nil
}

func (c *nodeLoadBalancerController) vmFirewallAnchorLabels() map[string]string {
	return map[string]string{
		vmFirewallAnchorLabel:            "true",
		nodeLoadBalancerNodeClusterLabel: c.provider.config.ClusterID,
	}
}

// validateVMFirewallAnchor requires the exact identity of an anchor: name,
// namespace, both labels and the vm annotation.
func (c *nodeLoadBalancerController) validateVMFirewallAnchor(namespace, vmUUID string, cm *corev1.ConfigMap) error {
	if cm.Namespace != namespace || cm.Name != vmFirewallAnchorName(vmUUID) {
		return corruptVMFirewallLedger("anchor %s/%s is not the anchor of VM %s", cm.Namespace, cm.Name, vmUUID)
	}
	for key, want := range c.vmFirewallAnchorLabels() {
		if cm.Labels[key] != want {
			return corruptVMFirewallLedger("anchor %s label %s is %q, want %q", cm.Name, key, cm.Labels[key], want)
		}
	}
	if cm.Annotations[annotationVMFirewallVM] != vmUUID {
		return corruptVMFirewallLedger("anchor %s names VM %q, want %q", cm.Name, cm.Annotations[annotationVMFirewallVM], vmUUID)
	}
	return nil
}

func validateVMFirewallAnchorVMUUID(vmUUID string) error {
	if _, err := inspace.NodeLoadBalancerVMFirewallName("anchor", vmUUID); err != nil {
		return err
	}
	return nil
}

// getVMFirewallAnchor returns the anchor of vmUUID, or nil when there is none.
func (c *nodeLoadBalancerController) getVMFirewallAnchor(ctx context.Context, vmUUID string) (*corev1.ConfigMap, error) {
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return nil, err
	}
	if err := validateVMFirewallAnchorVMUUID(vmUUID); err != nil {
		return nil, err
	}
	cm, err := c.provider.kubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, vmFirewallAnchorName(vmUUID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("public-node-local: read VM firewall anchor of %s: %w", vmUUID, err)
	}
	if err := c.validateVMFirewallAnchor(namespace, vmUUID, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

// listVMFirewallAnchors returns every anchor of this cluster.
func (c *nodeLoadBalancerController) listVMFirewallAnchors(ctx context.Context) ([]corev1.ConfigMap, error) {
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return nil, err
	}
	selector := vmFirewallAnchorLabel + "=true," + nodeLoadBalancerNodeClusterLabel + "=" + c.provider.config.ClusterID
	list, err := c.provider.kubeClient.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list VM firewall anchors: %w", err)
	}
	for index := range list.Items {
		cm := &list.Items[index]
		vmUUID := strings.TrimPrefix(cm.Name, vmFirewallAnchorPrefix)
		if !strings.HasPrefix(cm.Name, vmFirewallAnchorPrefix) {
			return nil, corruptVMFirewallLedger("anchor %s does not carry the anchor name prefix", cm.Name)
		}
		if err := c.validateVMFirewallAnchor(namespace, vmUUID, cm); err != nil {
			return nil, err
		}
	}
	return list.Items, nil
}

// createVMFirewallAnchor creates the empty anchor of a VM, or returns the
// existing one.
func (c *nodeLoadBalancerController) createVMFirewallAnchor(ctx context.Context, vmUUID string) (*corev1.ConfigMap, error) {
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return nil, err
	}
	if err := validateVMFirewallAnchorVMUUID(vmUUID); err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        vmFirewallAnchorName(vmUUID),
			Labels:      c.vmFirewallAnchorLabels(),
			Annotations: map[string]string{annotationVMFirewallVM: vmUUID},
			Finalizers:  []string{vmFirewallAnchorFinalizer},
		},
	}
	created, err := c.provider.kubeClient.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := c.getVMFirewallAnchor(ctx, vmUUID)
		if getErr != nil {
			return nil, getErr
		}
		if existing == nil {
			return nil, fmt.Errorf("public-node-local: VM firewall anchor of %s vanished while it was being created", vmUUID)
		}
		return existing, nil
	}
	if err != nil {
		return nil, fmt.Errorf("public-node-local: create VM firewall anchor of %s: %w", vmUUID, err)
	}
	if err := c.validateVMFirewallAnchor(namespace, vmUUID, created); err != nil {
		return nil, err
	}
	return created, nil
}

// updateVMFirewallAnchor applies mutate to the annotations of the anchor under
// compare-and-swap on its resourceVersion and exact UID. On a conflict it
// re-reads the anchor and runs mutate once more on the fresh object. The write
// is read back and must match byte for byte. The bool reports a write.
func (c *nodeLoadBalancerController) updateVMFirewallAnchor(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	mutate func(*corev1.ConfigMap) (bool, error),
) (*corev1.ConfigMap, bool, error) {
	namespace, err := c.vmFirewallNamespace()
	if err != nil {
		return nil, false, err
	}
	if anchor == nil {
		return nil, false, errors.New("public-node-local: VM firewall anchor is required")
	}
	cms := c.provider.kubeClient.CoreV1().ConfigMaps(namespace)
	current := anchor
	for attempt := 0; ; attempt++ {
		next := current.DeepCopy()
		if next.Annotations == nil {
			next.Annotations = map[string]string{}
		}
		changed, err := mutate(next)
		if err != nil {
			return nil, false, err
		}
		if !changed {
			return current, false, nil
		}
		updated, err := cms.Update(ctx, next, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) && attempt == 0 {
			fresh, getErr := cms.Get(ctx, anchor.Name, metav1.GetOptions{})
			if getErr != nil {
				return nil, false, fmt.Errorf("public-node-local: re-read VM firewall anchor %s after a conflict: %w", anchor.Name, getErr)
			}
			if fresh.UID != anchor.UID {
				return nil, false, fmt.Errorf("public-node-local: VM firewall anchor %s identity changed", anchor.Name)
			}
			current = fresh
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("public-node-local: update VM firewall anchor %s: %w", anchor.Name, err)
		}
		verified, err := cms.Get(ctx, anchor.Name, metav1.GetOptions{})
		if err != nil {
			return nil, false, fmt.Errorf("public-node-local: read back VM firewall anchor %s: %w", anchor.Name, err)
		}
		if verified.UID != anchor.UID || updated.UID != anchor.UID {
			return nil, false, fmt.Errorf("public-node-local: VM firewall anchor %s identity changed during the update", anchor.Name)
		}
		if verified.ResourceVersion != updated.ResourceVersion || !mapsEqualStringString(verified.Annotations, next.Annotations) {
			return nil, false, fmt.Errorf("public-node-local: VM firewall anchor %s failed exact readback", anchor.Name)
		}
		return verified, true, nil
	}
}

// vmFirewallAnchorView reads the typed state of an anchor.
type vmFirewallAnchorView struct{ cm *corev1.ConfigMap }

func (a vmFirewallAnchorView) get(key string) string { return a.cm.Annotations[key] }

func (a vmFirewallAnchorView) vm() string          { return a.get(annotationVMFirewallVM) }
func (a vmFirewallAnchorView) uuid() string        { return a.get(annotationVMFirewallUUID) }
func (a vmFirewallAnchorView) appliedHash() string { return a.get(annotationVMFirewallAppliedHash) }
func (a vmFirewallAnchorView) pendingOp() string   { return a.get(annotationVMFirewallPendingOp) }

func (a vmFirewallAnchorView) ledger(key string) (vmFirewallLedger, error) {
	raw := a.get(key)
	if raw == "" {
		return vmFirewallLedger{V: vmFirewallLedgerVersion, Members: []vmFirewallMember{}}, nil
	}
	return decodeVMFirewallLedger(raw)
}

// applied is the ledger the firewall was last read back with.
func (a vmFirewallAnchorView) applied() (vmFirewallLedger, error) {
	return a.ledger(annotationVMFirewallApplied)
}

// pending is the staged next ledger of an unresolved mutation.
func (a vmFirewallAnchorView) pending() (vmFirewallLedger, error) {
	return a.ledger(annotationVMFirewallPending)
}

func (a vmFirewallAnchorView) appliedAt() (time.Time, bool, error) {
	raw := a.get(annotationVMFirewallAppliedAt)
	if raw == "" {
		return time.Time{}, false, nil
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, corruptVMFirewallLedger("anchor %s applied-at %q: %v", a.cm.Name, raw, err)
	}
	return at, true, nil
}

// hasReceipt reports an unresolved PUT, create or delete.
func (a vmFirewallAnchorView) hasReceipt() bool {
	return a.get(annotationVMFirewallPending) != "" || a.get(annotationVMFirewallPendingOp) != "" ||
		a.get(annotationVMFirewallIssuedAt) != "" || a.get(annotationVMFirewallDeleteTarget) != ""
}

const (
	vmFirewallDriftReason        = "PublicNodeLocalVMFirewallDrift"
	vmFirewallPortConflictReason = "PublicNodeLocalVMPortConflict"

	// vmFirewallNewFirewall stands in for the UUID of a firewall that does not
	// exist yet when the attach capacity of a VM is checked before a create.
	vmFirewallNewFirewall = "(new per-VM firewall)"

	// vmFirewallCreateAbsenceReads is how many spaced absent reads retire an
	// ambiguous create after the retire delay.
	vmFirewallCreateAbsenceReads = 2
)

// errVMFirewallDrift reports a per-VM firewall whose cloud state is not what
// its anchor recorded. Every Service on the VM holds; nothing is mutated and
// nothing is removed.
var errVMFirewallDrift = errors.New("public-node-local: VM firewall drifted from its recorded ledger")

func vmFirewallDrift(vmUUID, format string, args ...any) error {
	return fmt.Errorf("%w: VM %s: %s", errVMFirewallDrift, vmUUID, fmt.Sprintf(format, args...))
}

type vmFirewallOp string

const (
	vmFirewallOpCreate vmFirewallOp = "create"
	vmFirewallOpUpdate vmFirewallOp = "update"
	vmFirewallOpDelete vmFirewallOp = "delete"
	vmFirewallOpAdopt  vmFirewallOp = "adopt"
)

// vmFirewallDelta is the one ledger change a transaction makes: add or remove
// exactly one entry. LedgerOnly applies to a removal on a VM that is proven
// gone: nothing can reach it, so no PUT is made.
type vmFirewallDelta struct {
	Add        *vmFirewallMember
	Remove     *vmFirewallMemberKey
	LedgerOnly bool
}

func (d vmFirewallDelta) validate() error {
	if (d.Add == nil) == (d.Remove == nil) {
		return errors.New("public-node-local: a VM firewall delta adds or removes exactly one entry")
	}
	if d.LedgerOnly && d.Remove == nil {
		return errors.New("public-node-local: a ledger-only VM firewall delta must be a removal")
	}
	if d.Add != nil {
		return validateVMFirewallMember(*d.Add)
	}
	return nil
}

// vmFirewallDeltaAuthority is the last check before a mutation crosses the
// provider boundary: it re-derives, from live state, that the Service still
// wants (add) or has verifiably given up (remove) this entry. fresh is the
// per-VM firewall just re-read, nil for a create.
type vmFirewallDeltaAuthority func(ctx context.Context, anchor *corev1.ConfigMap, fresh *inspace.Firewall) error

type vmFirewallStepResult struct {
	// Converged is true when the delta is applied, read back and, for an add,
	// the firewall is attached to the VM.
	Converged    bool
	AppliedAt    time.Time
	FirewallUUID string
}

func vmFirewallWait(retry time.Duration, format string, args ...any) error {
	if retry < time.Second {
		retry = time.Second
	}
	return &nodeLoadBalancerFirewallRelationPendingError{message: fmt.Sprintf(format, args...), retryAfter: retry}
}

func (c *nodeLoadBalancerController) vmFirewallMemberServices(ctx context.Context, members func(context.Context) []*corev1.Service) []*corev1.Service {
	if members == nil {
		return nil
	}
	return members(ctx)
}

func (c *nodeLoadBalancerController) recordVMFirewallEvent(ctx context.Context, services []*corev1.Service, reason string, cause error) {
	for _, service := range services {
		if service == nil {
			continue
		}
		if err := c.recordPublicNodeLocalHoldEvent(ctx, service, reason, cause); err != nil {
			klog.Warningf("node load balancer: record %s Event on %s/%s: %v", reason, service.Namespace, service.Name, err)
		}
	}
}

func (c *nodeLoadBalancerController) refuseVMFirewallCreate(ctx context.Context, vmUUID string, services []*corev1.Service, cause error) {
	for _, service := range services {
		if service != nil {
			c.recordFirewallLimitExceeded(ctx, service, "VM firewall anchor "+vmUUID, cause)
		}
	}
}

// vmFirewallByNameFromItems returns the one firewall with the given name, nil
// when there is none, and an error when case-folded rows make the name
// ambiguous.
func vmFirewallByNameFromItems(items []inspace.Firewall, name string) (*inspace.Firewall, error) {
	var exact *inspace.Firewall
	matches := 0
	for index := range items {
		if !strings.EqualFold(items[index].EffectiveName(), name) {
			continue
		}
		matches++
		if items[index].EffectiveName() == name {
			copy := items[index]
			exact = &copy
		}
	}
	if matches == 0 {
		return nil, nil
	}
	if matches != 1 || exact == nil {
		return nil, fmt.Errorf("public-node-local: firewall name %q has %d case-folded rows and no unique exact owner", name, matches)
	}
	return exact, nil
}

func vmFirewallAttachedTo(firewall inspace.Firewall, vmUUID string) bool {
	for _, row := range firewall.ResourcesAssigned {
		if strings.EqualFold(row.ResourceType, "vm") && strings.EqualFold(row.ResourceUUID, vmUUID) {
			return true
		}
	}
	return false
}

// vmFirewallMergedNarrows reports whether after closes anything before opened:
// a port that is gone, or a source range that no longer covers the old one.
// An add must never narrow. A removal narrows only what no entry needs any
// more, which mergeVMFirewallLedger guarantees by construction.
func vmFirewallMergedNarrows(before, after []inspace.FirewallRule) bool {
	type view struct {
		any     bool
		sources map[string]struct{}
	}
	index := func(rules []inspace.FirewallRule) map[string]view {
		out := map[string]view{}
		for _, rule := range rules {
			v := view{sources: map[string]struct{}{}}
			if rule.EndpointSpecType == "any" {
				v.any = true
			}
			for _, source := range rule.EndpointSpec {
				v.sources[source] = struct{}{}
			}
			out[nodeLoadBalancerShardFirewallRuleLogicalKey(rule)] = v
		}
		return out
	}
	was, now := index(before), index(after)
	for key, old := range was {
		current, kept := now[key]
		if !kept {
			return true
		}
		if current.any {
			continue
		}
		if old.any {
			return true
		}
		for source := range old.sources {
			if _, covered := current.sources[source]; !covered {
				return true
			}
		}
	}
	return false
}

type vmFirewallObservation struct {
	firewall *inspace.Firewall
	attached bool
}

// observeVMFirewall validates the applied state of a VM: the firewall the
// anchor names must be present by UUID and by name as one resource, owned,
// attached to this VM only and carry exactly the applied rules. Anything else
// is drift.
func (c *nodeLoadBalancerController) observeVMFirewall(
	vmUUID string,
	view vmFirewallAnchorView,
	applied vmFirewallLedger,
	items []inspace.Firewall,
) (vmFirewallObservation, error) {
	cluster := c.provider.config.ClusterID
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return vmFirewallObservation{}, err
	}
	byName, err := vmFirewallByNameFromItems(items, name)
	if err != nil {
		return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "%v", err)
	}
	uuid := view.uuid()
	if uuid == "" {
		if len(applied.Members) != 0 {
			return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "the anchor records an applied ledger but no firewall UUID")
		}
		if byName != nil {
			return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "firewall %s carries the per-VM name but the anchor does not own it", byName.UUID)
		}
		return vmFirewallObservation{}, nil
	}
	exact, err := exactNodeLoadBalancerFirewallFromItems(items, uuid)
	if err != nil {
		return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "recorded firewall %s is not readable: %v", uuid, err)
	}
	if byName == nil || byName.UUID != exact.UUID {
		return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "recorded firewall %s is not the one carrying the per-VM name", uuid)
	}
	if err := inspace.ValidateNodeLoadBalancerVMFirewall(*exact, cluster, vmUUID, c.provider.config.BillingAccountID, view.appliedHash()); err != nil {
		return vmFirewallObservation{}, vmFirewallDrift(vmUUID, "firewall %s: %v", uuid, err)
	}
	return vmFirewallObservation{firewall: exact, attached: vmFirewallAttachedTo(*exact, vmUUID)}, nil
}

// vmFirewallStep makes exactly one ledger change on one VM and carries it to the
// cloud: create, PUT or (in a later task) delete, then the attach. Every call
// advances at most one durable step and returns; callers repeat it until
// Converged. The rules of members outside the delta always come from the
// anchor ledger, never from live Service specs, so a broken sibling keeps its
// recorded rules. Removal needs the verified intent that authorize re-derives.
func (c *nodeLoadBalancerController) vmFirewallStep(
	ctx context.Context,
	vmUUID string,
	delta vmFirewallDelta,
	authorize vmFirewallDeltaAuthority,
	members func(context.Context) []*corev1.Service,
) (vmFirewallStepResult, error) {
	if err := delta.validate(); err != nil {
		return vmFirewallStepResult{}, err
	}
	if authorize == nil {
		return vmFirewallStepResult{}, errors.New("public-node-local: a VM firewall step needs its authority check")
	}
	cluster := c.provider.config.ClusterID
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return vmFirewallStepResult{}, err
	}
	anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
	if err != nil {
		return vmFirewallStepResult{}, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return vmFirewallStepResult{}, fmt.Errorf("public-node-local: list firewalls for VM %s: %w", vmUUID, err)
	}
	if anchor == nil {
		if delta.Remove != nil {
			// Nothing was ever recorded for this VM.
			return vmFirewallStepResult{Converged: true}, nil
		}
		existing, nameErr := vmFirewallByNameFromItems(items, name)
		if nameErr != nil {
			return vmFirewallStepResult{}, vmFirewallDrift(vmUUID, "%v", nameErr)
		}
		if existing != nil {
			return vmFirewallStepResult{}, vmFirewallDrift(vmUUID, "firewall %s carries the per-VM name but no anchor records it", existing.UUID)
		}
		// Refuse before anything is persisted: a VM at the firewall limit gets no
		// anchor and no receipt.
		if capacityErr := c.firewallVMCapacityFromItems(items, vmFirewallNewFirewall, vmUUID); capacityErr != nil {
			c.refuseVMFirewallCreate(ctx, vmUUID, c.vmFirewallMemberServices(ctx, members), capacityErr)
			return vmFirewallStepResult{}, capacityErr
		}
		if anchor, err = c.createVMFirewallAnchor(ctx, vmUUID); err != nil {
			return vmFirewallStepResult{}, err
		}
	}
	view := vmFirewallAnchorView{cm: anchor}
	if view.hasReceipt() {
		_, err := c.resolveVMFirewallReceipt(ctx, anchor, items, members)
		return vmFirewallStepResult{}, err
	}
	if anchor.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		// An attach or detach is still unresolved: settle it before anything else.
		_, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.vmFirewallRelationOwner(vmUUID, members), nil)
		return vmFirewallStepResult{}, err
	}
	applied, err := view.applied()
	if err != nil {
		return vmFirewallStepResult{}, err
	}
	observation, err := c.observeVMFirewall(vmUUID, view, applied, items)
	if err != nil {
		if errors.Is(err, errVMFirewallDrift) {
			c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), vmFirewallDriftReason, err)
		}
		return vmFirewallStepResult{}, err
	}

	var next vmFirewallLedger
	unchanged := false
	switch {
	case delta.Add != nil:
		if _, present := applied.find(delta.Add.key()); present {
			next, unchanged = applied, true
		} else if next, err = applied.with(*delta.Add); err != nil {
			return vmFirewallStepResult{}, err
		}
	default:
		var found bool
		next, found = applied.without(*delta.Remove)
		unchanged = !found
	}

	if unchanged {
		if delta.Remove != nil {
			return vmFirewallStepResult{Converged: true, FirewallUUID: view.uuid()}, nil
		}
		if !observation.attached {
			fence := nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: view.uuid(), vmUUID: vmUUID,
			}
			_, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.vmFirewallRelationOwner(vmUUID, members), &fence)
			return vmFirewallStepResult{FirewallUUID: view.uuid()}, err
		}
		appliedAt, _, err := view.appliedAt()
		if err != nil {
			return vmFirewallStepResult{}, err
		}
		return vmFirewallStepResult{Converged: true, AppliedAt: appliedAt, FirewallUUID: view.uuid()}, nil
	}

	if delta.LedgerOnly {
		err := c.removeVMFirewallEntryLedgerOnly(ctx, vmUUID, anchor, observation, next, authorize)
		return vmFirewallStepResult{FirewallUUID: view.uuid()}, err
	}
	if len(next.Members) == 0 {
		// An empty PUT is rejected, and the last member's closure is the detach
		// itself: stage the delete and let the receipt carry it.
		err := c.stageVMFirewallDelete(ctx, anchor, observation, authorize)
		return vmFirewallStepResult{FirewallUUID: view.uuid()}, err
	}
	merged, err := mergeVMFirewallLedger(next)
	if err != nil {
		var conflict *errVMFirewallPortConflict
		if errors.As(err, &conflict) && delta.Add != nil {
			var asking []*corev1.Service
			for _, service := range c.vmFirewallMemberServices(ctx, members) {
				if service != nil && string(service.UID) == delta.Add.UID {
					asking = append(asking, service)
				}
			}
			c.recordVMFirewallEvent(ctx, asking, vmFirewallPortConflictReason, err)
		}
		return vmFirewallStepResult{}, err
	}
	if delta.Add != nil && len(applied.Members) != 0 {
		before, mergeErr := mergeVMFirewallLedger(applied)
		if mergeErr != nil {
			return vmFirewallStepResult{}, mergeErr
		}
		if vmFirewallMergedNarrows(before, merged) {
			return vmFirewallStepResult{}, errors.New("public-node-local: an add must never narrow the VM firewall; make-before-break")
		}
	}
	op := vmFirewallOpUpdate
	if observation.firewall == nil {
		op = vmFirewallOpCreate
	}
	if err := c.runVMFirewallMutation(ctx, vmUUID, anchor, observation, op, next, merged, authorize, members); err != nil {
		return vmFirewallStepResult{}, err
	}
	return vmFirewallStepResult{FirewallUUID: view.uuid()}, nil
}

var vmFirewallReceiptKeys = []string{
	annotationVMFirewallPending,
	annotationVMFirewallPendingHash,
	annotationVMFirewallPendingOp,
	annotationVMFirewallPendingAt,
	annotationVMFirewallIssuedAt,
	annotationVMFirewallIssueID,
}

func vmFirewallSameReceipt(a, b map[string]string) bool {
	for _, key := range vmFirewallReceiptKeys {
		if a[key] != b[key] {
			return false
		}
	}
	return true
}

// stageVMFirewallMutation records the next ledger as pending. It fails if the
// applied ledger moved or any receipt appeared since the caller read the anchor.
func (c *nodeLoadBalancerController) stageVMFirewallMutation(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	op vmFirewallOp,
	appliedRaw, pendingRaw, pendingHash string,
) (*corev1.ConfigMap, error) {
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	updated, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		view := vmFirewallAnchorView{cm: cm}
		if view.hasReceipt() || view.get(annotationVMFirewallApplied) != appliedRaw {
			return false, errors.New("public-node-local: the VM firewall anchor changed before the mutation was staged")
		}
		cm.Annotations[annotationVMFirewallPending] = pendingRaw
		cm.Annotations[annotationVMFirewallPendingHash] = pendingHash
		cm.Annotations[annotationVMFirewallPendingOp] = string(op)
		cm.Annotations[annotationVMFirewallPendingAt] = now
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("public-node-local: the VM firewall mutation was not staged")
	}
	return updated, nil
}

// issueVMFirewallMutation records the issued receipt in its own write, before
// the HTTP call, so a crash in between can never be mistaken for a dispatched
// request that committed.
func (c *nodeLoadBalancerController) issueVMFirewallMutation(ctx context.Context, staged *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	token, err := newNodeLoadBalancerFirewallCreateIssuedToken()
	if err != nil {
		return nil, err
	}
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	updated, changed, err := c.updateVMFirewallAnchor(ctx, staged, func(cm *corev1.ConfigMap) (bool, error) {
		if cm.Annotations[annotationVMFirewallPending] != staged.Annotations[annotationVMFirewallPending] ||
			cm.Annotations[annotationVMFirewallPendingAt] != staged.Annotations[annotationVMFirewallPendingAt] ||
			cm.Annotations[annotationVMFirewallIssuedAt] != "" {
			return false, errors.New("public-node-local: the staged VM firewall mutation changed before it was issued")
		}
		cm.Annotations[annotationVMFirewallIssuedAt] = now
		cm.Annotations[annotationVMFirewallIssueID] = token
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("public-node-local: the VM firewall mutation was not issued")
	}
	return updated, nil
}

// resetVMFirewallReceipt clears a receipt whose request provably never left
// this process. It uses a detached context: a canceled caller must not strand
// an issued receipt that no request backs.
func (c *nodeLoadBalancerController) resetVMFirewallReceipt(ctx context.Context, anchor *corev1.ConfigMap) error {
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	expected := anchor.Annotations
	_, _, err := c.updateVMFirewallAnchor(resetCtx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if !vmFirewallSameReceipt(cm.Annotations, expected) {
			return false, errors.New("public-node-local: the VM firewall receipt changed before it was reset")
		}
		for _, key := range vmFirewallReceiptKeys {
			delete(cm.Annotations, key)
		}
		delete(cm.Annotations, annotationVMFirewallAbsenceCount)
		delete(cm.Annotations, annotationVMFirewallAbsenceCheckedAt)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("public-node-local: reset the VM firewall receipt: %w", err)
	}
	return nil
}

// commitVMFirewallMutation turns the pending ledger into the applied one after
// an exact readback, and clears the receipt, in one write.
func (c *nodeLoadBalancerController) commitVMFirewallMutation(ctx context.Context, anchor *corev1.ConfigMap, firewall inspace.Firewall) error {
	expected := anchor.Annotations
	now := c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
	_, changed, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if !vmFirewallSameReceipt(cm.Annotations, expected) || cm.Annotations[annotationVMFirewallPending] == "" {
			return false, errors.New("public-node-local: the VM firewall receipt changed before its commit")
		}
		if cm.Annotations[annotationVMFirewallPending] == cm.Annotations[annotationVMFirewallApplied] {
			// A PUT that restores the applied ledger is a repair: single use.
			delete(cm.Annotations, annotationVMFirewallRepair)
		}
		cm.Annotations[annotationVMFirewallApplied] = cm.Annotations[annotationVMFirewallPending]
		cm.Annotations[annotationVMFirewallAppliedHash] = cm.Annotations[annotationVMFirewallPendingHash]
		cm.Annotations[annotationVMFirewallAppliedAt] = now
		cm.Annotations[annotationVMFirewallUUID] = firewall.UUID
		for _, key := range vmFirewallReceiptKeys {
			delete(cm.Annotations, key)
		}
		delete(cm.Annotations, annotationVMFirewallAbsenceCount)
		delete(cm.Annotations, annotationVMFirewallAbsenceCheckedAt)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("public-node-local: commit the VM firewall mutation: %w", err)
	}
	if !changed {
		return errors.New("public-node-local: the VM firewall mutation was not committed")
	}
	return nil
}

// authorizeVMFirewallMutation is the pre-dispatch authority of one create or
// PUT: the receipt is still exactly the one this process issued, the firewall is
// unchanged since it was read, and the delta's own authority holds.
func (c *nodeLoadBalancerController) authorizeVMFirewallMutation(
	ctx context.Context,
	vmUUID string,
	issued *corev1.ConfigMap,
	op vmFirewallOp,
	observation vmFirewallObservation,
	authorize vmFirewallDeltaAuthority,
) error {
	sameReceipt := func() (*corev1.ConfigMap, error) {
		current, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return nil, err
		}
		if current == nil || current.UID != issued.UID || !vmFirewallSameReceipt(current.Annotations, issued.Annotations) {
			return nil, errors.New("public-node-local: the VM firewall receipt changed during final authority")
		}
		return current, nil
	}
	if _, err := sameReceipt(); err != nil {
		return err
	}
	var fresh *inspace.Firewall
	switch op {
	case vmFirewallOpUpdate:
		current, err := c.exactNodeLoadBalancerFirewallFresh(ctx, observation.firewall.UUID)
		if err != nil {
			return err
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(*observation.firewall, *current) {
			return fmt.Errorf("public-node-local: VM firewall %s changed after the mutation was issued", current.UUID)
		}
		fresh = current
	case vmFirewallOpCreate:
		name, err := inspace.NodeLoadBalancerVMFirewallName(c.provider.config.ClusterID, vmUUID)
		if err != nil {
			return err
		}
		existing, absent, err := c.exactNodeLoadBalancerFirewallNameFresh(ctx, name)
		if err != nil {
			return err
		}
		if !absent || existing != nil {
			return fmt.Errorf("public-node-local: firewall %s already carries the per-VM name", name)
		}
		if err := c.requireFirewallVMCapacity(ctx, vmFirewallNewFirewall, vmUUID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("public-node-local: unsupported VM firewall operation %q", op)
	}
	anchor, err := sameReceipt()
	if err != nil {
		return err
	}
	if err := authorize(ctx, anchor, fresh); err != nil {
		return err
	}
	_, err = sameReceipt()
	return err
}

func (c *nodeLoadBalancerController) runVMFirewallMutation(
	ctx context.Context,
	vmUUID string,
	anchor *corev1.ConfigMap,
	observation vmFirewallObservation,
	op vmFirewallOp,
	next vmFirewallLedger,
	merged []inspace.FirewallRule,
	authorize vmFirewallDeltaAuthority,
	members func(context.Context) []*corev1.Service,
) error {
	cluster := c.provider.config.ClusterID
	nextRaw, err := encodeVMFirewallLedger(next)
	if err != nil {
		return err
	}
	hash, err := inspace.NodeLoadBalancerVMFirewallSpecHash(merged)
	if err != nil {
		return err
	}
	var (
		createRequest inspace.CreateFirewallRequest
		updateRequest inspace.UpdateFirewallRequest
	)
	switch op {
	case vmFirewallOpCreate:
		createRequest, err = vmFirewallCreateRequest(cluster, vmUUID, c.provider.config.BillingAccountID, merged)
	case vmFirewallOpUpdate:
		updateRequest, err = vmFirewallUpdateRequest(cluster, vmUUID, *observation.firewall, merged)
	default:
		err = fmt.Errorf("public-node-local: unsupported VM firewall operation %q", op)
	}
	if err != nil {
		return err
	}
	appliedRaw := anchor.Annotations[annotationVMFirewallApplied]
	staged, err := c.stageVMFirewallMutation(ctx, anchor, op, appliedRaw, nextRaw, hash)
	if err != nil {
		return err
	}
	issued, err := c.issueVMFirewallMutation(ctx, staged)
	if err != nil {
		return err
	}
	if err := c.authorizeVMFirewallMutation(ctx, vmUUID, issued, op, observation, authorize); err != nil {
		var limit *FirewallLimitExceededError
		if errors.As(err, &limit) {
			c.refuseVMFirewallCreate(ctx, vmUUID, c.vmFirewallMemberServices(ctx, members), err)
		}
		rejection := fmt.Errorf("public-node-local: reject VM firewall %s for %s at final pre-dispatch authority: %w", op, vmUUID, err)
		if resetErr := c.resetVMFirewallReceipt(ctx, issued); resetErr != nil {
			return errors.Join(rejection, resetErr)
		}
		return rejection
	}

	timeout := vmFirewallMutationTimeout(len(merged))
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	klog.Infof("node load balancer: VM firewall %s for %s with %d rules", op, vmUUID, len(merged))
	var dispatchErr error
	switch op {
	case vmFirewallOpCreate:
		_, dispatchErr = c.provider.api.CreateFirewall(callCtx, c.provider.config.Location, createRequest)
	case vmFirewallOpUpdate:
		_, dispatchErr = c.provider.api.UpdateFirewall(callCtx, c.provider.config.Location, observation.firewall.UUID, updateRequest)
	}
	if dispatchErr != nil {
		dispatchErr = fmt.Errorf("public-node-local: %s VM firewall for %s: %w", op, vmUUID, dispatchErr)
		if nodeLoadBalancerMutationKnownPreDispatch(dispatchErr) {
			return errors.Join(dispatchErr, c.resetVMFirewallReceipt(ctx, issued))
		}
	}
	items, listErr := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if listErr != nil {
		return errors.Join(dispatchErr, fmt.Errorf("public-node-local: read back the VM firewall of %s: %w", vmUUID, listErr))
	}
	current, getErr := c.getVMFirewallAnchor(ctx, vmUUID)
	if getErr != nil || current == nil {
		return errors.Join(dispatchErr, getErr, errors.New("public-node-local: the VM firewall anchor disappeared during a mutation"))
	}
	if _, resolveErr := c.resolveVMFirewallReceipt(ctx, current, items, members); resolveErr != nil {
		return errors.Join(dispatchErr, resolveErr)
	}
	return nil
}

// resolveVMFirewallReceipt settles an issued or staged create or PUT from a
// fresh listing. It reports true once the receipt is gone: committed or reset.
func (c *nodeLoadBalancerController) resolveVMFirewallReceipt(
	ctx context.Context,
	anchor *corev1.ConfigMap,
	items []inspace.Firewall,
	members func(context.Context) []*corev1.Service,
) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	vmUUID := view.vm()
	op := vmFirewallOp(view.pendingOp())
	switch op {
	case vmFirewallOpCreate, vmFirewallOpUpdate:
	case vmFirewallOpDelete:
		return c.deleteVMFirewall(ctx, anchor)
	default:
		return false, fmt.Errorf("public-node-local: VM firewall receipt operation %q cannot be resolved here", op)
	}
	if view.get(annotationVMFirewallIssuedAt) == "" {
		// Staged but never issued: no request was ever authorized.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, view.get(annotationVMFirewallIssuedAt))
	if err != nil {
		return false, corruptVMFirewallLedger("anchor %s issued-at %q: %v", anchor.Name, view.get(annotationVMFirewallIssuedAt), err)
	}
	now := c.nodeLoadBalancerFirewallRelationTime()
	retireAt := issuedAt.Add(nodeLoadBalancerFirewallRelationRetireDelay)
	untilRetire := retireAt.Sub(now)
	if untilRetire > nodeLoadBalancerRetry {
		untilRetire = nodeLoadBalancerRetry
	}
	cluster := c.provider.config.ClusterID
	name, err := inspace.NodeLoadBalancerVMFirewallName(cluster, vmUUID)
	if err != nil {
		return false, err
	}
	drift := func(format string, args ...any) (bool, error) {
		err := vmFirewallDrift(vmUUID, format, args...)
		c.recordVMFirewallEvent(ctx, c.vmFirewallMemberServices(ctx, members), vmFirewallDriftReason, err)
		return false, err
	}
	byName, err := vmFirewallByNameFromItems(items, name)
	if err != nil {
		return drift("%v", err)
	}
	pendingHash := view.get(annotationVMFirewallPendingHash)

	if op == vmFirewallOpCreate {
		if byName != nil {
			// A create that landed late, or one the readback simply saw: adopt it
			// by its deterministic name when it carries exactly the pending rules.
			hash, hashErr := inspace.NodeLoadBalancerVMFirewallSpecHash(byName.Rules)
			if hashErr != nil || hash != pendingHash {
				return drift("firewall %s carries the per-VM name with rules other than the pending create", byName.UUID)
			}
			if err := inspace.ValidateNodeLoadBalancerVMFirewall(*byName, cluster, vmUUID, c.provider.config.BillingAccountID, pendingHash); err != nil {
				return drift("firewall %s: %v", byName.UUID, err)
			}
			return true, c.commitVMFirewallMutation(ctx, anchor, *byName)
		}
		if now.Before(retireAt) {
			return false, vmFirewallWait(untilRetire, "public-node-local: VM firewall create for %s is ambiguous; waiting for readback", vmUUID)
		}
		return c.retireAbsentVMFirewallCreate(ctx, anchor, now)
	}

	firewall, err := exactNodeLoadBalancerFirewallFromItems(items, view.uuid())
	if err != nil {
		return drift("recorded firewall %s is not readable during a PUT: %v", view.uuid(), err)
	}
	if byName == nil || byName.UUID != firewall.UUID {
		return drift("recorded firewall %s is not the one carrying the per-VM name", view.uuid())
	}
	hash, hashErr := inspace.NodeLoadBalancerVMFirewallSpecHash(firewall.Rules)
	if hashErr != nil {
		return drift("firewall %s: %v", firewall.UUID, hashErr)
	}
	if hash == pendingHash {
		return true, c.commitVMFirewallMutation(ctx, anchor, *firewall)
	}
	if hash == view.appliedHash() {
		if now.Before(retireAt) {
			return false, vmFirewallWait(untilRetire, "public-node-local: VM firewall update for %s is ambiguous; waiting for readback", vmUUID)
		}
		// The request can no longer be in flight and a fresh read still shows the
		// applied rules, so it did not commit. Clear this one receipt, once; the
		// next pass re-derives the change and issues it again with full authority.
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	}
	if pendingHash == view.appliedHash() {
		// A repair PUT restores the applied rules over a drifted firewall, so a
		// third state is exactly what an unchanged readback looks like for it.
		if now.Before(retireAt) {
			return false, vmFirewallWait(untilRetire, "public-node-local: VM firewall repair for %s is ambiguous; waiting for readback", vmUUID)
		}
		return true, c.resetVMFirewallReceipt(ctx, anchor)
	}
	return drift("firewall %s has rules that are neither the applied nor the pending ledger", firewall.UUID)
}

// retireAbsentVMFirewallCreate counts the spaced absent reads that, after the
// retire delay, prove an ambiguous create did not commit. Two reads at least
// one confirmation delay apart retire the receipt.
func (c *nodeLoadBalancerController) retireAbsentVMFirewallCreate(ctx context.Context, anchor *corev1.ConfigMap, now time.Time) (bool, error) {
	view := vmFirewallAnchorView{cm: anchor}
	delay := c.nodeLoadBalancerFirewallRelationAbsenceDelay()
	count := 0
	if raw := view.get(annotationVMFirewallAbsenceCount); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > nodeLoadBalancerAbsenceConfirmations {
			return false, corruptVMFirewallLedger("anchor %s absence count %q", anchor.Name, raw)
		}
		count = parsed
	}
	if count > 0 {
		checked, err := time.Parse(time.RFC3339Nano, view.get(annotationVMFirewallAbsenceCheckedAt))
		if err != nil {
			return false, corruptVMFirewallLedger("anchor %s absence-checked-at %q", anchor.Name, view.get(annotationVMFirewallAbsenceCheckedAt))
		}
		if now.Before(checked.Add(delay)) {
			return false, vmFirewallWait(checked.Add(delay).Sub(now), "public-node-local: VM firewall create for %s: waiting for the second spaced absent read", view.vm())
		}
		if count+1 >= vmFirewallCreateAbsenceReads {
			return true, c.resetVMFirewallReceipt(ctx, anchor)
		}
	}
	expected := anchor.Annotations
	_, _, err := c.updateVMFirewallAnchor(ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		if !vmFirewallSameReceipt(cm.Annotations, expected) {
			return false, errors.New("public-node-local: the VM firewall receipt changed before its absence was recorded")
		}
		cm.Annotations[annotationVMFirewallAbsenceCount] = strconv.Itoa(count + 1)
		cm.Annotations[annotationVMFirewallAbsenceCheckedAt] = now.Format(time.RFC3339Nano)
		return true, nil
	})
	if err != nil {
		return false, err
	}
	return false, vmFirewallWait(delay, "public-node-local: VM firewall create for %s: first absent read recorded", view.vm())
}

// errVMFirewallReceiptPending reports a VM whose anchor holds an unresolved
// receipt that concerns the asking Service. The VM is ambiguous for every
// member: callers resolve the receipt and requeue, and never plan on top of it.
var errVMFirewallReceiptPending = errors.New("public-node-local: a VM firewall receipt is unresolved")

// vmEdgeAssigned returns the VMs on which Service serviceUID is open under
// policy. A VM is in the set only when every one of these holds in one fresh
// read: the anchor applied ledger has the entry, the anchor has no receipt,
// the firewall its uuid names is in items, attached to this VM and only this
// VM, owned (name, billing, description), with exactly the applied rules.
// Anything else leaves the VM out; an open receipt that concerns the Service
// is also reported through errVMFirewallReceiptPending.
func (c *nodeLoadBalancerController) vmEdgeAssigned(
	serviceUID, policy string,
	items []inspace.Firewall,
	anchors []corev1.ConfigMap,
) (map[string]struct{}, error) {
	assigned := map[string]struct{}{}
	pendingVMs := []string{}
	key := vmFirewallMemberKey{UID: serviceUID, Policy: policy}
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		vmUUID := view.vm()
		applied, err := view.applied()
		if err != nil {
			continue // a corrupt anchor holds its VM: the Service is not open there
		}
		_, inApplied := applied.find(key)
		if view.hasReceipt() {
			concerns := inApplied
			if pending, pendingErr := view.pending(); pendingErr == nil {
				_, inPending := pending.find(key)
				concerns = concerns || inPending
			} else {
				concerns = true
			}
			if concerns {
				pendingVMs = append(pendingVMs, vmUUID)
			}
			continue
		}
		if !inApplied || !validNodeLoadBalancerCloudUUID(view.uuid()) {
			continue
		}
		firewall, err := exactNodeLoadBalancerFirewallFromItems(items, view.uuid())
		if err != nil || !vmFirewallAttachedTo(*firewall, vmUUID) {
			continue
		}
		if err := inspace.ValidateNodeLoadBalancerVMFirewall(
			*firewall, c.provider.config.ClusterID, vmUUID, c.provider.config.BillingAccountID, view.appliedHash(),
		); err != nil {
			continue
		}
		assigned[vmUUID] = struct{}{}
	}
	if len(pendingVMs) != 0 {
		sort.Strings(pendingVMs)
		return assigned, fmt.Errorf("%w on VM(s) %s", errVMFirewallReceiptPending, strings.Join(pendingVMs, ", "))
	}
	return assigned, nil
}

// errPublicNodeLocalVMFirewallSettling reports a Service step that must wait
// for the per-VM firewall change to take effect everywhere before it relies on
// the new edge. It is a bounded wait with a fixed requeue, not a fault.
type errPublicNodeLocalVMFirewallSettling struct {
	vmUUID     string
	retryAfter time.Duration
}

func (e *errPublicNodeLocalVMFirewallSettling) Error() string {
	return fmt.Sprintf("public-node-local: the VM firewall of %s was applied just now; waiting %s for it to take effect", e.vmUUID, e.retryAfter)
}

// vmFirewallSettle is how long a change must have been read back before a
// Service relies on it: the configured value, else the measured default.
func (p *Provider) vmFirewallSettle() time.Duration {
	if settle := p.config.NodeLoadBalancer.VMFirewallSettle; settle > 0 {
		return settle
	}
	return vmFirewallSettleDefault
}

// vmFirewallSettleRemaining is how much of the settle delay is left, counted
// from the anchor's applied-at. An anchor that never applied anything has
// nothing to settle.
func vmFirewallSettleRemaining(anchor *corev1.ConfigMap, settle time.Duration, now time.Time) time.Duration {
	appliedAt, ok, err := vmFirewallAnchorView{cm: anchor}.appliedAt()
	if err != nil || !ok {
		return 0
	}
	if remaining := appliedAt.Add(settle).Sub(now); remaining > 0 {
		return remaining
	}
	return 0
}
