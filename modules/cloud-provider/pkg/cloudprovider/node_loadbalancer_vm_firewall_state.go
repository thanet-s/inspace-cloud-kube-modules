package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
