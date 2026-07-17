package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	annotationNodeLoadBalancerFirewallRelationIssued   = "service.inspace.cloud/node-lb-firewall-relation-issued"
	annotationNodeLoadBalancerFirewallRelationOwnerUID = "service.inspace.cloud/node-lb-firewall-relation-owner-uid"
	annotationNodeLoadBalancerFirewallRelationVMAbsent = "service.inspace.cloud/node-lb-firewall-relation-vm-absence"
)

type nodeLoadBalancerFirewallRelationOperation string

const (
	nodeLoadBalancerFirewallRelationAssign   nodeLoadBalancerFirewallRelationOperation = "assign"
	nodeLoadBalancerFirewallRelationUnassign nodeLoadBalancerFirewallRelationOperation = "unassign"
)

type nodeLoadBalancerFirewallRelationFence struct {
	operation         nodeLoadBalancerFirewallRelationOperation
	firewallUUID      string
	vmUUID            string
	issueID           string
	issuedAt          string
	targetAbsentAt    string
	absenceObservedAt string
}

func (f nodeLoadBalancerFirewallRelationFence) String() string {
	logical := f.logicalString()
	if f.issueID == "" && f.issuedAt == "" {
		return logical
	}
	if f.targetAbsentAt != "" {
		return "v3|" + string(f.operation) + "|" + f.firewallUUID + "|" + f.vmUUID + "|" + f.issueID + "|" + f.issuedAt + "|" + f.targetAbsentAt + "|" + f.absenceObservedAt
	}
	if f.absenceObservedAt != "" {
		return "v2|" + string(f.operation) + "|" + f.firewallUUID + "|" + f.vmUUID + "|" + f.issueID + "|" + f.issuedAt + "|" + f.absenceObservedAt
	}
	return "v1|" + string(f.operation) + "|" + f.firewallUUID + "|" + f.vmUUID + "|" + f.issueID + "|" + f.issuedAt
}

func (f nodeLoadBalancerFirewallRelationFence) logicalString() string {
	return string(f.operation) + ":" + f.firewallUUID + "/" + f.vmUUID
}

func parseNodeLoadBalancerFirewallRelationFence(value string) (nodeLoadBalancerFirewallRelationFence, error) {
	parts := strings.Split(strings.TrimSpace(value), "|")
	if (len(parts) != 6 || parts[0] != "v1") && (len(parts) != 7 || parts[0] != "v2") &&
		(len(parts) != 8 || parts[0] != "v3") {
		return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: malformed firewall relation fence %q", value)
	}
	operation := nodeLoadBalancerFirewallRelationOperation(parts[1])
	firewallUUID := parts[2]
	vmUUID := parts[3]
	if (operation != nodeLoadBalancerFirewallRelationAssign && operation != nodeLoadBalancerFirewallRelationUnassign) ||
		!validNodeLoadBalancerCloudUUID(firewallUUID) || !validNodeLoadBalancerCloudUUID(vmUUID) {
		return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: malformed firewall relation fence %q", value)
	}
	if err := validateNodeLoadBalancerFirewallCreateIssued(parts[4], parts[5]); err != nil {
		return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: invalid firewall relation issue identity: %w", err)
	}
	result := nodeLoadBalancerFirewallRelationFence{
		operation: operation, firewallUUID: strings.ToLower(firewallUUID), vmUUID: strings.ToLower(vmUUID),
		issueID: parts[4], issuedAt: parts[5],
	}
	if len(parts) == 7 {
		if operation != nodeLoadBalancerFirewallRelationUnassign {
			return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: only an unassign fence may contain absence evidence %q", value)
		}
		observedAt, err := time.Parse(time.RFC3339Nano, parts[6])
		if err != nil || observedAt.Location() != time.UTC {
			return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: invalid firewall relation absence observation %q", parts[6])
		}
		result.absenceObservedAt = parts[6]
	}
	if len(parts) == 8 {
		if operation != nodeLoadBalancerFirewallRelationUnassign || parts[6] == "" {
			return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: only an unassign fence may contain target-absence evidence %q", value)
		}
		targetObservedAt, targetErr := time.Parse(time.RFC3339Nano, parts[6])
		issuedAt, issuedErr := time.Parse(time.RFC3339Nano, parts[5])
		if targetErr != nil || targetObservedAt.Location() != time.UTC || issuedErr != nil || targetObservedAt.After(issuedAt) {
			return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: invalid firewall relation target-absence observation %q", parts[6])
		}
		result.targetAbsentAt = parts[6]
		if parts[7] != "" {
			observedAt, err := time.Parse(time.RFC3339Nano, parts[7])
			if err != nil || observedAt.Location() != time.UTC {
				return nodeLoadBalancerFirewallRelationFence{}, fmt.Errorf("node load balancer: invalid firewall relation absence observation %q", parts[7])
			}
			result.absenceObservedAt = parts[7]
		}
	}
	return result, nil
}

// nodeLoadBalancerFirewallVMAssignments treats byte-for-byte duplicate cloud
// relationship rows as one set member. It still rejects every malformed or
// non-VM row; callers compare the returned set with their exact authorized VM
// set so a foreign VM remains a fail-closed observation.
func nodeLoadBalancerFirewallVMAssignments(firewall inspace.Firewall) (map[string]struct{}, error) {
	if !validNodeLoadBalancerCloudUUID(firewall.UUID) {
		return nil, fmt.Errorf("node load balancer: firewall has invalid UUID %q", firewall.UUID)
	}
	if firewall.ResourcesAssigned == nil {
		return nil, fmt.Errorf("node load balancer: firewall %s omitted resources_assigned", firewall.UUID)
	}
	result := make(map[string]struct{}, len(firewall.ResourcesAssigned))
	for _, resource := range firewall.ResourcesAssigned {
		if !strings.EqualFold(resource.ResourceType, "vm") || !validNodeLoadBalancerCloudUUID(resource.ResourceUUID) {
			return nil, fmt.Errorf("node load balancer: firewall %s has unexpected assigned resource %#v", firewall.UUID, resource)
		}
		result[strings.ToLower(resource.ResourceUUID)] = struct{}{}
	}
	return result, nil
}

func nodeLoadBalancerFirewallRelationConverged(
	fence nodeLoadBalancerFirewallRelationFence,
	items []inspace.Firewall,
) (bool, error) {
	var current *inspace.Firewall
	for index := range items {
		if !strings.EqualFold(items[index].UUID, fence.firewallUUID) {
			continue
		}
		if current != nil {
			return false, fmt.Errorf("node load balancer: firewall UUID %s appears multiple times during relation readback", fence.firewallUUID)
		}
		copy := items[index]
		current = &copy
	}
	if current == nil {
		return fence.operation == nodeLoadBalancerFirewallRelationUnassign, nil
	}
	assignments, err := nodeLoadBalancerFirewallVMAssignments(*current)
	if err != nil {
		return false, err
	}
	_, assigned := assignments[fence.vmUUID]
	if fence.operation == nodeLoadBalancerFirewallRelationAssign {
		return assigned, nil
	}
	return !assigned, nil
}

// advanceNodeLoadBalancerFirewallRelationObservation updates only the durable
// owner receipt. Additive assignment may resolve from one positive observation,
// but a removal requires two absence observations separated by the standard
// provider-convergence delay. A transiently omitted firewall/relation therefore
// cannot clear the one-shot DELETE authority and permit a replay after restart.
func advanceNodeLoadBalancerFirewallRelationObservation(
	values map[string]string,
	fence nodeLoadBalancerFirewallRelationFence,
	converged bool,
	now time.Time,
	absenceDelay time.Duration,
) (cleared, changed bool, err error) {
	if fence.operation == nodeLoadBalancerFirewallRelationAssign {
		if fence.absenceObservedAt != "" {
			return false, false, errors.New("node load balancer: assignment relation fence contains removal absence evidence")
		}
		if !converged {
			return false, false, nil
		}
		delete(values, annotationNodeLoadBalancerFirewallRelationIssued)
		delete(values, annotationNodeLoadBalancerFirewallRelationOwnerUID)
		return true, true, nil
	}
	if fence.operation != nodeLoadBalancerFirewallRelationUnassign {
		return false, false, fmt.Errorf("node load balancer: unsupported firewall relation operation %q", fence.operation)
	}
	if !converged {
		if fence.absenceObservedAt == "" {
			return false, false, nil
		}
		fence.absenceObservedAt = ""
		values[annotationNodeLoadBalancerFirewallRelationIssued] = fence.String()
		return false, true, nil
	}
	if fence.absenceObservedAt == "" {
		fence.absenceObservedAt = now.UTC().Format(time.RFC3339Nano)
		values[annotationNodeLoadBalancerFirewallRelationIssued] = fence.String()
		return false, true, nil
	}
	observedAt, parseErr := time.Parse(time.RFC3339Nano, fence.absenceObservedAt)
	if parseErr != nil || observedAt.Location() != time.UTC {
		return false, false, fmt.Errorf("node load balancer: invalid persisted firewall relation absence observation %q", fence.absenceObservedAt)
	}
	if now.UTC().Before(observedAt.Add(absenceDelay)) {
		return false, false, nil
	}
	delete(values, annotationNodeLoadBalancerFirewallRelationIssued)
	delete(values, annotationNodeLoadBalancerFirewallRelationOwnerUID)
	return true, true, nil
}

func sameNodeLoadBalancerFirewallRelationIssue(left, right nodeLoadBalancerFirewallRelationFence) bool {
	return left.operation == right.operation &&
		strings.EqualFold(left.firewallUUID, right.firewallUUID) &&
		strings.EqualFold(left.vmUUID, right.vmUUID) &&
		left.issueID == right.issueID &&
		left.issuedAt == right.issuedAt &&
		left.targetAbsentAt == right.targetAbsentAt
}

func (c *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationTime() time.Time {
	if c.firewallRelationNow != nil {
		return c.firewallRelationNow().UTC()
	}
	return time.Now().UTC()
}

func (c *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationAbsenceDelay() time.Duration {
	if c.firewallRelationAbsentDelay < 0 {
		return nodeLoadBalancerAbsenceConfirmationDelay
	}
	return c.firewallRelationAbsentDelay
}

func encodeNodeLoadBalancerFirewallRelationVMAbsence(
	firewallUUID, vmUUID string,
	observedAt time.Time,
) string {
	return firewallUUID + "|" + vmUUID + "|" + observedAt.UTC().Format(time.RFC3339Nano)
}

func parseNodeLoadBalancerFirewallRelationVMAbsence(
	value, firewallUUID, vmUUID string,
) (time.Time, bool, error) {
	if value == "" {
		return time.Time{}, false, nil
	}
	parts := strings.Split(value, "|")
	if len(parts) != 3 || parts[0] != firewallUUID || parts[1] != vmUUID {
		return time.Time{}, false, errors.New("node load balancer: firewall relation VM-absence receipt does not match the requested relation")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil || observedAt.Location() != time.UTC {
		return time.Time{}, false, errors.New("node load balancer: firewall relation VM-absence receipt has an invalid timestamp")
	}
	return observedAt, true, nil
}

// nodeLoadBalancerFirewallRelationVMCloudAuthority corroborates one VM through
// exact GET, account inventory, and the configured VPC membership. The absent
// result is only one observation; callers must persist it and repeat all three
// reads after the convergence delay before using absence as detach authority.
func (c *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationVMCloudAuthority(
	ctx context.Context,
	vmUUID string,
) (owned, absent bool, err error) {
	if !validNodeLoadBalancerCloudUUID(vmUUID) {
		return false, false, fmt.Errorf("node load balancer: invalid relation VM UUID %q", vmUUID)
	}
	exact, getErr := c.provider.api.GetVM(ctx, c.provider.config.Location, vmUUID)
	exactAbsent := false
	if getErr != nil {
		if !inspace.IsNotFound(getErr) {
			return false, false, fmt.Errorf("node load balancer: read exact relation VM %s: %w", vmUUID, getErr)
		}
		exactAbsent = true
	} else if exact == nil {
		return false, false, fmt.Errorf("node load balancer: exact relation VM %s returned an empty response", vmUUID)
	} else if strings.EqualFold(strings.TrimSpace(exact.Status), "deleted") {
		if exact.UUID != vmUUID || exact.BillingAccountID != c.provider.config.BillingAccountID ||
			(exact.NetworkUUID != "" && exact.NetworkUUID != c.provider.config.NetworkUUID) {
			return false, false, fmt.Errorf("node load balancer: deleted relation VM %s has conflicting exact identity", vmUUID)
		}
		// A canonical tombstone is one source of absence evidence. List and
		// configured-VPC membership below must independently omit it, and callers
		// still persist two spaced observations before an unassign may dispatch.
		exactAbsent = true
	}
	items, err := c.provider.api.ListVMs(ctx, c.provider.config.Location)
	if err != nil {
		return false, false, fmt.Errorf("node load balancer: list relation VM inventory: %w", err)
	}
	network, err := c.provider.api.GetNetwork(ctx, c.provider.config.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return false, false, fmt.Errorf("node load balancer: read relation VM VPC membership: %w", err)
	}
	if network == nil || network.UUID != c.provider.config.NetworkUUID {
		return false, false, errors.New("node load balancer: relation VM VPC identity changed")
	}
	members, membershipErr := canonicalConfiguredVPCVMUUIDs(c.provider.config.Location, network)
	if membershipErr != nil {
		return false, false, fmt.Errorf("node load balancer: relation VM VPC membership is invalid: %w", membershipErr)
	}
	listMatches := 0
	var listed *inspace.VM
	for index := range items {
		if !strings.EqualFold(items[index].UUID, vmUUID) {
			continue
		}
		listMatches++
		if items[index].UUID == vmUUID {
			copy := items[index]
			listed = &copy
		}
	}
	memberships := 0
	exactMembership := false
	if member, present := members[vmUUID]; present {
		memberships = 1
		exactMembership = member == vmUUID
	}
	if exactAbsent {
		if listMatches == 0 && memberships == 0 {
			return false, true, nil
		}
		return false, false, fmt.Errorf(
			"node load balancer: exact relation VM %s is absent but inventory/VPC still report it (rows=%d memberships=%d)",
			vmUUID,
			listMatches,
			memberships,
		)
	}
	if exact.UUID != vmUUID || listMatches != 1 || listed == nil || memberships != 1 || !exactMembership {
		return false, false, fmt.Errorf(
			"node load balancer: relation VM %s lacks unique exact GET/list/VPC identity (rows=%d memberships=%d)",
			vmUUID,
			listMatches,
			memberships,
		)
	}
	for role, vm := range map[string]*inspace.VM{"exact": exact, "listed": listed} {
		if vm.BillingAccountID != c.provider.config.BillingAccountID ||
			(vm.NetworkUUID != "" && vm.NetworkUUID != c.provider.config.NetworkUUID) {
			return false, false, fmt.Errorf("node load balancer: %s relation VM %s has foreign billing or VPC identity", role, vmUUID)
		}
	}
	return true, false, nil
}

func (c *nodeLoadBalancerController) authorizeFirewallRelationUnassignVM(
	ctx context.Context,
	fence nodeLoadBalancerFirewallRelationFence,
) error {
	owned, absent, err := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, fence.vmUUID)
	if err != nil {
		return err
	}
	if owned {
		return nil
	}
	if !absent || fence.targetAbsentAt == "" {
		return errors.New("node load balancer: unassign target has neither canonical owned VM authority nor durable absence proof")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, fence.targetAbsentAt)
	if err != nil || c.nodeLoadBalancerFirewallRelationTime().Before(observedAt.Add(c.nodeLoadBalancerFirewallRelationAbsenceDelay())) {
		return errors.New("node load balancer: unassign target VM absence is not durably spaced")
	}
	return nil
}

type nodeLoadBalancerFirewallRelationOwner struct {
	description string
	read        func(context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error)
	authorize   func(context.Context, nodeLoadBalancerFirewallRelationFence, inspace.Firewall) error
}

type nodeLoadBalancerFirewallRelationOwnerSnapshot struct {
	annotations map[string]string
	uid         types.UID
	commit      func(context.Context, map[string]string) error
}

func copyNodeLoadBalancerAnnotations(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func (c *nodeLoadBalancerController) serviceFirewallRelationOwner(service *corev1.Service) nodeLoadBalancerFirewallRelationOwner {
	return nodeLoadBalancerFirewallRelationOwner{
		description: fmt.Sprintf("Service %s/%s", service.Namespace, service.Name),
		authorize: func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			return c.authorizeServiceFirewallRelationPreDispatch(ctx, service, fence, before)
		},
		read: func(ctx context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error) {
			current, err := c.getExactParentService(ctx, service)
			if err != nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, err
			}
			return nodeLoadBalancerFirewallRelationOwnerSnapshot{
				annotations: copyNodeLoadBalancerAnnotations(current.Annotations),
				uid:         current.UID,
				commit: func(ctx context.Context, values map[string]string) error {
					copy := current.DeepCopy()
					copy.Annotations = copyNodeLoadBalancerAnnotations(values)
					updated, updateErr := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Update(ctx, copy, metav1.UpdateOptions{})
					if updateErr != nil {
						return updateErr
					}
					if updated.UID != service.UID {
						return errors.New("node load balancer: Service identity changed during firewall relation fence update")
					}
					if !mapsEqualStringString(updated.Annotations, values) {
						return errors.New("node load balancer: Service admission changed the firewall relation fence update")
					}
					verified, verifyErr := c.provider.kubeClient.CoreV1().Services(copy.Namespace).Get(ctx, copy.Name, metav1.GetOptions{})
					if verifyErr != nil {
						return fmt.Errorf("read back Service firewall relation fence: %w", verifyErr)
					}
					if verified.UID != service.UID || verified.ResourceVersion != updated.ResourceVersion ||
						!mapsEqualStringString(verified.Annotations, values) {
						return errors.New("node load balancer: Service firewall relation fence failed exact UID/resourceVersion readback")
					}
					return nil
				},
			}, nil
		},
	}
}

func (c *nodeLoadBalancerController) shardFirewallRelationOwner(shard string) nodeLoadBalancerFirewallRelationOwner {
	return c.shardFirewallRelationOwnerForUID(shard, "")
}

func (c *nodeLoadBalancerController) shardFirewallRelationOwnerForUID(
	shard string,
	expectedUID types.UID,
) nodeLoadBalancerFirewallRelationOwner {
	return nodeLoadBalancerFirewallRelationOwner{
		description: "NodePool " + shard,
		authorize: func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			return c.authorizeShardFirewallRelationPreDispatch(ctx, shard, fence, before)
		},
		read: func(ctx context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error) {
			resource := c.provider.dynamicClient.Resource(nodePoolGVR)
			pool, err := resource.Get(ctx, shard, metav1.GetOptions{})
			if err != nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, err
			}
			if expectedUID != "" && pool.GetUID() != expectedUID {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, fmt.Errorf(
					"node load balancer: NodePool %s identity changed before firewall relation transition",
					shard,
				)
			}
			labels := pool.GetLabels()
			if labels[nodeLoadBalancerManagedLabel] != "true" ||
				labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
				labels[nodeLoadBalancerShardLabel] != shard ||
				!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, fmt.Errorf("node load balancer: NodePool %s lacks exact relation-fence ownership", shard)
			}
			return nodeLoadBalancerFirewallRelationOwnerSnapshot{
				annotations: copyNodeLoadBalancerAnnotations(pool.GetAnnotations()),
				uid:         pool.GetUID(),
				commit: func(ctx context.Context, values map[string]string) error {
					copy := pool.DeepCopy()
					copy.SetAnnotations(copyNodeLoadBalancerAnnotations(values))
					updated, updateErr := resource.Update(ctx, copy, metav1.UpdateOptions{})
					if updateErr != nil {
						return updateErr
					}
					if updated.GetUID() != pool.GetUID() || !mapsEqualStringString(updated.GetAnnotations(), values) {
						return errors.New("node load balancer: NodePool admission changed the firewall relation fence update")
					}
					verified, verifyErr := resource.Get(ctx, shard, metav1.GetOptions{})
					if verifyErr != nil {
						return fmt.Errorf("read back NodePool firewall relation fence: %w", verifyErr)
					}
					labels := verified.GetLabels()
					if verified.GetUID() != pool.GetUID() || verified.GetResourceVersion() != updated.GetResourceVersion() ||
						labels[nodeLoadBalancerManagedLabel] != "true" ||
						labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
						labels[nodeLoadBalancerShardLabel] != shard ||
						!containsString(verified.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) ||
						!mapsEqualStringString(verified.GetAnnotations(), values) {
						return errors.New("node load balancer: NodePool firewall relation fence failed exact UID/resourceVersion readback")
					}
					return nil
				},
			}, nil
		},
	}
}

func (c *nodeLoadBalancerController) clusterICMPFirewallRelationOwner(nodeClassName string) nodeLoadBalancerFirewallRelationOwner {
	return c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, "")
}

func (c *nodeLoadBalancerController) clusterICMPFirewallRelationOwnerForUID(
	nodeClassName string,
	expectedUID types.UID,
) nodeLoadBalancerFirewallRelationOwner {
	return nodeLoadBalancerFirewallRelationOwner{
		description: "InSpaceNodeClass " + nodeClassName,
		authorize: func(ctx context.Context, fence nodeLoadBalancerFirewallRelationFence, before inspace.Firewall) error {
			return c.authorizeClusterICMPFirewallRelationPreDispatch(ctx, nodeClassName, fence, before)
		},
		read: func(ctx context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error) {
			object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
			if err != nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, err
			}
			if expectedUID != "" && object.GetUID() != expectedUID {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, fmt.Errorf(
					"node load balancer: InSpaceNodeClass %s identity changed before firewall relation transition",
					nodeClassName,
				)
			}
			resource := c.provider.dynamicClient.Resource(nodeClassGVR)
			return nodeLoadBalancerFirewallRelationOwnerSnapshot{
				annotations: copyNodeLoadBalancerAnnotations(object.GetAnnotations()),
				uid:         object.GetUID(),
				commit: func(ctx context.Context, values map[string]string) error {
					copy := object.DeepCopy()
					copy.SetAnnotations(copyNodeLoadBalancerAnnotations(values))
					updated, updateErr := resource.Update(ctx, copy, metav1.UpdateOptions{})
					if updateErr != nil {
						return updateErr
					}
					if updated.GetUID() != object.GetUID() || !mapsEqualStringString(updated.GetAnnotations(), values) {
						return errors.New("node load balancer: InSpaceNodeClass admission changed the firewall relation fence update")
					}
					verified, verifyErr := resource.Get(ctx, nodeClassName, metav1.GetOptions{})
					if verifyErr != nil {
						return fmt.Errorf("read back InSpaceNodeClass firewall relation fence: %w", verifyErr)
					}
					labels := verified.GetLabels()
					if verified.GetUID() != object.GetUID() || verified.GetResourceVersion() != updated.GetResourceVersion() ||
						labels[nodeLoadBalancerManagedLabel] != "true" ||
						labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
						!containsString(verified.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) ||
						!mapsEqualStringString(verified.GetAnnotations(), values) {
						return errors.New("node load balancer: InSpaceNodeClass firewall relation fence failed exact UID/resourceVersion readback")
					}
					return nil
				},
			}, nil
		},
	}
}

// exactNodeLoadBalancerFirewallFresh re-reads the cloud immediately before a
// relationship mutation. A case-folded duplicate or a case-changed UUID is
// ambiguous and therefore cannot authorize an attach or detach.
func (c *nodeLoadBalancerController) exactNodeLoadBalancerFirewallFresh(
	ctx context.Context,
	uuid string,
) (*inspace.Firewall, error) {
	if !validNodeLoadBalancerCloudUUID(uuid) {
		return nil, fmt.Errorf("node load balancer: invalid firewall UUID %q", uuid)
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, fmt.Errorf("node load balancer: fresh firewall authority read: %w", err)
	}
	return exactNodeLoadBalancerFirewallFromItems(items, uuid)
}

func exactNodeLoadBalancerFirewallFromItems(items []inspace.Firewall, uuid string) (*inspace.Firewall, error) {
	if !validNodeLoadBalancerCloudUUID(uuid) {
		return nil, fmt.Errorf("node load balancer: invalid firewall UUID %q", uuid)
	}
	var exact *inspace.Firewall
	matches := 0
	for index := range items {
		if !strings.EqualFold(items[index].UUID, uuid) {
			continue
		}
		matches++
		if items[index].UUID == uuid {
			copy := items[index]
			exact = &copy
		}
	}
	if matches != 1 || exact == nil {
		return nil, fmt.Errorf("node load balancer: firewall UUID %s has %d case-folded rows and no unique exact authority", uuid, matches)
	}
	if _, err := nodeLoadBalancerFirewallVMAssignments(*exact); err != nil {
		return nil, err
	}
	return exact, nil
}

// exactNodeLoadBalancerFirewallNameFresh is the final absence/identity proof
// before any deterministic-name firewall create crosses the cloud boundary.
// The list is intentionally unfiltered: a case-fold collision or duplicate
// row is authority ambiguity, never permission to issue another paid POST.
func (c *nodeLoadBalancerController) exactNodeLoadBalancerFirewallNameFresh(
	ctx context.Context,
	name string,
) (*inspace.Firewall, bool, error) {
	if name == "" {
		return nil, false, errors.New("node load balancer: exact firewall name authority requires a non-empty name")
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: fresh deterministic firewall-name read: %w", err)
	}
	var exact *inspace.Firewall
	matches := 0
	for index := range items {
		candidate := items[index].EffectiveName()
		if !strings.EqualFold(candidate, name) {
			continue
		}
		matches++
		if candidate == name {
			copy := items[index]
			exact = &copy
		}
	}
	if matches == 0 {
		return nil, true, nil
	}
	if matches != 1 || exact == nil {
		return nil, false, fmt.Errorf(
			"node load balancer: deterministic firewall name %q has %d case-folded rows and no unique exact authority",
			name,
			matches,
		)
	}
	return exact, false, nil
}

func nodeLoadBalancerFirewallAuthorityUnchanged(before, after inspace.Firewall) bool {
	return before.UUID == after.UUID &&
		before.EffectiveName() == after.EffectiveName() &&
		before.Description == after.Description &&
		before.BillingAccountID == after.BillingAccountID &&
		reflect.DeepEqual(before.Rules, after.Rules) &&
		reflect.DeepEqual(before.ResourcesAssigned, after.ResourcesAssigned)
}

func (c *nodeLoadBalancerController) exactNodeForFirewallRelationVM(
	ctx context.Context,
	vmUUID string,
) (*corev1.Node, error) {
	if !validNodeLoadBalancerCloudUUID(vmUUID) {
		return nil, fmt.Errorf("node load balancer: invalid VM UUID %q", vmUUID)
	}
	items, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list Nodes for VM authority: %w", err)
	}
	var result *corev1.Node
	matches := 0
	for index := range items.Items {
		candidate := &items.Items[index]
		candidateUUID, ok := nodeLoadBalancerVMUUID(candidate)
		if !ok || !strings.EqualFold(candidateUUID, vmUUID) {
			continue
		}
		matches++
		if candidateUUID == vmUUID {
			result = candidate.DeepCopy()
		}
	}
	if matches != 1 || result == nil {
		return nil, fmt.Errorf("node load balancer: VM UUID %s maps to %d case-folded Nodes and no unique exact Node", vmUUID, matches)
	}
	return result, nil
}

func (c *nodeLoadBalancerController) authorizeServiceFirewallRelationPreDispatch(
	ctx context.Context,
	service *corev1.Service,
	fence nodeLoadBalancerFirewallRelationFence,
	before inspace.Firewall,
) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	validateFirewall := func() (*inspace.Firewall, error) {
		firewall, readErr := c.exactNodeLoadBalancerFirewallFresh(ctx, fence.firewallUUID)
		if readErr != nil {
			return nil, readErr
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *firewall) {
			return nil, fmt.Errorf("Service firewall %s changed after relation issue", fence.firewallUUID)
		}
		if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
			if !nodeLoadBalancerFirewallIdentityOwnedByService(
				*firewall,
				c.provider.config.ClusterID,
				string(current.UID),
				c.provider.config.BillingAccountID,
			) {
				return nil, fmt.Errorf("Service firewall %s lost exact owner or billing", fence.firewallUUID)
			}
		} else if !nodeLoadBalancerFirewallOwnedByService(
			*firewall,
			c.provider.config.ClusterID,
			string(current.UID),
			c.provider.config.BillingAccountID,
		) {
			return nil, fmt.Errorf("Service firewall %s lost exact owner, billing, or self-authenticating policy", fence.firewallUUID)
		}
		return firewall, nil
	}
	firewall, err := validateFirewall()
	if err != nil {
		return err
	}
	if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
		return c.authorizeFirewallRelationUnassignVM(ctx, fence)
	}
	if fence.operation != nodeLoadBalancerFirewallRelationAssign {
		return fmt.Errorf("unsupported firewall relation operation %q", fence.operation)
	}
	if current.DeletionTimestamp != nil || (!containsString(current.Finalizers, nodeLoadBalancerFinalizer) &&
		!containsString(current.Finalizers, publicNodeLocalFinalizer)) {
		return errors.New("Service is deleting or lacks its durable NodeLB finalizer")
	}
	desired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return err
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallUUID] != fence.firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
		!nodeLoadBalancerFirewallMatches(*firewall, desired) {
		return errors.New("Service firewall no longer matches the exact live policy ledger")
	}
	target, err := c.exactNodeForFirewallRelationVM(ctx, fence.vmUUID)
	if err != nil {
		return err
	}
	intent, err := parseNodeLoadBalancerService(
		current,
		nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard},
	)
	if err != nil {
		return err
	}
	if intent.Mode == nodeLoadBalancerModeLocal {
		addresses, patched, addressErr := c.publicNodeLocalAddresses(ctx, current, intent)
		if addressErr != nil {
			return addressErr
		}
		if patched {
			return errors.New("public-node-local Node authority changed and requires a fresh reconciliation")
		}
		found := false
		for _, address := range addresses {
			vmUUID, ok := nodeLoadBalancerVMUUID(address.Node)
			if ok && vmUUID == fence.vmUUID && address.Node.Name == target.Name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("VM %s is not a current authorized local endpoint", fence.vmUUID)
		}
		if err := c.validatePublicNodeLocalAssignmentState(
			ctx, current, intent, desired, fence.firewallUUID, addresses, true, false,
		); err != nil {
			return err
		}
	} else if err := c.validateServiceFirewallAssignmentMutation(ctx, current, *firewall, target); err != nil {
		return err
	}
	// Make firewall ownership and policy the final cloud observation before the
	// attach crosses the provider boundary. VM/VPC authority above is itself
	// derived from fresh canonical reads.
	_, err = validateFirewall()
	return err
}

func (c *nodeLoadBalancerController) authorizeShardFirewallRelationPreDispatch(
	ctx context.Context,
	shard string,
	fence nodeLoadBalancerFirewallRelationFence,
	before inspace.Firewall,
) error {
	validateFirewall := func() error {
		pool, poolErr := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
		if poolErr != nil {
			return fmt.Errorf("read shard owner: %w", poolErr)
		}
		labels := pool.GetLabels()
		if labels[nodeLoadBalancerManagedLabel] != "true" ||
			labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
			labels[nodeLoadBalancerShardLabel] != shard ||
			!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
			return errors.New("shard NodePool lost exact ownership")
		}
		if fence.operation == nodeLoadBalancerFirewallRelationAssign && pool.GetDeletionTimestamp() != nil {
			return errors.New("shard NodePool is deleting and no longer authorizes firewall assignment")
		}
		firewall, readErr := c.exactNodeLoadBalancerFirewallFresh(ctx, fence.firewallUUID)
		if readErr != nil {
			return readErr
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *firewall) {
			return fmt.Errorf("shard firewall %s changed after relation issue", fence.firewallUUID)
		}
		if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
			name, nameErr := inspace.NodeLoadBalancerShardFirewallName(c.provider.config.ClusterID, shard)
			if nameErr != nil {
				return nameErr
			}
			if firewall.EffectiveName() != name || firewall.BillingAccountID != c.provider.config.BillingAccountID {
				return fmt.Errorf("shard firewall %s lost exact owner or billing", fence.firewallUUID)
			}
			return nil
		}
		annotations, annotationErr := nodeLoadBalancerShardFirewallAnnotations(pool)
		if annotationErr != nil {
			return annotationErr
		}
		expectedHash := annotations[annotationNodeLoadBalancerShardFirewallHash]
		expectedLedger := annotations[annotationNodeLoadBalancerShardFirewallLedger]
		if fence.operation == nodeLoadBalancerFirewallRelationAssign {
			if annotations[annotationNodeLoadBalancerShardFirewallUUID] != fence.firewallUUID ||
				!validNodeLoadBalancerShardFirewallPolicyHash(expectedHash) || expectedLedger == "" {
				return errors.New("shard firewall assignment lost its exact UUID, policy hash, or membership ledger")
			}
			freshPolicy, freshLedger, _, policyErr := c.desiredStagedShardFirewallPolicy(ctx, shard)
			if policyErr != nil {
				return policyErr
			}
			if freshPolicy == nil || freshPolicy.Hash != expectedHash || freshLedger != expectedLedger {
				return errors.New("shard firewall assignment no longer matches the live staged Service policy")
			}
		}
		if err := inspace.ValidateNodeLoadBalancerShardFirewall(
			*firewall,
			c.provider.config.ClusterID,
			shard,
			c.provider.config.BillingAccountID,
			expectedHash,
		); err != nil {
			return fmt.Errorf("shard firewall %s lost exact owner, billing, or policy: %w", fence.firewallUUID, err)
		}
		return nil
	}
	if err := validateFirewall(); err != nil {
		return err
	}
	if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
		return c.authorizeFirewallRelationUnassignVM(ctx, fence)
	}
	if fence.operation != nodeLoadBalancerFirewallRelationAssign {
		return fmt.Errorf("unsupported firewall relation operation %q", fence.operation)
	}
	nodes, err := c.authorizedNodesForShard(ctx, shard)
	if err != nil {
		return err
	}
	if err := requireAuthorizedNodeLoadBalancerFirewallVM(nodes, fence.vmUUID); err != nil {
		return err
	}
	return validateFirewall()
}

func (c *nodeLoadBalancerController) authorizeClusterICMPFirewallRelationPreDispatch(
	ctx context.Context,
	nodeClassName string,
	fence nodeLoadBalancerFirewallRelationFence,
	before inspace.Firewall,
) error {
	readLiveNodeClass := func() (*unstructured.Unstructured, error) {
		nodeClass, readErr := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
		if readErr != nil {
			return nil, readErr
		}
		if fence.operation == nodeLoadBalancerFirewallRelationAssign && nodeClass.GetDeletionTimestamp() != nil {
			return nil, errors.New("cluster ICMP NodeClass is deleting and no longer authorizes firewall assignment")
		}
		return nodeClass, nil
	}
	nodeClass, err := readLiveNodeClass()
	if err != nil {
		return err
	}
	validateFirewall := func() error {
		firewall, readErr := c.exactNodeLoadBalancerFirewallFresh(ctx, fence.firewallUUID)
		if readErr != nil {
			return readErr
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(before, *firewall) {
			return fmt.Errorf("cluster ICMP firewall %s changed after relation issue", fence.firewallUUID)
		}
		if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
			desired, desiredErr := desiredNodeLoadBalancerClusterICMPFirewall(
				c.provider.config.ClusterID,
				c.provider.config.BillingAccountID,
			)
			if desiredErr != nil {
				return desiredErr
			}
			if firewall.EffectiveName() != desired.Request.DisplayName ||
				firewall.BillingAccountID != c.provider.config.BillingAccountID {
				return fmt.Errorf("cluster ICMP firewall %s lost exact owner or billing", fence.firewallUUID)
			}
			return nil
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(
			*firewall,
			c.provider.config.ClusterID,
			c.provider.config.BillingAccountID,
		) {
			return fmt.Errorf("cluster ICMP firewall %s lost exact owner, billing, or policy", fence.firewallUUID)
		}
		return nil
	}
	if err := validateFirewall(); err != nil {
		return err
	}
	if fence.operation == nodeLoadBalancerFirewallRelationUnassign {
		return c.authorizeFirewallRelationUnassignVM(ctx, fence)
	}
	if fence.operation != nodeLoadBalancerFirewallRelationAssign {
		return fmt.Errorf("unsupported firewall relation operation %q", fence.operation)
	}
	if nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID] != fence.firewallUUID {
		return errors.New("cluster ICMP firewall no longer matches the NodeClass ledger")
	}
	nodes, err := c.authorizedNodesForCluster(ctx)
	if err != nil {
		return err
	}
	if err := requireAuthorizedNodeLoadBalancerFirewallVM(nodes, fence.vmUUID); err != nil {
		return err
	}
	nodeClass, err = readLiveNodeClass()
	if err != nil {
		return err
	}
	if nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID] != fence.firewallUUID {
		return errors.New("cluster ICMP firewall no longer matches the NodeClass ledger")
	}
	return validateFirewall()
}

func requireAuthorizedNodeLoadBalancerFirewallVM(nodes []*corev1.Node, vmUUID string) error {
	matches := 0
	for _, node := range nodes {
		candidate, ok := nodeLoadBalancerVMUUID(node)
		if ok && candidate == vmUUID && nodeLoadBalancerNodeHealthy(node) {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("VM %s has %d healthy authoritative managed Nodes, want exactly one", vmUUID, matches)
	}
	return nil
}

// reconcileNodeLoadBalancerFirewallRelation serializes an exact cloud
// relationship mutation through the Kubernetes object that owns it. The
// persisted fence is deliberately retained after a successful response: only
// a later authoritative ListFirewalls observation may clear it. Therefore an
// HTTP 500, timeout, controller restart, or concurrent reconciler can never
// issue a second POST/DELETE for the same attempt.
//
// A nil desired fence only resolves an already-issued attempt. The bool is
// true only when no fence was advanced and the requested relation (if any) is
// already converged.
func (c *nodeLoadBalancerController) reconcileNodeLoadBalancerFirewallRelation(
	ctx context.Context,
	owner nodeLoadBalancerFirewallRelationOwner,
	desired *nodeLoadBalancerFirewallRelationFence,
) (bool, error) {
	snapshot, err := owner.read(ctx)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read %s firewall relation owner: %w", owner.description, err)
	}
	if snapshot.uid == "" {
		return false, fmt.Errorf("node load balancer: %s firewall relation owner has an empty UID", owner.description)
	}
	legacyIssued := snapshot.annotations[annotationNodeLoadBalancerFirewallRelationIssued]
	legacyOwnerUID := snapshot.annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID]
	if legacyIssued != "" && legacyOwnerUID == "" {
		if _, parseErr := parseNodeLoadBalancerFirewallRelationFence(legacyIssued); parseErr != nil {
			return false, parseErr
		}
		// v0.6.0-rc.2 persisted relation receipts before they carried an owner
		// UID. Bind a valid legacy receipt to the exact live object through the
		// owner's optimistic CAS, then stop this pass. This migration performs no
		// cloud read or mutation; the next reconciliation resolves the unchanged
		// receipt through the normal authoritative readback path.
		values := copyNodeLoadBalancerAnnotations(snapshot.annotations)
		values[annotationNodeLoadBalancerFirewallRelationOwnerUID] = string(snapshot.uid)
		if commitErr := snapshot.commit(ctx, values); commitErr != nil {
			return false, fmt.Errorf(
				"node load balancer: bind legacy %s firewall relation receipt to owner UID: %w",
				owner.description,
				commitErr,
			)
		}
		return false, nil
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, fmt.Errorf("node load balancer: list firewalls for %s relation fence: %w", owner.description, err)
	}

	type outcome int
	const (
		outcomeConverged outcome = iota
		outcomePending
		outcomePreDispatchProof
		outcomeCleared
		outcomeIssued
	)
	result := outcomeConverged
	var issuedFence *nodeLoadBalancerFirewallRelationFence
	confirmRemovalImmediately := false
	retryPreDispatchProofImmediately := false
	values := copyNodeLoadBalancerAnnotations(snapshot.annotations)
	changed := false
	existingValue := values[annotationNodeLoadBalancerFirewallRelationIssued]
	existingOwnerUID := values[annotationNodeLoadBalancerFirewallRelationOwnerUID]
	if existingValue != "" {
		if existingOwnerUID != string(snapshot.uid) {
			return false, fmt.Errorf(
				"node load balancer: %s firewall relation receipt owner UID %q does not match live UID %q",
				owner.description,
				existingOwnerUID,
				snapshot.uid,
			)
		}
		existing, parseErr := parseNodeLoadBalancerFirewallRelationFence(existingValue)
		if parseErr != nil {
			return false, parseErr
		}
		converged, readbackErr := nodeLoadBalancerFirewallRelationConverged(existing, items)
		if readbackErr != nil {
			return false, readbackErr
		}
		cleared, observationChanged, observationErr := advanceNodeLoadBalancerFirewallRelationObservation(
			values,
			existing,
			converged,
			c.nodeLoadBalancerFirewallRelationTime(),
			c.nodeLoadBalancerFirewallRelationAbsenceDelay(),
		)
		if observationErr != nil {
			return false, observationErr
		}
		changed = observationChanged
		if cleared {
			result = outcomeCleared
		} else {
			result = outcomePending
			confirmRemovalImmediately = existing.operation == nodeLoadBalancerFirewallRelationUnassign &&
				converged && existing.absenceObservedAt == "" &&
				c.nodeLoadBalancerFirewallRelationAbsenceDelay() == 0
		}
	} else if existingOwnerUID != "" {
		return false, fmt.Errorf(
			"node load balancer: %s has an orphan firewall relation owner UID receipt %q",
			owner.description,
			existingOwnerUID,
		)
	} else if desired != nil {
		converged, readbackErr := nodeLoadBalancerFirewallRelationConverged(*desired, items)
		if readbackErr != nil {
			return false, readbackErr
		}
		if converged {
			if values[annotationNodeLoadBalancerFirewallRelationVMAbsent] != "" {
				delete(values, annotationNodeLoadBalancerFirewallRelationVMAbsent)
				changed = true
				result = outcomeCleared
			}
		} else {
			issued := *desired
			readyToIssue := true
			if desired.operation == nodeLoadBalancerFirewallRelationUnassign {
				owned, absent, authorityErr := c.nodeLoadBalancerFirewallRelationVMCloudAuthority(ctx, desired.vmUUID)
				if authorityErr != nil {
					return false, authorityErr
				}
				if !owned {
					if !absent {
						return false, errors.New("node load balancer: unassign target VM is neither canonically owned nor absent")
					}
					observedAt, found, parseErr := parseNodeLoadBalancerFirewallRelationVMAbsence(
						values[annotationNodeLoadBalancerFirewallRelationVMAbsent],
						desired.firewallUUID,
						desired.vmUUID,
					)
					if parseErr != nil {
						return false, parseErr
					}
					now := c.nodeLoadBalancerFirewallRelationTime()
					if !found {
						values[annotationNodeLoadBalancerFirewallRelationVMAbsent] =
							encodeNodeLoadBalancerFirewallRelationVMAbsence(desired.firewallUUID, desired.vmUUID, now)
						changed = true
						readyToIssue = false
						result = outcomePreDispatchProof
						retryPreDispatchProofImmediately = c.nodeLoadBalancerFirewallRelationAbsenceDelay() == 0
					} else if now.Before(observedAt.Add(c.nodeLoadBalancerFirewallRelationAbsenceDelay())) {
						readyToIssue = false
						result = outcomePreDispatchProof
					} else {
						issued.targetAbsentAt = observedAt.Format(time.RFC3339Nano)
						delete(values, annotationNodeLoadBalancerFirewallRelationVMAbsent)
						changed = true
					}
				} else if values[annotationNodeLoadBalancerFirewallRelationVMAbsent] != "" {
					delete(values, annotationNodeLoadBalancerFirewallRelationVMAbsent)
					changed = true
				}
			} else if values[annotationNodeLoadBalancerFirewallRelationVMAbsent] != "" {
				delete(values, annotationNodeLoadBalancerFirewallRelationVMAbsent)
				changed = true
			}
			if readyToIssue {
				issueID, issueErr := newNodeLoadBalancerFirewallCreateIssuedToken()
				if issueErr != nil {
					return false, issueErr
				}
				issued.issueID = issueID
				issued.issuedAt = c.nodeLoadBalancerFirewallRelationTime().Format(time.RFC3339Nano)
				values[annotationNodeLoadBalancerFirewallRelationIssued] = issued.String()
				values[annotationNodeLoadBalancerFirewallRelationOwnerUID] = string(snapshot.uid)
				issuedFence = &issued
				result = outcomeIssued
				changed = true
			}
		}
	}
	if changed {
		if err := snapshot.commit(ctx, values); err != nil {
			return false, fmt.Errorf("node load balancer: persist %s firewall relation fence: %w", owner.description, err)
		}
	}
	if confirmRemovalImmediately {
		// Unit controllers use a zero delay while still requiring a second fresh
		// cloud observation. Production controllers always use the configured
		// convergence interval installed by newNodeLoadBalancerController.
		return c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, nil)
	}
	if retryPreDispatchProofImmediately {
		// Zero-delay unit controllers still perform two complete cloud
		// observations, separated by the durable owner CAS above.
		return c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, desired)
	}

	switch result {
	case outcomeConverged:
		finalOwner, readErr := owner.read(ctx)
		if readErr != nil {
			return false, fmt.Errorf("node load balancer: re-read converged %s firewall relation owner: %w", owner.description, readErr)
		}
		if finalOwner.uid != snapshot.uid {
			return false, errors.New("node load balancer: firewall relation owner UID changed during converged readback")
		}
		for _, key := range []string{
			annotationNodeLoadBalancerFirewallRelationIssued,
			annotationNodeLoadBalancerFirewallRelationOwnerUID,
			annotationNodeLoadBalancerFirewallRelationVMAbsent,
		} {
			if finalOwner.annotations[key] != snapshot.annotations[key] {
				return false, errors.New("node load balancer: firewall relation receipt changed during converged readback")
			}
		}
		return true, nil
	case outcomePending:
		return false, fmt.Errorf(
			"node load balancer: %s firewall relation mutation %s remains ambiguous; waiting for authoritative cloud readback",
			owner.description,
			mustNodeLoadBalancerFirewallRelationFenceValue(owner, desired),
		)
	case outcomePreDispatchProof:
		return false, errors.New("node load balancer: waiting for spaced exact VM-absence authority before firewall detach")
	case outcomeCleared:
		// The cloud relationship was authoritatively re-read before this exact
		// Kubernetes fence was cleared. Stop this pass: when desired is non-nil,
		// it may describe a different logical relationship than the completed
		// attempt (for example after a concurrent Service update). A fresh pass
		// must read both owner and cloud state again before claiming convergence.
		return false, nil
	case outcomeIssued:
		// Continue below. Only the controller that successfully persisted this
		// exact resourceVersion is authorized to cross the cloud boundary.
		if issuedFence == nil {
			return false, errors.New("node load balancer: firewall relation issue identity is absent")
		}
	default:
		return false, errors.New("node load balancer: invalid firewall relation fence outcome")
	}
	if owner.authorize == nil {
		return false, fmt.Errorf("node load balancer: %s firewall relation has no pre-dispatch authority", owner.description)
	}
	issuedOwnerUID := snapshot.uid
	rejectUndispatched := func(authorityErr error) (bool, error) {
		rejection := fmt.Errorf(
			"node load balancer: reject %s firewall relation mutation %s at final pre-dispatch authority: %w",
			owner.description,
			issuedFence,
			authorityErr,
		)
		clearErr := clearNodeLoadBalancerFirewallRelationFence(ctx, owner, issuedOwnerUID, *issuedFence)
		if clearErr != nil {
			clearErr = fmt.Errorf("node load balancer: clear proven-undispatched %s firewall relation fence: %w", owner.description, clearErr)
		}
		return false, errors.Join(rejection, clearErr)
	}
	authorityBefore, err := exactNodeLoadBalancerFirewallFromItems(items, issuedFence.firewallUUID)
	if err != nil {
		return rejectUndispatched(fmt.Errorf("capture %s firewall relation issue authority: %w", owner.description, err))
	}
	if err := owner.authorize(ctx, *issuedFence, *authorityBefore); err != nil {
		// No cloud request was dispatched. The requested relation therefore
		// cannot converge and an issued receipt would suppress every future
		// attempt forever. Clear only this exact CAS-owned issue; concurrent
		// replacement is preserved by clearNodeLoadBalancerFirewallRelationFence.
		return rejectUndispatched(err)
	}
	// The policy/VM authority above may perform several reads. Re-read the
	// durable owner last so a stale controller cannot dispatch after another
	// reconciler cleared or replaced its one-shot receipt.
	finalOwner, err := owner.read(ctx)
	if err != nil {
		return rejectUndispatched(fmt.Errorf("re-read exact issued receipt: %w", err))
	}
	if finalOwner.uid != issuedOwnerUID ||
		finalOwner.annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != string(issuedOwnerUID) {
		return rejectUndispatched(errors.New("firewall relation owner UID changed during final authority"))
	}
	finalFence, err := parseNodeLoadBalancerFirewallRelationFence(
		finalOwner.annotations[annotationNodeLoadBalancerFirewallRelationIssued],
	)
	if err != nil || !sameNodeLoadBalancerFirewallRelationIssue(finalFence, *issuedFence) {
		return rejectUndispatched(errors.Join(
			errors.New("exact issued receipt changed during final authority"),
			err,
		))
	}

	var mutationErr error
	if issuedFence.operation == nodeLoadBalancerFirewallRelationAssign {
		mutationErr = c.provider.api.AssignFirewallToVM(ctx, c.provider.config.Location, issuedFence.firewallUUID, issuedFence.vmUUID)
	} else {
		mutationErr = c.provider.api.UnassignFirewallFromVM(ctx, c.provider.config.Location, issuedFence.firewallUUID, issuedFence.vmUUID)
	}
	if errors.Is(mutationErr, inspace.ErrMutationBlocked) {
		// The SDK produced this typed error before dispatch. Clear only the exact
		// UID-pinned receipt using a detached bounded context; a canceled caller
		// must not strand authority that provably never crossed the HTTP boundary.
		clearErr := clearNodeLoadBalancerFirewallRelationFence(ctx, owner, issuedOwnerUID, *issuedFence)
		return false, errors.Join(
			fmt.Errorf("node load balancer: %s firewall relation mutation %s was blocked before dispatch: %w", owner.description, issuedFence, mutationErr),
			clearErr,
		)
	}
	if mutationErr == nil {
		// A successful response is still not authoritative state. Perform one
		// fresh readback; if the provider is eventually consistent, retain the
		// fence and let a later reconciliation resolve it without another call.
		_, readbackErr := c.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, nil)
		if readbackErr != nil {
			return false, readbackErr
		}
		// Even when the provider readback was immediate and cleared the fence,
		// the caller must stop this pass so readiness/publication cannot consume
		// a pre-mutation snapshot.
		return false, nil
	}

	// No HTTP status is sufficient evidence that an already-dispatched relation
	// mutation did not commit. Re-read the exact firewall relationship first. A
	// read failure preserves the issued owner fence, including for ordinary 4xx.
	items, readbackErr := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if readbackErr != nil {
		return false, errors.Join(
			fmt.Errorf("node load balancer: %s firewall relation mutation %s returned an error: %w", owner.description, issuedFence, mutationErr),
			fmt.Errorf("node load balancer: authoritative firewall relation readback: %w", readbackErr),
		)
	}
	cleared, observationErr := c.observeNodeLoadBalancerFirewallRelationIssue(
		ctx,
		owner,
		issuedOwnerUID,
		*issuedFence,
		items,
		c.nodeLoadBalancerFirewallRelationTime(),
	)
	if observationErr != nil {
		return false, errors.Join(mutationErr, observationErr)
	}
	if cleared {
		// The error reported a committed mutation. Assignment has positive proof;
		// removal has two durable, spaced absence observations. The caller still
		// stops this pass and refreshes all other state before publication/cleanup.
		return false, nil
	}
	return false, fmt.Errorf("node load balancer: %s firewall relation mutation %s is ambiguous: %w", owner.description, issuedFence, mutationErr)
}

func (c *nodeLoadBalancerController) observeNodeLoadBalancerFirewallRelationIssue(
	ctx context.Context,
	owner nodeLoadBalancerFirewallRelationOwner,
	expectedOwnerUID types.UID,
	expected nodeLoadBalancerFirewallRelationFence,
	items []inspace.Firewall,
	now time.Time,
) (bool, error) {
	snapshot, err := owner.read(ctx)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read %s firewall relation owner after mutation: %w", owner.description, err)
	}
	if expectedOwnerUID == "" || snapshot.uid != expectedOwnerUID ||
		snapshot.annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != string(expectedOwnerUID) {
		return false, errors.New("node load balancer: firewall relation owner UID changed before authoritative-outcome observation")
	}
	storedValue := snapshot.annotations[annotationNodeLoadBalancerFirewallRelationIssued]
	stored, err := parseNodeLoadBalancerFirewallRelationFence(storedValue)
	if err != nil {
		return false, err
	}
	if !sameNodeLoadBalancerFirewallRelationIssue(stored, expected) {
		return false, errors.New("node load balancer: firewall relation issue changed before authoritative-outcome observation")
	}
	converged, err := nodeLoadBalancerFirewallRelationConverged(stored, items)
	if err != nil {
		return false, err
	}
	values := copyNodeLoadBalancerAnnotations(snapshot.annotations)
	cleared, changed, err := advanceNodeLoadBalancerFirewallRelationObservation(
		values,
		stored,
		converged,
		now,
		c.nodeLoadBalancerFirewallRelationAbsenceDelay(),
	)
	if err != nil || !changed {
		return cleared, err
	}
	if err := snapshot.commit(ctx, values); err != nil {
		return false, fmt.Errorf("node load balancer: persist %s firewall relation observation: %w", owner.description, err)
	}
	return cleared, nil
}

func clearNodeLoadBalancerFirewallRelationFence(
	ctx context.Context,
	owner nodeLoadBalancerFirewallRelationOwner,
	expectedOwnerUID types.UID,
	issued nodeLoadBalancerFirewallRelationFence,
) error {
	clearCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	clearSnapshot, err := owner.read(clearCtx)
	if err != nil {
		return err
	}
	if expectedOwnerUID == "" || clearSnapshot.uid != expectedOwnerUID ||
		clearSnapshot.annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != string(expectedOwnerUID) {
		return errors.New("firewall relation owner UID changed before authoritative-outcome clearance")
	}
	stored, parseErr := parseNodeLoadBalancerFirewallRelationFence(
		clearSnapshot.annotations[annotationNodeLoadBalancerFirewallRelationIssued],
	)
	if parseErr != nil || !sameNodeLoadBalancerFirewallRelationIssue(stored, issued) {
		return errors.New("firewall relation fence changed before authoritative-outcome clearance")
	}
	clearValues := copyNodeLoadBalancerAnnotations(clearSnapshot.annotations)
	delete(clearValues, annotationNodeLoadBalancerFirewallRelationIssued)
	delete(clearValues, annotationNodeLoadBalancerFirewallRelationOwnerUID)
	return clearSnapshot.commit(clearCtx, clearValues)
}

func mustNodeLoadBalancerFirewallRelationFenceValue(
	owner nodeLoadBalancerFirewallRelationOwner,
	desired *nodeLoadBalancerFirewallRelationFence,
) string {
	if desired != nil {
		return desired.String()
	}
	return "owned by " + owner.description
}

func nodeLoadBalancerFirewallAssignmentVMs(firewall inspace.Firewall) ([]string, error) {
	set, err := nodeLoadBalancerFirewallVMAssignments(firewall)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(set))
	for vmUUID := range set {
		result = append(result, vmUUID)
	}
	sort.Strings(result)
	return result, nil
}
