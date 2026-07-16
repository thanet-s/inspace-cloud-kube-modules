package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	annotationNodeLoadBalancerICMPFirewallUUID   = "service.inspace.cloud/node-lb-icmp-firewall-uuid"
	annotationNodeLoadBalancerICMPPendingUUID    = "service.inspace.cloud/node-lb-icmp-pending-firewall-uuid"
	annotationNodeLoadBalancerICMPPendingName    = "service.inspace.cloud/node-lb-icmp-pending-firewall-name"
	annotationNodeLoadBalancerICMPPendingStarted = "service.inspace.cloud/node-lb-icmp-pending-firewall-started-at"
	annotationNodeLoadBalancerICMPCreateIssued   = "service.inspace.cloud/node-lb-icmp-create-issued-at"
	annotationNodeLoadBalancerICMPAbsent         = "service.inspace.cloud/node-lb-icmp-firewall-absence-count"
	annotationNodeLoadBalancerICMPAbsentChecked  = "service.inspace.cloud/node-lb-icmp-firewall-absence-checked-at"
	annotationNodeLoadBalancerICMPCleanupAbsent  = "service.inspace.cloud/node-lb-icmp-cleanup-absence-count"
	annotationNodeLoadBalancerICMPCleanupChecked = "service.inspace.cloud/node-lb-icmp-cleanup-absence-checked-at"
	nodeLoadBalancerICMPFirewallDescription      = "Managed InSpace node load balancer cluster ICMP firewall"
)

func desiredNodeLoadBalancerClusterICMPFirewall(cluster string, billingAccountID int64) (desiredNodeLoadBalancerFirewall, error) {
	if cluster == "" || billingAccountID < 1 {
		return desiredNodeLoadBalancerFirewall{}, errors.New("node load balancer: cluster identity and billing account are required for the ICMP firewall")
	}
	rules := []inspace.FirewallRule{{
		Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any",
	}}
	name, hash, err := inspace.NodeLoadBalancerClusterICMPFirewallName(cluster, rules)
	if err != nil {
		return desiredNodeLoadBalancerFirewall{}, err
	}
	return desiredNodeLoadBalancerFirewall{
		Request: inspace.CreateFirewallRequest{
			DisplayName:      name,
			Description:      nodeLoadBalancerICMPFirewallDescription,
			BillingAccountID: billingAccountID,
			Rules:            rules,
		},
		Hash: hash,
	}, nil
}

func nodeLoadBalancerICMPFirewallSpecHash(rules []inspace.FirewallRule) (string, error) {
	return inspace.NodeLoadBalancerClusterICMPFirewallSpecHash(rules)
}

func nodeLoadBalancerClusterICMPFirewallOwned(firewall inspace.Firewall, cluster string, billingAccountID int64) bool {
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(cluster, billingAccountID)
	return err == nil && firewall.EffectiveName() == desired.Request.DisplayName &&
		inspace.ValidateNodeLoadBalancerClusterICMPFirewall(firewall, cluster, billingAccountID) == nil &&
		nodeLoadBalancerFirewallMatches(firewall, desired)
}

func (c *nodeLoadBalancerController) currentClusterICMPFirewall(
	ctx context.Context,
	items []inspace.Firewall,
) (*inspace.Firewall, error) {
	nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
	nodeClass, err := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if nodeClass.GetDeletionTimestamp() != nil {
		return nil, fmt.Errorf("node load balancer: managed NodeClass %q is deleting", nodeClassName)
	}
	uuid := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
	if uuid == "" {
		return nil, nil
	}
	if !validNodeLoadBalancerCloudUUID(uuid) {
		return nil, fmt.Errorf("node load balancer: invalid current cluster ICMP firewall UUID %q", uuid)
	}
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(c.provider.config.ClusterID, c.provider.config.BillingAccountID)
	if err != nil {
		return nil, err
	}
	var current *inspace.Firewall
	var byName *inspace.Firewall
	for i := range items {
		item := items[i]
		if item.EffectiveName() == desired.Request.DisplayName {
			if byName != nil {
				return nil, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
			}
			if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return nil, fmt.Errorf("node load balancer: managed cluster ICMP name is occupied by a foreign or changed firewall")
			}
			copy := item
			byName = &copy
		}
		if item.UUID != uuid {
			continue
		}
		if current != nil {
			return nil, fmt.Errorf("node load balancer: cluster ICMP firewall UUID %s appears multiple times", uuid)
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return nil, fmt.Errorf("node load balancer: current cluster ICMP firewall %s lost exact ownership", uuid)
		}
		copy := item
		current = &copy
	}
	if byName != nil && (current == nil || byName.UUID != current.UUID) {
		return nil, fmt.Errorf(
			"node load balancer: persisted cluster ICMP firewall %s is absent or differs while managed name %q resolves to UUID %s",
			uuid, desired.Request.DisplayName, byName.UUID,
		)
	}
	return current, nil
}

// ensureClusterICMPFirewall converges one durable, cluster-owned ICMP policy
// and reuses it on every authoritative Node-LB VM. Creation intent is persisted
// on the managed NodeClass before the billable API mutation, so an ambiguous
// response cannot result in a duplicate create after restart.
func (c *nodeLoadBalancerController) ensureClusterICMPFirewall(
	ctx context.Context,
	nodeClassName string,
	nodes []*corev1.Node,
) (*inspace.Firewall, bool, error) {
	nodeClass, err := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
	if err != nil {
		return nil, false, err
	}
	if nodeClass.GetDeletionTimestamp() != nil {
		return nil, false, fmt.Errorf("node load balancer: managed NodeClass %q is deleting", nodeClassName)
	}
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(c.provider.config.ClusterID, c.provider.config.BillingAccountID)
	if err != nil {
		return nil, false, err
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: list cluster ICMP firewalls: %w", err)
	}

	annotations := nodeClass.GetAnnotations()
	currentUUID := annotations[annotationNodeLoadBalancerICMPFirewallUUID]
	pendingUUID := annotations[annotationNodeLoadBalancerICMPPendingUUID]
	pendingName := annotations[annotationNodeLoadBalancerICMPPendingName]
	pendingStarted := annotations[annotationNodeLoadBalancerICMPPendingStarted]
	createIssued := annotations[annotationNodeLoadBalancerICMPCreateIssued]
	if currentUUID != "" && !validNodeLoadBalancerCloudUUID(currentUUID) {
		return nil, false, fmt.Errorf("node load balancer: invalid persisted cluster ICMP firewall UUID %q", currentUUID)
	}
	if pendingUUID != "" && !validNodeLoadBalancerCloudUUID(pendingUUID) {
		return nil, false, fmt.Errorf("node load balancer: invalid pending cluster ICMP firewall UUID %q", pendingUUID)
	}
	if pendingName != "" && pendingName != desired.Request.DisplayName {
		return nil, false, fmt.Errorf("node load balancer: persisted cluster ICMP firewall name %q does not match %q", pendingName, desired.Request.DisplayName)
	}
	if pendingUUID != "" && pendingName == "" {
		return nil, false, errors.New("node load balancer: pending cluster ICMP firewall UUID lacks create identity")
	}
	if pendingName != "" && pendingStarted == "" {
		return nil, false, errors.New("node load balancer: pending cluster ICMP firewall name lacks create timestamp")
	}
	if createIssued != "" && pendingName == "" {
		return nil, false, errors.New("node load balancer: issued cluster ICMP firewall create lacks pending identity")
	}
	var byName, byCurrentUUID, byPendingUUID *inspace.Firewall
	for i := range items {
		item := items[i]
		if currentUUID != "" && item.UUID == currentUUID {
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return nil, false, fmt.Errorf("node load balancer: persisted cluster ICMP firewall %s lost exact ownership", item.UUID)
			}
			copy := item
			byCurrentUUID = &copy
		}
		if pendingUUID != "" && item.UUID == pendingUUID {
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return nil, false, fmt.Errorf("node load balancer: pending cluster ICMP firewall %s lost exact ownership", item.UUID)
			}
			copy := item
			byPendingUUID = &copy
		}
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if byName != nil {
			return nil, false, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return nil, false, fmt.Errorf("node load balancer: cluster ICMP firewall name %q is occupied by a foreign or changed resource", desired.Request.DisplayName)
		}
		copy := item
		byName = &copy
	}
	if currentUUID != "" && byName != nil && byName.UUID != currentUUID {
		return nil, false, fmt.Errorf(
			"node load balancer: persisted cluster ICMP firewall %s is absent while managed name resolves to different UUID %s",
			currentUUID, byName.UUID,
		)
	}
	if pendingUUID != "" && byName != nil && byName.UUID != pendingUUID {
		return nil, false, fmt.Errorf(
			"node load balancer: pending cluster ICMP firewall %s is absent while managed name resolves to different UUID %s",
			pendingUUID, byName.UUID,
		)
	}

	var firewall *inspace.Firewall
	switch {
	case currentUUID != "":
		firewall = byCurrentUUID
	case pendingUUID != "":
		firewall = byPendingUUID
	default:
		firewall = byName
	}

	if pendingName != "" {
		if firewall == nil {
			if createIssued != "" {
				return nil, false, fmt.Errorf(
					"node load balancer: cluster ICMP firewall create issued at %s remains ambiguous; refusing a second paid create until the original firewall is observable or manually resolved",
					createIssued,
				)
			}
			// The pending identity was persisted, but POST authority was never
			// durably issued. It is safe to discard this staged-only intent; a later
			// reconciliation may create a fresh one.
			_, clearErr := c.clearManagedNodeClassICMPAnnotations(
				ctx, nodeClassName,
				map[string]string{
					annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
					annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
					annotationNodeLoadBalancerICMPPendingName:    pendingName,
					annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
					annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
				},
				annotationNodeLoadBalancerICMPPendingUUID, annotationNodeLoadBalancerICMPPendingName,
				annotationNodeLoadBalancerICMPPendingStarted, annotationNodeLoadBalancerICMPCreateIssued,
				annotationNodeLoadBalancerICMPAbsent,
				annotationNodeLoadBalancerICMPAbsentChecked,
			)
			return nil, false, clearErr
		}
		if pendingUUID != "" && pendingUUID != firewall.UUID {
			return nil, false, fmt.Errorf("node load balancer: pending cluster ICMP firewall UUID %s resolved to %s", pendingUUID, firewall.UUID)
		}
		if pendingUUID == "" {
			_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPPendingUUID] = firewall.UUID
			})
			return nil, false, err
		}
		_, err := c.promoteClusterICMPFirewall(ctx, nodeClassName, firewall.UUID)
		return nil, false, err
	}

	if firewall == nil && currentUUID != "" {
		confirmed, _, err := c.recordNodeClassFirewallAbsence(
			ctx, nodeClassName,
			annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
			time.Now().UTC(), time.Time{},
		)
		if err != nil || !confirmed {
			return nil, false, err
		}
		_, err = c.clearManagedNodeClassICMPAnnotations(
			ctx, nodeClassName,
			map[string]string{
				annotationNodeLoadBalancerICMPFirewallUUID: currentUUID,
				annotationNodeLoadBalancerICMPPendingUUID:  pendingUUID,
				annotationNodeLoadBalancerICMPPendingName:  pendingName,
			},
			annotationNodeLoadBalancerICMPFirewallUUID,
			annotationNodeLoadBalancerICMPAbsent,
			annotationNodeLoadBalancerICMPAbsentChecked,
		)
		return nil, false, err
	}

	if firewall == nil {
		started := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			values[annotationNodeLoadBalancerICMPPendingName] = desired.Request.DisplayName
			values[annotationNodeLoadBalancerICMPPendingStarted] = started
			delete(values, annotationNodeLoadBalancerICMPPendingUUID)
			delete(values, annotationNodeLoadBalancerICMPCreateIssued)
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		}); err != nil {
			return nil, false, err
		}
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			values[annotationNodeLoadBalancerICMPCreateIssued] = issuedAt
		}); err != nil {
			return nil, false, err
		}
		created, err := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
		if err != nil {
			if definitiveNodeLoadBalancerCreateFailure(err) {
				_, clearErr := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
					delete(values, annotationNodeLoadBalancerICMPPendingName)
					delete(values, annotationNodeLoadBalancerICMPPendingStarted)
					delete(values, annotationNodeLoadBalancerICMPCreateIssued)
				})
				return nil, false, errors.Join(fmt.Errorf("node load balancer: create cluster ICMP firewall: %w", err), clearErr)
			}
			return nil, false, fmt.Errorf("node load balancer: create cluster ICMP firewall: %w", err)
		}
		if err := validateCreatedNodeLoadBalancerFirewall(created, desired); err != nil {
			return nil, false, fmt.Errorf("node load balancer: created cluster ICMP firewall response: %w", err)
		}
		_, err = c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			values[annotationNodeLoadBalancerICMPPendingUUID] = created.UUID
		})
		return nil, false, err
	}

	if currentUUID != firewall.UUID {
		_, err := c.promoteClusterICMPFirewall(ctx, nodeClassName, firewall.UUID)
		return nil, false, err
	}
	if annotations[annotationNodeLoadBalancerICMPAbsent] != "" ||
		annotations[annotationNodeLoadBalancerICMPAbsentChecked] != "" {
		_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
		})
		return nil, false, err
	}
	if annotations[annotationNodeLoadBalancerICMPCleanupAbsent] != "" ||
		annotations[annotationNodeLoadBalancerICMPCleanupChecked] != "" {
		_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		})
		return nil, false, err
	}

	desiredVMs := make(map[string]struct{}, len(nodes))
	assignmentsReady := true
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			assignmentsReady = false
			continue
		}
		desiredVMs[vmUUID] = struct{}{}
		if !firewallAssignedToVM(*firewall, vmUUID) {
			// Never attach a firewall while this VM is publicly advertised. An
			// externally removed assignment is recovered in two passes: the caller
			// first withdraws the protected ready label/status, then the next pass
			// performs the attachment while the VM is closed.
			if node.Labels[nodeLoadBalancerReadyLabel] == "true" {
				assignmentsReady = false
				continue
			}
			if err := c.provider.api.AssignFirewallToVM(ctx, c.provider.config.Location, firewall.UUID, vmUUID); err != nil {
				return nil, false, fmt.Errorf("node load balancer: assign cluster ICMP firewall %s to VM %s: %w", firewall.UUID, vmUUID, err)
			}
			assignmentsReady = false
		}
	}
	stale, err := staleNodeLoadBalancerFirewallAssignments(*firewall, desiredVMs)
	if err != nil {
		return nil, false, err
	}
	for _, vmUUID := range stale {
		if err := c.provider.api.UnassignFirewallFromVM(ctx, c.provider.config.Location, firewall.UUID, vmUUID); err != nil && !inspace.IsNotFound(err) {
			return nil, false, fmt.Errorf("node load balancer: unassign cluster ICMP firewall %s from stale VM %s: %w", firewall.UUID, vmUUID, err)
		}
		assignmentsReady = false
	}
	return firewall, assignmentsReady, nil
}

func (c *nodeLoadBalancerController) getManagedNodeLoadBalancerNodeClass(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	object, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: get managed NodeClass %q: %w", name, err)
	}
	labels := object.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" || labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID {
		return nil, fmt.Errorf("node load balancer: NodeClass %q lacks exact cluster ownership", name)
	}
	if !containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return nil, fmt.Errorf("node load balancer: NodeClass %q lacks its cluster-state finalizer", name)
	}
	return object, nil
}

func (c *nodeLoadBalancerController) updateManagedNodeClassAnnotations(
	ctx context.Context,
	name string,
	mutate func(map[string]string),
) (bool, error) {
	object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, err
	}
	before := object.GetAnnotations()
	values := make(map[string]string, len(before))
	for key, value := range before {
		values[key] = value
	}
	mutate(values)
	if mapsEqualStringString(before, values) {
		return false, nil
	}
	copy := object.DeepCopy()
	copy.SetAnnotations(values)
	if _, err := c.provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: update cluster ICMP firewall state: %w", err)
	}
	return true, nil
}

// clearManagedNodeClassICMPAnnotations clears a completed transaction only if
// the exact persisted identities observed before the absence proof are still
// present. The fresh GET plus optimistic Update prevents a concurrent
// reconciliation from orphaning a newly persisted firewall identity.
func (c *nodeLoadBalancerController) clearManagedNodeClassICMPAnnotations(
	ctx context.Context,
	name string,
	expected map[string]string,
	keys ...string,
) (bool, error) {
	object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, err
	}
	before := object.GetAnnotations()
	for key, value := range expected {
		if before[key] != value {
			return false, fmt.Errorf("node load balancer: cluster ICMP firewall identity changed during absence proof")
		}
	}
	values := make(map[string]string, len(before))
	for key, value := range before {
		values[key] = value
	}
	for _, key := range keys {
		delete(values, key)
	}
	if mapsEqualStringString(before, values) {
		return false, nil
	}
	copy := object.DeepCopy()
	copy.SetAnnotations(values)
	if _, err := c.provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("node load balancer: clear cluster ICMP firewall state: %w", err)
	}
	return true, nil
}

func mapsEqualStringString(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (c *nodeLoadBalancerController) promoteClusterICMPFirewall(ctx context.Context, nodeClassName, uuid string) (bool, error) {
	return c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
		values[annotationNodeLoadBalancerICMPFirewallUUID] = uuid
		for _, key := range []string{
			annotationNodeLoadBalancerICMPPendingUUID, annotationNodeLoadBalancerICMPPendingName,
			annotationNodeLoadBalancerICMPPendingStarted, annotationNodeLoadBalancerICMPCreateIssued,
			annotationNodeLoadBalancerICMPAbsent,
			annotationNodeLoadBalancerICMPAbsentChecked, annotationNodeLoadBalancerICMPCleanupAbsent,
			annotationNodeLoadBalancerICMPCleanupChecked,
		} {
			delete(values, key)
		}
	})
}

func (c *nodeLoadBalancerController) recordNodeClassFirewallAbsence(
	ctx context.Context,
	nodeClassName, countAnnotation, checkedAnnotation string,
	now, notBefore time.Time,
) (confirmed, changed bool, err error) {
	if now.Before(notBefore) {
		return false, false, nil
	}
	object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
	if err != nil {
		return false, false, err
	}
	annotations := object.GetAnnotations()
	count := 0
	if raw := annotations[countAnnotation]; raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 0 || parsed > nodeLoadBalancerAbsenceConfirmations {
			return false, false, fmt.Errorf("node load balancer: invalid cluster ICMP firewall absence count %q", raw)
		}
		count = parsed
	}
	if count >= nodeLoadBalancerAbsenceConfirmations {
		return true, false, nil
	}
	if raw := annotations[checkedAnnotation]; raw != "" {
		checkedAt, parseErr := time.Parse(time.RFC3339Nano, raw)
		if parseErr != nil {
			return false, false, fmt.Errorf("node load balancer: invalid cluster ICMP firewall absence timestamp: %w", parseErr)
		}
		if now.Before(checkedAt.Add(nodeLoadBalancerAbsenceConfirmationDelay)) {
			return false, false, nil
		}
	}
	changed, err = c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
		values[countAnnotation] = strconv.Itoa(count + 1)
		values[checkedAnnotation] = now.UTC().Format(time.RFC3339Nano)
	})
	return false, changed, err
}

func (c *nodeLoadBalancerController) cleanupClusterICMPFirewall(ctx context.Context, nodeClassName string) (bool, error) {
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(c.provider.config.ClusterID, c.provider.config.BillingAccountID)
	if err != nil {
		return false, err
	}
	nodeClass, nodeClassErr := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
	if nodeClassErr != nil && !apierrors.IsNotFound(nodeClassErr) {
		return false, nodeClassErr
	}
	annotations := map[string]string{}
	if nodeClass != nil {
		annotations = nodeClass.GetAnnotations()
	}
	currentUUID := annotations[annotationNodeLoadBalancerICMPFirewallUUID]
	pendingUUID := annotations[annotationNodeLoadBalancerICMPPendingUUID]
	pendingName := annotations[annotationNodeLoadBalancerICMPPendingName]
	pendingStarted := annotations[annotationNodeLoadBalancerICMPPendingStarted]
	createIssued := annotations[annotationNodeLoadBalancerICMPCreateIssued]
	if currentUUID != "" && !validNodeLoadBalancerCloudUUID(currentUUID) {
		return false, fmt.Errorf("node load balancer: invalid persisted cluster ICMP cleanup UUID %q", currentUUID)
	}
	if pendingUUID != "" && !validNodeLoadBalancerCloudUUID(pendingUUID) {
		return false, fmt.Errorf("node load balancer: invalid pending cluster ICMP cleanup UUID %q", pendingUUID)
	}
	if pendingName != "" && pendingName != desired.Request.DisplayName {
		return false, fmt.Errorf("node load balancer: persisted cluster ICMP cleanup name %q does not match %q", pendingName, desired.Request.DisplayName)
	}
	if pendingUUID != "" && pendingName == "" {
		return false, errors.New("node load balancer: pending cluster ICMP cleanup UUID lacks create identity")
	}
	if pendingName != "" && pendingStarted == "" {
		return false, errors.New("node load balancer: pending cluster ICMP cleanup identity lacks create timestamp")
	}
	if createIssued != "" && pendingName == "" {
		return false, errors.New("node load balancer: issued cluster ICMP cleanup create lacks pending identity")
	}
	if currentUUID != "" && pendingUUID != "" && currentUUID != pendingUUID {
		return false, errors.New("node load balancer: current and pending cluster ICMP cleanup UUIDs conflict")
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var byName, byCurrentUUID, byPendingUUID *inspace.Firewall
	for i := range items {
		item := items[i]
		if currentUUID != "" && item.UUID == currentUUID {
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return false, fmt.Errorf("node load balancer: refusing to clean persisted cluster ICMP firewall %s after ownership drift", item.UUID)
			}
			copy := item
			byCurrentUUID = &copy
		}
		if pendingUUID != "" && item.UUID == pendingUUID {
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return false, fmt.Errorf("node load balancer: refusing to clean pending cluster ICMP firewall %s after ownership drift", item.UUID)
			}
			copy := item
			byPendingUUID = &copy
		}
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if byName != nil {
			return false, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return false, fmt.Errorf("node load balancer: refusing to delete cluster ICMP firewall without exact ownership")
		}
		copy := item
		byName = &copy
	}
	if currentUUID != "" && byName != nil && byName.UUID != currentUUID {
		return false, fmt.Errorf(
			"node load balancer: refusing to clean managed cluster ICMP name at UUID %s; persisted UUID is %s",
			byName.UUID, currentUUID,
		)
	}
	if pendingUUID != "" && byName != nil && byName.UUID != pendingUUID {
		return false, fmt.Errorf(
			"node load balancer: refusing to clean managed cluster ICMP name at UUID %s; pending UUID is %s",
			byName.UUID, pendingUUID,
		)
	}

	var firewall *inspace.Firewall
	switch {
	case currentUUID != "":
		firewall = byCurrentUUID
	case pendingUUID != "":
		firewall = byPendingUUID
	default:
		firewall = byName
	}
	if firewall != nil {
		if nodeClass != nil && currentUUID == "" && pendingUUID != "" {
			if pendingUUID != firewall.UUID {
				return false, fmt.Errorf("node load balancer: pending cluster ICMP cleanup UUID %s resolved to %s", pendingUUID, firewall.UUID)
			}
			// Convert a create response/readback identity into the durable current
			// identity before DELETE. This clears the unresolved-create marker, so
			// a crash after deletion can finish through spaced exact-UUID absence
			// proof without ever authorizing another POST.
			_, err := c.promoteClusterICMPFirewall(ctx, nodeClassName, firewall.UUID)
			return false, err
		}
		if nodeClass != nil && currentUUID == "" && pendingName != "" && pendingUUID == "" {
			_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPPendingUUID] = firewall.UUID
				delete(values, annotationNodeLoadBalancerICMPAbsent)
				delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
			})
			return false, err
		}
		if nodeClass != nil && currentUUID == "" && pendingUUID == "" {
			// Bind a discovered legacy/exact-name resource to durable state before
			// issuing an irreversible delete. A restart can then only target this UUID.
			_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPFirewallUUID] = firewall.UUID
				delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
				delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
			})
			return false, err
		}
		if nodeClass != nil && (annotations[annotationNodeLoadBalancerICMPCleanupAbsent] != "" ||
			annotations[annotationNodeLoadBalancerICMPCleanupChecked] != "") {
			_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
				delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
			})
			return false, err
		}
		if len(firewall.ResourcesAssigned) != 0 {
			for _, resource := range firewall.ResourcesAssigned {
				if !stringsEqualFoldVMResource(resource) {
					return false, fmt.Errorf("node load balancer: cluster ICMP firewall has unexpected assigned resource %#v", resource)
				}
				if err := c.provider.api.UnassignFirewallFromVM(ctx, c.provider.config.Location, firewall.UUID, resource.ResourceUUID); err != nil && !inspace.IsNotFound(err) {
					return false, err
				}
			}
			return false, nil
		}
		if err := c.provider.api.DeleteFirewall(ctx, c.provider.config.Location, firewall.UUID); err != nil && !inspace.IsNotFound(err) {
			return false, err
		}
		return false, nil
	}

	if nodeClass == nil {
		return false, errors.New("node load balancer: managed NodeClass state anchor is absent during cluster ICMP cleanup")
	}
	if createIssued != "" {
		return false, fmt.Errorf(
			"node load balancer: cluster ICMP firewall create issued at %s remains ambiguous during cleanup; retaining the NodeClass finalizer until the original firewall is observable or manually resolved",
			createIssued,
		)
	}
	if pendingName != "" {
		_, clearErr := c.clearManagedNodeClassICMPAnnotations(
			ctx, nodeClassName,
			map[string]string{
				annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
				annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
				annotationNodeLoadBalancerICMPPendingName:    pendingName,
				annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
				annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
			},
			annotationNodeLoadBalancerICMPPendingUUID, annotationNodeLoadBalancerICMPPendingName,
			annotationNodeLoadBalancerICMPPendingStarted, annotationNodeLoadBalancerICMPCreateIssued,
			annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
			annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		)
		return false, clearErr
	}
	confirmed, _, err := c.recordNodeClassFirewallAbsence(
		ctx, nodeClassName,
		annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		time.Now().UTC(), time.Time{},
	)
	if err != nil || !confirmed {
		return false, err
	}
	_, err = c.clearManagedNodeClassICMPAnnotations(
		ctx, nodeClassName,
		map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
			annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
			annotationNodeLoadBalancerICMPPendingName:    pendingName,
			annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
			annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
		},
		annotationNodeLoadBalancerICMPFirewallUUID, annotationNodeLoadBalancerICMPPendingUUID,
		annotationNodeLoadBalancerICMPPendingName, annotationNodeLoadBalancerICMPPendingStarted,
		annotationNodeLoadBalancerICMPCreateIssued,
		annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
		annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
	)
	return err == nil, err
}

func stringsEqualFoldVMResource(resource inspace.FirewallResource) bool {
	return resource.ResourceUUID != "" && strings.EqualFold(resource.ResourceType, "vm")
}
