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
	uuid := nodeClass.GetAnnotations()[annotationNodeLoadBalancerICMPFirewallUUID]
	if uuid == "" {
		return nil, nil
	}
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall(c.provider.config.ClusterID, c.provider.config.BillingAccountID)
	if err != nil {
		return nil, err
	}
	var current *inspace.Firewall
	managedNameCount := 0
	for i := range items {
		item := items[i]
		if item.EffectiveName() == desired.Request.DisplayName {
			managedNameCount++
			if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return nil, fmt.Errorf("node load balancer: managed cluster ICMP name is occupied by a foreign or changed firewall")
			}
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
	if managedNameCount > 1 {
		return nil, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
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
	if pendingName != "" && pendingName != desired.Request.DisplayName {
		return nil, false, fmt.Errorf("node load balancer: persisted cluster ICMP firewall name %q does not match %q", pendingName, desired.Request.DisplayName)
	}

	var firewall *inspace.Firewall
	for i := range items {
		item := items[i]
		if (currentUUID != "" && item.UUID == currentUUID) || (pendingUUID != "" && item.UUID == pendingUUID) {
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return nil, false, fmt.Errorf("node load balancer: persisted cluster ICMP firewall %s lost exact ownership", item.UUID)
			}
		}
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if firewall != nil {
			return nil, false, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return nil, false, fmt.Errorf("node load balancer: cluster ICMP firewall name %q is occupied by a foreign or changed resource", desired.Request.DisplayName)
		}
		copy := item
		firewall = &copy
	}

	if pendingName != "" {
		if firewall == nil {
			started, parseErr := time.Parse(time.RFC3339Nano, annotations[annotationNodeLoadBalancerICMPPendingStarted])
			if parseErr != nil {
				return nil, false, fmt.Errorf("node load balancer: invalid cluster ICMP create timestamp: %w", parseErr)
			}
			confirmed, _, confirmErr := c.recordNodeClassFirewallAbsence(
				ctx, nodeClassName,
				annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
				time.Now().UTC(), started.Add(nodeLoadBalancerPendingCreateTimeout),
			)
			if confirmErr != nil || !confirmed {
				return nil, false, confirmErr
			}
			_, clearErr := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				for _, key := range []string{
					annotationNodeLoadBalancerICMPPendingUUID, annotationNodeLoadBalancerICMPPendingName,
					annotationNodeLoadBalancerICMPPendingStarted, annotationNodeLoadBalancerICMPAbsent,
					annotationNodeLoadBalancerICMPAbsentChecked,
				} {
					delete(values, key)
				}
			})
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
		_, err = c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPFirewallUUID)
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
		})
		return nil, false, err
	}

	if firewall == nil {
		started := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
			values[annotationNodeLoadBalancerICMPPendingName] = desired.Request.DisplayName
			values[annotationNodeLoadBalancerICMPPendingStarted] = started
			delete(values, annotationNodeLoadBalancerICMPPendingUUID)
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		}); err != nil {
			return nil, false, err
		}
		created, err := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
		if err != nil {
			if definitiveNodeLoadBalancerCreateFailure(err) {
				_, clearErr := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
					delete(values, annotationNodeLoadBalancerICMPPendingName)
					delete(values, annotationNodeLoadBalancerICMPPendingStarted)
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
	if object.GetDeletionTimestamp() != nil {
		return nil, fmt.Errorf("node load balancer: NodeClass %q is deleting", name)
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
			annotationNodeLoadBalancerICMPPendingStarted, annotationNodeLoadBalancerICMPAbsent,
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
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var firewall *inspace.Firewall
	for i := range items {
		if (currentUUID != "" && items[i].UUID == currentUUID) || (pendingUUID != "" && items[i].UUID == pendingUUID) {
			if !nodeLoadBalancerClusterICMPFirewallOwned(items[i], c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return false, fmt.Errorf("node load balancer: refusing to clean persisted cluster ICMP firewall %s after ownership drift", items[i].UUID)
			}
		}
		if items[i].EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if firewall != nil {
			return false, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q", desired.Request.DisplayName)
		}
		if !nodeLoadBalancerClusterICMPFirewallOwned(items[i], c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return false, fmt.Errorf("node load balancer: refusing to delete cluster ICMP firewall without exact ownership")
		}
		copy := items[i]
		firewall = &copy
	}
	if firewall != nil {
		if nodeClass != nil && (annotations[annotationNodeLoadBalancerICMPPendingName] != "" ||
			annotations[annotationNodeLoadBalancerICMPPendingUUID] != "" ||
			annotations[annotationNodeLoadBalancerICMPPendingStarted] != "") {
			_, err := c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPFirewallUUID] = firewall.UUID
				delete(values, annotationNodeLoadBalancerICMPPendingName)
				delete(values, annotationNodeLoadBalancerICMPPendingUUID)
				delete(values, annotationNodeLoadBalancerICMPPendingStarted)
				delete(values, annotationNodeLoadBalancerICMPAbsent)
				delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
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
		return true, nil
	}
	notBefore := time.Time{}
	if annotations[annotationNodeLoadBalancerICMPPendingName] != "" {
		started, parseErr := time.Parse(time.RFC3339Nano, annotations[annotationNodeLoadBalancerICMPPendingStarted])
		if parseErr != nil {
			return false, fmt.Errorf("node load balancer: invalid pending cluster ICMP create timestamp during cleanup: %w", parseErr)
		}
		notBefore = started.Add(nodeLoadBalancerPendingCreateTimeout)
	}
	confirmed, _, err := c.recordNodeClassFirewallAbsence(
		ctx, nodeClassName,
		annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		time.Now().UTC(), notBefore,
	)
	if err != nil || !confirmed {
		return false, err
	}
	_, err = c.updateManagedNodeClassAnnotations(ctx, nodeClassName, func(values map[string]string) {
		for _, key := range []string{
			annotationNodeLoadBalancerICMPFirewallUUID, annotationNodeLoadBalancerICMPPendingUUID,
			annotationNodeLoadBalancerICMPPendingName, annotationNodeLoadBalancerICMPPendingStarted,
			annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
			annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		} {
			delete(values, key)
		}
	})
	return err == nil, err
}

func stringsEqualFoldVMResource(resource inspace.FirewallResource) bool {
	return resource.ResourceUUID != "" && strings.EqualFold(resource.ResourceType, "vm")
}
