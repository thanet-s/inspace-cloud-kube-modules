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
	"k8s.io/apimachinery/pkg/types"

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
	annotationNodeLoadBalancerICMPDeleteTarget   = "service.inspace.cloud/node-lb-icmp-delete-target-uuid"
	annotationNodeLoadBalancerICMPDeleteIssued   = "service.inspace.cloud/node-lb-icmp-delete-issued-at"
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
	ownerUID := nodeClass.GetUID()
	if ownerUID == "" {
		return nil, false, fmt.Errorf("node load balancer: managed NodeClass %q has an empty UID", nodeClassName)
	}
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, ownerUID),
		nil,
	)
	if err != nil {
		return nil, false, err
	}
	if !converged {
		return nil, false, nil
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
	deleteTarget, _, receiptErr := nodeLoadBalancerFirewallDeleteReceipt(
		annotations,
		annotationNodeLoadBalancerICMPDeleteTarget,
		annotationNodeLoadBalancerICMPDeleteIssued,
		annotationNodeLoadBalancerICMPCleanupAbsent,
		annotationNodeLoadBalancerICMPCleanupChecked,
	)
	if receiptErr != nil {
		return nil, false, fmt.Errorf("node load balancer: parse cluster ICMP firewall delete receipt: %w", receiptErr)
	}
	if deleteTarget != "" {
		return nil, false, errors.New("node load balancer: cluster ICMP firewall deletion remains fenced")
	}
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
			_, clearErr := c.clearManagedNodeClassICMPAnnotationsForUID(
				ctx, nodeClassName, ownerUID,
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
			_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, ownerUID, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPPendingUUID] = firewall.UUID
			})
			return nil, false, err
		}
		_, err := c.promoteClusterICMPFirewallForUID(ctx, nodeClassName, ownerUID, firewall.UUID)
		return nil, false, err
	}

	if firewall == nil && currentUUID != "" {
		confirmed, _, err := c.recordNodeClassFirewallAbsenceForUID(
			ctx, nodeClassName, ownerUID,
			annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
			time.Now().UTC(), time.Time{},
		)
		if err != nil || !confirmed {
			return nil, false, err
		}
		_, err = c.clearManagedNodeClassICMPAnnotationsForUID(
			ctx, nodeClassName, ownerUID,
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
		staged, err := c.mutateManagedNodeClassICMPCreateForUID(ctx, nodeClassName, ownerUID, map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
			annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
			annotationNodeLoadBalancerICMPPendingName:    pendingName,
			annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
			annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
		}, func(values map[string]string) {
			values[annotationNodeLoadBalancerICMPPendingName] = desired.Request.DisplayName
			values[annotationNodeLoadBalancerICMPPendingStarted] = started
			delete(values, annotationNodeLoadBalancerICMPPendingUUID)
			delete(values, annotationNodeLoadBalancerICMPCreateIssued)
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		})
		if err != nil {
			return nil, false, err
		}
		if !staged {
			return nil, false, errors.New("node load balancer: cluster ICMP firewall create intent was not durably staged")
		}
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		expectedStaged := map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
			annotationNodeLoadBalancerICMPPendingUUID:    "",
			annotationNodeLoadBalancerICMPPendingName:    desired.Request.DisplayName,
			annotationNodeLoadBalancerICMPPendingStarted: started,
			annotationNodeLoadBalancerICMPCreateIssued:   "",
		}
		expectedCreate, err := c.issueManagedNodeClassICMPCreate(ctx, nodeClassName, ownerUID, expectedStaged, issuedAt)
		if err != nil {
			return nil, false, err
		}
		rejectUndispatched := func(rejection error) (*inspace.Firewall, bool, error) {
			return nil, false, errors.Join(
				rejection,
				c.resetManagedNodeClassICMPCreateAfterProvenNonDispatch(
					ctx,
					nodeClassName,
					ownerUID,
					expectedCreate,
				),
			)
		}
		observed, absent, authorityErr := c.exactNodeLoadBalancerFirewallNameFresh(ctx, desired.Request.DisplayName)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: authorize cluster ICMP firewall create after issue: %w", authorityErr))
		}
		if !absent {
			if observed == nil || !validNodeLoadBalancerCloudUUID(observed.UUID) ||
				!nodeLoadBalancerClusterICMPFirewallOwned(
					*observed,
					c.provider.config.ClusterID,
					c.provider.config.BillingAccountID,
				) {
				return rejectUndispatched(fmt.Errorf(
					"node load balancer: managed cluster ICMP name %q became foreign after create issue",
					desired.Request.DisplayName,
				))
			}
			committed, recoveryErr := c.resolveClusterICMPCreateReadback(
				ctx, nodeClassName, ownerUID, expectedCreate, desired,
			)
			if recoveryErr != nil {
				return rejectUndispatched(recoveryErr)
			}
			if !committed {
				return rejectUndispatched(errors.New("node load balancer: observed cluster ICMP firewall was not durably promoted"))
			}
			return nil, false, nil
		}
		// Deletion may begin after the issued create receipt was persisted.  A
		// fresh exact owner read immediately before POST prevents a deleting
		// NodeClass from authorizing a new paid cluster firewall.
		authorizedNodeClass, authorityErr := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: re-read cluster ICMP owner before create: %w", authorityErr))
		}
		if authorizedNodeClass.GetUID() != ownerUID || authorizedNodeClass.GetDeletionTimestamp() != nil {
			return rejectUndispatched(errors.New("node load balancer: cluster ICMP firewall create owner is deleting or changed identity"))
		}
		for key, value := range expectedCreate {
			if authorizedNodeClass.GetAnnotations()[key] != value {
				return rejectUndispatched(errors.New("node load balancer: cluster ICMP firewall create receipt changed after issue"))
			}
		}
		created, err := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
		if err != nil {
			createErr := fmt.Errorf("node load balancer: create cluster ICMP firewall: %w", err)
			if nodeLoadBalancerMutationKnownPreDispatch(err) {
				return nil, false, errors.Join(
					createErr,
					c.resetManagedNodeClassICMPCreateAfterProvenNonDispatch(
						ctx,
						nodeClassName,
						ownerUID,
						expectedCreate,
					),
				)
			}
			committed, recoveryErr := c.resolveClusterICMPCreateReadback(ctx, nodeClassName, ownerUID, expectedCreate, desired)
			if recoveryErr != nil {
				return nil, false, errors.Join(createErr, recoveryErr)
			}
			if committed {
				return nil, false, nil
			}
			return nil, false, createErr
		}
		if err := validateCreatedNodeLoadBalancerFirewall(created, desired); err != nil {
			responseErr := fmt.Errorf("node load balancer: created cluster ICMP firewall response: %w", err)
			committed, recoveryErr := c.resolveClusterICMPCreateReadback(ctx, nodeClassName, ownerUID, expectedCreate, desired)
			if recoveryErr != nil {
				return nil, false, errors.Join(responseErr, recoveryErr)
			}
			if committed {
				return nil, false, nil
			}
			return nil, false, responseErr
		}
		// The response UUID is provisional only. Canonical identity is promoted
		// exclusively from a unique deterministic-name ListFirewalls readback.
		committed, recoveryErr := c.resolveClusterICMPCreateReadback(
			ctx, nodeClassName, ownerUID, expectedCreate, desired,
		)
		if recoveryErr != nil {
			return nil, false, recoveryErr
		}
		if !committed {
			return nil, false, errors.New("node load balancer: cluster ICMP firewall create response lacks authoritative readback")
		}
		return nil, false, nil
	}

	if currentUUID != firewall.UUID {
		_, err := c.promoteClusterICMPFirewallForUID(ctx, nodeClassName, ownerUID, firewall.UUID)
		return nil, false, err
	}
	if annotations[annotationNodeLoadBalancerICMPAbsent] != "" ||
		annotations[annotationNodeLoadBalancerICMPAbsentChecked] != "" {
		_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, ownerUID, func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPAbsent)
			delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
		})
		return nil, false, err
	}
	if annotations[annotationNodeLoadBalancerICMPCleanupAbsent] != "" ||
		annotations[annotationNodeLoadBalancerICMPCleanupChecked] != "" {
		_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, ownerUID, func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		})
		return nil, false, err
	}

	desiredVMs := make(map[string]struct{}, len(nodes))
	assignments, err := nodeLoadBalancerFirewallVMAssignments(*firewall)
	if err != nil {
		return nil, false, err
	}
	assignmentsReady := true
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			assignmentsReady = false
			continue
		}
		desiredVMs[vmUUID] = struct{}{}
		if _, assigned := assignments[strings.ToLower(vmUUID)]; !assigned {
			// Never attach a firewall while this VM is publicly advertised. An
			// externally removed assignment is recovered in two passes: the caller
			// first withdraws the protected ready label/status, then the next pass
			// performs the attachment while the VM is closed.
			if node.Labels[nodeLoadBalancerReadyLabel] == "true" {
				assignmentsReady = false
				continue
			}
			converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, ownerUID),
				&nodeLoadBalancerFirewallRelationFence{
					operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
				},
			)
			if relationErr != nil {
				return nil, false, fmt.Errorf("node load balancer: assign cluster ICMP firewall %s to VM %s: %w", firewall.UUID, vmUUID, relationErr)
			}
			assignmentsReady = false
			if !converged {
				return firewall, false, nil
			}
		}
	}
	stale, err := staleNodeLoadBalancerFirewallAssignments(*firewall, desiredVMs)
	if err != nil {
		return nil, false, err
	}
	for _, vmUUID := range stale {
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, ownerUID),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if relationErr != nil {
			return nil, false, fmt.Errorf("node load balancer: unassign cluster ICMP firewall %s from stale VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		assignmentsReady = false
		if !converged {
			return firewall, false, nil
		}
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
	return c.updateManagedNodeClassAnnotationsForUID(ctx, name, "", mutate)
}

func (c *nodeLoadBalancerController) updateManagedNodeClassAnnotationsForUID(
	ctx context.Context,
	name string,
	expectedUID types.UID,
	mutate func(map[string]string),
) (bool, error) {
	object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, err
	}
	if expectedUID != "" && object.GetUID() != expectedUID {
		return false, fmt.Errorf("node load balancer: NodeClass %q identity changed before exact receipt transition", name)
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
	updated, err := c.provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("node load balancer: update cluster ICMP firewall state: %w", err)
	}
	if err := c.validateManagedNodeClassAnnotationWrite(updated, name, object.GetUID(), values); err != nil {
		return false, err
	}
	verified, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read back cluster ICMP firewall state: %w", err)
	}
	if err := c.validateManagedNodeClassAnnotationWrite(verified, name, object.GetUID(), values); err != nil {
		return false, err
	}
	return true, nil
}

func (c *nodeLoadBalancerController) validateManagedNodeClassAnnotationWrite(
	object *unstructured.Unstructured,
	name string,
	uid types.UID,
	expected map[string]string,
) error {
	if object == nil || object.GetName() != name {
		return fmt.Errorf("node load balancer: cluster ICMP firewall state update returned the wrong NodeClass identity")
	}
	if uid != "" && object.GetUID() != uid {
		return fmt.Errorf("node load balancer: NodeClass %q UID changed while persisting cluster ICMP firewall state", name)
	}
	labels := object.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" || labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		!containsString(object.GetFinalizers(), nodeLoadBalancerNodeClassFinalizer) {
		return fmt.Errorf("node load balancer: NodeClass %q lost exact ownership while persisting cluster ICMP firewall state", name)
	}
	if !mapsEqualStringString(object.GetAnnotations(), expected) {
		return fmt.Errorf("node load balancer: NodeClass %q did not retain the exact cluster ICMP firewall receipt", name)
	}
	return nil
}

func (c *nodeLoadBalancerController) mutateManagedNodeClassICMPCreate(
	ctx context.Context,
	name string,
	expected map[string]string,
	mutate func(map[string]string),
) (bool, error) {
	return c.mutateManagedNodeClassICMPCreateForUID(ctx, name, "", expected, mutate)
}

func (c *nodeLoadBalancerController) mutateManagedNodeClassICMPCreateForUID(
	ctx context.Context,
	name string,
	expectedUID types.UID,
	expected map[string]string,
	mutate func(map[string]string),
) (bool, error) {
	object, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, err
	}
	if expectedUID != "" && object.GetUID() != expectedUID {
		return false, fmt.Errorf("node load balancer: NodeClass %q identity changed before exact receipt transition", name)
	}
	before := object.GetAnnotations()
	for key, value := range expected {
		if before[key] != value {
			return false, fmt.Errorf("node load balancer: cluster ICMP firewall create receipt changed before exact transition")
		}
	}
	values := make(map[string]string, len(before)+1)
	for key, value := range before {
		values[key] = value
	}
	mutate(values)
	if mapsEqualStringString(before, values) {
		return false, nil
	}
	copy := object.DeepCopy()
	copy.SetAnnotations(values)
	updated, err := c.provider.dynamicClient.Resource(nodeClassGVR).Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("node load balancer: transition cluster ICMP firewall create receipt: %w", err)
	}
	if err := c.validateManagedNodeClassAnnotationWrite(updated, name, object.GetUID(), values); err != nil {
		return false, err
	}
	verified, err := c.getManagedNodeLoadBalancerNodeClass(ctx, name)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read back cluster ICMP firewall create receipt: %w", err)
	}
	if err := c.validateManagedNodeClassAnnotationWrite(verified, name, object.GetUID(), values); err != nil {
		return false, err
	}
	return true, nil
}

func (c *nodeLoadBalancerController) recordManagedNodeClassICMPCreateUUID(
	ctx context.Context,
	name string,
	ownerUID types.UID,
	expected map[string]string,
	uuid string,
) (bool, error) {
	if !validNodeLoadBalancerCloudUUID(uuid) {
		return false, fmt.Errorf("node load balancer: invalid cluster ICMP firewall create response UUID %q", uuid)
	}
	if ownerUID == "" {
		return false, errors.New("node load balancer: cluster ICMP create UUID transition lacks its exact NodeClass UID")
	}
	return c.mutateManagedNodeClassICMPCreateForUID(ctx, name, ownerUID, expected, func(values map[string]string) {
		values[annotationNodeLoadBalancerICMPPendingUUID] = uuid
	})
}

func (c *nodeLoadBalancerController) issueManagedNodeClassICMPCreate(
	ctx context.Context,
	name string,
	ownerUID types.UID,
	expectedStaged map[string]string,
	issuedAt string,
) (map[string]string, error) {
	if ownerUID == "" ||
		expectedStaged[annotationNodeLoadBalancerICMPPendingName] == "" ||
		expectedStaged[annotationNodeLoadBalancerICMPPendingStarted] == "" ||
		expectedStaged[annotationNodeLoadBalancerICMPPendingUUID] != "" ||
		expectedStaged[annotationNodeLoadBalancerICMPCreateIssued] != "" {
		return nil, errors.New("node load balancer: incomplete cluster ICMP firewall staged create identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, issuedAt); err != nil {
		return nil, fmt.Errorf("node load balancer: invalid cluster ICMP firewall issue timestamp: %w", err)
	}
	issued, err := c.mutateManagedNodeClassICMPCreateForUID(ctx, name, ownerUID, expectedStaged, func(values map[string]string) {
		values[annotationNodeLoadBalancerICMPCreateIssued] = issuedAt
	})
	if err != nil {
		return nil, err
	}
	if !issued {
		return nil, errors.New("node load balancer: cluster ICMP firewall create authority was not durably issued")
	}
	expectedCreate := make(map[string]string, len(expectedStaged))
	for key, value := range expectedStaged {
		expectedCreate[key] = value
	}
	expectedCreate[annotationNodeLoadBalancerICMPCreateIssued] = issuedAt
	return expectedCreate, nil
}

func (c *nodeLoadBalancerController) transitionManagedNodeClassICMPCreate(
	ctx context.Context,
	name string,
	ownerUID types.UID,
	expected map[string]string,
	committedUUID string,
) (bool, error) {
	if ownerUID == "" {
		return false, errors.New("node load balancer: cluster ICMP create transition lacks its exact NodeClass UID")
	}
	if committedUUID != "" && !validNodeLoadBalancerCloudUUID(committedUUID) {
		return false, fmt.Errorf("node load balancer: invalid observed cluster ICMP firewall UUID %q", committedUUID)
	}
	return c.mutateManagedNodeClassICMPCreateForUID(ctx, name, ownerUID, expected, func(values map[string]string) {
		if committedUUID != "" {
			values[annotationNodeLoadBalancerICMPFirewallUUID] = committedUUID
		}
		for _, key := range []string{
			annotationNodeLoadBalancerICMPPendingUUID,
			annotationNodeLoadBalancerICMPPendingName,
			annotationNodeLoadBalancerICMPPendingStarted,
			annotationNodeLoadBalancerICMPCreateIssued,
			annotationNodeLoadBalancerICMPAbsent,
			annotationNodeLoadBalancerICMPAbsentChecked,
		} {
			delete(values, key)
		}
	})
}

func (c *nodeLoadBalancerController) resetManagedNodeClassICMPCreateAfterProvenNonDispatch(
	ctx context.Context,
	name string,
	ownerUID types.UID,
	expected map[string]string,
) error {
	if expected[annotationNodeLoadBalancerICMPPendingName] == "" ||
		expected[annotationNodeLoadBalancerICMPPendingStarted] == "" ||
		expected[annotationNodeLoadBalancerICMPPendingUUID] != "" ||
		expected[annotationNodeLoadBalancerICMPCreateIssued] == "" {
		return errors.New("node load balancer: incomplete cluster ICMP create receipt for pre-dispatch reset")
	}
	if _, err := time.Parse(time.RFC3339Nano, expected[annotationNodeLoadBalancerICMPCreateIssued]); err != nil {
		return fmt.Errorf("node load balancer: invalid cluster ICMP create issue timestamp: %w", err)
	}
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	changed, err := c.mutateManagedNodeClassICMPCreateForUID(
		resetCtx,
		name,
		ownerUID,
		expected,
		func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPCreateIssued)
		},
	)
	if err != nil {
		return fmt.Errorf("node load balancer: reset proven non-dispatched cluster ICMP create receipt: %w", err)
	}
	if !changed {
		return errors.New("node load balancer: proven non-dispatched cluster ICMP create receipt was not reset")
	}
	return nil
}

func (c *nodeLoadBalancerController) resolveClusterICMPCreateReadback(
	ctx context.Context,
	nodeClassName string,
	ownerUID types.UID,
	expected map[string]string,
	desired desiredNodeLoadBalancerFirewall,
) (bool, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, fmt.Errorf("node load balancer: read back cluster ICMP firewall after create response: %w", err)
	}
	var observed *inspace.Firewall
	for index := range items {
		item := items[index]
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if observed != nil {
			return false, fmt.Errorf("node load balancer: multiple firewalls use managed cluster ICMP name %q after create response", desired.Request.DisplayName)
		}
		copy := item
		observed = &copy
	}
	if observed != nil {
		if !validNodeLoadBalancerCloudUUID(observed.UUID) ||
			!nodeLoadBalancerClusterICMPFirewallOwned(*observed, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
			return false, fmt.Errorf("node load balancer: managed cluster ICMP name %q resolved to a foreign or third-state resource after create response", desired.Request.DisplayName)
		}
		if _, err := c.transitionManagedNodeClassICMPCreate(ctx, nodeClassName, ownerUID, expected, observed.UUID); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, errors.New("node load balancer: cluster ICMP firewall create outcome remains ambiguous after exact name absence readback")
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
	return c.clearManagedNodeClassICMPAnnotationsForUID(ctx, name, "", expected, keys...)
}

func (c *nodeLoadBalancerController) clearManagedNodeClassICMPAnnotationsForUID(
	ctx context.Context,
	name string,
	expectedUID types.UID,
	expected map[string]string,
	keys ...string,
) (bool, error) {
	return c.mutateManagedNodeClassICMPCreateForUID(ctx, name, expectedUID, expected, func(values map[string]string) {
		for _, key := range keys {
			delete(values, key)
		}
	})
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
	return c.promoteClusterICMPFirewallForUID(ctx, nodeClassName, "", uuid)
}

func (c *nodeLoadBalancerController) promoteClusterICMPFirewallForUID(
	ctx context.Context,
	nodeClassName string,
	expectedUID types.UID,
	uuid string,
) (bool, error) {
	return c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, expectedUID, func(values map[string]string) {
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
	return c.recordNodeClassFirewallAbsenceForUID(
		ctx, nodeClassName, "", countAnnotation, checkedAnnotation, now, notBefore,
	)
}

func (c *nodeLoadBalancerController) recordNodeClassFirewallAbsenceForUID(
	ctx context.Context,
	nodeClassName string,
	expectedUID types.UID,
	countAnnotation, checkedAnnotation string,
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
	changed, err = c.mutateManagedNodeClassICMPCreateForUID(
		ctx,
		nodeClassName,
		expectedUID,
		map[string]string{
			countAnnotation:   annotations[countAnnotation],
			checkedAnnotation: annotations[checkedAnnotation],
		},
		func(values map[string]string) {
			next := count + 1
			values[countAnnotation] = strconv.Itoa(next)
			values[checkedAnnotation] = now.UTC().Format(time.RFC3339Nano)
			confirmed = next >= nodeLoadBalancerAbsenceConfirmations
		},
	)
	return confirmed, changed, err
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
	var nodeClassUID types.UID
	if nodeClass != nil {
		nodeClassUID = nodeClass.GetUID()
		if nodeClassUID == "" {
			return false, fmt.Errorf("node load balancer: managed NodeClass %q has an empty UID", nodeClassName)
		}
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, nodeClassUID),
			nil,
		)
		if relationErr != nil || !converged {
			return false, relationErr
		}
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
	deleteTarget, deleteIssuedAt, receiptErr := nodeLoadBalancerFirewallDeleteReceipt(
		annotations,
		annotationNodeLoadBalancerICMPDeleteTarget,
		annotationNodeLoadBalancerICMPDeleteIssued,
		annotationNodeLoadBalancerICMPCleanupAbsent,
		annotationNodeLoadBalancerICMPCleanupChecked,
	)
	if receiptErr != nil {
		return false, fmt.Errorf("node load balancer: parse cluster ICMP firewall delete receipt: %w", receiptErr)
	}
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
	if deleteTarget != "" && currentUUID != "" && deleteTarget != currentUUID {
		return false, errors.New("node load balancer: cluster ICMP firewall delete target conflicts with current UUID")
	}
	if deleteTarget != "" && pendingUUID != "" && deleteTarget != pendingUUID {
		return false, errors.New("node load balancer: cluster ICMP firewall delete target conflicts with pending UUID")
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	var byName, byCurrentUUID, byPendingUUID, byDeleteUUID *inspace.Firewall
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
		if deleteTarget != "" && item.UUID == deleteTarget {
			if byDeleteUUID != nil {
				return false, fmt.Errorf("node load balancer: cluster ICMP firewall delete target UUID %s appears multiple times", deleteTarget)
			}
			if item.EffectiveName() != desired.Request.DisplayName || !nodeLoadBalancerClusterICMPFirewallOwned(item, c.provider.config.ClusterID, c.provider.config.BillingAccountID) {
				return false, fmt.Errorf("node load balancer: cluster ICMP firewall delete target %s lost exact ownership", deleteTarget)
			}
			copy := item
			byDeleteUUID = &copy
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
	if deleteTarget != "" && byName != nil && byName.UUID != deleteTarget {
		return false, fmt.Errorf(
			"node load balancer: refusing to clean managed cluster ICMP name at UUID %s; delete target is %s",
			byName.UUID, deleteTarget,
		)
	}

	var firewall *inspace.Firewall
	switch {
	case deleteTarget != "":
		firewall = byDeleteUUID
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
			_, err := c.promoteClusterICMPFirewallForUID(ctx, nodeClassName, nodeClassUID, firewall.UUID)
			return false, err
		}
		if nodeClass != nil && currentUUID == "" && pendingName != "" && pendingUUID == "" {
			_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPPendingUUID] = firewall.UUID
				delete(values, annotationNodeLoadBalancerICMPAbsent)
				delete(values, annotationNodeLoadBalancerICMPAbsentChecked)
			})
			return false, err
		}
		if nodeClass != nil && currentUUID == "" && pendingUUID == "" {
			// Bind a discovered legacy/exact-name resource to durable state before
			// issuing an irreversible delete. A restart can then only target this UUID.
			_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
				values[annotationNodeLoadBalancerICMPFirewallUUID] = firewall.UUID
				delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
				delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
			})
			return false, err
		}
		if nodeClass != nil && (annotations[annotationNodeLoadBalancerICMPCleanupAbsent] != "" ||
			annotations[annotationNodeLoadBalancerICMPCleanupChecked] != "") {
			_, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
				delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
				delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
			})
			return false, err
		}
		if nodeClass != nil && deleteTarget != "" &&
			(annotations[annotationNodeLoadBalancerICMPCleanupAbsent] != "" ||
				annotations[annotationNodeLoadBalancerICMPCleanupChecked] != "") {
			changed, err := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
				if values[annotationNodeLoadBalancerICMPDeleteTarget] != deleteTarget ||
					values[annotationNodeLoadBalancerICMPDeleteIssued] != deleteIssuedAt {
					return
				}
				delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
				delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
			})
			if err != nil || changed {
				return false, err
			}
		}
		assignments, assignmentErr := nodeLoadBalancerFirewallAssignmentVMs(*firewall)
		if assignmentErr != nil {
			return false, assignmentErr
		}
		if len(assignments) != 0 {
			if nodeClass == nil {
				return false, errors.New("node load balancer: cannot safely detach cluster ICMP firewall without its NodeClass state owner")
			}
			for _, vmUUID := range assignments {
				converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
					ctx,
					c.clusterICMPFirewallRelationOwnerForUID(nodeClassName, nodeClassUID),
					&nodeLoadBalancerFirewallRelationFence{
						operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
					},
				)
				if relationErr != nil || !converged {
					return false, relationErr
				}
			}
			return false, nil
		}
		if deleteIssuedAt != "" {
			// The issued receipt survives stale visibility and restarts. No cloud
			// readback can authorize a second irreversible request.
			return false, nil
		}
		issuedAt := time.Now().UTC().Format(time.RFC3339Nano)
		winner, issueErr := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
			storedTarget, storedIssued, parseErr := nodeLoadBalancerFirewallDeleteReceipt(
				values,
				annotationNodeLoadBalancerICMPDeleteTarget,
				annotationNodeLoadBalancerICMPDeleteIssued,
				annotationNodeLoadBalancerICMPCleanupAbsent,
				annotationNodeLoadBalancerICMPCleanupChecked,
			)
			if parseErr != nil || (storedTarget != "" && storedTarget != firewall.UUID) || storedIssued != "" {
				return
			}
			values[annotationNodeLoadBalancerICMPDeleteTarget] = firewall.UUID
			values[annotationNodeLoadBalancerICMPDeleteIssued] = issuedAt
			delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
			delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
		})
		if issueErr != nil {
			return false, fmt.Errorf("node load balancer: persist cluster ICMP firewall delete-issued receipt: %w", issueErr)
		}
		if !winner {
			return false, nil
		}
		expectedDelete := map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
			annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
			annotationNodeLoadBalancerICMPPendingName:    pendingName,
			annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
			annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
			annotationNodeLoadBalancerICMPDeleteTarget:   firewall.UUID,
			annotationNodeLoadBalancerICMPDeleteIssued:   issuedAt,
			annotationNodeLoadBalancerICMPCleanupAbsent:  "",
			annotationNodeLoadBalancerICMPCleanupChecked: "",
		}
		rejectUndispatched := func(rejection error) (bool, error) {
			return false, errors.Join(
				rejection,
				c.resetClusterICMPFirewallDeleteAfterProvenNonDispatch(
					ctx,
					nodeClassName,
					nodeClassUID,
					expectedDelete,
				),
			)
		}
		authorizedNodeClass, authorityErr := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: re-read NodeClass owner after cluster ICMP delete issue: %w", authorityErr))
		}
		authorizedAnnotations := authorizedNodeClass.GetAnnotations()
		if authorizedNodeClass.GetUID() != nodeClassUID ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPFirewallUUID] != currentUUID ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPPendingUUID] != pendingUUID ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPPendingName] != pendingName ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPPendingStarted] != pendingStarted ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPCreateIssued] != createIssued ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPDeleteTarget] != firewall.UUID ||
			authorizedAnnotations[annotationNodeLoadBalancerICMPDeleteIssued] != issuedAt {
			return rejectUndispatched(errors.New("node load balancer: cluster ICMP firewall delete authority changed after issue"))
		}
		authorizedFirewall, authorityErr := c.exactNodeLoadBalancerFirewallFresh(ctx, firewall.UUID)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: re-read cluster ICMP firewall after delete issue: %w", authorityErr))
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(*firewall, *authorizedFirewall) ||
			!nodeLoadBalancerClusterICMPFirewallOwned(
				*authorizedFirewall,
				c.provider.config.ClusterID,
				c.provider.config.BillingAccountID,
			) {
			return rejectUndispatched(errors.New("node load balancer: cluster ICMP firewall lost exact ownership or policy after delete issue"))
		}
		postIssueAssignments, authorityErr := nodeLoadBalancerFirewallAssignmentVMs(*authorizedFirewall)
		if authorityErr != nil {
			return rejectUndispatched(authorityErr)
		}
		if len(postIssueAssignments) != 0 {
			return rejectUndispatched(errors.New("node load balancer: cluster ICMP firewall gained assignments after delete issue"))
		}
		deleteErr := c.provider.api.DeleteFirewall(ctx, c.provider.config.Location, firewall.UUID)
		if nodeLoadBalancerMutationKnownPreDispatch(deleteErr) {
			return false, errors.Join(
				deleteErr,
				c.resetClusterICMPFirewallDeleteAfterProvenNonDispatch(
					ctx,
					nodeClassName,
					nodeClassUID,
					expectedDelete,
				),
			)
		}
		if deleteErr != nil {
			return false, deleteErr
		}
		return false, nil
	}

	if nodeClass == nil {
		return false, errors.New("node load balancer: managed NodeClass state anchor is absent during cluster ICMP cleanup")
	}
	if deleteTarget == "" {
		candidate := currentUUID
		if candidate == "" {
			candidate = pendingUUID
		}
		if candidate != "" {
			changed, stageErr := c.updateManagedNodeClassAnnotationsForUID(ctx, nodeClassName, nodeClassUID, func(values map[string]string) {
				if values[annotationNodeLoadBalancerICMPDeleteTarget] == "" {
					values[annotationNodeLoadBalancerICMPDeleteTarget] = candidate
					delete(values, annotationNodeLoadBalancerICMPDeleteIssued)
					delete(values, annotationNodeLoadBalancerICMPCleanupAbsent)
					delete(values, annotationNodeLoadBalancerICMPCleanupChecked)
				}
			})
			if stageErr != nil {
				return false, fmt.Errorf("node load balancer: persist cluster ICMP firewall delete intent: %w", stageErr)
			}
			if changed {
				deleteTarget = candidate
				deleteIssuedAt = ""
			} else {
				return false, nil
			}
		}
	}
	if createIssued != "" {
		return false, fmt.Errorf(
			"node load balancer: cluster ICMP firewall create issued at %s remains ambiguous during cleanup; retaining the NodeClass finalizer until the original firewall is observable or manually resolved",
			createIssued,
		)
	}
	if pendingName != "" {
		_, clearErr := c.clearManagedNodeClassICMPAnnotationsForUID(
			ctx, nodeClassName, nodeClassUID,
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
			annotationNodeLoadBalancerFirewallRelationIssued,
			annotationNodeLoadBalancerFirewallRelationOwnerUID,
		)
		return false, clearErr
	}
	confirmed, changed, err := c.recordNodeClassFirewallAbsenceForUID(
		ctx, nodeClassName, nodeClassUID,
		annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		time.Now().UTC(), time.Time{},
	)
	if err != nil || changed || !confirmed {
		return false, err
	}
	deleteAbsent, deleteChecked := "", ""
	if deleteTarget != "" {
		latest, getErr := c.getManagedNodeLoadBalancerNodeClass(ctx, nodeClassName)
		if getErr != nil {
			return false, getErr
		}
		if latest.GetUID() != nodeClassUID {
			return false, errors.New("node load balancer: cluster ICMP NodeClass identity changed during absence proof")
		}
		latestAnnotations := latest.GetAnnotations()
		if latestAnnotations[annotationNodeLoadBalancerICMPDeleteTarget] != deleteTarget ||
			latestAnnotations[annotationNodeLoadBalancerICMPDeleteIssued] != deleteIssuedAt {
			return false, errors.New("node load balancer: cluster ICMP firewall delete receipt changed during absence proof")
		}
		count, parseErr := strconv.Atoi(latestAnnotations[annotationNodeLoadBalancerICMPCleanupAbsent])
		if parseErr != nil || count < nodeLoadBalancerAbsenceConfirmations {
			return false, errors.New("node load balancer: cluster ICMP firewall delete absence is no longer confirmed")
		}
		deleteAbsent = latestAnnotations[annotationNodeLoadBalancerICMPCleanupAbsent]
		deleteChecked = latestAnnotations[annotationNodeLoadBalancerICMPCleanupChecked]
	}
	_, err = c.clearManagedNodeClassICMPAnnotationsForUID(
		ctx, nodeClassName, nodeClassUID,
		map[string]string{
			annotationNodeLoadBalancerICMPFirewallUUID:   currentUUID,
			annotationNodeLoadBalancerICMPPendingUUID:    pendingUUID,
			annotationNodeLoadBalancerICMPPendingName:    pendingName,
			annotationNodeLoadBalancerICMPPendingStarted: pendingStarted,
			annotationNodeLoadBalancerICMPCreateIssued:   createIssued,
			annotationNodeLoadBalancerICMPDeleteTarget:   deleteTarget,
			annotationNodeLoadBalancerICMPDeleteIssued:   deleteIssuedAt,
			annotationNodeLoadBalancerICMPCleanupAbsent:  deleteAbsent,
			annotationNodeLoadBalancerICMPCleanupChecked: deleteChecked,
		},
		annotationNodeLoadBalancerICMPFirewallUUID, annotationNodeLoadBalancerICMPPendingUUID,
		annotationNodeLoadBalancerICMPPendingName, annotationNodeLoadBalancerICMPPendingStarted,
		annotationNodeLoadBalancerICMPCreateIssued,
		annotationNodeLoadBalancerICMPAbsent, annotationNodeLoadBalancerICMPAbsentChecked,
		annotationNodeLoadBalancerICMPCleanupAbsent, annotationNodeLoadBalancerICMPCleanupChecked,
		annotationNodeLoadBalancerICMPDeleteTarget, annotationNodeLoadBalancerICMPDeleteIssued,
		annotationNodeLoadBalancerFirewallRelationIssued,
		annotationNodeLoadBalancerFirewallRelationOwnerUID,
	)
	return err == nil, err
}

func (c *nodeLoadBalancerController) resetClusterICMPFirewallDeleteAfterProvenNonDispatch(
	ctx context.Context,
	nodeClassName string,
	ownerUID types.UID,
	expected map[string]string,
) error {
	target := expected[annotationNodeLoadBalancerICMPDeleteTarget]
	issuedAt := expected[annotationNodeLoadBalancerICMPDeleteIssued]
	if !validNodeLoadBalancerCloudUUID(target) || issuedAt == "" {
		return errors.New("node load balancer: incomplete cluster ICMP firewall delete receipt for pre-dispatch reset")
	}
	if _, err := time.Parse(time.RFC3339Nano, issuedAt); err != nil {
		return fmt.Errorf("node load balancer: invalid cluster ICMP firewall delete issue timestamp: %w", err)
	}
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	changed, err := c.mutateManagedNodeClassICMPCreateForUID(
		resetCtx,
		nodeClassName,
		ownerUID,
		expected,
		func(values map[string]string) {
			delete(values, annotationNodeLoadBalancerICMPDeleteIssued)
		},
	)
	if err != nil {
		return fmt.Errorf("node load balancer: reset proven non-dispatched cluster ICMP firewall delete receipt: %w", err)
	}
	if !changed {
		return errors.New("node load balancer: proven non-dispatched cluster ICMP firewall delete receipt was not reset")
	}
	return nil
}
