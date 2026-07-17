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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	annotationNodeLoadBalancerDatapathStaged        = "service.inspace.cloud/node-lb-datapath-staged-shard"
	annotationNodeLoadBalancerDatapathStagedPolicy  = "service.inspace.cloud/node-lb-datapath-staged-policy"
	annotationNodeLoadBalancerDatapathRestage       = "service.inspace.cloud/node-lb-datapath-restage-shard"
	annotationNodeLoadBalancerDatapathRestagePolicy = "service.inspace.cloud/node-lb-datapath-restage-policy"
	annotationNodeLoadBalancerShardCleanupProven    = "service.inspace.cloud/node-lb-shard-cleanup-proven"
	annotationNodeLoadBalancerShardStateMaterial    = "service.inspace.cloud/node-lb-shard-state-materialized"
	annotationNodeLoadBalancerClusterCleanupProven  = "service.inspace.cloud/node-lb-cluster-cleanup-proven"
	annotationNodeLoadBalancerClusterStateMaterial  = "service.inspace.cloud/node-lb-cluster-state-materialized"

	annotationNodeLoadBalancerShardFirewallUUID    = "service.inspace.cloud/node-lb-shard-firewall-uuid"
	annotationNodeLoadBalancerShardFirewallHash    = "service.inspace.cloud/node-lb-shard-firewall-hash"
	annotationNodeLoadBalancerShardFirewallLedger  = "service.inspace.cloud/node-lb-shard-firewall-ledger"
	annotationNodeLoadBalancerShardFWPendingHash   = "service.inspace.cloud/node-lb-shard-firewall-pending-hash"
	annotationNodeLoadBalancerShardFWPendingLedger = "service.inspace.cloud/node-lb-shard-firewall-pending-ledger"
	annotationNodeLoadBalancerShardFWPendingAt     = "service.inspace.cloud/node-lb-shard-firewall-pending-at"
	annotationNodeLoadBalancerShardFWIssuedAt      = "service.inspace.cloud/node-lb-shard-firewall-issued-at"
	annotationNodeLoadBalancerShardFWPendingUUID   = "service.inspace.cloud/node-lb-shard-firewall-pending-uuid"
	annotationNodeLoadBalancerShardFWAbsent        = "service.inspace.cloud/node-lb-shard-firewall-absence-count"
	annotationNodeLoadBalancerShardFWAbsentChecked = "service.inspace.cloud/node-lb-shard-firewall-absence-checked-at"
	annotationNodeLoadBalancerShardFWCreateAbsent  = "service.inspace.cloud/node-lb-shard-firewall-create-absence-count"
	annotationNodeLoadBalancerShardFWCreateChecked = "service.inspace.cloud/node-lb-shard-firewall-create-absence-checked-at"
	annotationNodeLoadBalancerShardFWCleanupAbsent = "service.inspace.cloud/node-lb-shard-firewall-cleanup-absence-count"
	annotationNodeLoadBalancerShardFWCleanupCheck  = "service.inspace.cloud/node-lb-shard-firewall-cleanup-absence-checked-at"
	annotationNodeLoadBalancerShardFWCleanupSeen   = "service.inspace.cloud/node-lb-shard-firewall-cleanup-observed-uuid"
	annotationNodeLoadBalancerShardFWDeleteTarget  = "service.inspace.cloud/node-lb-shard-firewall-delete-target-uuid"
	annotationNodeLoadBalancerShardFWDeleteIssued  = "service.inspace.cloud/node-lb-shard-firewall-delete-issued-at"

	nodeLoadBalancerShardFirewallMutationTimeout  = 5 * time.Minute
	nodeLoadBalancerShardFirewallPolicyHashLength = 64
	nodeLoadBalancerShardFirewallFutureSkew       = time.Minute
)

type nodeLoadBalancerShardFirewallState struct {
	Firewall         *inspace.Firewall
	AppliedHash      string
	AppliedLedger    string
	DesiredHash      string
	DesiredLedger    string
	PolicyReady      bool
	AssignmentsReady bool
	MutationIssued   bool
}

func (state nodeLoadBalancerShardFirewallState) covers(service *corev1.Service) bool {
	if service == nil || state.AppliedLedger == "" {
		return false
	}
	desired, err := desiredNodeLoadBalancerServicePolicyHash(service)
	if err != nil {
		return false
	}
	members, err := parseNodeLoadBalancerShardFirewallLedger(state.AppliedLedger)
	if err != nil {
		return false
	}
	return members[string(service.UID)] == desired
}

func desiredNodeLoadBalancerServicePolicyHash(service *corev1.Service) (string, error) {
	if service == nil {
		return "", errors.New("node load balancer: Service is required for policy hashing")
	}
	sources, err := canonicalNodeLoadBalancerSourceRanges(service.Spec.LoadBalancerSourceRanges)
	if err != nil {
		return "", err
	}
	ports, err := nodeLoadBalancerPortClaims(service)
	if err != nil {
		return "", err
	}
	rules := make([]inspace.FirewallRule, 0, len(ports))
	for _, port := range ports {
		start, stop := port.Port, port.Port
		rule := inspace.FirewallRule{
			Protocol: strings.ToLower(string(port.Protocol)), Direction: "inbound",
			PortStart: &start, PortEnd: &stop, EndpointSpecType: "any",
		}
		if len(sources) != 0 {
			rule.EndpointSpecType = "ip_prefixes"
			rule.EndpointSpec = append([]string(nil), sources...)
		}
		rules = append(rules, rule)
	}
	return inspace.NodeLoadBalancerShardFirewallSpecHash(rules)
}

func parseNodeLoadBalancerShardFirewallLedger(encoded string) (map[string]string, error) {
	if encoded == "" {
		return nil, errors.New("node load balancer: shard firewall ledger is empty")
	}
	result := map[string]string{}
	previous := ""
	for _, entry := range strings.Split(encoded, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 || validateNodeLoadBalancerServiceUID(parts[0]) != nil ||
			!validNodeLoadBalancerShardFirewallPolicyHash(parts[1]) {
			return nil, fmt.Errorf("node load balancer: invalid shard firewall ledger %q", encoded)
		}
		if previous != "" && entry <= previous {
			return nil, fmt.Errorf("node load balancer: shard firewall ledger is not strictly sorted: %q", encoded)
		}
		previous = entry
		result[parts[0]] = parts[1]
	}
	return result, nil
}

// desiredStagedShardFirewallPolicy deliberately includes only Services whose
// private datapath and exact policy have been durably staged. A newly created
// Service therefore cannot open its public edge before the private Cilium VIP
// exists, and an edited Service is removed from the old edge before restaging.
func (c *nodeLoadBalancerController) desiredStagedShardFirewallPolicy(
	ctx context.Context,
	shard string,
) (*nodeLoadBalancerShardFirewallPolicy, string, []*corev1.Service, error) {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return nil, "", nil, fmt.Errorf("node load balancer: invalid shard %q", shard)
	}
	list, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, "", nil, fmt.Errorf("node load balancer: list Services for shard policy: %w", err)
	}
	services := make([]*corev1.Service, 0)
	plan := nodeLoadBalancerShardPlan{Name: shard}
	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	for index := range list.Items {
		service := &list.Items[index]
		if service.DeletionTimestamp != nil || !isNodeLoadBalancerService(service) ||
			!containsString(service.Finalizers, nodeLoadBalancerFinalizer) {
			continue
		}
		if _, parseErr := parseNodeLoadBalancerService(service, defaults); parseErr != nil {
			continue
		}
		policyHash, hashErr := desiredNodeLoadBalancerServicePolicyHash(service)
		if hashErr != nil {
			continue
		}
		staged := service.Annotations[annotationNodeLoadBalancerDatapathActive] == shard &&
			service.Annotations[annotationNodeLoadBalancerDatapathStaged] == shard &&
			service.Annotations[annotationNodeLoadBalancerDatapathStagedPolicy] == policyHash
		restaging := service.Annotations[annotationNodeLoadBalancerDatapathRestage] == shard &&
			service.Annotations[annotationNodeLoadBalancerDatapathRestagePolicy] == policyHash
		if !staged && !restaging {
			continue
		}
		if restaging {
			// A restaging member is allowed into the public policy only while its
			// functional Cilium frontend and informational public status are closed.
			// That makes source-range tightening an old-policy -> closed -> new-policy
			// transition, even across controller crashes.
			if len(service.Status.LoadBalancer.Ingress) != 0 {
				continue
			}
			child, childErr := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
				ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
			)
			if childErr != nil || !nodeLoadBalancerDatapathMatchesDesired(child, service, shard) ||
				len(child.Status.LoadBalancer.Ingress) != 0 {
				continue
			}
		}
		ports, portErr := nodeLoadBalancerPortClaims(service)
		if portErr != nil {
			return nil, "", nil, portErr
		}
		plan.Claims = append(plan.Claims, string(service.UID))
		plan.Ports = append(plan.Ports, ports...)
		services = append(services, service.DeepCopy())
	}
	if len(services) == 0 {
		return nil, "", nil, nil
	}
	sort.Strings(plan.Claims)
	sortNodeLoadBalancerPorts(plan.Ports)
	policy, err := desiredNodeLoadBalancerShardFirewall(
		c.provider.config.ClusterID,
		c.provider.config.BillingAccountID,
		plan,
		services,
	)
	if err != nil {
		return nil, "", nil, err
	}
	ledger, err := nodeLoadBalancerShardFirewallPolicyLedger(policy)
	if err != nil {
		return nil, "", nil, err
	}
	return &policy, ledger, services, nil
}

func (c *nodeLoadBalancerController) updateManagedNodePoolAnnotations(
	ctx context.Context,
	shard string,
	mutate func(map[string]string) (bool, error),
) (*unstructured.Unstructured, bool, error) {
	return c.updateManagedNodePoolAnnotationsForUID(ctx, shard, "", mutate)
}

func (c *nodeLoadBalancerController) updateManagedNodePoolAnnotationsForUID(
	ctx context.Context,
	shard string,
	expectedUID types.UID,
	mutate func(map[string]string) (bool, error),
) (*unstructured.Unstructured, bool, error) {
	resource := c.provider.dynamicClient.Resource(nodePoolGVR)
	pool, err := resource.Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: get NodePool %s for shard firewall state: %w", shard, err)
	}
	if expectedUID != "" && pool.GetUID() != expectedUID {
		return nil, false, fmt.Errorf("node load balancer: NodePool %s identity changed before exact receipt transition", shard)
	}
	labels := pool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != shard {
		return nil, false, fmt.Errorf("node load balancer: NodePool %s lacks exact shard ownership", shard)
	}
	annotations := pool.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	copyAnnotations := make(map[string]string, len(annotations))
	for key, value := range annotations {
		copyAnnotations[key] = value
	}
	changed, err := mutate(copyAnnotations)
	if err != nil {
		return pool, false, err
	}
	anchorMissing := !containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer)
	if !changed && !anchorMissing {
		return pool, false, err
	}
	if anchorMissing && pool.GetDeletionTimestamp() != nil {
		return nil, false, fmt.Errorf("node load balancer: deleting NodePool %s is missing its state finalizer", shard)
	}
	updated := pool.DeepCopy()
	updated.SetAnnotations(copyAnnotations)
	if anchorMissing {
		updated.SetFinalizers(append(updated.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer))
	}
	updated, err = resource.Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: persist shard firewall state on NodePool %s: %w", shard, err)
	}
	if err := c.validateManagedNodePoolAnnotationWrite(updated, shard, pool.GetUID(), copyAnnotations); err != nil {
		return nil, false, err
	}
	verified, err := resource.Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: read back shard firewall state on NodePool %s: %w", shard, err)
	}
	if err := c.validateManagedNodePoolAnnotationWrite(verified, shard, pool.GetUID(), copyAnnotations); err != nil {
		return nil, false, err
	}
	return verified, true, nil
}

func (c *nodeLoadBalancerController) validateManagedNodePoolAnnotationWrite(
	pool *unstructured.Unstructured,
	shard string,
	uid types.UID,
	expected map[string]string,
) error {
	if pool == nil || pool.GetName() != shard {
		return fmt.Errorf("node load balancer: shard firewall state update returned the wrong NodePool identity")
	}
	if uid != "" && pool.GetUID() != uid {
		return fmt.Errorf("node load balancer: NodePool %s UID changed while persisting shard firewall state", shard)
	}
	labels := pool.GetLabels()
	if labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return fmt.Errorf("node load balancer: failed exact state-anchor readback: NodePool %s lost exact ownership while persisting shard firewall state", shard)
	}
	if !mapsEqualStringString(pool.GetAnnotations(), expected) {
		return fmt.Errorf("node load balancer: NodePool %s did not retain the exact shard firewall receipt", shard)
	}
	return nil
}

func nodeLoadBalancerShardFirewallAnnotations(pool *unstructured.Unstructured) (map[string]string, error) {
	if pool == nil {
		return nil, errors.New("node load balancer: NodePool is required for shard firewall state")
	}
	annotations := pool.GetAnnotations()
	currentUUID := annotations[annotationNodeLoadBalancerShardFirewallUUID]
	currentHash := annotations[annotationNodeLoadBalancerShardFirewallHash]
	currentLedger := annotations[annotationNodeLoadBalancerShardFirewallLedger]
	if (currentUUID == "") != (currentHash == "") || (currentUUID == "") != (currentLedger == "") {
		return nil, errors.New("node load balancer: shard firewall UUID, hash, and ledger must be persisted together")
	}
	if currentUUID != "" {
		if !validNodeLoadBalancerCloudUUID(currentUUID) {
			return nil, fmt.Errorf("node load balancer: invalid persisted shard firewall UUID %q", currentUUID)
		}
		if !validNodeLoadBalancerShardFirewallPolicyHash(currentHash) {
			return nil, fmt.Errorf("node load balancer: invalid persisted shard firewall hash %q", currentHash)
		}
		if _, err := parseNodeLoadBalancerShardFirewallLedger(currentLedger); err != nil {
			return nil, err
		}
	}
	pendingHash := annotations[annotationNodeLoadBalancerShardFWPendingHash]
	pendingLedger := annotations[annotationNodeLoadBalancerShardFWPendingLedger]
	pendingAt := annotations[annotationNodeLoadBalancerShardFWPendingAt]
	if (pendingHash == "") != (pendingLedger == "") || (pendingHash == "") != (pendingAt == "") {
		return nil, errors.New("node load balancer: incomplete pending shard firewall policy fence")
	}
	if pendingHash != "" {
		if !validNodeLoadBalancerShardFirewallPolicyHash(pendingHash) {
			return nil, fmt.Errorf("node load balancer: invalid pending shard firewall hash %q", pendingHash)
		}
		if _, err := parseNodeLoadBalancerShardFirewallLedger(pendingLedger); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, pendingAt)
		if err != nil {
			return nil, fmt.Errorf("node load balancer: invalid pending shard firewall timestamp: %w", err)
		}
		if parsed.After(time.Now().UTC().Add(nodeLoadBalancerShardFirewallFutureSkew)) {
			return nil, errors.New("node load balancer: pending shard firewall timestamp is unreasonably in the future")
		}
	}
	if issued := annotations[annotationNodeLoadBalancerShardFWIssuedAt]; issued != "" {
		if pendingHash == "" {
			return nil, errors.New("node load balancer: shard firewall mutation is issued without a pending policy")
		}
		parsed, err := time.Parse(time.RFC3339Nano, issued)
		if err != nil {
			return nil, fmt.Errorf("node load balancer: invalid shard firewall issued timestamp: %w", err)
		}
		if parsed.After(time.Now().UTC().Add(nodeLoadBalancerShardFirewallFutureSkew)) {
			return nil, errors.New("node load balancer: shard firewall issued timestamp is unreasonably in the future")
		}
	}
	if pendingUUID := annotations[annotationNodeLoadBalancerShardFWPendingUUID]; pendingUUID != "" {
		if !validNodeLoadBalancerCloudUUID(pendingUUID) {
			return nil, fmt.Errorf("node load balancer: invalid pending shard firewall UUID %q", pendingUUID)
		}
		if pendingHash == "" || annotations[annotationNodeLoadBalancerShardFWIssuedAt] == "" {
			return nil, errors.New("node load balancer: pending shard firewall UUID lacks a complete issued transaction")
		}
	}
	if cleanupUUID := annotations[annotationNodeLoadBalancerShardFWCleanupSeen]; cleanupUUID != "" && !validNodeLoadBalancerCloudUUID(cleanupUUID) {
		return nil, fmt.Errorf("node load balancer: invalid cleanup-observed shard firewall UUID %q", cleanupUUID)
	}
	if _, _, err := nodeLoadBalancerFirewallDeleteReceipt(
		annotations,
		annotationNodeLoadBalancerShardFWDeleteTarget,
		annotationNodeLoadBalancerShardFWDeleteIssued,
		annotationNodeLoadBalancerShardFWCleanupAbsent,
		annotationNodeLoadBalancerShardFWCleanupCheck,
	); err != nil {
		return nil, fmt.Errorf("node load balancer: invalid shard firewall delete receipt: %w", err)
	}
	return annotations, nil
}

func validNodeLoadBalancerShardFirewallPolicyHash(value string) bool {
	return len(value) == nodeLoadBalancerShardFirewallPolicyHashLength && isLowerHex(value)
}

func (c *nodeLoadBalancerController) recordManagedNodePoolFirewallAbsence(
	ctx context.Context,
	shard, countAnnotation, checkedAnnotation string,
	now, notBefore time.Time,
) (confirmed, changed bool, err error) {
	return c.recordManagedNodePoolFirewallAbsenceForUID(
		ctx, shard, "", countAnnotation, checkedAnnotation, now, notBefore,
	)
}

func (c *nodeLoadBalancerController) recordManagedNodePoolFirewallAbsenceForUID(
	ctx context.Context,
	shard string,
	expectedUID types.UID,
	countAnnotation, checkedAnnotation string,
	now, notBefore time.Time,
) (confirmed, changed bool, err error) {
	if now.Before(notBefore) {
		return false, false, nil
	}
	_, changed, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, expectedUID, func(values map[string]string) (bool, error) {
		count := 0
		if raw := values[countAnnotation]; raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 0 || parsed > nodeLoadBalancerAbsenceConfirmations {
				return false, fmt.Errorf("node load balancer: invalid shard firewall absence count %q", raw)
			}
			count = parsed
		}
		if count >= nodeLoadBalancerAbsenceConfirmations {
			confirmed = true
			return false, nil
		}
		if raw := values[checkedAnnotation]; raw != "" {
			checkedAt, parseErr := time.Parse(time.RFC3339Nano, raw)
			if parseErr != nil {
				return false, fmt.Errorf("node load balancer: invalid shard firewall absence timestamp: %w", parseErr)
			}
			if now.Before(checkedAt.Add(nodeLoadBalancerAbsenceConfirmationDelay)) {
				return false, nil
			}
		}
		next := count + 1
		values[countAnnotation] = strconv.Itoa(next)
		values[checkedAnnotation] = now.UTC().Format(time.RFC3339Nano)
		confirmed = next >= nodeLoadBalancerAbsenceConfirmations
		return true, nil
	})
	return confirmed, changed, err
}

func (c *nodeLoadBalancerController) clearManagedNodePoolFirewallAbsence(
	ctx context.Context,
	shard string,
	pairs ...string,
) (bool, error) {
	return c.clearManagedNodePoolFirewallAbsenceForUID(ctx, shard, "", pairs...)
}

func (c *nodeLoadBalancerController) clearManagedNodePoolFirewallAbsenceForUID(
	ctx context.Context,
	shard string,
	expectedUID types.UID,
	pairs ...string,
) (bool, error) {
	_, changed, err := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, expectedUID, func(values map[string]string) (bool, error) {
		changed := false
		for _, key := range pairs {
			if values[key] != "" {
				delete(values, key)
				changed = true
			}
		}
		return changed, nil
	})
	return changed, err
}

var nodeLoadBalancerShardFirewallMutationReceiptKeys = []string{
	annotationNodeLoadBalancerShardFirewallUUID,
	annotationNodeLoadBalancerShardFirewallHash,
	annotationNodeLoadBalancerShardFirewallLedger,
	annotationNodeLoadBalancerShardFWPendingHash,
	annotationNodeLoadBalancerShardFWPendingLedger,
	annotationNodeLoadBalancerShardFWPendingAt,
	annotationNodeLoadBalancerShardFWIssuedAt,
	annotationNodeLoadBalancerShardFWPendingUUID,
}

func nodeLoadBalancerShardFirewallMutationExpected(annotations map[string]string, issuedAt string) map[string]string {
	expected := make(map[string]string, len(nodeLoadBalancerShardFirewallMutationReceiptKeys))
	for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
		expected[key] = annotations[key]
	}
	expected[annotationNodeLoadBalancerShardFWIssuedAt] = issuedAt
	return expected
}

func (c *nodeLoadBalancerController) issueShardFirewallMutation(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expectedStaged map[string]string,
	issuedAt string,
	clearCreateAbsence bool,
) (map[string]string, error) {
	if ownerUID == "" ||
		expectedStaged[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
		expectedStaged[annotationNodeLoadBalancerShardFWPendingLedger] == "" ||
		expectedStaged[annotationNodeLoadBalancerShardFWPendingAt] == "" ||
		expectedStaged[annotationNodeLoadBalancerShardFWIssuedAt] != "" ||
		expectedStaged[annotationNodeLoadBalancerShardFWPendingUUID] != "" {
		return nil, errors.New("node load balancer: incomplete staged shard firewall mutation identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, issuedAt); err != nil {
		return nil, fmt.Errorf("node load balancer: invalid shard firewall issue timestamp: %w", err)
	}
	issuedPool, changed, err := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
		for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
			if values[key] != expectedStaged[key] {
				return false, errors.New("node load balancer: shard firewall staged mutation changed before authority issuance")
			}
		}
		values[annotationNodeLoadBalancerShardFWIssuedAt] = issuedAt
		if clearCreateAbsence {
			delete(values, annotationNodeLoadBalancerShardFWCreateAbsent)
			delete(values, annotationNodeLoadBalancerShardFWCreateChecked)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !changed || issuedPool == nil {
		return nil, errors.New("node load balancer: shard firewall mutation authority was not durably issued")
	}
	verifiedAnnotations, err := nodeLoadBalancerShardFirewallAnnotations(issuedPool)
	if err != nil {
		return nil, err
	}
	expectedMutation := nodeLoadBalancerShardFirewallMutationExpected(expectedStaged, issuedAt)
	for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
		if verifiedAnnotations[key] != expectedMutation[key] {
			return nil, errors.New("node load balancer: shard firewall issue readback changed the exact mutation receipt")
		}
	}
	return expectedMutation, nil
}

// authorizeShardFirewallPolicyMutationPreDispatch re-derives both halves of
// the mutation authority after the issued receipt is durable: the exact live
// NodePool receipt and the policy assembled from live Services.  The latter is
// important because a Service can change or disappear between staging the
// receipt and crossing the cloud API boundary.
func (c *nodeLoadBalancerController) authorizeShardFirewallPolicyMutationPreDispatch(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
	desired nodeLoadBalancerShardFirewallPolicy,
	desiredLedger string,
) error {
	owner, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("node load balancer: re-read shard owner before firewall mutation: %w", err)
	}
	labels := owner.GetLabels()
	if owner.GetName() != shard || (ownerUID != "" && owner.GetUID() != ownerUID) ||
		owner.GetDeletionTimestamp() != nil ||
		labels[nodeLoadBalancerManagedLabel] != "true" ||
		labels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		labels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(owner.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) {
		return errors.New("node load balancer: shard firewall mutation owner is no longer an authoritative live NodePool")
	}
	annotations, err := nodeLoadBalancerShardFirewallAnnotations(owner)
	if err != nil {
		return err
	}
	for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
		if annotations[key] != expected[key] {
			return errors.New("node load balancer: shard firewall mutation receipt changed after issue")
		}
	}

	fresh, freshLedger, _, err := c.desiredStagedShardFirewallPolicy(ctx, shard)
	if err != nil {
		return fmt.Errorf("node load balancer: re-derive live shard firewall policy before mutation: %w", err)
	}
	if fresh == nil || fresh.Hash != desired.Hash || freshLedger != desiredLedger ||
		fresh.ClusterID != desired.ClusterID || fresh.Shard != desired.Shard ||
		fresh.Request.DisplayName != desired.Request.DisplayName ||
		fresh.Request.Description != desired.Request.Description ||
		fresh.Request.BillingAccountID != desired.Request.BillingAccountID ||
		expected[annotationNodeLoadBalancerShardFWPendingHash] != fresh.Hash ||
		expected[annotationNodeLoadBalancerShardFWPendingLedger] != freshLedger {
		return errors.New("node load balancer: live staged Service policy changed after shard firewall mutation issue")
	}
	return nil
}

func (c *nodeLoadBalancerController) transitionShardFirewallMutation(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
	committed *inspace.Firewall,
) error {
	if ownerUID == "" {
		return errors.New("node load balancer: shard firewall mutation transition lacks its exact NodePool UID")
	}
	updated, changed, err := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
		for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
			if values[key] != expected[key] {
				return false, errors.New("node load balancer: shard firewall mutation receipt changed before exact transition")
			}
		}
		if expected[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
			expected[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
			expected[annotationNodeLoadBalancerShardFWPendingLedger] == "" ||
			expected[annotationNodeLoadBalancerShardFWPendingAt] == "" {
			return false, errors.New("node load balancer: incomplete shard firewall mutation receipt")
		}
		if committed != nil {
			if !validNodeLoadBalancerCloudUUID(committed.UUID) {
				return false, fmt.Errorf("node load balancer: invalid observed shard firewall UUID %q", committed.UUID)
			}
			values[annotationNodeLoadBalancerShardFirewallUUID] = committed.UUID
			values[annotationNodeLoadBalancerShardFirewallHash] = expected[annotationNodeLoadBalancerShardFWPendingHash]
			values[annotationNodeLoadBalancerShardFirewallLedger] = expected[annotationNodeLoadBalancerShardFWPendingLedger]
		}
		for _, key := range []string{
			annotationNodeLoadBalancerShardFWPendingHash,
			annotationNodeLoadBalancerShardFWPendingLedger,
			annotationNodeLoadBalancerShardFWPendingAt,
			annotationNodeLoadBalancerShardFWIssuedAt,
			annotationNodeLoadBalancerShardFWPendingUUID,
			annotationNodeLoadBalancerShardFWCreateAbsent,
			annotationNodeLoadBalancerShardFWCreateChecked,
		} {
			delete(values, key)
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	if !changed || updated == nil {
		return errors.New("node load balancer: shard firewall mutation receipt transition was not persisted")
	}
	annotations := updated.GetAnnotations()
	for _, key := range []string{
		annotationNodeLoadBalancerShardFWPendingHash,
		annotationNodeLoadBalancerShardFWPendingLedger,
		annotationNodeLoadBalancerShardFWPendingAt,
		annotationNodeLoadBalancerShardFWIssuedAt,
		annotationNodeLoadBalancerShardFWPendingUUID,
	} {
		if annotations[key] != "" {
			return errors.New("node load balancer: shard firewall mutation receipt update returned uncleared pending state")
		}
	}
	if committed != nil && (annotations[annotationNodeLoadBalancerShardFirewallUUID] != committed.UUID ||
		annotations[annotationNodeLoadBalancerShardFirewallHash] != expected[annotationNodeLoadBalancerShardFWPendingHash] ||
		annotations[annotationNodeLoadBalancerShardFirewallLedger] != expected[annotationNodeLoadBalancerShardFWPendingLedger]) {
		return errors.New("node load balancer: shard firewall mutation receipt update returned unexpected committed state")
	}
	return nil
}

// resetShardFirewallMutationAfterProvenNonDispatch returns the exact issued
// shard policy transaction to its staged state. Callers have won issuance and
// proved that no provider HTTP mutation was dispatched, either through final
// authority rejection or the SDK's typed ErrMutationBlocked result.
func (c *nodeLoadBalancerController) resetShardFirewallMutationAfterProvenNonDispatch(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
) error {
	if ownerUID == "" ||
		expected[annotationNodeLoadBalancerShardFWIssuedAt] == "" ||
		expected[annotationNodeLoadBalancerShardFWPendingHash] == "" ||
		expected[annotationNodeLoadBalancerShardFWPendingLedger] == "" ||
		expected[annotationNodeLoadBalancerShardFWPendingAt] == "" {
		return errors.New("node load balancer: incomplete shard firewall mutation receipt for pre-dispatch reset")
	}
	resetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableReceiptWriteTimeout)
	defer cancel()
	updated, changed, err := c.updateManagedNodePoolAnnotationsForUID(resetCtx, shard, ownerUID, func(values map[string]string) (bool, error) {
		for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
			if values[key] != expected[key] {
				return false, errors.New("node load balancer: shard firewall mutation receipt changed before pre-dispatch reset")
			}
		}
		delete(values, annotationNodeLoadBalancerShardFWIssuedAt)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("node load balancer: reset proven non-dispatched shard firewall mutation receipt: %w", err)
	}
	if !changed || updated == nil {
		return errors.New("node load balancer: proven non-dispatched shard firewall mutation receipt was not reset")
	}
	annotations := updated.GetAnnotations()
	if annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
		return errors.New("node load balancer: shard firewall mutation reset retained issued authority")
	}
	for _, key := range nodeLoadBalancerShardFirewallMutationReceiptKeys {
		if key == annotationNodeLoadBalancerShardFWIssuedAt {
			continue
		}
		if annotations[key] != expected[key] {
			return errors.New("node load balancer: shard firewall mutation reset changed its staged identity")
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) resolveShardFirewallCreateReadback(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
	desired nodeLoadBalancerShardFirewallPolicy,
) (*inspace.Firewall, bool, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: read back shard firewall after create response: %w", err)
	}
	var observed *inspace.Firewall
	for index := range items {
		item := items[index]
		if item.EffectiveName() != desired.Request.DisplayName {
			continue
		}
		if observed != nil {
			return nil, false, fmt.Errorf("node load balancer: multiple firewalls use stable shard name %q after create response", desired.Request.DisplayName)
		}
		copy := item
		observed = &copy
	}
	if observed != nil {
		if !validNodeLoadBalancerCloudUUID(observed.UUID) ||
			(observed.Description != "" && observed.Description != desired.Request.Description) ||
			inspace.ValidateNodeLoadBalancerShardFirewall(
				*observed,
				desired.ClusterID,
				desired.Shard,
				desired.Request.BillingAccountID,
				desired.Hash,
			) != nil {
			return nil, false, fmt.Errorf("node load balancer: stable shard firewall name %q resolved to a foreign or third-state resource after create response", desired.Request.DisplayName)
		}
		if err := c.transitionShardFirewallMutation(ctx, shard, ownerUID, expected, observed); err != nil {
			return nil, false, err
		}
		return observed, true, nil
	}
	return nil, false, errors.New("node load balancer: shard firewall create outcome remains ambiguous after exact name absence readback")
}

func (c *nodeLoadBalancerController) resolveShardFirewallUpdateReadback(
	ctx context.Context,
	shard string,
	ownerUID types.UID,
	expected map[string]string,
	desired nodeLoadBalancerShardFirewallPolicy,
) (*inspace.Firewall, bool, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: read back shard firewall after update response: %w", err)
	}
	appliedUUID := expected[annotationNodeLoadBalancerShardFirewallUUID]
	var byName, byUUID *inspace.Firewall
	for index := range items {
		item := items[index]
		if item.EffectiveName() == desired.Request.DisplayName {
			if byName != nil {
				return nil, false, fmt.Errorf("node load balancer: multiple firewalls use stable shard name %q after update response", desired.Request.DisplayName)
			}
			copy := item
			byName = &copy
		}
		if item.UUID == appliedUUID {
			if byUUID != nil {
				return nil, false, fmt.Errorf("node load balancer: shard firewall UUID %s appears multiple times after update response", appliedUUID)
			}
			copy := item
			byUUID = &copy
		}
	}
	if byName != nil && (byUUID == nil || byName.UUID != byUUID.UUID) {
		return nil, false, errors.New("node load balancer: stable shard name and applied UUID resolve to different resources after update response")
	}
	if byUUID != nil && byUUID.EffectiveName() != desired.Request.DisplayName {
		return nil, false, errors.New("node load balancer: applied shard firewall UUID lost its stable name after update response")
	}
	if byUUID == nil {
		return nil, false, errors.New("node load balancer: shard firewall update outcome remains ambiguous after exact UUID and name absence readback")
	}
	if byUUID.Description != "" && byUUID.Description != desired.Request.Description {
		return nil, false, fmt.Errorf("node load balancer: shard firewall %s has foreign description after update response", byUUID.UUID)
	}
	actualHash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(byUUID.Rules)
	if err != nil {
		return nil, false, fmt.Errorf("node load balancer: shard firewall %s policy after update response: %w", byUUID.UUID, err)
	}
	switch actualHash {
	case expected[annotationNodeLoadBalancerShardFWPendingHash]:
		if err := inspace.ValidateNodeLoadBalancerShardFirewall(
			*byUUID,
			desired.ClusterID,
			desired.Shard,
			desired.Request.BillingAccountID,
			actualHash,
		); err != nil {
			return nil, false, fmt.Errorf("node load balancer: pending shard firewall readback lost exact ownership: %w", err)
		}
		if err := c.transitionShardFirewallMutation(ctx, shard, ownerUID, expected, byUUID); err != nil {
			return nil, false, err
		}
		return byUUID, true, nil
	case expected[annotationNodeLoadBalancerShardFirewallHash]:
		if err := inspace.ValidateNodeLoadBalancerShardFirewall(
			*byUUID,
			desired.ClusterID,
			desired.Shard,
			desired.Request.BillingAccountID,
			actualHash,
		); err != nil {
			return nil, false, fmt.Errorf("node load balancer: unchanged shard firewall readback lost exact ownership: %w", err)
		}
		return nil, false, errors.New("node load balancer: shard firewall update outcome remains ambiguous after unchanged readback")
	default:
		return nil, false, fmt.Errorf("node load balancer: shard firewall %s is in a third policy state after update response", byUUID.UUID)
	}
}

func validateUpdatedNodeLoadBalancerShardFirewallResponse(
	response *inspace.Firewall,
	uuid string,
	desired nodeLoadBalancerShardFirewallPolicy,
) error {
	if response == nil || response.UUID == "" {
		return errors.New("response has no firewall UUID")
	}
	if response.UUID != uuid {
		return fmt.Errorf("response UUID %q does not match updated firewall %q", response.UUID, uuid)
	}
	if name := response.EffectiveName(); name != "" && name != desired.Request.DisplayName {
		return fmt.Errorf("response name %q does not match %q", name, desired.Request.DisplayName)
	}
	if response.BillingAccountID != 0 && response.BillingAccountID != desired.Request.BillingAccountID {
		return errors.New("response billing account does not match")
	}
	if response.Description != "" && response.Description != desired.Request.Description {
		return errors.New("response description does not match")
	}
	if len(response.Rules) != 0 {
		hash, err := inspace.NodeLoadBalancerShardFirewallSpecHash(response.Rules)
		if err != nil {
			return fmt.Errorf("response policy: %w", err)
		}
		if hash != desired.Hash {
			return fmt.Errorf("response policy hash %q does not match %q", hash, desired.Hash)
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) reconcileShardFirewallPolicy(
	ctx context.Context,
	shard string,
) (nodeLoadBalancerShardFirewallState, error) {
	state := nodeLoadBalancerShardFirewallState{}
	desired, desiredLedger, _, err := c.desiredStagedShardFirewallPolicy(ctx, shard)
	if err != nil {
		return state, err
	}
	if desired == nil {
		return state, nil
	}
	state.DesiredHash = desired.Hash
	state.DesiredLedger = desiredLedger

	pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		return state, fmt.Errorf("node load balancer: get NodePool %s for shard firewall: %w", shard, err)
	}
	poolLabels := pool.GetLabels()
	if poolLabels[nodeLoadBalancerManagedLabel] != "true" ||
		poolLabels[nodeLoadBalancerClusterLabel] != c.provider.config.ClusterID ||
		poolLabels[nodeLoadBalancerShardLabel] != shard ||
		!containsString(pool.GetFinalizers(), nodeLoadBalancerNodePoolFinalizer) ||
		pool.GetDeletionTimestamp() != nil {
		return state, fmt.Errorf("node load balancer: NodePool %s is not an authoritative live shard-state anchor", shard)
	}
	ownerUID := pool.GetUID()
	if ownerUID == "" {
		return state, fmt.Errorf("node load balancer: NodePool %s has an empty UID", shard)
	}
	annotations, err := nodeLoadBalancerShardFirewallAnnotations(pool)
	if err != nil {
		return state, err
	}
	stableName := desired.Request.DisplayName
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return state, fmt.Errorf("node load balancer: list shard firewalls: %w", err)
	}
	appliedUUID := annotations[annotationNodeLoadBalancerShardFirewallUUID]
	pendingUUID := annotations[annotationNodeLoadBalancerShardFWPendingUUID]
	var byName, byUUID, byPendingUUID *inspace.Firewall
	for index := range firewalls {
		firewall := firewalls[index]
		if firewall.EffectiveName() == stableName {
			if byName != nil {
				return state, fmt.Errorf("node load balancer: multiple firewalls use stable shard name %q", stableName)
			}
			copy := firewall
			byName = &copy
		}
		if appliedUUID != "" && firewall.UUID == appliedUUID {
			copy := firewall
			byUUID = &copy
		}
		if pendingUUID != "" && firewall.UUID == pendingUUID {
			copy := firewall
			byPendingUUID = &copy
		}
	}
	if byUUID != nil && byUUID.EffectiveName() != stableName {
		return state, fmt.Errorf("node load balancer: persisted shard firewall %s lost stable name %q", byUUID.UUID, stableName)
	}
	if byName != nil && byUUID != nil && byName.UUID != byUUID.UUID {
		return state, fmt.Errorf("node load balancer: stable shard firewall name %q and persisted UUID resolve to different resources", stableName)
	}
	if byPendingUUID != nil && byPendingUUID.EffectiveName() != stableName {
		return state, fmt.Errorf("node load balancer: pending shard firewall %s lost stable name %q", byPendingUUID.UUID, stableName)
	}
	if byName != nil && byPendingUUID != nil && byName.UUID != byPendingUUID.UUID {
		return state, fmt.Errorf("node load balancer: stable shard firewall name %q conflicts with pending UUID %s", stableName, pendingUUID)
	}
	if pendingUUID != "" && byName != nil && byName.UUID != pendingUUID {
		return state, fmt.Errorf("node load balancer: stable shard firewall UUID %s does not match pending UUID %s", byName.UUID, pendingUUID)
	}
	if pendingUUID != "" && appliedUUID != "" && pendingUUID != appliedUUID {
		return state, errors.New("node load balancer: pending and applied shard firewall UUIDs conflict")
	}
	var current *inspace.Firewall
	switch {
	case appliedUUID != "" && byUUID == nil:
		if byName != nil {
			return state, fmt.Errorf("node load balancer: persisted shard firewall %s is absent but stable name resolves to different UUID %s", appliedUUID, byName.UUID)
		}
		confirmed, _, absenceErr := c.recordManagedNodePoolFirewallAbsenceForUID(
			ctx, shard, ownerUID,
			annotationNodeLoadBalancerShardFWAbsent,
			annotationNodeLoadBalancerShardFWAbsentChecked,
			time.Now().UTC(), time.Time{},
		)
		if absenceErr != nil {
			return state, absenceErr
		}
		if !confirmed {
			return state, nil
		}
		_, _, clearErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
			if values[annotationNodeLoadBalancerShardFirewallUUID] != appliedUUID {
				return false, errors.New("node load balancer: applied shard firewall identity changed during absence proof")
			}
			for _, key := range []string{
				annotationNodeLoadBalancerShardFirewallUUID,
				annotationNodeLoadBalancerShardFirewallHash,
				annotationNodeLoadBalancerShardFirewallLedger,
				annotationNodeLoadBalancerShardFWAbsent,
				annotationNodeLoadBalancerShardFWAbsentChecked,
			} {
				delete(values, key)
			}
			return true, nil
		})
		return state, clearErr
	case appliedUUID != "":
		current = byUUID
		if _, clearErr := c.clearManagedNodePoolFirewallAbsenceForUID(
			ctx, shard, ownerUID,
			annotationNodeLoadBalancerShardFWAbsent,
			annotationNodeLoadBalancerShardFWAbsentChecked,
		); clearErr != nil {
			return state, clearErr
		}
	case pendingUUID != "":
		current = byPendingUUID
		if current == nil {
			current = byName
		}
	default:
		current = byName
	}
	if current != nil {
		if _, clearErr := c.clearManagedNodePoolFirewallAbsenceForUID(
			ctx, shard, ownerUID,
			annotationNodeLoadBalancerShardFWCreateAbsent,
			annotationNodeLoadBalancerShardFWCreateChecked,
		); clearErr != nil {
			return state, clearErr
		}
	}
	if current != nil {
		actualHash, hashErr := inspace.NodeLoadBalancerShardFirewallSpecHash(current.Rules)
		if hashErr != nil {
			return state, fmt.Errorf("node load balancer: shard firewall %s policy: %w", current.UUID, hashErr)
		}
		if validateErr := inspace.ValidateNodeLoadBalancerShardFirewall(
			*current,
			c.provider.config.ClusterID,
			shard,
			c.provider.config.BillingAccountID,
			actualHash,
		); validateErr != nil {
			return state, fmt.Errorf("node load balancer: shard firewall %s lost exact ownership: %w", current.UUID, validateErr)
		}
		if current.Description != "" && current.Description != nodeLoadBalancerShardFirewallDescription {
			return state, fmt.Errorf("node load balancer: shard firewall %s has foreign description %q", current.UUID, current.Description)
		}

		appliedHash := annotations[annotationNodeLoadBalancerShardFirewallHash]
		appliedLedger := annotations[annotationNodeLoadBalancerShardFirewallLedger]
		pendingHash := annotations[annotationNodeLoadBalancerShardFWPendingHash]
		pendingLedger := annotations[annotationNodeLoadBalancerShardFWPendingLedger]
		switch {
		case pendingHash != "" && actualHash == pendingHash:
			if _, changed, promoteErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
				values[annotationNodeLoadBalancerShardFirewallUUID] = current.UUID
				values[annotationNodeLoadBalancerShardFirewallHash] = pendingHash
				values[annotationNodeLoadBalancerShardFirewallLedger] = pendingLedger
				for _, key := range []string{annotationNodeLoadBalancerShardFWPendingHash, annotationNodeLoadBalancerShardFWPendingLedger, annotationNodeLoadBalancerShardFWPendingAt, annotationNodeLoadBalancerShardFWIssuedAt, annotationNodeLoadBalancerShardFWPendingUUID, annotationNodeLoadBalancerShardFWCreateAbsent, annotationNodeLoadBalancerShardFWCreateChecked, annotationNodeLoadBalancerShardFWAbsent, annotationNodeLoadBalancerShardFWAbsentChecked} {
					delete(values, key)
				}
				return true, nil
			}); promoteErr != nil {
				return state, promoteErr
			} else if changed {
				state.Firewall = current
				state.AppliedHash = pendingHash
				state.AppliedLedger = pendingLedger
				state.PolicyReady = pendingHash == desired.Hash && pendingLedger == desiredLedger
				return state, nil
			}
		case appliedHash == "" && actualHash == desired.Hash:
			if _, changed, adoptErr := c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
				values[annotationNodeLoadBalancerShardFirewallUUID] = current.UUID
				values[annotationNodeLoadBalancerShardFirewallHash] = desired.Hash
				values[annotationNodeLoadBalancerShardFirewallLedger] = desiredLedger
				for _, key := range []string{annotationNodeLoadBalancerShardFWPendingHash, annotationNodeLoadBalancerShardFWPendingLedger, annotationNodeLoadBalancerShardFWPendingAt, annotationNodeLoadBalancerShardFWIssuedAt, annotationNodeLoadBalancerShardFWPendingUUID, annotationNodeLoadBalancerShardFWCreateAbsent, annotationNodeLoadBalancerShardFWCreateChecked, annotationNodeLoadBalancerShardFWAbsent, annotationNodeLoadBalancerShardFWAbsentChecked} {
					delete(values, key)
				}
				return true, nil
			}); adoptErr != nil {
				return state, adoptErr
			} else if changed {
				state.Firewall = current
				state.AppliedHash = desired.Hash
				state.AppliedLedger = desiredLedger
				state.PolicyReady = true
				return state, nil
			}
		case appliedHash == "" || actualHash != appliedHash:
			return state, fmt.Errorf("node load balancer: shard firewall %s policy hash %s matches neither applied nor pending state", current.UUID, actualHash)
		}
		state.Firewall = current
		state.AppliedHash = appliedHash
		state.AppliedLedger = appliedLedger
	}

	if current == nil {
		if annotations[annotationNodeLoadBalancerShardFirewallUUID] != "" {
			return state, fmt.Errorf("node load balancer: persisted shard firewall %s is absent from authoritative readback", annotations[annotationNodeLoadBalancerShardFirewallUUID])
		}
		if annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" {
			_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
				values[annotationNodeLoadBalancerShardFWPendingHash] = desired.Hash
				values[annotationNodeLoadBalancerShardFWPendingLedger] = desiredLedger
				values[annotationNodeLoadBalancerShardFWPendingAt] = time.Now().UTC().Format(time.RFC3339Nano)
				delete(values, annotationNodeLoadBalancerShardFWCreateAbsent)
				delete(values, annotationNodeLoadBalancerShardFWCreateChecked)
				return true, nil
			})
			return state, err
		}
		if annotations[annotationNodeLoadBalancerShardFWPendingHash] != desired.Hash ||
			annotations[annotationNodeLoadBalancerShardFWPendingLedger] != desiredLedger {
			if annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
				return state, errors.New("node load balancer: waiting for an issued shard firewall create before changing desired policy")
			}
			_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
				values[annotationNodeLoadBalancerShardFWPendingHash] = desired.Hash
				values[annotationNodeLoadBalancerShardFWPendingLedger] = desiredLedger
				values[annotationNodeLoadBalancerShardFWPendingAt] = time.Now().UTC().Format(time.RFC3339Nano)
				delete(values, annotationNodeLoadBalancerShardFWCreateAbsent)
				delete(values, annotationNodeLoadBalancerShardFWCreateChecked)
				return true, nil
			})
			return state, err
		}
		if issued := annotations[annotationNodeLoadBalancerShardFWIssuedAt]; issued != "" {
			// No finite sequence of empty Lists proves that a timed-out paid POST
			// cannot commit later. Keep the NodePool finalizer and immutable intent
			// forever until the exact stable-name firewall becomes observable (and
			// can be adopted), or an operator resolves the cloud-side attempt.
			return state, fmt.Errorf(
				"node load balancer: shard firewall create issued at %s remains ambiguous; refusing a second paid create until the original firewall is observable or manually resolved",
				issued,
			)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		expectedStaged := nodeLoadBalancerShardFirewallMutationExpected(annotations, "")
		expectedMutation, issueErr := c.issueShardFirewallMutation(ctx, shard, ownerUID, expectedStaged, now, true)
		if issueErr != nil {
			return state, issueErr
		}
		rejectUndispatched := func(rejection error) (nodeLoadBalancerShardFirewallState, error) {
			resetErr := c.resetShardFirewallMutationAfterProvenNonDispatch(ctx, shard, ownerUID, expectedMutation)
			state.MutationIssued = resetErr != nil
			return state, errors.Join(rejection, resetErr)
		}
		observed, absent, authorityErr := c.exactNodeLoadBalancerFirewallNameFresh(ctx, desired.Request.DisplayName)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: authorize shard firewall create after issue: %w", authorityErr))
		}
		if !absent {
			if observed == nil || !validNodeLoadBalancerCloudUUID(observed.UUID) ||
				(observed.Description != "" && observed.Description != desired.Request.Description) ||
				inspace.ValidateNodeLoadBalancerShardFirewall(
					*observed,
					desired.ClusterID,
					desired.Shard,
					desired.Request.BillingAccountID,
					desired.Hash,
				) != nil {
				return rejectUndispatched(fmt.Errorf(
					"node load balancer: stable shard firewall name %q became foreign after create issue",
					desired.Request.DisplayName,
				))
			}
			observed, committed, recoveryErr := c.resolveShardFirewallCreateReadback(
				ctx, shard, ownerUID, expectedMutation, *desired,
			)
			if recoveryErr != nil {
				return rejectUndispatched(recoveryErr)
			}
			if !committed {
				return rejectUndispatched(errors.New("node load balancer: observed shard firewall was not durably promoted"))
			}
			state.Firewall = observed
			state.AppliedHash = desired.Hash
			state.AppliedLedger = desiredLedger
			state.PolicyReady = true
			return state, nil
		}
		if authorityErr := c.authorizeShardFirewallPolicyMutationPreDispatch(
			ctx, shard, ownerUID, expectedMutation, *desired, desiredLedger,
		); authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: reject shard firewall create at final authority: %w", authorityErr))
		}
		created, createErr := c.provider.api.CreateFirewall(ctx, c.provider.config.Location, desired.Request)
		if createErr != nil {
			wrappedErr := fmt.Errorf("node load balancer: create shard firewall: %w", createErr)
			if nodeLoadBalancerMutationKnownPreDispatch(createErr) {
				resetErr := c.resetShardFirewallMutationAfterProvenNonDispatch(ctx, shard, ownerUID, expectedMutation)
				state.MutationIssued = resetErr != nil
				return state, errors.Join(
					wrappedErr,
					resetErr,
				)
			}
			observed, committed, recoveryErr := c.resolveShardFirewallCreateReadback(
				ctx, shard, ownerUID, expectedMutation, *desired,
			)
			if recoveryErr != nil {
				return state, errors.Join(wrappedErr, recoveryErr)
			}
			if committed {
				state.Firewall = observed
				state.AppliedHash = desired.Hash
				state.AppliedLedger = desiredLedger
				state.PolicyReady = true
				return state, nil
			}
			return state, wrappedErr
		}
		if responseErr := validateCreatedNodeLoadBalancerFirewall(
			created,
			desiredNodeLoadBalancerFirewall{Request: desired.Request, Hash: desired.Hash},
		); responseErr != nil {
			wrappedErr := fmt.Errorf("node load balancer: created shard firewall response: %w", responseErr)
			observed, committed, recoveryErr := c.resolveShardFirewallCreateReadback(
				ctx, shard, ownerUID, expectedMutation, *desired,
			)
			if recoveryErr != nil {
				return state, errors.Join(wrappedErr, recoveryErr)
			}
			if committed {
				state.Firewall = observed
				state.AppliedHash = desired.Hash
				state.AppliedLedger = desiredLedger
				state.PolicyReady = true
				return state, nil
			}
			return state, wrappedErr
		}
		// The response UUID is provisional only. Canonical identity is promoted
		// exclusively from a unique deterministic-name ListFirewalls readback.
		observed, committed, recoveryErr := c.resolveShardFirewallCreateReadback(
			ctx, shard, ownerUID, expectedMutation, *desired,
		)
		if recoveryErr != nil {
			state.MutationIssued = true
			return state, recoveryErr
		}
		if committed {
			state.Firewall = observed
			state.AppliedHash = desired.Hash
			state.AppliedLedger = desiredLedger
			state.PolicyReady = true
			return state, nil
		}
		state.MutationIssued = true
		return state, errors.New("node load balancer: shard firewall create response lacks authoritative readback")
	}

	if state.AppliedHash == desired.Hash && state.AppliedLedger == desiredLedger {
		state.PolicyReady = true
	} else if state.AppliedHash == desired.Hash && annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" {
		_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
			values[annotationNodeLoadBalancerShardFirewallLedger] = desiredLedger
			return true, nil
		})
		return state, err
	} else if annotations[annotationNodeLoadBalancerShardFWPendingHash] == "" {
		_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
			values[annotationNodeLoadBalancerShardFWPendingHash] = desired.Hash
			values[annotationNodeLoadBalancerShardFWPendingLedger] = desiredLedger
			values[annotationNodeLoadBalancerShardFWPendingAt] = time.Now().UTC().Format(time.RFC3339Nano)
			return true, nil
		})
		return state, err
	} else {
		pendingHash := annotations[annotationNodeLoadBalancerShardFWPendingHash]
		pendingLedger := annotations[annotationNodeLoadBalancerShardFWPendingLedger]
		if pendingHash != desired.Hash || pendingLedger != desiredLedger {
			if annotations[annotationNodeLoadBalancerShardFWIssuedAt] != "" {
				return state, errors.New("node load balancer: waiting for issued shard firewall update to resolve")
			}
			_, _, err = c.updateManagedNodePoolAnnotationsForUID(ctx, shard, ownerUID, func(values map[string]string) (bool, error) {
				values[annotationNodeLoadBalancerShardFWPendingHash] = desired.Hash
				values[annotationNodeLoadBalancerShardFWPendingLedger] = desiredLedger
				values[annotationNodeLoadBalancerShardFWPendingAt] = time.Now().UTC().Format(time.RFC3339Nano)
				return true, nil
			})
			return state, err
		}
		if issued := annotations[annotationNodeLoadBalancerShardFWIssuedAt]; issued != "" {
			// A second PUT can outlive this generation and commit after a later
			// policy, reverting the public firewall to stale or broader rules. No
			// elapsed time or finite run of old-policy readbacks proves the issued
			// request cannot still commit. Wait for the exact pending policy to
			// become observable (the promotion path above), or operator resolution.
			return state, fmt.Errorf(
				"node load balancer: shard firewall update issued at %s remains ambiguous; refusing another mutation until the pending policy is observable or manually resolved",
				issued,
			)
		}
		request, requestErr := nodeLoadBalancerShardFirewallUpdateRequest(*state.Firewall, *desired)
		if requestErr != nil {
			return state, requestErr
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		expectedStaged := nodeLoadBalancerShardFirewallMutationExpected(annotations, "")
		expectedMutation, issueErr := c.issueShardFirewallMutation(ctx, shard, ownerUID, expectedStaged, now, false)
		if issueErr != nil {
			return state, issueErr
		}
		rejectUndispatched := func(rejection error) (nodeLoadBalancerShardFirewallState, error) {
			resetErr := c.resetShardFirewallMutationAfterProvenNonDispatch(ctx, shard, ownerUID, expectedMutation)
			state.MutationIssued = resetErr != nil
			return state, errors.Join(rejection, resetErr)
		}
		if authorityErr := c.authorizeShardFirewallPolicyMutationPreDispatch(
			ctx, shard, ownerUID, expectedMutation, *desired, desiredLedger,
		); authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: reject shard firewall update at final authority: %w", authorityErr))
		}
		fresh, authorityErr := c.exactNodeLoadBalancerFirewallFresh(ctx, state.Firewall.UUID)
		if authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: authorize shard firewall update after issue: %w", authorityErr))
		}
		if !nodeLoadBalancerFirewallAuthorityUnchanged(*state.Firewall, *fresh) {
			return rejectUndispatched(errors.New("node load balancer: shard firewall changed after update issue"))
		}
		if err := inspace.ValidateNodeLoadBalancerShardFirewall(
			*fresh,
			desired.ClusterID,
			desired.Shard,
			desired.Request.BillingAccountID,
			expectedMutation[annotationNodeLoadBalancerShardFirewallHash],
		); err != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: shard firewall lost exact applied-policy authority after update issue: %w", err))
		}
		// Keep the live Service policy check adjacent to the provider boundary;
		// the cloud read above may itself take long enough for policy to change.
		if authorityErr := c.authorizeShardFirewallPolicyMutationPreDispatch(
			ctx, shard, ownerUID, expectedMutation, *desired, desiredLedger,
		); authorityErr != nil {
			return rejectUndispatched(fmt.Errorf("node load balancer: reject shard firewall update at final authority: %w", authorityErr))
		}
		updated, updateErr := c.provider.api.UpdateFirewall(ctx, c.provider.config.Location, state.Firewall.UUID, request)
		if updateErr != nil {
			wrappedErr := fmt.Errorf("node load balancer: update shard firewall %s: %w", state.Firewall.UUID, updateErr)
			if nodeLoadBalancerMutationKnownPreDispatch(updateErr) {
				resetErr := c.resetShardFirewallMutationAfterProvenNonDispatch(ctx, shard, ownerUID, expectedMutation)
				state.MutationIssued = resetErr != nil
				return state, errors.Join(
					wrappedErr,
					resetErr,
				)
			}
			observed, committed, recoveryErr := c.resolveShardFirewallUpdateReadback(
				ctx, shard, ownerUID, expectedMutation, *desired,
			)
			if recoveryErr != nil {
				state.MutationIssued = true
				return state, errors.Join(wrappedErr, recoveryErr)
			}
			if committed {
				state.Firewall = observed
				state.AppliedHash = desired.Hash
				state.AppliedLedger = desiredLedger
				state.PolicyReady = true
				return state, nil
			}
			state.MutationIssued = true
			return state, wrappedErr
		}
		if responseErr := validateUpdatedNodeLoadBalancerShardFirewallResponse(updated, state.Firewall.UUID, *desired); responseErr != nil {
			wrappedErr := fmt.Errorf("node load balancer: updated shard firewall response: %w", responseErr)
			observed, committed, recoveryErr := c.resolveShardFirewallUpdateReadback(
				ctx, shard, ownerUID, expectedMutation, *desired,
			)
			if recoveryErr != nil {
				state.MutationIssued = true
				return state, errors.Join(wrappedErr, recoveryErr)
			}
			if committed {
				state.Firewall = observed
				state.AppliedHash = desired.Hash
				state.AppliedLedger = desiredLedger
				state.PolicyReady = true
				return state, nil
			}
			state.MutationIssued = true
			return state, wrappedErr
		}
		state.MutationIssued = true
		return state, nil
	}
	return state, nil
}

// ensureShardFirewallAssignments never detaches from an authorized NotReady
// Node. Transient kubelet loss only withdraws Cilium/public status; retaining
// the firewall avoids the attach/detach feedback loop proven by live testing.
func (c *nodeLoadBalancerController) ensureShardFirewallAssignments(
	ctx context.Context,
	shard string,
	firewall inspace.Firewall,
) (bool, *inspace.Firewall, error) {
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.shardFirewallRelationOwner(shard),
		nil,
	)
	if err != nil {
		return false, nil, err
	}
	if !converged {
		return false, nil, nil
	}
	nodes, err := c.authorizedNodesForShard(ctx, shard)
	if err != nil {
		return false, nil, err
	}
	// Retention is derived from the API-owned NodePool -> NodeClaim -> providerID
	// chain, not mutable Node health or ordinary labels. A NotReady Node keeps
	// its firewall until Karpenter has authoritatively removed its NodeClaim.
	desiredVMs, err := c.retainedShardVMIdentities(ctx, shard)
	if err != nil {
		return false, nil, err
	}
	// A protected ready label is a one-pass detach fence if the NodeClaim has
	// just disappeared. Eligibility reconciliation closes the Node first; only a
	// later pass may detach the now-unclaimed VM.
	protectedVMs := map[string]struct{}{}
	allNodes, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, nil, fmt.Errorf("node load balancer: list Nodes before shard firewall detach: %w", err)
	}
	for index := range allNodes.Items {
		node := &allNodes.Items[index]
		if node.Labels[nodeLoadBalancerNodeClusterLabel] != c.provider.config.ClusterID ||
			node.Labels[nodeLoadBalancerNodeShardLabel] != shard ||
			node.Labels[nodeLoadBalancerReadyLabel] != "true" {
			continue
		}
		if vmUUID, ok := nodeLoadBalancerVMUUID(node); ok {
			protectedVMs[vmUUID] = struct{}{}
		}
	}
	healthyVMs := map[string]struct{}{}
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			return false, nil, fmt.Errorf("node load balancer: authorized Node %s has no VM identity", node.Name)
		}
		if nodeLoadBalancerNodeHealthy(node) {
			healthyVMs[vmUUID] = struct{}{}
		}
	}
	assignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
	if err != nil {
		return false, nil, err
	}
	for vmUUID := range assignments {
		if _, desired := desiredVMs[vmUUID]; desired {
			continue
		}
		if _, protected := protectedVMs[vmUUID]; protected {
			return false, &firewall, nil
		}
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.shardFirewallRelationOwner(shard),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationUnassign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if relationErr != nil {
			return false, nil, fmt.Errorf("node load balancer: detach shard firewall %s from stale VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		if !converged {
			return false, nil, nil
		}
	}
	for vmUUID := range healthyVMs {
		if _, assigned := assignments[strings.ToLower(vmUUID)]; assigned {
			continue
		}
		for _, node := range nodes {
			nodeVM, ok := nodeLoadBalancerVMUUID(node)
			if ok && nodeVM == vmUUID && node.Labels[nodeLoadBalancerReadyLabel] == "true" {
				// The eligibility reconciliation immediately following this call
				// withdraws the node first. Attachment happens on a later pass once
				// the protected label is authoritatively absent.
				return false, &firewall, nil
			}
		}
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.shardFirewallRelationOwner(shard),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if relationErr != nil {
			return false, nil, fmt.Errorf("node load balancer: attach shard firewall %s to new VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		if !converged {
			return false, nil, nil
		}
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, nil, err
	}
	for index := range firewalls {
		if firewalls[index].UUID != firewall.UUID {
			continue
		}
		current := firewalls[index]
		stale, err := staleNodeLoadBalancerFirewallAssignments(current, desiredVMs)
		if err != nil || len(stale) != 0 {
			return false, &current, errors.Join(err, fmt.Errorf("node load balancer: shard firewall retains stale assignments %v", stale))
		}
		for vmUUID := range healthyVMs {
			if !firewallAssignedToVM(current, vmUUID) {
				return false, &current, nil
			}
		}
		return true, &current, nil
	}
	return false, nil, fmt.Errorf("node load balancer: shard firewall %s disappeared during assignment readback", firewall.UUID)
}

func (c *nodeLoadBalancerController) retainedShardVMIdentities(
	ctx context.Context,
	shard string,
) (map[string]struct{}, error) {
	if !isManagedNodeLoadBalancerShardName(shard) {
		return nil, fmt.Errorf("node load balancer: invalid shard %q for VM retention", shard)
	}
	nodeClassName := managedNodeLoadBalancerName(c.provider.config.ClusterID, "node-lb")
	pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: get NodePool %s for VM retention: %w", shard, err)
	}
	if !c.nodeLoadBalancerNodePoolAuthoritative(pool, shard, nodeClassName) {
		return nil, fmt.Errorf("node load balancer: NodePool %s is not authoritative for VM retention", shard)
	}
	claims, err := c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{karpenterNodePoolLabel: shard}).String(),
	})
	if err != nil {
		return nil, fmt.Errorf("node load balancer: list NodeClaims for VM retention: %w", err)
	}
	result := make(map[string]struct{}, len(claims.Items))
	for index := range claims.Items {
		claim := &claims.Items[index]
		claimLabels := claim.GetLabels()
		if claimLabels[karpenterNodePoolLabel] != shard ||
			claimLabels[nodeLoadBalancerNodeLabel] != "true" ||
			claimLabels[nodeLoadBalancerNodeClusterLabel] != c.provider.config.ClusterID ||
			claimLabels[nodeLoadBalancerNodeShardLabel] != shard {
			continue
		}
		if claim.GetUID() == "" || !strings.HasPrefix(claim.GetName(), shard+"-") ||
			!nodeLoadBalancerNodeClassRefMatches(claim, []string{"spec", "nodeClassRef"}, nodeClassName) ||
			!hasExactSingleNodeLoadBalancerOwnerReference(
				claim.GetOwnerReferences(), "karpenter.sh/v1", "NodePool", pool.GetName(), pool.GetUID(),
			) {
			return nil, fmt.Errorf("node load balancer: managed NodeClaim %s lost exact retention identity", claim.GetName())
		}
		providerID, found, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
		if providerErr != nil {
			return nil, fmt.Errorf("node load balancer: managed NodeClaim %s has malformed retention providerID: %w", claim.GetName(), providerErr)
		}
		if !found || strings.TrimSpace(providerID) == "" {
			// A freshly created NodeClaim has not launched a VM yet. It owns no
			// firewall-retention identity until Karpenter publishes providerID.
			continue
		}
		identity, parseErr := providerid.Parse(providerID)
		if parseErr != nil || identity.Location != c.provider.config.Location || identity.String() != providerID {
			return nil, fmt.Errorf("node load balancer: managed NodeClaim %s has invalid retention providerID", claim.GetName())
		}
		if _, duplicate := result[identity.UUID]; duplicate {
			return nil, fmt.Errorf("node load balancer: duplicate retained VM identity %s", identity.UUID)
		}
		result[identity.UUID] = struct{}{}
	}
	return result, nil
}

func (c *nodeLoadBalancerController) reconcileAggregateShardNodeEligibility(
	ctx context.Context,
	shard string,
	firewall *inspace.Firewall,
	appliedHash string,
	requireFirewall bool,
) error {
	rawNodes, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return err
	}
	nodes, err := c.authorizedNodeLoadBalancerNodes(ctx, rawNodes, shard)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	firewalls, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	icmpFirewall, err := c.currentClusterICMPFirewall(ctx, firewalls)
	if err != nil || icmpFirewall == nil {
		return errors.Join(err, c.setShardNodesReady(ctx, rawNodes, nil))
	}
	if requireFirewall {
		if firewall == nil || !validNodeLoadBalancerShardFirewallPolicyHash(appliedHash) {
			return c.setShardNodesReady(ctx, rawNodes, nil)
		}
		var current *inspace.Firewall
		for index := range firewalls {
			if firewalls[index].UUID == firewall.UUID {
				copy := firewalls[index]
				current = &copy
				break
			}
		}
		if current == nil {
			return errors.Join(
				errors.New("node load balancer: aggregate firewall disappeared before eligibility readback"),
				c.setShardNodesReady(ctx, rawNodes, nil),
			)
		}
		actualHash, hashErr := inspace.NodeLoadBalancerShardFirewallSpecHash(current.Rules)
		if hashErr != nil || actualHash != appliedHash {
			return errors.Join(
				hashErr,
				fmt.Errorf("node load balancer: aggregate firewall policy changed before eligibility readback: got %s, want %s", actualHash, appliedHash),
				c.setShardNodesReady(ctx, rawNodes, nil),
			)
		}
		if validateErr := inspace.ValidateNodeLoadBalancerShardFirewall(
			*current,
			c.provider.config.ClusterID,
			shard,
			c.provider.config.BillingAccountID,
			actualHash,
		); validateErr != nil {
			return errors.Join(validateErr, c.setShardNodesReady(ctx, rawNodes, nil))
		}
		firewall = current
	}
	ready := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		eligible := ok && nodeLoadBalancerNodeHealthy(node) && firewallAssignedToVM(*icmpFirewall, vmUUID)
		if requireFirewall {
			eligible = eligible && firewall != nil && firewallAssignedToVM(*firewall, vmUUID)
		}
		ready[node.Name] = eligible
	}
	return c.setShardNodesReady(ctx, rawNodes, ready)
}

func managedNodeLoadBalancerNodeClaimsRemain(items []unstructured.Unstructured, shard, cluster string) bool {
	for index := range items {
		labels := items[index].GetLabels()
		if labels[karpenterNodePoolLabel] == shard &&
			labels[nodeLoadBalancerNodeLabel] == "true" &&
			labels[nodeLoadBalancerNodeClusterLabel] == cluster {
			return true
		}
	}
	return false
}

func (c *nodeLoadBalancerController) managedShardNodeClaimsRemain(ctx context.Context, shard string) (bool, error) {
	claims, err := c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{karpenterNodePoolLabel: shard}).String(),
	})
	if err != nil {
		return false, err
	}
	return managedNodeLoadBalancerNodeClaimsRemain(claims.Items, shard, c.provider.config.ClusterID), nil
}

func (c *nodeLoadBalancerController) managedShardCapacityAbsent(ctx context.Context, shard string) (bool, error) {
	if pool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{}); err == nil {
		poolLabels := pool.GetLabels()
		heldOnlyByStateFinalizer := pool.GetDeletionTimestamp() != nil &&
			poolLabels[nodeLoadBalancerManagedLabel] == "true" &&
			poolLabels[nodeLoadBalancerClusterLabel] == c.provider.config.ClusterID &&
			poolLabels[nodeLoadBalancerShardLabel] == shard &&
			len(pool.GetFinalizers()) == 1 &&
			pool.GetFinalizers()[0] == nodeLoadBalancerNodePoolFinalizer
		if !heldOnlyByStateFinalizer {
			return false, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return false, err
	}
	claimsRemain, err := c.managedShardNodeClaimsRemain(ctx, shard)
	if err != nil {
		return false, err
	}
	if claimsRemain {
		return false, nil
	}
	nodes, err := c.rawNodesForShard(ctx, shard)
	if err != nil {
		return false, err
	}
	return len(nodes) == 0, nil
}
