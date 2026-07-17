package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudv1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

const (
	publicNodeLocalFinalizer = "service.inspace.cloud/public-node-local"

	annotationPublicNodeLocalActivePool   = "service.inspace.cloud/public-node-local-active-pool"
	annotationPublicNodeLocalActivePolicy = "service.inspace.cloud/public-node-local-active-policy"
	annotationPublicNodeLocalDatapathPool = "service.inspace.cloud/public-node-local-pool"
	annotationPublicNodeLocalConflict     = "service.inspace.cloud/public-node-local-conflict"
	annotationPublicNodeLocalAssignPolicy = "service.inspace.cloud/public-node-local-assigning-policy"
	annotationPublicNodeLocalAssignVMs    = "service.inspace.cloud/public-node-local-assigning-vms"

	publicNodeLocalFirewallProfile = "public-node-local"
)

type publicNodeLocalVMOwnership struct {
	Schema           string `json:"schema"`
	Cluster          string `json:"cluster"`
	NodePool         string `json:"nodePool"`
	NodeClaim        string `json:"nodeClaim"`
	VMName           string `json:"vmName"`
	FirewallProfile  string `json:"firewallProfile"`
	FirewallUUID     string `json:"firewallUUID"`
	NetworkUUID      string `json:"networkUUID"`
	BillingAccountID int64  `json:"billingAccountID"`
	FloatingIPName   string `json:"floatingIPName"`
	PublicIPv4       string `json:"publicIPv4"`
}

func publicNodeLocalRequested(service *corev1.Service) bool {
	return isNodeLoadBalancerService(service) &&
		strings.TrimSpace(service.Annotations[annotationNodeLoadBalancerMode]) == nodeLoadBalancerModeLocal
}

func (c *nodeLoadBalancerController) syncPublicNodeLocal(
	ctx context.Context,
	key string,
	service *corev1.Service,
) error {
	if service == nil {
		return errors.New("public-node-local: Service is required")
	}
	if service.DeletionTimestamp != nil || !publicNodeLocalRequested(service) {
		if containsString(service.Finalizers, publicNodeLocalFinalizer) {
			return c.cleanupPublicNodeLocal(ctx, key, service)
		}
		return nil
	}

	defaults := nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard}
	intent, err := parseNodeLoadBalancerService(service, defaults)
	if err != nil || intent.Mode != nodeLoadBalancerModeLocal {
		cause := err
		if cause == nil {
			cause = errors.New("public-node-local: parsed Service mode is not public-node-local")
		}
		if containsString(service.Finalizers, publicNodeLocalFinalizer) {
			return c.failPublicNodeLocalClosed(ctx, service, cause)
		}
		return cause
	}
	if !containsString(service.Finalizers, publicNodeLocalFinalizer) {
		patched, err := c.ensurePublicNodeLocalFinalizer(ctx, service)
		if err != nil || patched {
			return err
		}
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}

	desiredFirewall, err := c.desiredServiceFirewall(service)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	activePool := service.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := service.Annotations[annotationPublicNodeLocalActivePolicy]
	if (activePool == "") != (activePolicy == "") {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: incomplete persisted activation identity"))
	}
	if activePool == "" && len(service.Status.LoadBalancer.Ingress) != 0 {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: public status exists without persisted activation authorization"))
	}
	if activePool != "" && (activePool != intent.Pool || activePolicy != desiredFirewall.Hash) {
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	addresses, patchedNode, err := c.publicNodeLocalAddresses(ctx, service, intent)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, service, intent)
	if loses {
		cause := conflictErr
		if cause == nil {
			cause = fmt.Errorf("public-node-local: Service %s/%s lost a deterministic protocol/port claim in pool %s", service.Namespace, service.Name, intent.Pool)
		}
		return errors.Join(c.recordPublicNodeLocalConflictEvent(ctx, service, cause), c.failPublicNodeLocalClosed(ctx, service, cause))
	}
	if conflictErr != nil {
		return c.failPublicNodeLocalClosed(ctx, service, conflictErr)
	}
	if cleared, err := c.clearPublicNodeLocalConflict(ctx, service); err != nil || cleared {
		if cleared {
			c.requeuePublicNodeLocal(key)
		}
		return err
	}
	if winnerWaiting {
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	desiredPublicStatus := nodeLoadBalancerStatus(append([]nodeLoadBalancerAddress(nil), addresses...), true)
	if len(service.Status.LoadBalancer.Ingress) != 0 && !reflect.DeepEqual(service.Status.LoadBalancer, desiredPublicStatus) {
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	datapath, changed, err := c.ensurePublicNodeLocalDatapath(ctx, service, intent.Pool)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if changed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	selectedNodes := make([]*corev1.Node, 0, len(addresses))
	for _, address := range addresses {
		selectedNodes = append(selectedNodes, address.Node)
	}
	desiredPrivateStatus := nodeLoadBalancerStatus(append([]nodeLoadBalancerAddress(nil), addresses...), false)
	if len(selectedNodes) == 0 || publicNodeLocalStatusRemovesAddress(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		// A removed private frontend must never precede closure of its public
		// firewall edge. Withdraw all assignments and prove the readback first;
		// a later reconciliation rebuilds the retained/additional frontends.
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		if len(selectedNodes) != 0 || patchedNode {
			c.requeuePublicNodeLocal(key)
		}
		return nil
	}
	var firewall *inspace.Firewall
	var waiting bool
	service, firewall, waiting, err = c.preparePublicNodeLocalFirewall(ctx, service)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if waiting {
		if activePool != "" {
			return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: active Service firewall is not authoritatively ready"))
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if activePool == "" && !reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		// Recovery and first bootstrap both prove the Service firewall fully
		// detached before reactivating the private Cilium frontend. This
		// closes the stale-assignment window after an uncertain cloud read.
		if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, nil); err != nil {
			return c.failPublicNodeLocalClosed(ctx, service, err)
		}
	}
	datapath, changed, err = c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, intent.Pool, desiredPrivateStatus)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if changed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if !reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: private datapath status did not read back exactly"))
	}

	if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, selectedNodes); err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}

	assignmentsMatch, err := c.publicNodeLocalFirewallAssignmentsMatch(ctx, service, intent, desiredFirewall, firewall.UUID, selectedNodes)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if !assignmentsMatch {
		service, _, err = c.ensurePublicNodeLocalAssignmentIntent(ctx, service, intent, desiredFirewall, firewall.UUID, addresses)
		if err != nil {
			return c.failPublicNodeLocalClosed(ctx, service, err)
		}
		// A fresh exact fence may have been persisted by a previous process that
		// crashed before (or midway through) the cloud assignment. Always resume
		// the idempotent missing assignments after the helper has validated that
		// durable authorization; the cloud mutation validates it again per VM.
		if err := c.assignPublicNodeLocalFirewallWithFence(ctx, service, intent, desiredFirewall, firewall, addresses); err != nil {
			return c.failPublicNodeLocalClosed(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	assignmentsMatch, err = c.publicNodeLocalFirewallAssignmentsMatch(ctx, service, intent, desiredFirewall, firewall.UUID, selectedNodes)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if !assignmentsMatch {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: firewall assignments changed after exact readback"))
	}
	assignmentFencePresent := publicNodeLocalAssignmentFencePresent(service)
	if assignmentFencePresent && service.Annotations[annotationNodeLoadBalancerFirewallAssigning] == "" {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: incomplete durable assignment authorization cannot be adopted"))
	}
	if !assignmentFencePresent && (activePool == "" || !reflect.DeepEqual(service.Status.LoadBalancer, desiredPublicStatus)) {
		return c.failPublicNodeLocalClosed(ctx, service, errors.New("public-node-local: inactive or unpublished firewall assignment has no durable authorization fence"))
	}
	if service.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" && len(service.Status.LoadBalancer.Ingress) == 0 {
		if cleared, clearErr := c.clearPublicNodeLocalWithdrawalEvidenceAfterAssignment(ctx, service, intent, desiredFirewall, firewall.UUID, addresses); clearErr != nil {
			return c.failPublicNodeLocalClosed(ctx, service, clearErr)
		} else if cleared {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}

	service, err = c.validatePublicNodeLocalPublicationState(ctx, service, intent, desiredFirewall, firewall.UUID, addresses, activePool != "", false)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	if activePool == "" {
		patched, err := c.ensurePublicNodeLocalActivation(ctx, service, intent.Pool, desiredFirewall.Hash)
		if err != nil || patched {
			if patched {
				c.requeuePublicNodeLocal(key)
			}
			return err
		}
	}
	service, err = c.validatePublicNodeLocalPublicationState(ctx, service, intent, desiredFirewall, firewall.UUID, addresses, true, false)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	updated, _, err := c.updatePublicNodeLocalStatusBound(ctx, service, desiredPublicStatus)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, service, err)
	}
	updated, err = c.validatePublicNodeLocalPublicationState(ctx, updated, intent, desiredFirewall, firewall.UUID, addresses, true, true)
	if err != nil {
		return c.failPublicNodeLocalClosed(ctx, updated, err)
	}
	if updated.Annotations[annotationNodeLoadBalancerFirewallAssigning] != "" {
		var cleared bool
		updated, cleared, err = c.clearPublicNodeLocalAssignmentIntent(ctx, updated, intent, desiredFirewall, firewall.UUID, addresses)
		if err != nil {
			return c.failPublicNodeLocalClosed(ctx, updated, err)
		}
		if cleared {
			updated, err = c.validatePublicNodeLocalPublicationState(ctx, updated, intent, desiredFirewall, firewall.UUID, addresses, true, true)
			if err != nil {
				return c.failPublicNodeLocalClosed(ctx, updated, err)
			}
		}
	}
	if patchedNode {
		c.requeuePublicNodeLocal(key)
	}
	return nil
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalFinalizer(ctx context.Context, service *corev1.Service) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp != nil || !publicNodeLocalRequested(copy) || containsString(copy.Finalizers, nodeLoadBalancerFinalizer) {
			return false, errors.New("public-node-local: Service changed before finalizer persistence")
		}
		intent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		if parseErr != nil || intent.Mode != nodeLoadBalancerModeLocal {
			return false, errors.Join(parseErr, errors.New("public-node-local: invalid Service intent before finalizer persistence"))
		}
		if containsString(copy.Finalizers, publicNodeLocalFinalizer) {
			return false, nil
		}
		copy.Finalizers = append(copy.Finalizers, publicNodeLocalFinalizer)
		return true, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) preparePublicNodeLocalFirewall(
	ctx context.Context,
	service *corev1.Service,
) (*corev1.Service, *inspace.Firewall, bool, error) {
	firewall, previousUUID, _, err := c.ensureServiceFirewall(ctx, service, nil)
	if err != nil {
		return service, nil, false, err
	}
	if firewall == nil {
		return service, nil, true, nil
	}
	if patched, err := c.ensureFirewallMetadata(ctx, service, firewall, previousUUID); err != nil || patched {
		return service, nil, patched, err
	}
	service, err = c.getExactParentService(ctx, service)
	if err != nil {
		return service, nil, false, err
	}
	if err := c.cleanupPreviousFirewall(ctx, service); err != nil {
		return service, nil, false, err
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return service, nil, false, err
	}
	if len(owned) != 1 || owned[0].UUID != firewall.UUID {
		return service, nil, true, nil
	}
	return service, &owned[0], false, nil
}

func desiredPublicNodeLocalDatapath(service *corev1.Service, pool string) *corev1.Service {
	name := nodeLoadBalancerDatapathName(service)
	class := nodeLoadBalancerDatapathClass
	allocateNodePorts := false
	controller := true
	blockOwnerDeletion := true
	ports := append([]corev1.ServicePort(nil), service.Spec.Ports...)
	for index := range ports {
		ports[index].NodePort = 0
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: service.Namespace,
			Name:      name,
			Labels: map[string]string{
				nodeLoadBalancerDatapathLabel:        "true",
				nodeLoadBalancerServiceIdentityLabel: nodeLoadBalancerServiceIdentity(service),
			},
			Annotations: map[string]string{annotationPublicNodeLocalDatapathPool: pool},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID,
				Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass:             &class,
			AllocateLoadBalancerNodePorts: &allocateNodePorts,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyLocal,
			Selector:                      copyStringMap(service.Spec.Selector),
			Ports:                         ports,
			SessionAffinity:               service.Spec.SessionAffinity,
			SessionAffinityConfig:         service.Spec.SessionAffinityConfig.DeepCopy(),
			PublishNotReadyAddresses:      false,
			LoadBalancerSourceRanges:      append([]string(nil), service.Spec.LoadBalancerSourceRanges...),
			IPFamilyPolicy:                service.Spec.IPFamilyPolicy,
			IPFamilies:                    append([]corev1.IPFamily(nil), service.Spec.IPFamilies...),
			InternalTrafficPolicy:         service.Spec.InternalTrafficPolicy,
			TrafficDistribution:           service.Spec.TrafficDistribution,
		},
	}
}

func publicNodeLocalDatapathMatches(datapath, service *corev1.Service, pool string) bool {
	if datapath == nil || service == nil || datapath.DeletionTimestamp != nil ||
		!nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return false
	}
	desired := normalizedDesiredPublicNodeLocalDatapath(desiredPublicNodeLocalDatapath(service, pool), datapath)
	return reflect.DeepEqual(datapath.Labels, desired.Labels) &&
		reflect.DeepEqual(datapath.Annotations, desired.Annotations) &&
		reflect.DeepEqual(datapath.OwnerReferences, desired.OwnerReferences) &&
		reflect.DeepEqual(datapath.Spec, desired.Spec)
}

func normalizedDesiredPublicNodeLocalDatapath(desired, existing *corev1.Service) *corev1.Service {
	normalized := normalizedDesiredNodeLoadBalancerDatapath(desired, existing)
	if normalized != nil && existing != nil {
		// The apiserver allocates this even when Service NodePorts are disabled
		// because externalTrafficPolicy=Local needs a health-check frontend.
		normalized.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
	}
	return normalized
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalDatapath(
	ctx context.Context,
	service *corev1.Service,
	pool string,
) (*corev1.Service, bool, error) {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	name := nodeLoadBalancerDatapathName(service)
	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, fmt.Errorf("public-node-local: get private datapath Service: %w", err)
	}
	desired := desiredPublicNodeLocalDatapath(service, pool)
	if apierrors.IsNotFound(err) {
		stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, service)
		if exposureErr != nil {
			return nil, false, exposureErr
		}
		if stillExposed {
			if withdrawErr := c.withdrawPublicNodeLocal(ctx, service); withdrawErr != nil {
				return nil, false, withdrawErr
			}
			return nil, true, nil
		}
		created, createErr := client.Create(ctx, desired, metav1.CreateOptions{})
		return created, createErr == nil, createErr
	}
	if !nodeLoadBalancerDatapathOwnedByService(existing, service) {
		return nil, false, fmt.Errorf("public-node-local: datapath Service %s/%s has foreign ownership", service.Namespace, name)
	}
	if existing.DeletionTimestamp != nil {
		stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, service)
		if exposureErr != nil {
			return nil, false, exposureErr
		}
		if stillExposed {
			if withdrawErr := c.withdrawPublicNodeLocal(ctx, service); withdrawErr != nil {
				return nil, false, withdrawErr
			}
		}
		return existing, true, nil
	}
	if existing.Spec.LoadBalancerClass == nil || *existing.Spec.LoadBalancerClass != nodeLoadBalancerDatapathClass {
		stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, service)
		if exposureErr != nil {
			return nil, false, exposureErr
		}
		if stillExposed {
			if withdrawErr := c.withdrawPublicNodeLocal(ctx, service); withdrawErr != nil {
				return nil, false, withdrawErr
			}
			return existing, true, nil
		}
		if err := deleteServiceWithUIDPrecondition(ctx, client, existing); err != nil && !apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("public-node-local: replace exact-owned datapath with immutable class drift: %w", err)
		}
		return nil, true, nil
	}
	desired = normalizedDesiredPublicNodeLocalDatapath(desired, existing)
	if publicNodeLocalDatapathMatches(existing, service, pool) {
		return existing, false, nil
	}
	// Close a drifted exact-owned datapath before changing its selectors or
	// traffic policy. The next reconciliation applies the desired spec.
	stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, service)
	if exposureErr != nil {
		return nil, false, exposureErr
	}
	if stillExposed {
		if withdrawErr := c.withdrawPublicNodeLocal(ctx, service); withdrawErr != nil {
			return nil, false, withdrawErr
		}
		return existing, true, nil
	}
	updated, updateErr := client.Update(ctx, desired, metav1.UpdateOptions{})
	return updated, updateErr == nil, updateErr
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalDatapathStatus(
	ctx context.Context,
	service, datapath *corev1.Service,
	pool string,
	status corev1.LoadBalancerStatus,
) (*corev1.Service, bool, error) {
	if !publicNodeLocalDatapathMatches(datapath, service, pool) {
		return nil, false, errors.New("public-node-local: refuse status publication to a drifted private datapath")
	}
	if reflect.DeepEqual(datapath.Status.LoadBalancer, status) {
		return datapath, false, nil
	}
	copy := datapath.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("public-node-local: publish private datapath status: %w", err)
	}
	if updated.UID != datapath.UID || !publicNodeLocalDatapathMatches(updated, service, pool) {
		return nil, false, errors.New("public-node-local: private datapath identity changed during status publication")
	}
	return updated, true, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalAddresses(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) ([]nodeLoadBalancerAddress, bool, error) {
	readyEndpoints, err := c.publicNodeLocalReadyEndpointNodes(service)
	if err != nil {
		return nil, false, err
	}
	nodeList, err := c.provider.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("public-node-local: list live Nodes: %w", err)
	}
	addresses := make([]nodeLoadBalancerAddress, 0)
	seenPrivate := map[string]string{}
	seenPublic := map[string]string{}
	patchedNode := false
	for index := range nodeList.Items {
		node := &nodeList.Items[index]
		if !loadBalancerNodeEligible(node) {
			continue
		}
		authorized, patched, err := c.authorizePublicNodeLocalNode(ctx, node, intent.Pool)
		if err != nil {
			return nil, patchedNode, err
		}
		patchedNode = patchedNode || patched
		if !authorized {
			continue
		}
		if _, serves := readyEndpoints[node.Name]; !serves {
			continue
		}
		address, err := c.publicNodeLocalAddress(ctx, node)
		if err != nil {
			return nil, patchedNode, err
		}
		if other := seenPrivate[address.PrivateIPv4]; other != "" {
			return nil, patchedNode, fmt.Errorf("public-node-local: Nodes %s and %s share private IPv4 %s", other, node.Name, address.PrivateIPv4)
		}
		if other := seenPublic[address.PublicIPv4]; other != "" {
			return nil, patchedNode, fmt.Errorf("public-node-local: Nodes %s and %s share public IPv4 %s", other, node.Name, address.PublicIPv4)
		}
		seenPrivate[address.PrivateIPv4] = node.Name
		seenPublic[address.PublicIPv4] = node.Name
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		left := netip.MustParseAddr(addresses[i].PublicIPv4)
		right := netip.MustParseAddr(addresses[j].PublicIPv4)
		if comparison := left.Compare(right); comparison != 0 {
			return comparison < 0
		}
		return addresses[i].Node.Name < addresses[j].Node.Name
	})
	return addresses, patchedNode, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalReadyEndpointNodes(service *corev1.Service) (map[string]struct{}, error) {
	if c.endpointSlices == nil {
		return nil, errors.New("public-node-local: EndpointSlice informer is unavailable")
	}
	slices, err := c.endpointSlices.EndpointSlices(service.Namespace).List(labels.SelectorFromSet(labels.Set{
		discoveryv1.LabelServiceName: service.Name,
	}))
	if err != nil {
		return nil, fmt.Errorf("public-node-local: list EndpointSlices: %w", err)
	}
	result := map[string]struct{}{}
	for _, endpointSlice := range slices {
		if !publicNodeLocalEndpointSliceOwnedByService(endpointSlice, service) {
			continue
		}
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.NodeName == nil || endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
				(endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				continue
			}
			result[*endpoint.NodeName] = struct{}{}
		}
	}
	return result, nil
}

func publicNodeLocalEndpointSliceOwnedByService(endpointSlice *discoveryv1.EndpointSlice, service *corev1.Service) bool {
	if endpointSlice == nil || service == nil || endpointSlice.DeletionTimestamp != nil ||
		endpointSlice.Namespace != service.Namespace ||
		endpointSlice.Labels[discoveryv1.LabelServiceName] != service.Name {
		return false
	}
	matches := 0
	for _, owner := range endpointSlice.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Service" {
			matches++
			if owner.Name != service.Name || owner.UID != service.UID || owner.Controller == nil || !*owner.Controller {
				return false
			}
		}
	}
	return matches == 1
}

func (c *nodeLoadBalancerController) authorizePublicNodeLocalNode(
	ctx context.Context,
	node *corev1.Node,
	pool string,
) (bool, bool, error) {
	karpenterBacked := node.Labels[karpenterNodePoolLabel] != ""
	for _, owner := range node.OwnerReferences {
		if owner.APIVersion == "karpenter.sh/v1" && owner.Kind == "NodeClaim" {
			karpenterBacked = true
		}
	}
	if !karpenterBacked && node.Labels[publicNodeLocalPoolLabel] != pool {
		return false, false, nil
	}
	providerIdentity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || providerIdentity.Location != c.provider.config.Location || providerIdentity.String() != node.Spec.ProviderID {
		return false, false, nil
	}
	vm, err := c.provider.api.GetVM(ctx, providerIdentity.Location, providerIdentity.UUID)
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: read canonical VM ownership for Node %s: %w", node.Name, err)
	}
	if vm == nil || vm.UUID != providerIdentity.UUID ||
		strings.EqualFold(strings.TrimSpace(vm.Status), "deleted") ||
		vm.BillingAccountID != c.provider.config.BillingAccountID ||
		(vm.NetworkUUID != "" && !strings.EqualFold(vm.NetworkUUID, c.provider.config.NetworkUUID)) {
		return false, false, nil
	}
	network, err := c.provider.api.GetNetwork(ctx, providerIdentity.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: read canonical VPC membership for Node %s: %w", node.Name, err)
	}
	if network == nil || !strings.EqualFold(network.UUID, c.provider.config.NetworkUUID) {
		return false, false, nil
	}
	members, membershipErr := canonicalConfiguredVPCVMUUIDs(providerIdentity.Location, network)
	if membershipErr != nil {
		return false, false, fmt.Errorf("public-node-local: canonical VPC membership for Node %s is invalid: %w", node.Name, membershipErr)
	}
	member, present := members[providerIdentity.UUID]
	if !present || member != providerIdentity.UUID {
		return false, false, nil
	}
	var ownership publicNodeLocalVMOwnership
	ownershipErr := error(nil)
	if vm.Description != "" {
		if parseErr := json.Unmarshal([]byte(vm.Description), &ownership); parseErr != nil &&
			strings.Contains(vm.Description, "karpenter.inspace.cloud/") {
			ownershipErr = parseErr
		}
	}
	if ownership.Schema == "karpenter.inspace.cloud/v3" {
		karpenterBacked = true
	}
	var claims *unstructured.UnstructuredList
	if c.provider.dynamicClient != nil {
		claims, err = c.provider.dynamicClient.Resource(nodeClaimGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, false, fmt.Errorf("public-node-local: list NodeClaims before manual/Karpenter classification: %w", err)
		}
		for index := range claims.Items {
			claim := &claims.Items[index]
			claimProviderID, providerFound, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
			claimNodeName, nodeFound, nodeErr := unstructured.NestedString(claim.Object, "status", "nodeName")
			if providerErr == nil && nodeErr == nil &&
				((providerFound && claimProviderID == node.Spec.ProviderID) || (nodeFound && claimNodeName == node.Name)) {
				karpenterBacked = true
				break
			}
		}
	}
	if !karpenterBacked {
		return node.Labels[publicNodeLocalPoolLabel] == pool && ownershipErr == nil, false, nil
	}
	if c.provider.dynamicClient == nil {
		return false, false, errors.New("public-node-local: dynamic client is required to authorize a Karpenter Node")
	}
	matching := make([]*unstructured.Unstructured, 0, 1)
	for index := range claims.Items {
		claim := &claims.Items[index]
		claimProviderID, providerFound, providerErr := unstructured.NestedString(claim.Object, "status", "providerID")
		claimNodeName, nodeFound, nodeErr := unstructured.NestedString(claim.Object, "status", "nodeName")
		if providerErr == nil && nodeErr == nil &&
			((providerFound && claimProviderID == node.Spec.ProviderID) || (nodeFound && claimNodeName == node.Name)) {
			matching = append(matching, claim.DeepCopy())
		}
	}
	if len(matching) != 1 {
		return false, false, nil
	}
	claim := matching[0]
	claimProviderID, providerFound, _ := unstructured.NestedString(claim.Object, "status", "providerID")
	claimNodeName, nodeFound, _ := unstructured.NestedString(claim.Object, "status", "nodeName")
	if !providerFound || !nodeFound || claimProviderID != node.Spec.ProviderID || claimNodeName != node.Name ||
		claim.GetUID() == "" || claim.GetDeletionTimestamp() != nil ||
		!hasExactSingleNodeLoadBalancerOwnerReference(node.OwnerReferences, "karpenter.sh/v1", "NodeClaim", claim.GetName(), claim.GetUID()) {
		return false, false, nil
	}
	poolName := claim.GetLabels()[karpenterNodePoolLabel]
	if poolName == "" || node.Labels[karpenterNodePoolLabel] != poolName {
		return false, false, nil
	}
	nodePool, err := c.provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, poolName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: get NodePool %s: %w", poolName, err)
	}
	if nodePool.GetUID() == "" || nodePool.GetDeletionTimestamp() != nil ||
		!hasExactSingleNodeLoadBalancerOwnerReference(claim.GetOwnerReferences(), "karpenter.sh/v1", "NodePool", nodePool.GetName(), nodePool.GetUID()) {
		return false, false, nil
	}
	templateLabels, found, err := unstructured.NestedStringMap(nodePool.Object, "spec", "template", "metadata", "labels")
	if err != nil || !found || templateLabels[publicNodeLocalPoolLabel] != pool {
		return false, false, nil
	}
	claimClassName, ok := publicNodeLocalNodeClassRefName(claim, []string{"spec", "nodeClassRef"})
	if !ok {
		return false, false, nil
	}
	poolClassName, ok := publicNodeLocalNodeClassRefName(nodePool, []string{"spec", "template", "spec", "nodeClassRef"})
	if !ok || poolClassName != claimClassName {
		return false, false, nil
	}
	nodeClass, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, claimClassName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: get InSpaceNodeClass %s: %w", claimClassName, err)
	}
	profile, profileFound, profileErr := unstructured.NestedString(nodeClass.Object, "spec", "firewallProfile")
	if nodeClass.GetDeletionTimestamp() != nil || profileErr != nil || !profileFound || profile != publicNodeLocalFirewallProfile {
		return false, false, nil
	}
	if err := c.validateBaseNodeClass(nodeClass); err != nil {
		return false, false, fmt.Errorf("public-node-local: validate InSpaceNodeClass %s: %w", claimClassName, err)
	}
	baseFirewallUUID, err := c.publicNodeLocalTrustedBaseFirewall(ctx, nodeClass)
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: validate InSpaceNodeClass %s security base: %w", claimClassName, err)
	}
	if ownershipErr != nil ||
		ownership.Schema != "karpenter.inspace.cloud/v3" || ownership.Cluster != c.provider.config.ClusterID ||
		ownership.NodePool != poolName || ownership.NodeClaim != claim.GetName() ||
		ownership.VMName == "" || ownership.VMName != vm.Name || ownership.VMName != node.Name ||
		ownership.FirewallProfile != publicNodeLocalFirewallProfile || ownership.FirewallUUID != baseFirewallUUID ||
		ownership.NetworkUUID != c.provider.config.NetworkUUID || ownership.BillingAccountID != c.provider.config.BillingAccountID {
		return false, false, nil
	}
	if node.Labels[publicNodeLocalPoolLabel] != pool {
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{
			"resourceVersion": node.ResourceVersion,
			"labels":          map[string]any{publicNodeLocalPoolLabel: pool},
		}})
		if _, err := c.provider.kubeClient.CoreV1().Nodes().Patch(ctx, node.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return false, false, fmt.Errorf("public-node-local: mirror protected pool label to Node %s: %w", node.Name, err)
		}
		// Do not authorize from a stale pre-patch Node object. The next
		// reconciliation must observe the protected label and then complete the
		// VM firewall audit against the exact live Service state.
		return false, true, nil
	}
	if err := c.auditPublicNodeLocalVMFirewalls(ctx, node, baseFirewallUUID); err != nil {
		return false, false, fmt.Errorf("public-node-local: audit VM %s firewall assignments: %w", node.Name, err)
	}
	return true, false, nil
}

func (c *nodeLoadBalancerController) publicNodeLocalTrustedBaseFirewall(
	ctx context.Context,
	nodeClass *unstructured.Unstructured,
) (string, error) {
	if nodeClass == nil {
		return "", errors.New("NodeClass is required")
	}
	reservePublic, found, err := unstructured.NestedBool(nodeClass.Object, "spec", "reservePublicIPv4")
	if err != nil || !found || !reservePublic {
		return "", errors.New("spec.reservePublicIPv4 must be true")
	}
	return c.trustedNodeLoadBalancerBaseFirewall(ctx, nodeClass)
}

// trustedNodeLoadBalancerBaseFirewall binds a derived public NodeClass back to
// the configured private-worker security boundary. Both NodeClass status
// objects must confirm the same canonical firewall UUID before a VM ownership
// record may use it as authorization for any additional public firewall.
func (c *nodeLoadBalancerController) trustedNodeLoadBalancerBaseFirewall(
	ctx context.Context,
	nodeClass *unstructured.Unstructured,
) (string, error) {
	if nodeClass == nil || c.provider.config.NodeLoadBalancer.DefaultNodeClass == "" {
		return "", errors.New("configured default NodeClass is required")
	}
	localFirewallUUID, found, err := unstructured.NestedString(nodeClass.Object, "spec", "firewallUUID")
	if err != nil || !found || !validNodeLoadBalancerCloudUUID(localFirewallUUID) {
		return "", errors.New("spec.firewallUUID must be a canonical cloud UUID")
	}
	localStatusFirewallUUID, found, err := unstructured.NestedString(nodeClass.Object, "status", "firewallUUID")
	if err != nil || !found || localStatusFirewallUUID != localFirewallUUID {
		return "", errors.New("status.firewallUUID must exactly confirm spec.firewallUUID")
	}
	base, err := c.provider.dynamicClient.Resource(nodeClassGVR).Get(
		ctx, c.provider.config.NodeLoadBalancer.DefaultNodeClass, metav1.GetOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("get configured default NodeClass %q: %w", c.provider.config.NodeLoadBalancer.DefaultNodeClass, err)
	}
	if base.GetDeletionTimestamp() != nil {
		return "", errors.New("configured default NodeClass is deleting")
	}
	if err := c.validateBaseNodeClass(base); err != nil {
		return "", err
	}
	baseFirewallUUID, found, err := unstructured.NestedString(base.Object, "spec", "firewallUUID")
	if err != nil || !found || !validNodeLoadBalancerCloudUUID(baseFirewallUUID) {
		return "", errors.New("configured default NodeClass has no canonical spec.firewallUUID")
	}
	baseStatusFirewallUUID, found, err := unstructured.NestedString(base.Object, "status", "firewallUUID")
	if err != nil || !found || baseStatusFirewallUUID != baseFirewallUUID {
		return "", errors.New("configured default NodeClass status.firewallUUID does not confirm its spec")
	}
	if localFirewallUUID != baseFirewallUUID {
		return "", fmt.Errorf("spec.firewallUUID %s does not match trusted default NodeClass firewall %s", localFirewallUUID, baseFirewallUUID)
	}
	return baseFirewallUUID, nil
}

// auditManagedNodeLoadBalancerBaseFirewall proves the live cloud security
// boundary for one managed VM. NodeClass spec/status and the VM description
// identify the intended firewall, but only this fresh inventory read proves
// that the UUID still has our billing identity, exact private-worker policy,
// and exactly one attachment row for the VM being authorized.
func (c *nodeLoadBalancerController) auditManagedNodeLoadBalancerBaseFirewall(
	ctx context.Context,
	vmUUID, baseFirewallUUID, subnet string,
) error {
	base, err := c.exactNodeLoadBalancerFirewallFresh(ctx, baseFirewallUUID)
	if err != nil {
		return err
	}
	if base.BillingAccountID != c.provider.config.BillingAccountID {
		return fmt.Errorf("trusted base firewall %s has foreign billing identity", baseFirewallUUID)
	}
	if err := bootstrap.ValidateDefaultNodeFirewallPolicy(base, subnet, cloudv1.CiliumNativeRoutingPodCIDR); err != nil {
		return fmt.Errorf("trusted base firewall %s policy drifted: %w", baseFirewallUUID, err)
	}
	assignments := 0
	for _, relation := range base.ResourcesAssigned {
		if !strings.EqualFold(relation.ResourceType, "vm") || !validNodeLoadBalancerCloudUUID(relation.ResourceUUID) {
			return fmt.Errorf("trusted base firewall %s has malformed assignment %#v", baseFirewallUUID, relation)
		}
		if strings.EqualFold(relation.ResourceUUID, vmUUID) {
			if relation.ResourceUUID != vmUUID {
				return fmt.Errorf("trusted base firewall %s has non-canonical VM assignment %q", baseFirewallUUID, relation.ResourceUUID)
			}
			assignments++
		}
	}
	if assignments != 1 {
		return fmt.Errorf("VM %s must have exactly one trusted base firewall %s assignment, got %d", vmUUID, baseFirewallUUID, assignments)
	}
	return nil
}

func (c *nodeLoadBalancerController) auditPublicNodeLocalVMFirewalls(
	ctx context.Context,
	node *corev1.Node,
	baseFirewallUUID string,
) error {
	vmUUID, ok := nodeLoadBalancerVMUUID(node)
	if !ok {
		return errors.New("Node has no canonical VM identity")
	}
	metadata, err := c.provider.InstanceMetadata(ctx, node)
	if err != nil || metadata.ProviderID != node.Spec.ProviderID {
		return errors.Join(err, errors.New("Node provider identity changed during firewall authorization"))
	}
	authoritativePublicIP, publicOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeExternalIP, false)
	nodePublicIP, nodePublicOK := nodeLoadBalancerNodeExternalIPv4(node)
	if !publicOK || !nodePublicOK || authoritativePublicIP != nodePublicIP {
		return errors.New("Node public IPv4 does not match authoritative VM/FIP metadata during firewall authorization")
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return err
	}
	network, err := c.provider.api.GetNetwork(ctx, c.provider.config.Location, c.provider.config.NetworkUUID)
	if err != nil {
		return fmt.Errorf("read trusted VPC policy boundary: %w", err)
	}
	if network == nil || network.UUID != c.provider.config.NetworkUUID {
		return errors.New("trusted VPC identity changed during firewall audit")
	}
	seen := make(map[string]struct{}, len(items))
	baseAssignments := 0
	var baseFirewall *inspace.Firewall
	for index := range items {
		firewall := items[index]
		if !validNodeLoadBalancerCloudUUID(firewall.UUID) {
			return fmt.Errorf("firewall list row has invalid UUID %q", firewall.UUID)
		}
		if _, duplicate := seen[firewall.UUID]; duplicate {
			return fmt.Errorf("firewall list contains duplicate UUID %s", firewall.UUID)
		}
		seen[firewall.UUID] = struct{}{}
		if firewall.UUID == baseFirewallUUID {
			copy := firewall
			baseFirewall = &copy
			if firewall.BillingAccountID != c.provider.config.BillingAccountID {
				return fmt.Errorf("trusted base firewall %s has foreign billing identity", baseFirewallUUID)
			}
		}
		assignments, assignmentErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignmentErr != nil {
			return assignmentErr
		}
		if _, assigned := assignments[strings.ToLower(vmUUID)]; !assigned {
			continue
		}
		if firewall.UUID == baseFirewallUUID {
			baseAssignments++
			continue
		}
		if err := inspace.ValidateNodeLoadBalancerServiceFirewall(
			firewall,
			c.provider.config.ClusterID,
			c.provider.config.BillingAccountID,
		); err != nil {
			return fmt.Errorf("VM %s has unauthorized additional firewall %s: %w", vmUUID, firewall.UUID, err)
		}
		if err := c.validateLivePublicNodeLocalServiceFirewall(ctx, node, authoritativePublicIP, firewall); err != nil {
			return err
		}
	}
	if baseFirewall == nil {
		return fmt.Errorf("trusted base firewall %s is absent", baseFirewallUUID)
	}
	if err := bootstrap.ValidateDefaultNodeFirewallPolicy(baseFirewall, network.Subnet, cloudv1.CiliumNativeRoutingPodCIDR); err != nil {
		return fmt.Errorf("trusted base firewall %s policy drifted: %w", baseFirewallUUID, err)
	}
	if baseAssignments != 1 {
		return fmt.Errorf("VM %s must have exactly one trusted base firewall %s assignment, got %d", vmUUID, baseFirewallUUID, baseAssignments)
	}
	return nil
}

func (c *nodeLoadBalancerController) validateLivePublicNodeLocalServiceFirewall(
	ctx context.Context,
	node *corev1.Node,
	authoritativePublicIP string,
	firewall inspace.Firewall,
) error {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("public-node-local: list live Services for VM firewall authorization: %w", err)
	}
	vmUUID, _ := nodeLoadBalancerVMUUID(node)
	privateIP, privateOK := nodeLoadBalancerNodeInternalIPv4(node)
	if !privateOK {
		return fmt.Errorf("public-node-local: Node %s has no canonical private IP", node.Name)
	}
	matches := 0
	for index := range services.Items {
		service := &services.Items[index]
		if !nodeLoadBalancerFirewallOwnedByService(
			firewall,
			c.provider.config.ClusterID,
			string(service.UID),
			c.provider.config.BillingAccountID,
		) {
			continue
		}
		matches++
		intent, parseErr := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		if parseErr != nil || service.DeletionTimestamp != nil || intent.Mode != nodeLoadBalancerModeLocal ||
			!containsString(service.Finalizers, publicNodeLocalFinalizer) || node.Labels[publicNodeLocalPoolLabel] != intent.Pool {
			return errors.Join(parseErr, fmt.Errorf("public-node-local: firewall %s is not bound to a live valid local Service", firewall.UUID))
		}
		desired, desiredErr := c.desiredServiceFirewall(service)
		if desiredErr != nil || service.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewall.UUID ||
			service.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
			!nodeLoadBalancerFirewallMatches(firewall, desired) {
			return errors.Join(desiredErr, fmt.Errorf("public-node-local: firewall %s lost its exact live Service ledger", firewall.UUID))
		}
		readyNodes, endpointErr := c.publicNodeLocalReadyEndpointNodes(service)
		if endpointErr != nil {
			return endpointErr
		}
		if _, ready := readyNodes[node.Name]; !ready {
			return fmt.Errorf("public-node-local: firewall %s is assigned to VM %s without a Ready local endpoint", firewall.UUID, vmUUID)
		}
		datapath, datapathErr := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
			ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
		)
		if datapathErr != nil || !publicNodeLocalDatapathMatches(datapath, service, intent.Pool) {
			return errors.Join(datapathErr, fmt.Errorf("public-node-local: firewall %s has no exact live child datapath", firewall.UUID))
		}
		privateAdvertised := false
		for _, ingress := range datapath.Status.LoadBalancer.Ingress {
			if ingress.IP == privateIP && ingress.IPMode != nil && *ingress.IPMode == corev1.LoadBalancerIPModeVIP {
				privateAdvertised = true
				break
			}
		}
		if !privateAdvertised {
			return fmt.Errorf("public-node-local: firewall %s VM %s is absent from the exact child VIP status", firewall.UUID, vmUUID)
		}
		publicAdvertised := false
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP == authoritativePublicIP && ingress.IPMode != nil && *ingress.IPMode == corev1.LoadBalancerIPModeProxy {
				if publicAdvertised {
					return fmt.Errorf("public-node-local: firewall %s VM %s has a duplicate public status entry", firewall.UUID, vmUUID)
				}
				publicAdvertised = true
			}
		}
		active := publicAdvertised &&
			service.Annotations[annotationPublicNodeLocalActivePool] == intent.Pool &&
			service.Annotations[annotationPublicNodeLocalActivePolicy] == desired.Hash
		staged := false
		if len(service.Status.LoadBalancer.Ingress) == 0 &&
			service.Annotations[annotationNodeLoadBalancerFirewallAssigning] == firewall.UUID &&
			service.Annotations[annotationPublicNodeLocalAssignPolicy] == desired.Hash {
			vmSet := strings.Split(service.Annotations[annotationPublicNodeLocalAssignVMs], ",")
			sortedVMs := append([]string(nil), vmSet...)
			sort.Strings(sortedVMs)
			canonical := len(sortedVMs) != 0 && reflect.DeepEqual(vmSet, sortedVMs)
			seenVM := false
			for _, candidate := range vmSet {
				if !validNodeLoadBalancerCloudUUID(candidate) {
					canonical = false
				}
				if candidate == vmUUID {
					if seenVM {
						canonical = false
					}
					seenVM = true
				}
			}
			startedAt, timeErr := time.Parse(time.RFC3339Nano, service.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
			now := time.Now().UTC()
			staged = canonical && seenVM && timeErr == nil && !startedAt.After(now) && now.Before(startedAt.Add(nodeLoadBalancerPendingCreateTimeout))
		}
		if !active && !staged {
			return fmt.Errorf("public-node-local: firewall %s VM assignment has no active or durable staged authorization", firewall.UUID)
		}
	}
	if matches != 1 {
		return fmt.Errorf("public-node-local: Service firewall %s resolves to %d live exact owners", firewall.UUID, matches)
	}
	return nil
}

func publicNodeLocalNodeClassRefName(object *unstructured.Unstructured, path []string) (string, bool) {
	group, groupFound, groupErr := unstructured.NestedString(object.Object, append(path, "group")...)
	kind, kindFound, kindErr := unstructured.NestedString(object.Object, append(path, "kind")...)
	name, nameFound, nameErr := unstructured.NestedString(object.Object, append(path, "name")...)
	return name, groupErr == nil && kindErr == nil && nameErr == nil && groupFound && kindFound && nameFound &&
		group == "karpenter.inspace.cloud" && kind == "InSpaceNodeClass" && name != ""
}

func (c *nodeLoadBalancerController) publicNodeLocalAddress(ctx context.Context, node *corev1.Node) (nodeLoadBalancerAddress, error) {
	identity, err := providerid.Parse(node.Spec.ProviderID)
	if err != nil || identity.Location != c.provider.config.Location || identity.String() != node.Spec.ProviderID {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s has an invalid or foreign providerID", node.Name)
	}
	metadata, err := c.provider.InstanceMetadata(ctx, node)
	if err != nil {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: resolve provider metadata for Node %s: %w", node.Name, err)
	}
	if metadata.ProviderID != node.Spec.ProviderID {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s provider identity changed during metadata lookup", node.Name)
	}
	privateIP, privateOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeInternalIP, true)
	publicIP, publicOK := exactNodeAddressIPv4(metadata.NodeAddresses, corev1.NodeExternalIP, false)
	nodePrivate, nodePrivateOK := nodeLoadBalancerNodeInternalIPv4(node)
	nodePublic, nodePublicOK := nodeLoadBalancerNodeExternalIPv4(node)
	if !privateOK || !publicOK || !nodePrivateOK || !nodePublicOK || privateIP != nodePrivate || publicIP != nodePublic {
		return nodeLoadBalancerAddress{}, fmt.Errorf("public-node-local: Node %s addresses do not match authoritative VM/FIP metadata", node.Name)
	}
	return nodeLoadBalancerAddress{Node: node.DeepCopy(), PrivateIPv4: privateIP, PublicIPv4: publicIP}, nil
}

func exactNodeAddressIPv4(addresses []corev1.NodeAddress, addressType corev1.NodeAddressType, private bool) (string, bool) {
	result := ""
	for _, address := range addresses {
		if address.Type != addressType {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.String() != address.Address || parsed.IsPrivate() != private || result != "" {
			return "", false
		}
		result = parsed.String()
	}
	return result, result != ""
}

func publicNodeLocalAddressIdentities(addresses []nodeLoadBalancerAddress) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Node.Name+"|"+address.Node.Spec.ProviderID+"|"+address.PrivateIPv4+"|"+address.PublicIPv4)
	}
	sort.Strings(result)
	return result
}

func (c *nodeLoadBalancerController) publicNodeLocalPortConflict(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) (loses, winnerWaiting bool, resultErr error) {
	services, err := c.provider.kubeClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, false, fmt.Errorf("public-node-local: list Services for port claims: %w", err)
	}
	for index := range services.Items {
		other := &services.Items[index]
		if other.UID == service.UID {
			continue
		}

		validDesiredConflict := false
		if other.DeletionTimestamp == nil && publicNodeLocalRequested(other) {
			otherIntent, parseErr := parseNodeLoadBalancerService(other, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
			if parseErr == nil && otherIntent.Mode == nodeLoadBalancerModeLocal && otherIntent.Pool == intent.Pool &&
				publicNodeLocalPortsOverlap(intent.Ports, otherIntent.Ports) {
				validDesiredConflict = true
				if string(other.UID) < string(service.UID) {
					return true, false, fmt.Errorf(
						"public-node-local: pool %s protocol/port claim belongs to lexicographic winner %s/%s (UID %s); Service %s/%s (UID %s) must remain closed",
						intent.Pool, other.Namespace, other.Name, other.UID, service.Namespace, service.Name, service.UID,
					)
				}
			}
		}

		aggregateOwned := containsString(other.Finalizers, nodeLoadBalancerFinalizer) &&
			!containsString(other.Finalizers, publicNodeLocalFinalizer) &&
			other.Annotations[annotationPublicNodeLocalActivePool] == "" &&
			other.Annotations[annotationPublicNodeLocalActivePolicy] == "" &&
			!publicNodeLocalAssignmentFencePresent(other) &&
			other.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] == "" &&
			other.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] == ""
		mayRetainLocalState := containsString(other.Finalizers, publicNodeLocalFinalizer) ||
			other.Annotations[annotationPublicNodeLocalActivePool] != "" ||
			other.Annotations[annotationPublicNodeLocalActivePolicy] != "" ||
			(!aggregateOwned && len(other.Status.LoadBalancer.Ingress) != 0 && other.Spec.LoadBalancerClass != nil &&
				*other.Spec.LoadBalancerClass == nodeLoadBalancerClass)
		if !validDesiredConflict && !mayRetainLocalState {
			continue
		}
		stillExposed, exposureErr := c.publicNodeLocalServiceStillExposed(ctx, other)
		if exposureErr != nil {
			return false, false, exposureErr
		}
		if !stillExposed {
			continue
		}
		if validDesiredConflict {
			winnerWaiting = true
		}
		if mayRetainLocalState {
			blocks, blockErr := c.publicNodeLocalStaleExposureBlocks(ctx, other, intent)
			if blockErr != nil {
				return false, false, blockErr
			}
			if blocks {
				winnerWaiting = true
			}
		}
	}
	return false, winnerWaiting, nil
}

// publicNodeLocalStaleExposureBlocks compares the persisted activation
// identity with the exact-owned child that implements the old datapath. A
// Service spec can change before its cleanup reconciliation runs, so its new
// desired pool and ports are not evidence that the old exposure disappeared.
func (c *nodeLoadBalancerController) publicNodeLocalStaleExposureBlocks(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
) (bool, error) {
	activePool := strings.TrimSpace(service.Annotations[annotationPublicNodeLocalActivePool])
	childPool := ""
	var childPorts []nodeLoadBalancerPortClaim
	childPortsProven := false
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
			return false, fmt.Errorf("public-node-local: conflict peer %s/%s has a foreign datapath identity", service.Namespace, service.Name)
		}
		childPool = strings.TrimSpace(datapath.Annotations[annotationPublicNodeLocalDatapathPool])
		childPorts, err = nodeLoadBalancerPortClaims(datapath)
		childPortsProven = err == nil && len(childPorts) != 0
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("public-node-local: inspect conflict peer persisted datapath: %w", err)
	}

	// Disagreement between the two persisted identities means the exact old
	// port set cannot be attributed safely. Block either named pool until the
	// peer's withdrawal removes the exposure.
	if activePool != "" && childPool != "" && activePool != childPool {
		return activePool == intent.Pool || childPool == intent.Pool, nil
	}
	exposurePool := activePool
	if exposurePool == "" {
		exposurePool = childPool
	}
	if exposurePool == "" {
		// A privileged status/firewall proves exposure, but no persisted pool
		// proves where it belongs. The only safe temporary choice is to block.
		return true, nil
	}
	if exposurePool != intent.Pool {
		return false, nil
	}
	if !childPortsProven || childPool != exposurePool {
		// activePool is authoritative for the pool, but only the exact-owned
		// child proves the old frontend ports. Missing/drifted evidence blocks
		// that pool until cleanup completes.
		return true, nil
	}
	return publicNodeLocalPortsOverlap(intent.Ports, childPorts), nil
}

func (c *nodeLoadBalancerController) publicNodeLocalServiceStillExposed(
	ctx context.Context,
	service *corev1.Service,
) (bool, error) {
	if len(service.Status.LoadBalancer.Ingress) != 0 ||
		service.Annotations[annotationPublicNodeLocalActivePool] != "" ||
		service.Annotations[annotationPublicNodeLocalActivePolicy] != "" ||
		publicNodeLocalAssignmentFencePresent(service) ||
		service.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] != "" ||
		service.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] != "" {
		return true, nil
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(service.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{},
	)
	if err == nil {
		if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
			return false, fmt.Errorf("public-node-local: conflict peer %s/%s has a foreign datapath identity", service.Namespace, service.Name)
		}
		if len(datapath.Status.LoadBalancer.Ingress) != 0 {
			return true, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("public-node-local: inspect conflict peer datapath: %w", err)
	}
	owned, err := c.serviceFirewallsForEmergencyDetach(ctx, service)
	if err != nil {
		return false, fmt.Errorf("public-node-local: inspect conflict peer firewalls: %w", err)
	}
	for _, firewall := range owned {
		assignments, assignmentErr := nodeLoadBalancerFirewallVMAssignments(firewall)
		if assignmentErr != nil {
			return false, assignmentErr
		}
		if len(assignments) != 0 {
			return true, nil
		}
	}
	return false, nil
}

func (c *nodeLoadBalancerController) recordPublicNodeLocalConflictEvent(
	ctx context.Context,
	service *corev1.Service,
	cause error,
) error {
	if service == nil || cause == nil {
		return nil
	}
	conflictID := shortHash(cause.Error())
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalConflict] == conflictID {
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationPublicNodeLocalConflict] = conflictID
		return true, nil
	})
	if err != nil || !changed {
		return err
	}
	now := metav1.Now()
	client := c.provider.kubeClient.CoreV1().Events(service.Namespace)
	_, err = client.Create(ctx, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: service.Name + ".", Namespace: service.Namespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1", Kind: "Service", Namespace: service.Namespace,
			Name: service.Name, UID: service.UID,
		},
		Reason:         "PublicNodeLocalPortConflict",
		Message:        cause.Error(),
		Source:         corev1.EventSource{Component: "inspace-cloud-controller-manager"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Type:           corev1.EventTypeWarning,
	}, metav1.CreateOptions{})
	return err
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalConflict(ctx context.Context, service *corev1.Service) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalConflict] == "" {
			return false, nil
		}
		delete(copy.Annotations, annotationPublicNodeLocalConflict)
		return true, nil
	})
	return changed, err
}

func publicNodeLocalPortsOverlap(left, right []nodeLoadBalancerPortClaim) bool {
	set := make(map[nodeLoadBalancerPortClaim]struct{}, len(left))
	for _, claim := range left {
		set[claim] = struct{}{}
	}
	for _, claim := range right {
		if _, found := set[claim]; found {
			return true
		}
	}
	return false
}

func publicNodeLocalVMSet(addresses []nodeLoadBalancerAddress) (string, error) {
	vmUUIDs := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		vmUUID, ok := nodeLoadBalancerVMUUID(address.Node)
		if !ok || !validNodeLoadBalancerCloudUUID(vmUUID) {
			return "", fmt.Errorf("public-node-local: Node %s has no valid VM identity", address.Node.Name)
		}
		if _, duplicate := seen[vmUUID]; duplicate {
			return "", fmt.Errorf("public-node-local: duplicate VM identity %s", vmUUID)
		}
		seen[vmUUID] = struct{}{}
		vmUUIDs = append(vmUUIDs, vmUUID)
	}
	sort.Strings(vmUUIDs)
	return strings.Join(vmUUIDs, ","), nil
}

func publicNodeLocalAssignmentFencePresent(service *corev1.Service) bool {
	if service == nil {
		return false
	}
	for _, key := range []string{
		annotationNodeLoadBalancerFirewallAssigning,
		annotationNodeLoadBalancerFirewallAssignAt,
		annotationPublicNodeLocalAssignPolicy,
		annotationPublicNodeLocalAssignVMs,
	} {
		if service.Annotations[key] != "" {
			return true
		}
	}
	return false
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, bool, error) {
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil || vmSet == "" {
		return service, false, errors.Join(err, errors.New("public-node-local: non-empty VM set is required before assignment authorization"))
	}
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return service, false, err
	}
	if err := c.validatePublicNodeLocalAssignmentState(ctx, current, intent, desired, firewallUUID, addresses, false, false); err != nil {
		return current, false, err
	}
	now := time.Now().UTC()
	updated, changed, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		assigning := copy.Annotations[annotationNodeLoadBalancerFirewallAssigning]
		started := copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		policy := copy.Annotations[annotationPublicNodeLocalAssignPolicy]
		storedVMs := copy.Annotations[annotationPublicNodeLocalAssignVMs]
		if assigning != "" || started != "" || policy != "" || storedVMs != "" {
			if assigning != firewallUUID || policy != desired.Hash || storedVMs != vmSet || started == "" {
				return false, errors.New("public-node-local: durable firewall assignment authorization no longer matches the desired VM set")
			}
			startedAt, parseErr := time.Parse(time.RFC3339Nano, started)
			if parseErr != nil {
				return false, fmt.Errorf("public-node-local: invalid assignment authorization timestamp: %w", parseErr)
			}
			if !now.Before(startedAt.Add(nodeLoadBalancerPendingCreateTimeout)) {
				return false, errors.New("public-node-local: timed out waiting for authoritative firewall assignment readback")
			}
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
		copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = now.Format(time.RFC3339Nano)
		copy.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
		copy.Annotations[annotationPublicNodeLocalAssignVMs] = vmSet
		return true, nil
	})
	if err != nil {
		return current, false, err
	}
	return updated, changed, nil
}

func (c *nodeLoadBalancerController) assignPublicNodeLocalFirewallWithFence(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewall *inspace.Firewall,
	addresses []nodeLoadBalancerAddress,
) error {
	if firewall == nil || !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
		!nodeLoadBalancerFirewallOwnedByService(*firewall, c.provider.config.ClusterID, string(service.UID), c.provider.config.BillingAccountID) {
		return errors.New("public-node-local: refuse assignment without exact Service firewall ownership and policy")
	}
	converged, err := c.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		c.serviceFirewallRelationOwner(service),
		nil,
	)
	if err != nil || !converged {
		return err
	}
	assignments, err := nodeLoadBalancerFirewallVMAssignments(*firewall)
	if err != nil {
		return err
	}
	for _, address := range addresses {
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		if _, assigned := assignments[strings.ToLower(vmUUID)]; assigned {
			continue
		}
		if err := c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, firewall.UUID, addresses, true, false); err != nil {
			return err
		}
		converged, relationErr := c.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			c.serviceFirewallRelationOwner(service),
			&nodeLoadBalancerFirewallRelationFence{
				operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: firewall.UUID, vmUUID: vmUUID,
			},
		)
		if relationErr != nil {
			return fmt.Errorf("public-node-local: assign firewall %s to VM %s: %w", firewall.UUID, vmUUID, relationErr)
		}
		if !converged {
			return nil
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) validatePublicNodeLocalAssignmentState(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	addresses []nodeLoadBalancerAddress,
	requireFence, requirePublished bool,
) error {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return errors.Join(err, errors.New("public-node-local: live Service contract changed during firewall assignment authorization"))
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return errors.New("public-node-local: live firewall ledger or policy changed during assignment authorization")
	}
	if requirePublished {
		if !reflect.DeepEqual(current.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, true)) {
			return errors.New("public-node-local: exact public Proxy status is required for final assignment-fence clearance")
		}
	} else if len(current.Status.LoadBalancer.Ingress) != 0 {
		return errors.New("public-node-local: public Proxy status must be empty during pre-publication firewall assignment authorization")
	}
	activePool := current.Annotations[annotationPublicNodeLocalActivePool]
	activePolicy := current.Annotations[annotationPublicNodeLocalActivePolicy]
	if (activePool == "") != (activePolicy == "") ||
		(activePool != "" && (activePool != intent.Pool || activePolicy != desired.Hash)) {
		return errors.New("public-node-local: persisted activation identity changed during assignment authorization")
	}
	if requirePublished && activePool == "" {
		return errors.New("public-node-local: exact activation identity is required for final assignment-fence clearance")
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("public-node-local: read private datapath during assignment authorization: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, intent.Pool) ||
		!reflect.DeepEqual(datapath.Status.LoadBalancer, nodeLoadBalancerStatus(addresses, false)) {
		return errors.New("public-node-local: private datapath changed during firewall assignment authorization")
	}
	verified, _, err := c.publicNodeLocalAddresses(ctx, current, currentIntent)
	if err != nil || !reflect.DeepEqual(publicNodeLocalAddressIdentities(verified), publicNodeLocalAddressIdentities(addresses)) {
		return errors.Join(err, errors.New("public-node-local: endpoint or Node eligibility changed during firewall assignment authorization"))
	}
	if requireFence {
		vmSet, vmErr := publicNodeLocalVMSet(addresses)
		if vmErr != nil {
			return vmErr
		}
		started := current.Annotations[annotationNodeLoadBalancerFirewallAssignAt]
		if current.Annotations[annotationNodeLoadBalancerFirewallAssigning] != firewallUUID || started == "" ||
			current.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			current.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return errors.New("public-node-local: durable firewall assignment fence changed before the cloud mutation")
		}
		startedAt, err := time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return fmt.Errorf("public-node-local: invalid durable assignment timestamp: %w", err)
		}
		now := time.Now().UTC()
		if startedAt.After(now) || !now.Before(startedAt.Add(nodeLoadBalancerPendingCreateTimeout)) {
			return errors.New("public-node-local: durable firewall assignment fence is not fresh")
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	addresses []nodeLoadBalancerAddress,
) (*corev1.Service, bool, error) {
	if err := c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, firewallUUID, addresses, true, true); err != nil {
		return service, false, err
	}
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil {
		return service, false, err
	}
	updated, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != firewallUUID ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] == "" ||
			copy.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			copy.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return false, errors.New("public-node-local: assignment fence changed before exact readback clearance")
		}
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssigning)
		delete(copy.Annotations, annotationNodeLoadBalancerFirewallAssignAt)
		delete(copy.Annotations, annotationPublicNodeLocalAssignPolicy)
		delete(copy.Annotations, annotationPublicNodeLocalAssignVMs)
		return true, nil
	})
	return updated, changed, err
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalWithdrawalEvidenceAfterAssignment(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	addresses []nodeLoadBalancerAddress,
) (bool, error) {
	if len(addresses) == 0 {
		return false, errors.New("public-node-local: positive non-empty assignment proof is required to reset withdrawal evidence")
	}
	if err := c.validatePublicNodeLocalAssignmentState(ctx, service, intent, desired, firewallUUID, addresses, true, false); err != nil {
		return false, err
	}
	vmSet, err := publicNodeLocalVMSet(addresses)
	if err != nil {
		return false, err
	}
	provedPairs := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !loadBalancerNodeEligible(address.Node) {
			return false, fmt.Errorf("public-node-local: Node %s is not eligible withdrawal recovery proof", address.Node.Name)
		}
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		provedPairs[firewallUUID+"/"+vmUUID] = struct{}{}
	}
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != firewallUUID ||
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] == "" ||
			copy.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
			copy.Annotations[annotationPublicNodeLocalAssignVMs] != vmSet {
			return false, errors.New("public-node-local: positive assignment proof lost its exact Service identity")
		}
		changed := false
		for _, key := range []string{
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
		} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		storedSet := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach]
		storedAt := copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt]
		if (storedSet == "") != (storedAt == "") {
			return false, errors.New("public-node-local: incomplete firewall withdrawal detach fence during recovery")
		}
		if storedSet == "" {
			return changed, nil
		}
		if err := validateNodeLoadBalancerFirewallDetachSet(storedSet); err != nil {
			return false, err
		}
		detachedAt, parseErr := parseNodeLoadBalancerFirewallDetachTimes(storedAt)
		if parseErr != nil {
			return false, parseErr
		}
		for pair := range provedPairs {
			if _, recorded := detachedAt[pair]; recorded {
				delete(detachedAt, pair)
				changed = true
			}
		}
		if len(detachedAt) == 0 {
			delete(copy.Annotations, annotationNodeLoadBalancerWithdrawFWDetach)
			delete(copy.Annotations, annotationNodeLoadBalancerWithdrawFWDetachAt)
			return changed, nil
		}
		if changed {
			encodedTimes, marshalErr := json.Marshal(detachedAt)
			if marshalErr != nil {
				return false, fmt.Errorf("public-node-local: encode retained firewall withdrawal timestamps: %w", marshalErr)
			}
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = nodeLoadBalancerFirewallDetachSetFromTimes(detachedAt)
			copy.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(encodedTimes)
		}
		return changed, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) publicNodeLocalFirewallAssignmentsMatch(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	nodes []*corev1.Node,
) (bool, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return false, err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return false, errors.Join(err, errors.New("public-node-local: live Service intent changed before firewall assignment readback"))
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return false, errors.New("public-node-local: firewall assignment readback is not bound to the exact current Service ledger and policy")
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		current.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		return false, nil
	}
	desiredVMs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		vmUUID, ok := nodeLoadBalancerVMUUID(node)
		if !ok {
			return false, fmt.Errorf("public-node-local: Node %s has no valid VM identity", node.Name)
		}
		desiredVMs[vmUUID] = struct{}{}
	}
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, err
	}
	matches := 0
	for _, firewall := range items {
		if firewall.UUID != firewallUUID {
			continue
		}
		matches++
		if !nodeLoadBalancerFirewallOwnedByService(firewall, c.provider.config.ClusterID, string(current.UID), c.provider.config.BillingAccountID) ||
			!nodeLoadBalancerFirewallMatches(firewall, desired) {
			return false, errors.New("public-node-local: current firewall lost exact Service ownership")
		}
		stale, err := staleNodeLoadBalancerFirewallAssignments(firewall, desiredVMs)
		if err != nil {
			return false, err
		}
		normalizedAssignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
		if err != nil {
			return false, err
		}
		if len(stale) != 0 || len(normalizedAssignments) != len(desiredVMs) {
			return false, nil
		}
	}
	if matches > 1 {
		return false, fmt.Errorf("public-node-local: firewall UUID %s appears multiple times", firewallUUID)
	}
	return matches == 1, nil
}

func (c *nodeLoadBalancerController) ensurePublicNodeLocalActivation(
	ctx context.Context,
	service *corev1.Service,
	pool, policy string,
) (bool, error) {
	_, changed, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		intent, parseErr := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
		if parseErr != nil || intent.Mode != nodeLoadBalancerModeLocal || intent.Pool != pool ||
			copy.Annotations[annotationNodeLoadBalancerFirewallHash] != policy {
			return false, errors.Join(parseErr, errors.New("public-node-local: Service changed before activation persistence"))
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if copy.Annotations[annotationPublicNodeLocalActivePool] == pool && copy.Annotations[annotationPublicNodeLocalActivePolicy] == policy {
			return false, nil
		}
		if copy.Annotations[annotationPublicNodeLocalActivePool] != "" || copy.Annotations[annotationPublicNodeLocalActivePolicy] != "" {
			return false, errors.New("public-node-local: another activation identity is still persisted")
		}
		copy.Annotations[annotationPublicNodeLocalActivePool] = pool
		copy.Annotations[annotationPublicNodeLocalActivePolicy] = policy
		return true, nil
	})
	return changed, err
}

func (c *nodeLoadBalancerController) validatePublicNodeLocalPublicationState(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	addresses []nodeLoadBalancerAddress,
	requireActivation, requirePublished bool,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return nil, errors.Join(err, errors.New("public-node-local: live Service intent changed at the publication gate"))
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return nil, errors.New("public-node-local: live firewall ledger or policy changed at the publication gate")
	}
	if requireActivation {
		if current.Annotations[annotationPublicNodeLocalActivePool] != intent.Pool ||
			current.Annotations[annotationPublicNodeLocalActivePolicy] != desired.Hash {
			return nil, errors.New("public-node-local: activation authorization changed at the publication gate")
		}
	} else if current.Annotations[annotationPublicNodeLocalActivePool] != "" ||
		current.Annotations[annotationPublicNodeLocalActivePolicy] != "" {
		return nil, errors.New("public-node-local: unexpected activation authorization at the pre-activation gate")
	}
	desiredPrivateStatus := nodeLoadBalancerStatus(addresses, false)
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("public-node-local: read private datapath at publication gate: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, intent.Pool) ||
		!reflect.DeepEqual(datapath.Status.LoadBalancer, desiredPrivateStatus) {
		return nil, errors.New("public-node-local: private datapath spec or status changed at the publication gate")
	}
	verified, _, err := c.publicNodeLocalAddresses(ctx, current, currentIntent)
	if err != nil || !reflect.DeepEqual(publicNodeLocalAddressIdentities(verified), publicNodeLocalAddressIdentities(addresses)) {
		return nil, errors.Join(err, errors.New("public-node-local: endpoint, Node, VM, or FIP proof changed at the publication gate"))
	}
	loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, current, currentIntent)
	if conflictErr != nil || loses || winnerWaiting {
		return nil, errors.Join(conflictErr, errors.New("public-node-local: protocol/port ownership changed at the publication gate"))
	}
	nodes := make([]*corev1.Node, 0, len(addresses))
	for _, address := range addresses {
		nodes = append(nodes, address.Node)
	}
	assignmentsMatch, err := c.publicNodeLocalFirewallAssignmentsMatch(ctx, current, currentIntent, currentDesired, firewallUUID, nodes)
	if err != nil || !assignmentsMatch {
		return nil, errors.Join(err, errors.New("public-node-local: exact firewall assignment proof changed at the publication gate"))
	}
	desiredPublicStatus := nodeLoadBalancerStatus(addresses, true)
	if requirePublished {
		if !reflect.DeepEqual(current.Status.LoadBalancer, desiredPublicStatus) {
			return nil, errors.New("public-node-local: public Proxy status did not read back exactly at the publication gate")
		}
	} else if len(current.Status.LoadBalancer.Ingress) != 0 &&
		!reflect.DeepEqual(current.Status.LoadBalancer, desiredPublicStatus) {
		return nil, errors.New("public-node-local: unexpected public status at the publication gate")
	}
	return current, nil
}

// updatePublicNodeLocalStatusBound deliberately uses the ResourceVersion from
// the fully validated parent read. Unlike a helper that re-GETs internally,
// this makes a concurrent selector/port/session edit conflict before status is
// published; the post-publication gate catches a change racing immediately
// after the update.
func (c *nodeLoadBalancerController) updatePublicNodeLocalStatusBound(
	ctx context.Context,
	service *corev1.Service,
	status corev1.LoadBalancerStatus,
) (*corev1.Service, bool, error) {
	if service == nil || service.UID == "" || service.ResourceVersion == "" {
		// The simple client-go fake does not assign ResourceVersions. Production
		// apiservers always do, while the exact object still provides UID fencing
		// for unit tests.
		if service == nil || service.UID == "" {
			return nil, false, errors.New("public-node-local: exact parent identity is required for bound status publication")
		}
	}
	if reflect.DeepEqual(service.Status.LoadBalancer, status) {
		return service, false, nil
	}
	copy := service.DeepCopy()
	copy.Status.LoadBalancer = *status.DeepCopy()
	updated, err := c.provider.kubeClient.CoreV1().Services(copy.Namespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, false, err
	}
	if updated.UID != service.UID || updated.Generation != service.Generation {
		return nil, false, errors.New("public-node-local: parent identity or generation changed during bound status publication")
	}
	return updated, true, nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalActivation(ctx context.Context, service *corev1.Service) error {
	_, _, err := c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, key := range []string{
			annotationPublicNodeLocalActivePool,
			annotationPublicNodeLocalActivePolicy,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
			annotationPublicNodeLocalAssignPolicy,
			annotationPublicNodeLocalAssignVMs,
		} {
			if copy.Annotations[key] != "" {
				delete(copy.Annotations, key)
				changed = true
			}
		}
		return changed, nil
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *nodeLoadBalancerController) detachPublicNodeLocalFirewalls(
	ctx context.Context,
	service *corev1.Service,
	nodes []*corev1.Node,
) error {
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	for index := range owned {
		if err := c.detachServiceFirewallFromOtherNodes(ctx, service, &owned[index], nodes); err != nil {
			return err
		}
	}
	return nil
}

func (c *nodeLoadBalancerController) clearPublicNodeLocalDatapathStatus(ctx context.Context, service *corev1.Service) error {
	client := c.provider.kubeClient.CoreV1().Services(service.Namespace)
	datapath, err := client.Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !nodeLoadBalancerDatapathOwnedByService(datapath, service) {
		return errors.New("public-node-local: refuse to clear foreign datapath status")
	}
	if len(datapath.Status.LoadBalancer.Ingress) == 0 {
		return nil
	}
	copy := datapath.DeepCopy()
	copy.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	_, err = client.UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *nodeLoadBalancerController) withdrawPublicNodeLocal(ctx context.Context, service *corev1.Service) error {
	// The cloud firewall is the functional public edge. Close and positively
	// read it back before removing either Kubernetes status; otherwise a crash
	// can leave a FIP reaching a host listener after the private VIP vanished.
	if err := c.detachOwnedServiceFirewallsForFailure(ctx, service); err != nil {
		return err
	}
	detached, err := c.serviceFirewallsDetached(ctx, service)
	if err != nil {
		return err
	}
	if !detached {
		return errors.New("public-node-local: waiting for exact Service firewall detachment readback")
	}
	if err := c.clearServiceLoadBalancerStatus(ctx, service); err != nil {
		return err
	}
	if err := c.clearPublicNodeLocalDatapathStatus(ctx, service); err != nil {
		return err
	}
	return c.clearPublicNodeLocalActivation(ctx, service)
}

func (c *nodeLoadBalancerController) failPublicNodeLocalClosed(ctx context.Context, service *corev1.Service, cause error) error {
	return errors.Join(cause, c.withdrawPublicNodeLocal(ctx, service))
}

func (c *nodeLoadBalancerController) cleanupPublicNodeLocal(ctx context.Context, key string, service *corev1.Service) error {
	if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
		return err
	}
	if err := c.deleteOwnedDatapathService(ctx, service); err != nil {
		return err
	}
	absent, err := c.ownedDatapathServiceAbsent(ctx, service)
	if err != nil {
		return err
	}
	if !absent {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if waiting, completed, err := c.resumeOwnedServiceFirewallDelete(ctx, service); err != nil || waiting {
		if waiting {
			c.requeuePublicNodeLocal(key)
		}
		return err
	} else if completed {
		service, err = c.getExactParentService(ctx, service)
		if err != nil {
			return err
		}
	}
	owned, err := c.ownedServiceFirewalls(ctx, service)
	if err != nil {
		return err
	}
	if len(owned) != 0 {
		if changed, err := c.clearFirewallAbsenceEvidence(
			ctx,
			service,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
		); err != nil || changed {
			return err
		}
	}
	if changed, err := c.preparePendingFirewallTeardown(ctx, service, owned); err != nil || changed {
		if changed {
			c.requeuePublicNodeLocal(key)
		}
		return err
	}
	for _, firewall := range owned {
		done, err := c.deleteOwnedServiceFirewall(ctx, service, firewall.UUID)
		if err != nil {
			return err
		}
		if !done {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}
	if len(owned) != 0 {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if service.Annotations[annotationNodeLoadBalancerPendingFWName] != "" {
		if _, err := c.confirmPendingFirewallAbsent(ctx, service, metav1.Now().Time); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	confirmedAbsent, changed, err := c.recordFirewallAbsence(
		ctx,
		service,
		annotationNodeLoadBalancerCleanupFWAbsent,
		annotationNodeLoadBalancerCleanupFWChecked,
		time.Now().UTC(),
		time.Time{},
	)
	if err != nil {
		return err
	}
	if changed || !confirmedAbsent {
		if c.queue != nil {
			c.queue.AddAfter(key, nodeLoadBalancerAbsenceConfirmationDelay)
		}
		return nil
	}
	_, _, err = c.updateExactParentService(ctx, service, func(copy *corev1.Service) (bool, error) {
		if copy.DeletionTimestamp == nil && publicNodeLocalRequested(copy) {
			return false, errors.New("public-node-local: Service became active before finalization")
		}
		if len(copy.Status.LoadBalancer.Ingress) != 0 {
			return false, errors.New("public-node-local: public status remains during finalization")
		}
		if copy.Annotations[annotationNodeLoadBalancerFWDeleteTarget] != "" ||
			copy.Annotations[annotationNodeLoadBalancerFWDeleteIssued] != "" {
			return false, errors.New("public-node-local: refusing finalization while firewall deletion remains fenced")
		}
		changed := containsString(copy.Finalizers, publicNodeLocalFinalizer)
		copy.Finalizers = removeString(copy.Finalizers, publicNodeLocalFinalizer)
		for _, annotation := range []string{
			annotationPublicNodeLocalActivePool,
			annotationPublicNodeLocalActivePolicy,
			annotationPublicNodeLocalConflict,
			annotationNodeLoadBalancerFirewallUUID,
			annotationNodeLoadBalancerFirewallHash,
			annotationNodeLoadBalancerFirewallAbsent,
			annotationNodeLoadBalancerFirewallChecked,
			annotationNodeLoadBalancerPendingFirewall,
			annotationNodeLoadBalancerPendingFWName,
			annotationNodeLoadBalancerPendingFWStarted,
			annotationNodeLoadBalancerPendingFWDelete,
			annotationNodeLoadBalancerPendingFWAbsent,
			annotationNodeLoadBalancerPendingFWChecked,
			annotationNodeLoadBalancerPreviousFirewall,
			annotationNodeLoadBalancerCleanupFWAbsent,
			annotationNodeLoadBalancerCleanupFWChecked,
			annotationNodeLoadBalancerFirewallAssigning,
			annotationNodeLoadBalancerFirewallAssignAt,
			annotationNodeLoadBalancerWithdrawFWAbsent,
			annotationNodeLoadBalancerWithdrawFWChecked,
			annotationNodeLoadBalancerWithdrawFWMissing,
			annotationNodeLoadBalancerWithdrawFWDetach,
			annotationNodeLoadBalancerWithdrawFWDetachAt,
			annotationPublicNodeLocalAssignPolicy,
			annotationPublicNodeLocalAssignVMs,
			annotationNodeLoadBalancerFWDeleteTarget,
			annotationNodeLoadBalancerFWDeleteIssued,
		} {
			if copy.Annotations[annotation] != "" {
				delete(copy.Annotations, annotation)
				changed = true
			}
		}
		return changed, nil
	})
	return err
}

func publicNodeLocalStatusRemovesAddress(current, desired corev1.LoadBalancerStatus) bool {
	for _, existing := range current.Ingress {
		retained := false
		for _, wanted := range desired.Ingress {
			if reflect.DeepEqual(existing, wanted) {
				retained = true
				break
			}
		}
		if !retained {
			return true
		}
	}
	return false
}

func (c *nodeLoadBalancerController) requeuePublicNodeLocal(key string) {
	if c.queue != nil {
		c.queue.AddAfter(key, nodeLoadBalancerRetry)
	}
}
