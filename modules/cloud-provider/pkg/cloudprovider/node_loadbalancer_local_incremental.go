package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	// publicNodeLocalEndpointGoneGrace is how long a published Node may lack a
	// Ready local endpoint before it is removed. It covers a rolling restart.
	publicNodeLocalEndpointGoneGrace = 60 * time.Second

	publicNodeLocalReasonNoReadyEndpoints = "PublicNodeLocalNoReadyEndpoints"
)

func (c *nodeLoadBalancerController) publicNodeLocalClock() time.Time {
	if c.publicNodeLocalNow != nil {
		return c.publicNodeLocalNow().UTC()
	}
	return time.Now().UTC()
}

// noteEndpointGone returns when the key was first seen without an endpoint.
func (c *nodeLoadBalancerController) noteEndpointGone(key string, now time.Time) time.Time {
	c.endpointGoneMu.Lock()
	defer c.endpointGoneMu.Unlock()
	if c.endpointGoneSince == nil {
		c.endpointGoneSince = map[string]time.Time{}
	}
	since, found := c.endpointGoneSince[key]
	if !found {
		c.endpointGoneSince[key] = now
		return now
	}
	return since
}

// pruneEndpointGone forgets every entry of the Service that is not in current.
func (c *nodeLoadBalancerController) pruneEndpointGone(uid string, current map[string]struct{}) {
	c.endpointGoneMu.Lock()
	defer c.endpointGoneMu.Unlock()
	for key := range c.endpointGoneSince {
		if strings.HasPrefix(key, uid+"/") {
			if _, still := current[key]; !still {
				delete(c.endpointGoneSince, key)
			}
		}
	}
}

type publicNodeLocalMember struct {
	node    *corev1.Node
	vmUUID  string
	private string
	public  string
}

func publicNodeLocalMemberOf(node *corev1.Node) publicNodeLocalMember {
	member := publicNodeLocalMember{node: node}
	member.vmUUID, _ = nodeLoadBalancerVMUUID(node)
	member.private, _ = nodeLoadBalancerNodeInternalIPv4(node)
	member.public, _ = nodeLoadBalancerNodeExternalIPv4(node)
	return member
}

func publicNodeLocalIngressSet(status corev1.LoadBalancerStatus) map[string]struct{} {
	result := make(map[string]struct{}, len(status.Ingress))
	for _, ingress := range status.Ingress {
		result[ingress.IP] = struct{}{}
	}
	return result
}

// publicNodeLocalOrderedStatus builds a status whose entries follow the public
// IP order that the bootstrap path uses. Entries without a known public IP
// (stale ones) go last.
func publicNodeLocalOrderedStatus(ips map[string]struct{}, publicOf map[string]string, public bool) corev1.LoadBalancerStatus {
	mode := corev1.LoadBalancerIPModeVIP
	if public {
		mode = corev1.LoadBalancerIPModeProxy
	}
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	rank := func(ip string) (netip.Addr, bool) {
		key := ip
		if !public {
			key = publicOf[ip]
		}
		parsed, err := netip.ParseAddr(key)
		return parsed, err == nil
	}
	sort.Slice(list, func(i, j int) bool {
		left, leftOK := rank(list[i])
		right, rightOK := rank(list[j])
		if leftOK != rightOK {
			return leftOK
		}
		if leftOK {
			if comparison := left.Compare(right); comparison != 0 {
				return comparison < 0
			}
		}
		return list[i] < list[j]
	})
	status := corev1.LoadBalancerStatus{}
	for _, ip := range list {
		status.Ingress = append(status.Ingress, corev1.LoadBalancerIngress{IP: ip, IPMode: &mode})
	}
	return status
}

// convergeActivePublicNodeLocal reconciles a Service that already carries a
// persisted activation. It holds the last known good exposure on every error
// and changes the edge one node at a time: adds run VIP, firewall, FIP;
// removals run FIP, firewall, VIP. One mutation is made per pass.
func (c *nodeLoadBalancerController) convergeActivePublicNodeLocal(
	ctx context.Context,
	key string,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
) error {
	loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, service, intent)
	if loses {
		cause := conflictErr
		if cause == nil {
			cause = fmt.Errorf("public-node-local: Service %s/%s lost a deterministic protocol/port claim in pool %s", service.Namespace, service.Name, intent.Pool)
		}
		return errors.Join(c.recordPublicNodeLocalConflictEvent(ctx, service, cause), c.failPublicNodeLocalClosed(ctx, service, cause))
	}
	if conflictErr != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, conflictErr)
	}
	if cleared, err := c.clearPublicNodeLocalConflict(ctx, service); err != nil || cleared {
		if cleared {
			c.requeuePublicNodeLocal(key)
		}
		return err
	}
	if winnerWaiting {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New(
			"public-node-local: a peer still exposes an overlapping protocol/port claim in the pool"))
	}

	datapath, changed, err := c.ensurePublicNodeLocalDatapath(ctx, service, intent.Pool)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if changed {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	nodes, patchedNode, err := c.classifyPublicNodeLocalNodes(ctx, service, intent)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if patchedNode {
		c.requeuePublicNodeLocal(key)
		return nil
	}
	endpointNodes, err := c.publicNodeLocalReadyEndpointNodes(service)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	var firewall *inspace.Firewall
	var waiting bool
	service, firewall, waiting, err = c.preparePublicNodeLocalFirewall(ctx, service)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	if waiting {
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.New("public-node-local: active Service firewall is not authoritatively ready"))
	}
	if service.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		service.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		// Resolve the unresolved relation receipt before planning on top of it.
		if _, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.serviceFirewallRelationOwner(service), nil); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	assigned, err := nodeLoadBalancerFirewallVMAssignments(*firewall)
	if err != nil {
		return c.holdOrFailPublicNodeLocal(ctx, service, err)
	}
	fips := publicNodeLocalIngressSet(service.Status.LoadBalancer)
	vips := publicNodeLocalIngressSet(datapath.Status.LoadBalancer)

	members := make(map[string]publicNodeLocalMember, len(nodes.Nodes))
	knownPublic := map[string]string{}
	knownPrivate := map[string]string{}
	publicOfPrivate := map[string]string{}
	for name, node := range nodes.Nodes {
		member := publicNodeLocalMemberOf(node)
		members[name] = member
		if member.public != "" {
			knownPublic[member.public] = name
		}
		if member.private != "" {
			knownPrivate[member.private] = name
			publicOfPrivate[member.private] = member.public
		}
	}
	// Ready Nodes carry metadata-verified addresses.
	readyByName := make(map[string]nodeLoadBalancerAddress, len(nodes.Ready))
	for _, address := range nodes.Ready {
		readyByName[address.Node.Name] = address
		member := members[address.Node.Name]
		member.private, member.public = address.PrivateIPv4, address.PublicIPv4
		members[address.Node.Name] = member
		knownPublic[address.PublicIPv4] = address.Node.Name
		knownPrivate[address.PrivateIPv4] = address.Node.Name
		publicOfPrivate[address.PrivateIPv4] = address.PublicIPv4
	}

	now := c.publicNodeLocalClock()
	readyEmpty := len(nodes.Ready) == 0
	keep := map[string]struct{}{}
	// removeGone holds Nodes whose absence is verified; removeGrace holds Nodes
	// that only lost their endpoint for longer than the grace.
	removeGone := map[string]struct{}{}
	removeGrace := map[string]struct{}{}
	goneKeys := map[string]struct{}{}
	var nextCheck time.Duration
	for name := range readyByName {
		keep[name] = struct{}{}
	}
	published := func(name string) bool {
		member := members[name]
		_, found := fips[member.public]
		return member.public != "" && found
	}
	noteGone := func(name string) {
		if readyEmpty {
			// Nothing serves, so no Node is "the one that lost its endpoint". The
			// grace does not run, and pruning below forgets any timer that ran, so
			// the first pod that returns starts a fresh grace for every other Node.
			keep[name] = struct{}{}
			return
		}
		goneKeys[string(service.UID)+"/"+name] = struct{}{}
		since := c.noteEndpointGone(string(service.UID)+"/"+name, now)
		if elapsed := now.Sub(since); elapsed >= publicNodeLocalEndpointGoneGrace {
			removeGrace[name] = struct{}{}
			return
		} else if remaining := publicNodeLocalEndpointGoneGrace - elapsed; nextCheck == 0 || remaining < nextCheck {
			nextCheck = remaining
		}
		keep[name] = struct{}{}
	}
	for name := range nodes.Gone {
		if _, known := members[name]; known {
			removeGone[name] = struct{}{}
		}
	}
	for name := range nodes.Unverified {
		if published(name) {
			keep[name] = struct{}{}
		}
	}
	for name := range nodes.EndpointMissing {
		if published(name) {
			noteGone(name)
		}
	}
	for name := range nodes.NotEligible {
		if !published(name) {
			continue
		}
		if _, serves := endpointNodes[name]; serves {
			keep[name] = struct{}{}
			continue
		}
		noteGone(name)
	}
	c.pruneEndpointGone(string(service.UID), goneKeys)
	for _, set := range []map[string]struct{}{removeGone, removeGrace} {
		for name := range set {
			delete(keep, name)
		}
	}

	staleFIPs := map[string]struct{}{}
	for ip := range fips {
		if _, known := knownPublic[ip]; !known {
			staleFIPs[ip] = struct{}{}
		}
	}
	if readyEmpty && len(fips) != 0 && (len(nodes.EndpointMissing) != 0 || len(nodes.NotEligible) != 0 || len(nodes.Nodes) == 0 || len(keep) != 0) {
		if eventErr := c.recordPublicNodeLocalHoldEvent(ctx, service, publicNodeLocalReasonNoReadyEndpoints, errors.New(
			"public-node-local: no Node has a Ready local endpoint; holding every published Node")); eventErr != nil {
			klog.Warningf("public-node-local %s/%s: record Event: %v", service.Namespace, service.Name, eventErr)
		}
	}
	if len(keep) == 0 && len(fips) != 0 {
		// Every published Node is verified gone: nothing is left to serve.
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	if nextCheck > 0 && c.queue != nil {
		c.queue.AddAfter(key, nextCheck)
	}

	// removeNodes runs one removal step for the dropped Nodes while the kept
	// Nodes stay on the edge. It reports whether it changed anything.
	removeNodes := func(drop, kept map[string]struct{}) (bool, error) {
		removeFIPs := map[string]struct{}{}
		for ip := range staleFIPs {
			removeFIPs[ip] = struct{}{}
		}
		for name := range drop {
			if member := members[name]; member.public != "" {
				if _, has := fips[member.public]; has {
					removeFIPs[member.public] = struct{}{}
				}
			}
		}
		if len(removeFIPs) != 0 {
			next := map[string]struct{}{}
			for ip := range fips {
				if _, drop := removeFIPs[ip]; !drop {
					next[ip] = struct{}{}
				}
			}
			if err := c.publishActivePublicNodeLocalStatus(ctx, service, intent, desired, firewall.UUID, publicNodeLocalOrderedStatus(next, nil, true)); err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			c.requeuePublicNodeLocal(key)
			return true, nil
		}
		keepNodes := make([]*corev1.Node, 0, len(kept))
		keepVMSet := map[string]struct{}{}
		keepPrivate := map[string]struct{}{}
		for name := range kept {
			member := members[name]
			keepPrivate[member.private] = struct{}{}
			if member.vmUUID != "" {
				keepNodes = append(keepNodes, member.node)
				keepVMSet[member.vmUUID] = struct{}{}
			}
		}
		stale, err := staleNodeLoadBalancerFirewallAssignments(*firewall, keepVMSet)
		if err != nil {
			return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if len(stale) != 0 {
			if err := c.detachServiceFirewallFromOtherNodes(ctx, service, firewall, keepNodes); err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			c.requeuePublicNodeLocal(key)
			return true, nil
		}
		next := map[string]struct{}{}
		for ip := range vips {
			if _, keptVIP := keepPrivate[ip]; keptVIP {
				next[ip] = struct{}{}
			}
		}
		if len(next) != len(vips) {
			if _, _, err := c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, intent.Pool, publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			c.requeuePublicNodeLocal(key)
			return true, nil
		}
		return false, nil
	}

	// A recreated or class-repaired child lost its VIPs. Every kept and published
	// Node gets its VIP back first, Ready or not, so the FIP, the firewall and
	// the VIP of each published Node stay consistent before anything else moves.
	restoreVIPs := map[string]struct{}{}
	for name := range keep {
		member := members[name]
		if member.private == "" || !published(name) {
			continue
		}
		if _, has := vips[member.private]; !has {
			restoreVIPs[member.private] = struct{}{}
		}
	}
	if len(restoreVIPs) != 0 {
		next := map[string]struct{}{}
		for ip := range vips {
			next[ip] = struct{}{}
		}
		for ip := range restoreVIPs {
			next[ip] = struct{}{}
		}
		if _, _, err := c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, intent.Pool, publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	// Removals: FIP, then the firewall, then the child VIP. Nodes that are
	// verifiably gone leave first and never wait behind a stuck or parked add,
	// since a gone Node can not serve and removing it takes no capacity away.
	// The grace removals run after the adds so a replacement is up first.
	keepWithGrace := map[string]struct{}{}
	for name := range keep {
		keepWithGrace[name] = struct{}{}
	}
	for name := range removeGrace {
		keepWithGrace[name] = struct{}{}
	}
	if acted, err := removeNodes(removeGone, keepWithGrace); acted || err != nil {
		return err
	}

	// Adds first: child VIP, then the firewall, then the FIP.
	var addVIP, addAssign, addFIP []nodeLoadBalancerAddress
	for _, address := range nodes.Ready {
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		if _, has := vips[address.PrivateIPv4]; !has {
			addVIP = append(addVIP, address)
		}
		if _, has := assigned[vmUUID]; !has {
			addAssign = append(addAssign, address)
		}
		if _, has := fips[address.PublicIPv4]; !has {
			addFIP = append(addFIP, address)
		}
	}
	if len(addVIP) != 0 {
		next := map[string]struct{}{}
		for ip := range vips {
			next[ip] = struct{}{}
		}
		for _, address := range addVIP {
			next[address.PrivateIPv4] = struct{}{}
		}
		if _, _, err := c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, intent.Pool, publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if len(addAssign) != 0 {
		keepVMs := make([]string, 0, len(keep))
		for name := range keep {
			if vmUUID := members[name].vmUUID; vmUUID != "" {
				keepVMs = append(keepVMs, vmUUID)
			}
		}
		sort.Strings(keepVMs)
		authorized, err := c.ensureActivePublicNodeLocalAssignmentIntent(ctx, service, intent, desired, firewall.UUID, keepVMs)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if err := c.assignPublicNodeLocalFirewallWithFence(ctx, authorized, intent, desired, firewall, addAssign); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, authorized, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if len(addFIP) != 0 {
		next := map[string]struct{}{}
		for ip := range fips {
			next[ip] = struct{}{}
		}
		for _, address := range addFIP {
			next[address.PublicIPv4] = struct{}{}
		}
		if err := c.publishActivePublicNodeLocalStatus(ctx, service, intent, desired, firewall.UUID, publicNodeLocalOrderedStatus(next, nil, true)); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		// The adds are complete, so the assignment intent ends with them.
		if publicNodeLocalAssignmentFencePresent(service) {
			if err := c.clearActivePublicNodeLocalAssignmentIntent(ctx, service, intent, desired, firewall.UUID); err != nil {
				return c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	if publicNodeLocalAssignmentFencePresent(service) {
		if err := c.clearActivePublicNodeLocalAssignmentIntent(ctx, service, intent, desired, firewall.UUID); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	// The rest of the removals, after every add is done.
	allDropped := map[string]struct{}{}
	for name := range removeGone {
		allDropped[name] = struct{}{}
	}
	for name := range removeGrace {
		allDropped[name] = struct{}{}
	}
	if acted, err := removeNodes(allDropped, keep); acted || err != nil {
		return err
	}

	if len(nodes.Unverified) != 0 {
		names := make([]string, 0, len(nodes.Unverified))
		for name := range nodes.Unverified {
			names = append(names, name)
		}
		sort.Strings(names)
		causes := make([]error, 0, len(names))
		for _, name := range names {
			causes = append(causes, nodes.Unverified[name])
		}
		return c.holdOrFailPublicNodeLocal(ctx, service, errors.Join(causes...))
	}
	return nil
}

// activePublicNodeLocalContract re-reads the Service and proves that the
// intent, the firewall ledger and the activation are still the ones the pass
// planned with.
func (c *nodeLoadBalancerController) activePublicNodeLocalContract(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
) (*corev1.Service, error) {
	current, err := c.getExactParentService(ctx, service)
	if err != nil {
		return nil, err
	}
	currentIntent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{NodesPerShard: c.provider.config.NodeLoadBalancer.NodesPerShard})
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) ||
		!reflect.DeepEqual(currentIntent, intent) {
		return nil, joinWithExplanation(errors.New("public-node-local: live Service contract changed during an incremental change"), err)
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(currentDesired, desired) ||
		current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return nil, errors.New("public-node-local: live firewall ledger or policy changed during an incremental change")
	}
	if current.Annotations[annotationPublicNodeLocalActivePool] != intent.Pool ||
		current.Annotations[annotationPublicNodeLocalActivePolicy] != desired.Hash {
		return nil, errors.New("public-node-local: persisted activation identity changed during an incremental change")
	}
	return current, nil
}

// ensureActivePublicNodeLocalAssignmentIntent persists the durable intent for
// incremental assignments. A stale or different intent is renewed because the
// Service is serving and nothing was dispatched under it unreceipted.
func (c *nodeLoadBalancerController) ensureActivePublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	vmUUIDs []string,
) (*corev1.Service, error) {
	if len(vmUUIDs) == 0 {
		return service, errors.New("public-node-local: non-empty VM set is required before assignment authorization")
	}
	current, err := c.activePublicNodeLocalContract(ctx, service, intent, desired, firewallUUID)
	if err != nil {
		return service, err
	}
	vmSet := strings.Join(vmUUIDs, ",")
	now := time.Now().UTC()
	updated, _, err := c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		startedAt, parseErr := time.Parse(time.RFC3339Nano, copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
		fresh := parseErr == nil && !startedAt.After(now) && now.Before(startedAt.Add(nodeLoadBalancerPublicNodeLocalAssignTimeout))
		if fresh && copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] == firewallUUID &&
			copy.Annotations[annotationPublicNodeLocalAssignPolicy] == desired.Hash &&
			copy.Annotations[annotationPublicNodeLocalAssignVMs] == vmSet {
			return false, nil
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		if !fresh || copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] != firewallUUID {
			copy.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = now.Format(time.RFC3339Nano)
		}
		copy.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
		copy.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
		copy.Annotations[annotationPublicNodeLocalAssignVMs] = vmSet
		return true, nil
	})
	if err != nil {
		return current, err
	}
	return updated, nil
}

func (c *nodeLoadBalancerController) clearActivePublicNodeLocalAssignmentIntent(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
) error {
	current, err := c.activePublicNodeLocalContract(ctx, service, intent, desired, firewallUUID)
	if err != nil {
		return err
	}
	_, _, err = c.updateExactParentService(ctx, current, func(copy *corev1.Service) (bool, error) {
		changed := false
		for _, key := range []string{
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
	return err
}

// publishActivePublicNodeLocalStatus writes the parent FIP status of a serving
// Service after the contract is proven unchanged.
func (c *nodeLoadBalancerController) publishActivePublicNodeLocalStatus(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	status corev1.LoadBalancerStatus,
) error {
	current, err := c.activePublicNodeLocalContract(ctx, service, intent, desired, firewallUUID)
	if err != nil {
		return err
	}
	_, _, err = c.updatePublicNodeLocalStatusBound(ctx, current, status)
	return err
}

// validateActivePublicNodeLocalAssignState is the pre-dispatch authority for
// assigning the Service firewall to one more VM of a serving Service. Unlike
// the bootstrap gate it allows a non-empty public status and only needs the one
// VM to be a current, verified, Ready endpoint with a child VIP.
func (c *nodeLoadBalancerController) validateActivePublicNodeLocalAssignState(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID, vmUUID string,
) error {
	current, err := c.activePublicNodeLocalContract(ctx, service, intent, desired, firewallUUID)
	if err != nil {
		return err
	}
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("public-node-local: read private datapath during assignment authorization: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, intent.Pool) {
		return errors.New("public-node-local: private datapath spec changed during firewall assignment authorization")
	}
	nodes, patched, err := c.classifyPublicNodeLocalNodes(ctx, current, intent)
	if err != nil {
		return err
	}
	if patched {
		return errors.New("public-node-local Node authority changed and requires a fresh reconciliation")
	}
	var target *nodeLoadBalancerAddress
	for index := range nodes.Ready {
		if id, ok := nodeLoadBalancerVMUUID(nodes.Ready[index].Node); ok && id == vmUUID {
			target = &nodes.Ready[index]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("VM %s is not a current authorized local endpoint", vmUUID)
	}
	vips := publicNodeLocalIngressSet(datapath.Status.LoadBalancer)
	if _, has := vips[target.PrivateIPv4]; !has {
		return fmt.Errorf("public-node-local: VM %s is absent from the exact child VIP status", vmUUID)
	}
	started, err := time.Parse(time.RFC3339Nano, current.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
	now := time.Now().UTC()
	if err != nil || started.After(now) || !now.Before(started.Add(nodeLoadBalancerPublicNodeLocalAssignTimeout)) {
		return errors.New("public-node-local: durable firewall assignment fence is not fresh")
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallAssigning] != firewallUUID ||
		current.Annotations[annotationPublicNodeLocalAssignPolicy] != desired.Hash ||
		!containsString(strings.Split(current.Annotations[annotationPublicNodeLocalAssignVMs], ","), vmUUID) {
		return errors.New("public-node-local: durable firewall assignment fence does not cover the VM")
	}
	return nil
}
