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

	publicNodeLocalReasonAwaitingConfirmation = "PublicNodeLocalAwaitingConfirmation"
)

// unverifiedCauses joins why Nodes could not be verified, in Node name order, so
// a hold keeps a transient cause visible and is deferred like any transient error.
func (s publicNodeLocalNodeSet) unverifiedCauses() error {
	names := make([]string, 0, len(s.Unverified))
	for name := range s.Unverified {
		names = append(names, name)
	}
	sort.Strings(names)
	causes := make([]error, 0, len(names))
	for _, name := range names {
		causes = append(causes, s.Unverified[name])
	}
	return errors.Join(causes...)
}

// holdCause is why a pass holds. A Node that could not be verified is the
// better reason: a transient cause behind it stays visible and the pass is
// deferred, where a plain waiting message would turn it into a definite hold.
func (s publicNodeLocalNodeSet) holdCause(waiting error) error {
	if len(s.Unverified) != 0 {
		return s.unverifiedCauses()
	}
	return waiting
}

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
// removals run FIP, firewall, VIP. One mutation is made per pass. While a pool
// or policy change is pending, the pass runs under the active identity (see
// publicNodeLocalPassMode).
func (c *nodeLoadBalancerController) convergeActivePublicNodeLocal(
	ctx context.Context,
	key string,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	mode publicNodeLocalPassMode,
) error {
	policyHeld := mode == publicNodeLocalPassPolicyHeld
	union := mode == publicNodeLocalPassUnion
	// The child follows the persisted activation. During a union the intent is
	// the target, and the child keeps the active pool until promotion.
	activePool := service.Annotations[annotationPublicNodeLocalActivePool]
	if !policyHeld {
		loses, winnerWaiting, conflictErr := c.publicNodeLocalPortConflict(ctx, service, intent)
		if loses {
			cause := conflictErr
			if cause == nil {
				cause = fmt.Errorf("public-node-local: Service %s/%s lost a deterministic protocol/port claim in pool %s", service.Namespace, service.Name, intent.Pool)
			}
			if union {
				// The active exposure still holds its own claim. Only the target
				// is given up.
				return errors.Join(c.recordPublicNodeLocalConflictEvent(ctx, service, cause), c.abortPublicNodeLocalTransition(ctx, key, service, cause))
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
	}

	var datapath *corev1.Service
	if policyHeld {
		// The Service spec describes the pending policy, not the child. Leave the
		// child spec alone and only work with what it publishes.
		var readErr error
		if datapath, readErr = c.readPublicNodeLocalDatapathHeld(ctx, service); readErr != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, readErr)
		}
	} else {
		var changed bool
		var err error
		datapath, changed, err = c.ensurePublicNodeLocalDatapath(ctx, service, activePool)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if changed {
			c.requeuePublicNodeLocal(key)
			return nil
		}
	}
	pools := []string{activePool}
	if union && intent.Pool != activePool {
		pools = append(pools, intent.Pool)
	}
	nodes, patchedNode, _, err := c.classifyPublicNodeLocalNodesPools(ctx, service, pools, activePool, false, !policyHeld)
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
	var firewall, previousFirewall *inspace.Firewall
	if policyHeld {
		if service, err = c.getExactParentService(ctx, service); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if firewall, previousFirewall, err = c.activePublicNodeLocalFirewall(ctx, service, desired.Hash); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
	} else {
		var waiting bool
		service, firewall, previousFirewall, waiting, err = c.preparePublicNodeLocalFirewall(ctx, service)
		if err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if waiting {
			return c.holdOrFailPublicNodeLocal(ctx, service, nodes.holdCause(
				errors.New("public-node-local: active Service firewall is not authoritatively ready")))
		}
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
	vips := map[string]struct{}{}
	if datapath != nil {
		vips = publicNodeLocalIngressSet(datapath.Status.LoadBalancer)
	}
	// setVIPs writes the child VIPs. A held policy has no spec to compare with.
	setVIPs := func(status corev1.LoadBalancerStatus) error {
		if policyHeld {
			return c.setPublicNodeLocalDatapathStatusHeld(ctx, service, datapath, status)
		}
		_, _, err := c.ensurePublicNodeLocalDatapathStatus(ctx, service, datapath, activePool, status)
		return err
	}

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
	// An unverified Node stays wherever it already is: published, or part of the way
	// through an add (firewall assigned or VIP present). Detaching a half-added Node
	// on one odd answer would only undo the add and flap it.
	for name := range nodes.Unverified {
		member := members[name]
		_, assignedVM := assigned[member.vmUUID]
		_, hasVIP := vips[member.private]
		if published(name) || (member.vmUUID != "" && assignedVM) || (member.private != "" && hasVIP) {
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
		// Every published Node is gone. A withdrawal of the whole Service needs
		// the Node objects themselves as evidence, or two reads that are spaced
		// apart: one odd cloud answer (an empty VPC member list) must not close
		// the edge on its own.
		evidenced := true
		for name := range removeGone {
			if _, ok := nodes.NodeEvidence[name]; !ok {
				evidenced = false
			}
		}
		if !evidenced {
			since := c.noteAllGone(string(service.UID), now)
			if elapsed := now.Sub(since); elapsed < nodeLoadBalancerAbsenceConfirmationDelay {
				if eventErr := c.recordPublicNodeLocalHoldEvent(ctx, service, publicNodeLocalReasonAwaitingConfirmation, errors.New(
					"public-node-local: every published Node looks gone on cloud evidence alone; waiting for a second spaced read before withdrawing")); eventErr != nil {
					klog.Warningf("public-node-local %s/%s: record Event: %v", service.Namespace, service.Name, eventErr)
				}
				if c.queue != nil {
					c.queue.AddAfter(key, nodeLoadBalancerAbsenceConfirmationDelay-elapsed)
				}
				return nil
			}
		}
		c.clearAllGone(string(service.UID))
		// Nothing is left to serve.
		if err := c.withdrawPublicNodeLocal(ctx, service); err != nil {
			return err
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}
	c.clearAllGone(string(service.UID))

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
		// The current firewall and, while one is left over, the previous one: a
		// node that leaves loses both before its child VIP goes.
		for _, leaving := range []*inspace.Firewall{firewall, previousFirewall} {
			if leaving == nil {
				continue
			}
			stale, err := staleNodeLoadBalancerFirewallAssignments(*leaving, keepVMSet)
			if err != nil {
				return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			if len(stale) != 0 {
				if err := c.detachServiceFirewallFromOtherNodes(ctx, service, leaving, keepNodes); err != nil {
					return true, c.holdOrFailPublicNodeLocal(ctx, service, err)
				}
				c.requeuePublicNodeLocal(key)
				return true, nil
			}
		}
		next := map[string]struct{}{}
		for ip := range vips {
			if _, keptVIP := keepPrivate[ip]; keptVIP {
				next[ip] = struct{}{}
			}
		}
		if len(next) != len(vips) {
			if err := setVIPs(publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
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
	if len(restoreVIPs) != 0 && datapath != nil {
		next := map[string]struct{}{}
		for ip := range vips {
			next[ip] = struct{}{}
		}
		for ip := range restoreVIPs {
			next[ip] = struct{}{}
		}
		if err := setVIPs(publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
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
	addCandidates := nodes.Ready
	if policyHeld {
		// Adds wait for a make-before-break transition: a new node would need the
		// pending policy, and the active one is the only one this pass may use.
		addCandidates = nil
	}
	var targetReady []nodeLoadBalancerAddress
	if union {
		for _, address := range nodes.Ready {
			if nodes.PoolOf[address.Node.Name] == intent.Pool {
				targetReady = append(targetReady, address)
			}
		}
		if desired.Hash != service.Annotations[annotationPublicNodeLocalActivePolicy] {
			// The active pool's Nodes hold the old firewall and the ledger names the
			// new one, so only the target pool gains Nodes. The active pool keeps
			// what it has and loses it through the removal order after promotion.
			addCandidates = targetReady
		}
		// With the same policy the firewall is shared, so a Node that joins the
		// active pool meanwhile (a replacement, say) can still join.
	}
	for _, address := range addCandidates {
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
		if err := setVIPs(publicNodeLocalOrderedStatus(next, publicOfPrivate, false)); err != nil {
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
		if err := c.verifyActivePublicNodeLocalPublication(ctx, service, intent, desired, firewall.UUID, addFIP); err != nil {
			if inspace.IsTransient(err) {
				return c.holdOrFailPublicNodeLocal(ctx, service, err)
			}
			// The proof behind the new FIPs is gone, so take them back. The
			// FIPs that were already serving stay.
			rollbackErr := c.publishActivePublicNodeLocalStatus(ctx, service, intent, desired, firewall.UUID, publicNodeLocalOrderedStatus(fips, nil, true))
			return c.holdOrFailPublicNodeLocal(ctx, service, errors.Join(err, rollbackErr))
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
	if !policyHeld && publicNodeLocalAssignmentFencePresent(service) {
		if err := c.clearActivePublicNodeLocalAssignmentIntent(ctx, service, intent, desired, firewall.UUID); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		c.requeuePublicNodeLocal(key)
		return nil
	}

	if union {
		// Every Node of the target pool is on the edge now. It must be a pool
		// that serves at all: promoting an empty one would take the edge away.
		if len(targetReady) == 0 {
			return c.holdPendingPublicNodeLocalTransition(ctx, service, nodes.holdCause(errors.New(
				"public-node-local: the target pool has no Ready Node with a local endpoint yet; the active exposure stays")))
		}
		if err := c.verifyActivePublicNodeLocalPublication(ctx, service, intent, desired, firewall.UUID, targetReady); err != nil {
			return c.holdOrFailPublicNodeLocal(ctx, service, err)
		}
		if err := c.promotePublicNodeLocalTransition(ctx, service, intent.Pool, desired.Hash, firewall.UUID); err != nil {
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
	if acted, err := c.finishPreviousPublicNodeLocalFirewall(ctx, key, service, firewall, previousFirewall, assigned, keep, members); acted || err != nil {
		return err
	}

	if len(nodes.Unverified) != 0 {
		return c.holdOrFailPublicNodeLocal(ctx, service, nodes.unverifiedCauses())
	}
	return nil
}

// activePublicNodeLocalContract re-reads the Service and proves that the
// intent, the firewall ledger and the activation are still the ones the pass
// planned with. A pass under a pending change plans with the active identity:
// the live pool annotation is read as the active pool, and a live spec whose
// policy differs from the active one is not compared at all, since it belongs
// to the held intent. Only the active identity and the ledger must still match.
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
	if err != nil || current.DeletionTimestamp != nil || !containsString(current.Finalizers, publicNodeLocalFinalizer) {
		return nil, joinWithExplanation(errors.New("public-node-local: live Service contract changed during an incremental change"), err)
	}
	state, err := publicNodeLocalTransition(current)
	if err != nil {
		return nil, err
	}
	// Adds converge to the target while a union runs and to the active identity
	// otherwise. A held pass reads the live pool annotation as the active pool.
	workPool, workPolicy := state.Work()
	if state.Phase != publicNodeLocalPhaseUnion && workPool != "" {
		currentIntent.Pool = workPool
	}
	currentDesired, err := c.desiredServiceFirewall(current)
	if err != nil {
		return nil, err
	}
	if state.Phase == publicNodeLocalPhaseUnion && currentDesired.Hash != workPolicy {
		return nil, errors.New("public-node-local: live target policy changed during a transition")
	}
	if currentDesired.Hash == workPolicy {
		if !reflect.DeepEqual(currentIntent, intent) {
			return nil, errors.New("public-node-local: live Service contract changed during an incremental change")
		}
		if !reflect.DeepEqual(currentDesired, desired) {
			return nil, errors.New("public-node-local: live firewall ledger or policy changed during an incremental change")
		}
	}
	if current.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewallUUID ||
		current.Annotations[annotationNodeLoadBalancerFirewallHash] != desired.Hash {
		return nil, errors.New("public-node-local: live firewall ledger or policy changed during an incremental change")
	}
	if workPool != intent.Pool || workPolicy != desired.Hash {
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
	if !publicNodeLocalDatapathMatches(datapath, current, publicNodeLocalChildPool(current, intent.Pool)) {
		return errors.New("public-node-local: private datapath spec changed during firewall assignment authorization")
	}
	nodes, patched, err := c.classifyPublicNodeLocalNodesInTransition(ctx, current)
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
		for name, cause := range nodes.Unverified {
			if id, ok := nodeLoadBalancerVMUUID(nodes.Nodes[name]); ok && id == vmUUID {
				// A cause that is only a missing cloud answer stays transient.
				return cause
			}
		}
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

// classifyPublicNodeLocalNodesInTransition classifies the Nodes of a serving
// Service against the active pool and, during a union, the target pool too.
func (c *nodeLoadBalancerController) classifyPublicNodeLocalNodesInTransition(
	ctx context.Context,
	service *corev1.Service,
) (publicNodeLocalNodeSet, bool, error) {
	active := service.Annotations[annotationPublicNodeLocalActivePool]
	pools := []string{active}
	if target := service.Annotations[annotationPublicNodeLocalTargetPool]; target != "" && target != active {
		pools = append(pools, target)
	}
	set, patched, _, err := c.classifyPublicNodeLocalNodesPools(ctx, service, pools, active, false, true)
	return set, patched, err
}

// noteAllGone returns when the Service was first seen with every published Node
// gone on cloud evidence alone.
func (c *nodeLoadBalancerController) noteAllGone(uid string, now time.Time) time.Time {
	c.endpointGoneMu.Lock()
	defer c.endpointGoneMu.Unlock()
	if c.allGoneSince == nil {
		c.allGoneSince = map[string]time.Time{}
	}
	since, found := c.allGoneSince[uid]
	if !found {
		c.allGoneSince[uid] = now
		return now
	}
	return since
}

// clearAllGone forgets the confirmation of a Service.
func (c *nodeLoadBalancerController) clearAllGone(uid string) {
	c.endpointGoneMu.Lock()
	defer c.endpointGoneMu.Unlock()
	delete(c.allGoneSince, uid)
}

// verifyActivePublicNodeLocalPublication is the post-write gate of an add on a
// serving Service, in the spirit of validatePublicNodeLocalPublicationState:
// the parent status carries the new FIPs, and the child VIP, the firewall
// assignment and the Node proof of every added VM read back exactly.
func (c *nodeLoadBalancerController) verifyActivePublicNodeLocalPublication(
	ctx context.Context,
	service *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	firewallUUID string,
	added []nodeLoadBalancerAddress,
) error {
	current, err := c.activePublicNodeLocalContract(ctx, service, intent, desired, firewallUUID)
	if err != nil {
		return err
	}
	published := publicNodeLocalIngressSet(current.Status.LoadBalancer)
	datapath, err := c.provider.kubeClient.CoreV1().Services(current.Namespace).Get(
		ctx, nodeLoadBalancerDatapathName(current), metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("public-node-local: read private datapath after publication: %w", err)
	}
	if !publicNodeLocalDatapathMatches(datapath, current, publicNodeLocalChildPool(current, intent.Pool)) {
		return errors.New("public-node-local: private datapath spec changed after publication")
	}
	vips := publicNodeLocalIngressSet(datapath.Status.LoadBalancer)
	owned, err := c.ownedServiceFirewalls(ctx, current)
	if err != nil {
		return err
	}
	var assigned map[string]struct{}
	for index := range owned {
		if owned[index].UUID == firewallUUID {
			assignments, assignErr := nodeLoadBalancerFirewallVMAssignments(owned[index])
			if assignErr != nil {
				return assignErr
			}
			assigned = make(map[string]struct{}, len(assignments))
			for vmUUID := range assignments {
				assigned[vmUUID] = struct{}{}
			}
		}
	}
	if assigned == nil {
		return fmt.Errorf("public-node-local: Service firewall %s is absent after publication", firewallUUID)
	}
	nodes, patched, err := c.classifyPublicNodeLocalNodesInTransition(ctx, current)
	if err != nil {
		return err
	}
	if patched {
		return errors.New("public-node-local Node authority changed after publication")
	}
	ready := map[string]nodeLoadBalancerAddress{}
	for _, address := range nodes.Ready {
		ready[address.Node.Name] = address
	}
	for _, address := range added {
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		if _, ok := published[address.PublicIPv4]; !ok {
			return fmt.Errorf("public-node-local: FIP %s did not read back in the parent status", address.PublicIPv4)
		}
		if _, ok := vips[address.PrivateIPv4]; !ok {
			return fmt.Errorf("public-node-local: VIP %s of VM %s is absent after publication", address.PrivateIPv4, vmUUID)
		}
		if _, ok := assigned[vmUUID]; !ok {
			return fmt.Errorf("public-node-local: VM %s has no Service firewall after publication", vmUUID)
		}
		if cause, unverified := nodes.Unverified[address.Node.Name]; unverified {
			// A cause that is only a missing cloud answer stays transient.
			return cause
		}
		verified, ok := ready[address.Node.Name]
		if !ok || !reflect.DeepEqual(
			publicNodeLocalAddressIdentities([]nodeLoadBalancerAddress{verified}),
			publicNodeLocalAddressIdentities([]nodeLoadBalancerAddress{address}),
		) {
			return fmt.Errorf("public-node-local: Node %s is no longer a verified endpoint after publication", address.Node.Name)
		}
	}
	return nil
}
