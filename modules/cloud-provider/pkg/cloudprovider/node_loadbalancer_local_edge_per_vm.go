package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	// annotationPublicNodeLocalFirewallMode marks a Service whose edge is the
	// per-VM firewall. It is written before the Service opens its first VM and
	// never removed while the Service lives; absent means per-Service.
	annotationPublicNodeLocalFirewallMode = "service.inspace.cloud/public-node-local-firewall-mode"
	// annotationPublicNodeLocalAssignEdge is the assignment fence of a per-VM
	// edge. It replaces the assigning-uuid key, which a per-VM Service leaves
	// empty. A v1.1.9 controller reads that as an incomplete fence and holds.
	annotationPublicNodeLocalAssignEdge = "service.inspace.cloud/public-node-local-assigning-edge"
	publicNodeLocalEdgePerVM            = "per-vm"

	publicNodeLocalReasonVMFirewallMigrationWaiting = "PublicNodeLocalVMFirewallMigrationWaiting"
)

// publicNodeLocalServicePerVM says whether the Service lives on the per-VM firewall.
func publicNodeLocalServicePerVM(svc *corev1.Service) bool {
	return svc != nil && svc.Annotations[annotationPublicNodeLocalFirewallMode] == publicNodeLocalEdgePerVM
}

// publicNodeLocalOldEdgePending says whether the Service still has an old edge
// to retire after a promotion or an abort: the previous firewall of a
// per-Service Service, the old-policy entries of a per-VM one.
func publicNodeLocalOldEdgePending(svc *corev1.Service) bool {
	return svc != nil && (svc.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" ||
		(publicNodeLocalServicePerVM(svc) && svc.Annotations[annotationPublicNodeLocalPromotedAt] != ""))
}

// publicNodeLocalUsesPerVMEdge says whether, in the perVM mode, the Service
// takes the per-VM edge: it already lives on it, or it has no per-Service
// firewall state of any kind.
func publicNodeLocalUsesPerVMEdge(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if publicNodeLocalServicePerVM(svc) {
		return true
	}
	for _, key := range []string{
		annotationNodeLoadBalancerFirewallUUID,
		annotationNodeLoadBalancerFirewallHash,
		annotationNodeLoadBalancerPreviousFirewall,
		annotationPublicNodeLocalActivePolicy,
		annotationNodeLoadBalancerPendingFirewall,
		annotationNodeLoadBalancerPendingFWName,
	} {
		if svc.Annotations[key] != "" {
			return false
		}
	}
	return true
}

// perVMEdge is the edge of one firewall per VM. A Service owns no cloud
// firewall: it holds ledger entries on the anchors of its VMs, and the shared
// transaction of node_loadbalancer_vm_firewall_state.go carries each entry to
// the cloud one delta at a time.
type perVMEdge struct{ c *nodeLoadBalancerController }

var _ publicNodeLocalEdge = perVMEdge{}

// vmFirewallLedgerKeys lists the entries of one Service on an anchor, in the
// applied and in the staged ledger. An unreadable ledger lists nothing here;
// the transaction that reads the anchor reports it.
func (a vmFirewallAnchorView) memberKeys(serviceUID string) []vmFirewallMemberKey {
	seen := map[vmFirewallMemberKey]struct{}{}
	keys := []vmFirewallMemberKey{}
	for _, read := range []func() (vmFirewallLedger, error){a.applied, a.pending} {
		ledger, err := read()
		if err != nil {
			continue
		}
		for _, member := range ledger.Members {
			if member.UID != serviceUID {
				continue
			}
			if _, dup := seen[member.key()]; dup {
				continue
			}
			seen[member.key()] = struct{}{}
			keys = append(keys, member.key())
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Policy < keys[j].Policy })
	return keys
}

// vmFirewallMemberLookup returns the Services whose entries live on the anchor
// of vmUUID, plus the asking Service. They receive the Events of the VM.
func (c *nodeLoadBalancerController) vmFirewallMemberLookup(vmUUID string, asking *corev1.Service) func(context.Context) []*corev1.Service {
	return func(ctx context.Context) []*corev1.Service {
		out := []*corev1.Service{}
		seen := map[string]struct{}{}
		if asking != nil {
			out = append(out, asking)
			seen[string(asking.UID)] = struct{}{}
		}
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil || anchor == nil {
			return out
		}
		view := vmFirewallAnchorView{cm: anchor}
		uids := map[string]struct{}{}
		for _, read := range []func() (vmFirewallLedger, error){view.applied, view.pending} {
			if ledger, readErr := read(); readErr == nil {
				for _, member := range ledger.Members {
					uids[member.UID] = struct{}{}
				}
			}
		}
		if len(uids) == 0 {
			return out
		}
		list, err := c.provider.kubeClient.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return out
		}
		for index := range list.Items {
			service := &list.Items[index]
			if _, member := uids[string(service.UID)]; !member {
				continue
			}
			if _, dup := seen[string(service.UID)]; dup {
				continue
			}
			seen[string(service.UID)] = struct{}{}
			out = append(out, service.DeepCopy())
		}
		return out
	}
}

// perVMEdgeID reads the edge of one policy of a Service from a listing and the
// anchors. An open receipt that concerns the Service leaves the VM out of the
// open set and is resolved by ResolvePending.
func (c *nodeLoadBalancerController) perVMEdgeID(
	serviceUID, policy string,
	items []inspace.Firewall,
	anchors []corev1.ConfigMap,
) (edgeID, error) {
	open, err := c.vmEdgeAssigned(serviceUID, policy, items, anchors)
	if err != nil && !errors.Is(err, errVMFirewallReceiptPending) {
		return edgeID{}, err
	}
	listed := map[string]struct{}{}
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		for _, key := range view.memberKeys(serviceUID) {
			if key.Policy == policy {
				listed[view.vm()] = struct{}{}
			}
		}
	}
	return edgeID{policy: policy, perVM: true, open: open, listed: listed}, nil
}

// perVMPreviousPolicy is the policy whose entries the Service still has to
// retire: the active one while a union runs for a new policy, and after a
// promotion or an abort the one left behind.
func perVMPreviousPolicy(svc *corev1.Service, policy string, anchors []corev1.ConfigMap) (string, error) {
	if state, err := publicNodeLocalTransition(svc); err == nil &&
		state.Phase == publicNodeLocalPhaseUnion && state.ActivePolicy != "" && state.ActivePolicy != policy {
		return state.ActivePolicy, nil
	}
	if svc.Annotations[annotationPublicNodeLocalPromotedAt] == "" {
		return "", nil
	}
	stale := map[string]struct{}{}
	for index := range anchors {
		for _, key := range (vmFirewallAnchorView{cm: &anchors[index]}).memberKeys(string(svc.UID)) {
			if key.Policy != policy {
				stale[key.Policy] = struct{}{}
			}
		}
	}
	switch len(stale) {
	case 0:
		return "", nil
	case 1:
		for p := range stale {
			return p, nil
		}
	}
	return "", fmt.Errorf("public-node-local: Service %s/%s has entries of %d old policies on its VM firewalls", svc.Namespace, svc.Name, len(stale))
}

func (e perVMEdge) read(ctx context.Context, svc *corev1.Service, policy string) (edgeID, edgeID, error) {
	c := e.c
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	current, err := c.perVMEdgeID(string(svc.UID), policy, items, anchors)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	previousPolicy, err := perVMPreviousPolicy(svc, policy, anchors)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	if previousPolicy == "" {
		return current, edgeID{}, nil
	}
	previous, err := c.perVMEdgeID(string(svc.UID), previousPolicy, items, anchors)
	if err != nil {
		return edgeID{}, edgeID{}, err
	}
	return current, previous, nil
}

// ensureMode records that the Service lives on the per-VM firewall. It is the
// first write of a fresh Service, so every later pass picks this edge again.
func (e perVMEdge) ensureMode(ctx context.Context, svc *corev1.Service) (*corev1.Service, error) {
	if publicNodeLocalServicePerVM(svc) {
		return svc, nil
	}
	updated, _, err := e.c.updateExactParentService(ctx, svc, func(copy *corev1.Service) (bool, error) {
		if !publicNodeLocalUsesPerVMEdge(copy) {
			return false, errors.New("public-node-local: the Service gained per-Service firewall state before it joined the per-VM firewall mode")
		}
		if copy.Annotations == nil {
			copy.Annotations = map[string]string{}
		}
		copy.Annotations[annotationPublicNodeLocalFirewallMode] = publicNodeLocalEdgePerVM
		return true, nil
	})
	if err != nil {
		return svc, err
	}
	return updated, nil
}

func (e perVMEdge) Prepare(ctx context.Context, svc *corev1.Service, desired desiredNodeLoadBalancerFirewall) (*corev1.Service, edgeID, edgeID, bool, error) {
	svc, err := e.ensureMode(ctx, svc)
	if err != nil {
		return svc, edgeID{}, edgeID{}, false, err
	}
	current, previous, err := e.read(ctx, svc, desired.Hash)
	return svc, current, previous, false, err
}

func (e perVMEdge) Active(ctx context.Context, svc *corev1.Service, activePolicy string) (edgeID, edgeID, error) {
	return e.read(ctx, svc, activePolicy)
}

func (e perVMEdge) Assigned(_ context.Context, _ *corev1.Service, id edgeID) (map[string]struct{}, error) {
	if !id.perVM {
		return nil, errors.New("public-node-local: not a per-VM edge")
	}
	out := make(map[string]struct{}, len(id.open))
	for vmUUID := range id.open {
		out[vmUUID] = struct{}{}
	}
	return out, nil
}

func (e perVMEdge) ResolvePending(ctx context.Context, svc *corev1.Service) (bool, error) {
	c := e.c
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, err
	}
	resolved := true
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		if len(view.memberKeys(string(svc.UID))) == 0 {
			continue
		}
		members := c.vmFirewallMemberLookup(view.vm(), svc)
		switch {
		case view.hasReceipt():
			items, listErr := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
			if listErr != nil {
				return false, listErr
			}
			resolved = false
			if _, err := c.resolveVMFirewallReceipt(ctx, &anchors[index], items, members); err != nil {
				return false, err
			}
		case anchors[index].Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "":
			resolved = false
			if _, err := c.reconcileNodeLoadBalancerFirewallRelation(ctx, c.vmFirewallRelationOwner(view.vm(), members), nil); err != nil {
				return false, err
			}
		}
	}
	return resolved, nil
}

// waitForUnmigratedVM holds an add on a VM that still carries the per-Service
// firewall of a Service, or whose anchor has a migration in flight: the VM
// moves to the per-VM firewall first, never half and half.
func (e perVMEdge) waitForUnmigratedVM(ctx context.Context, svc *corev1.Service, vmUUID string, items []inspace.Firewall) error {
	c := e.c
	reason := ""
	for index := range items {
		firewall := items[index]
		if !vmFirewallAttachedTo(firewall, vmUUID) {
			continue
		}
		if inspace.ValidateNodeLoadBalancerServiceFirewall(firewall, c.provider.config.ClusterID, c.provider.config.BillingAccountID) == nil {
			reason = fmt.Sprintf("VM %s still carries the per-Service firewall %s", vmUUID, firewall.UUID)
			break
		}
	}
	if reason == "" {
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if anchor != nil && anchor.Annotations[annotationVMFirewallMigration] != "" {
			reason = fmt.Sprintf("VM %s has a firewall migration in flight", vmUUID)
		}
	}
	if reason == "" {
		return nil
	}
	cause := vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: %s; the add waits for the VM to move to the per-VM firewall", reason)
	c.recordPublicNodeLocalEvent(ctx, svc, publicNodeLocalReasonVMFirewallMigrationWaiting, cause)
	return cause
}

// authorizeAdd is the pre-dispatch authority of an add: the Service, live and
// exact, still wants this VM under this policy, with the same fence the
// per-Service backend uses.
func (e perVMEdge) authorizeAdd(
	svc *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	id edgeID,
	addresses []nodeLoadBalancerAddress,
	vmUUID string,
) vmFirewallDeltaAuthority {
	c := e.c
	return func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		current, err := c.getExactParentService(ctx, svc)
		if err != nil {
			return err
		}
		liveDesired, err := c.desiredServiceFirewall(current)
		if err != nil {
			return err
		}
		if liveDesired.Hash != desired.Hash {
			return errors.New("public-node-local: the live Service policy changed before the VM firewall entry was added")
		}
		if current.Annotations[annotationPublicNodeLocalActivePool] != "" {
			return c.validateActivePublicNodeLocalAssignState(ctx, current, intent, desired, id, vmUUID)
		}
		return c.validatePublicNodeLocalAssignmentState(ctx, current, intent, desired, id, addresses, true, false)
	}
}

func (e perVMEdge) Assign(
	ctx context.Context,
	svc *corev1.Service,
	intent nodeLoadBalancerIntent,
	desired desiredNodeLoadBalancerFirewall,
	id edgeID,
	addresses []nodeLoadBalancerAddress,
) (bool, error) {
	c := e.c
	member, err := vmFirewallMemberFromDesired(string(svc.UID), desired)
	if err != nil {
		return false, err
	}
	if member.Policy != desired.Hash {
		return false, errors.New("public-node-local: the VM firewall entry does not hash to the Service policy")
	}
	ordered := append([]nodeLoadBalancerAddress(nil), addresses...)
	vmOf := func(address nodeLoadBalancerAddress) string {
		vmUUID, _ := nodeLoadBalancerVMUUID(address.Node)
		return vmUUID
	}
	sort.Slice(ordered, func(i, j int) bool { return vmOf(ordered[i]) < vmOf(ordered[j]) })
	for _, address := range ordered {
		vmUUID := vmOf(address)
		if vmUUID == "" {
			return false, fmt.Errorf("public-node-local: Node %s has no VM identity", address.Node.Name)
		}
		items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
		if err != nil {
			return false, err
		}
		if err := e.waitForUnmigratedVM(ctx, svc, vmUUID, items); err != nil {
			return false, err
		}
		result, err := c.vmFirewallStep(ctx, vmUUID, vmFirewallDelta{Add: &member},
			e.authorizeAdd(svc, intent, desired, id, addresses, vmUUID), c.vmFirewallMemberLookup(vmUUID, svc))
		if errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
			c.recordPublicNodeLocalStuckRelation(ctx, svc, err)
			continue
		}
		if err != nil {
			return false, fmt.Errorf("public-node-local: open VM %s on its firewall: %w", vmUUID, err)
		}
		if !result.Converged {
			return false, nil
		}
	}
	return true, nil
}

// vmFirewallSettleGate holds a step that relies on the per-VM firewall of these
// VMs until every one has been read back for the settle delay. A stamp that
// cannot be read never counts as settled: it is announced on every member.
func (c *nodeLoadBalancerController) vmFirewallSettleGate(ctx context.Context, svc *corev1.Service, vmUUIDs []string) error {
	ordered := append([]string(nil), vmUUIDs...)
	sort.Strings(ordered)
	settle := c.provider.vmFirewallSettle()
	now := c.nodeLoadBalancerFirewallRelationTime()
	var wait *errPublicNodeLocalVMFirewallSettling
	for _, vmUUID := range ordered {
		anchor, err := c.getVMFirewallAnchor(ctx, vmUUID)
		if err != nil {
			return err
		}
		if anchor == nil {
			return fmt.Errorf("public-node-local: VM %s has no firewall anchor to settle", vmUUID)
		}
		view := vmFirewallAnchorView{cm: anchor}
		if _, err := view.settledFrom(); err != nil {
			bad := annotationVMFirewallAppliedAt
			if _, _, attachedErr := view.attachedAt(); attachedErr != nil {
				bad = annotationVMFirewallAttachedAt
			}
			cause := fmt.Errorf("anchor %s annotation %s cannot be read, so the VM firewall can never settle: %w", anchor.Name, bad, err)
			c.recordVMFirewallEvent(ctx, c.vmFirewallMemberLookup(vmUUID, svc)(ctx), vmFirewallDriftReason, cause)
			return cause
		}
		if remaining := vmFirewallSettleRemaining(anchor, settle, now); remaining > 0 && wait == nil {
			wait = &errPublicNodeLocalVMFirewallSettling{vmUUID: vmUUID, retryAfter: remaining}
		}
	}
	if wait != nil {
		return wait
	}
	return nil
}

// vmFirewallRemovalReason names why an entry may leave a VM.
type vmFirewallRemovalReason int

const (
	vmRemovalNotAllowed vmFirewallRemovalReason = iota
	vmRemovalNotServing
	vmRemovalWithdrawing
	vmRemovalNodeLeaving
	vmRemovalSuperseded
)

// publicNodeLocalVMLeaving says whether a VM is no longer a place the Service
// serves from, on a fresh classification: it is not a Ready endpoint, not an
// unverified Node (which stays where it is) and its FIP is not in the status.
func (c *nodeLoadBalancerController) publicNodeLocalVMLeaving(ctx context.Context, current *corev1.Service, vmUUID string) (bool, error) {
	nodes, patched, err := c.classifyPublicNodeLocalNodesInTransition(ctx, current)
	if err != nil {
		return false, err
	}
	if patched {
		return false, errors.New("public-node-local Node authority changed and requires a fresh reconciliation")
	}
	fips := publicNodeLocalIngressSet(current.Status.LoadBalancer)
	for _, address := range nodes.Ready {
		if id, ok := nodeLoadBalancerVMUUID(address.Node); ok && id == vmUUID {
			return false, nil
		}
	}
	for name, node := range nodes.Nodes {
		id, ok := nodeLoadBalancerVMUUID(node)
		if !ok || id != vmUUID {
			continue
		}
		if _, unverified := nodes.Unverified[name]; unverified {
			return false, nil
		}
		if public, hasPublic := nodeLoadBalancerNodeExternalIPv4(node); hasPublic {
			if _, published := fips[public]; published {
				return false, nil
			}
		}
	}
	return true, nil
}

// authorizeRemoval is the pre-dispatch authority of taking one entry off a VM
// (spec section 6.4). The entry leaves only on verified intent: the Service is
// being withdrawn or does not serve at all, the VM is verifiably not served
// from any more (its FIP is already out of the status), or the entry is of an
// old policy and the active one is open on the VM.
func (e perVMEdge) authorizeRemoval(svc *corev1.Service, vmUUID string, key vmFirewallMemberKey) vmFirewallDeltaAuthority {
	c := e.c
	return func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		current, err := c.getExactParentService(ctx, svc)
		if err != nil {
			return err
		}
		reason, err := e.removalReason(ctx, current, vmUUID, key)
		if err != nil {
			return err
		}
		if reason == vmRemovalNotAllowed {
			return fmt.Errorf("public-node-local: no verified intent removes policy %s of Service %s/%s from VM %s", key.Policy, current.Namespace, current.Name, vmUUID)
		}
		return nil
	}
}

func (e perVMEdge) removalReason(ctx context.Context, current *corev1.Service, vmUUID string, key vmFirewallMemberKey) (vmFirewallRemovalReason, error) {
	c := e.c
	if current.DeletionTimestamp != nil || !publicNodeLocalRequested(current) ||
		current.Annotations[annotationNodeLoadBalancerRebuilding] != "" {
		return vmRemovalWithdrawing, nil
	}
	if current.Annotations[annotationPublicNodeLocalActivePool] == "" && len(current.Status.LoadBalancer.Ingress) == 0 {
		return vmRemovalNotServing, nil
	}
	activePolicy := current.Annotations[annotationPublicNodeLocalActivePolicy]
	targetPolicy := current.Annotations[annotationPublicNodeLocalTargetPolicy]
	if key.Policy != activePolicy && key.Policy != targetPolicy && activePolicy != "" {
		items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
		if err != nil {
			return vmRemovalNotAllowed, err
		}
		anchors, err := c.listVMFirewallAnchors(ctx)
		if err != nil {
			return vmRemovalNotAllowed, err
		}
		// The removal being authorized holds the receipt of its own VM, so that
		// anchor is read without it: it is the active policy that must be open.
		for index := range anchors {
			if (vmFirewallAnchorView{cm: &anchors[index]}).vm() == vmUUID {
				anchors[index] = *stripVMFirewallReceipt(&anchors[index])
			}
		}
		open, err := c.vmEdgeAssigned(string(current.UID), activePolicy, items, anchors)
		if err != nil && !errors.Is(err, errVMFirewallReceiptPending) {
			return vmRemovalNotAllowed, err
		}
		if _, active := open[vmUUID]; active {
			return vmRemovalSuperseded, nil
		}
	}
	leaving, err := c.publicNodeLocalVMLeaving(ctx, current, vmUUID)
	if err != nil {
		return vmRemovalNotAllowed, err
	}
	if leaving {
		return vmRemovalNodeLeaving, nil
	}
	return vmRemovalNotAllowed, nil
}

// stripVMFirewallReceipt returns a copy of the anchor without its PUT receipt.
func stripVMFirewallReceipt(anchor *corev1.ConfigMap) *corev1.ConfigMap {
	clean := anchor.DeepCopy()
	for _, key := range vmFirewallReceiptKeys {
		delete(clean.Annotations, key)
	}
	return clean
}

// removalTarget is one entry to take off one VM.
type vmFirewallRemovalTarget struct {
	vmUUID string
	key    vmFirewallMemberKey
}

// removalTargets lists the entries of the Service the anchors hold for policy,
// on VMs outside keep. A Service that does not serve also gives up the entries
// of every other policy: nothing it exposed is left to protect.
func (e perVMEdge) removalTargets(ctx context.Context, svc *corev1.Service, policy string, keep map[string]struct{}, everyPolicy bool) ([]vmFirewallRemovalTarget, error) {
	anchors, err := e.c.listVMFirewallAnchors(ctx)
	if err != nil {
		return nil, err
	}
	var targets []vmFirewallRemovalTarget
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		_, kept := keep[view.vm()]
		for _, key := range view.memberKeys(string(svc.UID)) {
			if (key.Policy == policy && !kept) || (everyPolicy && (key.Policy != policy || !kept)) {
				targets = append(targets, vmFirewallRemovalTarget{vmUUID: view.vm(), key: key})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].vmUUID != targets[j].vmUUID {
			return targets[i].vmUUID < targets[j].vmUUID
		}
		return targets[i].key.Policy < targets[j].key.Policy
	})
	return targets, nil
}

// removeOne takes one entry off one VM through the shared transaction.
func (e perVMEdge) removeOne(ctx context.Context, svc *corev1.Service, target vmFirewallRemovalTarget, authorize vmFirewallDeltaAuthority) (parked []string, err error) {
	c := e.c
	key := target.key
	_, err = c.vmFirewallStep(ctx, target.vmUUID, vmFirewallDelta{Remove: &key}, authorize, c.vmFirewallMemberLookup(target.vmUUID, svc))
	if errors.Is(err, errNodeLoadBalancerFirewallRelationParked) {
		c.recordPublicNodeLocalStuckRelation(ctx, svc, err)
		return []string{target.vmUUID}, nil
	}
	return nil, err
}

func (e perVMEdge) Unassign(ctx context.Context, svc *corev1.Service, id edgeID, keep []*corev1.Node) ([]string, error) {
	keepVMs := map[string]struct{}{}
	for _, node := range keep {
		if vmUUID, ok := nodeLoadBalancerVMUUID(node); ok {
			keepVMs[vmUUID] = struct{}{}
		}
	}
	current, err := e.c.getExactParentService(ctx, svc)
	if err != nil {
		return nil, err
	}
	notServing := current.Annotations[annotationPublicNodeLocalActivePool] == "" && len(current.Status.LoadBalancer.Ingress) == 0
	targets, err := e.removalTargets(ctx, current, id.policy, keepVMs, notServing)
	if err != nil || len(targets) == 0 {
		return nil, err
	}
	target := targets[0]
	if target.key.Policy != current.Annotations[annotationPublicNodeLocalActivePolicy] &&
		target.key.Policy != current.Annotations[annotationPublicNodeLocalTargetPolicy] && !notServing {
		// An old policy leaves only after the change that widened or replaced it
		// has settled everywhere it matters.
		if err := e.c.vmFirewallSettleGate(ctx, current, []string{target.vmUUID}); err != nil {
			return nil, err
		}
	}
	return e.removeOne(ctx, current, target, e.authorizeRemoval(current, target.vmUUID, target.key))
}

func (e perVMEdge) Retire(ctx context.Context, svc *corev1.Service, id edgeID) (bool, error) {
	c := e.c
	if id.policy != "" {
		targets, err := e.removalTargets(ctx, svc, id.policy, nil, false)
		if err != nil {
			return false, err
		}
		if len(targets) != 0 {
			target := targets[0]
			if err := c.vmFirewallSettleGate(ctx, svc, []string{target.vmUUID}); err != nil {
				return false, err
			}
			_, err := e.removeOne(ctx, svc, target, e.authorizeRemoval(svc, target.vmUUID, target.key))
			return false, err
		}
	}
	_, _, err := c.updateExactParentService(ctx, svc, func(copy *corev1.Service) (bool, error) {
		if copy.Annotations[annotationPublicNodeLocalPromotedAt] == "" {
			return false, nil
		}
		delete(copy.Annotations, annotationPublicNodeLocalPromotedAt)
		return true, nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// vmFirewallServiceClosed says whether the Service is closed on every VM: no
// anchor lists it, or the only anchors that do are being deleted and the
// firewall of each is already detached from its VM.
func (c *nodeLoadBalancerController) vmFirewallServiceClosed(ctx context.Context, serviceUID string) (bool, []vmFirewallRemovalTarget, error) {
	items, err := c.provider.api.ListFirewalls(ctx, c.provider.config.Location)
	if err != nil {
		return false, nil, err
	}
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, nil, err
	}
	var open []vmFirewallRemovalTarget
	for index := range anchors {
		view := vmFirewallAnchorView{cm: &anchors[index]}
		keys := view.memberKeys(serviceUID)
		if len(keys) == 0 {
			continue
		}
		if view.pendingOp() == string(vmFirewallOpDelete) {
			firewall, listErr := exactNodeLoadBalancerFirewallFromItems(items, view.uuid())
			if listErr != nil || !vmFirewallAttachedTo(*firewall, view.vm()) {
				// Gone, or detached: the VM no longer carries the Service's ports.
				continue
			}
		}
		for _, key := range keys {
			open = append(open, vmFirewallRemovalTarget{vmUUID: view.vm(), key: key})
		}
	}
	sort.Slice(open, func(i, j int) bool {
		if open[i].vmUUID != open[j].vmUUID {
			return open[i].vmUUID < open[j].vmUUID
		}
		return open[i].key.Policy < open[j].key.Policy
	})
	return len(open) == 0, open, nil
}

func (e perVMEdge) WithdrawAll(ctx context.Context, svc *corev1.Service) (bool, error) {
	c := e.c
	closed, open, err := c.vmFirewallServiceClosed(ctx, string(svc.UID))
	if err != nil {
		return false, err
	}
	if closed {
		return true, nil
	}
	target := open[0]
	anchor, err := c.getVMFirewallAnchor(ctx, target.vmUUID)
	if err != nil {
		return false, err
	}
	if anchor != nil && (vmFirewallAnchorView{cm: anchor}).hasReceipt() {
		// A receipt on the VM, ours or a sibling's, is resolved before the next
		// delta; the step does exactly that.
		_, err := c.vmFirewallStep(ctx, target.vmUUID, vmFirewallDelta{Remove: &target.key},
			e.authorizeWithdraw(svc), c.vmFirewallMemberLookup(target.vmUUID, svc))
		return false, err
	}
	_, err = e.removeOne(ctx, svc, target, e.authorizeWithdraw(svc))
	return false, err
}

// authorizeWithdraw is the authority of a withdrawal: the caller reached it on
// verified intent, and the Service object is still the one asked about.
func (e perVMEdge) authorizeWithdraw(svc *corev1.Service) vmFirewallDeltaAuthority {
	return func(ctx context.Context, _ *corev1.ConfigMap, _ *inspace.Firewall) error {
		current, err := e.c.getExactParentService(ctx, svc)
		if err != nil {
			return err
		}
		if current.UID != svc.UID {
			return errors.New("public-node-local: the Service identity changed before its VM firewall entries were withdrawn")
		}
		return nil
	}
}

// vmFirewallLedgersList reports whether any anchor still lists the Service.
func (c *nodeLoadBalancerController) vmFirewallLedgersList(ctx context.Context, serviceUID string) (bool, error) {
	anchors, err := c.listVMFirewallAnchors(ctx)
	if err != nil {
		return false, err
	}
	for index := range anchors {
		if len((vmFirewallAnchorView{cm: &anchors[index]}).memberKeys(serviceUID)) != 0 {
			return true, nil
		}
	}
	return false, nil
}

// vmFirewallSettleVMs is the VMs of the addresses.
func vmFirewallSettleVMs(addresses []nodeLoadBalancerAddress) []string {
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if vmUUID, ok := nodeLoadBalancerVMUUID(address.Node); ok {
			out = append(out, vmUUID)
		}
	}
	sort.Strings(out)
	return out
}

// publicNodeLocalPerVMHeldError is the hold of a Service that lives on the
// per-VM firewall while the controller runs the per-Service mode.
func publicNodeLocalPerVMHeldError(svc *corev1.Service) error {
	return &publicNodeLocalPerVMStatePresentError{service: svc.Namespace + "/" + svc.Name}
}
