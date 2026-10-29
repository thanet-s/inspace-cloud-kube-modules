package cloudprovider

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// validateVMFirewallReversePlan checks the record of a reverse migration. Its
// sources are the ledger members, sorted by Service UID; a source's firewall is
// the UUID of the Service's own firewall, or empty when it is yet to be created.
func validateVMFirewallReversePlan(p vmFirewallMigrationPlan) error {
	switch p.Phase {
	case vmFirewallMigrationPhasePlanned, vmFirewallMigrationPhaseOpened, vmFirewallMigrationPhaseDetaching:
	default:
		return fmt.Errorf("unknown reverse migration phase %q", p.Phase)
	}
	if p.Strategy != vmFirewallMigrationStrategyHeadroom && p.Strategy != vmFirewallMigrationStrategyAdopt {
		return fmt.Errorf("unknown migration strategy %q", p.Strategy)
	}
	if len(p.Sources) == 0 {
		return errors.New("a reverse migration needs at least one member Service")
	}
	for index, source := range p.Sources {
		if source.Firewall != "" && !validNodeLoadBalancerCloudUUID(source.Firewall) ||
			validateNodeLoadBalancerServiceUID(source.UID) != nil || !vmFirewallPolicyPattern.MatchString(source.Policy) {
			return fmt.Errorf("reverse migration member %d is malformed", index)
		}
		if index > 0 && p.Sources[index-1].UID >= source.UID {
			return errors.New("reverse migration members are not unique and sorted by Service UID")
		}
	}
	if p.Strategy == vmFirewallMigrationStrategyAdopt {
		if _, found := p.sourceOfService(p.Adoptee); !found {
			return errors.New("a reverse adopt needs its adoptee among the members")
		}
	} else if p.Adoptee != "" {
		return errors.New("only a reverse adopt has an adoptee")
	}
	if p.DoneAt != "" {
		return errors.New("a reverse migration ends with its anchor and has no done time")
	}
	if p.OpenedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, p.OpenedAt); err != nil {
			return fmt.Errorf("reverse migration openedAt: %w", err)
		}
	}
	if p.Phase == vmFirewallMigrationPhasePlanned && p.OpenedAt != "" {
		return errors.New("a planned reverse migration is not opened yet")
	}
	if p.Phase != vmFirewallMigrationPhasePlanned && p.OpenedAt == "" {
		return errors.New("an opened reverse migration needs its opened time")
	}
	return nil
}

// vmFirewallReverseServiceWaiting names why a member Service is not steady
// enough to move back to its own firewall, or returns "" when it is. The
// firewall create keys are not part of it: the reverse writes them itself.
func vmFirewallReverseServiceWaiting(svc *corev1.Service, allowReceipt bool) string {
	switch {
	case svc.DeletionTimestamp != nil:
		return "is being deleted; it finishes once the per-VM mode is on again, or the reverse migration waits for it to be gone"
	case !publicNodeLocalRequested(svc):
		return "is not a public-node-local Service"
	case svc.Annotations[annotationPublicNodeLocalActivePool] == "" || svc.Annotations[annotationPublicNodeLocalActivePolicy] == "":
		return "is not serving yet"
	case svc.Annotations[annotationPublicNodeLocalTargetPool] != "" || svc.Annotations[annotationPublicNodeLocalTargetPolicy] != "":
		return "has a pool or policy change in flight; turn the per-VM mode on to finish it, or revert the change"
	case svc.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" || svc.Annotations[annotationPublicNodeLocalPromotedAt] != "":
		return "is still retiring a previous firewall or policy"
	case publicNodeLocalAssignmentFencePresent(svc):
		return "has an assignment fence"
	case !allowReceipt && (svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		svc.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != ""):
		return "has an unresolved firewall relation receipt"
	case svc.Annotations[annotationNodeLoadBalancerRebuilding] != "" || svc.Annotations[annotationNodeLoadBalancerRebuildingAssigned] != "":
		return "is rebuilding"
	}
	return ""
}

// vmFirewallReverseCreateInFlight says a member has a firewall create, delete or
// withdraw receipt open. The reverse's own create leaves the create keys open for
// a while; the planner only starts when none is.
func vmFirewallReverseCreateInFlight(svc *corev1.Service) bool {
	for _, key := range []string{
		annotationNodeLoadBalancerPendingFirewall, annotationNodeLoadBalancerPendingFWName, annotationNodeLoadBalancerPendingFWStarted,
		annotationNodeLoadBalancerPendingFWIssued, annotationNodeLoadBalancerPendingFWIssuedAt, annotationNodeLoadBalancerPendingFWDelete,
		annotationNodeLoadBalancerFWDeleteTarget, annotationNodeLoadBalancerFWDeleteIssued,
		annotationNodeLoadBalancerWithdrawFWAbsent, annotationNodeLoadBalancerWithdrawFWChecked,
		annotationNodeLoadBalancerWithdrawFWMissing, annotationNodeLoadBalancerWithdrawFWDetach, annotationNodeLoadBalancerWithdrawFWDetachAt,
	} {
		if svc.Annotations[key] != "" {
			return true
		}
	}
	return false
}

// planVMFirewallReverse is the read-only plan that moves the Services of one
// per-VM firewall back onto per-Service firewalls (spec section 7.4). k is the
// number of member Services on the VM.
//
//   - A VM with k >= limit can not exist in per-Service mode (base plus k firewalls);
//     it is blocked.
//   - Strategy A attaches each member's own firewall (created when missing),
//     settles, and then retires the per-VM firewall. It needs a free slot for
//     every member whose firewall is not already on the VM.
//   - Strategy B is the reverse adopt: one PUT renames the per-VM firewall into
//     the own firewall of one member, so one member needs no slot. It is chosen
//     when a member's firewall is the per-VM firewall itself (a forward adopt that
//     did not finish), when the only member runs on this VM alone, and when
//     members are one more than the free slots. It needs the rename.
//
// It returns *errVMFirewallMigrationDeferred when a member is not ready,
// *errVMFirewallMigrationBlocked when only an operator can help, and any other
// error for state it does not recognize, which holds the VM.
func planVMFirewallReverse(
	vmUUID string,
	anchor *corev1.ConfigMap,
	items []inspace.Firewall,
	services []corev1.Service,
	cluster string,
	billing int64,
	limit int,
) (vmFirewallMigrationPlan, error) {
	plan := vmFirewallMigrationPlan{Direction: vmFirewallMigrationDirectionReverse, Phase: vmFirewallMigrationPhasePlanned}
	view := vmFirewallAnchorView{cm: anchor}
	if view.hasReceipt() {
		return plan, vmFirewallWait(nodeLoadBalancerRetry, "public-node-local: the VM firewall of %s has an unresolved receipt", vmUUID)
	}
	applied, err := view.applied()
	if err != nil {
		return plan, err
	}
	if len(applied.Members) == 0 {
		return plan, nil
	}
	perVMUUID := view.uuid()
	perVM, err := exactNodeLoadBalancerFirewallFromItems(items, perVMUUID)
	if err != nil {
		return plan, vmFirewallDrift(vmUUID, "the per-VM firewall %q is not readable: %v", perVMUUID, err)
	}
	if err := inspace.ValidateNodeLoadBalancerVMFirewall(*perVM, cluster, vmUUID, billing, view.appliedHash()); err != nil {
		return plan, vmFirewallDrift(vmUUID, "firewall %s: %v", perVMUUID, err)
	}
	if !vmFirewallAttachedTo(*perVM, vmUUID) {
		return plan, vmFirewallDrift(vmUUID, "the per-VM firewall %s is not attached to the VM", perVMUUID)
	}
	k := len(applied.Members)
	if k >= limit {
		return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: fmt.Sprintf(
			"k exceeds per-Service capacity: %d Services share VM %s, and the per-Service mode fits at most %d beside the base firewall",
			k, vmUUID, limit-1)}
	}
	seenUID := map[string]struct{}{}
	for _, member := range applied.Members {
		if _, dup := seenUID[member.UID]; dup {
			return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: fmt.Sprintf(
				"Service %s has two policies on the per-VM firewall (a policy change in flight); turn the per-VM mode on to finish it", member.UID)}
		}
		seenUID[member.UID] = struct{}{}
	}

	type memberState struct {
		member    vmFirewallMember
		svc       *corev1.Service
		desired   desiredNodeLoadBalancerFirewall
		canonical *inspace.Firewall // the own firewall that exists, or nil
		isPerVM   bool              // the Service names the per-VM firewall itself as its own
		onVM      bool              // the own firewall is attached to this VM
		singleVM  bool
	}
	states := make([]memberState, 0, len(applied.Members))
	known := map[string]struct{}{perVMUUID: {}}
	for _, member := range applied.Members {
		var svc *corev1.Service
		for index := range services {
			if string(services[index].UID) == member.UID {
				svc = &services[index]
			}
		}
		if svc == nil {
			return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID, reason: fmt.Sprintf("waiting: Service %s is gone; its entry leaves with the ordinary upkeep", member.UID)}
		}
		if reason := vmFirewallReverseServiceWaiting(svc, false); reason != "" {
			return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID, reason: fmt.Sprintf("waiting: Service %s/%s %s", svc.Namespace, svc.Name, reason)}
		}
		if vmFirewallReverseCreateInFlight(svc) {
			return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID, reason: fmt.Sprintf("waiting: Service %s/%s has a firewall create, delete or withdraw in flight", svc.Namespace, svc.Name)}
		}
		desired, err := desiredServiceFirewallFor(cluster, billing, svc)
		if err != nil {
			return plan, fmt.Errorf("public-node-local: Service %s/%s: %w", svc.Namespace, svc.Name, err)
		}
		if desired.Hash != member.Policy || svc.Annotations[annotationPublicNodeLocalActivePolicy] != member.Policy {
			return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID, reason: fmt.Sprintf(
				"waiting: Service %s/%s wants policy %s, but the per-VM firewall serves %s; revert the change or turn the per-VM mode on",
				svc.Namespace, svc.Name, desired.Hash, member.Policy)}
		}
		state := memberState{member: member, svc: svc, desired: desired, singleVM: len(publicNodeLocalIngressSet(svc.Status.LoadBalancer)) <= 1}
		own := svc.Annotations[annotationNodeLoadBalancerFirewallUUID]
		switch {
		case own == "":
			if !publicNodeLocalServicePerVM(svc) {
				return plan, fmt.Errorf("public-node-local: Service %s/%s is on the per-VM firewall but is marked neither per-VM nor per-Service", svc.Namespace, svc.Name)
			}
		case strings.EqualFold(own, perVMUUID):
			state.isPerVM = true
		default:
			firewall, err := exactNodeLoadBalancerFirewallFromItems(items, own)
			if err != nil {
				return plan, fmt.Errorf("public-node-local: Service %s/%s names firewall %s: %w", svc.Namespace, svc.Name, own, err)
			}
			if !nodeLoadBalancerFirewallMatches(*firewall, desired) ||
				!nodeLoadBalancerFirewallOwnedByService(*firewall, cluster, member.UID, billing) {
				return plan, fmt.Errorf("public-node-local: firewall %s of Service %s/%s is not the exact firewall of its policy", own, svc.Namespace, svc.Name)
			}
			state.canonical = firewall
		}
		if state.canonical == nil && !state.isPerVM {
			byName, err := vmFirewallByNameFromItems(items, desired.Request.DisplayName)
			if err != nil {
				return plan, err
			}
			if byName != nil {
				if !nodeLoadBalancerFirewallMatches(*byName, desired) || !nodeLoadBalancerFirewallOwnedByService(*byName, cluster, member.UID, billing) {
					return plan, fmt.Errorf("public-node-local: firewall name %q is occupied by a foreign or changed resource", desired.Request.DisplayName)
				}
				state.canonical = byName
			}
		}
		if state.canonical != nil {
			known[state.canonical.UUID] = struct{}{}
			state.onVM = vmFirewallAttachedTo(*state.canonical, vmUUID)
		}
		states = append(states, state)
	}

	// What else is on the VM: exactly the base firewall.
	attached := vmFirewallsAttachedTo(items, vmUUID)
	unknown := 0
	for _, firewall := range attached {
		if _, ok := known[firewall.UUID]; !ok {
			unknown++
		}
	}
	if unknown != 1 {
		return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: fmt.Sprintf(
			"VM %s carries %d firewalls other than the per-VM firewall and its Services' own; the reverse expects only the base firewall", vmUUID, unknown)}
	}
	headroom := limit - len(attached)

	var needAttach []int // members that need a slot
	for index, state := range states {
		if !state.isPerVM && !state.onVM {
			needAttach = append(needAttach, index)
		}
	}
	adopteeIndex := -1
	for index, state := range states {
		if state.isPerVM {
			adopteeIndex = index
		}
	}
	renameOK := vmFirewallRenameSupportedForTest
	candidate := func() int { // the last member by UID whose own firewall does not exist yet
		best := -1
		for _, index := range needAttach {
			if states[index].canonical == nil {
				best = index
			}
		}
		return best
	}
	switch {
	case adopteeIndex >= 0:
		// A forward adopt that did not finish left the per-VM firewall carrying
		// this Service's own identity: it goes back under its own name.
		if !renameOK {
			return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "rename unsupported"}
		}
		if len(needAttach) > headroom {
			return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "no free firewall slot for the members that are not on the VM yet"}
		}
	case len(needAttach) <= headroom:
		if len(states) == 1 && states[0].singleVM && states[0].canonical == nil && renameOK {
			adopteeIndex = 0
		}
	case len(needAttach) == headroom+1:
		if !renameOK {
			return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "rename unsupported"}
		}
		if adopteeIndex = candidate(); adopteeIndex < 0 {
			return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "every member's own firewall exists already, so none can take the per-VM firewall by rename"}
		}
	default:
		return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "no free firewall slot for the members that are not on the VM yet"}
	}

	plan.Strategy = vmFirewallMigrationStrategyHeadroom
	if adopteeIndex >= 0 {
		plan.Strategy = vmFirewallMigrationStrategyAdopt
		plan.Adoptee = states[adopteeIndex].member.UID
	}
	for _, state := range states {
		source := vmFirewallMigrationSource{UID: state.member.UID, Policy: state.member.Policy}
		if state.canonical != nil {
			source.Firewall = state.canonical.UUID
		}
		plan.Sources = append(plan.Sources, source)
	}
	sort.Slice(plan.Sources, func(i, j int) bool { return plan.Sources[i].UID < plan.Sources[j].UID })
	return plan, nil
}
