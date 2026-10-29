package cloudprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	// annotationPublicNodeLocalVMFirewallMigrate is read from a Node: "true"
	// migrates the VM in manual mode, "hold" pauses it in both modes.
	annotationPublicNodeLocalVMFirewallMigrate = "service.inspace.cloud/public-node-local-vm-firewall-migrate"

	vmFirewallMigrateValueTrue = "true"
	vmFirewallMigrateValueHold = "hold"

	publicNodeLocalReasonVMFirewallMigrationBlocked = "PublicNodeLocalVMFirewallMigrationBlocked"

	vmFirewallMigrationDirectionForward = "forward"
	vmFirewallMigrationDirectionReverse = "reverse"

	vmFirewallMigrationPhasePlanned   = "planned"
	vmFirewallMigrationPhaseOpened    = "opened"
	vmFirewallMigrationPhaseDetaching = "detaching"
	vmFirewallMigrationPhaseAborting  = "aborting"

	vmFirewallMigrationStrategyHeadroom = "A"
	vmFirewallMigrationStrategyAdopt    = "B"
)

// vmFirewallRenameSupportedForTest lets a test turn the rename off; production
// never changes it from vmFirewallRenameSupported.
var vmFirewallRenameSupportedForTest = vmFirewallRenameSupported

// vmFirewallMigrationSource is one per-Service firewall a migration retires.
type vmFirewallMigrationSource struct {
	Firewall string `json:"firewall"`
	UID      string `json:"uid"`
	Policy   string `json:"policy"`
}

// vmFirewallMigrationPlan is the plan and the progress record of one VM. The
// anchor stores it as JSON in the migration annotation; the audit reads the
// phase and the source firewalls from it.
//
// A forward plan moves the per-Service firewalls of the VM onto its per-VM
// firewall: Sources are those firewalls, sorted by firewall UUID, and Adoptee is
// the firewall UUID that is renamed (strategy B). A reverse plan moves the
// Services of the per-VM firewall back onto their own firewalls: Sources are
// the ledger members, sorted by Service UID, each with the UUID of its
// per-Service firewall when that exists at plan time and empty when it is yet
// to be created, and Adoptee is the Service UID whose firewall the per-VM
// firewall is renamed into (strategy B). Strategy A attaches every member's own
// firewall and then retires the per-VM firewall.
type vmFirewallMigrationPlan struct {
	Direction string                      `json:"direction"`
	Phase     string                      `json:"phase"`
	Strategy  string                      `json:"strategy"`
	Sources   []vmFirewallMigrationSource `json:"sources"`
	Adoptee   string                      `json:"adoptee,omitempty"`
	// DoneAt is when the phase became done; it paces the next VM.
	DoneAt string `json:"doneAt,omitempty"`
	// OpenedAt is when a reverse plan's last attach read back; its settle delay
	// counts from here.
	OpenedAt string `json:"openedAt,omitempty"`
}

// errVMFirewallMigrationDeferred says the VM can not be planned yet: a Service
// on it is not steady, or no firewall can be adopted. It is a wait.
type errVMFirewallMigrationDeferred struct{ vmUUID, reason string }

func (e *errVMFirewallMigrationDeferred) Error() string {
	return fmt.Sprintf("public-node-local: the migration of VM %s to the per-VM firewall waits: %s", e.vmUUID, e.reason)
}

// errVMFirewallMigrationBlocked says the VM can not migrate without an operator
// decision.
type errVMFirewallMigrationBlocked struct{ vmUUID, reason string }

func (e *errVMFirewallMigrationBlocked) Error() string {
	return fmt.Sprintf("public-node-local: the migration of VM %s to the per-VM firewall is blocked: %s", e.vmUUID, e.reason)
}

func (p vmFirewallMigrationPlan) source(firewall string) (vmFirewallMigrationSource, bool) {
	for _, source := range p.Sources {
		if strings.EqualFold(source.Firewall, firewall) {
			return source, true
		}
	}
	return vmFirewallMigrationSource{}, false
}

func (p vmFirewallMigrationPlan) sourceOfService(uid string) (vmFirewallMigrationSource, bool) {
	for _, source := range p.Sources {
		if source.UID == uid {
			return source, true
		}
	}
	return vmFirewallMigrationSource{}, false
}

func validateVMFirewallMigrationPlan(p vmFirewallMigrationPlan) error {
	if p.Direction == vmFirewallMigrationDirectionReverse {
		return validateVMFirewallReversePlan(p)
	}
	if p.Direction != vmFirewallMigrationDirectionForward {
		return fmt.Errorf("unsupported migration direction %q", p.Direction)
	}
	if p.OpenedAt != "" {
		return errors.New("only a reverse migration has an opened time")
	}
	switch p.Phase {
	case vmFirewallMigrationPhasePlanned, vmFirewallMigrationPhaseOpened, vmFirewallMigrationPhaseDetaching,
		vmFirewallMigrationPhaseDone, vmFirewallMigrationPhaseAborting:
	default:
		return fmt.Errorf("unknown migration phase %q", p.Phase)
	}
	if p.Strategy != vmFirewallMigrationStrategyHeadroom && p.Strategy != vmFirewallMigrationStrategyAdopt {
		return fmt.Errorf("unknown migration strategy %q", p.Strategy)
	}
	if len(p.Sources) == 0 {
		return errors.New("a migration needs at least one source firewall")
	}
	for index, source := range p.Sources {
		if !validNodeLoadBalancerCloudUUID(source.Firewall) || validateNodeLoadBalancerServiceUID(source.UID) != nil ||
			!vmFirewallPolicyPattern.MatchString(source.Policy) {
			return fmt.Errorf("migration source %d is malformed", index)
		}
		if index > 0 && p.Sources[index-1].Firewall >= source.Firewall {
			return errors.New("migration sources are not unique and sorted by firewall")
		}
	}
	if p.Strategy == vmFirewallMigrationStrategyAdopt {
		if _, found := p.source(p.Adoptee); !found {
			return errors.New("an adopt migration needs its adoptee among the sources")
		}
	} else if p.Adoptee != "" {
		return errors.New("only an adopt migration has an adoptee")
	}
	if p.DoneAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, p.DoneAt); err != nil {
			return fmt.Errorf("migration doneAt: %w", err)
		}
	}
	return nil
}

func encodeVMFirewallMigrationPlan(p vmFirewallMigrationPlan) (string, error) {
	if err := validateVMFirewallMigrationPlan(p); err != nil {
		return "", err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// decodeVMFirewallMigrationPlan reads the migration record strictly: unknown
// fields, trailing data or a non-canonical form are corruption.
func decodeVMFirewallMigrationPlan(raw string) (vmFirewallMigrationPlan, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan vmFirewallMigrationPlan
	if err := decoder.Decode(&plan); err != nil {
		return vmFirewallMigrationPlan{}, corruptVMFirewallLedger("migration record: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return vmFirewallMigrationPlan{}, corruptVMFirewallLedger("migration record: trailing data")
	}
	if err := validateVMFirewallMigrationPlan(plan); err != nil {
		return vmFirewallMigrationPlan{}, corruptVMFirewallLedger("migration record: %v", err)
	}
	encoded, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil || !bytes.Equal([]byte(encoded), []byte(raw)) {
		return vmFirewallMigrationPlan{}, corruptVMFirewallLedger("migration record is not in canonical form")
	}
	return plan, nil
}

// migration returns the migration record of the anchor; ok is false when it has
// none.
func (a vmFirewallAnchorView) migration() (plan vmFirewallMigrationPlan, ok bool, err error) {
	raw := a.get(annotationVMFirewallMigration)
	if raw == "" {
		return vmFirewallMigrationPlan{}, false, nil
	}
	plan, err = decodeVMFirewallMigrationPlan(raw)
	if err != nil {
		return vmFirewallMigrationPlan{}, false, err
	}
	return plan, true, nil
}

// vmFirewallMigrationInFlight says whether the anchor's migration record is a
// plan that is not done. An unreadable record counts as in flight: it holds.
func vmFirewallMigrationInFlight(anchor *corev1.ConfigMap) bool {
	if anchor == nil {
		return false
	}
	plan, ok, err := (vmFirewallAnchorView{cm: anchor}).migration()
	if err != nil {
		return true
	}
	return ok && plan.Phase != vmFirewallMigrationPhaseDone
}

// vmFirewallMigrationServiceWaiting names why a Service is not steady enough to
// migrate (spec section 7.1), or returns "" when it is.
func vmFirewallMigrationServiceWaiting(svc *corev1.Service) string {
	switch {
	case svc.DeletionTimestamp != nil:
		return "is being deleted"
	case !publicNodeLocalRequested(svc):
		return "is not a public-node-local Service"
	case publicNodeLocalServicePerVM(svc):
		return "already lives on the per-VM firewall"
	case svc.Annotations[annotationPublicNodeLocalActivePool] == "" || svc.Annotations[annotationPublicNodeLocalActivePolicy] == "":
		return "is not serving yet"
	case svc.Annotations[annotationPublicNodeLocalTargetPool] != "" || svc.Annotations[annotationPublicNodeLocalTargetPolicy] != "":
		return "has a pool or policy change in flight"
	case svc.Annotations[annotationNodeLoadBalancerPreviousFirewall] != "" || svc.Annotations[annotationPublicNodeLocalPromotedAt] != "":
		return "is still retiring a previous firewall"
	case publicNodeLocalAssignmentFencePresent(svc):
		return "has an assignment fence"
	case svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		svc.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "":
		return "has an unresolved firewall relation receipt"
	case svc.Annotations[annotationNodeLoadBalancerRebuilding] != "" || svc.Annotations[annotationNodeLoadBalancerRebuildingAssigned] != "":
		return "is rebuilding"
	}
	for _, key := range []string{
		annotationNodeLoadBalancerPendingFirewall, annotationNodeLoadBalancerPendingFWName, annotationNodeLoadBalancerPendingFWStarted,
		annotationNodeLoadBalancerPendingFWIssued, annotationNodeLoadBalancerPendingFWIssuedAt, annotationNodeLoadBalancerPendingFWDelete,
		annotationNodeLoadBalancerFWDeleteTarget, annotationNodeLoadBalancerFWDeleteIssued,
		annotationNodeLoadBalancerWithdrawFWAbsent, annotationNodeLoadBalancerWithdrawFWChecked,
		annotationNodeLoadBalancerWithdrawFWMissing, annotationNodeLoadBalancerWithdrawFWDetach, annotationNodeLoadBalancerWithdrawFWDetachAt,
	} {
		if svc.Annotations[key] != "" {
			return "has a firewall create, delete or withdraw in flight"
		}
	}
	return ""
}

// vmFirewallMemberFromFirewall builds the ledger entry of a source from the
// rules its per-Service firewall carries now. The entry must hash to the policy.
func vmFirewallMemberFromFirewall(uid, policy string, firewall inspace.Firewall) (vmFirewallMember, error) {
	member, err := vmFirewallMemberFromDesired(uid, desiredNodeLoadBalancerFirewall{
		Hash: policy, Request: inspace.CreateFirewallRequest{Rules: firewall.Rules},
	})
	if err != nil {
		return vmFirewallMember{}, err
	}
	return member, nil
}

// planVMFirewallMigration is M0: a pure, read-only plan for one VM. It returns a
// plan with no sources when the VM carries nothing but the base firewall. It
// returns *errVMFirewallMigrationDeferred when the VM is not ready to migrate,
// *errVMFirewallMigrationBlocked when it needs an operator, and any other error
// for state it does not recognize, which holds the VM.
func planVMFirewallMigration(
	vmUUID string,
	items []inspace.Firewall,
	services []corev1.Service,
	cluster string,
	billing int64,
	baseUUID string,
	limit int,
) (vmFirewallMigrationPlan, error) {
	plan := vmFirewallMigrationPlan{Direction: vmFirewallMigrationDirectionForward, Phase: vmFirewallMigrationPhasePlanned}
	baseAttached := 0
	var others []inspace.Firewall
	for index := range items {
		firewall := items[index]
		if !vmFirewallAttachedTo(firewall, vmUUID) {
			continue
		}
		if strings.EqualFold(firewall.UUID, baseUUID) {
			baseAttached++
			continue
		}
		others = append(others, firewall)
	}
	if baseAttached != 1 {
		return plan, fmt.Errorf("public-node-local: VM %s must carry the base firewall %s exactly once, not %d times", vmUUID, baseUUID, baseAttached)
	}
	if len(others) == 0 {
		return plan, nil
	}
	if count := 1 + len(others); count > limit {
		return plan, fmt.Errorf("public-node-local: VM %s carries %d firewalls, above the limit of %d", vmUUID, count, limit)
	}

	owners := map[string]*corev1.Service{}
	members := make([]vmFirewallMember, 0, len(others))
	sources := make([]vmFirewallMigrationSource, 0, len(others))
	seenServices := map[string]struct{}{}
	for _, firewall := range others {
		if _, isVMFirewall := inspace.ParseNodeLoadBalancerVMFirewallName(cluster, firewall.EffectiveName()); isVMFirewall {
			return plan, fmt.Errorf("public-node-local: VM %s already carries the per-VM firewall %s", vmUUID, firewall.UUID)
		}
		if err := inspace.ValidateNodeLoadBalancerServiceFirewall(firewall, cluster, billing); err != nil {
			return plan, fmt.Errorf("public-node-local: VM %s carries firewall %s that is not a Service firewall of this cluster: %w", vmUUID, firewall.UUID, err)
		}
		var owner *corev1.Service
		for index := range services {
			service := &services[index]
			if service.Annotations[annotationNodeLoadBalancerFirewallUUID] != firewall.UUID {
				continue
			}
			if owner != nil {
				return plan, fmt.Errorf("public-node-local: firewall %s is named by more than one Service", firewall.UUID)
			}
			owner = service
		}
		if owner == nil {
			return plan, fmt.Errorf("public-node-local: no Service names firewall %s on VM %s", firewall.UUID, vmUUID)
		}
		if !nodeLoadBalancerFirewallOwnedByService(firewall, cluster, string(owner.UID), billing) {
			return plan, fmt.Errorf("public-node-local: firewall %s is not owned by Service %s/%s", firewall.UUID, owner.Namespace, owner.Name)
		}
		if _, dup := seenServices[string(owner.UID)]; dup {
			return plan, fmt.Errorf("public-node-local: Service %s/%s has more than one firewall on VM %s", owner.Namespace, owner.Name, vmUUID)
		}
		seenServices[string(owner.UID)] = struct{}{}
		if reason := vmFirewallMigrationServiceWaiting(owner); reason != "" {
			return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID, reason: fmt.Sprintf("waiting: Service %s/%s %s", owner.Namespace, owner.Name, reason)}
		}
		policy := owner.Annotations[annotationPublicNodeLocalActivePolicy]
		hash, err := nodeLoadBalancerFirewallSpecHash(firewall.Rules)
		if err != nil || hash != policy || owner.Annotations[annotationNodeLoadBalancerFirewallHash] != policy {
			return plan, fmt.Errorf("public-node-local: firewall %s does not carry the active policy %s of Service %s/%s", firewall.UUID, policy, owner.Namespace, owner.Name)
		}
		member, err := vmFirewallMemberFromFirewall(string(owner.UID), policy, firewall)
		if err != nil {
			return plan, fmt.Errorf("public-node-local: firewall %s of Service %s/%s: %w", firewall.UUID, owner.Namespace, owner.Name, err)
		}
		owners[firewall.UUID] = owner
		members = append(members, member)
		sources = append(sources, vmFirewallMigrationSource{Firewall: firewall.UUID, UID: string(owner.UID), Policy: policy})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].UID < members[j].UID })
	if _, err := mergeVMFirewallLedger(vmFirewallLedger{V: vmFirewallLedgerVersion, Members: members}); err != nil {
		return plan, fmt.Errorf("public-node-local: the Services on VM %s can not share one firewall: %w", vmUUID, err)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Firewall < sources[j].Firewall })
	plan.Sources = sources

	if 1+len(others) < limit {
		plan.Strategy = vmFirewallMigrationStrategyHeadroom
		return plan, nil
	}
	plan.Strategy = vmFirewallMigrationStrategyAdopt
	if !vmFirewallRenameSupportedForTest {
		return plan, &errVMFirewallMigrationBlocked{vmUUID: vmUUID, reason: "rename unsupported"}
	}
	for _, firewall := range others {
		rows, err := nodeLoadBalancerFirewallAssignmentVMs(firewall)
		if err != nil {
			return plan, err
		}
		if len(rows) == 1 && strings.EqualFold(rows[0], vmUUID) && (plan.Adoptee == "" || firewall.UUID < plan.Adoptee) {
			plan.Adoptee = firewall.UUID
		}
	}
	if plan.Adoptee == "" {
		return plan, &errVMFirewallMigrationDeferred{vmUUID: vmUUID,
			reason: "no per-Service firewall of this full VM is attached to this VM alone; other VMs migrate first"}
	}
	return plan, nil
}
