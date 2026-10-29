package cloudprovider

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const reverseTestFirewall = "dddddddd-0000-4000-8000-000000000001"

// reverseWorld is a hand-built per-VM cluster for the reverse planner: Services
// that live on the per-VM firewall of vmTestVM.
type reverseWorld struct {
	t        *testing.T
	f        *vmFirewallFixture
	services []corev1.Service
	members  []vmFirewallMember
	nextUUID int
}

func newReverseWorld(t *testing.T) *reverseWorld {
	return &reverseWorld{t: t, f: newVMFirewallFixture(t)}
}

// service adds a per-VM Service that is serving on ingressCount VMs.
func (w *reverseWorld) service(name, uid string, ingressCount int, ports ...int32) *corev1.Service {
	w.t.Helper()
	svc := publicNodeLocalTestService(name, uid, "edge", corev1.ProtocolTCP, ports[0])
	svc.Spec.Ports = nil
	for _, port := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolTCP, Port: port})
	}
	desired, err := w.f.controller.desiredServiceFirewall(svc)
	if err != nil {
		w.t.Fatal(err)
	}
	svc.Annotations[annotationPublicNodeLocalActivePool] = "edge"
	svc.Annotations[annotationPublicNodeLocalActivePolicy] = desired.Hash
	svc.Annotations[annotationPublicNodeLocalFirewallMode] = publicNodeLocalEdgePerVM
	for index := 0; index < ingressCount; index++ {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: fmt.Sprintf("203.0.113.%d", 21+index)})
	}
	w.services = append(w.services, *svc)
	w.members = append(w.members, w.f.member(svc))
	return &w.services[len(w.services)-1]
}

// seed puts the per-VM firewall of the VM, with the ledger of every Service
// added so far, into the fake cloud.
func (w *reverseWorld) seed() *corev1.ConfigMap {
	w.t.Helper()
	return w.f.seedVMFirewall(vmTestVM, reverseTestFirewall, true, w.members...)
}

// own adds the own firewall of svc, attached to the given VMs, and records it on
// the Service.
func (w *reverseWorld) own(svc *corev1.Service, vms ...string) *inspace.Firewall {
	w.t.Helper()
	desired, err := w.f.controller.desiredServiceFirewall(svc)
	if err != nil {
		w.t.Fatal(err)
	}
	w.nextUUID++
	firewall := inspace.Firewall{
		UUID: fmt.Sprintf("eeeeeeee-0000-4000-8000-%012d", w.nextUUID), DisplayName: desired.Request.DisplayName,
		Description: desired.Request.Description, BillingAccountID: 42, Rules: desired.Request.Rules,
	}
	for _, vm := range vms {
		firewall.ResourcesAssigned = append(firewall.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm})
	}
	w.f.api.firewalls = append(w.f.api.firewalls, firewall)
	return &w.f.api.firewalls[len(w.f.api.firewalls)-1]
}

func (w *reverseWorld) plan(limit int) (vmFirewallMigrationPlan, error) {
	w.t.Helper()
	return planVMFirewallReverse(vmTestVM, w.f.anchor(vmTestVM), w.f.api.firewalls, w.services, w.f.provider.config.ClusterID, 42, limit)
}

func requireReverseBlocked(t *testing.T, err error, contains string) {
	t.Helper()
	var blocked *errVMFirewallMigrationBlocked
	if !errors.As(err, &blocked) || !strings.Contains(blocked.reason, contains) {
		t.Fatalf("err = %v, want a block that says %q", err, contains)
	}
}

func TestPlanVMFirewallReverseSingleServiceMultiVMAttachesItsOwnFirewall(t *testing.T) {
	w := newReverseWorld(t)
	traefik := w.service("traefik-public", "traefik-public-uid", 2, 80, 443)
	w.seed()
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Direction != "reverse" || plan.Phase != "planned" || plan.Strategy != vmFirewallMigrationStrategyHeadroom || plan.Adoptee != "" {
		t.Fatalf("plan = %#v, want reverse strategy A", plan)
	}
	if len(plan.Sources) != 1 || plan.Sources[0].UID != "traefik-public-uid" || plan.Sources[0].Firewall != "" {
		t.Fatalf("sources = %#v, want the Service with no firewall yet", plan.Sources)
	}

	// With its own firewall elsewhere already, the plan names it.
	own := w.own(traefik, vmTestOtherVM)
	plan, err = w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyHeadroom || plan.Sources[0].Firewall != own.UUID {
		t.Fatalf("plan = %#v, want strategy A with firewall %s", plan, own.UUID)
	}
	if _, err := encodeVMFirewallMigrationPlan(plan); err != nil {
		t.Fatalf("the plan is not a valid record: %v", err)
	}
}

func TestPlanVMFirewallReverseSingleServiceOnOneVMAdopts(t *testing.T) {
	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.seed()
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != "relay-prod-uid" {
		t.Fatalf("plan = %#v, want a reverse adopt into relay-prod-uid", plan)
	}
	if _, err := encodeVMFirewallMigrationPlan(plan); err != nil {
		t.Fatalf("the plan is not a valid record: %v", err)
	}
}

func TestPlanVMFirewallReverseTwoServicesAttachOneAndAdoptTheOther(t *testing.T) {
	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.service("relay-staging", "relay-staging-uid", 1, 1936)
	w.seed()
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != "relay-staging-uid" {
		t.Fatalf("plan = %#v, want the last Service by UID to take the per-VM firewall", plan)
	}
	if len(plan.Sources) != 2 || plan.Sources[0].UID != "relay-prod-uid" || plan.Sources[1].UID != "relay-staging-uid" {
		t.Fatalf("sources = %#v", plan.Sources)
	}
}

func TestPlanVMFirewallReverseAdopteeNeedsAFirewallNameThatIsFree(t *testing.T) {
	w := newReverseWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 2, 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 2, 1936)
	w.seed()
	w.own(staging, "11111111-2222-4333-8444-555555555555")
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Adoptee != "relay-prod-uid" {
		t.Fatalf("plan = %#v, want relay-prod-uid: the staging firewall exists", plan)
	}
	w.own(prod, "11111111-2222-4333-8444-555555555555")
	_, err = w.plan(3)
	requireReverseBlocked(t, err, "exists already")
}

func TestPlanVMFirewallReverseRefusesKAtTheLimit(t *testing.T) {
	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.service("relay-staging", "relay-staging-uid", 1, 1936)
	w.service("traefik-public-relay", "traefik-public-relay-uid", 1, 80)
	w.seed()
	_, err := w.plan(3)
	requireReverseBlocked(t, err, "k exceeds per-Service capacity")
}

func TestPlanVMFirewallReverseWithoutRenameOnlyAttaches(t *testing.T) {
	saved := vmFirewallRenameSupportedForTest
	vmFirewallRenameSupportedForTest = false
	t.Cleanup(func() { vmFirewallRenameSupportedForTest = saved })

	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.seed()
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyHeadroom {
		t.Fatalf("plan = %#v, want the attach-only variant", plan)
	}

	w = newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.service("relay-staging", "relay-staging-uid", 1, 1936)
	w.seed()
	_, err = w.plan(3)
	requireReverseBlocked(t, err, "rename unsupported")

	// A fourth slot makes the attach-only variant enough for two Services.
	plan, err = w.plan(4)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyHeadroom || plan.Adoptee != "" {
		t.Fatalf("plan = %#v, want attach-only with limit 4", plan)
	}
}

func TestPlanVMFirewallReverseBlocksOnAnUnexpectedFirewall(t *testing.T) {
	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	w.service("relay-staging", "relay-staging-uid", 1, 1936)
	w.seed()
	w.f.addForeignFirewall(vmTestVM, 1)
	_, err := w.plan(3)
	requireReverseBlocked(t, err, "other than the per-VM firewall")
	// One more slot does not make a foreign firewall acceptable.
	_, err = w.plan(4)
	requireReverseBlocked(t, err, "other than the per-VM firewall")
}

func TestPlanVMFirewallReverseWaitsForAServiceThatIsNotSteady(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Service){
		"policy change in flight": func(s *corev1.Service) { s.Annotations[annotationPublicNodeLocalTargetPolicy] = "abcdef12" },
		"assignment fence":        func(s *corev1.Service) { s.Annotations[annotationPublicNodeLocalAssignEdge] = publicNodeLocalEdgePerVM },
		"relation receipt": func(s *corev1.Service) {
			s.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] = "x"
		},
		"create in flight": func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPendingFWName] = "inlb-x" },
	} {
		t.Run(name, func(t *testing.T) {
			w := newReverseWorld(t)
			svc := w.service("relay-prod", "relay-prod-uid", 1, 1935)
			w.seed()
			mutate(&w.services[0])
			_ = svc
			_, err := w.plan(3)
			var deferred *errVMFirewallMigrationDeferred
			if !errors.As(err, &deferred) {
				t.Fatalf("err = %v, want a deferral", err)
			}
		})
	}
	t.Run("the spec asks for another policy than the one serving", func(t *testing.T) {
		w := newReverseWorld(t)
		w.service("relay-prod", "relay-prod-uid", 1, 1935)
		w.seed()
		w.services[0].Spec.Ports = append(w.services[0].Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolTCP, Port: 1936})
		_, err := w.plan(3)
		var deferred *errVMFirewallMigrationDeferred
		if !errors.As(err, &deferred) || !strings.Contains(deferred.reason, "wants policy") {
			t.Fatalf("err = %v, want a deferral that names the policy", err)
		}
	})
	t.Run("a Service that is gone", func(t *testing.T) {
		w := newReverseWorld(t)
		w.service("relay-prod", "relay-prod-uid", 1, 1935)
		w.seed()
		w.services = nil
		_, err := w.plan(3)
		var deferred *errVMFirewallMigrationDeferred
		if !errors.As(err, &deferred) || !strings.Contains(deferred.reason, "gone") {
			t.Fatalf("err = %v, want a deferral that says the Service is gone", err)
		}
	})
}

func TestPlanVMFirewallReverseTakesTheFirewallOfAnUnfinishedAdoptBack(t *testing.T) {
	w := newReverseWorld(t)
	w.service("relay-prod", "relay-prod-uid", 1, 1935)
	delete(w.services[0].Annotations, annotationPublicNodeLocalFirewallMode)
	w.services[0].Annotations[annotationNodeLoadBalancerFirewallUUID] = reverseTestFirewall
	w.seed()
	plan, err := w.plan(3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != "relay-prod-uid" {
		t.Fatalf("plan = %#v, want the per-VM firewall renamed back to relay-prod", plan)
	}
}

func TestVMFirewallReverseRecordRoundTripsAndForwardRecordsAreUnchanged(t *testing.T) {
	forward := vmFirewallMigrationPlan{
		Direction: "forward", Phase: "planned", Strategy: "A",
		Sources: []vmFirewallMigrationSource{{Firewall: "2ea7a127-0000-4000-8000-000000000003", UID: "traefik-public-uid", Policy: "3f2a9c1d"}},
	}
	raw, err := encodeVMFirewallMigrationPlan(forward)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "openedAt") {
		t.Fatalf("a forward record grew a field: %s", raw)
	}
	reverse := vmFirewallMigrationPlan{
		Direction: "reverse", Phase: "opened", Strategy: "B", Adoptee: "b-uid", OpenedAt: "2026-10-29T09:00:00Z",
		Sources: []vmFirewallMigrationSource{{UID: "a-uid", Policy: "3f2a9c1d"}, {Firewall: "2ea7a127-0000-4000-8000-000000000003", UID: "b-uid", Policy: "a1b2c3d4"}},
	}
	raw, err = encodeVMFirewallMigrationPlan(reverse)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeVMFirewallMigrationPlan(raw)
	if err != nil || fmt.Sprint(got) != fmt.Sprint(reverse) {
		t.Fatalf("round trip = %#v, %v", got, err)
	}
	for name, bad := range map[string]vmFirewallMigrationPlan{
		"unsorted":       {Direction: "reverse", Phase: "planned", Strategy: "A", Sources: []vmFirewallMigrationSource{{UID: "b", Policy: "3f2a9c1d"}, {UID: "a", Policy: "3f2a9c1d"}}},
		"adoptee absent": {Direction: "reverse", Phase: "planned", Strategy: "B", Adoptee: "z", Sources: []vmFirewallMigrationSource{{UID: "a", Policy: "3f2a9c1d"}}},
		"opened unset":   {Direction: "reverse", Phase: "opened", Strategy: "A", Sources: []vmFirewallMigrationSource{{UID: "a", Policy: "3f2a9c1d"}}},
		"done":           {Direction: "reverse", Phase: "done", Strategy: "A", Sources: []vmFirewallMigrationSource{{UID: "a", Policy: "3f2a9c1d"}}},
	} {
		if _, err := encodeVMFirewallMigrationPlan(bad); err == nil {
			t.Errorf("%s: a malformed reverse record was accepted", name)
		}
	}
}
