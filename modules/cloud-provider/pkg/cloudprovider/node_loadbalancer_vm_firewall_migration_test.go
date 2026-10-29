package cloudprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// planWorld is a hand-built v1.1.9 cluster for the read-only planner: Services
// that are steady and the per-Service firewalls they own.
type planWorld struct {
	t          *testing.T
	f          *vmFirewallFixture
	services   []corev1.Service
	items      []inspace.Firewall
	baseUUID   string
	nextRuleID int
}

func newPlanWorld(t *testing.T) *planWorld {
	f := newVMFirewallFixture(t)
	return &planWorld{t: t, f: f, baseUUID: f.api.firewalls[0].UUID}
}

// service adds a steady, serving Service that asks for the given ports.
func (w *planWorld) service(name, uid string, ports ...int32) *corev1.Service {
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
	svc.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	w.services = append(w.services, *svc)
	return &w.services[len(w.services)-1]
}

// firewall adds the per-Service firewall of svc, attached to the given VMs.
func (w *planWorld) firewall(svc *corev1.Service, uuid string, vms ...string) *inspace.Firewall {
	w.t.Helper()
	desired, err := w.f.controller.desiredServiceFirewall(svc)
	if err != nil {
		w.t.Fatal(err)
	}
	rules := retainFirewallRuleUUIDs(nil, desired.Request.Rules)
	for index := range rules {
		w.nextRuleID++
		rules[index].UUID = fmt.Sprintf("cccccccc-0000-4000-8000-%012d", w.nextRuleID)
	}
	firewall := inspace.Firewall{
		UUID: uuid, DisplayName: desired.Request.DisplayName, Description: desired.Request.Description,
		BillingAccountID: 42, Rules: rules,
	}
	for _, vm := range vms {
		firewall.ResourcesAssigned = append(firewall.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm})
	}
	w.items = append(w.items, firewall)
	svc.Annotations[annotationNodeLoadBalancerFirewallUUID] = uuid
	for index := range w.services {
		if w.services[index].UID == svc.UID {
			w.services[index].Annotations = svc.Annotations
		}
	}
	return &w.items[len(w.items)-1]
}

func (w *planWorld) base(vms ...string) {
	base := publicNodeLocalTestBaseFirewall("")
	base.ResourcesAssigned = nil
	for _, vm := range vms {
		base.ResourcesAssigned = append(base.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm})
	}
	w.items = append(w.items, base)
}

func (w *planWorld) plan(vm string, limit int) (vmFirewallMigrationPlan, error) {
	w.t.Helper()
	return planVMFirewallMigration(vm, w.items, w.services, "unit-test-cluster", 42, w.baseUUID, limit)
}

const (
	// The th-live firewalls, as far as their order goes.
	planRelayProd    = "35cd0068-0000-4000-8000-000000000001"
	planRelayStaging = "a9ffbec4-0000-4000-8000-000000000002"
	planGatewayFW    = "2ea7a127-0000-4000-8000-000000000003"
)

func TestPlanVMFirewallMigrationGatewayVMUsesHeadroom(t *testing.T) {
	w := newPlanWorld(t)
	traefik := w.service("traefik-public", "traefik-public-uid", 80, 443)
	w.firewall(traefik, planGatewayFW, vmTestVM, vmTestOtherVM)
	w.base(vmTestVM, vmTestOtherVM)

	plan, err := w.plan(vmTestVM, 3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyHeadroom || plan.Adoptee != "" || plan.Direction != "forward" || plan.Phase != "planned" {
		t.Fatalf("plan = %#v, want strategy A", plan)
	}
	if len(plan.Sources) != 1 || plan.Sources[0].Firewall != planGatewayFW || plan.Sources[0].UID != "traefik-public-uid" {
		t.Fatalf("sources = %#v", plan.Sources)
	}
}

func TestPlanVMFirewallMigrationRelayVMAdoptsTheLowestSingleVMFirewall(t *testing.T) {
	w := newPlanWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 1936)
	w.firewall(prod, planRelayProd, vmTestVM)
	w.firewall(staging, planRelayStaging, vmTestVM)
	w.base(vmTestVM)

	plan, err := w.plan(vmTestVM, 3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != vmFirewallMigrationStrategyAdopt || plan.Adoptee != planRelayProd {
		t.Fatalf("plan = %#v, want strategy B adopting %s", plan, planRelayProd)
	}
	if len(plan.Sources) != 2 || plan.Sources[0].Firewall != planRelayProd || plan.Sources[1].Firewall != planRelayStaging {
		t.Fatalf("sources are not sorted by firewall: %#v", plan.Sources)
	}
}

func TestPlanVMFirewallMigrationAdopteeSkipsAMultiVMFirewall(t *testing.T) {
	w := newPlanWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 1936)
	w.firewall(prod, planRelayProd, vmTestVM, vmTestOtherVM)
	w.firewall(staging, planRelayStaging, vmTestVM)
	w.base(vmTestVM, vmTestOtherVM)

	plan, err := w.plan(vmTestVM, 3)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Adoptee != planRelayStaging {
		t.Fatalf("adoptee = %s, want the single-VM %s", plan.Adoptee, planRelayStaging)
	}
}

func TestPlanVMFirewallMigrationDefersWhenNoFirewallCanBeAdopted(t *testing.T) {
	w := newPlanWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 1936)
	w.firewall(prod, planRelayProd, vmTestVM, vmTestOtherVM)
	w.firewall(staging, planRelayStaging, vmTestVM, vmTestOtherVM)
	w.base(vmTestVM, vmTestOtherVM)

	_, err := w.plan(vmTestVM, 3)
	var deferred *errVMFirewallMigrationDeferred
	if !errors.As(err, &deferred) {
		t.Fatalf("error = %v, want a deferral", err)
	}
}

func TestPlanVMFirewallMigrationDefersForAServiceThatIsNotSteady(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Service){
		"target policy":    func(s *corev1.Service) { s.Annotations[annotationPublicNodeLocalTargetPolicy] = "00000000" },
		"previous":         func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPreviousFirewall] = planGatewayFW },
		"assignment fence": func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerFirewallAssigning] = planGatewayFW },
		"edge fence":       func(s *corev1.Service) { s.Annotations[annotationPublicNodeLocalAssignEdge] = publicNodeLocalEdgePerVM },
		"relation receipt": func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] = "x" },
		"withdraw journal": func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = "x" },
		"rebuild":          func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerRebuilding] = "true" },
		"pending create":   func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPendingFirewall] = planGatewayFW },
		"pending delete":   func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerFWDeleteTarget] = planGatewayFW },
		"not serving":      func(s *corev1.Service) { delete(s.Annotations, annotationPublicNodeLocalActivePool) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newPlanWorld(t)
			traefik := w.service("traefik-public", "traefik-public-uid", 80)
			w.firewall(traefik, planGatewayFW, vmTestVM)
			w.base(vmTestVM)
			mutate(&w.services[0])
			_, err := w.plan(vmTestVM, 3)
			var deferred *errVMFirewallMigrationDeferred
			if !errors.As(err, &deferred) || !strings.Contains(deferred.reason, "waiting") {
				t.Fatalf("error = %v, want a deferral that says waiting", err)
			}
		})
	}
}

func TestPlanVMFirewallMigrationRefusesWhatItDoesNotRecognize(t *testing.T) {
	t.Run("unknown firewall", func(t *testing.T) {
		w := newPlanWorld(t)
		w.base(vmTestVM)
		w.items = append(w.items, inspace.Firewall{
			UUID: planGatewayFW, DisplayName: "someone-elses", BillingAccountID: 42,
			ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmTestVM}},
		})
		if _, err := w.plan(vmTestVM, 3); err == nil {
			t.Fatal("an unknown firewall must hold the VM")
		}
	})
	t.Run("no Service names the firewall", func(t *testing.T) {
		w := newPlanWorld(t)
		traefik := w.service("traefik-public", "traefik-public-uid", 80)
		w.firewall(traefik, planGatewayFW, vmTestVM)
		w.base(vmTestVM)
		delete(w.services[0].Annotations, annotationNodeLoadBalancerFirewallUUID)
		if _, err := w.plan(vmTestVM, 3); err == nil {
			t.Fatal("an unnamed firewall must hold the VM")
		}
	})
	t.Run("overlapping ports", func(t *testing.T) {
		w := newPlanWorld(t)
		a := w.service("a", "a-uid", 443)
		b := w.service("b", "b-uid", 443)
		w.firewall(a, planRelayProd, vmTestVM)
		w.firewall(b, planRelayStaging, vmTestVM)
		w.base(vmTestVM)
		_, err := w.plan(vmTestVM, 4)
		var conflict *errVMFirewallPortConflict
		if !errors.As(err, &conflict) {
			t.Fatalf("error = %v, want a port conflict", err)
		}
	})
	t.Run("rules that are not the active policy", func(t *testing.T) {
		w := newPlanWorld(t)
		traefik := w.service("traefik-public", "traefik-public-uid", 80)
		fw := w.firewall(traefik, planGatewayFW, vmTestVM)
		port := int32(9999)
		fw.Rules[0].PortStart, fw.Rules[0].PortEnd = &port, &port
		w.base(vmTestVM)
		if _, err := w.plan(vmTestVM, 3); err == nil {
			t.Fatal("a firewall that drifted from the active policy must hold the VM")
		}
	})
	t.Run("base missing", func(t *testing.T) {
		w := newPlanWorld(t)
		traefik := w.service("traefik-public", "traefik-public-uid", 80)
		w.firewall(traefik, planGatewayFW, vmTestVM)
		if _, err := w.plan(vmTestVM, 3); err == nil {
			t.Fatal("a VM without the base firewall must hold")
		}
	})
	t.Run("already per-VM", func(t *testing.T) {
		w := newPlanWorld(t)
		w.base(vmTestVM)
		w.items = append(w.items, perVMTestFirewall(t, "unit-test-cluster", vmTestVM, planGatewayFW, 80))
		if _, err := w.plan(vmTestVM, 3); err == nil {
			t.Fatal("a VM that already has its per-VM firewall is not planned again")
		}
	})
}

func TestPlanVMFirewallMigrationBlockedWhenRenameUnsupported(t *testing.T) {
	previous := vmFirewallRenameSupportedForTest
	vmFirewallRenameSupportedForTest = false
	t.Cleanup(func() { vmFirewallRenameSupportedForTest = previous })

	w := newPlanWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 1936)
	w.firewall(prod, planRelayProd, vmTestVM)
	w.firewall(staging, planRelayStaging, vmTestVM)
	w.base(vmTestVM)
	_, err := w.plan(vmTestVM, 3)
	var blocked *errVMFirewallMigrationBlocked
	if !errors.As(err, &blocked) || blocked.reason != "rename unsupported" {
		t.Fatalf("error = %v, want blocked: rename unsupported", err)
	}
	// Headroom needs no rename.
	w2 := newPlanWorld(t)
	traefik := w2.service("traefik-public", "traefik-public-uid", 80)
	w2.firewall(traefik, planGatewayFW, vmTestVM)
	w2.base(vmTestVM)
	if plan, err := w2.plan(vmTestVM, 3); err != nil || plan.Strategy != vmFirewallMigrationStrategyHeadroom {
		t.Fatalf("headroom with rename off = %#v, %v", plan, err)
	}
}

// The limit is configurable: with room for a fourth firewall the relay VM has
// headroom and needs no rename.
func TestPlanVMFirewallMigrationFollowsTheConfiguredLimit(t *testing.T) {
	w := newPlanWorld(t)
	prod := w.service("relay-prod", "relay-prod-uid", 1935)
	staging := w.service("relay-staging", "relay-staging-uid", 1936)
	w.firewall(prod, planRelayProd, vmTestVM)
	w.firewall(staging, planRelayStaging, vmTestVM)
	w.base(vmTestVM)
	plan, err := w.plan(vmTestVM, 4)
	if err != nil || plan.Strategy != vmFirewallMigrationStrategyHeadroom {
		t.Fatalf("plan = %#v, %v, want strategy A", plan, err)
	}
	if _, err := w.plan(vmTestVM, 2); err == nil {
		t.Fatal("a VM above the limit must hold")
	}
}

func TestPlanVMFirewallMigrationNothingToMigrate(t *testing.T) {
	w := newPlanWorld(t)
	w.base(vmTestVM)
	plan, err := w.plan(vmTestVM, 3)
	if err != nil || len(plan.Sources) != 0 {
		t.Fatalf("plan = %#v, %v, want an empty plan", plan, err)
	}
}

func TestVMFirewallMigrationRecordRoundTripsAndStaysAuditable(t *testing.T) {
	plan := vmFirewallMigrationPlan{
		Direction: "forward", Phase: "opened", Strategy: "B", Adoptee: planRelayProd,
		Sources: []vmFirewallMigrationSource{
			{Firewall: planRelayProd, UID: "relay-prod-uid", Policy: "3f2a9c1d"},
			{Firewall: planRelayStaging, UID: "relay-staging-uid", Policy: "a1b2c3d4"},
		},
	}
	raw, err := encodeVMFirewallMigrationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeVMFirewallMigrationPlan(raw)
	if err != nil || fmt.Sprint(back) != fmt.Sprint(plan) {
		t.Fatalf("round trip = %#v, %v", back, err)
	}
	// The PR 4 audit reads only the phase and the source firewalls.
	var audit vmFirewallMigrationPlanAudit
	if err := json.Unmarshal([]byte(raw), &audit); err != nil || audit.Phase != "opened" || len(audit.Sources) != 2 || audit.Sources[1].Firewall != planRelayStaging {
		t.Fatalf("audit view = %#v, %v", audit, err)
	}
	for _, bad := range []string{
		raw + " ", `{"direction":"forward"}`, strings.Replace(raw, `"phase":"opened"`, `"phase":"later"`, 1),
		strings.Replace(raw, `"adoptee":"`+planRelayProd+`"`, `"adoptee":"`+planGatewayFW+`"`, 1),
		strings.Replace(raw, "{", `{"extra":1,`, 1),
	} {
		if _, err := decodeVMFirewallMigrationPlan(bad); err == nil || !errors.Is(err, errVMFirewallLedgerCorrupt) {
			t.Errorf("record %q decoded: %v", bad, err)
		}
	}
}
