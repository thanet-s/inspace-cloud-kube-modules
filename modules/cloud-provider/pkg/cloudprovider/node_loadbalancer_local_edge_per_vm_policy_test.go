package cloudprovider

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// stepPerVMUntil steps the Service, checking the edge invariant on every pass,
// until cond holds.
func stepPerVMUntil(t *testing.T, f *publicNodeLocalTransientFixture, limit int, what string, cond func(*corev1.Service) bool) {
	t.Helper()
	for pass := 0; pass < limit; pass++ {
		stepPublicNodeLocal(t, f, pass)
		requireVMEdgeSafe(t, f)
		if cond(f.current(t)) {
			return
		}
	}
	t.Fatalf("%s: never reached: %#v", what, f.current(t).Annotations)
}

func perVMPolicyChangeDone(t *testing.T, f *publicNodeLocalTransientFixture, oldPolicy string) func(*corev1.Service) bool {
	return func(s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalActivePolicy] != oldPolicy &&
			s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			s.Annotations[annotationPublicNodeLocalPromotedAt] == "" &&
			!publicNodeLocalAssignmentFencePresent(s) &&
			publicNodeLocalDatapathMatches(trackedPublicNodeLocalDatapath(t, f), s, s.Annotations[annotationPublicNodeLocalActivePool])
	}
}

// A node leaves in the order FIP, firewall, VIP, and only the VM that left is
// touched.
func TestPerVMRemoveNodeOrder(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	name2, vm2, priv2, pub2 := publicNodeLocalFixtureNode(1)
	_, vm1, priv1, pub1 := publicNodeLocalFixtureNode(0)
	if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name2, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.setEndpoints(t, "edge-0")
	done := false
	for pass := 0; pass < 80 && !done; pass++ {
		stepPublicNodeLocal(t, f, pass)
		requireVMEdgeSafe(t, f)
		observed := observePublicNodeLocal(t, f)
		if !observed.fips[pub1] || !observed.vips[priv1] {
			t.Fatalf("pass %d: the remaining node left the edge: %#v", pass, observed)
		}
		carries := false
		for _, firewall := range vmFirewallsOfVM(f, vm2) {
			if _, isVM := parseVMFirewallNameForTest(f, firewall.EffectiveName()); isVM {
				carries = true
			}
		}
		if observed.fips[pub2] && !carries {
			t.Fatalf("pass %d: the firewall left VM2 while its FIP was published", pass)
		}
		if !observed.vips[priv2] && carries {
			t.Fatalf("pass %d: the child VIP left before the firewall: %#v", pass, observed)
		}
		done = !observed.fips[pub2] && !observed.vips[priv2] && !carries
	}
	if !done {
		t.Fatalf("the removed node never left the edge: %#v", observePublicNodeLocal(t, f))
	}
	if len(vmFirewallsOfVM(f, vm1)) != 2 {
		t.Fatalf("the remaining VM was touched: %#v", vmFirewallsOfVM(f, vm1))
	}
}

// 443 becomes 443+8443 on VMs that already carry the base and the per-VM
// firewall: no third firewall is ever needed, and each VM gets exactly one PUT.
func TestPerVMPolicyChangeNeedsNoExtraSlot(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	updatesBefore := len(f.api.updatedFirewalls)
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	stepPerVMUntil(t, f, 300, "the widening", perVMPolicyChangeDone(t, f, oldPolicy))
	if f.gate.maxObservedFirewallsPerVM > 2 {
		t.Fatalf("a VM carried %d firewalls; the change needs no extra slot", f.gate.maxObservedFirewallsPerVM)
	}
	if got := len(f.api.updatedFirewalls) - updatesBefore; got != 2 {
		t.Fatalf("%d PUTs for 2 VMs, want one widening PUT each and no PUT for the retire", got)
	}
	requireSteadyFirewallCount(t, f, 2, 2)
	ports := childPortSet(trackedPublicNodeLocalDatapath(t, f))
	if !ports[443] || !ports[8443] || len(ports) != 2 {
		t.Fatalf("child ports = %v", ports)
	}
}

// 443+80 becomes 443: the widening entry changes nothing the firewall allows,
// so only the narrowing after the promotion is a PUT, and port 80 stays in the
// child until it has been made.
func TestPerVMPortRemovalNarrowsAfterPromotion(t *testing.T) {
	f := newPerVMPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443, 80))
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	updatesBefore := len(f.api.updatedFirewalls)
	setPublicNodeLocalFixturePorts(t, f, 443)
	for pass := 0; pass < 300; pass++ {
		stepPublicNodeLocal(t, f, pass)
		requireVMEdgeSafe(t, f)
		current := f.current(t)
		ports := childPortSet(trackedPublicNodeLocalDatapath(t, f))
		for i := 0; i < 2; i++ {
			_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
			for _, firewall := range vmFirewallsOfVM(f, vmUUID) {
				for _, rule := range firewall.Rules {
					if rule.PortStart != nil && *rule.PortStart == 80 && !ports[80] {
						t.Fatalf("pass %d: port 80 left the child while a firewall still allows it", pass)
					}
				}
			}
		}
		if perVMPolicyChangeDone(t, f, oldPolicy)(current) {
			break
		}
	}
	if !perVMPolicyChangeDone(t, f, oldPolicy)(f.current(t)) {
		t.Fatalf("the narrowing never completed: %#v", f.current(t).Annotations)
	}
	if got := len(f.api.updatedFirewalls) - updatesBefore; got != 2 {
		t.Fatalf("%d PUTs for 2 VMs, want one narrowing PUT each", got)
	}
	if ports := childPortSet(trackedPublicNodeLocalDatapath(t, f)); len(ports) != 1 || !ports[443] {
		t.Fatalf("child ports = %v", ports)
	}
}

// A source range change opens the union of both ranges first and narrows to the
// new range only after the promotion.
func TestPerVMRangeChangeUnionThenNarrow(t *testing.T) {
	f := newPerVMPublicNodeLocalFixtureWith(t, 2, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"} })
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	updatesBefore := len(f.api.updatedFirewalls)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Spec.LoadBalancerSourceRanges = []string{"203.0.113.0/24"} })
	sawUnion := false
	stepPerVMUntil(t, f, 400, "the range change", func(s *corev1.Service) bool {
		_, vmUUID, _, _ := publicNodeLocalFixtureNode(0)
		for _, firewall := range vmFirewallsOfVM(f, vmUUID) {
			if _, isVM := parseVMFirewallNameForTest(f, firewall.EffectiveName()); isVM && len(firewall.Rules) == 1 && len(firewall.Rules[0].EndpointSpec) == 2 {
				sawUnion = true
			}
		}
		return perVMPolicyChangeDone(t, f, oldPolicy)(s)
	})
	if !sawUnion {
		t.Fatal("the firewall never carried both ranges")
	}
	if got := len(f.api.updatedFirewalls) - updatesBefore; got != 4 {
		t.Fatalf("%d PUTs for 2 VMs, want a widening and a narrowing PUT each", got)
	}
	_, vmUUID, _, _ := publicNodeLocalFixtureNode(0)
	for _, firewall := range vmFirewallsOfVM(f, vmUUID) {
		if _, isVM := parseVMFirewallNameForTest(f, firewall.EffectiveName()); isVM {
			if len(firewall.Rules) != 1 || len(firewall.Rules[0].EndpointSpec) != 1 || firewall.Rules[0].EndpointSpec[0] != "203.0.113.0/24" {
				t.Fatalf("the firewall did not narrow to the new range: %#v", firewall.Rules)
			}
		}
	}
}

// Reverting a policy change in the middle removes the target entries only, and
// the active policy keeps serving.
func TestPerVMRevertAndRetarget(t *testing.T) {
	f := newPerVMPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443))
	oldPolicy := f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
	setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	stepPerVMUntil(t, f, 200, "the target is open", func(s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] != "" &&
			len(vmFirewallsOfVM(f, "11111111-2222-4333-8444-555555555555")) == 2
	})
	setPublicNodeLocalFixturePorts(t, f, 443)
	stepPerVMUntil(t, f, 400, "the policy is restored", func(s *corev1.Service) bool {
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" &&
			s.Annotations[annotationPublicNodeLocalActivePolicy] == oldPolicy &&
			s.Annotations[annotationPublicNodeLocalPromotedAt] == "" && !publicNodeLocalAssignmentFencePresent(s)
	})
	for i := 0; i < 2; i++ {
		_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
		for _, firewall := range vmFirewallsOfVM(f, vmUUID) {
			if _, isVM := parseVMFirewallNameForTest(f, firewall.EffectiveName()); isVM && len(firewall.Rules) != 1 {
				t.Fatalf("VM %d still carries the target ports: %#v", i, firewall.Rules)
			}
		}
	}
	if ports := childPortSet(trackedPublicNodeLocalDatapath(t, f)); len(ports) != 1 || !ports[443] {
		t.Fatalf("child ports = %v", ports)
	}
}

// A pool change adds the new pool's VMs under the same policy, promotes, and
// only then takes the old pool's VM off the edge.
func TestPerVMPoolChange(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	f.addNode(t, 1)
	_, vmA, privA, pubA := publicNodeLocalFixtureNode(0)
	_, vmB, _, pubB := publicNodeLocalFixtureNode(1)
	// Karpenter attaches the base firewall when it creates the VM.
	f.api.firewalls[0].ResourcesAssigned = append(f.api.firewalls[0].ResourcesAssigned,
		inspaceVMResource(vmB))
	moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
	sawUnion := false
	stepPerVMUntil(t, f, 400, "the pool change", func(s *corev1.Service) bool {
		published := publicNodeLocalIngressSet(s.Status.LoadBalancer)
		_, a := published[pubA]
		_, b := published[pubB]
		if a && b {
			sawUnion = true
		}
		return s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			!a && len(vmFirewallsOfVM(f, vmA)) == 1 && !publicNodeLocalIngressSetHas(trackedPublicNodeLocalDatapath(t, f), privA)
	})
	if !sawUnion {
		t.Fatal("both pools were never published together")
	}
	if len(vmFirewallsOfVM(f, vmB)) != 2 {
		t.Fatalf("the new pool VM must end with the base and its per-VM firewall: %#v", vmFirewallsOfVM(f, vmB))
	}
}

func publicNodeLocalIngressSetHas(service *corev1.Service, ip string) bool {
	_, has := publicNodeLocalIngressSet(service.Status.LoadBalancer)[ip]
	return has
}
