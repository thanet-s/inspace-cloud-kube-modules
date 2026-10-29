package cloudprovider

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestPublicNodeLocalEdgeDefaultsToPerService(t *testing.T) {
	f := newPublishedPublicNodeLocalFixture(t)
	if f.controller.publicNodeLocalPerVMModeEnabled() {
		t.Fatal("the default mode must be perService")
	}
	if _, ok := f.controller.publicNodeLocalEdgeFor(f.current(t)).(perServiceEdge); !ok {
		t.Fatalf("the default edge is %T, want perServiceEdge", f.controller.publicNodeLocalEdgeFor(f.current(t)))
	}
}

func TestPublicNodeLocalEdgeForSelection(t *testing.T) {
	fresh := &corev1.Service{}
	perServiceState := &corev1.Service{}
	perServiceState.Annotations = map[string]string{annotationNodeLoadBalancerFirewallUUID: "11111111-1111-4111-8111-111111111111"}
	activePerService := &corev1.Service{}
	activePerService.Annotations = map[string]string{annotationPublicNodeLocalActivePolicy: "3f2a9c1d"}
	onPerVM := &corev1.Service{}
	onPerVM.Annotations = map[string]string{
		annotationPublicNodeLocalFirewallMode: publicNodeLocalEdgePerVM,
		annotationPublicNodeLocalActivePolicy: "3f2a9c1d",
	}
	for _, test := range []struct {
		name    string
		mode    PublicNodeLocalFirewallMode
		service *corev1.Service
		perVM   bool
	}{
		{name: "perService mode, fresh Service", mode: PublicNodeLocalFirewallModePerService, service: fresh},
		{name: "perService mode, per-vm annotation", mode: PublicNodeLocalFirewallModePerService, service: onPerVM},
		{name: "perVM mode, fresh Service", mode: PublicNodeLocalFirewallModePerVM, service: fresh, perVM: true},
		{name: "perVM mode, per-Service firewall state", mode: PublicNodeLocalFirewallModePerVM, service: perServiceState},
		{name: "perVM mode, active per-Service policy", mode: PublicNodeLocalFirewallModePerVM, service: activePerService},
		{name: "perVM mode, per-vm annotation", mode: PublicNodeLocalFirewallModePerVM, service: onPerVM, perVM: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newPublishedPublicNodeLocalFixture(t)
			f.provider.config.NodeLoadBalancer.LocalFirewallMode = test.mode
			_, isPerVM := f.controller.publicNodeLocalEdgeFor(test.service).(perVMEdge)
			if isPerVM != test.perVM {
				t.Fatalf("per-VM edge = %t, want %t", isPerVM, test.perVM)
			}
		})
	}
}

// perVMFakeClock drives the settle delay of a per-VM fixture.
type perVMFakeClock struct{ now time.Time }

func (c *perVMFakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func useFakeClock(f *publicNodeLocalFixtureT, settle time.Duration) *perVMFakeClock {
	clock := &perVMFakeClock{now: time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)}
	f.controller.firewallRelationNow = func() time.Time { return clock.now }
	f.provider.config.NodeLoadBalancer.VMFirewallSettle = settle
	return clock
}

// publicNodeLocalFixtureT is the fixture type under a short name.
type publicNodeLocalFixtureT = publicNodeLocalTransientFixture

// runUntilSettling runs passes until the Service waits for the settle delay,
// and fails on any other error.
func runUntilSettling(t *testing.T, f *publicNodeLocalFixtureT, limit int) {
	t.Helper()
	for pass := 0; pass < limit; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var settling *errPublicNodeLocalVMFirewallSettling
		if errors.As(err, &settling) {
			return
		}
		var pending *nodeLoadBalancerFirewallRelationPendingError
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &pending) && !errors.As(err, &holding) {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if len(f.current(t).Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("pass %d: the Service published before the settle delay: %#v", pass, f.current(t).Status)
		}
	}
	t.Fatalf("the Service never waited for the settle delay: %#v", f.current(t).Annotations)
}

func TestPerVMBootstrapOpensOneVMPerPassAndSettlesBeforePublishing(t *testing.T) {
	f := buildPerVMPublicNodeLocalFixture(t, 2, nil)
	clock := useFakeClock(f, 10*time.Second)
	runUntilSettling(t, f, 200)

	// Both VMs carry their per-VM firewall and nothing is published yet.
	for index := 0; index < 2; index++ {
		_, vmUUID, _, _ := publicNodeLocalFixtureNode(index)
		attached := vmFirewallsOfVM(f, vmUUID)
		if len(attached) != 2 {
			t.Fatalf("VM %d carries %d firewalls, want the base and its per-VM firewall: %#v", index, len(attached), attached)
		}
	}
	if got := f.current(t).Annotations[annotationPublicNodeLocalFirewallMode]; got != publicNodeLocalEdgePerVM {
		t.Fatalf("firewall mode annotation = %q", got)
	}
	if got := f.current(t).Annotations[annotationNodeLoadBalancerFirewallUUID]; got != "" {
		t.Fatalf("a per-VM Service must keep no per-Service firewall ledger, got %q", got)
	}

	clock.advance(11 * time.Second)
	for pass := 0; pass < 40 && len(f.current(t).Status.LoadBalancer.Ingress) != 2; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var settling *errPublicNodeLocalVMFirewallSettling
		var pending *nodeLoadBalancerFirewallRelationPendingError
		var holding *errPublicNodeLocalHolding
		if err != nil && !errors.As(err, &settling) && !errors.As(err, &pending) && !errors.As(err, &holding) {
			t.Fatalf("pass %d after the settle delay: %v", pass, err)
		}
	}
	if got := len(f.current(t).Status.LoadBalancer.Ingress); got != 2 {
		t.Fatalf("published %d FIPs after the settle delay, want 2", got)
	}
	if f.gate.maxObservedFirewallsPerVM > 3 {
		t.Fatalf("a VM carried %d firewalls", f.gate.maxObservedFirewallsPerVM)
	}
	if publicNodeLocalAssignmentFencePresent(f.current(t)) {
		t.Fatalf("the assignment fence was not cleared: %#v", f.current(t).Annotations)
	}
}

// perVMFirewallVMCount is how many VMs carry a per-VM firewall in the fake cloud.
func perVMFirewallVMCount(f *publicNodeLocalFixtureT) int {
	count := 0
	for _, firewall := range f.api.firewalls {
		if _, isVM := parseVMFirewallNameForTest(f, firewall.EffectiveName()); isVM && len(firewall.ResourcesAssigned) != 0 {
			count++
		}
	}
	return count
}

func parseVMFirewallNameForTest(f *publicNodeLocalFixtureT, name string) (string, bool) {
	return inspace.ParseNodeLoadBalancerVMFirewallName(f.provider.config.ClusterID, name)
}

// A pass opens at most one more VM: the bootstrap never attaches two per-VM
// firewalls in one step.
func TestPerVMBootstrapNeverOpensTwoVMsInOnePass(t *testing.T) {
	f := buildPerVMPublicNodeLocalFixture(t, 3, nil)
	useFakeClock(f, 10*time.Second)
	before := 0
	for pass := 0; pass < 200 && perVMFirewallVMCount(f) < 3; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		now := perVMFirewallVMCount(f)
		if now-before > 1 {
			t.Fatalf("pass %d opened %d VMs at once", pass, now-before)
		}
		before = now
	}
	if before != 3 {
		t.Fatalf("only %d VMs were opened", before)
	}
}

func TestPerVMEdgeAssignedReadsAnchors(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	service := f.current(t)
	desired, err := f.controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	edge := f.controller.publicNodeLocalEdgeFor(service)
	_, current, previous, waiting, err := edge.Prepare(f.ctx, service, desired)
	if err != nil || waiting {
		t.Fatalf("Prepare = waiting:%t err:%v", waiting, err)
	}
	if previous.known() {
		t.Fatalf("a steady Service has no previous edge: %#v", previous)
	}
	assigned, err := edge.Assigned(f.ctx, service, current)
	if err != nil {
		t.Fatal(err)
	}
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	_, vm1, _, _ := publicNodeLocalFixtureNode(1)
	if len(assigned) != 2 {
		t.Fatalf("assigned = %v, want both VMs", assigned)
	}
	if _, ok := assigned[vm0]; !ok {
		t.Fatalf("assigned = %v lacks %s", assigned, vm0)
	}
	// A detached per-VM firewall is not open, though its entry is still listed.
	for index := range f.api.firewalls {
		if _, isVM := parseVMFirewallNameForTest(f, f.api.firewalls[index].EffectiveName()); isVM {
			kept := f.api.firewalls[index].ResourcesAssigned[:0]
			for _, row := range f.api.firewalls[index].ResourcesAssigned {
				if row.ResourceUUID != vm0 {
					kept = append(kept, row)
				}
			}
			f.api.firewalls[index].ResourcesAssigned = kept
		}
	}
	_, current, _, _, err = edge.Prepare(f.ctx, service, desired)
	if err != nil {
		t.Fatal(err)
	}
	assigned, _ = edge.Assigned(f.ctx, service, current)
	if _, ok := assigned[vm0]; ok || len(assigned) != 1 {
		t.Fatalf("assigned after a detach = %v, want only %s", assigned, vm1)
	}
	if _, listed := current.listed[vm0]; !listed {
		t.Fatalf("the entry on %s must still be listed: %#v", vm0, current.listed)
	}
}

func TestPerVMEdgeResolvePendingBlocksPlanning(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	service := f.current(t)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	f.controller.firewallRelationNow = func() time.Time { return time.Now().UTC() }
	anchor, err := f.controller.getVMFirewallAnchor(f.ctx, vm0)
	if err != nil || anchor == nil {
		t.Fatalf("anchor = %v, %v", anchor, err)
	}
	// An issued PUT that left the rules as they were: a receipt to resolve.
	if _, _, err := f.controller.updateVMFirewallAnchor(f.ctx, anchor, func(cm *corev1.ConfigMap) (bool, error) {
		cm.Annotations[annotationVMFirewallPending] = cm.Annotations[annotationVMFirewallApplied]
		cm.Annotations[annotationVMFirewallPendingHash] = cm.Annotations[annotationVMFirewallAppliedHash]
		cm.Annotations[annotationVMFirewallPendingOp] = string(vmFirewallOpUpdate)
		cm.Annotations[annotationVMFirewallPendingAt] = time.Now().UTC().Format(time.RFC3339Nano)
		cm.Annotations[annotationVMFirewallIssuedAt] = time.Now().UTC().Format(time.RFC3339Nano)
		cm.Annotations[annotationVMFirewallIssueID] = "issue"
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	edge := f.controller.publicNodeLocalEdgeFor(service)
	resolved, err := edge.ResolvePending(f.ctx, service)
	if err != nil || resolved {
		t.Fatalf("ResolvePending = %t, %v; want unresolved while a receipt was open", resolved, err)
	}
	resolved, err = edge.ResolvePending(f.ctx, service)
	if err != nil || !resolved {
		t.Fatalf("ResolvePending after the commit = %t, %v", resolved, err)
	}
}

// A node added to a serving Service opens on the new VM only; its FIP follows
// the settle delay, and the VM that already served is not touched.
func TestPerVMActiveAddNode(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	clock := useFakeClock(f, 10*time.Second)
	clock.advance(time.Hour)
	updatesBefore := len(f.api.updatedFirewalls)
	createdBefore := len(f.api.createdFirewalls)
	f.addNode(t, 1)
	_, vm1, _, _ := publicNodeLocalFixtureNode(1)
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	// Karpenter attaches the base firewall when it creates the VM.
	f.api.firewalls[0].ResourcesAssigned = append(f.api.firewalls[0].ResourcesAssigned,
		inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vm1})
	sawWait := false
	for pass := 0; pass < 100 && len(f.current(t).Status.LoadBalancer.Ingress) != 2; pass++ {
		err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		var settling *errPublicNodeLocalVMFirewallSettling
		if errors.As(err, &settling) {
			sawWait = true
			if len(f.current(t).Status.LoadBalancer.Ingress) != 1 {
				t.Fatalf("the new FIP was published while the VM firewall settled: %#v", f.current(t).Status)
			}
			clock.advance(11 * time.Second)
		}
	}
	if !sawWait {
		t.Fatal("the add never waited for the settle delay")
	}
	if got := len(f.current(t).Status.LoadBalancer.Ingress); got != 2 {
		t.Fatalf("published %d FIPs, want 2", got)
	}
	if len(f.api.updatedFirewalls) != updatesBefore {
		t.Fatalf("the add PUT the firewall of the VM that already served: %d updates", len(f.api.updatedFirewalls)-updatesBefore)
	}
	if got := len(f.api.createdFirewalls) - createdBefore; got != 1 {
		t.Fatalf("the add created %d firewalls, want exactly the new VM's", got)
	}
	if len(vmFirewallsOfVM(f, vm1)) != 2 || len(vmFirewallsOfVM(f, vm0)) != 2 {
		t.Fatalf("each VM must end with the base and its per-VM firewall")
	}
}

// The cloud call needs the durable assignment fence: without it nothing is
// created, and the receipt is reset.
func TestPerVMAssignRefusesWithoutFence(t *testing.T) {
	f := buildPerVMPublicNodeLocalFixture(t, 1, nil)
	service := f.current(t)
	desired, err := f.controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 1})
	if err != nil {
		t.Fatal(err)
	}
	edge := f.controller.publicNodeLocalEdgeFor(service)
	service, current, _, _, err := edge.Prepare(f.ctx, service, desired)
	if err != nil {
		t.Fatal(err)
	}
	name, vm0, privateIP, publicIP := publicNodeLocalFixtureNode(0)
	node, err := f.provider.kubeClient.CoreV1().Nodes().Get(f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	address := nodeLoadBalancerAddress{Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP}
	if _, err := edge.Assign(f.ctx, service, intent, desired, current, []nodeLoadBalancerAddress{address}); err == nil {
		t.Fatal("an assignment without a fence must be refused")
	}
	if len(f.api.createdFirewalls) != 0 {
		t.Fatalf("a firewall was created without authority: %#v", f.api.createdFirewalls)
	}
	anchor, err := f.controller.getVMFirewallAnchor(f.ctx, vm0)
	if err != nil {
		t.Fatal(err)
	}
	if anchor != nil && (vmFirewallAnchorView{cm: anchor}).hasReceipt() {
		t.Fatalf("the rejected mutation left a receipt: %#v", anchor.Annotations)
	}
}

// A VM that still carries the per-Service firewall of another Service waits for
// its migration: the new Service does not mix both kinds on it.
func TestPerVMAddWaitsOnUnmigratedVM(t *testing.T) {
	f := buildPerVMPublicNodeLocalFixture(t, 1, nil)
	other := publicNodeLocalTestService("other", "other-service-uid", "edge", corev1.ProtocolTCP, 8080)
	otherDesired, err := f.controller.desiredServiceFirewall(other)
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.api.CreateFirewall(f.ctx, "bkk01", otherDesired.Request)
	if err != nil {
		t.Fatal(err)
	}
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	if err := f.api.AssignFirewallToVM(f.ctx, "bkk01", created.UUID, vm0); err != nil {
		t.Fatal(err)
	}
	createdBefore := len(f.api.createdFirewalls)
	for pass := 0; pass < 40; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
	}
	if len(f.api.createdFirewalls) != createdBefore {
		t.Fatalf("the Service created a per-VM firewall on a VM with a per-Service firewall: %#v", f.api.createdFirewalls)
	}
	if len(f.current(t).Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("the Service published while its VM was unmigrated: %#v", f.current(t).Status)
	}
	waiting := 0
	events, err := f.provider.kubeClient.CoreV1().Events("default").List(f.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Items {
		if event.Reason == publicNodeLocalReasonVMFirewallMigrationWaiting {
			waiting++
		}
	}
	if waiting == 0 {
		t.Fatal("no PublicNodeLocalVMFirewallMigrationWaiting Event was recorded")
	}
}
