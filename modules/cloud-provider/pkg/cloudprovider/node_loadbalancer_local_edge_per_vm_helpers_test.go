package cloudprovider

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A peer that exposes nothing through its own Kubernetes state is still exposed
// while a VM firewall ledger lists it.
func TestPerVMServiceStillExposedThroughVMFirewall(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	// Strip every Kubernetes trace of the exposure, as a lost status would.
	service := f.current(t)
	service.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	if _, err := f.provider.kubeClient.CoreV1().Services(service.Namespace).UpdateStatus(f.ctx, service, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := f.controller.clearPublicNodeLocalDatapathStatus(f.ctx, service); err != nil {
		t.Fatal(err)
	}
	if err := f.controller.clearPublicNodeLocalActivation(f.ctx, f.current(t)); err != nil {
		t.Fatal(err)
	}
	exposed, err := f.controller.publicNodeLocalServiceStillExposed(f.ctx, f.current(t))
	if err != nil || !exposed {
		t.Fatalf("exposed = %t, %v; a ledger entry on a VM firewall is an exposure", exposed, err)
	}
	for pass := 0; pass < 40; pass++ {
		if proven, err := f.controller.publicNodeLocalEdgeFor(f.current(t)).WithdrawAll(f.ctx, f.current(t)); err == nil && proven {
			break
		}
	}
	exposed, err = f.controller.publicNodeLocalServiceStillExposed(f.ctx, f.current(t))
	if err != nil || exposed {
		t.Fatalf("exposed after the withdrawal = %t, %v", exposed, err)
	}
}

// A Service that lived on the per-VM firewall is finalized only after its
// entries are off the VMs and the readback shows it.
func TestPerVMCleanupRemovesMembersAndFinalizesAfterReadback(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	child := trackedPublicNodeLocalDatapath(t, f)
	child.UID = "child-datapath-uid"
	if _, err := f.provider.kubeClient.CoreV1().Services(child.Namespace).Update(f.ctx, child, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		now := metav1.NewTime(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
		s.DeletionTimestamp = &now
	})
	finalized := false
	for pass := 0; pass < 120 && !finalized; pass++ {
		_ = f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t))
		requireVMEdgeSafe(t, f)
		finalized = len(f.current(t).Finalizers) == 0
		if finalized {
			closed, open, err := f.controller.vmFirewallServiceClosed(f.ctx, string(f.service.UID))
			if err != nil || !closed {
				t.Fatalf("finalized with entries left on %v (%v)", open, err)
			}
		}
	}
	if !finalized {
		t.Fatalf("the cleanup never finalized: %#v", f.current(t).Annotations)
	}
	for i := 0; i < 2; i++ {
		_, vmUUID, _, _ := publicNodeLocalFixtureNode(i)
		if got := len(vmFirewallsOfVM(f, vmUUID)); got != 1 {
			t.Fatalf("VM %d still carries %d firewalls, want only the base", i, got)
		}
	}
	for _, key := range []string{annotationPublicNodeLocalFirewallMode, annotationPublicNodeLocalAssignEdge, annotationPublicNodeLocalPromotedAt} {
		if got := f.current(t).Annotations[key]; got != "" {
			t.Fatalf("annotation %s = %q survived the cleanup", key, got)
		}
	}
}

// With the mode off, a Service that lives on the per-VM firewall is not
// finalized: its entries would be orphaned.
func TestPerVMCleanupHoldsWhenTheModeIsOff(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 1)
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		now := metav1.NewTime(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
		s.DeletionTimestamp = &now
	})
	f.provider.config.NodeLoadBalancer.LocalFirewallMode = PublicNodeLocalFirewallModePerService
	mutations := len(f.api.unassignedFirewalls) + len(f.api.deletedFirewalls) + len(f.api.updatedFirewalls)
	for pass := 0; pass < 5; pass++ {
		if err := f.controller.syncPublicNodeLocal(f.ctx, f.key, f.current(t)); err == nil {
			t.Fatalf("pass %d: the cleanup must hold", pass)
		}
	}
	if len(f.current(t).Finalizers) == 0 {
		t.Fatal("the Service was finalized with its entries on the VM firewalls")
	}
	if got := len(f.api.unassignedFirewalls) + len(f.api.deletedFirewalls) + len(f.api.updatedFirewalls); got != mutations {
		t.Fatal("a firewall was touched with the mode off")
	}
}

// A lost child is rebuilt from the rules of the ledger entry the Service serves
// under, not from a per-Service firewall it does not have.
func TestPerVMLostChildIsRebuiltFromTheLedger(t *testing.T) {
	f := newPerVMPublicNodeLocalFixtureWith(t, 1, func(s *corev1.Service) {
		shapePublicNodeLocalPorts(443, 80)(s)
		s.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"}
	})
	child, err := f.controller.publicNodeLocalChildFromActiveFirewall(f.ctx, f.current(t))
	if err != nil || child == nil {
		t.Fatalf("child = %v, %v", child, err)
	}
	ports := childPortSet(child)
	if len(ports) != 2 || !ports[443] || !ports[80] {
		t.Fatalf("rebuilt ports = %v", ports)
	}
	if got := child.Spec.LoadBalancerSourceRanges; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("rebuilt source ranges = %v", got)
	}
}

// The rebuild journal lists the VM firewall/VM pairs the Service has an entry on,
// and a pair counts as read back once the entry is off the VM.
func TestPerVMAssignedPairsJournalVMFirewalls(t *testing.T) {
	f := newPerVMPublicNodeLocalFixture(t, 2)
	pairs, err := f.controller.publicNodeLocalAssignedPairs(f.ctx, f.current(t))
	if err != nil {
		t.Fatal(err)
	}
	_, vm0, _, _ := publicNodeLocalFixtureNode(0)
	_, vm1, _, _ := publicNodeLocalFixtureNode(1)
	listed := strings.Split(pairs, ",")
	if len(listed) != 2 || !strings.HasSuffix(listed[0], "/"+vm0) || !strings.HasSuffix(listed[1], "/"+vm1) {
		t.Fatalf("pairs = %q", pairs)
	}
	updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
		s.Annotations[annotationNodeLoadBalancerRebuildingAssigned] = pairs
	})
	if readBack, err := f.controller.publicNodeLocalRebuildDetachReadBack(f.ctx, f.current(t)); err != nil || readBack {
		t.Fatalf("read back = %t, %v before any detach", readBack, err)
	}
	for pass := 0; pass < 40; pass++ {
		if proven, err := f.controller.publicNodeLocalEdgeFor(f.current(t)).WithdrawAll(f.ctx, f.current(t)); err == nil && proven {
			break
		}
	}
	if readBack, err := f.controller.publicNodeLocalRebuildDetachReadBack(f.ctx, f.current(t)); err != nil || !readBack {
		t.Fatalf("read back = %t, %v after the withdrawal", readBack, err)
	}
}
