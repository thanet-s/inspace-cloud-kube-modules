package cloudprovider

import (
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// edgeTwin is one of two identical fixtures whose cloud mutations are logged.
type edgeTwin struct {
	f   *publicNodeLocalTransientFixture
	log []string
}

func newEdgeTwin(t *testing.T, nodes int, prepare func(*testing.T, *publicNodeLocalTransientFixture)) *edgeTwin {
	t.Helper()
	f := newPublishedPublicNodeLocalFixtureN(t, nodes)
	if prepare != nil {
		prepare(t, f)
	}
	twin := &edgeTwin{f: f}
	f.provider.api = &edgeRecordingAPI{API: f.provider.api, log: &twin.log}
	return twin
}

func (w *edgeTwin) node(t *testing.T, index int) *corev1.Node {
	t.Helper()
	name, _, _, _ := publicNodeLocalFixtureNode(index)
	node, err := w.f.provider.kubeClient.CoreV1().Nodes().Get(w.f.ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func (w *edgeTwin) address(t *testing.T, index int) nodeLoadBalancerAddress {
	_, _, privateIP, publicIP := publicNodeLocalFixtureNode(index)
	return nodeLoadBalancerAddress{Node: w.node(t, index), PrivateIPv4: privateIP, PublicIPv4: publicIP}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// firewallIdentity is what the caller sees of a firewall pointer.
func firewallIdentity(firewall *inspace.Firewall) string {
	if firewall == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s|%s|%d rules|%d resources", firewall.UUID, firewall.EffectiveName(), len(firewall.Rules), len(firewall.ResourcesAssigned))
}

// requireTwinsEqual compares the cloud mutation logs and the Service
// annotations of the twins after a call on each.
func requireTwinsEqual(t *testing.T, what string, old, edge *edgeTwin, oldResult, edgeResult any) {
	t.Helper()
	if !reflect.DeepEqual(oldResult, edgeResult) {
		t.Fatalf("%s: results differ\n old: %#v\nedge: %#v", what, oldResult, edgeResult)
	}
	if !reflect.DeepEqual(old.log, edge.log) {
		t.Fatalf("%s: cloud mutations differ\n old: %v\nedge: %v", what, old.log, edge.log)
	}
	oa, ea := maskEdgeAnnotations(old.f.current(t).Annotations), maskEdgeAnnotations(edge.f.current(t).Annotations)
	if !reflect.DeepEqual(oa, ea) {
		t.Fatalf("%s: Service annotations differ\n old: %v\nedge: %v", what, oa, ea)
	}
	if !reflect.DeepEqual(old.f.api.firewalls, edge.f.api.firewalls) {
		t.Fatalf("%s: firewalls differ\n old: %#v\nedge: %#v", what, old.f.api.firewalls, edge.f.api.firewalls)
	}
}

func TestPerServiceEdgeDelegatesExactly(t *testing.T) {
	widened := func(t *testing.T, f *publicNodeLocalTransientFixture) {
		setPublicNodeLocalFixturePorts(t, f, 443, 8443)
	}
	pair := func(t *testing.T, nodes int, prepare func(*testing.T, *publicNodeLocalTransientFixture)) (old, edge *edgeTwin) {
		t.Helper()
		return newEdgeTwin(t, nodes, prepare), newEdgeTwin(t, nodes, prepare)
	}
	desiredOf := func(t *testing.T, w *edgeTwin) (nodeLoadBalancerIntent, desiredNodeLoadBalancerFirewall) {
		t.Helper()
		service := w.f.current(t)
		intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: w.f.provider.config.NodeLoadBalancer.NodesPerShard})
		if err != nil {
			t.Fatal(err)
		}
		desired, err := w.f.controller.desiredServiceFirewall(service)
		if err != nil {
			t.Fatal(err)
		}
		return intent, desired
	}

	for name, prepare := range map[string]func(*testing.T, *publicNodeLocalTransientFixture){"steady": nil, "port widened": widened} {
		t.Run("Prepare/"+name, func(t *testing.T) {
			old, edge := pair(t, 2, prepare)
			_, desired := desiredOf(t, old)
			oldSvc, oldCur, oldPrev, oldWait, oldErr := old.f.controller.preparePublicNodeLocalFirewall(old.f.ctx, old.f.current(t))
			edgeSvc, edgeCur, edgePrev, edgeWait, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Prepare(edge.f.ctx, edge.f.current(t), desired)
			if edgeCur.snapshot != nil && edgeCur.firewallUUID != edgeCur.snapshot.UUID || edgeCur.fenceValue() != edgeCur.firewallUUID {
				t.Fatalf("edge identity is inconsistent: %#v", edgeCur)
			}
			requireTwinsEqual(t, "Prepare", old, edge,
				[]any{oldSvc.Annotations, firewallIdentity(oldCur), firewallIdentity(oldPrev), oldWait, errText(oldErr)},
				[]any{edgeSvc.Annotations, firewallIdentity(edgeCur.snapshot), firewallIdentity(edgePrev.snapshot), edgeWait, errText(edgeErr)})
		})
	}

	t.Run("Active", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		policy := old.f.current(t).Annotations[annotationPublicNodeLocalActivePolicy]
		for _, activePolicy := range []string{policy, "not-the-policy"} {
			oldCur, oldPrev, oldErr := old.f.controller.activePublicNodeLocalFirewall(old.f.ctx, old.f.current(t), activePolicy)
			edgeCur, edgePrev, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Active(edge.f.ctx, edge.f.current(t), activePolicy)
			requireTwinsEqual(t, "Active "+activePolicy, old, edge,
				[]any{firewallIdentity(oldCur), firewallIdentity(oldPrev), errText(oldErr)},
				[]any{firewallIdentity(edgeCur.snapshot), firewallIdentity(edgePrev.snapshot), errText(edgeErr)})
		}
	})

	t.Run("Assigned", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		_, desired := desiredOf(t, old)
		_, oldCur, _, _, _ := old.f.controller.preparePublicNodeLocalFirewall(old.f.ctx, old.f.current(t))
		_, edgeCur, _, _, _ := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Prepare(edge.f.ctx, edge.f.current(t), desired)
		oldSet, oldErr := nodeLoadBalancerFirewallVMAssignments(*oldCur)
		edgeSet, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Assigned(edge.f.ctx, edge.f.current(t), edgeCur)
		if len(oldSet) != 2 {
			t.Fatalf("fixture has %d assignments, want 2", len(oldSet))
		}
		requireTwinsEqual(t, "Assigned", old, edge, []any{oldSet, errText(oldErr)}, []any{edgeSet, errText(edgeErr)})
	})

	t.Run("ResolvePending", func(t *testing.T) {
		for name, receipt := range map[string]bool{"no receipt": false, "receipt": true} {
			old, edge := pair(t, 2, func(t *testing.T, f *publicNodeLocalTransientFixture) {
				if receipt {
					updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
						s.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] = "unknown-owner"
					})
				}
			})
			var oldResolved bool
			var oldErr error
			svc := old.f.current(t)
			if svc.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" || svc.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
				_, oldErr = old.f.controller.reconcileNodeLoadBalancerFirewallRelation(old.f.ctx, old.f.controller.serviceFirewallRelationOwner(svc), nil)
			} else {
				oldResolved = true
			}
			edgeResolved, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(svc).ResolvePending(edge.f.ctx, edge.f.current(t))
			requireTwinsEqual(t, "ResolvePending "+name, old, edge, []any{oldResolved, errText(oldErr)}, []any{edgeResolved, errText(edgeErr)})
		}
	})

	t.Run("Assign", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		intent, desired := desiredOf(t, old)
		_, oldCur, _, _, _ := old.f.controller.preparePublicNodeLocalFirewall(old.f.ctx, old.f.current(t))
		_, edgeCur, _, _, _ := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Prepare(edge.f.ctx, edge.f.current(t), desired)
		oldAddrs := []nodeLoadBalancerAddress{old.address(t, 0), old.address(t, 1)}
		edgeAddrs := []nodeLoadBalancerAddress{edge.address(t, 0), edge.address(t, 1)}
		oldErr := old.f.controller.assignPublicNodeLocalFirewallWithFence(old.f.ctx, old.f.current(t), intent, desired, oldCur, oldAddrs)
		converged, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Assign(edge.f.ctx, edge.f.current(t), intent, desired, edgeCur, edgeAddrs)
		requireTwinsEqual(t, "Assign", old, edge, []any{oldErr == nil, errText(oldErr)}, []any{converged, errText(edgeErr)})
	})

	t.Run("Unassign", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		_, desired := desiredOf(t, old)
		_, oldCur, _, _, _ := old.f.controller.preparePublicNodeLocalFirewall(old.f.ctx, old.f.current(t))
		_, edgeCur, _, _, _ := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Prepare(edge.f.ctx, edge.f.current(t), desired)
		oldParked, oldErr := old.f.controller.detachServiceFirewallFromOtherNodesParked(old.f.ctx, old.f.current(t), oldCur, []*corev1.Node{old.node(t, 0)})
		edgeParked, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Unassign(edge.f.ctx, edge.f.current(t), edgeCur, []*corev1.Node{edge.node(t, 0)})
		if len(old.log) == 0 {
			t.Fatal("the fixture detached nothing, so the comparison proves nothing")
		}
		requireTwinsEqual(t, "Unassign", old, edge, []any{oldParked, errText(oldErr)}, []any{edgeParked, errText(edgeErr)})
	})

	t.Run("Retire", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		oldErr := old.f.controller.cleanupPreviousFirewall(old.f.ctx, old.f.current(t))
		done, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).Retire(edge.f.ctx, edge.f.current(t), edgeID{})
		requireTwinsEqual(t, "Retire", old, edge, []any{oldErr == nil, errText(oldErr)}, []any{done, errText(edgeErr)})
	})

	t.Run("WithdrawAll", func(t *testing.T) {
		old, edge := pair(t, 2, nil)
		var oldProven bool
		oldErr := old.f.controller.detachOwnedServiceFirewallsForFailure(old.f.ctx, old.f.current(t))
		if oldErr == nil {
			oldProven, oldErr = old.f.controller.serviceFirewallsDetached(old.f.ctx, old.f.current(t))
		}
		proven, edgeErr := edge.f.controller.publicNodeLocalEdgeFor(edge.f.current(t)).WithdrawAll(edge.f.ctx, edge.f.current(t))
		if len(old.log) == 0 {
			t.Fatal("the fixture detached nothing, so the comparison proves nothing")
		}
		requireTwinsEqual(t, "WithdrawAll", old, edge, []any{oldProven, errText(oldErr)}, []any{proven, errText(edgeErr)})
	})
}
