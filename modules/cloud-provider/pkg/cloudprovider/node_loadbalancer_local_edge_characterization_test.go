package cloudprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

var updateEdgeGolden = flag.Bool("update-edge-golden", false, "rewrite testdata/public_node_local_edge_golden.json")

const publicNodeLocalEdgeGoldenPath = "testdata/public_node_local_edge_golden.json"

// publicNodeLocalEdgeTrace is everything a public-node-local scenario writes to
// the cloud and to the Service annotations. The edge refactor must leave it
// byte-identical.
type publicNodeLocalEdgeTrace struct {
	// Passes is the outcome class of each reconcile pass after the setup.
	Passes []string `json:"passes"`
	// Calls is the ordered mutation log of the cloud API after the setup.
	Calls []string `json:"calls"`
	// The fake API mutation slices, cumulative since the fixture was built.
	CreatedFirewalls    []string `json:"createdFirewalls"`
	UpdatedFirewalls    []string `json:"updatedFirewalls"`
	DeletedFirewalls    []string `json:"deletedFirewalls"`
	AssignedFirewalls   []string `json:"assignedFirewalls"`
	UnassignedFirewalls []string `json:"unassignedFirewalls"`
	UnassignedIPs       []string `json:"unassignedIPs"`
	// Final state.
	FloatingIPs         []string          `json:"floatingIPs"`
	FirewallAssignments []string          `json:"firewallAssignments"`
	Ingress             []string          `json:"ingress"`
	Finalizers          []string          `json:"finalizers"`
	Annotations         map[string]string `json:"annotations"`
	ChildAnnotations    map[string]string `json:"childAnnotations"`
	ChildPorts          []int32           `json:"childPorts"`
}

// edgeRecordingAPI logs every mutating cloud call in order.
type edgeRecordingAPI struct {
	API
	log *[]string
}

func (a *edgeRecordingAPI) note(format string, args ...any) {
	*a.log = append(*a.log, fmt.Sprintf(format, args...))
}

func (a *edgeRecordingAPI) CreateFirewall(ctx context.Context, location string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	a.note("CreateFirewall %s", request.DisplayName)
	return a.API.CreateFirewall(ctx, location, request)
}

func (a *edgeRecordingAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	a.note("UpdateFirewall %s %s", uuid, request.Name)
	return a.API.UpdateFirewall(ctx, location, uuid, request)
}

func (a *edgeRecordingAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	a.note("DeleteFirewall %s", uuid)
	return a.API.DeleteFirewall(ctx, location, uuid)
}

func (a *edgeRecordingAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	a.note("AssignFirewallToVM %s %s", firewallUUID, vmUUID)
	return a.API.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func (a *edgeRecordingAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	a.note("UnassignFirewallFromVM %s %s", firewallUUID, vmUUID)
	return a.API.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

func (a *edgeRecordingAPI) AssignFloatingIP(ctx context.Context, location, address, uuid, resourceType string) (*inspace.FloatingIP, error) {
	a.note("AssignFloatingIP %s %s", address, uuid)
	return a.API.AssignFloatingIP(ctx, location, address, uuid, resourceType)
}

func (a *edgeRecordingAPI) UnassignFloatingIP(ctx context.Context, location, address string) (*inspace.FloatingIP, error) {
	a.note("UnassignFloatingIP %s", address)
	return a.API.UnassignFloatingIP(ctx, location, address)
}

// edgeScenarioRun drives one scenario on a fixture with a fixed clock.
type edgeScenarioRun struct {
	t      *testing.T
	f      *publicNodeLocalTransientFixture
	now    time.Time
	log    []string
	passes []string
}

func newEdgeScenarioRun(t *testing.T, f *publicNodeLocalTransientFixture) *edgeScenarioRun {
	t.Helper()
	r := &edgeScenarioRun{t: t, f: f, now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	f.provider.api = &edgeRecordingAPI{API: f.provider.api, log: &r.log}
	r.installClock()
	return r
}

func (r *edgeScenarioRun) installClock() {
	r.f.controller.publicNodeLocalNow = func() time.Time { return r.now }
}

// pass runs one reconcile and records the class of its outcome.
func (r *edgeScenarioRun) pass() {
	r.t.Helper()
	if current := r.f.current(r.t); current.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
		ageNodeLoadBalancerAbsenceEvidence(r.t, r.f.ctx, r.f.provider, current, annotationNodeLoadBalancerCleanupFWChecked)
	}
	err := r.f.controller.syncPublicNodeLocal(r.f.ctx, r.f.key, r.f.current(r.t))
	var holding *errPublicNodeLocalHolding
	var pending *nodeLoadBalancerFirewallRelationPendingError
	switch {
	case err == nil:
		r.passes = append(r.passes, "ok")
	case errors.As(err, &holding):
		r.passes = append(r.passes, "hold")
	case errors.As(err, &pending):
		r.passes = append(r.passes, "relation-pending")
	case strings.Contains(err.Error(), "waiting for"):
		r.passes = append(r.passes, "waiting")
	case inspace.IsTransient(err):
		r.passes = append(r.passes, "transient")
	default:
		msg := err.Error()
		if len(msg) > 90 {
			msg = msg[:90]
		}
		r.passes = append(r.passes, "error: "+msg)
	}
}

// until runs passes until done holds or the limit is reached.
func (r *edgeScenarioRun) until(limit int, done func() bool) {
	r.t.Helper()
	for i := 0; i < limit; i++ {
		r.pass()
		if done != nil && done() {
			return
		}
	}
}

func maskEdgeAnnotations(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		if strings.HasSuffix(key, "-at") || strings.HasSuffix(key, "-since") || strings.HasSuffix(key, "-checked-at") {
			out[key] = "<t>"
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err == nil {
			out[key] = "<t>"
			continue
		}
		out[key] = value
	}
	return out
}

// recordPublicNodeLocalEdgeTrace snapshots the mutations and the final state.
func recordPublicNodeLocalEdgeTrace(t *testing.T, f *publicNodeLocalTransientFixture) publicNodeLocalEdgeTrace {
	t.Helper()
	trace := publicNodeLocalEdgeTrace{
		Passes: []string{}, Calls: []string{},
		CreatedFirewalls: []string{}, UpdatedFirewalls: []string{},
		AssignedFirewalls:   append([]string{}, f.api.assignedFirewalls...),
		UnassignedFirewalls: append([]string{}, f.api.unassignedFirewalls...),
		UnassignedIPs:       append([]string{}, f.api.unassignedIPs...),
		DeletedFirewalls:    append([]string{}, f.api.deletedFirewalls...),
		FloatingIPs:         []string{}, FirewallAssignments: []string{}, Ingress: []string{},
	}
	for _, request := range f.api.createdFirewalls {
		trace.CreatedFirewalls = append(trace.CreatedFirewalls, request.DisplayName)
	}
	for _, request := range f.api.updatedFirewalls {
		trace.UpdatedFirewalls = append(trace.UpdatedFirewalls, request.Name)
	}
	for _, ip := range f.api.floatingIPs {
		trace.FloatingIPs = append(trace.FloatingIPs, ip.Address+"="+ip.AssignedTo)
	}
	for _, firewall := range f.api.firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			trace.FirewallAssignments = append(trace.FirewallAssignments, firewall.UUID+"/"+resource.ResourceUUID)
		}
	}
	sort.Strings(trace.FloatingIPs)
	sort.Strings(trace.FirewallAssignments)
	current := f.current(t)
	for _, ingress := range current.Status.LoadBalancer.Ingress {
		trace.Ingress = append(trace.Ingress, ingress.IP)
	}
	trace.Finalizers = append([]string{}, current.Finalizers...)
	trace.Annotations = maskEdgeAnnotations(current.Annotations)
	if child := trackedPublicNodeLocalDatapathOrNil(f); child != nil {
		trace.ChildAnnotations = maskEdgeAnnotations(child.Annotations)
		trace.ChildPorts = []int32{}
		for _, port := range child.Spec.Ports {
			trace.ChildPorts = append(trace.ChildPorts, port.Port)
		}
	}
	return trace
}

func (r *edgeScenarioRun) trace() publicNodeLocalEdgeTrace {
	r.t.Helper()
	trace := recordPublicNodeLocalEdgeTrace(r.t, r.f)
	trace.Passes = append(trace.Passes, r.passes...)
	trace.Calls = append(trace.Calls, r.log...)
	return trace
}

func edgeUnpublished(r *edgeScenarioRun, index int) func() bool {
	_, vmUUID, privateIP, publicIP := publicNodeLocalFixtureNode(index)
	return func() bool {
		o := observePublicNodeLocal(r.t, r.f)
		return !o.fips[publicIP] && !o.vips[privateIP] && !o.assigned[vmUUID]
	}
}

func edgePublished(r *edgeScenarioRun, index int) func() bool {
	_, vmUUID, privateIP, publicIP := publicNodeLocalFixtureNode(index)
	return func() bool {
		o := observePublicNodeLocal(r.t, r.f)
		return o.fips[publicIP] && o.vips[privateIP] && o.assigned[vmUUID] && !publicNodeLocalAssignmentFencePresent(r.f.current(r.t))
	}
}

func edgePolicySettled(r *edgeScenarioRun) func() bool {
	return func() bool {
		s := r.f.current(r.t)
		return s.Annotations[annotationPublicNodeLocalTargetPolicy] == "" && s.Annotations[annotationPublicNodeLocalTargetPool] == "" &&
			s.Annotations[annotationNodeLoadBalancerPreviousFirewall] == "" && !publicNodeLocalAssignmentFencePresent(s)
	}
}

func edgeCharacterizationScenarios() []struct {
	name string
	run  func(t *testing.T) publicNodeLocalEdgeTrace
} {
	return []struct {
		name string
		run  func(t *testing.T) publicNodeLocalEdgeTrace
	}{
		{"bootstrap 3 nodes", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 3)
			r := newEdgeScenarioRun(t, f)
			r.until(3, nil)
			return r.trace()
		}},
		{"add node", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			f.addNode(t, 1)
			r := newEdgeScenarioRun(t, f)
			r.until(60, edgePublished(r, 1))
			return r.trace()
		}},
		{"remove node", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			r := newEdgeScenarioRun(t, f)
			f.setEndpoints(t, "edge-0")
			r.until(1, nil)
			r.now = r.now.Add(publicNodeLocalEndpointGoneGrace + time.Second)
			r.until(40, edgeUnpublished(r, 1))
			return r.trace()
		}},
		{"port widening", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
			r := newEdgeScenarioRun(t, f)
			r.until(200, func() bool {
				return edgePolicySettled(r)() && r.f.current(t).Annotations[annotationPublicNodeLocalActivePolicy] != "886b49b4"
			})
			return r.trace()
		}},
		{"port narrowing", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureWith(t, 2, shapePublicNodeLocalPorts(443, 80))
			setPublicNodeLocalFixturePorts(t, f, 443)
			r := newEdgeScenarioRun(t, f)
			r.until(200, func() bool {
				return edgePolicySettled(r)() && len(childPortSet(trackedPublicNodeLocalDatapath(t, r.f))) == 1
			})
			return r.trace()
		}},
		{"pool change", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureWith(t, 1, nil)
			f.addNode(t, 1)
			moveFixtureNodeToPool(t, f, 1, "spe-relay-share")
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
			r := newEdgeScenarioRun(t, f)
			r.until(200, func() bool {
				s := r.f.current(t)
				return edgePolicySettled(r)() && s.Annotations[annotationPublicNodeLocalActivePool] == "spe-relay-share" && edgeUnpublished(r, 0)()
			})
			return r.trace()
		}},
		{"pool change without Nodes holds", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "other" })
			r := newEdgeScenarioRun(t, f)
			r.until(8, nil)
			return r.trace()
		}},
		{"peer on another pool", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			addPublicNodeLocalFixturePeer(t, f, "peer", "peer-uid", "other-pool", 443)
			r := newEdgeScenarioRun(t, f)
			r.until(4, nil)
			return r.trace()
		}},
		{"pool change refused by a peer", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			addPublicNodeLocalFixturePeer(t, f, "peer", "peer-uid", "spe-relay-share", 443)
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerPool] = "spe-relay-share" })
			r := newEdgeScenarioRun(t, f)
			r.until(5, nil)
			return r.trace()
		}},
		{"withdraw all nodes gone", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			for _, name := range []string{"edge-0", "edge-1"} {
				if err := f.provider.kubeClient.CoreV1().Nodes().Delete(f.ctx, name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			f.setEndpoints(t)
			r := newEdgeScenarioRun(t, f)
			r.until(60, func() bool {
				s := r.f.current(t)
				return len(s.Status.LoadBalancer.Ingress) == 0 && s.Annotations[annotationPublicNodeLocalActivePool] == ""
			})
			return r.trace()
		}},
		{"withdraw and rebuild on allow-rebuild", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 1)
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) { s.Annotations[annotationNodeLoadBalancerAllowRebuild] = "true" })
			r := newEdgeScenarioRun(t, f)
			r.until(80, func() bool {
				s := r.f.current(t)
				desired, err := r.f.controller.desiredServiceFirewall(s)
				return err == nil && len(s.Status.LoadBalancer.Ingress) == 1 &&
					s.Annotations[annotationPublicNodeLocalActivePolicy] == desired.Hash && !publicNodeLocalAssignmentFencePresent(s)
			})
			return r.trace()
		}},
		{"service deleted", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			// The fake API server assigns no UID, and the cleanup refuses to
			// delete a child without one.
			child := trackedPublicNodeLocalDatapath(t, f)
			child.UID = "child-datapath-uid"
			if _, err := f.provider.kubeClient.CoreV1().Services(child.Namespace).Update(f.ctx, child, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			updatePublicNodeLocalFixtureService(t, f, func(s *corev1.Service) {
				now := metav1.NewTime(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
				s.DeletionTimestamp = &now
			})
			r := newEdgeScenarioRun(t, f)
			r.until(60, func() bool { return len(r.f.current(t).Finalizers) == 0 })
			return r.trace()
		}},
		{"restart mid policy change", func(t *testing.T) publicNodeLocalEdgeTrace {
			f := newPublishedPublicNodeLocalFixtureN(t, 2)
			setPublicNodeLocalFixturePorts(t, f, 443, 8443)
			r := newEdgeScenarioRun(t, f)
			r.until(6, nil)
			restartPublicNodeLocalController(f)
			r.installClock()
			r.until(200, func() bool {
				return edgePolicySettled(r)() && r.f.current(t).Annotations[annotationPublicNodeLocalActivePolicy] != "886b49b4"
			})
			return r.trace()
		}},
	}
}

func TestPublicNodeLocalEdgeCharacterization(t *testing.T) {
	traces := map[string]publicNodeLocalEdgeTrace{}
	for _, scenario := range edgeCharacterizationScenarios() {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			traces[scenario.name] = scenario.run(t)
		})
	}
	got, err := json.MarshalIndent(traces, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateEdgeGolden {
		if err := os.WriteFile(publicNodeLocalEdgeGoldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(publicNodeLocalEdgeGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the public-node-local edge trace changed (run with -update-edge-golden only for a deliberate behaviour change)\n%s", firstEdgeGoldenDiff(string(want), string(got)))
	}
}

func firstEdgeGoldenDiff(want, got string) string {
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wantLines) && i < len(gotLines); i++ {
		if wantLines[i] != gotLines[i] {
			return fmt.Sprintf("first difference at line %d:\nwant: %s\n got: %s", i+1, wantLines[i], gotLines[i])
		}
	}
	return fmt.Sprintf("length differs: want %d lines, got %d lines", len(wantLines), len(gotLines))
}
