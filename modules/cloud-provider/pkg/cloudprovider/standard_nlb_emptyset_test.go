package cloudprovider

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/tools/record"
)

const goneVM = "99999999-1111-4222-8333-444444444444"

func newEmptySetFixture(t *testing.T, current ...string) (*retireFixture, *record.FakeRecorder) {
	t.Helper()
	f := newRetireFixture(t)
	events := record.NewFakeRecorder(16)
	f.provider.standardNLBEvents = events
	setOwnedLoadBalancer(f.api.fakeAPI, f.provider, f.service, current)
	return f, events
}

func drainEvents(events *record.FakeRecorder) []string {
	var got []string
	for {
		select {
		case event := <-events.Events:
			got = append(got, event)
		default:
			return got
		}
	}
}

func TestEmptyDesiredSetEmitsOneEventAndKeepsTargets(t *testing.T) {
	f, events := newEmptySetFixture(t, testVMUUID, goneVM)
	run := f.reconcile()

	for range 3 {
		f.advance(time.Minute)
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainEvents(events); len(got) != 1 {
		t.Fatalf("events = %v, want exactly one", got)
	}
	if len(f.api.removedTargets) != 0 || len(f.api.lbs[0].Targets) != 2 {
		t.Fatalf("grace period removed targets: %v", f.api.removedTargets)
	}
	current, err := f.provider.standardNLBServiceStore.GetExact(context.Background(), f.service)
	if err != nil || current.Annotations[annotationStandardNLBEmptyTargetsSince] == "" {
		t.Fatalf("empty-set start was not recorded: %v %v", err, current.Annotations)
	}
}

func TestEmptyDesiredSetAfterGraceRemovesOnlyTargetsWhoseVMIsGone(t *testing.T) {
	f, _ := newEmptySetFixture(t, testVMUUID, goneVM)
	run := f.reconcile()

	if err := run(); err != nil {
		t.Fatal(err)
	}
	f.advance(emptyTargetSetGrace + time.Minute)
	requireStandardNLBConvergence(t, func() error {
		f.advance(standardNLBRemovalAbsenceDelay + time.Second)
		return run()
	})
	if !reflectStrings(f.api.removedTargets, []string{goneVM}) {
		t.Fatalf("removed %v, want only the target whose VM is gone", f.api.removedTargets)
	}
	if len(f.api.lbs[0].Targets) != 1 || f.api.lbs[0].Targets[0].TargetUUID != testVMUUID {
		t.Fatalf("remaining targets = %v", f.api.lbs[0].Targets)
	}
}

func TestEmptyDesiredSetRecoveryClearsTheGraceMark(t *testing.T) {
	f, _ := newEmptySetFixture(t, testVMUUID)

	if err := f.reconcile()(); err != nil {
		t.Fatal(err)
	}
	// The informer cache catches up with the mark the controller wrote.
	marked, err := f.provider.standardNLBServiceStore.GetExact(context.Background(), f.service)
	if err != nil {
		t.Fatal(err)
	}
	f.service.Annotations[annotationStandardNLBEmptyTargetsSince] = marked.Annotations[annotationStandardNLBEmptyTargetsSince]
	if err := f.reconcile(testVMUUID)(); err != nil {
		t.Fatal(err)
	}
	current, err := f.provider.standardNLBServiceStore.GetExact(context.Background(), f.service)
	if err != nil || current.Annotations[annotationStandardNLBEmptyTargetsSince] != "" {
		t.Fatalf("grace mark survived a recovered target set: %v %v", err, current.Annotations)
	}
}
