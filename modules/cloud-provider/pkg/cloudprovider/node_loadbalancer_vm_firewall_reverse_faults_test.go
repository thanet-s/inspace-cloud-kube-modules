package cloudprovider

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ageServiceCreateReceipts moves the wall-clock stamps of the Services' own
// firewall create receipts into the past. Those receipts (v1.1.9 code the reverse
// migration reuses to create a Service's firewall) are timed by the real clock,
// which the fault runs do not advance; without this a lost create would wait for
// minutes of real time. The write goes around the fault reactors.
func (m *migrationCluster) ageServiceCreateReceipts(age time.Duration) {
	m.t.Helper()
	for _, name := range m.services {
		svc := m.service(name)
		copy := svc.DeepCopy()
		changed := false
		for _, key := range []string{
			annotationNodeLoadBalancerPendingFWStarted, annotationNodeLoadBalancerPendingFWIssuedAt, annotationNodeLoadBalancerPendingFWChecked,
		} {
			raw := copy.Annotations[key]
			if raw == "" {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				continue
			}
			copy.Annotations[key] = at.Add(-age).UTC().Format(time.RFC3339Nano)
			changed = true
		}
		if !changed {
			continue
		}
		if err := m.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("services"), copy, copy.Namespace); err != nil {
			m.t.Fatal(err)
		}
	}
}

// runTHLiveReverseWithFault is the reverse migration of th-live with one fault: the
// forward migration runs clean, then the mode is turned off and the fault hits
// the k-th write or the k-th mutating cloud call of the way back.
func runTHLiveReverseWithFault(t *testing.T, kind migrationFault, at int) migrationFaultRun {
	return runMigrationWithFault(t, kind, at,
		func(t *testing.T) *migrationCluster {
			m := newTHLiveCluster(t)
			migrateTHLiveForward(m)
			m.trackCoverage()
			m.afterPass = func() { m.ageServiceCreateReceipts(10 * time.Minute) }
			return m
		},
		(*migrationCluster).switchToPerService,
		(*migrationCluster).allReversed)
}

// Fault the reverse migration of th-live at every write and every mutating cloud
// call, in each way a real failure looks, and require the same end state: at most
// one create per firewall, at most one rename PUT, never a fourth firewall on a
// VM, no refused attach, every served port covered between any two cloud calls,
// and no per-VM state left.
func TestReverseMigrationRestartAtEveryPhase(t *testing.T) {
	baseline := runTHLiveReverseWithFault(t, faultNone, 0)
	if baseline.outcome.writes < 20 || len(baseline.cloud) < 8 {
		t.Fatalf("baseline = %#v: the harness saw too few writes or calls", baseline)
	}
	check := func(t *testing.T, kind migrationFault, at int) {
		got := runTHLiveReverseWithFault(t, kind, at)
		if !got.fired {
			t.Fatalf("the harness never injected %s at %d of %d writes / %d calls", kind, at, baseline.outcome.writes, len(baseline.cloud))
		}
		if !reflect.DeepEqual(got.outcome.firewalls, baseline.outcome.firewalls) || !reflect.DeepEqual(got.outcome.modes, baseline.outcome.modes) {
			t.Fatalf("end state = %#v, want %#v", got.outcome, baseline.outcome)
		}
		if len(got.outcome.deleted) != len(baseline.outcome.deleted) {
			t.Fatalf("deleted %v, want %v", got.outcome.deleted, baseline.outcome.deleted)
		}
		if got.outcome.creates > baseline.outcome.creates || got.outcome.puts > baseline.outcome.puts {
			t.Fatalf("creates=%d puts=%d, baseline %d and %d: a failure must never double-send",
				got.outcome.creates, got.outcome.puts, baseline.outcome.creates, baseline.outcome.puts)
		}
		if got.assigned > baseline.assigned || got.unassign > baseline.unassign {
			t.Fatalf("attaches=%d detaches=%d, baseline %d and %d", got.assigned, got.unassign, baseline.assigned, baseline.unassign)
		}
	}
	for _, kind := range []migrationFault{faultCrash, faultLostWrite, faultLostWriteCrash} {
		for at := 1; at <= baseline.outcome.writes; at++ {
			t.Run(fmt.Sprintf("%s at write %d", kind, at), func(t *testing.T) { check(t, kind, at) })
		}
	}
	for _, kind := range []migrationFault{faultCloudFailed, faultCloudLost} {
		for at := 1; at <= len(baseline.cloud); at++ {
			t.Run(fmt.Sprintf("%s at call %d (%s)", kind, at, baseline.cloud[at-1]), func(t *testing.T) { check(t, kind, at) })
		}
	}
}
