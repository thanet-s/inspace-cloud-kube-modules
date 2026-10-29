package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type migrationFault string

const (
	faultNone = migrationFault("")
	// The k-th write to a ConfigMap or Service does not land and the process
	// dies; the next one starts from what the cluster holds.
	faultCrash = migrationFault("crash")
	// The k-th write lands but the caller sees an error, as when the response
	// is lost. The process goes on and must not repeat or skip a step.
	faultLostWrite = migrationFault("lost-write")
	// The k-th write lands, the caller sees an error, and the process dies.
	faultLostWriteCrash = migrationFault("lost-write-then-crash")
	// The k-th mutating cloud call does not take effect and answers with an
	// ambiguous error (a gateway timeout).
	faultCloudFailed = migrationFault("cloud-call-fails")
	// The k-th mutating cloud call takes effect and answers with an ambiguous error.
	faultCloudLost = migrationFault("cloud-call-lands-but-errors")
)

// migrationFaultAPI counts the mutating cloud calls and fails the at-th one.
type migrationFaultAPI struct {
	API
	at      int
	applied bool
	calls   int
	names   []string
	fired   bool
}

func (a *migrationFaultAPI) hit(name string, call func() error) error {
	a.calls++
	a.names = append(a.names, name)
	if a.at != 0 && a.calls == a.at && !a.fired {
		a.fired = true
		if a.applied {
			_ = call()
		}
		return vmTestTimeoutError()
	}
	return call()
}

func (a *migrationFaultAPI) CreateFirewall(ctx context.Context, location string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	var out *inspace.Firewall
	err := a.hit("create", func() (err error) { out, err = a.API.CreateFirewall(ctx, location, request); return })
	return out, err
}

func (a *migrationFaultAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	var out *inspace.Firewall
	err := a.hit("update", func() (err error) { out, err = a.API.UpdateFirewall(ctx, location, uuid, request); return })
	return out, err
}

func (a *migrationFaultAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	return a.hit("assign", func() error { return a.API.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID) })
}

func (a *migrationFaultAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	return a.hit("unassign", func() error { return a.API.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID) })
}

func (a *migrationFaultAPI) DeleteFirewall(ctx context.Context, location, uuid string) error {
	return a.hit("delete", func() error { return a.API.DeleteFirewall(ctx, location, uuid) })
}

// migrationFaultRun is one run of the whole th-live migration with one fault.
type migrationFaultRun struct {
	outcome  migrationOutcome
	fired    bool
	cloud    []string
	assigned int
	unassign int
}

func runTHLiveWithFault(t *testing.T, kind migrationFault, at int) migrationFaultRun {
	return runMigrationWithFault(t, kind, at,
		func(t *testing.T) *migrationCluster {
			m := newTHLiveCluster(t)
			m.trackCoverage()
			return m
		},
		func(m *migrationCluster) {
			for _, vm := range m.vms {
				m.annotateNode(vm.name, "true")
			}
		},
		(*migrationCluster).allMigrated)
}

// runMigrationWithFault runs one migration of a cluster with one fault. prepare
// builds the cluster and everything that happens before the fault window, start
// begins the migration, and finished says when it is over. Writes and cloud calls
// are counted from start on.
func runMigrationWithFault(
	t *testing.T,
	kind migrationFault,
	at int,
	prepare func(*testing.T) *migrationCluster,
	start func(*migrationCluster),
	finished func(*migrationCluster) bool,
) migrationFaultRun {
	m := prepare(t)
	faultAPI := &migrationFaultAPI{API: m.provider.api}
	if kind == faultCloudFailed || kind == faultCloudLost {
		faultAPI.at, faultAPI.applied = at, kind == faultCloudLost
	}
	m.provider.api = faultAPI
	start(m)
	writes, down, fired, restarted := 0, false, false, false
	m.kube.PrependReactor("*", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		verb, resource := action.GetVerb(), action.GetResource().Resource
		if (verb != "update" && verb != "create") || (resource != "configmaps" && resource != "services") {
			return false, nil, nil
		}
		if down {
			return true, nil, errors.New("controller crashed")
		}
		writes++
		if at == 0 || writes != at || fired {
			return false, nil, nil
		}
		switch kind {
		case faultCrash:
			fired, down = true, true
			return true, nil, errors.New("controller crashed")
		case faultLostWrite, faultLostWriteCrash:
			fired, down = true, kind == faultLostWriteCrash
			var obj runtime.Object
			var err error
			// Update and create actions share one interface; the verb tells them apart.
			if typed, ok := action.(kubetesting.CreateAction); ok {
				obj = typed.GetObject()
				if verb == "create" {
					err = m.kube.Tracker().Create(action.GetResource(), obj, action.GetNamespace())
				} else {
					err = m.kube.Tracker().Update(action.GetResource(), obj, action.GetNamespace())
				}
			}
			if err != nil {
				t.Fatalf("applying the write that is then reported as failed: %v", err)
			}
			return true, obj, errors.New("write landed but its response was lost")
		}
		return false, nil, nil
	})
	var last error
	for pass := 0; pass < 6000 && !finished(m); pass++ {
		m.clock = m.clock.Add(7 * time.Second)
		step := func(err error) {
			if err == nil {
				return
			}
			var limit *FirewallLimitExceededError
			if errors.As(err, &limit) {
				t.Fatalf("%s at %d, pass %d: the controller ran into the firewall limit: %v", kind, at, pass, err)
			}
			if down && !restarted {
				restarted, down = true, false
				m.restart()
				return
			}
			text := err.Error()
			if tolerableMigrationError(err) || strings.Contains(text, "response was lost") ||
				strings.Contains(text, "gateway timeout") || strings.Contains(text, "controller crashed") {
				return
			}
			t.Fatalf("%s at %d, pass %d: %v", kind, at, pass, err)
		}
		for _, vm := range m.vms {
			last = m.controller.syncVMFirewall(m.ctx, vm.uuid)
			step(last)
		}
		for _, name := range m.services {
			last = m.controller.syncPublicNodeLocal(m.ctx, m.key(name), m.service(name))
			step(last)
		}
		if m.afterPass != nil {
			m.afterPass()
		}
	}
	if !finished(m) {
		t.Fatalf("%s at %d: never finished; last %v", kind, at, last)
	}
	// The limit gate and the coverage check hold for every run, fault or not.
	if m.gate.maxObservedFirewallsPerVM > 3 || m.gate.refusedAttaches != 0 {
		t.Errorf("%s at %d: peak %d firewalls, %d refused attaches", kind, at, m.gate.maxObservedFirewallsPerVM, m.gate.refusedAttaches)
	}
	out := m.outcome(writes)
	out.crashed = fired || faultAPI.fired
	return migrationFaultRun{
		outcome: out, fired: fired || faultAPI.fired, cloud: faultAPI.names,
		assigned: len(m.api.assignedFirewalls), unassign: len(m.api.unassignedFirewalls),
	}
}

// Fault the whole migration of th-live at every write and every mutating cloud
// call, in each way a real failure looks, and require the same end state: at
// most one create per firewall, at most one adopt PUT, never a fourth firewall
// on a VM, no refused attach, and every served port covered between any two
// cloud calls.
func TestVMFirewallMigrationRestartAtEveryPhase(t *testing.T) {
	baseline := runTHLiveWithFault(t, faultNone, 0)
	if baseline.outcome.writes < 20 || len(baseline.cloud) < 10 {
		t.Fatalf("baseline = %#v: the harness saw too few writes or calls", baseline)
	}
	check := func(t *testing.T, kind migrationFault, at int) {
		got := runTHLiveWithFault(t, kind, at)
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

// An unassign during the detach phase whose answer is lost: the source stays
// covered by the per-VM firewall, the fence resolves it by readback, and the
// migration finishes without a second unassign of the same relation that
// landed.
func TestVMFirewallMigrationAmbiguousUnassignDuringDetach(t *testing.T) {
	baseline := runTHLiveWithFault(t, faultNone, 0)
	first := -1
	for index, name := range baseline.cloud {
		if name == "unassign" {
			first = index + 1
			break
		}
	}
	if first < 0 {
		t.Fatal("the baseline never unassigns a firewall")
	}
	for _, kind := range []migrationFault{faultCloudFailed, faultCloudLost} {
		t.Run(string(kind), func(t *testing.T) {
			got := runTHLiveWithFault(t, kind, first)
			if !got.fired {
				t.Fatal("the unassign was never faulted")
			}
			if !reflect.DeepEqual(got.outcome.firewalls, baseline.outcome.firewalls) {
				t.Fatalf("end state = %v, want %v", got.outcome.firewalls, baseline.outcome.firewalls)
			}
			if got.unassign > baseline.unassign {
				t.Fatalf("unassigns = %d, baseline %d", got.unassign, baseline.unassign)
			}
		})
	}
}
