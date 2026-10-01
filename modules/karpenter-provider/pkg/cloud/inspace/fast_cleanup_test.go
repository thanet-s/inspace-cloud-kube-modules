package inspace

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func init() {
	// DeleteVM logs its proof stages; without a configured root logger
	// controller-runtime prints a one-time stack trace into the test output.
	ctrllog.SetLogger(logr.Discard())
}

// virtualReadbackClock replaces the spaced-observation sleeps with a recording
// virtual clock so a test can state how long a cleanup path would have waited
// at production intervals without actually sleeping.
type virtualReadbackClock struct {
	waits []time.Duration
}

func installVirtualReadbackClock(t *testing.T) *virtualReadbackClock {
	t.Helper()
	clock := &virtualReadbackClock{}
	original := waitForReadback
	waitForReadback = func(ctx context.Context, interval time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		clock.waits = append(clock.waits, interval)
		return nil
	}
	t.Cleanup(func() { waitForReadback = original })
	return clock
}

func (c *virtualReadbackClock) total() time.Duration {
	var sum time.Duration
	for _, wait := range c.waits {
		sum += wait
	}
	return sum
}

// spaced counts only the production confirmation intervals (10s or 30s), not
// the sub-second backoff between ordinary readbacks.
func (c *virtualReadbackClock) spaced() int {
	count := 0
	for _, wait := range c.waits {
		if wait >= 10*time.Second {
			count++
		}
	}
	return count
}

// useProductionConfirmationIntervals keeps every test timeout generous while
// restoring the shipped spacing between confirmations; combined with the
// virtual clock this measures production wall time deterministically.
func useProductionConfirmationIntervals(adapter *Adapter) {
	adapter.destructiveAbsenceReadInterval = defaultDestructiveAbsenceReadInterval
	adapter.createAbsenceReadInterval = defaultCreateAbsenceReadInterval
	adapter.convergedAbsenceReadInterval = defaultConvergedAbsenceReadInterval
	adapter.destructiveAbsenceTimeout = time.Hour
	adapter.networkAttachmentRequestTimeout = time.Minute
}

func TestDeleteMissingVMDoesNotRepeatVMAbsenceProofOrFirewallSpacedProof(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, boundedReadbackTestTimeout)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	api.vms = nil // the VM vanished; its floating IP and firewall relation remain
	api.operations = nil
	clock := installVirtualReadbackClock(t)
	useProductionConfirmationIntervals(adapter)
	getBefore := api.vmGetCalls

	err = adapter.DeleteVM(context.Background(), "bkk01", created.UUID, "cluster-a", "nodeclaim-a", durableDeleteIdentity(created))
	t.Logf("missing-VM delete (floating IP and firewall relation still present) simulated wait: %v over %d spaced waits, %d VM GETs", clock.total(), clock.spaced(), api.vmGetCalls-getBefore)
	if !errors.Is(err, cloudapi.ErrNotFound) || !errors.Is(err, cloudapi.ErrDeletionConverged) {
		t.Fatalf("DeleteVM error = %v, want ErrNotFound carrying ErrDeletionConverged", err)
	}
	wantOperations := []string{"unassign-floating-ip", "delete-floating-ip", "unassign-firewall"}
	if !reflect.DeepEqual(api.operations, wantOperations) || api.deleteVMCalls != 0 {
		t.Fatalf("operations = %v (VM deletes=%d), want %v with no VM DELETE", api.operations, api.deleteVMCalls, wantOperations)
	}
	// One spaced proof that the VM is gone (2 gaps), spaced FIP absence (2),
	// and spaced firewall-relation absence (2). The second VM-absence proof and
	// the firewall pre-DELETE proof reuse the first proof plus one confirming
	// read instead of two more spaced proofs.
	if got := clock.spaced(); got != 6 {
		t.Fatalf("spaced waits = %d (%v), want 6", got, clock.waits)
	}
	if got := api.vmGetCalls - getBefore; got != 6 {
		t.Fatalf("VM GET reads = %d, want 3 (proof) + 1 (core confirm) + 1 (dependent confirm) + 1 (firewall confirm)", got)
	}
}

func TestDeleteMissingVMWithObservedFloatingIPDeleteSkipsSeparateSpacedFloatingIPProof(t *testing.T) {
	api := &fakeAPI{}
	adapter, _ := New(api)
	configureFastNetworkReadback(adapter, 500*time.Millisecond)
	created, err := adapter.CreateVM(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	harness := &testRemovalMutationHarness{}
	identity := durableDeleteIdentity(created)
	identity.NetworkUUID = testRequest().NetworkUUID
	harness.attachDelete(&identity)
	if err := adapter.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity); err != nil {
		t.Fatalf("first (live) delete = %v", err)
	}
	if harness.current.Operation != cloudapi.RemovalMutationFloatingIPDelete || harness.current.Phase != cloudapi.RemovalMutationObserved {
		t.Fatalf("durable journal = %#v, want an observed floating-IP DELETE", harness.current)
	}
	if len(api.floatingIPs) != 0 || len(api.vms) != 0 {
		t.Fatalf("first delete left VMs=%d floating IPs=%d", len(api.vms), len(api.floatingIPs))
	}

	clock := installVirtualReadbackClock(t)
	restarted, _ := New(api)
	configureFastNetworkReadback(restarted, 500*time.Millisecond)
	useProductionConfirmationIntervals(restarted)
	api.operations = nil
	floatingGetsBefore, deletesBefore := api.floatingIPGetCalls, api.deleteVMCalls

	err = restarted.DeleteVM(context.Background(), created.Location, created.UUID, created.ClusterName, created.NodeClaimName, identity)
	t.Logf("repeat delete after converged cleanup simulated wait: %v over %d spaced waits, %d exact FIP reads", clock.total(), clock.spaced(), api.floatingIPGetCalls-floatingGetsBefore)
	if !errors.Is(err, cloudapi.ErrNotFound) || !errors.Is(err, cloudapi.ErrDeletionConverged) {
		t.Fatalf("second (missing) delete = %v, want ErrNotFound carrying ErrDeletionConverged", err)
	}
	if api.deleteVMCalls != deletesBefore || len(api.operations) != 0 {
		t.Fatalf("converged repeat delete mutated the cloud: deletes=%d operations=%v", api.deleteVMCalls-deletesBefore, api.operations)
	}
	if got := api.floatingIPGetCalls - floatingGetsBefore; got != 1 {
		t.Fatalf("exact floating-IP reads = %d, want one confirming read", got)
	}
	// 2 gaps for the single VM-absence proof and 2 for firewall-relation
	// absence. No separate 2-gap floating-IP proof and no duplicate VM proof.
	if got := clock.spaced(); got != 4 {
		t.Fatalf("spaced waits = %d (%v), want 4", got, clock.waits)
	}
}

func TestReadOrphanFloatingIPForDeleteUsesObservedHistoryOnlyForExactMatch(t *testing.T) {
	setup := func(t *testing.T) (*fakeAPI, *Adapter, *cloudapi.VM, cloudapi.DeleteVMIdentity, *testRemovalMutationHarness) {
		t.Helper()
		api := &fakeAPI{}
		adapter, _ := New(api)
		configureFastNetworkReadback(adapter, 500*time.Millisecond)
		created, err := adapter.CreateVM(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}
		api.vms = nil
		harness := &testRemovalMutationHarness{}
		identity := durableDeleteIdentity(created)
		harness.attachDelete(&identity)
		useProductionConfirmationIntervals(adapter)
		return api, adapter, created, identity, harness
	}
	observedDelete := func(created *cloudapi.VM, mutate func(*cloudapi.RemovalMutation)) cloudapi.RemovalMutationFence {
		mutation := cloudapi.RemovalMutation{
			Operation: cloudapi.RemovalMutationFloatingIPDelete, Location: created.Location, VMUUID: strings.ToLower(created.UUID),
			Address: created.PublicIPv4, Name: created.FloatingIPName, BillingAccountID: created.BillingAccountID,
		}
		if mutate != nil {
			mutate(&mutation)
		}
		issued := time.Now().Add(-time.Hour).UTC()
		return cloudapi.RemovalMutationFence{
			RemovalMutation: mutation, Phase: cloudapi.RemovalMutationObserved,
			IssueID: "44444444444444444444444444444444", IssuedAt: issued, ObservedAt: issued.Add(time.Minute),
		}
	}
	read := func(adapter *Adapter, created *cloudapi.VM, identity cloudapi.DeleteVMIdentity) (*sdk.FloatingIP, error) {
		return adapter.readOrphanFloatingIPForDelete(context.Background(), created.Location, created.UUID, created.FloatingIPName, identity, deleteRemovalMutationAuthority(identity))
	}

	t.Run("exact observed delete and absent address needs one read", func(t *testing.T) {
		api, adapter, created, identity, harness := setup(t)
		api.floatingIPs = nil
		harness.current = observedDelete(created, nil)
		clock := installVirtualReadbackClock(t)
		before := api.floatingIPGetCalls
		floatingIP, err := read(adapter, created, identity)
		if err != nil || floatingIP != nil {
			t.Fatalf("readOrphanFloatingIPForDelete() = %#v, %v; want absence", floatingIP, err)
		}
		if got := api.floatingIPGetCalls - before; got != 1 || clock.spaced() != 0 {
			t.Fatalf("reads=%d spaced waits=%d, want exactly one confirming read and no spaced wait", got, clock.spaced())
		}
	})

	t.Run("no history keeps the full spaced proof", func(t *testing.T) {
		api, adapter, created, identity, _ := setup(t)
		api.floatingIPs = nil
		clock := installVirtualReadbackClock(t)
		before := api.floatingIPGetCalls
		floatingIP, err := read(adapter, created, identity)
		if err != nil || floatingIP != nil {
			t.Fatalf("readOrphanFloatingIPForDelete() = %#v, %v; want absence", floatingIP, err)
		}
		if got := api.floatingIPGetCalls - before; got != destructiveAbsenceConfirmations || clock.spaced() != destructiveAbsenceConfirmations-1 {
			t.Fatalf("reads=%d spaced waits=%d, want %d reads and %d spaced waits", got, clock.spaced(), destructiveAbsenceConfirmations, destructiveAbsenceConfirmations-1)
		}
	})

	for name, mutate := range map[string]func(*cloudapi.RemovalMutation){
		"different address": func(m *cloudapi.RemovalMutation) { m.Address = "203.0.113.99" },
		"different VM":      func(m *cloudapi.RemovalMutation) { m.VMUUID = "99999999-9999-4999-8999-999999999999" },
		"different billing": func(m *cloudapi.RemovalMutation) { m.BillingAccountID = 99 },
		"unassign receipt":  func(m *cloudapi.RemovalMutation) { m.Operation = cloudapi.RemovalMutationFloatingIPUnassign },
	} {
		t.Run("history for "+name+" keeps the full spaced proof", func(t *testing.T) {
			api, adapter, created, identity, harness := setup(t)
			api.floatingIPs = nil
			harness.current = observedDelete(created, mutate)
			clock := installVirtualReadbackClock(t)
			floatingIP, err := read(adapter, created, identity)
			if err != nil || floatingIP != nil {
				t.Fatalf("readOrphanFloatingIPForDelete() = %#v, %v; want absence", floatingIP, err)
			}
			if clock.spaced() != destructiveAbsenceConfirmations-1 {
				t.Fatalf("spaced waits = %d, want the full proof's %d", clock.spaced(), destructiveAbsenceConfirmations-1)
			}
		})
	}

	t.Run("exact observed delete with the address still present is still returned for removal", func(t *testing.T) {
		api, adapter, created, identity, harness := setup(t)
		if len(api.floatingIPs) != 1 {
			t.Fatalf("setup floating IPs = %d, want the auto-reserved address", len(api.floatingIPs))
		}
		harness.current = observedDelete(created, nil)
		floatingIP, err := read(adapter, created, identity)
		if err != nil || floatingIP == nil || floatingIP.Address != created.PublicIPv4 {
			t.Fatalf("readOrphanFloatingIPForDelete() = %#v, %v; want the live address handed to removal", floatingIP, err)
		}
	})
}
