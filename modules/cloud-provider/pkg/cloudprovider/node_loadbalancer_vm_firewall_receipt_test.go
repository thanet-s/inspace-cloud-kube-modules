package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// applyThenFailAPI lets the cloud apply a create or PUT and still returns an
// error, as a lost response does.
type applyThenFailAPI struct {
	API
	updateErr error
	createErr error
}

func (a *applyThenFailAPI) UpdateFirewall(ctx context.Context, location, uuid string, request inspace.UpdateFirewallRequest) (*inspace.Firewall, error) {
	result, err := a.API.UpdateFirewall(ctx, location, uuid, request)
	if err == nil && a.updateErr != nil {
		return nil, a.updateErr
	}
	return result, err
}

func (a *applyThenFailAPI) CreateFirewall(ctx context.Context, location string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	result, err := a.API.CreateFirewall(ctx, location, request)
	if err == nil && a.createErr != nil {
		return nil, a.createErr
	}
	return result, err
}

func vmTestProviderError() error {
	return &inspace.APIError{StatusCode: 500, Method: "PUT", Path: "/firewall", Message: "boom"}
}

func (f *vmFirewallFixture) requirePending(err error) *nodeLoadBalancerFirewallRelationPendingError {
	f.t.Helper()
	var pending *nodeLoadBalancerFirewallRelationPendingError
	if !errors.As(err, &pending) {
		f.t.Fatalf("error = %v, want a bounded wait", err)
	}
	return pending
}

func (f *vmFirewallFixture) requireNoReceipt(vmUUID string) {
	f.t.Helper()
	annotations := f.anchor(vmUUID).Annotations
	for _, key := range append(append([]string{}, vmFirewallReceiptKeys...), annotationVMFirewallAbsenceCount, annotationVMFirewallAbsenceCheckedAt) {
		if annotations[key] != "" {
			f.t.Fatalf("receipt key %s=%q is still set: %#v", key, annotations[key], annotations)
		}
	}
}

// twoServices seeds S1 on the VM and returns S1's member and S2's member.
func (f *vmFirewallFixture) twoServices() (vmFirewallMember, vmFirewallMember) {
	s1 := f.addService("svc-a", 1935)
	s2 := f.addService("svc-b", 1936)
	f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(s1))
	return f.member(s1), f.member(s2)
}

func TestVMFirewallStepPreDispatchErrorResetsReceipt(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	f.api.updateFirewallErr = fmt.Errorf("blocked: %w", inspace.ErrMutationNotDispatched)
	if _, err := f.step(vmTestVM, addDelta(m2), nil); err == nil || !errors.Is(err, inspace.ErrMutationNotDispatched) {
		t.Fatalf("error = %v", err)
	}
	f.requireNoReceipt(vmTestVM)
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("attempts = %d", len(f.api.updatedFirewalls))
	}
	// The same step can run again at once: the request never left.
	f.api.updateFirewallErr = nil
	f.stepUntilConverged(vmTestVM, addDelta(m2))
	if len(f.api.updatedFirewalls) != 2 {
		t.Fatalf("attempts = %d, want the blocked one and one real PUT", len(f.api.updatedFirewalls))
	}
}

func TestVMFirewallStepCommittedDespiteHTTPError(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	f.provider.api = &applyThenFailAPI{API: f.gate, updateErr: vmTestProviderError()}
	if _, err := f.step(vmTestVM, addDelta(m2), nil); err != nil {
		t.Fatalf("a PUT that committed despite the error must resolve by readback, got %v", err)
	}
	f.requireNoReceipt(vmTestVM)
	applied, err := vmFirewallAnchorView{cm: f.anchor(vmTestVM)}.applied()
	if err != nil || len(applied.Members) != 2 {
		t.Fatalf("applied = %#v, %v", applied, err)
	}
	f.provider.api = f.gate
	f.stepUntilConverged(vmTestVM, addDelta(m2))
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("PUTs = %d, want 1", len(f.api.updatedFirewalls))
	}
}

func TestVMFirewallStepUnchangedReadbackRetiresOnce(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	f.api.updateFirewallErr = vmTestProviderError()
	_, err := f.step(vmTestVM, addDelta(m2), nil)
	f.requirePending(err)
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatalf("attempts = %d", len(f.api.updatedFirewalls))
	}
	f.api.updateFirewallErr = nil

	// Until the request can no longer be in flight, nothing is re-sent.
	for _, wait := range []time.Duration{time.Second, time.Minute, 4 * time.Minute} {
		f.advance(wait)
		_, err := f.step(vmTestVM, addDelta(m2), nil)
		f.requirePending(err)
		if len(f.api.updatedFirewalls) != 1 {
			t.Fatalf("a PUT was re-sent %s after it was issued", wait)
		}
	}
	f.advance(nodeLoadBalancerFirewallRelationRetireDelay)
	if _, err := f.step(vmTestVM, addDelta(m2), nil); err != nil {
		t.Fatalf("the retiring pass: %v", err)
	}
	f.requireNoReceipt(vmTestVM)
	if len(f.api.updatedFirewalls) != 1 {
		t.Fatal("retiring the receipt must not itself send anything")
	}
	f.stepUntilConverged(vmTestVM, addDelta(m2))
	if len(f.api.updatedFirewalls) != 2 {
		t.Fatalf("PUT attempts = %d, want the lost one and exactly one re-issue", len(f.api.updatedFirewalls))
	}
}

func TestVMFirewallStepThirdStateIsDrift(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	f.api.updateFirewallErr = vmTestProviderError()
	_, err := f.step(vmTestVM, addDelta(m2), nil)
	f.requirePending(err)
	f.api.updateFirewallErr = nil
	// Someone edits the firewall in the console while the receipt is open.
	port := int32(22)
	for index := range f.api.firewalls {
		if f.api.firewalls[index].UUID == vmTestFirewallUUID {
			f.api.firewalls[index].Rules[0].PortStart = &port
			f.api.firewalls[index].Rules[0].PortEnd = &port
		}
	}
	updates := len(f.api.updatedFirewalls)
	_, err = f.step(vmTestVM, addDelta(m2), nil)
	if !errors.Is(err, errVMFirewallDrift) {
		t.Fatalf("error = %v, want drift", err)
	}
	if len(f.api.updatedFirewalls) != updates || len(f.api.createdFirewalls) != 0 {
		t.Fatal("drift must make no mutation")
	}
	involved := map[string]bool{}
	for _, event := range f.eventsFor(vmFirewallDriftReason) {
		involved[event.InvolvedObject.Name] = true
	}
	if !involved["svc-svc-a"] || !involved["svc-svc-b"] {
		t.Fatalf("drift Events = %v, want one per member Service", involved)
	}
	// The applied state check holds every other step too.
	f.advance(time.Hour)
	if _, err := f.step(vmTestVM, addDelta(f.member(f.addService("svc-c", 1937))), nil); !errors.Is(err, errVMFirewallDrift) {
		t.Fatalf("a drifted VM must hold every Service: %v", err)
	}
}

func TestVMFirewallStepAmbiguousCreateNeverResent(t *testing.T) {
	t.Run("a late create is adopted by name", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		service := f.addService("svc-a", 1935)
		member := f.member(service)
		f.api.createFirewallErr = vmTestProviderError()
		_, err := f.step(vmTestVM, addDelta(member), nil)
		f.requirePending(err)
		f.api.createFirewallErr = nil
		for _, wait := range []time.Duration{time.Second, time.Minute} {
			f.advance(wait)
			_, err := f.step(vmTestVM, addDelta(member), nil)
			f.requirePending(err)
		}
		if len(f.api.createdFirewalls) != 1 {
			t.Fatalf("create attempts = %d, an issued create is never re-sent", len(f.api.createdFirewalls))
		}
		// The create lands late.
		merged, _ := mergeVMFirewallLedger(vmTestLedger(member))
		request, _ := vmFirewallCreateRequest(vmTestCluster, vmTestVM, 42, merged)
		if _, err := f.api.CreateFirewall(f.ctx, "bkk01", request); err != nil {
			t.Fatal(err)
		}
		created := len(f.api.createdFirewalls)
		f.stepUntilConverged(vmTestVM, addDelta(member))
		if len(f.api.createdFirewalls) != created {
			t.Fatalf("the late create must be adopted, not repeated: %d creates", len(f.api.createdFirewalls))
		}
		firewall := f.vmFirewall(vmTestVM)
		if firewall == nil || f.anchor(vmTestVM).Annotations[annotationVMFirewallUUID] != firewall.UUID {
			t.Fatal("the anchor must record the adopted firewall")
		}
	})
	t.Run("a lost create retires after two spaced absent reads", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		service := f.addService("svc-a", 1935)
		member := f.member(service)
		f.api.createFirewallErr = vmTestProviderError()
		_, err := f.step(vmTestVM, addDelta(member), nil)
		f.requirePending(err)
		f.api.createFirewallErr = nil

		f.advance(nodeLoadBalancerFirewallRelationRetireDelay)
		_, err = f.step(vmTestVM, addDelta(member), nil)
		f.requirePending(err) // first absent read
		if f.anchor(vmTestVM).Annotations[annotationVMFirewallIssuedAt] == "" {
			t.Fatal("one absent read must not retire a create")
		}
		f.advance(nodeLoadBalancerAbsenceConfirmationDelay / 2)
		_, err = f.step(vmTestVM, addDelta(member), nil)
		f.requirePending(err) // too soon for the second read
		f.advance(nodeLoadBalancerAbsenceConfirmationDelay)
		if _, err = f.step(vmTestVM, addDelta(member), nil); err != nil {
			t.Fatalf("second spaced absent read: %v", err)
		}
		f.requireNoReceipt(vmTestVM)
		if len(f.api.createdFirewalls) != 1 {
			t.Fatalf("retiring must not send: %d", len(f.api.createdFirewalls))
		}
		f.stepUntilConverged(vmTestVM, addDelta(member))
		if len(f.api.createdFirewalls) != 2 {
			t.Fatalf("create attempts = %d, want one more after the retirement", len(f.api.createdFirewalls))
		}
	})
}

func TestVMFirewallStepFreezesVMWhileReceiptPending(t *testing.T) {
	f := newVMFirewallFixture(t)
	_, m2 := f.twoServices()
	s3 := f.addService("svc-c", 1937)
	f.api.updateFirewallErr = vmTestProviderError()
	_, err := f.step(vmTestVM, addDelta(m2), nil)
	f.requirePending(err)
	f.api.updateFirewallErr = nil
	puts, creates, assigns, unassigns := len(f.api.updatedFirewalls), len(f.api.createdFirewalls), len(f.api.assignedFirewalls), len(f.api.unassignedFirewalls)

	result, err := f.step(vmTestVM, addDelta(f.member(s3)), nil)
	f.requirePending(err)
	if result.Converged {
		t.Fatal("a frozen VM must not report converged")
	}
	if _, err := f.step(vmTestVM, removeDelta(f.member(s3)), nil); err == nil {
		t.Fatal("even a removal waits for the open receipt")
	}
	if len(f.api.updatedFirewalls) != puts || len(f.api.createdFirewalls) != creates ||
		len(f.api.assignedFirewalls) != assigns || len(f.api.unassignedFirewalls) != unassigns {
		t.Fatal("no second mutation may be issued on top of an unresolved receipt")
	}
}

// Crash the controller after every anchor write of two consecutive logical
// steps (a create, then a PUT) and require that the next process finishes with
// the same anchor, never a double create, never a double PUT.
func TestVMFirewallStepRestartAtEveryCAS(t *testing.T) {
	type outcome struct {
		applied, hash string
		creates, puts int
		updates       int
		maxPerVM      int
		attached      bool
	}
	run := func(t *testing.T, crashAfter int) outcome {
		f := newVMFirewallFixture(t)
		s1 := f.addService("svc-a", 1935)
		s2 := f.addService("svc-b", 1936)
		m1, m2 := f.member(s1), f.member(s2)
		updates, crashed := 0, false
		kube := f.provider.kubeClient.(*kubefake.Clientset)
		kube.PrependReactor("update", "configmaps", func(kubetesting.Action) (bool, runtime.Object, error) {
			if crashAfter > 0 && updates >= crashAfter {
				crashed = true
				return true, nil, errors.New("controller crashed")
			}
			updates++
			return false, nil, nil
		})
		restarted := false
		for _, delta := range []vmFirewallDelta{addDelta(m1), addDelta(m2)} {
			converged := false
			for pass := 0; pass < 400 && !converged; pass++ {
				result, err := f.step(vmTestVM, delta, nil)
				switch {
				case err == nil:
					converged = result.Converged
				case crashed && !restarted:
					restarted = true
					crashAfter = 0
					f.restart()
				default:
					var pending *nodeLoadBalancerFirewallRelationPendingError
					if !errors.As(err, &pending) {
						t.Fatalf("crash after write %d, pass %d: %v", crashAfter, pass, err)
					}
					f.advance(pending.retryAfter + time.Second)
				}
			}
			if !converged {
				t.Fatalf("crash after write %d: %v never converged", crashAfter, delta)
			}
		}
		annotations := f.anchor(vmTestVM).Annotations
		firewall := f.vmFirewall(vmTestVM)
		return outcome{
			applied: annotations[annotationVMFirewallApplied], hash: annotations[annotationVMFirewallAppliedHash],
			creates: len(f.api.createdFirewalls), puts: len(f.api.updatedFirewalls), updates: updates,
			maxPerVM: f.gate.maxObservedFirewallsPerVM, attached: firewall != nil && vmFirewallAttachedTo(*firewall, vmTestVM),
		}
	}
	baseline := run(t, 0)
	if baseline.creates != 1 || baseline.puts != 1 || !baseline.attached {
		t.Fatalf("baseline = %#v", baseline)
	}
	for crash := 1; crash <= baseline.updates+1; crash++ {
		t.Run(fmt.Sprintf("crash after write %d", crash), func(t *testing.T) {
			got := run(t, crash)
			if got.applied != baseline.applied || got.hash != baseline.hash || !got.attached {
				t.Fatalf("outcome = %#v, want the baseline anchor %#v", got, baseline)
			}
			if got.creates > 1 || got.puts > 1 {
				t.Fatalf("creates=%d puts=%d: a restart must never double-send", got.creates, got.puts)
			}
			if got.maxPerVM > 2 {
				t.Fatalf("a VM carried %d firewalls", got.maxPerVM)
			}
			if got.creates+got.puts < 2 {
				t.Fatalf("creates=%d puts=%d: both logical steps must reach the cloud", got.creates, got.puts)
			}
		})
	}
}
