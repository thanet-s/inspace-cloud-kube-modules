package cloudprovider

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func (f *vmFirewallFixture) assigned(uid, policy string) (map[string]struct{}, error) {
	f.t.Helper()
	items, err := f.api.ListFirewalls(f.ctx, "bkk01")
	if err != nil {
		f.t.Fatal(err)
	}
	anchors, err := f.controller.listVMFirewallAnchors(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.controller.vmEdgeAssigned(uid, policy, items, anchors)
}

func sortedKeys(set map[string]struct{}) []string {
	out := []string{}
	for key := range set {
		out = append(out, key)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestVMEdgeAssignedRequiresExactState(t *testing.T) {
	// A settled fixture: S1 is open on VM 1 and VM 2, each with its own firewall.
	setup := func(t *testing.T) (*vmFirewallFixture, vmFirewallMember) {
		f := newVMFirewallFixture(t)
		s1 := f.addService("svc-a", 1935)
		m1 := f.member(s1)
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, m1)
		f.seedVMFirewall(vmTestOtherVM, "44444444-4444-4444-8444-444444444444", true, m1)
		return f, m1
	}
	set := func(vms ...string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, vm := range vms {
			out[vm] = struct{}{}
		}
		return out
	}
	t.Run("both VMs are open", func(t *testing.T) {
		f, m1 := setup(t)
		got, err := f.assigned(m1.UID, m1.Policy)
		if err != nil || !reflect.DeepEqual(got, set(vmTestVM, vmTestOtherVM)) {
			t.Fatalf("assigned = %v, %v", sortedKeys(got), err)
		}
	})
	mutateFirewall := func(f *vmFirewallFixture, mutate func(*inspace.Firewall)) {
		for index := range f.api.firewalls {
			if f.api.firewalls[index].UUID == vmTestFirewallUUID {
				mutate(&f.api.firewalls[index])
			}
		}
	}
	exclusions := map[string]func(*vmFirewallFixture){
		"firewall missing from the same read": func(f *vmFirewallFixture) {
			kept := f.api.firewalls[:0]
			for _, fw := range f.api.firewalls {
				if fw.UUID != vmTestFirewallUUID {
					kept = append(kept, fw)
				}
			}
			f.api.firewalls = kept
		},
		"firewall attached to a second VM": func(f *vmFirewallFixture) {
			mutateFirewall(f, func(fw *inspace.Firewall) {
				fw.ResourcesAssigned = append(fw.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: vmTestOtherVM})
			})
		},
		"firewall not attached": func(f *vmFirewallFixture) {
			mutateFirewall(f, func(fw *inspace.Firewall) { fw.ResourcesAssigned = nil })
		},
		"hash differs from applied-hash": func(f *vmFirewallFixture) {
			port := int32(22)
			mutateFirewall(f, func(fw *inspace.Firewall) { fw.Rules[0].PortStart, fw.Rules[0].PortEnd = &port, &port })
		},
		"billing mismatch": func(f *vmFirewallFixture) {
			mutateFirewall(f, func(fw *inspace.Firewall) { fw.BillingAccountID = 7 })
		},
		"foreign description": func(f *vmFirewallFixture) {
			mutateFirewall(f, func(fw *inspace.Firewall) { fw.Description = "someone else's" })
		},
		"name of another VM": func(f *vmFirewallFixture) {
			other, _ := inspace.NodeLoadBalancerVMFirewallName(vmTestCluster, vmTestOtherVM)
			mutateFirewall(f, func(fw *inspace.Firewall) { fw.DisplayName = other })
		},
		"anchor ledger is corrupt": func(f *vmFirewallFixture) {
			f.setAnchor(vmTestVM, func(a map[string]string) { a[annotationVMFirewallApplied] = "not json" })
		},
	}
	for name, mutate := range exclusions {
		t.Run(name, func(t *testing.T) {
			f, m1 := setup(t)
			mutate(f)
			got, err := f.assigned(m1.UID, m1.Policy)
			if err != nil {
				t.Fatalf("an excluded VM is not an error: %v", err)
			}
			if !reflect.DeepEqual(got, set(vmTestOtherVM)) {
				t.Fatalf("assigned = %v, want only the untouched VM", sortedKeys(got))
			}
		})
	}
	t.Run("receipt present", func(t *testing.T) {
		f, m1 := setup(t)
		f.setAnchor(vmTestVM, func(a map[string]string) {
			a[annotationVMFirewallPending] = a[annotationVMFirewallApplied]
			a[annotationVMFirewallPendingOp] = string(vmFirewallOpUpdate)
			a[annotationVMFirewallPendingHash] = a[annotationVMFirewallAppliedHash]
			a[annotationVMFirewallPendingAt] = f.clock.Format(time.RFC3339Nano)
		})
		got, err := f.assigned(m1.UID, m1.Policy)
		if !errors.Is(err, errVMFirewallReceiptPending) {
			t.Fatalf("error = %v, want errVMFirewallReceiptPending", err)
		}
		if !reflect.DeepEqual(got, set(vmTestOtherVM)) {
			t.Fatalf("assigned = %v: the VM with a receipt is excluded", sortedKeys(got))
		}
	})
	t.Run("a receipt on a VM the Service has no entry on does not concern it", func(t *testing.T) {
		f := newVMFirewallFixture(t)
		m1 := f.member(f.addService("svc-a", 1935))
		mz := f.member(f.addService("svc-z", 7777))
		f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, m1)
		f.seedVMFirewall(vmTestOtherVM, "44444444-4444-4444-8444-444444444444", true, mz)
		f.setAnchor(vmTestOtherVM, func(a map[string]string) {
			a[annotationVMFirewallPending] = a[annotationVMFirewallApplied]
			a[annotationVMFirewallPendingOp] = string(vmFirewallOpUpdate)
			a[annotationVMFirewallPendingHash] = a[annotationVMFirewallAppliedHash]
		})
		got, err := f.assigned(m1.UID, m1.Policy)
		if err != nil || !reflect.DeepEqual(got, set(vmTestVM)) {
			t.Fatalf("assigned = %v, %v", sortedKeys(got), err)
		}
	})
	t.Run("entry for another policy", func(t *testing.T) {
		f, m1 := setup(t)
		got, err := f.assigned(m1.UID, "00000000")
		if err != nil || len(got) != 0 {
			t.Fatalf("assigned = %v, %v", sortedKeys(got), err)
		}
		got, err = f.assigned("svc-other", m1.Policy)
		if err != nil || len(got) != 0 {
			t.Fatalf("assigned = %v, %v", sortedKeys(got), err)
		}
	})
}

func TestVMFirewallSettle(t *testing.T) {
	f := newVMFirewallFixture(t)
	if got := f.provider.vmFirewallSettle(); got != 10*time.Second {
		t.Fatalf("settle = %s, want the measured default", got)
	}
	f.provider.config.NodeLoadBalancer.VMFirewallSettle = 45 * time.Second
	if got := f.provider.vmFirewallSettle(); got != 45*time.Second {
		t.Fatalf("settle = %s, want the configured value", got)
	}
	service := f.addService("svc-a", 1935)
	anchor := f.seedVMFirewall(vmTestVM, vmTestFirewallUUID, true, f.member(service))
	applied := f.clock
	for _, test := range []struct {
		after time.Duration
		want  time.Duration
	}{
		{0, 45 * time.Second},
		{20 * time.Second, 25 * time.Second},
		{45 * time.Second, 0},
		{time.Hour, 0},
	} {
		got := vmFirewallSettleRemaining(anchor, 45*time.Second, applied.Add(test.after))
		if got != test.want {
			t.Errorf("after %s: remaining %s, want %s", test.after, got, test.want)
		}
	}
	bare := &corev1.ConfigMap{}
	if got := vmFirewallSettleRemaining(bare, 45*time.Second, applied); got != 0 {
		t.Errorf("an anchor that never applied anything has nothing to settle, got %s", got)
	}
}

// A settling Service waits a fixed time, like a hold: the delay must not grow
// the rate-limited backoff.
func TestVMFirewallSettleRequeueIsFixed(t *testing.T) {
	settling := &errPublicNodeLocalVMFirewallSettling{vmUUID: vmTestVM, retryAfter: 7 * time.Second}
	delay, fixed := nodeLoadBalancerRequeueDelay(fmt.Errorf("wrapped: %w", settling))
	if !fixed || delay != 7*time.Second {
		t.Fatalf("delay=%s fixed=%t, want 7s fixed", delay, fixed)
	}
	if delay, fixed := nodeLoadBalancerRequeueDelay(&errPublicNodeLocalVMFirewallSettling{vmUUID: vmTestVM}); !fixed || delay <= 0 {
		t.Fatalf("a settle error without a delay must still requeue at once: %s %t", delay, fixed)
	}
	if settling.Error() == "" {
		t.Fatal("the error needs a message")
	}
}
