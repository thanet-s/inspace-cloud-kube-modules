package cloudprovider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// listFailAPI fails the post-issue absence read while a predicate holds, like a
// brownout that hits exactly between persisting a receipt and dispatching.
type listFailAPI struct {
	*slowMutationAPI
	failLBList  func() bool
	failFIPList func() bool
}

func (a *listFailAPI) ListLoadBalancers(ctx context.Context, location string) ([]inspace.LoadBalancer, error) {
	if a.failLBList != nil && a.failLBList() {
		return nil, errors.New("test: list load balancers unavailable")
	}
	return a.slowMutationAPI.ListLoadBalancers(ctx, location)
}

func (a *listFailAPI) ListFloatingIPs(ctx context.Context, location string, filters *inspace.FloatingIPFilters) ([]inspace.FloatingIP, error) {
	if a.failFIPList != nil && a.failFIPList() {
		return nil, errors.New("test: list floating IPs unavailable")
	}
	return a.slowMutationAPI.ListFloatingIPs(ctx, location, filters)
}

func (f *retireFixture) storedFence() *standardNLBMutationFence {
	f.t.Helper()
	stored, err := f.provider.standardNLBServiceStore.GetExact(context.Background(), f.service)
	if err != nil {
		f.t.Fatal(err)
	}
	fence, err := parseStandardNLBFence(stored.Annotations[annotationStandardNLBMutation])
	if err != nil {
		f.t.Fatal(err)
	}
	return fence
}

// An attempt-1 create whose post-issue read fails is cleared as non-dispatched.
// That clear must keep the attempt count, otherwise the next pass would start a
// fresh attempt-0 create while the original may still land: three paid
// resources and an ownership-name collision.
func TestNonDispatchClearOfARecreateKeepsTheAttemptBudget(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation string
		api       string
		arm       func(*listFailAPI, func() bool)
	}{
		{"NLB", standardNLBCreateLoadBalancer, "CreateLoadBalancer", func(a *listFailAPI, p func() bool) { a.failLBList = p }},
		{"FIP", standardNLBCreateFloatingIP, "CreateFloatingIP", func(a *listFailAPI, p func() bool) { a.failFIPList = p }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRetireFixture(t)
			wrapped := &listFailAPI{slowMutationAPI: f.api}
			f.provider.api = wrapped
			f.api.dropFirst[test.api] = 99

			if err := f.ensure(); err == nil {
				t.Fatal("first Ensure should report the ambiguous create")
			}
			f.advance(standardNLBAdditiveRetireDelay(test.operation) + time.Second)
			_ = f.ensure() // records the first absent read
			f.advance(standardNLBRemovalAbsenceDelay + time.Second)

			// The retire pass re-stages and issues attempt 1; its post-issue
			// read then fails.
			armed := true
			test.arm(wrapped, func() bool {
				fence := f.storedFence()
				return armed && fence != nil && fence.Operation == test.operation &&
					fence.Phase == standardNLBPhaseIssued && fence.Attempt == 1
			})
			if err := f.ensure(); err == nil {
				t.Fatal("the retire pass should fail on the unavailable read")
			}
			armed = false
			fence := f.storedFence()
			if fence == nil || fence.Operation != test.operation || fence.Phase != standardNLBPhaseIntent || fence.Attempt != 1 {
				t.Fatalf("non-dispatch clear lost the attempt budget: %#v", fence)
			}
			if f.api.calls[test.api] != 1 {
				t.Fatalf("creates after the failed pass = %d, want 1 (nothing dispatched)", f.api.calls[test.api])
			}

			// Next pass dispatches attempt 1, which stays ambiguous.
			if err := f.ensure(); err == nil || f.api.calls[test.api] != 2 {
				t.Fatalf("attempt-1 pass: err=%v creates=%d, want 2", err, f.api.calls[test.api])
			}
			// After the window the budget is spent: no third create.
			f.advance(standardNLBAdditiveRetireDelay(test.operation) + time.Second)
			_ = f.ensure()
			f.advance(standardNLBRemovalAbsenceDelay + time.Second)
			err := f.ensure()
			if f.api.calls[test.api] != 2 || err == nil || !strings.Contains(err.Error(), "manually") {
				t.Fatalf("budget reset: creates=%d err=%v, want 2 and a manual-resolution refusal", f.api.calls[test.api], err)
			}
		})
	}
}
