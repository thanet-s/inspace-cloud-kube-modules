package cloudprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// rejectingAddAPI answers the first rejectAdds target adds with a definite 4xx
// that applies nothing.
type rejectingAddAPI struct {
	*fakeAPI
	rejectAdds int
	adds       int
	rejection  error
}

func (a *rejectingAddAPI) AddLoadBalancerTarget(ctx context.Context, l, lb, uuid string) (*inspace.LoadBalancerTarget, error) {
	a.adds++
	if a.adds <= a.rejectAdds {
		return nil, a.rejection
	}
	return a.fakeAPI.AddLoadBalancerTarget(ctx, l, lb, uuid)
}

func definiteBadRequest() error {
	return &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/network/load_balancers/x/targets", Message: "invalid target"}
}

func newRejectingAddFixture(t *testing.T, rejects int, current ...string) (*rejectingAddAPI, *retireFixture) {
	t.Helper()
	f := newRetireFixture(t)
	api := &rejectingAddAPI{fakeAPI: f.api.fakeAPI, rejectAdds: rejects, rejection: definiteBadRequest()}
	f.provider.api = api
	setOwnedLoadBalancer(api.fakeAPI, f.provider, f.service, current)
	return api, f
}

func TestDefinite4xxAddTargetClearsItsReceiptSoItCannotBlock(t *testing.T) {
	api, f := newRejectingAddFixture(t, 1, testVMUUIDB)
	run := f.reconcile(testVMUUID, testVMUUIDB)

	if err := run(); err == nil {
		t.Fatal("the rejected add must still be reported")
	}
	assertNoStandardNLBFence(t, f.provider.standardNLBServiceStore, f.service)
	if err := run(); err != nil {
		t.Fatalf("retry after the cleared receipt: %v", err)
	}
	if api.adds != 2 || len(api.fakeAPI.lbs[0].Targets) != 2 {
		t.Fatalf("retry: adds=%d targets=%v", api.adds, api.fakeAPI.lbs[0].Targets)
	}
}

func TestFailedAddDoesNotBlockRemovalWhileADesiredTargetServes(t *testing.T) {
	const stale = "99999999-1111-4222-8333-444444444444"
	api, f := newRejectingAddFixture(t, 99, testVMUUIDB, stale)
	run := f.reconcile(testVMUUID, testVMUUIDB)

	err := run()
	if err == nil {
		t.Fatal("the failed add must still be reported")
	}
	requireStandardNLBConvergence(t, func() error {
		f.advance(standardNLBRemovalAbsenceDelay + time.Second)
		err := run()
		if err != nil && !errors.Is(err, errStandardNLBRemovalPending) {
			return nil
		}
		return err
	})
	if !reflectStrings(api.fakeAPI.removedTargets, []string{stale}) {
		t.Fatalf("stale target removal = %v, want it removed while %s serves", api.fakeAPI.removedTargets, testVMUUIDB)
	}
}

func TestFailedAddNeverRemovesTheLastServingTarget(t *testing.T) {
	const stale = "99999999-1111-4222-8333-444444444444"
	api, f := newRejectingAddFixture(t, 99, stale)
	run := f.reconcile(testVMUUID)

	for range 3 {
		f.advance(standardNLBRemovalAbsenceDelay + time.Second)
		if err := run(); err == nil {
			t.Fatal("the failed add must still be reported")
		}
	}
	if len(api.fakeAPI.removedTargets) != 0 || len(api.fakeAPI.lbs[0].Targets) != 1 {
		t.Fatalf("removed %v although no desired target serves", api.fakeAPI.removedTargets)
	}
}

func TestFailedAddDoesNotBlockRuleUpdates(t *testing.T) {
	api, f := newRejectingAddFixture(t, 99, testVMUUIDB)
	api.fakeAPI.lbs[0].ForwardingRules = []inspace.LoadBalancerRule{
		{UUID: "77777777-1111-4222-8333-444444444444", Protocol: "TCP", SourcePort: 8443, TargetPort: 30001},
	}
	run := f.reconcile(testVMUUID, testVMUUIDB)

	for range 6 {
		f.advance(standardNLBRemovalAbsenceDelay + time.Second)
		_ = run()
	}
	if len(api.fakeAPI.addedRules) != 1 || len(api.fakeAPI.removedRules) != 1 {
		t.Fatalf("rules did not converge: add=%v remove=%v", api.fakeAPI.addedRules, api.fakeAPI.removedRules)
	}
}

func TestIssuedAddForATargetNoLongerWantedDoesNotBlock(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["AddLoadBalancerTarget"] = 1
	setOwnedLoadBalancer(f.api.fakeAPI, f.provider, f.service, []string{testVMUUIDB})

	if err := f.reconcile(testVMUUID, testVMUUIDB)(); err == nil {
		t.Fatal("first reconcile should report the ambiguous add")
	}
	// The node behind the stuck add is gone from the desired set.
	if err := f.reconcile(testVMUUIDB)(); err != nil {
		t.Fatalf("a receipt for an unwanted target blocked the reconcile: %v", err)
	}
	assertNoStandardNLBFence(t, f.provider.standardNLBServiceStore, f.service)
}
