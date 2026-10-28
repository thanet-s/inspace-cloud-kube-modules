package cloudprovider

import (
	"context"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	corev1 "k8s.io/api/core/v1"
)

// slowMutationAPI models InSpace calls that outlive their deadline: the first
// dropFirst[op] calls return DeadlineExceeded without applying anything, and
// calls marked lateLand are queued and applied by flush.
type slowMutationAPI struct {
	*fakeAPI
	dropFirst map[string]int
	lateLand  map[string]bool
	calls     map[string]int
	queued    []func()
}

func newSlowMutationAPI() *slowMutationAPI {
	return &slowMutationAPI{
		fakeAPI: &fakeAPI{}, dropFirst: map[string]int{}, lateLand: map[string]bool{}, calls: map[string]int{},
	}
}

// gate returns true when the call must be swallowed.
func (a *slowMutationAPI) gate(op string, apply func()) bool {
	a.calls[op]++
	if a.dropFirst[op] >= a.calls[op] {
		if a.lateLand[op] {
			a.queued = append(a.queued, apply)
		}
		return true
	}
	return false
}

func (a *slowMutationAPI) flush() {
	for _, apply := range a.queued {
		apply()
	}
	a.queued = nil
}

func (a *slowMutationAPI) CreateLoadBalancer(ctx context.Context, l string, r inspace.CreateLoadBalancerRequest) (*inspace.LoadBalancer, error) {
	if a.gate("CreateLoadBalancer", func() { _, _ = a.fakeAPI.CreateLoadBalancer(ctx, l, r) }) {
		return nil, context.DeadlineExceeded
	}
	return a.fakeAPI.CreateLoadBalancer(ctx, l, r)
}

func (a *slowMutationAPI) CreateFloatingIP(ctx context.Context, l string, r inspace.CreateFloatingIPRequest) (*inspace.FloatingIP, error) {
	if a.gate("CreateFloatingIP", func() { _, _ = a.fakeAPI.CreateFloatingIP(ctx, l, r) }) {
		return nil, context.DeadlineExceeded
	}
	return a.fakeAPI.CreateFloatingIP(ctx, l, r)
}

func (a *slowMutationAPI) AssignFloatingIP(ctx context.Context, l, address, uuid, kind string) (*inspace.FloatingIP, error) {
	if a.gate("AssignFloatingIP", func() { _, _ = a.fakeAPI.AssignFloatingIP(ctx, l, address, uuid, kind) }) {
		return nil, context.DeadlineExceeded
	}
	return a.fakeAPI.AssignFloatingIP(ctx, l, address, uuid, kind)
}

func (a *slowMutationAPI) AddLoadBalancerTarget(ctx context.Context, l, lb, uuid string) (*inspace.LoadBalancerTarget, error) {
	if a.gate("AddLoadBalancerTarget", func() { _, _ = a.fakeAPI.AddLoadBalancerTarget(ctx, l, lb, uuid) }) {
		return nil, context.DeadlineExceeded
	}
	return a.fakeAPI.AddLoadBalancerTarget(ctx, l, lb, uuid)
}

func (a *slowMutationAPI) AddLoadBalancerRule(ctx context.Context, l, lb string, r inspace.LoadBalancerRule) (*inspace.LoadBalancerRule, error) {
	if a.gate("AddLoadBalancerRule", func() { _, _ = a.fakeAPI.AddLoadBalancerRule(ctx, l, lb, r) }) {
		return nil, context.DeadlineExceeded
	}
	return a.fakeAPI.AddLoadBalancerRule(ctx, l, lb, r)
}

type retireFixture struct {
	t        *testing.T
	api      *slowMutationAPI
	provider *Provider
	service  *corev1.Service
	nodes    []*corev1.Node
	now      time.Time
}

func newRetireFixture(t *testing.T) *retireFixture {
	t.Helper()
	f := &retireFixture{
		t: t, api: newSlowMutationAPI(), service: testService(),
		now:   time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		nodes: []*corev1.Node{readyNode("worker-0", "inspace://bkk01/"+testVMUUID)},
	}
	f.provider = newTestProvider(t, f.api)
	f.provider.standardNLBNow = func() time.Time { return f.now }
	f.provider.standardNLBAbsentDelay = standardNLBRemovalAbsenceDelay
	setStandardNLBKubeNodes(f.provider, f.nodes...)
	return f
}

func (f *retireFixture) ensure() error {
	_, err := f.provider.EnsureLoadBalancer(context.Background(), "ignored", f.service, f.nodes)
	return err
}

func (f *retireFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// passRetireWindow walks the clock past the retire delay and the spaced second
// read, running one reconcile after each step, and returns the last result.
func (f *retireFixture) passRetireWindow(operation string, run func() error) error {
	f.advance(standardNLBAdditiveRetireDelay(operation) + time.Second)
	_ = run() // the first absent read records the evidence
	f.advance(standardNLBRemovalAbsenceDelay + time.Second)
	return run()
}

func (f *retireFixture) reconcile(targets ...string) func() error {
	return func() error {
		lb, err := f.provider.findOwnedLoadBalancer(context.Background(), f.service)
		if err != nil {
			return err
		}
		return f.provider.reconcileLoadBalancer(context.Background(), f.service, lb, targets, serviceRules(f.service))
	}
}

func TestSlowAddTargetIsRetiredAndReplayedOnlyAfterSpacedAbsence(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["AddLoadBalancerTarget"] = 1
	const stale = "99999999-1111-4222-8333-444444444444"
	setOwnedLoadBalancer(f.api.fakeAPI, f.provider, f.service, []string{stale})
	run := f.reconcile(testVMUUID)

	if err := run(); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("first reconcile = %v, want ambiguous", err)
	}
	f.advance(time.Minute)
	if err := run(); err == nil || f.api.calls["AddLoadBalancerTarget"] != 1 {
		t.Fatalf("within the retire delay: err=%v calls=%d, want a pending error and no replay", err, f.api.calls["AddLoadBalancerTarget"])
	}
	f.advance(standardNLBAdditiveRetireDelay(standardNLBAddTarget))
	if err := run(); err == nil || f.api.calls["AddLoadBalancerTarget"] != 1 {
		t.Fatalf("first absent read: err=%v calls=%d, want a pending error and no replay", err, f.api.calls["AddLoadBalancerTarget"])
	}
	f.advance(standardNLBRemovalAbsenceDelay + time.Second)
	requireStandardNLBConvergence(t, func() error {
		f.advance(standardNLBRemovalAbsenceDelay + time.Second)
		return run()
	})
	if f.api.calls["AddLoadBalancerTarget"] != 2 {
		t.Fatalf("replay calls = %d, want exactly one replay", f.api.calls["AddLoadBalancerTarget"])
	}
	if !reflectStrings(f.api.removedTargets, []string{stale}) {
		t.Fatalf("stale target removal = %v", f.api.removedTargets)
	}
}

func TestSlowAddTargetThatLandsLateIsAdoptedWithoutReplay(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["AddLoadBalancerTarget"] = 1
	f.api.lateLand["AddLoadBalancerTarget"] = true
	setOwnedLoadBalancer(f.api.fakeAPI, f.provider, f.service, []string{testVMUUIDB})
	run := f.reconcile(testVMUUID, testVMUUIDB)

	if err := run(); err == nil {
		t.Fatal("first reconcile should report the ambiguous add")
	}
	f.advance(time.Minute)
	f.api.flush()
	if err := run(); err != nil {
		t.Fatalf("late landing was not adopted: %v", err)
	}
	if f.api.calls["AddLoadBalancerTarget"] != 1 {
		t.Fatalf("late landing was replayed: %d calls", f.api.calls["AddLoadBalancerTarget"])
	}
}

func TestSlowAddRuleIsRetiredAndReplayedAfterSpacedAbsence(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["AddLoadBalancerRule"] = 1
	setOwnedLoadBalancer(f.api.fakeAPI, f.provider, f.service, []string{testVMUUID})
	f.api.lbs[0].ForwardingRules = []inspace.LoadBalancerRule{}
	run := f.reconcile(testVMUUID)

	if err := run(); err == nil {
		t.Fatal("first reconcile should report the ambiguous add")
	}
	_ = f.passRetireWindow(standardNLBAddRule, run)
	requireStandardNLBConvergence(t, run)
	if f.api.calls["AddLoadBalancerRule"] != 2 || len(f.api.lbs[0].ForwardingRules) != 1 {
		t.Fatalf("rule replay: calls=%d rules=%v", f.api.calls["AddLoadBalancerRule"], f.api.lbs[0].ForwardingRules)
	}
}

func TestSlowFloatingIPAssignmentIsRetiredAndReplayed(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["AssignFloatingIP"] = 1
	if err := f.ensure(); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("first Ensure = %v, want ambiguous assignment", err)
	}
	if err := f.ensure(); err == nil || f.api.calls["AssignFloatingIP"] != 1 {
		t.Fatalf("within the delay: err=%v calls=%d", err, f.api.calls["AssignFloatingIP"])
	}
	_ = f.passRetireWindow(standardNLBAssignFloatingIP, f.ensure)
	if err := f.ensure(); err != nil {
		t.Fatal(err)
	}
	if f.api.calls["AssignFloatingIP"] != 2 || f.api.floatingIPs[0].AssignedTo == "" {
		t.Fatalf("assignment replay: calls=%d fip=%#v", f.api.calls["AssignFloatingIP"], f.api.floatingIPs)
	}
}

func TestSlowNLBCreateIsRecreatedAtMostOnce(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["CreateLoadBalancer"] = 5
	if err := f.ensure(); err == nil {
		t.Fatal("first Ensure should report the ambiguous create")
	}
	f.advance(time.Minute)
	if err := f.ensure(); err == nil || f.api.calls["CreateLoadBalancer"] != 1 {
		t.Fatalf("within the delay: err=%v creates=%d, want no second paid create", err, f.api.calls["CreateLoadBalancer"])
	}
	_ = f.passRetireWindow(standardNLBCreateLoadBalancer, f.ensure)
	if f.api.calls["CreateLoadBalancer"] != 2 {
		t.Fatalf("creates after the retire window = %d, want exactly one re-create", f.api.calls["CreateLoadBalancer"])
	}
	err := f.passRetireWindow(standardNLBCreateLoadBalancer, f.ensure)
	if f.api.calls["CreateLoadBalancer"] != 2 || err == nil || !strings.Contains(err.Error(), "manually") {
		t.Fatalf("third create must stay refused: creates=%d err=%v", f.api.calls["CreateLoadBalancer"], err)
	}
}

func TestSlowNLBCreateThatLandsLateIsAdoptedNotRecreated(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["CreateLoadBalancer"] = 1
	f.api.lateLand["CreateLoadBalancer"] = true
	if err := f.ensure(); err == nil {
		t.Fatal("first Ensure should report the ambiguous create")
	}
	f.advance(10 * time.Minute)
	f.api.flush()
	requireStandardNLBConvergence(t, f.ensure)
	if f.api.calls["CreateLoadBalancer"] != 1 || len(f.api.lbs) != 1 {
		t.Fatalf("late create: calls=%d LBs=%d", f.api.calls["CreateLoadBalancer"], len(f.api.lbs))
	}
}

func TestSlowNLBCreateAdoptedAfterNodesChangedIsReconciled(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["CreateLoadBalancer"] = 1
	f.api.lateLand["CreateLoadBalancer"] = true
	if err := f.ensure(); err == nil {
		t.Fatal("first Ensure should report the ambiguous create")
	}
	f.nodes = append(f.nodes, readyNode("worker-1", "inspace://bkk01/"+testVMUUIDB))
	setStandardNLBKubeNodes(f.provider, f.nodes...)
	f.advance(time.Minute)
	f.api.flush()
	requireStandardNLBConvergence(t, f.ensure)
	if f.api.calls["CreateLoadBalancer"] != 1 || len(f.api.lbs) != 1 || len(f.api.lbs[0].Targets) != 2 {
		t.Fatalf("adoption after node change: creates=%d LBs=%#v", f.api.calls["CreateLoadBalancer"], f.api.lbs)
	}
}

func TestSlowFloatingIPCreateIsRecreatedAtMostOnce(t *testing.T) {
	f := newRetireFixture(t)
	f.api.dropFirst["CreateFloatingIP"] = 5
	if err := f.ensure(); err == nil {
		t.Fatal("first Ensure should report the ambiguous FIP create")
	}
	f.advance(time.Minute)
	if err := f.ensure(); err == nil || f.api.calls["CreateFloatingIP"] != 1 {
		t.Fatalf("within the delay: err=%v creates=%d", err, f.api.calls["CreateFloatingIP"])
	}
	_ = f.passRetireWindow(standardNLBCreateFloatingIP, f.ensure)
	if f.api.calls["CreateFloatingIP"] != 2 {
		t.Fatalf("FIP creates = %d, want exactly one re-create", f.api.calls["CreateFloatingIP"])
	}
	err := f.passRetireWindow(standardNLBCreateFloatingIP, f.ensure)
	if f.api.calls["CreateFloatingIP"] != 2 || err == nil || !strings.Contains(err.Error(), "manually") {
		t.Fatalf("third FIP create must stay refused: creates=%d err=%v", f.api.calls["CreateFloatingIP"], err)
	}
}

func TestAdditiveRetireDelayFollowsEachOperationsOwnDeadline(t *testing.T) {
	for operation, want := range map[string]time.Duration{
		standardNLBAddTarget:          2*time.Minute + 30*time.Second,
		standardNLBAddRule:            2*time.Minute + 30*time.Second,
		standardNLBAssignFloatingIP:   3*time.Minute + 30*time.Second,
		standardNLBCreateFloatingIP:   2 * time.Minute,
		standardNLBCreateLoadBalancer: 5*time.Minute + 30*time.Second,
	} {
		if got := standardNLBAdditiveRetireDelay(operation); got != want {
			t.Errorf("retire delay for %s = %s, want %s", operation, got, want)
		}
	}
}
