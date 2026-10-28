package cloudprovider

import (
	"context"
	"strings"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

const (
	goneVMA = "99999999-1111-4222-8333-444444444441"
	goneVMB = "99999999-1111-4222-8333-444444444442"
	goneVMC = "99999999-1111-4222-8333-444444444443"
)

func lifecycleNotFound() error {
	return &inspace.APIError{StatusCode: 404, Method: "GET", Path: "/v1/bkk01/user-resource/vm", Message: "not found"}
}

func nodeFor(name, vmUUID string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{ProviderID: "inspace://bkk01/" + vmUUID},
	}
}

// lifecycleClock is a manual clock shared with the provider.
type lifecycleClock struct{ now time.Time }

func (c *lifecycleClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newLifecycleProvider(t *testing.T, api API) (*Provider, *lifecycleClock) {
	t.Helper()
	provider := newTestProvider(t, api)
	clock := &lifecycleClock{now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	provider.standardNLBNow = func() time.Time { return clock.now }
	return provider, clock
}

func emptyInventoryAPI() *resolvedVMReadErrorAPI {
	return &resolvedVMReadErrorAPI{
		fakeAPI:      &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}},
		getErr:       lifecycleNotFound(),
		overrideList: true,
		listResponse: []inspace.VM{},
	}
}

func TestEmptyInventoryAndVPCNeedTwoSpacedReadsToProveAbsence(t *testing.T) {
	provider, clock := newLifecycleProvider(t, emptyInventoryAPI())
	node := nodeFor("worker-0", testVMUUID)

	exists, err := provider.InstanceExists(context.Background(), node)
	if err == nil || exists {
		t.Fatalf("first read on empty lists = %t, %v; want an uncertainty error, not absence", exists, err)
	}
	clock.advance(standardNLBRemovalAbsenceDelay / 2)
	if exists, err := provider.InstanceExists(context.Background(), node); err == nil || exists {
		t.Fatalf("read inside the spacing window = %t, %v; want an uncertainty error", exists, err)
	}
	clock.advance(standardNLBRemovalAbsenceDelay)
	if exists, err := provider.InstanceExists(context.Background(), node); err != nil || exists {
		t.Fatalf("second spaced read = %t, %v; want false, nil", exists, err)
	}
}

func TestPopulatedInventoryProvesAbsenceImmediately(t *testing.T) {
	other := inspace.VM{UUID: "99999999-1111-4222-8333-444444444444"}
	api := &resolvedVMReadErrorAPI{
		fakeAPI:      &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{other.UUID}}},
		getErr:       lifecycleNotFound(),
		overrideList: true,
		listResponse: []inspace.VM{other},
	}
	provider, _ := newLifecycleProvider(t, api)
	if exists, err := provider.InstanceExists(context.Background(), nodeFor("worker-0", testVMUUID)); err != nil || exists {
		t.Fatalf("InstanceExists() = %t, %v; want false, nil with a populated inventory", exists, err)
	}
}

func TestMassAbsenceInOnePassIsRefusedAndReported(t *testing.T) {
	other := inspace.VM{UUID: "99999999-1111-4222-8333-444444444444"}
	api := &resolvedVMReadErrorAPI{
		fakeAPI:      &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{other.UUID}}},
		getErr:       lifecycleNotFound(),
		overrideList: true,
		listResponse: []inspace.VM{other},
	}
	provider, _ := newLifecycleProvider(t, api)
	events := record.NewFakeRecorder(8)
	provider.standardNLBEvents = events
	nodes := []*corev1.Node{
		nodeFor("w-a", goneVMA), nodeFor("w-b", goneVMB), nodeFor("w-c", goneVMC), nodeFor("w-d", testVMUUID),
	}
	setStandardNLBKubeNodes(provider, nodes...)

	// Two of four nodes is exactly half: still allowed.
	for _, node := range nodes[:2] {
		if exists, err := provider.InstanceExists(context.Background(), node); err != nil || exists {
			t.Fatalf("%s: InstanceExists() = %t, %v; want false, nil", node.Name, exists, err)
		}
	}
	// A third makes it more than half: refuse and say so.
	exists, err := provider.InstanceExists(context.Background(), nodes[2])
	if err == nil || exists || !strings.Contains(err.Error(), "more than half") {
		t.Fatalf("third absence = %t, %v; want a refusal naming the cluster-wide guard", exists, err)
	}
	if got := drainEvents(events); len(got) == 0 {
		t.Fatal("the refusal raised no Event")
	}
}

func metadataAPI(vm inspace.VM, floatingIPs []inspace.FloatingIP) *fakeAPI {
	return &fakeAPI{vms: []inspace.VM{vm}, floatingIPs: floatingIPs}
}

func TestInstanceMetadataRefusesAVMWithoutAPrivateAddress(t *testing.T) {
	vm := inspace.VM{
		UUID: testVMUUID, Name: "worker-0", Hostname: "worker-0", Status: "running",
		BillingAccountID: 42, NetworkUUID: testNetworkUUID, // PrivateIPv4 omitted
	}
	provider, _ := newLifecycleProvider(t, metadataAPI(vm, nil))
	node := nodeFor("worker-0", testVMUUID)
	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.7"}}
	if metadata, err := provider.InstanceMetadata(context.Background(), node); err == nil {
		t.Fatalf("InstanceMetadata() = %#v; want an error so the last good InternalIP is held", metadata)
	}
}

func TestInstanceMetadataHoldsTheExternalAddressThroughAnEmptyFloatingIPList(t *testing.T) {
	vm := inspace.VM{
		UUID: testVMUUID, Name: "worker-0", Hostname: "worker-0", Status: "running",
		BillingAccountID: 42, NetworkUUID: testNetworkUUID, PrivateIPv4: "10.0.0.7",
	}
	provider, clock := newLifecycleProvider(t, metadataAPI(vm, nil))
	node := nodeFor("worker-0", testVMUUID)
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.7"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	if _, err := provider.InstanceMetadata(context.Background(), node); err == nil {
		t.Fatal("an empty floating-IP answer dropped the node's ExternalIP at once")
	}
	clock.advance(addressShrinkGrace + time.Second)
	metadata, err := provider.InstanceMetadata(context.Background(), node)
	if err != nil {
		t.Fatalf("a persistent empty answer must eventually be accepted: %v", err)
	}
	for _, address := range metadata.NodeAddresses {
		if address.Type == corev1.NodeExternalIP {
			t.Fatalf("addresses still contain an ExternalIP: %v", metadata.NodeAddresses)
		}
	}
}

func TestInstanceMetadataWithoutAnExistingExternalAddressNeedsNoHold(t *testing.T) {
	vm := inspace.VM{
		UUID: testVMUUID, Name: "worker-0", Hostname: "worker-0", Status: "running",
		BillingAccountID: 42, NetworkUUID: testNetworkUUID, PrivateIPv4: "10.0.0.7",
	}
	provider, _ := newLifecycleProvider(t, metadataAPI(vm, nil))
	node := nodeFor("worker-0", testVMUUID)
	if _, err := provider.InstanceMetadata(context.Background(), node); err != nil {
		t.Fatal(err)
	}
}

// A real loss of every node must not stay refused forever: refused
// checks do not refresh their verdict, only allowed ones count, so the guard is
// a rate limit of at most half the cluster per window.
func TestMassAbsenceGuardIsARateLimitNotAPermanentRefusal(t *testing.T) {
	other := inspace.VM{UUID: "99999999-1111-4222-8333-444444444444"}
	api := &resolvedVMReadErrorAPI{
		fakeAPI:      &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{other.UUID}}},
		getErr:       lifecycleNotFound(),
		overrideList: true,
		listResponse: []inspace.VM{other},
	}
	provider, clock := newLifecycleProvider(t, api)
	nodes := []*corev1.Node{nodeFor("w-a", goneVMA), nodeFor("w-b", goneVMB), nodeFor("w-c", goneVMC)}
	setStandardNLBKubeNodes(provider, nodes...)
	ctx := context.Background()

	// All three VMs are really gone. One is allowed at once, the others are
	// refused no matter how often they are asked.
	if exists, err := provider.InstanceExists(ctx, nodes[0]); err != nil || exists {
		t.Fatalf("first absence = %t, %v; want allowed", exists, err)
	}
	for range 4 {
		clock.advance(time.Minute)
		for _, node := range nodes[1:] {
			if _, err := provider.InstanceExists(ctx, node); err == nil {
				t.Fatalf("%s: a second absence inside the window must be refused", node.Name)
			}
		}
	}
	// Refused checks left no verdict behind, so the window ends and the loss
	// drains at a rate of at most half the cluster per window.
	clock.advance(absenceVerdictWindow)
	if exists, err := provider.InstanceExists(ctx, nodes[1]); err != nil || exists {
		t.Fatalf("second absence after the window = %t, %v; want allowed", exists, err)
	}
	if _, err := provider.InstanceExists(ctx, nodes[2]); err == nil {
		t.Fatal("the third absence right after the second must wait for another window")
	}
	clock.advance(absenceVerdictWindow + time.Second)
	if exists, err := provider.InstanceExists(ctx, nodes[2]); err != nil || exists {
		t.Fatalf("third absence after another window = %t, %v; want allowed", exists, err)
	}
}

func TestSuccessfulVMReadClearsPendingEmptyEvidence(t *testing.T) {
	api := emptyInventoryAPI()
	provider, clock := newLifecycleProvider(t, api)
	node := nodeFor("worker-0", testVMUUID)
	ctx := context.Background()

	if _, err := provider.InstanceExists(ctx, node); err == nil {
		t.Fatal("first empty read must be uncertain")
	}
	// The VM is seen alive in between.
	api.getErr = nil
	api.fakeAPI.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{testVMUUID}}
	if exists, err := provider.InstanceExists(ctx, node); err != nil || !exists {
		t.Fatalf("live read = %t, %v; want true", exists, err)
	}
	// A later lone empty read, long after the first, must start over.
	clock.advance(10 * time.Minute)
	api.getErr = lifecycleNotFound()
	api.fakeAPI.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{}}
	if exists, err := provider.InstanceExists(ctx, node); err == nil || exists {
		t.Fatalf("lone empty read after a live read = %t, %v; want an uncertainty error", exists, err)
	}
}
