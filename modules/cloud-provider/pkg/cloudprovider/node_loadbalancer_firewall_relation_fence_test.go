package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const (
	testFirewallRelationFirewallUUID = "71111111-2222-4333-8444-555555555555"
	testFirewallRelationVMUUID       = "72222222-2222-4333-8444-555555555555"
)

type ambiguousFirewallRelationAPI struct {
	*fakeAPI

	mu            sync.Mutex
	operation     nodeLoadBalancerFirewallRelationOperation
	hiddenReads   int
	committed     bool
	mutationCalls int
}

type blockedFirewallRelationAPI struct {
	*fakeAPI
	cancel      context.CancelFunc
	listCalls   int
	assignCalls int
}

type legacyFirewallRelationMigrationAPI struct {
	*fakeAPI
	listCalls     int
	assignCalls   int
	unassignCalls int
}

func (a *blockedFirewallRelationAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.listCalls++
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func (a *blockedFirewallRelationAPI) AssignFirewallToVM(context.Context, string, string, string) error {
	a.assignCalls++
	if a.cancel != nil {
		a.cancel()
	}
	return inspace.ErrMutationBlocked
}

func (a *legacyFirewallRelationMigrationAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	a.listCalls++
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func (a *legacyFirewallRelationMigrationAPI) AssignFirewallToVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.assignCalls++
	return a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func (a *legacyFirewallRelationMigrationAPI) UnassignFirewallFromVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.unassignCalls++
	return a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

func (a *ambiguousFirewallRelationAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	result := cloneNodeLoadBalancerTestFirewalls(items)
	if !a.committed || a.hiddenReads == 0 {
		return result, nil
	}
	a.hiddenReads--
	for index := range result {
		if result[index].UUID != testFirewallRelationFirewallUUID {
			continue
		}
		if a.operation == nodeLoadBalancerFirewallRelationAssign {
			filtered := result[index].ResourcesAssigned[:0]
			for _, relation := range result[index].ResourcesAssigned {
				if !strings.EqualFold(relation.ResourceType, "vm") || relation.ResourceUUID != testFirewallRelationVMUUID {
					filtered = append(filtered, relation)
				}
			}
			result[index].ResourcesAssigned = filtered
		} else {
			result[index].ResourcesAssigned = append(result[index].ResourcesAssigned, inspace.FirewallResource{
				ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
			})
		}
	}
	return result, nil
}

func (a *ambiguousFirewallRelationAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mutationCalls++
	if err := a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID); err != nil {
		return err
	}
	a.committed = true
	return &inspace.APIError{StatusCode: 500, Method: "POST", Path: "/firewall/vms", Message: "committed but response lost", Retryable: true}
}

func (a *ambiguousFirewallRelationAPI) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mutationCalls++
	if err := a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID); err != nil {
		return err
	}
	a.committed = true
	return &inspace.APIError{StatusCode: 500, Method: "DELETE", Path: "/firewall/vms", Message: "committed but response lost", Retryable: true}
}

func cloneNodeLoadBalancerTestFirewalls(items []inspace.Firewall) []inspace.Firewall {
	result := append([]inspace.Firewall(nil), items...)
	for index := range result {
		result[index].ResourcesAssigned = append([]inspace.FirewallResource(nil), items[index].ResourcesAssigned...)
		result[index].Rules = append([]inspace.FirewallRule(nil), items[index].Rules...)
	}
	return result
}

type firewallRelationOwnerHarness struct {
	provider        *Provider
	owner           func(*nodeLoadBalancerController) nodeLoadBalancerFirewallRelationOwner
	readAnnotations func(context.Context) (map[string]string, error)
	replaceOwner    func(context.Context) error
}

type deletedRelationVMReadbackAPI struct {
	*fakeAPI
	exact  inspace.VM
	listed []inspace.VM
}

func (a *deletedRelationVMReadbackAPI) GetVM(context.Context, string, string) (*inspace.VM, error) {
	copy := a.exact
	return &copy, nil
}

func (a *deletedRelationVMReadbackAPI) ListVMs(context.Context, string) ([]inspace.VM, error) {
	return append([]inspace.VM(nil), a.listed...), nil
}

func TestNodeLoadBalancerRelationDeletedVMTombstoneNeedsCanonicalMultiSourceAbsence(t *testing.T) {
	base := inspace.VM{
		UUID: testFirewallRelationVMUUID, Status: "Deleted", BillingAccountID: 42, NetworkUUID: testNetworkUUID,
	}
	for _, test := range []struct {
		name       string
		exact      inspace.VM
		listed     []inspace.VM
		members    []string
		wantAbsent bool
	}{
		{name: "canonical absence", exact: base, wantAbsent: true},
		{name: "still listed", exact: base, listed: []inspace.VM{base}},
		{name: "still in VPC", exact: base, members: []string{testFirewallRelationVMUUID}},
		{name: "wrong billing", exact: func() inspace.VM { vm := base; vm.BillingAccountID++; return vm }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &deletedRelationVMReadbackAPI{
				fakeAPI: &fakeAPI{network: &inspace.Network{UUID: testNetworkUUID, VMUUIDs: test.members}},
				exact:   test.exact, listed: test.listed,
			}
			controller := &nodeLoadBalancerController{provider: newTestProvider(t, api)}
			owned, absent, err := controller.nodeLoadBalancerFirewallRelationVMCloudAuthority(context.Background(), testFirewallRelationVMUUID)
			if test.wantAbsent {
				if err != nil || owned || !absent {
					t.Fatalf("canonical tombstone authority: owned=%t absent=%t err=%v", owned, absent, err)
				}
				return
			}
			if err == nil || owned || absent {
				t.Fatalf("non-canonical tombstone authority: owned=%t absent=%t err=%v", owned, absent, err)
			}
		})
	}
}

// withoutFirewallRelationCloudAuthorityForFenceTest keeps the serialization
// tests focused on durable issue/readback behavior. Production owner
// constructors always install the real pre-dispatch authority; dedicated tests
// below exercise that boundary with full cloud/Kubernetes identity fixtures.
func withoutFirewallRelationCloudAuthorityForFenceTest(
	owner nodeLoadBalancerFirewallRelationOwner,
) nodeLoadBalancerFirewallRelationOwner {
	owner.authorize = func(context.Context, nodeLoadBalancerFirewallRelationFence, inspace.Firewall) error { return nil }
	return owner
}

func newFirewallRelationOwnerHarness(t *testing.T, path string, api API) firewallRelationOwnerHarness {
	t.Helper()
	provider := newTestProvider(t, api)
	switch path {
	case "per-service":
		service := nodeLoadBalancerTestService("relation-service", "relation-service-uid", corev1.ProtocolTCP, 443)
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		return firewallRelationOwnerHarness{
			provider: provider,
			owner: func(controller *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationOwner {
				return withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
			},
			readAnnotations: func(ctx context.Context) (map[string]string, error) {
				stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return stored.Annotations, nil
			},
			replaceOwner: func(ctx context.Context) error {
				stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				replacement := stored.DeepCopy()
				replacement.ResourceVersion = ""
				replacement.UID = types.UID("replacement-" + string(stored.UID))
				if err := provider.kubeClient.CoreV1().Services(service.Namespace).Delete(ctx, service.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				_, err = provider.kubeClient.CoreV1().Services(service.Namespace).Create(ctx, replacement, metav1.CreateOptions{})
				return err
			},
		}
	case "public-node-local":
		service := publicNodeLocalTestService("relation-local", "relation-local-uid", "edge", corev1.ProtocolTCP, 443)
		provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
		return firewallRelationOwnerHarness{
			provider: provider,
			owner: func(controller *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationOwner {
				return withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
			},
			readAnnotations: func(ctx context.Context) (map[string]string, error) {
				stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return stored.Annotations, nil
			},
			replaceOwner: func(ctx context.Context) error {
				stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				replacement := stored.DeepCopy()
				replacement.ResourceVersion = ""
				replacement.UID = types.UID("replacement-" + string(stored.UID))
				if err := provider.kubeClient.CoreV1().Services(service.Namespace).Delete(ctx, service.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				_, err = provider.kubeClient.CoreV1().Services(service.Namespace).Create(ctx, replacement, metav1.CreateOptions{})
				return err
			},
		}
	case "shared-shard":
		const shard = "inlb-7a7a7a7a"
		pool := nodeLoadBalancerSafetyNodePool(shard, provider.config.ClusterID, nodeLoadBalancerModeShared, 1)
		provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(pool)
		return firewallRelationOwnerHarness{
			provider: provider,
			owner: func(controller *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationOwner {
				return withoutFirewallRelationCloudAuthorityForFenceTest(controller.shardFirewallRelationOwner(shard))
			},
			readAnnotations: func(ctx context.Context) (map[string]string, error) {
				stored, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, shard, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return stored.GetAnnotations(), nil
			},
			replaceOwner: func(ctx context.Context) error {
				resource := provider.dynamicClient.Resource(nodePoolGVR)
				stored, err := resource.Get(ctx, shard, metav1.GetOptions{})
				if err != nil {
					return err
				}
				replacement := stored.DeepCopy()
				replacement.SetResourceVersion("")
				replacement.SetUID(types.UID("replacement-" + string(stored.GetUID())))
				if err := resource.Delete(ctx, shard, metav1.DeleteOptions{}); err != nil {
					return err
				}
				_, err = resource.Create(ctx, replacement, metav1.CreateOptions{})
				return err
			},
		}
	case "cluster-icmp":
		name := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
		nodeClass, err := renderNodeLoadBalancerNodeClass(nodeLoadBalancerSafetyBaseNodeClass(), name)
		if err != nil {
			t.Fatal(err)
		}
		if err := markNodeLoadBalancerManaged(nodeClass, provider.config.ClusterID, "", ""); err != nil {
			t.Fatal(err)
		}
		provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(nodeClass)
		return firewallRelationOwnerHarness{
			provider: provider,
			owner: func(controller *nodeLoadBalancerController) nodeLoadBalancerFirewallRelationOwner {
				return withoutFirewallRelationCloudAuthorityForFenceTest(controller.clusterICMPFirewallRelationOwner(name))
			},
			readAnnotations: func(ctx context.Context) (map[string]string, error) {
				stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return stored.GetAnnotations(), nil
			},
			replaceOwner: func(ctx context.Context) error {
				resource := provider.dynamicClient.Resource(nodeClassGVR)
				stored, err := resource.Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				replacement := stored.DeepCopy()
				replacement.SetResourceVersion("")
				replacement.SetUID(types.UID("replacement-" + string(stored.GetUID())))
				if err := resource.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				_, err = resource.Create(ctx, replacement, metav1.CreateOptions{})
				return err
			},
		}
	default:
		t.Fatalf("unknown relation owner path %q", path)
		return firewallRelationOwnerHarness{}
	}
}

func TestNodeLoadBalancerFirewallRelationCommitted500NeverReissuesAfterRestart(t *testing.T) {
	for _, path := range []string{"per-service", "public-node-local", "shared-shard", "cluster-icmp"} {
		for _, operation := range []nodeLoadBalancerFirewallRelationOperation{
			nodeLoadBalancerFirewallRelationAssign,
			nodeLoadBalancerFirewallRelationUnassign,
		} {
			t.Run(path+"/"+string(operation), func(t *testing.T) {
				ctx := context.Background()
				now := time.Date(2026, 7, 17, 1, 0, 0, 0, time.UTC)
				clock := func() time.Time { return now }
				firewall := inspace.Firewall{UUID: testFirewallRelationFirewallUUID}
				if operation == nodeLoadBalancerFirewallRelationUnassign {
					firewall.ResourcesAssigned = []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID}}
				}
				api := &ambiguousFirewallRelationAPI{
					// One hidden read is consumed by the mandatory post-error
					// verification; the second proves a restart also stays read-only.
					fakeAPI: &fakeAPI{
						firewalls: []inspace.Firewall{firewall},
						vms: []inspace.VM{{
							UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID,
						}},
					}, operation: operation, hiddenReads: 2,
				}
				harness := newFirewallRelationOwnerHarness(t, path, api)
				controller := &nodeLoadBalancerController{
					provider: harness.provider, firewallRelationNow: clock,
					firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
				}
				fence := &nodeLoadBalancerFirewallRelationFence{
					operation: operation, firewallUUID: testFirewallRelationFirewallUUID, vmUUID: testFirewallRelationVMUUID,
				}

				if converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, harness.owner(controller), fence); err == nil || converged {
					t.Fatalf("committed HTTP 500 did not remain fenced: converged=%t err=%v", converged, err)
				}
				if api.mutationCalls != 1 {
					t.Fatalf("initial mutation calls = %d, want 1", api.mutationCalls)
				}
				annotations, err := harness.readAnnotations(ctx)
				if err != nil {
					t.Fatal(err)
				}
				issued, parseErr := parseNodeLoadBalancerFirewallRelationFence(annotations[annotationNodeLoadBalancerFirewallRelationIssued])
				if parseErr != nil || issued.logicalString() != fence.logicalString() || issued.issueID == "" || issued.issuedAt == "" {
					t.Fatalf("issued fence = %#v, %v; want logical %q with unique issue identity", issued, parseErr, fence.logicalString())
				}

				restarted := &nodeLoadBalancerController{
					provider: harness.provider, firewallRelationNow: clock,
					firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
				}
				if converged, err := restarted.reconcileNodeLoadBalancerFirewallRelation(ctx, harness.owner(restarted), fence); err == nil || converged {
					t.Fatalf("hidden restart readback did not fail closed: converged=%t err=%v", converged, err)
				}
				if api.mutationCalls != 1 {
					t.Fatalf("hidden restart reissued mutation: %d calls", api.mutationCalls)
				}
				converged, visibleErr := restarted.reconcileNodeLoadBalancerFirewallRelation(ctx, harness.owner(restarted), fence)
				if operation == nodeLoadBalancerFirewallRelationUnassign {
					if visibleErr == nil || converged {
						t.Fatalf("first visible removal absence did not remain durably fenced: converged=%t err=%v", converged, visibleErr)
					}
					annotations, err = harness.readAnnotations(ctx)
					if err != nil {
						t.Fatal(err)
					}
					observed, parseErr := parseNodeLoadBalancerFirewallRelationFence(annotations[annotationNodeLoadBalancerFirewallRelationIssued])
					if parseErr != nil || observed.absenceObservedAt == "" {
						t.Fatalf("first removal absence was not durably recorded: %#v err=%v", observed, parseErr)
					}
					now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
					converged, visibleErr = restarted.reconcileNodeLoadBalancerFirewallRelation(ctx, harness.owner(restarted), fence)
				}
				if visibleErr != nil || converged {
					t.Fatalf("visible restart readback did not clear and stop after exact fence: converged=%t err=%v", converged, visibleErr)
				}
				if api.mutationCalls != 1 {
					t.Fatalf("visible restart reissued mutation: %d calls", api.mutationCalls)
				}
				annotations, err = harness.readAnnotations(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
					t.Fatalf("resolved relation retained issued fence: %#v", annotations)
				}
				if converged, err := restarted.reconcileNodeLoadBalancerFirewallRelation(ctx, harness.owner(restarted), fence); err != nil || !converged {
					t.Fatalf("fresh post-clear readback did not prove convergence: converged=%t err=%v", converged, err)
				}
				if api.mutationCalls != 1 {
					t.Fatalf("post-clear convergence reissued mutation: %d calls", api.mutationCalls)
				}
			})
		}
	}
}

type transientlyOmittedUnassignAPI struct {
	*fakeAPI
	listCalls     int
	unassignCalls int
}

func (a *transientlyOmittedUnassignAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	a.listCalls++
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	if a.listCalls == 2 {
		// The first post-DELETE observation transiently omits the entire row even
		// though the ambiguous DELETE below did not commit.
		return nil, nil
	}
	return cloneNodeLoadBalancerTestFirewalls(items), nil
}

func (a *transientlyOmittedUnassignAPI) UnassignFirewallFromVM(
	context.Context,
	string,
	string,
	string,
) error {
	a.unassignCalls++
	return &inspace.APIError{
		StatusCode: 500,
		Method:     "DELETE",
		Path:       "/firewall/vms",
		Message:    "ambiguous response without commit",
		Retryable:  true,
	}
}

func TestNodeLoadBalancerFirewallRelationTransientRemovalOmissionNeverReissues(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-omission", "relation-omission-uid", corev1.ProtocolTCP, 443)
	api := &transientlyOmittedUnassignAPI{fakeAPI: &fakeAPI{
		vms: []inspace.VM{{UUID: testFirewallRelationVMUUID, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		firewalls: []inspace.Firewall{{
			UUID: testFirewallRelationFirewallUUID,
			ResourcesAssigned: []inspace.FirewallResource{{
				ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
			}},
		}},
	}}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	now := time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	controller := &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: clock,
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationUnassign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}

	if converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)), desired,
	); err == nil || converged {
		t.Fatalf("ambiguous removal with transient omission did not remain fenced: converged=%t err=%v", converged, err)
	}
	if api.unassignCalls != 1 {
		t.Fatalf("initial unassign calls = %d, want 1", api.unassignCalls)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	issued, err := parseNodeLoadBalancerFirewallRelationFence(stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued])
	if err != nil || issued.absenceObservedAt == "" {
		t.Fatalf("transient omission lacks durable first-absence proof: %#v err=%v", issued, err)
	}

	// Even after the confirmation window, the relation's reappearance must reset
	// the first observation and keep the original issue read-only across restart.
	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	restarted := &nodeLoadBalancerController{
		provider: provider, firewallRelationNow: clock,
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	if converged, err := restarted.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(restarted.serviceFirewallRelationOwner(stored)), desired,
	); err == nil || converged {
		t.Fatalf("reappeared relation did not retain its original issue: converged=%t err=%v", converged, err)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	issued, err = parseNodeLoadBalancerFirewallRelationFence(stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued])
	if err != nil || issued.absenceObservedAt != "" {
		t.Fatalf("reappeared relation did not reset only its absence proof: %#v err=%v", issued, err)
	}
	if converged, err := restarted.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(restarted.serviceFirewallRelationOwner(stored)), desired,
	); err == nil || converged {
		t.Fatalf("restarted unresolved relation did not stay read-only: converged=%t err=%v", converged, err)
	}
	if api.unassignCalls != 1 {
		t.Fatalf("transient omission/reappearance reissued DELETE: calls=%d", api.unassignCalls)
	}
}

func TestNodeLoadBalancerFirewallDetachRequiresSpacedExactDeletedVMProof(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{firewalls: []inspace.Firewall{{
		UUID: testFirewallRelationFirewallUUID,
		ResourcesAssigned: []inspace.FirewallResource{{
			ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
		}},
	}}}
	harness := newFirewallRelationOwnerHarness(t, "per-service", api)
	now := time.Date(2026, 7, 17, 6, 0, 0, 0, time.UTC)
	controller := &nodeLoadBalancerController{
		provider: harness.provider,
		firewallRelationNow: func() time.Time {
			return now
		},
		firewallRelationAbsentDelay: nodeLoadBalancerAbsenceConfirmationDelay,
	}
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationUnassign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}

	for attempt := 0; attempt < 2; attempt++ {
		converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
			ctx,
			harness.owner(controller),
			desired,
		)
		if err == nil || converged || !strings.Contains(err.Error(), "spaced exact VM-absence") {
			t.Fatalf("pre-delay deleted-VM proof %d = converged %t, err %v", attempt, converged, err)
		}
		if len(api.unassignedFirewalls) != 0 {
			t.Fatalf("pre-delay deleted-VM proof issued detach: %#v", api.unassignedFirewalls)
		}
	}
	annotations, err := harness.readAnnotations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if annotations[annotationNodeLoadBalancerFirewallRelationVMAbsent] == "" ||
		annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("deleted-VM absence was not durably staged before issue: %#v", annotations)
	}

	now = now.Add(nodeLoadBalancerAbsenceConfirmationDelay + time.Second)
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		harness.owner(controller),
		desired,
	)
	if err == nil || converged {
		t.Fatalf("issued deleted-VM detach did not remain behind removal readback: converged=%t err=%v", converged, err)
	}
	if got := api.unassignedFirewalls; len(got) != 1 ||
		got[0] != testFirewallRelationFirewallUUID+"/"+testFirewallRelationVMUUID {
		t.Fatalf("deleted-VM detach calls = %#v, want exactly one", got)
	}
	annotations, err = harness.readAnnotations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := parseNodeLoadBalancerFirewallRelationFence(
		annotations[annotationNodeLoadBalancerFirewallRelationIssued],
	)
	if err != nil || issued.targetAbsentAt == "" {
		t.Fatalf("issued deleted-VM detach lacks durable absence proof: %#v err=%v", issued, err)
	}
}

func TestNodeLoadBalancerFirewallDetachRejectsForeignExistingVM(t *testing.T) {
	ctx := context.Background()
	api := &fakeAPI{
		vms: []inspace.VM{{
			UUID: testFirewallRelationVMUUID, BillingAccountID: 43, NetworkUUID: testNetworkUUID,
		}},
		firewalls: []inspace.Firewall{{
			UUID: testFirewallRelationFirewallUUID,
			ResourcesAssigned: []inspace.FirewallResource{{
				ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID,
			}},
		}},
	}
	harness := newFirewallRelationOwnerHarness(t, "per-service", api)
	controller := &nodeLoadBalancerController{provider: harness.provider}
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationUnassign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
	if converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		harness.owner(controller),
		desired,
	); err == nil || converged || !strings.Contains(err.Error(), "foreign billing") {
		t.Fatalf("foreign existing VM detach = converged %t, err %v", converged, err)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("foreign existing VM authorized detach: %#v", api.unassignedFirewalls)
	}
	annotations, err := harness.readAnnotations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("foreign existing VM acquired issued detach authority: %#v", annotations)
	}
}

type ambiguousServiceFirewallCreateAPI struct {
	*fakeAPI
	mu          sync.Mutex
	committed   bool
	hiddenReads int
	createCalls int
}

func (a *ambiguousServiceFirewallCreateAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	if a.committed && a.hiddenReads > 0 {
		a.hiddenReads--
		return nil, nil
	}
	return cloneNodeLoadBalancerTestFirewalls(items), nil
}

func (a *ambiguousServiceFirewallCreateAPI) CreateFirewall(ctx context.Context, location string, request inspace.CreateFirewallRequest) (*inspace.Firewall, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.createCalls++
	if _, err := a.fakeAPI.CreateFirewall(ctx, location, request); err != nil {
		return nil, err
	}
	a.committed = true
	return nil, &inspace.APIError{StatusCode: 500, Method: "POST", Path: "/firewall", Message: "committed but response lost", Retryable: true}
}

func TestNodeLoadBalancerServiceFirewallCreateCommitted500NeverRepostsAfterRestart(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("create-fence", "create-fence-uid", corev1.ProtocolTCP, 443)
	// Include the immediate post-error readback plus the restart passes below.
	api := &ambiguousServiceFirewallCreateAPI{fakeAPI: &fakeAPI{}, hiddenReads: nodeLoadBalancerAbsenceConfirmations + 1}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	if _, _, _, err := controller.ensureServiceFirewall(ctx, service, nil); err == nil || !strings.Contains(err.Error(), "create Service firewall") {
		t.Fatalf("committed create HTTP 500 did not fail closed: %v", err)
	}
	if api.createCalls != 1 {
		t.Fatalf("initial create calls = %d, want 1", api.createCalls)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] == "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFirewall] != "" {
		t.Fatalf("ambiguous create lacks immutable issued fence: %#v", stored.Annotations)
	}

	restarted := &nodeLoadBalancerController{provider: provider}
	for attempt := 0; attempt < nodeLoadBalancerAbsenceConfirmations; attempt++ {
		if _, _, _, err := restarted.ensureServiceFirewall(ctx, stored, nil); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
			t.Fatalf("hidden restart readback %d did not retain create fence: %v", attempt, err)
		}
		if api.createCalls != 1 {
			t.Fatalf("hidden restart %d issued %d creates, want 1", attempt, api.createCalls)
		}
		stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
		if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] == "" {
			t.Fatalf("hidden restart %d cleared immutable create fence: %#v", attempt, stored.Annotations)
		}
	}
	if _, _, _, err := restarted.ensureServiceFirewall(ctx, stored, nil); err != nil {
		t.Fatal(err)
	}
	if api.createCalls != 1 {
		t.Fatalf("visible restart issued %d creates, want 1", api.createCalls)
	}
	stored = getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerPendingFWIssued] != "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFWIssuedAt] != "" ||
		stored.Annotations[annotationNodeLoadBalancerPendingFirewall] == "" {
		t.Fatalf("exact deterministic adoption did not resolve create-issued fence: %#v", stored.Annotations)
	}
}

type concurrentFirewallRelationAPI struct {
	*fakeAPI
	mu          sync.Mutex
	listCalls   atomic.Int32
	firstLists  chan struct{}
	mutationCnt int
}

func (a *concurrentFirewallRelationAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	call := a.listCalls.Add(1)
	if call <= 2 {
		if call == 2 {
			close(a.firstLists)
		}
		<-a.firstLists
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	return cloneNodeLoadBalancerTestFirewalls(items), err
}

func (a *concurrentFirewallRelationAPI) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mutationCnt++
	return a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func TestNodeLoadBalancerFirewallRelationConcurrentCASIssuesOnce(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-race", "relation-race-uid", corev1.ProtocolTCP, 443)
	service.ResourceVersion = "1"
	api := &concurrentFirewallRelationAPI{
		fakeAPI:    &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}},
		firstLists: make(chan struct{}),
	}
	provider := newTestProvider(t, api)
	client := kubefake.NewSimpleClientset(service.DeepCopy())
	provider.kubeClient = client

	var versionMu sync.Mutex
	version := int64(1)
	client.Fake.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update := action.(k8stesting.UpdateAction).GetObject().(*corev1.Service)
		versionMu.Lock()
		defer versionMu.Unlock()
		if update.ResourceVersion != strconv.FormatInt(version, 10) {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "services"}, update.Name, errors.New("stale relation fence resourceVersion"))
		}
		version++
		update.ResourceVersion = strconv.FormatInt(version, 10)
		return false, nil, nil
	})

	fence := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
	controllers := []*nodeLoadBalancerController{{provider: provider}, {provider: provider}}
	errs := make(chan error, len(controllers))
	var wg sync.WaitGroup
	for _, controller := range controllers {
		wg.Add(1)
		go func(controller *nodeLoadBalancerController) {
			defer wg.Done()
			_, err := controller.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
				fence,
			)
			errs <- err
		}(controller)
	}
	wg.Wait()
	close(errs)
	if api.mutationCnt != 1 {
		t.Fatalf("concurrent relation mutations = %d, want exactly 1", api.mutationCnt)
	}
	for range errs {
		// Depending on which cloud List acquires the test API lock first, the
		// loser either observes convergence or receives the Kubernetes CAS
		// conflict. Both outcomes are safe; the mutation count is authoritative.
	}
}

type concurrentEmergencyUnassignAPI struct {
	*fakeAPI
	mu            sync.Mutex
	listCalls     atomic.Int32
	listBarriers  [3]chan struct{}
	mutationCalls int
}

func newConcurrentEmergencyUnassignAPI(api *fakeAPI) *concurrentEmergencyUnassignAPI {
	return &concurrentEmergencyUnassignAPI{
		fakeAPI: api,
		listBarriers: [3]chan struct{}{
			make(chan struct{}),
			make(chan struct{}),
			make(chan struct{}),
		},
	}
}

func (a *concurrentEmergencyUnassignAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	call := a.listCalls.Add(1)
	if call <= 6 {
		barrier := a.listBarriers[(call-1)/2]
		if call%2 == 0 {
			close(barrier)
		}
		select {
		case <-barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	return cloneNodeLoadBalancerTestFirewalls(items), err
}

func (a *concurrentEmergencyUnassignAPI) UnassignFirewallFromVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mutationCalls++
	return a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

func TestNodeLoadBalancerEmergencyWithdrawalConcurrentControllersCASIssuesOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
	if !ok {
		t.Fatal("fixture Node has no VM UUID")
	}
	pair := fixture.serviceFirewallUUID + "/" + vmUUID
	evidenceTimes, err := json.Marshal(map[string]string{
		pair: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := getNodeLoadBalancerTestService(
		t, ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
	)
	stored.ResourceVersion = "1"
	stored.Annotations[annotationNodeLoadBalancerWithdrawFWDetach] = pair
	stored.Annotations[annotationNodeLoadBalancerWithdrawFWDetachAt] = string(evidenceTimes)
	client := fixture.provider.kubeClient.(*kubefake.Clientset)
	if err := client.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("services"), stored, stored.Namespace,
	); err != nil {
		t.Fatal(err)
	}

	api := newConcurrentEmergencyUnassignAPI(fixture.api)
	fixture.provider.api = api
	version := int64(1)
	client.Fake.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		update := action.(k8stesting.UpdateAction).GetObject().(*corev1.Service)
		if update.ResourceVersion != strconv.FormatInt(version, 10) {
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Resource: "services"},
				update.Name,
				errors.New("stale emergency relation fence resourceVersion"),
			)
		}
		version++
		update.ResourceVersion = strconv.FormatInt(version, 10)
		return false, nil, nil
	})

	controllers := []*nodeLoadBalancerController{{provider: fixture.provider}, {provider: fixture.provider}}
	errs := make(chan error, len(controllers))
	var wg sync.WaitGroup
	for _, controller := range controllers {
		wg.Add(1)
		go func(controller *nodeLoadBalancerController) {
			defer wg.Done()
			errs <- controller.detachOwnedServiceFirewallsForFailure(ctx, stored)
		}(controller)
	}
	wg.Wait()
	close(errs)
	if api.mutationCalls != 1 {
		t.Fatalf("concurrent emergency DELETEs = %d, want exactly 1", api.mutationCalls)
	}
	for range errs {
		// One controller owns the successful CAS. The other may report its stale
		// resourceVersion, but neither outcome can authorize a second DELETE.
	}
}

func TestNodeLoadBalancerFirewallRelationRequiresExactWriteReadback(t *testing.T) {
	for _, test := range []struct {
		name    string
		reactor func(*kubefake.Clientset)
	}{
		{
			name: "admission removes issued annotation",
			reactor: func(client *kubefake.Clientset) {
				client.Fake.PrependReactor("update", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
					updated := action.(k8stesting.UpdateAction).GetObject().(*corev1.Service)
					delete(updated.Annotations, annotationNodeLoadBalancerFirewallRelationIssued)
					return false, nil, nil
				})
			},
		},
		{
			name: "concurrent owner change before readback",
			reactor: func(client *kubefake.Clientset) {
				var gets atomic.Int32
				client.Fake.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if gets.Add(1) != 2 {
						return false, nil, nil
					}
					get := action.(k8stesting.GetAction)
					object, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("services"), get.GetNamespace(), get.GetName())
					if err != nil {
						return true, nil, err
					}
					changed := object.(*corev1.Service).DeepCopy()
					changed.ResourceVersion = "concurrent-rv"
					changed.Annotations["test.inspace.cloud/concurrent"] = "true"
					return true, changed, nil
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service := nodeLoadBalancerTestService("relation-readback", "relation-readback-uid", corev1.ProtocolTCP, 443)
			service.ResourceVersion = "1"
			api := &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}}
			provider := newTestProvider(t, api)
			client := kubefake.NewSimpleClientset(service.DeepCopy())
			provider.kubeClient = client
			test.reactor(client)
			controller := &nodeLoadBalancerController{provider: provider}
			converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
				&nodeLoadBalancerFirewallRelationFence{
					operation:    nodeLoadBalancerFirewallRelationAssign,
					firewallUUID: testFirewallRelationFirewallUUID,
					vmUUID:       testFirewallRelationVMUUID,
				},
			)
			if err == nil || converged {
				t.Fatalf("non-exact fence write/readback crossed cloud boundary: converged=%t err=%v", converged, err)
			}
			if len(api.assignedFirewalls) != 0 {
				t.Fatalf("non-exact fence write/readback issued cloud mutation: %#v", api.assignedFirewalls)
			}
		})
	}
}

type definitiveFirewallRelationHookAPI struct {
	*fakeAPI
	beforeFailure func() error
	readbackErr   error
	failed        bool
	assignCalls   int
}

type postCASFirewallAuthorityRaceAPI struct {
	*fakeAPI
	mu            sync.Mutex
	targetUUID    string
	driftBilling  bool
	driftPolicy   bool
	listCalls     int
	assignCalls   int
	unassignCalls int
}

type postCASShardOwnerDriftAPI struct {
	*fakeAPI
	hook        func()
	assignCalls int
}

func (a *postCASShardOwnerDriftAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err == nil && a.hook != nil {
		a.hook()
	}
	return items, err
}

func (a *postCASShardOwnerDriftAPI) AssignFirewallToVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.assignCalls++
	return a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func (a *postCASFirewallAuthorityRaceAPI) ListFirewalls(
	ctx context.Context,
	location string,
) ([]inspace.Firewall, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listCalls++
	items, err := a.fakeAPI.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	result := cloneNodeLoadBalancerTestFirewalls(items)
	if a.listCalls < 2 {
		return result, nil
	}
	for index := range result {
		if result[index].UUID != a.targetUUID {
			continue
		}
		if a.driftBilling {
			result[index].BillingAccountID++
		}
		if a.driftPolicy && len(result[index].Rules) != 0 {
			result[index].Rules[0].Protocol = "udp"
		}
	}
	return result, nil
}

func (a *postCASFirewallAuthorityRaceAPI) AssignFirewallToVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.mu.Lock()
	a.assignCalls++
	a.mu.Unlock()
	return a.fakeAPI.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
}

func (a *postCASFirewallAuthorityRaceAPI) UnassignFirewallFromVM(
	ctx context.Context,
	location, firewallUUID, vmUUID string,
) error {
	a.mu.Lock()
	a.unassignCalls++
	a.mu.Unlock()
	return a.fakeAPI.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID)
}

func TestNodeLoadBalancerFirewallRelationPostCASAuthorityDriftBlocksDispatchAndClearsReceipt(t *testing.T) {
	for _, operation := range []nodeLoadBalancerFirewallRelationOperation{
		nodeLoadBalancerFirewallRelationAssign,
		nodeLoadBalancerFirewallRelationUnassign,
	} {
		for _, drift := range []string{"billing", "policy"} {
			t.Run(string(operation)+"/"+drift, func(t *testing.T) {
				fixture := newNodeLoadBalancerFailClosedFixture(t)
				defer fixture.controller.queue.ShutDown()
				firewall := fixture.firewall(t, fixture.serviceFirewallUUID)
				if operation == nodeLoadBalancerFirewallRelationAssign {
					firewall.ResourcesAssigned = nil
				}
				api := &postCASFirewallAuthorityRaceAPI{
					fakeAPI: fixture.api, targetUUID: fixture.serviceFirewallUUID,
					driftBilling: drift == "billing", driftPolicy: drift == "policy",
				}
				fixture.provider.api = api
				service := getNodeLoadBalancerTestService(
					t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
				)
				vmUUID, ok := nodeLoadBalancerVMUUID(fixture.node)
				if !ok {
					t.Fatal("fixture Node has no VM UUID")
				}
				converged, err := fixture.controller.reconcileNodeLoadBalancerFirewallRelation(
					fixture.ctx,
					fixture.controller.serviceFirewallRelationOwner(service),
					&nodeLoadBalancerFirewallRelationFence{
						operation: operation, firewallUUID: fixture.serviceFirewallUUID, vmUUID: vmUUID,
					},
				)
				if err == nil || converged || !strings.Contains(err.Error(), "final pre-dispatch authority") {
					t.Fatalf("post-CAS authority result: converged=%t err=%v", converged, err)
				}
				if api.assignCalls != 0 || api.unassignCalls != 0 ||
					len(fixture.api.assignedFirewalls) != 0 || len(fixture.api.unassignedFirewalls) != 0 {
					t.Fatalf(
						"post-CAS drift crossed cloud boundary: wrapper assign=%d unassign=%d fake assign=%v unassign=%v",
						api.assignCalls,
						api.unassignCalls,
						fixture.api.assignedFirewalls,
						fixture.api.unassignedFirewalls,
					)
				}
				stored := getNodeLoadBalancerTestService(
					t, fixture.ctx, fixture.provider, fixture.service.Namespace, fixture.service.Name,
				)
				if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
					t.Fatalf("rejected post-CAS authority retained a proven-undispatched issue fence: %#v", stored.Annotations)
				}
			})
		}
	}
}

func TestNodeLoadBalancerFirewallRelationMissingIssueAuthorityClearsUndispatchedReceipt(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-missing-firewall", "relation-missing-firewall-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
		&nodeLoadBalancerFirewallRelationFence{
			operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID: testFirewallRelationVMUUID,
		},
	)
	if err == nil || converged {
		t.Fatalf("missing firewall issue authority: converged=%t err=%v", converged, err)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("missing firewall crossed AssignFirewallToVM: %v", api.assignedFirewalls)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("missing firewall retained proven-undispatched receipt: %#v", stored.Annotations)
	}
}

func TestShardFirewallRelationAssignRejectsPostCASLedgerAndOwnerDrift(t *testing.T) {
	for _, drift := range []string{"uuid", "hash", "ledger", "deleting"} {
		t.Run(drift, func(t *testing.T) {
			service := aggregateTestService(
				"relation-owner-drift",
				"74444444-2222-4333-8444-555555555555",
				corev1.ProtocolTCP,
				443,
			)
			fixture := newAggregateShardFirewallTestFixture(t, service)
			desired, ledger, _, err := fixture.controller.desiredStagedShardFirewallPolicy(fixture.ctx, fixture.shard)
			if err != nil || desired == nil {
				t.Fatalf("desired shard firewall = %#v, err=%v", desired, err)
			}
			firewall := aggregateTestFirewall(*desired, testFirewallRelationFirewallUUID)
			fixture.api.firewalls = []inspace.Firewall{firewall}
			pool, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
				fixture.ctx, fixture.shard, metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			annotations := pool.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[annotationNodeLoadBalancerShardFirewallUUID] = firewall.UUID
			annotations[annotationNodeLoadBalancerShardFirewallHash] = desired.Hash
			annotations[annotationNodeLoadBalancerShardFirewallLedger] = ledger
			pool.SetAnnotations(annotations)
			if _, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
				fixture.ctx, pool, metav1.UpdateOptions{},
			); err != nil {
				t.Fatal(err)
			}

			api := &postCASShardOwnerDriftAPI{fakeAPI: fixture.api}
			fired := false
			api.hook = func() {
				if fired {
					return
				}
				current, getErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
					fixture.ctx, fixture.shard, metav1.GetOptions{},
				)
				if getErr != nil || current.GetAnnotations()[annotationNodeLoadBalancerFirewallRelationIssued] == "" {
					return
				}
				fired = true
				values := current.GetAnnotations()
				switch drift {
				case "uuid":
					values[annotationNodeLoadBalancerShardFirewallUUID] = "75555555-2222-4333-8444-555555555555"
				case "hash":
					values[annotationNodeLoadBalancerShardFirewallHash] = strings.Repeat("a", nodeLoadBalancerShardFirewallPolicyHashLength)
				case "ledger":
					values[annotationNodeLoadBalancerShardFirewallLedger] = string(service.UID) + "=" + strings.Repeat("b", nodeLoadBalancerShardFirewallPolicyHashLength)
				case "deleting":
					now := metav1.Now()
					current.SetDeletionTimestamp(&now)
				}
				current.SetAnnotations(values)
				if _, updateErr := fixture.provider.dynamicClient.Resource(nodePoolGVR).Update(
					fixture.ctx, current, metav1.UpdateOptions{},
				); updateErr != nil {
					t.Fatal(updateErr)
				}
			}
			fixture.provider.api = api
			converged, err := fixture.controller.reconcileNodeLoadBalancerFirewallRelation(
				fixture.ctx,
				fixture.controller.shardFirewallRelationOwner(fixture.shard),
				&nodeLoadBalancerFirewallRelationFence{
					operation:    nodeLoadBalancerFirewallRelationAssign,
					firewallUUID: firewall.UUID,
					vmUUID:       testFirewallRelationVMUUID,
				},
			)
			if err == nil || converged {
				t.Fatalf("post-CAS shard owner drift = converged=%t err=%v", converged, err)
			}
			if !fired || api.assignCalls != 0 || len(fixture.api.assignedFirewalls) != 0 {
				t.Fatalf("post-CAS shard owner drift crossed assignment: fired=%t calls=%d assignments=%v", fired, api.assignCalls, fixture.api.assignedFirewalls)
			}
			current, err := fixture.provider.dynamicClient.Resource(nodePoolGVR).Get(
				fixture.ctx, fixture.shard, metav1.GetOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if current.GetAnnotations()[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
				t.Fatal("rejected relation assignment retained its proven-undispatched receipt")
			}
		})
	}
}

func TestClusterICMPRelationAssignRejectsDeletingNodeClass(t *testing.T) {
	ctx, api, provider, controller, nodeClassName, desired := newClusterICMPSafetyFixture(t)
	const firewallUUID = "76666666-2222-4333-8444-555555555555"
	api.firewalls = []inspace.Firewall{clusterICMPSafetyFirewall(desired, firewallUUID)}
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := nodeClass.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[annotationNodeLoadBalancerICMPFirewallUUID] = firewallUUID
	nodeClass.SetAnnotations(annotations)
	now := metav1.Now()
	nodeClass.SetDeletionTimestamp(&now)
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Update(
		ctx, nodeClass, metav1.UpdateOptions{},
	); err != nil {
		t.Fatal(err)
	}

	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		controller.clusterICMPFirewallRelationOwner(nodeClassName),
		&nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationAssign,
			firewallUUID: firewallUUID,
			vmUUID:       testFirewallRelationVMUUID,
		},
	)
	if err == nil || converged || !strings.Contains(err.Error(), "deleting") {
		t.Fatalf("deleting NodeClass assignment = converged=%t err=%v", converged, err)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("deleting NodeClass crossed AssignFirewallToVM: %v", api.assignedFirewalls)
	}
	stored, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.GetAnnotations()[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatal("rejected ICMP assignment retained its proven-undispatched receipt")
	}
}

func (a *definitiveFirewallRelationHookAPI) AssignFirewallToVM(context.Context, string, string, string) error {
	a.assignCalls++
	if a.beforeFailure != nil {
		if err := a.beforeFailure(); err != nil {
			return err
		}
	}
	a.failed = true
	return &inspace.APIError{StatusCode: 400, Method: "POST", Path: "/firewall/vms", Message: "definitive rejection"}
}

func TestNodeLoadBalancerHTTP400AssignmentRetainsFenceAfterUnchangedReadback(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-http-400", "relation-http-400-uid", corev1.ProtocolTCP, 443)
	api := &definitiveFirewallRelationHookAPI{
		fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}},
	}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	desired := &nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
	}
	if converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)), desired,
	); err == nil || converged {
		t.Fatalf("HTTP 400 assignment result: converged=%t err=%v", converged, err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" {
		t.Fatalf("HTTP 400 cleared additive assignment fence: %#v", stored.Annotations)
	}
	if api.assignCalls != 1 {
		t.Fatalf("assignment calls = %d, want one", api.assignCalls)
	}

	restarted := &nodeLoadBalancerController{provider: provider}
	if converged, err := restarted.reconcileNodeLoadBalancerFirewallRelation(
		ctx, withoutFirewallRelationCloudAuthorityForFenceTest(restarted.serviceFirewallRelationOwner(service)), desired,
	); err == nil || converged {
		t.Fatalf("restart did not stay read-only: converged=%t err=%v", converged, err)
	}
	if api.assignCalls != 1 {
		t.Fatalf("HTTP 400 assignment replayed: calls=%d", api.assignCalls)
	}
}

func (a *definitiveFirewallRelationHookAPI) ListFirewalls(ctx context.Context, location string) ([]inspace.Firewall, error) {
	if a.failed && a.readbackErr != nil {
		return nil, a.readbackErr
	}
	return a.fakeAPI.ListFirewalls(ctx, location)
}

func TestNodeLoadBalancerFirewallRelationHTTPErrorAndReadFailureRetainFence(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-read-failure", "relation-read-failure-uid", corev1.ProtocolTCP, 443)
	api := &definitiveFirewallRelationHookAPI{
		fakeAPI:     &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}},
		readbackErr: errors.New("firewall readback unavailable"),
	}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
		&nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationAssign,
			firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID:       testFirewallRelationVMUUID,
		},
	)
	if err == nil || converged || !strings.Contains(err.Error(), api.readbackErr.Error()) {
		t.Fatalf("HTTP/readback failure result: converged=%t err=%v", converged, err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" {
		t.Fatalf("issued relation fence was cleared on read failure: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerFirewallRelationMutationBlockedClearsWithoutReadback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := nodeLoadBalancerTestService("relation-blocked", "relation-blocked-uid", corev1.ProtocolTCP, 443)
	api := &blockedFirewallRelationAPI{
		fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}},
		cancel:  cancel,
	}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
		&nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationAssign,
			firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID:       testFirewallRelationVMUUID,
		},
	)
	if converged || !errors.Is(err, inspace.ErrMutationBlocked) {
		t.Fatalf("blocked relation mutation result: converged=%t err=%v", converged, err)
	}
	if api.assignCalls != 1 || api.listCalls != 1 {
		t.Fatalf("blocked relation mutation calls: assign=%d list=%d, want 1/1", api.assignCalls, api.listCalls)
	}
	stored := getNodeLoadBalancerTestService(t, context.Background(), provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" ||
		stored.Annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		t.Fatalf("blocked relation mutation retained UID-pinned receipt: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerFirewallRelationLegacyReceiptBindsExactOwnerWithoutCloudIO(t *testing.T) {
	legacy := nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
		issueID:      "0123456789abcdef0123456789abcdef",
		issuedAt:     "2026-07-17T00:00:00Z",
	}
	for _, path := range []string{"per-service", "shared-shard", "cluster-icmp"} {
		for _, replaceOwner := range []bool{false, true} {
			name := path + "/live-owner"
			if replaceOwner {
				name = path + "/same-name-replacement"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				api := &legacyFirewallRelationMigrationAPI{
					fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}},
				}
				harness := newFirewallRelationOwnerHarness(t, path, api)
				controller := &nodeLoadBalancerController{provider: harness.provider}
				originalOwner := harness.owner(controller)
				original, err := originalOwner.read(ctx)
				if err != nil {
					t.Fatal(err)
				}
				values := copyNodeLoadBalancerAnnotations(original.annotations)
				values[annotationNodeLoadBalancerFirewallRelationIssued] = legacy.String()
				delete(values, annotationNodeLoadBalancerFirewallRelationOwnerUID)
				if err := original.commit(ctx, values); err != nil {
					t.Fatal(err)
				}

				owner := originalOwner
				if replaceOwner {
					if err := harness.replaceOwner(ctx); err != nil {
						t.Fatal(err)
					}
					if path == "per-service" {
						current, err := harness.provider.kubeClient.CoreV1().Services("default").Get(
							ctx,
							"relation-service",
							metav1.GetOptions{},
						)
						if err != nil {
							t.Fatal(err)
						}
						owner = withoutFirewallRelationCloudAuthorityForFenceTest(
							controller.serviceFirewallRelationOwner(current),
						)
					} else {
						owner = harness.owner(controller)
					}
				}
				beforeMigration, err := owner.read(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if replaceOwner && beforeMigration.uid == original.uid {
					t.Fatalf("same-name owner replacement retained UID %q", original.uid)
				}

				converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(ctx, owner, nil)
				if err != nil || converged {
					t.Fatalf("legacy receipt migration: converged=%t err=%v", converged, err)
				}
				if api.listCalls != 0 || api.assignCalls != 0 || api.unassignCalls != 0 {
					t.Fatalf(
						"legacy receipt migration crossed cloud API: list=%d assign=%d unassign=%d",
						api.listCalls,
						api.assignCalls,
						api.unassignCalls,
					)
				}
				afterMigration, err := owner.read(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if afterMigration.uid != beforeMigration.uid ||
					afterMigration.annotations[annotationNodeLoadBalancerFirewallRelationIssued] != legacy.String() ||
					afterMigration.annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != string(beforeMigration.uid) {
					t.Fatalf(
						"legacy receipt was not bound to exact live owner: before=%q after=%q annotations=%#v",
						beforeMigration.uid,
						afterMigration.uid,
						afterMigration.annotations,
					)
				}
			})
		}
	}
}

func TestNodeLoadBalancerFirewallRelationSameNameOwnerReplacementBlocksDispatch(t *testing.T) {
	for _, path := range []string{"per-service", "public-node-local", "shared-shard", "cluster-icmp"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			api := &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}}
			harness := newFirewallRelationOwnerHarness(t, path, api)
			controller := &nodeLoadBalancerController{provider: harness.provider}
			owner := harness.owner(controller)
			owner.authorize = func(context.Context, nodeLoadBalancerFirewallRelationFence, inspace.Firewall) error {
				return harness.replaceOwner(ctx)
			}
			converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				owner,
				&nodeLoadBalancerFirewallRelationFence{
					operation:    nodeLoadBalancerFirewallRelationAssign,
					firewallUUID: testFirewallRelationFirewallUUID,
					vmUUID:       testFirewallRelationVMUUID,
				},
			)
			if err == nil || converged {
				t.Fatalf("same-name owner replacement result: converged=%t err=%v", converged, err)
			}
			if len(api.assignedFirewalls) != 0 {
				t.Fatalf("same-name owner replacement crossed AssignFirewallToVM: %v", api.assignedFirewalls)
			}
			annotations, readErr := harness.readAnnotations(ctx)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if annotations[annotationNodeLoadBalancerFirewallRelationIssued] == "" ||
				annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] == "" {
				t.Fatalf("replacement did not preserve the stale UID-pinned receipt: %#v", annotations)
			}

			restarted := &nodeLoadBalancerController{provider: harness.provider}
			if converged, err = restarted.reconcileNodeLoadBalancerFirewallRelation(
				ctx,
				harness.owner(restarted),
				nil,
			); err == nil || converged {
				t.Fatalf("replacement accepted the predecessor receipt after restart: converged=%t err=%v", converged, err)
			}
			if len(api.assignedFirewalls) != 0 {
				t.Fatalf("restart crossed AssignFirewallToVM after owner replacement: %v", api.assignedFirewalls)
			}
		})
	}
}

func TestNodeLoadBalancerFirewallRelationDefinitiveFailureCannotClearReplacementAttempt(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-aba", "relation-aba-uid", corev1.ProtocolTCP, 443)
	api := &definitiveFirewallRelationHookAPI{fakeAPI: &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}}}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	replacement := nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
		issueID:      "0123456789abcdef0123456789abcdef",
		issuedAt:     "2026-07-17T00:00:00Z",
	}
	api.beforeFailure = func() error {
		current, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] = replacement.String()
		_, err = provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, current, metav1.UpdateOptions{})
		return err
	}
	controller := &nodeLoadBalancerController{provider: provider}
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service)),
		&nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationAssign,
			firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID:       testFirewallRelationVMUUID,
		},
	)
	if err == nil || converged {
		t.Fatalf("definitive failure cleared a replacement attempt: converged=%t err=%v", converged, err)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] != replacement.String() {
		t.Fatalf("replacement relation attempt was cleared: %#v", stored.Annotations)
	}
}

func TestNodeLoadBalancerFirewallRelationFinalReceiptDriftBlocksDispatchAndPreservesReplacement(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("relation-final-receipt", "relation-final-receipt-uid", corev1.ProtocolTCP, 443)
	api := &fakeAPI{firewalls: []inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}}}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	replacement := nodeLoadBalancerFirewallRelationFence{
		operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID: "73333333-2222-4333-8444-555555555555", issueID: "0123456789abcdef0123456789abcdef",
		issuedAt: "2026-07-17T00:00:00Z",
	}
	owner := withoutFirewallRelationCloudAuthorityForFenceTest(controller.serviceFirewallRelationOwner(service))
	owner.authorize = func(context.Context, nodeLoadBalancerFirewallRelationFence, inspace.Firewall) error {
		current, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current.Annotations[annotationNodeLoadBalancerFirewallRelationIssued] = replacement.String()
		_, err = provider.kubeClient.CoreV1().Services(service.Namespace).Update(ctx, current, metav1.UpdateOptions{})
		return err
	}
	converged, err := controller.reconcileNodeLoadBalancerFirewallRelation(
		ctx,
		owner,
		&nodeLoadBalancerFirewallRelationFence{
			operation: nodeLoadBalancerFirewallRelationAssign, firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID: testFirewallRelationVMUUID,
		},
	)
	if err == nil || converged || !strings.Contains(err.Error(), "exact issued receipt changed") {
		t.Fatalf("final receipt drift result: converged=%t err=%v", converged, err)
	}
	if len(api.assignedFirewalls) != 0 {
		t.Fatalf("final receipt drift crossed AssignFirewallToVM: %v", api.assignedFirewalls)
	}
	stored := getNodeLoadBalancerTestService(t, ctx, provider, service.Namespace, service.Name)
	if got := stored.Annotations[annotationNodeLoadBalancerFirewallRelationIssued]; got != replacement.String() {
		t.Fatalf("replacement receipt = %q, want %q", got, replacement.String())
	}
}

func TestNodeLoadBalancerFirewallRelationClearUsesBoundedDetachedContext(t *testing.T) {
	ownerUID := types.UID("canceled-context-owner")
	issued := nodeLoadBalancerFirewallRelationFence{
		operation:    nodeLoadBalancerFirewallRelationAssign,
		firewallUUID: testFirewallRelationFirewallUUID,
		vmUUID:       testFirewallRelationVMUUID,
		issueID:      "0123456789abcdef0123456789abcdef",
		issuedAt:     "2026-07-17T00:00:00Z",
	}
	annotations := map[string]string{
		annotationNodeLoadBalancerFirewallRelationIssued:   issued.String(),
		annotationNodeLoadBalancerFirewallRelationOwnerUID: string(ownerUID),
	}
	sawDeadline := false
	checkContext := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > durableReceiptWriteTimeout {
			return errors.New("firewall relation receipt cleanup lacks a live bounded context")
		}
		sawDeadline = true
		return nil
	}
	owner := nodeLoadBalancerFirewallRelationOwner{
		description: "canceled-context fixture",
		read: func(ctx context.Context) (nodeLoadBalancerFirewallRelationOwnerSnapshot, error) {
			if err := checkContext(ctx); err != nil {
				return nodeLoadBalancerFirewallRelationOwnerSnapshot{}, err
			}
			return nodeLoadBalancerFirewallRelationOwnerSnapshot{
				annotations: copyNodeLoadBalancerAnnotations(annotations),
				uid:         ownerUID,
				commit: func(ctx context.Context, values map[string]string) error {
					if err := checkContext(ctx); err != nil {
						return err
					}
					annotations = copyNodeLoadBalancerAnnotations(values)
					return nil
				},
			}, nil
		},
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := clearNodeLoadBalancerFirewallRelationFence(canceled, owner, ownerUID, issued); err != nil {
		t.Fatalf("clear receipt with canceled reconcile context: %v", err)
	}
	if !sawDeadline {
		t.Fatal("firewall relation receipt cleanup did not expose a finite deadline")
	}
	if annotations[annotationNodeLoadBalancerFirewallRelationIssued] != "" {
		t.Fatalf("canceled-context receipt cleanup retained annotation: %#v", annotations)
	}
	if annotations[annotationNodeLoadBalancerFirewallRelationOwnerUID] != "" {
		t.Fatalf("canceled-context receipt cleanup retained owner UID: %#v", annotations)
	}
}

func TestNodeLoadBalancerFirewallAssignmentNormalization(t *testing.T) {
	firewall := inspace.Firewall{
		UUID: testFirewallRelationFirewallUUID,
		ResourcesAssigned: []inspace.FirewallResource{
			{ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID},
			{ResourceType: "vm", ResourceUUID: testFirewallRelationVMUUID},
		},
	}
	assignments, err := nodeLoadBalancerFirewallVMAssignments(firewall)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("exact duplicate relationship did not normalize: %#v, %v", assignments, err)
	}
	foreignVM := "73333333-2222-4333-8444-555555555555"
	firewall.ResourcesAssigned = append(firewall.ResourcesAssigned, inspace.FirewallResource{ResourceType: "vm", ResourceUUID: foreignVM})
	stale, err := staleNodeLoadBalancerFirewallAssignments(firewall, map[string]struct{}{testFirewallRelationVMUUID: {}})
	if err != nil || len(stale) != 1 || stale[0] != foreignVM {
		t.Fatalf("foreign relationship was not rejected by exact desired-set audit: stale=%v err=%v", stale, err)
	}
	firewall.ResourcesAssigned = append(firewall.ResourcesAssigned, inspace.FirewallResource{ResourceType: "volume", ResourceUUID: foreignVM})
	if _, err := nodeLoadBalancerFirewallVMAssignments(firewall); err == nil {
		t.Fatal("non-VM relationship was accepted")
	}
	if _, err := nodeLoadBalancerFirewallRelationConverged(
		nodeLoadBalancerFirewallRelationFence{
			operation:    nodeLoadBalancerFirewallRelationAssign,
			firewallUUID: testFirewallRelationFirewallUUID,
			vmUUID:       testFirewallRelationVMUUID,
		},
		[]inspace.Firewall{{UUID: testFirewallRelationFirewallUUID}, {UUID: testFirewallRelationFirewallUUID}},
	); err == nil {
		t.Fatal("duplicate firewall objects were accepted")
	}
}

func TestNodeLoadBalancerOnlyTypedLocalBlockIsKnownPreDispatch(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 408, 409, 422, 425, 429, 499, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			err := &inspace.APIError{StatusCode: status, Method: "POST", Path: "/mutation"}
			if nodeLoadBalancerMutationKnownPreDispatch(err) {
				t.Fatalf("HTTP %d was treated as known pre-dispatch", status)
			}
		})
	}
	if !nodeLoadBalancerMutationKnownPreDispatch(errors.Join(errors.New("wrapped"), inspace.ErrMutationBlocked)) {
		t.Fatal("typed local mutation block was not recognized through wrapping")
	}
}
