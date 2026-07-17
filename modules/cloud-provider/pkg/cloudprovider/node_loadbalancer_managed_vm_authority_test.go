package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type managedNodeLoadBalancerVMReadErrorAPI struct {
	*fakeAPI
	err error
}

type managedNodeLoadBalancerFirewallReadErrorAPI struct {
	*fakeAPI
	err error
}

func (a *managedNodeLoadBalancerFirewallReadErrorAPI) ListFirewalls(context.Context, string) ([]inspace.Firewall, error) {
	return nil, a.err
}

func (a *managedNodeLoadBalancerVMReadErrorAPI) GetVM(context.Context, string, string) (*inspace.VM, error) {
	return nil, a.err
}

func TestManagedNodeLoadBalancerCanonicalVMAndVPCProofBlocksAdvertisement(t *testing.T) {
	readErr := errors.New("canonical ownership read failed")
	tests := []struct {
		name      string
		mutate    func(*testing.T, *nodeLoadBalancerFailClosedFixture)
		wantError bool
	}{
		{
			name: "zero VM billing",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				managedNodeLoadBalancerFixtureVM(t, fixture).BillingAccountID = 0
			},
		},
		{
			name: "wrong VM billing",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				managedNodeLoadBalancerFixtureVM(t, fixture).BillingAccountID++
			},
		},
		{
			name: "wrong VM VPC",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				managedNodeLoadBalancerFixtureVM(t, fixture).NetworkUUID = "22222222-3333-4444-8555-666666666666"
			},
		},
		{
			name: "wrong canonical VPC",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				fixture.api.network = &inspace.Network{
					UUID:    "22222222-3333-4444-8555-666666666666",
					VMUUIDs: []string{managedNodeLoadBalancerFixtureVMUUID},
				}
			},
		},
		{
			name: "missing VPC membership",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				fixture.api.network = &inspace.Network{UUID: fixture.provider.config.NetworkUUID}
			},
		},
		{
			name: "duplicate VPC membership",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				fixture.api.network = &inspace.Network{
					UUID:    fixture.provider.config.NetworkUUID,
					VMUUIDs: []string{managedNodeLoadBalancerFixtureVMUUID, managedNodeLoadBalancerFixtureVMUUID},
				}
			},
		},
		{
			name: "VM read error",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				fixture.provider.api = &managedNodeLoadBalancerVMReadErrorAPI{fakeAPI: fixture.api, err: readErr}
			},
			wantError: true,
		},
		{
			name: "VPC read error",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				fixture.api.networkErr = readErr
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeLoadBalancerFailClosedFixture(t)
			defer fixture.controller.queue.ShutDown()
			test.mutate(t, fixture)
			before := managedNodeLoadBalancerMutationSnapshot(fixture.api)
			kube := fixture.provider.kubeClient.(*kubefake.Clientset)
			actionsBefore := len(kube.Actions())

			authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), readErr.Error()) {
					t.Fatalf("authorization error = %v, want %v", err, readErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(authorized) != 0 {
				t.Fatalf("unproven VM was authorized: %#v", authorized)
			}
			managedNodeLoadBalancerAssertNoMutationOrStatus(t, fixture, before, actionsBefore)
		})
	}
}

func TestManagedNodeLoadBalancerAllowsOmittedRedundantVMNetworkWithExactMembership(t *testing.T) {
	fixture := newNodeLoadBalancerFailClosedFixture(t)
	defer fixture.controller.queue.ShutDown()
	managedNodeLoadBalancerFixtureVM(t, fixture).NetworkUUID = ""
	authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorized) != 1 || authorized[0].Name != fixture.node.Name {
		t.Fatalf("exact VPC membership did not authorize omitted redundant VM network: %#v", authorized)
	}
}

func TestManagedNodeLoadBalancerBaseFirewallCloudAuthorityBlocksAdvertisement(t *testing.T) {
	readErr := errors.New("base firewall authority read failed")
	tests := []struct {
		name   string
		mutate func(*testing.T, *nodeLoadBalancerFailClosedFixture, *inspace.Firewall)
	}{
		{
			name: "foreign billing",
			mutate: func(_ *testing.T, _ *nodeLoadBalancerFailClosedFixture, firewall *inspace.Firewall) {
				firewall.BillingAccountID++
			},
		},
		{
			name: "policy drift",
			mutate: func(t *testing.T, _ *nodeLoadBalancerFailClosedFixture, firewall *inspace.Firewall) {
				if len(firewall.Rules) == 0 {
					t.Fatal("base firewall fixture has no rules")
				}
				firewall.Rules[0].EndpointSpec = []string{"0.0.0.0/0"}
			},
		},
		{
			name: "missing VM assignment",
			mutate: func(_ *testing.T, _ *nodeLoadBalancerFailClosedFixture, firewall *inspace.Firewall) {
				firewall.ResourcesAssigned = nil
			},
		},
		{
			name: "duplicate VM assignment",
			mutate: func(_ *testing.T, _ *nodeLoadBalancerFailClosedFixture, firewall *inspace.Firewall) {
				firewall.ResourcesAssigned = append(
					firewall.ResourcesAssigned,
					inspace.FirewallResource{ResourceType: "vm", ResourceUUID: managedNodeLoadBalancerFixtureVMUUID},
				)
			},
		},
		{
			name: "duplicate firewall UUID row",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture, firewall *inspace.Firewall) {
				duplicate := *firewall
				duplicate.Rules = append([]inspace.FirewallRule(nil), firewall.Rules...)
				duplicate.ResourcesAssigned = append([]inspace.FirewallResource(nil), firewall.ResourcesAssigned...)
				fixture.api.firewalls = append(fixture.api.firewalls, duplicate)
			},
		},
		{
			name: "firewall inventory read error",
			mutate: func(_ *testing.T, fixture *nodeLoadBalancerFailClosedFixture, _ *inspace.Firewall) {
				fixture.provider.api = &managedNodeLoadBalancerFirewallReadErrorAPI{fakeAPI: fixture.api, err: readErr}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeLoadBalancerFailClosedFixture(t)
			defer fixture.controller.queue.ShutDown()
			base := managedNodeLoadBalancerFixtureBaseFirewall(t, fixture)
			test.mutate(t, fixture, base)
			before := managedNodeLoadBalancerMutationSnapshot(fixture.api)
			kube := fixture.provider.kubeClient.(*kubefake.Clientset)
			actionsBefore := len(kube.Actions())
			authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
			if err == nil {
				t.Fatalf("drifted base firewall authority returned no error and authorized=%#v", authorized)
			}
			if test.name == "firewall inventory read error" && !strings.Contains(err.Error(), readErr.Error()) {
				t.Fatalf("read error = %v, want %v", err, readErr)
			}
			if len(authorized) != 0 {
				t.Fatalf("drifted base firewall authorized Nodes: %#v", authorized)
			}
			managedNodeLoadBalancerAssertNoMutationOrStatus(t, fixture, before, actionsBefore)
		})
	}
}

func TestManagedNodeLoadBalancerRejectsSameAccountFIPSwapAndStaleOwnership(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *nodeLoadBalancerFailClosedFixture)
	}{
		{
			name: "same-account assigned FIP swap",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				const replacement = "203.0.113.77"
				managedNodeLoadBalancerSetClaimPublicIPv4(t, fixture, replacement)
				managedNodeLoadBalancerSetNodeExternalIPv4(t, fixture, replacement)
				fixture.api.floatingIPs[0].Address = replacement
				fixture.api.floatingIPs[0].Name = "same-account-swap"
			},
		},
		{
			name: "stale NodeClaim public address",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				const replacement = "203.0.113.78"
				managedNodeLoadBalancerSetNodeExternalIPv4(t, fixture, replacement)
				fixture.api.floatingIPs[0].Address = replacement
			},
		},
		{
			name: "stale VM ownership FIP name",
			mutate: func(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) {
				vm := managedNodeLoadBalancerFixtureVM(t, fixture)
				var ownership map[string]any
				if err := json.Unmarshal([]byte(vm.Description), &ownership); err != nil {
					t.Fatal(err)
				}
				ownership["floatingIPName"] = "stale-owned-name"
				encoded, err := json.Marshal(ownership)
				if err != nil {
					t.Fatal(err)
				}
				vm.Description = string(encoded)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeLoadBalancerFailClosedFixture(t)
			defer fixture.controller.queue.ShutDown()
			test.mutate(t, fixture)
			before := managedNodeLoadBalancerMutationSnapshot(fixture.api)
			kube := fixture.provider.kubeClient.(*kubefake.Clientset)
			actionsBefore := len(kube.Actions())
			authorized, err := fixture.controller.authorizedNodesForShard(fixture.ctx, fixture.shard)
			if err != nil {
				t.Fatal(err)
			}
			if len(authorized) != 0 {
				t.Fatalf("stale/swapped same-account FIP was authorized: %#v", authorized)
			}
			managedNodeLoadBalancerAssertNoMutationOrStatus(t, fixture, before, actionsBefore)
		})
	}
}

const managedNodeLoadBalancerFixtureVMUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"

func managedNodeLoadBalancerFixtureVM(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture) *inspace.VM {
	t.Helper()
	for index := range fixture.api.vms {
		if fixture.api.vms[index].UUID == managedNodeLoadBalancerFixtureVMUUID {
			return &fixture.api.vms[index]
		}
	}
	t.Fatal("managed NodeLB fixture VM is absent")
	return nil
}

func managedNodeLoadBalancerFixtureBaseFirewall(
	t *testing.T,
	fixture *nodeLoadBalancerFailClosedFixture,
) *inspace.Firewall {
	t.Helper()
	base := nodeLoadBalancerSafetyBaseNodeClass()
	uuid, found, err := unstructured.NestedString(base.Object, "spec", "firewallUUID")
	if err != nil || !found {
		t.Fatalf("fixture base NodeClass firewall UUID: found=%t err=%v", found, err)
	}
	for index := range fixture.api.firewalls {
		if fixture.api.firewalls[index].UUID == uuid {
			return &fixture.api.firewalls[index]
		}
	}
	t.Fatalf("fixture base firewall %s is absent", uuid)
	return nil
}

func managedNodeLoadBalancerSetClaimPublicIPv4(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture, address string) {
	t.Helper()
	claims, err := fixture.provider.dynamicClient.Resource(nodeClaimGVR).List(fixture.ctx, metav1.ListOptions{})
	if err != nil || len(claims.Items) != 1 {
		t.Fatalf("list managed NodeClaim: count=%d err=%v", len(claims.Items), err)
	}
	claim := claims.Items[0].DeepCopy()
	annotations := claim.GetAnnotations()
	annotations[karpenterPublicIPv4Annotation] = address
	claim.SetAnnotations(annotations)
	if _, err := fixture.provider.dynamicClient.Resource(nodeClaimGVR).Update(fixture.ctx, claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func managedNodeLoadBalancerSetNodeExternalIPv4(t *testing.T, fixture *nodeLoadBalancerFailClosedFixture, address string) {
	t.Helper()
	node, err := fixture.provider.kubeClient.CoreV1().Nodes().Get(fixture.ctx, fixture.node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index := range node.Status.Addresses {
		if node.Status.Addresses[index].Type == corev1.NodeExternalIP {
			node.Status.Addresses[index].Address = address
		}
	}
	if _, err := fixture.provider.kubeClient.CoreV1().Nodes().UpdateStatus(fixture.ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

type managedNodeLoadBalancerMutations struct {
	created, updated, deleted, assigned, unassigned int
}

func managedNodeLoadBalancerMutationSnapshot(api *fakeAPI) managedNodeLoadBalancerMutations {
	return managedNodeLoadBalancerMutations{
		created: len(api.createdFirewalls), updated: len(api.updatedFirewalls), deleted: len(api.deletedFirewalls),
		assigned: len(api.assignedFirewalls), unassigned: len(api.unassignedFirewalls),
	}
}

func managedNodeLoadBalancerAssertNoMutationOrStatus(
	t *testing.T,
	fixture *nodeLoadBalancerFailClosedFixture,
	before managedNodeLoadBalancerMutations,
	actionsBefore int,
) {
	t.Helper()
	if after := managedNodeLoadBalancerMutationSnapshot(fixture.api); !reflect.DeepEqual(after, before) {
		t.Fatalf("failed VM authority mutated firewall state: before=%#v after=%#v", before, after)
	}
	kube := fixture.provider.kubeClient.(*kubefake.Clientset)
	for _, action := range kube.Actions()[actionsBefore:] {
		if action.GetVerb() == "update" || action.GetVerb() == "patch" || action.GetVerb() == "create" || action.GetVerb() == "delete" {
			t.Fatalf("failed VM authority mutated Kubernetes state: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	for _, name := range []string{fixture.service.Name, nodeLoadBalancerDatapathName(fixture.service)} {
		service, err := fixture.provider.kubeClient.CoreV1().Services(fixture.service.Namespace).Get(fixture.ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(service.Status.LoadBalancer.Ingress) != 0 {
			t.Fatalf("failed VM authority published %s status: %#v", name, service.Status.LoadBalancer)
		}
	}
}
