package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	testMissingNode = "cluster-a-karp-general-abcde"
	testNodeClaim   = "general-abcde"
)

type missingNodeAuthorizer struct {
	requests     []missingNodeDetachRequest
	failOnCall   int
	authorizeErr error
}

func (*missingNodeAuthorizer) ProviderIDForNode(context.Context, string) (string, error) {
	return "", fmt.Errorf("%w: test node", errKubernetesNodeNotFound)
}

func (r *missingNodeAuthorizer) AuthorizeMissingNodeDetach(_ context.Context, request missingNodeDetachRequest) error {
	r.requests = append(r.requests, request)
	if r.failOnCall > 0 && len(r.requests) == r.failOnCall {
		return r.authorizeErr
	}
	return nil
}

func missingNodeVM(description string) sdk.VM {
	return sdk.VM{
		UUID: testVM1, Name: testMissingNode, Hostname: testMissingNode,
		Description: description,
		Storage:     []sdk.VMStorage{{UUID: testDiskID}},
	}
}

func missingNodeOwnership(schema string) string {
	return missingNodeOwnershipFor(schema, "cluster-a", testNodeClaim, testMissingNode)
}

func missingNodeOwnershipFor(schema, cluster, nodeClaim, vmName string) string {
	encoded, err := json.Marshal(missingNodeOwnershipRecord{
		Schema: schema, Cluster: cluster, NodeClaim: nodeClaim, VMName: vmName,
		KeyHash: strings.Repeat("a", 32), HostClass: "amd-epyc",
		InstanceType: "general-2c-4g", HostPoolUUID: testVM2,
		VCPU: 2, MemoryGiB: 4, RootDiskGiB: 100,
		SpecHash: strings.Repeat("b", 32), BootstrapHash: strings.Repeat("c", 32),
		FirewallUUID: testVM2, FirewallProfile: "private-worker",
		NetworkUUID: testNetwork, ControlPlaneVIP: "10.91.72.10",
		PrivateLoadBalancerPoolStart: "10.91.72.128",
		PrivateLoadBalancerPoolStop:  "10.91.72.191",
		OSName:                       "ubuntu", OSVersion: "24.04",
		BillingAccountID: 42, FloatingIPName: "karpenter-general-abcde-a1b2c3d4",
	})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func missingNodeAPI(vm sdk.VM) *fakeAPI {
	return &fakeAPI{
		disks: []sdk.Disk{{UUID: testDiskID, DisplayName: "pvc-missing-node", SizeGiB: 1}},
		vms:   []sdk.VM{vm},
	}
}

func TestDetachRecoversExactDeletingKarpenterNodeAfterNode404(t *testing.T) {
	api := missingNodeAPI(missingNodeVM(missingNodeOwnership(inspaceOwnershipV3)))
	resolver := &missingNodeAuthorizer{}
	adapter := newAdapter(t, api, resolver)

	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode); err != nil {
		t.Fatal(err)
	}
	if api.detachCalls != 1 {
		t.Fatalf("DetachDisk calls = %d, want 1", api.detachCalls)
	}
	if len(resolver.requests) != 2 {
		t.Fatalf("missing-node authority calls = %d, want pre-fence and pre-dispatch proofs", len(resolver.requests))
	}
	for _, request := range resolver.requests {
		if request.NodeName != testMissingNode || request.Location != testLocation ||
			request.VMUUID != testVM1 || request.DiskUUID != testDiskID ||
			request.NetworkUUID != testNetwork || request.BillingAccountID != 42 {
			t.Fatalf("missing-node authority request = %#v", request)
		}
	}
}

func TestDetachMissingNodeRevalidatesAuthorityAfterFence(t *testing.T) {
	api := missingNodeAPI(missingNodeVM(missingNodeOwnership(inspaceOwnershipV3)))
	resolver := &missingNodeAuthorizer{
		failOnCall: 2, authorizeErr: errors.New("NodeClaim identity changed"),
	}
	adapter := newAdapter(t, api, resolver)

	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode)
	if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), "NodeClaim identity changed") {
		t.Fatalf("DetachVolume error = %v, want retryable authority drift", err)
	}
	if api.detachCalls != 0 {
		t.Fatalf("authority drift issued %d DetachDisk call(s)", api.detachCalls)
	}
	if fence, getErr := adapter.fences.Get(context.Background(), diskAttachmentFenceKey(testLocation, testDiskID)); getErr != nil || fence != nil {
		t.Fatalf("unissued recovery fence = %#v, err=%v", fence, getErr)
	}
}

func TestDetachMissingNodePreservesCanceledAuthorityContext(t *testing.T) {
	api := missingNodeAPI(missingNodeVM(missingNodeOwnership(inspaceOwnershipV3)))
	resolver := &missingNodeAuthorizer{failOnCall: 1, authorizeErr: context.Canceled}
	adapter := newAdapter(t, api, resolver)

	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode)
	if !errors.Is(err, context.Canceled) || errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("DetachVolume error = %v, want context.Canceled without ErrUnavailable", err)
	}
	if api.detachCalls != 0 {
		t.Fatalf("canceled authority issued %d DetachDisk call(s)", api.detachCalls)
	}
}

func TestDetachMissingNodeFailsClosedWithoutCompleteCurrentV3Identity(t *testing.T) {
	tests := map[string]func(*sdk.VM){
		"legacy v2": func(vm *sdk.VM) {
			vm.Description = missingNodeOwnership("karpenter.inspace.cloud/v2")
		},
		"partial ownership": func(vm *sdk.VM) {
			vm.Description = `{"schema":"karpenter.inspace.cloud/v3"}`
		},
		"duplicate ownership field": func(vm *sdk.VM) {
			vm.Description = strings.Replace(
				missingNodeOwnership(inspaceOwnershipV3),
				`"cluster":"cluster-a"`,
				`"cluster":"cluster-a","cluster":"cluster-a"`,
				1,
			)
		},
		"trailing ownership data": func(vm *sdk.VM) {
			vm.Description = missingNodeOwnership(inspaceOwnershipV3) + `{}`
		},
		"invalid key hash": func(vm *sdk.VM) {
			vm.Description = strings.Replace(
				missingNodeOwnership(inspaceOwnershipV3),
				strings.Repeat("a", 32),
				strings.Repeat("a", 64),
				1,
			)
		},
		"hostname omitted": func(vm *sdk.VM) {
			vm.Hostname = ""
		},
		"hostname mismatch": func(vm *sdk.VM) {
			vm.Hostname = "another-node"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			vm := missingNodeVM(missingNodeOwnership(inspaceOwnershipV3))
			mutate(&vm)
			api := missingNodeAPI(vm)
			resolver := &missingNodeAuthorizer{}
			adapter := newAdapter(t, api, resolver)

			err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode)
			if !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("DetachVolume error = %v, want ErrUnavailable", err)
			}
			if api.detachCalls != 0 {
				t.Fatalf("invalid identity issued %d DetachDisk call(s)", api.detachCalls)
			}
		})
	}
}

func TestDetachMissingNodeDoesNotDetachCompleteDifferentVM(t *testing.T) {
	vm := missingNodeVM(missingNodeOwnership(inspaceOwnershipV3))
	vm.Name = "cluster-a-karp-general-other"
	vm.Hostname = vm.Name
	vm.Description = missingNodeOwnershipFor(
		inspaceOwnershipV3,
		"cluster-a",
		"general-other",
		vm.Name,
	)
	api := missingNodeAPI(vm)
	resolver := &missingNodeAuthorizer{}
	adapter := newAdapter(t, api, resolver)

	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode); err != nil {
		t.Fatal(err)
	}
	if api.detachCalls != 0 || len(resolver.requests) != 0 {
		t.Fatalf("different-VM detach calls=%d authority requests=%d", api.detachCalls, len(resolver.requests))
	}
}

func TestDetachMissingNodeRejectsContradictoryDifferentVM(t *testing.T) {
	vm := missingNodeVM(missingNodeOwnership(inspaceOwnershipV3))
	vm.Name = "cluster-a-karp-general-other"
	vm.Hostname = vm.Name
	api := missingNodeAPI(vm)
	resolver := &missingNodeAuthorizer{}
	adapter := newAdapter(t, api, resolver)

	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode)
	if !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatalf("DetachVolume error = %v, want ErrUnavailable", err)
	}
	if api.detachCalls != 0 || len(resolver.requests) != 0 {
		t.Fatalf("contradictory-VM detach calls=%d authority requests=%d", api.detachCalls, len(resolver.requests))
	}
}

func TestDetachUnresolvedNodeWithoutTyped404FailsRetryably(t *testing.T) {
	api := missingNodeAPI(missingNodeVM(missingNodeOwnership(inspaceOwnershipV3)))
	adapter := newAdapter(t, api, nodeResolver{})

	err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, testMissingNode)
	if !errors.Is(err, cloud.ErrUnavailable) || errors.Is(err, errKubernetesNodeNotFound) {
		t.Fatalf("DetachVolume error = %v, want generic retryable resolution failure", err)
	}
	if api.detachCalls != 0 {
		t.Fatalf("generic resolution failure issued %d DetachDisk call(s)", api.detachCalls)
	}
}

var _ NodeResolver = (*missingNodeAuthorizer)(nil)
var _ missingNodeDetachAuthorizer = (*missingNodeAuthorizer)(nil)
