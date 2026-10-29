package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestPublicNodeLocalKarpenterNodeHoldsOnOwnPerVMFirewall(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		nodePoolName = "edgepool"
		nodeClaim    = "edgepool-abcde"
		nodeName     = "unit-test-cluster-karp-edgepool-abcde"
		nodeClass    = "edge-workers"
		privateIP    = "10.0.0.31"
		publicIP     = "203.0.113.31"
	)
	block := true
	ownership := map[string]any{
		"schema": "karpenter.inspace.cloud/v3", "cluster": "unit-test-cluster",
		"nodePool": nodePoolName, "nodeClaim": nodeClaim, "vmName": nodeName,
		"firewallProfile": publicNodeLocalFirewallProfile,
		"firewallUUID":    "22222222-2222-4222-8222-222222222222",
		"networkUUID":     testNetworkUUID, "billingAccountID": int64(42),
	}
	description, err := json.Marshal(ownership)
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{
		vms:       []inspace.VM{{UUID: vmUUID, Name: nodeName, Hostname: nodeName, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID, Description: string(description)}},
		firewalls: []inspace.Firewall{publicNodeLocalTestBaseFirewall(vmUUID)},
		floatingIPs: []inspace.FloatingIP{{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		}},
	}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			Labels: map[string]string{
				karpenterNodePoolLabel: nodePoolName,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "karpenter.sh/v1", Kind: "NodeClaim", Name: nodeClaim,
				UID: "claim-uid", BlockOwnerDeletion: &block,
			}},
		},
		Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + vmUUID},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: privateIP},
			{Type: corev1.NodeExternalIP, Address: publicIP},
		}},
	}
	provider.kubeClient = kubefake.NewSimpleClientset(node.DeepCopy())

	pool := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodePool",
		"metadata": map[string]any{"name": nodePoolName, "uid": "pool-uid"},
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"labels": map[string]any{publicNodeLocalPoolLabel: "edge"}},
			"spec": map[string]any{"nodeClassRef": map[string]any{
				"group": "karpenter.inspace.cloud", "kind": "InSpaceNodeClass", "name": nodeClass,
			}},
		}},
	}}
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1", "kind": "NodeClaim",
		"metadata": map[string]any{
			"name": nodeClaim, "uid": "claim-uid",
			"labels": map[string]any{karpenterNodePoolLabel: nodePoolName},
			"ownerReferences": []any{map[string]any{
				"apiVersion": "karpenter.sh/v1", "kind": "NodePool", "name": nodePoolName,
				"uid": "pool-uid", "blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]any{"nodeClassRef": map[string]any{
			"group": "karpenter.inspace.cloud", "kind": "InSpaceNodeClass", "name": nodeClass,
		}},
		"status": map[string]any{"providerID": node.Spec.ProviderID, "nodeName": node.Name},
	}}
	base := nodeLoadBalancerSafetyBaseNodeClass()
	if err := unstructured.SetNestedField(base.Object, "22222222-2222-4222-8222-222222222222", "status", "firewallUUID"); err != nil {
		t.Fatal(err)
	}
	class := base.DeepCopy()
	class.SetName(nodeClass)
	if err := unstructured.SetNestedField(class.Object, publicNodeLocalFirewallProfile, "spec", "firewallProfile"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.dynamicClient.Resource(nodePoolGVR).Create(ctx, pool, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.dynamicClient.Resource(nodeClaimGVR).Create(ctx, claim, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Create(ctx, base, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.dynamicClient.Resource(nodeClassGVR).Create(ctx, class, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	authorized, patched, err := (&nodeLoadBalancerController{provider: provider}).authorizePublicNodeLocalNode(ctx, node, "edge")
	if err != nil || authorized || !patched {
		t.Fatalf("initial authorization = authorized:%t patched:%t err:%v", authorized, patched, err)
	}
	stored, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctrl := &nodeLoadBalancerController{provider: provider}
	if v, _, err := ctrl.authorizePublicNodeLocalNodeVerdict(ctx, stored, "edge", nil); err != nil || v.kind != publicNodeLocalNodeAuthorized {
		t.Fatalf("baseline: %v %v", v, err)
	}
	api.firewalls = append(api.firewalls, perVMTestFirewall(t, provider.config.ClusterID, vmUUID, "70000000-0000-4000-8000-000000000009", 443))
	v, _, err := ctrl.authorizePublicNodeLocalNodeVerdict(ctx, stored, "edge", nil)
	var present *publicNodeLocalPerVMStatePresentError
	if !errors.As(err, &present) || v.kind != publicNodeLocalNodeUnverified {
		t.Fatalf("per-VM: kind=%v err=%v", v.kind, err)
	}
	// A per-VM firewall named for another VM but attached here is unauthorized, not our own per-VM state.
	api.firewalls = api.firewalls[:len(api.firewalls)-1]
	other := perVMTestFirewall(t, provider.config.ClusterID, "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee", "70000000-0000-4000-8000-00000000000a", 443)
	other.ResourcesAssigned[0].ResourceUUID = vmUUID
	api.firewalls = append(api.firewalls, other)
	v, _, err = ctrl.authorizePublicNodeLocalNodeVerdict(ctx, stored, "edge", nil)
	if err == nil || errors.As(err, &present) || v.kind != publicNodeLocalNodeUnverified {
		t.Fatalf("foreign: kind=%v err=%v", v.kind, err)
	}
}
