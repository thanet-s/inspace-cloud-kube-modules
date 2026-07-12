package smoke_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/provider"
)

func TestFakeProvisioningLifecycleMakesNoNetworkCalls(t *testing.T) {
	ctx := context.Background()
	nodeClass := smokeNodeClass()
	resolver := provider.NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "test-only-token")
	cloud := cloudfake.New()
	cloudProvider, err := provider.New(cloud, resolver, provider.Options{
		ClusterName: "smoke-cluster", DefaultNodeClassName: nodeClass.Name,
		NetworkUUID: nodeClass.Spec.NetworkUUID, ControlPlaneVIP: "10.0.0.10", PrivateLoadBalancerPool: nodeClass.Spec.PrivateLoadBalancerPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeClaim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "general-worker", UID: types.UID("nodeclaim-uid-1")},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
			Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: corev1.NodeSelectorOpIn, Values: []string{"general"}},
				{Key: karpv1.CapacityTypeLabelKey, Operator: corev1.NodeSelectorOpIn, Values: []string{karpv1.CapacityTypeOnDemand}},
			},
			Resources: karpv1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3"),
				corev1.ResourceMemory: resource.MustParse("5Gi"),
			}},
		},
	}

	created, err := cloudProvider.Create(ctx, nodeClaim)
	if err != nil {
		t.Fatal(err)
	}
	if created.Labels[corev1.LabelInstanceTypeStable] != "is-general-4c-8g" {
		t.Fatalf("unexpected selection %q", created.Labels[corev1.LabelInstanceTypeStable])
	}
	retried, err := cloudProvider.Create(ctx, nodeClaim)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("idempotent create changed provider ID: %s != %s", retried.Status.ProviderID, created.Status.ProviderID)
	}

	got, err := cloudProvider.Get(ctx, created.Status.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("providerID mismatch: %s != %s", got.Status.ProviderID, created.Status.ProviderID)
	}
	listed, err := cloudProvider.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].Status.ProviderID != created.Status.ProviderID {
		t.Fatalf("unexpected list result %#v, %v", listed, err)
	}

	id := strings.TrimPrefix(created.Status.ProviderID, "inspace://bkk01/")
	request, ok := cloud.Request(id)
	if !ok {
		t.Fatalf("fake did not retain create request for %s", id)
	}
	if !request.PublicIPv4 {
		t.Fatal("worker must request a public IPv4 address because InSpace has no managed NAT")
	}
	if request.ControlPlaneVIP != "10.0.0.10" {
		t.Fatalf("private RKE2 supervisor VIP was not propagated: %q", request.ControlPlaneVIP)
	}
	if request.PrivateLoadBalancerPoolStart != nodeClass.Spec.PrivateLoadBalancerPool.Start || request.PrivateLoadBalancerPoolStop != nodeClass.Spec.PrivateLoadBalancerPool.Stop {
		t.Fatalf("private Service pool was not propagated: %s-%s", request.PrivateLoadBalancerPoolStart, request.PrivateLoadBalancerPoolStop)
	}
	if request.HostPoolUUID != inspacev1.AMDEPYCHostPoolUUID {
		t.Fatalf("unexpected host pool UUID %q", request.HostPoolUUID)
	}
	if request.SSHUsername != nodeClass.Spec.SSHUsername || request.SSHPublicKey != nodeClass.Spec.SSHPublicKey {
		t.Fatalf("worker SSH access was not propagated through the provider request")
	}
	decodedBootstrap := decodedCloudInitFiles(t, request.CloudInitJSON)
	if strings.Count(decodedBootstrap, "karpenter.sh/unregistered:NoExecute") != 1 {
		t.Fatalf("bootstrap must contain exactly one registration taint\n%s", request.CloudInitJSON)
	}
	if strings.Count(decodedBootstrap, bootstrap.VPCSubnetPlaceholder) != 1 || strings.Contains(decodedBootstrap, "ip -4 route show default") {
		t.Fatalf("bootstrap must bind private-IP discovery to one exact VPC subnet placeholder\n%s", decodedBootstrap)
	}
	if !strings.Contains(decodedBootstrap, "ufw --force disable") || !strings.Contains(decodedBootstrap, `ufw status | grep -Fq "Status: inactive"`) || !strings.Contains(decodedBootstrap, "systemctl disable --now ufw.service") {
		t.Fatalf("bootstrap must disable a preinstalled UFW service\n%s", decodedBootstrap)
	}
	if !strings.Contains(decodedBootstrap, "ExecStartPre=/usr/local/sbin/inspace-verify-host-firewall") || !strings.Contains(decodedBootstrap, "/usr/local/sbin/inspace-disable-host-firewall\n/usr/local/sbin/inspace-verify-host-firewall\n/usr/local/sbin/inspace-start-rke2-agent") {
		t.Fatalf("bootstrap must gate every RKE2 launch through fail-fast UFW verification\n%s", decodedBootstrap)
	}
	if !strings.Contains(decodedBootstrap, "systemctl start --no-block rke2-agent.service") || !strings.Contains(decodedBootstrap, `systemctl is-failed --quiet rke2-agent.service`) || !strings.Contains(decodedBootstrap, `[ "$attempt" -ge 180 ]`) {
		t.Fatalf("bootstrap must use bounded, fail-fast RKE2 agent startup\n%s", decodedBootstrap)
	}
	for _, forbidden := range []string{"ufw --force enable", "ufw allow", "ufw route", "iptables", "nft"} {
		if strings.Contains(decodedBootstrap, forbidden) {
			t.Fatalf("bootstrap must leave Cilium's datapath untouched; found %q\n%s", forbidden, decodedBootstrap)
		}
	}

	if err := cloudProvider.Delete(ctx, created); err != nil {
		t.Fatal(err)
	}
	if _, err := cloudProvider.Get(ctx, created.Status.ProviderID); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("expected not-found after delete, got %v", err)
	}
	if err := cloudProvider.Delete(ctx, created); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("Karpenter delete convergence must return NodeClaimNotFound, got %v", err)
	}
}

func decodedCloudInitFiles(t *testing.T, data string) string {
	t.Helper()
	var doc struct {
		WriteFiles []struct {
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("decode cloud-init: %v", err)
	}
	var decoded strings.Builder
	for _, file := range doc.WriteFiles {
		if file.Encoding != "b64" {
			t.Fatalf("cloud-init write_files encoding = %q, want b64", file.Encoding)
		}
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			t.Fatalf("decode cloud-init write_files: %v", err)
		}
		decoded.Write(content)
		decoded.WriteByte('\n')
	}
	return decoded.String()
}

func smokeNodeClass() *inspacev1.InSpaceNodeClass {
	nodeClass := &inspacev1.InSpaceNodeClass{
		ObjectMeta: metav1.ObjectMeta{Name: "smoke-amd"},
		Spec: inspacev1.InSpaceNodeClassSpec{
			ClusterName:             "smoke-cluster",
			BillingAccountID:        1,
			Location:                inspacev1.LocationBangkok,
			NetworkUUID:             "11111111-1111-4111-8111-111111111111",
			PrivateLoadBalancerPool: inspacev1.PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"},
			ReservePublicIPv4:       true,
			FirewallUUID:            "22222222-2222-4222-8222-222222222222",
			ImageSelector:           inspacev1.ImageSelector{OSName: inspacev1.OSNameUbuntu, OSVersion: inspacev1.OSVersionUbuntu},
			HostPoolSelector:        inspacev1.HostPoolSelector{Class: inspacev1.HostClassAMDEPYC},
			RootDiskGiB:             40,
			SSHUsername:             "inspacee2e",
			SSHPublicKey:            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea smoke@example",
			RKE2: inspacev1.RKE2Config{
				Version:        "v1.35.6+rke2r1",
				Server:         "https://10.0.0.10:9345",
				TokenSecretRef: inspacev1.SecretKeySelector{Name: inspacev1.RKE2AgentTokenSecretName, Key: inspacev1.RKE2AgentTokenSecretKey},
			},
		},
	}
	nodeClass.Status.ObservedGeneration = nodeClass.Generation
	nodeClass.Status.ObservedSpecHash = provider.NodeClassHash(nodeClass)
	nodeClass.StatusConditions().SetTrueWithReason("Ready", "NodeClassReady", "Private RKE2 supervisor VIP and Service pool, InSpace VPC, Cilium native-routing firewall, host pool, and RKE2 token are ready")
	return nodeClass
}
