package cloudprovider

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestPublicNodeLocalAssignTimeoutExceedsRelationRetireDelay(t *testing.T) {
	floor := nodeLoadBalancerFirewallRelationRetireDelay + 2*nodeLoadBalancerAbsenceConfirmationDelay
	if nodeLoadBalancerPublicNodeLocalAssignTimeout < floor {
		t.Fatalf("assignment timeout %s is shorter than the relation retire path %s",
			nodeLoadBalancerPublicNodeLocalAssignTimeout, floor)
	}
}

func TestPublicNodeLocalExpiredAssignmentIntentRefreshesWithoutWithdraw(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "51111111-2222-4333-8444-555555555555"
		firewallUUID = "52222222-2222-4333-8444-555555555555"
		privateIP    = "10.0.0.51"
		publicIP     = "203.0.113.51"
	)
	service := publicNodeLocalTestService("expired", "expired-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	node := publicNodeLocalTestNode("edge-expired", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, Status: "running", PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		floatingIPs: []inspace.FloatingIP{{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		}},
	}
	provider := newTestProvider(t, api)
	controller := &nodeLoadBalancerController{provider: provider}
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, node.Name)
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-7 * time.Minute)
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = expired.Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
	service.Annotations[annotationPublicNodeLocalAssignVMs] = vmUUID
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("expired-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy(), datapath)
	key := service.Namespace + "/" + service.Name

	if err := controller.syncPublicNodeLocal(ctx, key, service); err != nil {
		t.Fatalf("expired intent failed the Service: %v", err)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("expired intent unassigned a firewall: %#v", api.unassignedFirewalls)
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assignAt, parseErr := time.Parse(time.RFC3339Nano, stored.Annotations[annotationNodeLoadBalancerFirewallAssignAt])
	if parseErr != nil || !assignAt.After(expired.Add(6*time.Minute)) {
		t.Fatalf("assignment intent was not refreshed: %q err=%v", stored.Annotations[annotationNodeLoadBalancerFirewallAssignAt], parseErr)
	}
	for attempt := 0; attempt < 12; attempt++ {
		current, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if len(current.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(current) {
			break
		}
		if err := controller.syncPublicNodeLocal(ctx, key, current); err != nil {
			t.Fatalf("recovery reconcile %d: %v", attempt, err)
		}
	}
	stored, err = provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Status.LoadBalancer.Ingress) != 1 || publicNodeLocalAssignmentFencePresent(stored) {
		t.Fatalf("refreshed intent did not converge: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
	if len(api.unassignedFirewalls) != 0 {
		t.Fatalf("recovery unassigned a firewall: %#v", api.unassignedFirewalls)
	}
}
