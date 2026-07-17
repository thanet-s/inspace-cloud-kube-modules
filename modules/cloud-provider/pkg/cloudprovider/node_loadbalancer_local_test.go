package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestParsePublicNodeLocalServiceContract(t *testing.T) {
	service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 3})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Mode != nodeLoadBalancerModeLocal || intent.Pool != "edge" || intent.ExistingShard != "" {
		t.Fatalf("local intent = %#v", intent)
	}

	tests := map[string]func(*corev1.Service){
		"pool is explicit": func(service *corev1.Service) {
			delete(service.Annotations, annotationNodeLoadBalancerPool)
		},
		"traffic policy is Local": func(service *corev1.Service) {
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
		},
		"node ports stay disabled": func(service *corev1.Service) {
			value := true
			service.Spec.AllocateLoadBalancerNodePorts = &value
		},
		"shape knobs are rejected": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerCPU] = "2"
		},
		"not-ready publishing is rejected": func(service *corev1.Service) {
			service.Spec.PublishNotReadyAddresses = true
		},
		"shard identity is rejected": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerShard] = "inlb-1234abcd"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := service.DeepCopy()
			mutate(copy)
			if _, err := parseNodeLoadBalancerService(copy, nodeLoadBalancerDefaults{NodesPerShard: 1}); err == nil {
				t.Fatal("invalid public-node-local contract was accepted")
			}
		})
	}
}

func TestPublicNodeLocalMixedTCPUDPFirewallPolicy(t *testing.T) {
	service := publicNodeLocalTestService("mixed", "mixed-service-uid", "edge", corev1.ProtocolTCP, 80)
	service.Spec.Ports[0].Name = "http"
	service.Spec.Ports[0].TargetPort = intstr.FromString("http")
	service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{
		Name: "http3", Protocol: corev1.ProtocolUDP, Port: 443,
		TargetPort: intstr.FromString("http3"),
	})
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(intent.Ports, []nodeLoadBalancerPortClaim{
		{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 80},
		{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolUDP, Port: 443},
	}) {
		t.Fatalf("mixed protocol claims = %#v", intent.Ports)
	}
	controller := &nodeLoadBalancerController{provider: newTestProvider(t, &fakeAPI{})}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.Request.Rules) != 2 || desired.Request.Rules[0].Protocol != "tcp" ||
		desired.Request.Rules[1].Protocol != "udp" {
		t.Fatalf("mixed protocol firewall rules = %#v", desired.Request.Rules)
	}
}

func TestPublicNodeLocalEndpointSliceRequiresExactServiceOwner(t *testing.T) {
	service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	ready := true
	terminating := true
	controller := true
	owned := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: service.Namespace,
			Name:      "edge-owned",
			Labels:    map[string]string{discoveryv1.LabelServiceName: service.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID, Controller: &controller,
			}},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{NodeName: pointerTo("worker-a"), Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{NodeName: pointerTo("worker-b"), Conditions: discoveryv1.EndpointConditions{Ready: &ready, Terminating: &terminating}},
		},
	}
	foreign := owned.DeepCopy()
	foreign.Name = "edge-foreign"
	foreign.OwnerReferences[0].UID = "other-service-uid"
	foreign.Endpoints[0].NodeName = pointerTo("worker-foreign")
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(owned); err != nil {
		t.Fatal(err)
	}
	if err := indexer.Add(foreign); err != nil {
		t.Fatal(err)
	}
	controllerUnderTest := &nodeLoadBalancerController{endpointSlices: discoverylisters.NewEndpointSliceLister(indexer)}
	nodes, err := controllerUnderTest.publicNodeLocalReadyEndpointNodes(service)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nodes, map[string]struct{}{"worker-a": {}}) {
		t.Fatalf("ready local endpoints = %#v", nodes)
	}
}

func TestPublicNodeLocalPortClaimsHaveStableUIDWinnerAcrossWholePool(t *testing.T) {
	winner := publicNodeLocalTestService("winner", "a-service-uid", "edge", corev1.ProtocolTCP, 443)
	loser := publicNodeLocalTestService("loser", "z-service-uid", "edge", corev1.ProtocolTCP, 443)
	differentPool := publicNodeLocalTestService("other", "0-service-uid", "other", corev1.ProtocolTCP, 443)
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(winner, loser, differentPool)
	controller := &nodeLoadBalancerController{provider: provider}

	winnerIntent, err := parseNodeLoadBalancerService(winner, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	loses, waiting, err := controller.publicNodeLocalPortConflict(context.Background(), winner, winnerIntent)
	if err != nil || loses || waiting {
		t.Fatalf("winner conflict = loses:%t waiting:%t err:%v", loses, waiting, err)
	}
	loserIntent, err := parseNodeLoadBalancerService(loser, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	loses, waiting, err = controller.publicNodeLocalPortConflict(context.Background(), loser, loserIntent)
	if !loses || waiting || err == nil || !strings.Contains(err.Error(), "a-service-uid") {
		t.Fatalf("loser conflict = loses:%t waiting:%t err:%v", loses, waiting, err)
	}
}

func TestPublicNodeLocalCoexistsWithActiveAggregateService(t *testing.T) {
	current := publicNodeLocalTestService("local", "local-service-uid", "edge", corev1.ProtocolTCP, 443)
	aggregate := nodeLoadBalancerTestService("shared", "shared-service-uid", corev1.ProtocolTCP, 443)
	aggregate.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeShared
	aggregate.Annotations[annotationNodeLoadBalancerPool] = "edge"
	aggregate.Finalizers = []string{nodeLoadBalancerFinalizer}
	aggregate.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.80"}}
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(current.DeepCopy(), aggregate.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	intent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}

	loses, waiting, err := controller.publicNodeLocalPortConflict(context.Background(), current, intent)
	if err != nil || loses || waiting {
		t.Fatalf("active aggregate Service blocked public-node-local: loses:%t waiting:%t err:%v", loses, waiting, err)
	}
}

func TestPublicNodeLocalMalformedExposedPeerTemporarilyBlocksPort(t *testing.T) {
	current := publicNodeLocalTestService("current", "a-service-uid", "edge", corev1.ProtocolTCP, 443)
	peer := publicNodeLocalTestService("peer", "z-service-uid", "edge", corev1.ProtocolTCP, 443)
	// This peer is no longer a valid local contract, but its old public status
	// proves that the same pool/port datapath has not yet been withdrawn.
	peer.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
	peer.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.90"}}
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(current.DeepCopy(), peer.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	intent, err := parseNodeLoadBalancerService(current, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}

	loses, waiting, err := controller.publicNodeLocalPortConflict(context.Background(), current, intent)
	if err != nil || loses || !waiting {
		t.Fatalf("malformed exposed peer conflict = loses:%t waiting:%t err:%v", loses, waiting, err)
	}

	storedPeer, err := provider.kubeClient.CoreV1().Services(peer.Namespace).Get(context.Background(), peer.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	storedPeer.Status.LoadBalancer = corev1.LoadBalancerStatus{}
	if _, err := provider.kubeClient.CoreV1().Services(peer.Namespace).UpdateStatus(context.Background(), storedPeer, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	loses, waiting, err = controller.publicNodeLocalPortConflict(context.Background(), current, intent)
	if err != nil || loses || waiting {
		t.Fatalf("withdrawn malformed peer conflict = loses:%t waiting:%t err:%v", loses, waiting, err)
	}
}

func TestPublicNodeLocalFinalizerIsIncludedInFullResync(t *testing.T) {
	service := publicNodeLocalTestService("stale", "stale-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Spec.Type = corev1.ServiceTypeClusterIP
	service.Spec.LoadBalancerClass = nil
	service.Finalizers = []string{publicNodeLocalFinalizer}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(service); err != nil {
		t.Fatal(err)
	}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	t.Cleanup(queue.ShutDown)
	controller := &nodeLoadBalancerController{
		services: corelisters.NewServiceLister(indexer),
		queue:    queue,
	}

	controller.enqueueAll()
	assertQueuedKeys(t, queue, service.Namespace+"/"+service.Name)
}

func TestPublicNodeLocalManualNodeLifecycleUsesExistingFIP(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID    = "11111111-2222-4333-8444-555555555555"
		privateIP = "10.0.0.21"
		publicIP  = "203.0.113.21"
	)
	service := publicNodeLocalTestService("edge", "edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	node := publicNodeLocalTestNode("edge-0", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
		floatingIPs: []inspace.FloatingIP{{
			Address: publicIP, BillingAccountID: 42, Type: "public", Enabled: true,
			AssignedTo: vmUUID, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: privateIP,
		}},
	}
	provider := newTestProvider(t, api)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, node.Name)

	for attempt := 0; attempt < 24; attempt++ {
		current, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, current); err != nil {
			t.Fatalf("reconcile %d: %v", attempt, err)
		}
		current, err = provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(current.Status.LoadBalancer.Ingress) == 1 {
			break
		}
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(stored.Finalizers, publicNodeLocalFinalizer) ||
		stored.Annotations[annotationPublicNodeLocalActivePool] != "edge" ||
		len(stored.Status.LoadBalancer.Ingress) != 1 || stored.Status.LoadBalancer.Ingress[0].IP != publicIP ||
		stored.Status.LoadBalancer.Ingress[0].IPMode == nil || *stored.Status.LoadBalancer.Ingress[0].IPMode != corev1.LoadBalancerIPModeProxy ||
		publicNodeLocalAssignmentFencePresent(stored) {
		t.Fatalf("published parent = finalizers:%v annotations:%v status:%#v", stored.Finalizers, stored.Annotations, stored.Status.LoadBalancer)
	}
	datapath, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if datapath.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal ||
		len(datapath.Status.LoadBalancer.Ingress) != 1 || datapath.Status.LoadBalancer.Ingress[0].IP != privateIP {
		t.Fatalf("private datapath = spec:%#v status:%#v", datapath.Spec, datapath.Status.LoadBalancer)
	}
	if len(api.firewalls) != 1 || !firewallAssignedToVM(api.firewalls[0], vmUUID) {
		t.Fatalf("Service firewall = %#v", api.firewalls)
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Address != publicIP || len(api.unassignedIPs) != 0 || len(api.deletedIPs) != 0 {
		t.Fatalf("public-node-local mutated FIPs: %#v, unassigned=%v deleted=%v", api.floatingIPs, api.unassignedIPs, api.deletedIPs)
	}
	// The real API server assigns a UID on create; client-go's simple fake does
	// not, so supply one before exercising the UID-fenced deletion path.
	datapath = datapath.DeepCopy()
	datapath.UID = types.UID("local-datapath-uid")
	if _, err := provider.kubeClient.CoreV1().Services(datapath.Namespace).Update(ctx, datapath, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	// A mode transition must tear down every local-owned object before the
	// aggregate controller is allowed to adopt the Service.
	stored = stored.DeepCopy()
	stored.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeShared
	stored.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
	if _, err := provider.kubeClient.CoreV1().Services(stored.Namespace).Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 32; attempt++ {
		current, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !containsString(current.Finalizers, publicNodeLocalFinalizer) {
			break
		}
		if err := controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, current); err != nil &&
			!strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") {
			t.Fatalf("cleanup reconcile %d: %v", attempt, err)
		}
		latest, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if containsString(latest.Finalizers, publicNodeLocalFinalizer) && latest.Annotations[annotationNodeLoadBalancerCleanupFWChecked] != "" {
			latest = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, latest, annotationNodeLoadBalancerCleanupFWChecked)
		}
		if containsString(latest.Finalizers, publicNodeLocalFinalizer) && latest.Annotations[annotationNodeLoadBalancerWithdrawFWChecked] != "" {
			latest = ageNodeLoadBalancerAbsenceEvidence(t, ctx, provider, latest, annotationNodeLoadBalancerWithdrawFWChecked)
		}
	}
	stored, err = provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(stored.Finalizers, publicNodeLocalFinalizer) || len(stored.Status.LoadBalancer.Ingress) != 0 || len(api.firewalls) != 0 {
		t.Fatalf("local mode cleanup incomplete: finalizers=%v annotations=%v status=%#v firewalls=%#v", stored.Finalizers, stored.Annotations, stored.Status.LoadBalancer, api.firewalls)
	}
	if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, nodeLoadBalancerDatapathName(service), metav1.GetOptions{}); err == nil {
		t.Fatal("local datapath survived mode transition")
	}
	if len(api.floatingIPs) != 1 || api.floatingIPs[0].Address != publicIP {
		t.Fatalf("mode transition changed the existing FIP: %#v", api.floatingIPs)
	}
}

func TestPublicNodeLocalManualAuthorizationRequiresExactAccountVPCMembership(t *testing.T) {
	ctx := context.Background()
	const vmUUID = "21111111-2222-4333-8444-555555555555"
	node := publicNodeLocalTestNode("edge-identity", vmUUID, "10.0.0.31", "203.0.113.31")

	tests := []struct {
		name     string
		mutate   func(*fakeAPI)
		wantAuth bool
		wantErr  bool
	}{
		{name: "exact membership", wantAuth: true},
		{name: "sparse VM network with exact VPC membership", mutate: func(api *fakeAPI) { api.vms[0].NetworkUUID = "" }, wantAuth: true},
		{name: "HTTP 200 deleted VM tombstone", mutate: func(api *fakeAPI) { api.vms[0].Status = "Deleted" }},
		{name: "zero billing account", mutate: func(api *fakeAPI) { api.vms[0].BillingAccountID = 0 }},
		{name: "foreign billing account", mutate: func(api *fakeAPI) { api.vms[0].BillingAccountID = 99 }},
		{name: "foreign VM network", mutate: func(api *fakeAPI) { api.vms[0].NetworkUUID = "99999999-9999-4999-8999-999999999999" }},
		{name: "foreign canonical network", mutate: func(api *fakeAPI) {
			api.network = &inspace.Network{UUID: "99999999-9999-4999-8999-999999999999", VMUUIDs: []string{vmUUID}}
		}},
		{name: "missing canonical membership", mutate: func(api *fakeAPI) {
			api.network = &inspace.Network{UUID: testNetworkUUID}
		}},
		{name: "duplicate canonical membership", mutate: func(api *fakeAPI) {
			api.network = &inspace.Network{UUID: testNetworkUUID, VMUUIDs: []string{vmUUID, vmUUID}}
		}},
		{name: "canonical membership read outage", mutate: func(api *fakeAPI) {
			api.networkErr = errors.New("network read unavailable")
		}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{vms: []inspace.VM{{
				UUID: vmUUID, Name: node.Name, Hostname: node.Name,
				BillingAccountID: 42, NetworkUUID: testNetworkUUID,
			}}}
			if test.mutate != nil {
				test.mutate(api)
			}
			provider := newTestProvider(t, api)
			authorized, patched, err := (&nodeLoadBalancerController{provider: provider}).authorizePublicNodeLocalNode(ctx, node, "edge")
			if test.wantErr {
				if err == nil || authorized || patched {
					t.Fatalf("authorization = authorized:%t patched:%t err:%v", authorized, patched, err)
				}
				return
			}
			if err != nil || authorized != test.wantAuth || patched {
				t.Fatalf("authorization = authorized:%t patched:%t err:%v", authorized, patched, err)
			}
		})
	}
}

func TestPublicNodeLocalRejectsUnfencedPreexistingAssignment(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "31111111-2222-4333-8444-555555555555"
		firewallUUID = "32222222-2222-4333-8444-555555555555"
		privateIP    = "10.0.0.41"
		publicIP     = "203.0.113.41"
	)
	service := publicNodeLocalTestService("unfenced", "unfenced-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	node := publicNodeLocalTestNode("edge-unfenced", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
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
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("unfenced-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy(), datapath)

	err = controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, service)
	if err == nil || !strings.Contains(err.Error(), "has no durable authorization fence") {
		t.Fatalf("unfenced exact assignment was not rejected: %v", err)
	}
	if !reflect.DeepEqual(api.unassignedFirewalls, []string{firewallUUID + "/" + vmUUID}) {
		t.Fatalf("unfenced assignment was not closed first: %#v", api.unassignedFirewalls)
	}
	stored, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if getErr != nil {
		t.Fatal(getErr)
	}
	if len(stored.Status.LoadBalancer.Ingress) != 0 || stored.Annotations[annotationPublicNodeLocalActivePool] != "" {
		t.Fatalf("unfenced assignment became active: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
}

func TestPublicNodeLocalFreshFenceResumesAssignmentAfterRestart(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "51111111-2222-4333-8444-555555555555"
		firewallUUID = "52222222-2222-4333-8444-555555555555"
		privateIP    = "10.0.0.51"
		publicIP     = "203.0.113.51"
	)
	service := publicNodeLocalTestService("restart", "restart-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	node := publicNodeLocalTestNode("edge-restart", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
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
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
	service.Annotations[annotationPublicNodeLocalAssignVMs] = vmUUID
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("restart-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy(), datapath)

	// Simulate a new CCM process starting after the durable fence was written
	// but before AssignFirewallToVM ran. The first reconciliation must resume
	// the missing cloud mutation even though it did not create the fence.
	if err := controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, service); err != nil {
		t.Fatal(err)
	}
	if len(api.firewalls) != 1 || !firewallAssignedToVM(api.firewalls[0], vmUUID) {
		t.Fatalf("fresh persisted fence did not resume assignment: %#v", api.firewalls)
	}

	for attempt := 0; attempt < 12; attempt++ {
		current, getErr := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if len(current.Status.LoadBalancer.Ingress) == 1 && !publicNodeLocalAssignmentFencePresent(current) {
			break
		}
		if err := controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, current); err != nil {
			t.Fatalf("recovery reconcile %d: %v", attempt, err)
		}
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Status.LoadBalancer.Ingress) != 1 || stored.Status.LoadBalancer.Ingress[0].IP != publicIP ||
		publicNodeLocalAssignmentFencePresent(stored) {
		t.Fatalf("restart recovery did not converge: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
}

func TestPublicNodeLocalPublishedRestartClearsFreshAssignmentFence(t *testing.T) {
	ctx := context.Background()
	const (
		vmUUID       = "61111111-2222-4333-8444-555555555555"
		firewallUUID = "62222222-2222-4333-8444-555555555555"
		privateIP    = "10.0.0.61"
		publicIP     = "203.0.113.61"
	)
	service := publicNodeLocalTestService("published-restart", "published-restart-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	node := publicNodeLocalTestNode("edge-published-restart", vmUUID, privateIP, publicIP)
	api := &fakeAPI{
		vms: []inspace.VM{{UUID: vmUUID, Name: node.Name, Hostname: node.Name, PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID}},
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
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
	service.Annotations[annotationPublicNodeLocalAssignVMs] = vmUUID
	service.Annotations[annotationPublicNodeLocalActivePool] = "edge"
	service.Annotations[annotationPublicNodeLocalActivePolicy] = desired.Hash
	addresses := []nodeLoadBalancerAddress{{Node: node, PrivateIPv4: privateIP, PublicIPv4: publicIP}}
	service.Status.LoadBalancer = nodeLoadBalancerStatus(addresses, true)
	api.firewalls = []inspace.Firewall{{
		UUID: firewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("published-restart-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus(addresses, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), node.DeepCopy(), datapath)

	// Simulate restart after parent status publication and before the final
	// fence-clear write. The published exact state authorizes clearing the
	// fence; recovery must not withdraw a healthy edge.
	if err := controller.syncPublicNodeLocal(ctx, service.Namespace+"/"+service.Name, service); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.kubeClient.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if publicNodeLocalAssignmentFencePresent(stored) || !reflect.DeepEqual(stored.Status.LoadBalancer, service.Status.LoadBalancer) {
		t.Fatalf("published restart did not clear only the fence: annotations=%#v status=%#v", stored.Annotations, stored.Status.LoadBalancer)
	}
	if len(api.unassignedFirewalls) != 0 || !firewallAssignedToVM(api.firewalls[0], vmUUID) {
		t.Fatalf("published restart withdrew the healthy edge: unassigned=%#v firewalls=%#v", api.unassignedFirewalls, api.firewalls)
	}
}

func TestPublicNodeLocalFreshFenceResumesPartialMultiNodeAssignment(t *testing.T) {
	ctx := context.Background()
	const (
		firstVM     = "71111111-2222-4333-8444-555555555555"
		secondVM    = "72222222-2222-4333-8444-555555555555"
		firewallID  = "73333333-2222-4333-8444-555555555555"
		firstPublic = "203.0.113.71"
		secondPub   = "203.0.113.72"
	)
	service := publicNodeLocalTestService("partial-restart", "partial-restart-uid", "edge", corev1.ProtocolUDP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	first := publicNodeLocalTestNode("edge-partial-a", firstVM, "10.0.0.71", firstPublic)
	second := publicNodeLocalTestNode("edge-partial-b", secondVM, "10.0.0.72", secondPub)
	addresses := []nodeLoadBalancerAddress{
		{Node: first, PrivateIPv4: "10.0.0.71", PublicIPv4: firstPublic},
		{Node: second, PrivateIPv4: "10.0.0.72", PublicIPv4: secondPub},
	}
	api := &fakeAPI{
		vms: []inspace.VM{
			{UUID: firstVM, Name: first.Name, Hostname: first.Name, PrivateIPv4: "10.0.0.71", BillingAccountID: 42, NetworkUUID: testNetworkUUID},
			{UUID: secondVM, Name: second.Name, Hostname: second.Name, PrivateIPv4: "10.0.0.72", BillingAccountID: 42, NetworkUUID: testNetworkUUID},
		},
		floatingIPs: []inspace.FloatingIP{
			{Address: firstPublic, BillingAccountID: 42, Type: "public", Enabled: true, AssignedTo: firstVM, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: "10.0.0.71"},
			{Address: secondPub, BillingAccountID: 42, Type: "public", Enabled: true, AssignedTo: secondVM, AssignedToResourceType: "virtual_machine", AssignedToPrivateIP: "10.0.0.72"},
		},
	}
	provider := newTestProvider(t, &publicNodeLocalFilteringIPAPI{fakeAPI: api})
	controller := &nodeLoadBalancerController{provider: provider}
	controller.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, first.Name, second.Name)
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = firewallID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = firewallID
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = desired.Hash
	service.Annotations[annotationPublicNodeLocalAssignVMs] = firstVM + "," + secondVM
	api.firewalls = []inspace.Firewall{{
		UUID: firewallID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: firstVM}},
	}}
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("partial-restart-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus(addresses, false)
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), first.DeepCopy(), second.DeepCopy(), datapath)
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.assignPublicNodeLocalFirewallWithFence(
		ctx, service, intent, desired, &api.firewalls[0], addresses,
	); err != nil {
		t.Fatal(err)
	}
	assignments := make([]string, 0, len(api.firewalls[0].ResourcesAssigned))
	for _, assignment := range api.firewalls[0].ResourcesAssigned {
		assignments = append(assignments, assignment.ResourceUUID)
	}
	sort.Strings(assignments)
	if !reflect.DeepEqual(assignments, []string{firstVM, secondVM}) {
		t.Fatalf("partial fresh-fence recovery assignments = %#v", assignments)
	}
}

func TestPublicNodeLocalDriftCannotMutateChildWhileAssignmentFenceIsUnresolved(t *testing.T) {
	ctx := context.Background()
	service := publicNodeLocalTestService("drift", "drift-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	service.Annotations[annotationNodeLoadBalancerFirewallAssigning] = "42222222-2222-4333-8444-555555555555"
	service.Annotations[annotationNodeLoadBalancerFirewallAssignAt] = time.Now().UTC().Format(time.RFC3339Nano)
	service.Annotations[annotationPublicNodeLocalAssignPolicy] = "policy"
	service.Annotations[annotationPublicNodeLocalAssignVMs] = "41111111-2222-4333-8444-555555555555"
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("drift-datapath-uid")
	datapath.Spec.Selector = map[string]string{"app": "stale"}
	provider := newTestProvider(t, &fakeAPI{})
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy(), datapath.DeepCopy())
	controller := &nodeLoadBalancerController{provider: provider}

	_, changed, err := controller.ensurePublicNodeLocalDatapath(ctx, service, "edge")
	if err == nil || !strings.Contains(err.Error(), "waiting for exact Service firewall detachment readback") || changed {
		t.Fatalf("unresolved assignment fence did not block child mutation: changed=%t err=%v", changed, err)
	}
	stored, getErr := provider.kubeClient.CoreV1().Services(datapath.Namespace).Get(ctx, datapath.Name, metav1.GetOptions{})
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !reflect.DeepEqual(stored.Spec.Selector, map[string]string{"app": "stale"}) {
		t.Fatalf("drifted child mutated before withdrawal proof: %#v", stored.Spec.Selector)
	}
}

func TestPublicNodeLocalDatapathPreservesAPIServerHealthCheckNodePort(t *testing.T) {
	service := publicNodeLocalTestService("health", "health-service-uid", "edge", corev1.ProtocolTCP, 443)
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("health-datapath-uid")
	datapath.Spec.HealthCheckNodePort = 31234
	if !publicNodeLocalDatapathMatches(datapath, service, "edge") {
		t.Fatal("apiserver-assigned healthCheckNodePort caused false child drift")
	}
}

func TestPublicNodeLocalKarpenterAuthorizationRequiresLaunchProfileAndMirrorsProtectedLabel(t *testing.T) {
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
		vms:       []inspace.VM{{UUID: vmUUID, Name: nodeName, Hostname: nodeName, PrivateIPv4: privateIP, BillingAccountID: 42, NetworkUUID: testNetworkUUID, Description: string(description)}},
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
	if stored.Labels[publicNodeLocalPoolLabel] != "edge" {
		t.Fatalf("protected pool label was not mirrored: %#v", stored.Labels)
	}
	authorized, patched, err = (&nodeLoadBalancerController{provider: provider}).authorizePublicNodeLocalNode(ctx, stored, "edge")
	if err != nil || !authorized || patched {
		t.Fatalf("verified authorization = authorized:%t patched:%t err:%v", authorized, patched, err)
	}

	ownership["firewallProfile"] = "private-worker"
	description, _ = json.Marshal(ownership)
	api.vms[0].Description = string(description)
	authorized, patched, err = (&nodeLoadBalancerController{provider: provider}).authorizePublicNodeLocalNode(ctx, stored, "edge")
	if err != nil || authorized || patched {
		t.Fatalf("stale private launch profile = authorized:%t patched:%t err:%v", authorized, patched, err)
	}

	// Losing the mirrored protected label while an exact Service firewall is
	// active must converge by restoring the chain-proven label first. Auditing
	// the Service firewall against the stale Node object would otherwise reject
	// the node forever and make the repair unreachable.
	ownership["firewallProfile"] = publicNodeLocalFirewallProfile
	description, _ = json.Marshal(ownership)
	api.vms[0].Description = string(description)
	service := publicNodeLocalTestService("karp-edge", "karp-edge-service-uid", "edge", corev1.ProtocolTCP, 443)
	service.Finalizers = []string{publicNodeLocalFinalizer}
	localController := &nodeLoadBalancerController{provider: provider}
	desired, err := localController.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	const serviceFirewallUUID = "33333333-3333-4333-8333-333333333333"
	service.Annotations[annotationNodeLoadBalancerFirewallUUID] = serviceFirewallUUID
	service.Annotations[annotationNodeLoadBalancerFirewallHash] = desired.Hash
	service.Annotations[annotationPublicNodeLocalActivePool] = "edge"
	service.Annotations[annotationPublicNodeLocalActivePolicy] = desired.Hash
	service.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: stored, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, true)
	datapath := desiredPublicNodeLocalDatapath(service, "edge")
	datapath.UID = types.UID("karp-edge-datapath-uid")
	datapath.Status.LoadBalancer = nodeLoadBalancerStatus([]nodeLoadBalancerAddress{{
		Node: stored, PrivateIPv4: privateIP, PublicIPv4: publicIP,
	}}, false)
	if _, err := provider.kubeClient.CoreV1().Services(service.Namespace).Create(ctx, service, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.kubeClient.CoreV1().Services(datapath.Namespace).Create(ctx, datapath, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	localController.endpointSlices = publicNodeLocalTestEndpointSliceLister(t, service, stored.Name)
	api.firewalls = append(api.firewalls, inspace.Firewall{
		UUID: serviceFirewallUUID, DisplayName: desired.Request.DisplayName,
		BillingAccountID: desired.Request.BillingAccountID, Rules: desired.Request.Rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	})
	stripped := stored.DeepCopy()
	delete(stripped.Labels, publicNodeLocalPoolLabel)
	stripped, err = provider.kubeClient.CoreV1().Nodes().Update(ctx, stripped, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	authorized, patched, err = localController.authorizePublicNodeLocalNode(ctx, stripped, "edge")
	if err != nil || authorized || !patched {
		t.Fatalf("protected-label recovery = authorized:%t patched:%t err:%v", authorized, patched, err)
	}
	restored, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, stripped.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	authorized, patched, err = localController.authorizePublicNodeLocalNode(ctx, restored, "edge")
	if err != nil || !authorized || patched {
		t.Fatalf("post-recovery complete firewall audit = authorized:%t patched:%t err:%v", authorized, patched, err)
	}
}

func publicNodeLocalTestService(name, uid, pool string, protocol corev1.Protocol, port int32) *corev1.Service {
	service := nodeLoadBalancerTestService(name, uid, protocol, port)
	service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeLocal
	service.Annotations[annotationNodeLoadBalancerPool] = pool
	return service
}

func publicNodeLocalTestNode(name, vmUUID, privateIP, publicIP string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{publicNodeLocalPoolLabel: "edge"},
		},
		Spec: corev1.NodeSpec{ProviderID: "inspace://bkk01/" + vmUUID},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: privateIP},
				{Type: corev1.NodeExternalIP, Address: publicIP},
			},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
}

func publicNodeLocalTestBaseFirewall(vmUUID string) inspace.Firewall {
	rules := make([]inspace.FirewallRule, 0, 6)
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		rules = append(rules, inspace.FirewallRule{
			Protocol: protocol, Direction: "inbound", EndpointSpecType: "ip_prefixes",
			EndpointSpec: []string{"10.0.0.0/24", "10.42.0.0/16"},
		})
		rules = append(rules, inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"})
	}
	return inspace.Firewall{
		UUID: "22222222-2222-4222-8222-222222222222", DisplayName: "unit-test-base",
		BillingAccountID: 42, Rules: rules,
		ResourcesAssigned: []inspace.FirewallResource{{ResourceType: "vm", ResourceUUID: vmUUID}},
	}
}

func publicNodeLocalTestEndpointSliceLister(t *testing.T, service *corev1.Service, nodeNames ...string) discoverylisters.EndpointSliceLister {
	t.Helper()
	ready := true
	controller := true
	endpoints := make([]discoveryv1.Endpoint, 0, len(nodeNames))
	for index := range nodeNames {
		endpoints = append(endpoints, discoveryv1.Endpoint{
			NodeName: &nodeNames[index], Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
	endpointSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: service.Namespace,
			Name:      service.Name + "-slice",
			Labels:    map[string]string{discoveryv1.LabelServiceName: service.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID, Controller: &controller,
			}},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := indexer.Add(endpointSlice); err != nil {
		t.Fatal(err)
	}
	return discoverylisters.NewEndpointSliceLister(indexer)
}

func pointerTo[T any](value T) *T { return &value }

type publicNodeLocalFilteringIPAPI struct {
	*fakeAPI
}

func (f *publicNodeLocalFilteringIPAPI) ListFloatingIPs(
	_ context.Context,
	_ string,
	filters *inspace.FloatingIPFilters,
) ([]inspace.FloatingIP, error) {
	if filters == nil || filters.VMUUID == "" {
		return append([]inspace.FloatingIP(nil), f.fakeAPI.floatingIPs...), nil
	}
	result := make([]inspace.FloatingIP, 0, 1)
	for _, address := range f.fakeAPI.floatingIPs {
		if address.AssignedTo == filters.VMUUID {
			result = append(result, address)
		}
	}
	return result, nil
}
