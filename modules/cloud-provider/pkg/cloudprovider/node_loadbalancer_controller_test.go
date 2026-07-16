package cloudprovider

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

func TestParseNodeLoadBalancerServiceDefaultsToShared(t *testing.T) {
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Mode != nodeLoadBalancerModeShared || intent.Pool != nodeLoadBalancerDefaultPool ||
		intent.NodesPerShard != 1 || intent.CPU != nodeLoadBalancerDefaultCPU || intent.MemoryMiB != nodeLoadBalancerDefaultMemoryMiB {
		t.Fatalf("default intent = %#v", intent)
	}
	if len(intent.Ports) != 1 || intent.Ports[0] != (nodeLoadBalancerPortClaim{IPFamily: corev1.IPv4Protocol, Protocol: corev1.ProtocolTCP, Port: 443}) {
		t.Fatalf("default ports = %#v", intent.Ports)
	}

	service.Annotations[annotationNodeLoadBalancerMode] = "shared"
	alias, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 3})
	if err != nil || alias.Mode != nodeLoadBalancerModeShared || alias.NodesPerShard != 3 {
		t.Fatalf("short shared alias = %#v, %v", alias, err)
	}
}

func TestDesiredNodeLoadBalancerFirewallUsesExactOwnedPortsAndSources(t *testing.T) {
	service := nodeLoadBalancerTestService("web", "9f5db76f-90c1-4ee5-9067-9a3db48e3c9b", corev1.ProtocolTCP, 443)
	service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolUDP, Port: 53})
	service.Spec.LoadBalancerSourceRanges = []string{"203.0.113.9/24", "198.51.100.0/24"}
	provider := newTestProvider(t, &fakeAPI{})
	provider.config.ClusterID = "cluster"
	controller := &nodeLoadBalancerController{provider: provider}
	desired, err := controller.desiredServiceFirewall(service)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := nodeLoadBalancerFirewallServicePrefix("cluster", string(service.UID))
	if !strings.HasPrefix(desired.Request.DisplayName, wantPrefix) ||
		desired.Request.DisplayName != wantPrefix+desired.Hash {
		t.Fatalf("firewall name = %q, hash = %q", desired.Request.DisplayName, desired.Hash)
	}
	if desired.Hash == "" || desired.Request.BillingAccountID != 42 || len(desired.Request.Rules) != 2 {
		t.Fatalf("firewall = %#v", desired)
	}
	seen := map[string]bool{}
	for _, rule := range desired.Request.Rules {
		if rule.Direction != "inbound" || rule.EndpointSpecType != "ip_prefixes" ||
			!reflect.DeepEqual(rule.EndpointSpec, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
			t.Fatalf("unsafe firewall rule = %#v", rule)
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			t.Fatalf("unexpected firewall protocol = %#v", rule)
		}
		if rule.PortStart == nil || rule.PortEnd == nil || *rule.PortStart != *rule.PortEnd {
			t.Fatalf("unsafe port rule = %#v", rule)
		}
		seen[rule.Protocol+"/"+strconv.FormatInt(int64(*rule.PortStart), 10)] = true
	}
	if !reflect.DeepEqual(seen, map[string]bool{"tcp/443": true, "udp/53": true}) {
		t.Fatalf("firewall protocols = %#v", seen)
	}
}

func TestNodeLoadBalancerFirewallHashMatchesKarpenterContract(t *testing.T) {
	validRules := func() []inspace.FirewallRule {
		port := int32(443)
		return []inspace.FirewallRule{{
			Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
		}}
	}
	rules := validRules()
	hash, err := nodeLoadBalancerFirewallSpecHash(rules)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "886b49b4" {
		t.Fatalf("firewall hash = %q, want shared contract 886b49b4", hash)
	}

	invalid := map[string]func([]inspace.FirewallRule) []inspace.FirewallRule{
		"no Service port": func([]inspace.FirewallRule) []inspace.FirewallRule {
			return nil
		},
		"ICMP mixed in": func(rules []inspace.FirewallRule) []inspace.FirewallRule {
			return append(rules, inspace.FirewallRule{Protocol: "icmp", Direction: "inbound", EndpointSpecType: "any"})
		},
		"duplicate port": func(rules []inspace.FirewallRule) []inspace.FirewallRule {
			return append(rules, rules[0])
		},
		"duplicate prefix": func(rules []inspace.FirewallRule) []inspace.FirewallRule {
			rules[0].EndpointSpecType = "ip_prefixes"
			rules[0].EndpointSpec = []string{"198.51.100.0/24", "198.51.100.0/24"}
			return rules
		},
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := nodeLoadBalancerFirewallSpecHash(mutate(validRules())); err == nil {
				t.Fatal("invalid firewall policy was accepted")
			}
		})
	}
}

func TestDesiredNodeLoadBalancerClusterICMPFirewallUsesSharedContract(t *testing.T) {
	desired, err := desiredNodeLoadBalancerClusterICMPFirewall("cluster", 42)
	if err != nil {
		t.Fatal(err)
	}
	if desired.Request.DisplayName != "inlb-164cf1ca8391532e4f239c556c0c1958-icmp-564fcbd1" || desired.Hash != "564fcbd1" ||
		desired.Request.Description != nodeLoadBalancerICMPFirewallDescription || len(desired.Request.Rules) != 1 {
		t.Fatalf("cluster ICMP firewall = %#v", desired)
	}
	rule := desired.Request.Rules[0]
	if rule.Protocol != "icmp" || rule.Direction != "inbound" || rule.EndpointSpecType != "any" ||
		rule.PortStart != nil || rule.PortEnd != nil || len(rule.EndpointSpec) != 0 {
		t.Fatalf("cluster ICMP rule = %#v", rule)
	}
	firewall := inspace.Firewall{
		DisplayName: desired.Request.DisplayName, BillingAccountID: 42, Rules: desired.Request.Rules,
	}
	if !nodeLoadBalancerClusterICMPFirewallOwned(firewall, "cluster", 42) {
		t.Fatal("CCM-produced cluster ICMP firewall was rejected by the shared contract")
	}
}

func TestNodeLoadBalancerDatapathUsesPrivateVIPContractFromFirstCreate(t *testing.T) {
	service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
	service.Spec.Selector = map[string]string{"app": "web"}
	const shard = "inlb-0123abcd"
	datapath := desiredNodeLoadBalancerDatapath(service, nodeLoadBalancerDatapathName(service), shard)
	if datapath.Spec.LoadBalancerClass == nil || *datapath.Spec.LoadBalancerClass != nodeLoadBalancerDatapathClass ||
		datapath.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster ||
		datapath.Spec.AllocateLoadBalancerNodePorts == nil || *datapath.Spec.AllocateLoadBalancerNodePorts {
		t.Fatalf("datapath spec = %#v", datapath.Spec)
	}
	if datapath.Annotations[annotationNodeLoadBalancerDatapathShard] != shard {
		t.Fatalf("datapath shard = %q, want %q", datapath.Annotations[annotationNodeLoadBalancerDatapathShard], shard)
	}
	if _, exists := datapath.Annotations["io.cilium.nodeipam/match-node-labels"]; exists {
		t.Fatalf("datapath must not use Cilium Node IPAM: %#v", datapath.Annotations)
	}
	if !reflect.DeepEqual(datapath.Spec.Selector, service.Spec.Selector) ||
		len(datapath.Spec.Ports) != 1 || datapath.Spec.Ports[0].Port != 443 {
		t.Fatalf("datapath backend contract = %#v", datapath.Spec)
	}
	if len(datapath.OwnerReferences) != 1 || datapath.OwnerReferences[0].UID != service.UID {
		t.Fatalf("datapath owner = %#v", datapath.OwnerReferences)
	}
}

func TestNodeLoadBalancerHealthRequiresCanonicalPrivateAndPublicIPv4(t *testing.T) {
	node := readyNode("lb-a", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	node.Labels = map[string]string{nodeLoadBalancerNodeLabel: "true"}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	if !nodeLoadBalancerNodeHealthy(node) {
		t.Fatal("healthy LB node was rejected")
	}
	node.Status.Addresses[0].Address = "203.0.113.20"
	if nodeLoadBalancerNodeHealthy(node) {
		t.Fatal("node without a private InternalIP was advertised")
	}
	node.Status.Addresses[0].Address = "10.0.0.20"
	node.Status.Addresses[1].Address = "10.0.0.20"
	if nodeLoadBalancerNodeHealthy(node) {
		t.Fatal("private-only LB node was advertised")
	}
	for _, invalid := range []string{"169.254.10.20", "224.0.0.1"} {
		node.Status.Addresses[1].Address = invalid
		if nodeLoadBalancerNodeHealthy(node) {
			t.Fatalf("non-global LB address %s was advertised", invalid)
		}
	}
	node.Status.Addresses[1].Address = "203.0.113.10"
	node.Spec.Taints = append(node.Spec.Taints, corev1.Taint{Key: karpenterDisruptionTaint, Effect: corev1.TaintEffectNoSchedule})
	if nodeLoadBalancerNodeHealthy(node) {
		t.Fatal("disrupted LB node was advertised")
	}
	node.Spec.Taints = nil
	node.Labels[corev1.LabelNodeExcludeBalancers] = ""
	if nodeLoadBalancerNodeHealthy(node) {
		t.Fatal("explicitly excluded LB node was advertised")
	}
}

func TestNodeLoadBalancerReconcileSmokeCreatesOwnedKarpenterAndDatapathResources(t *testing.T) {
	ctx := context.Background()
	service := nodeLoadBalancerTestService("web", "9f5db76f-90c1-4ee5-9067-9a3db48e3c9b", corev1.ProtocolTCP, 443)
	service.Spec.Selector = map[string]string{"app": "web"}
	base := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.inspace.cloud/v1alpha1", "kind": "InSpaceNodeClass",
		"metadata": map[string]any{"name": "workers"},
		"spec": map[string]any{
			"clusterName": "unit-test-cluster", "billingAccountID": int64(42), "location": "bkk01",
			"networkUUID": testNetworkUUID, "firewallUUID": "22222222-2222-4222-8222-222222222222",
			"privateLoadBalancerPool": map[string]any{"start": "10.0.0.200", "stop": "10.0.0.239"},
			"rke2":                    map[string]any{"server": "https://10.0.0.10:9345"},
			"rootDiskGiB":             int64(100), "reservePublicIPv4": true,
		},
	}}
	api := &fakeAPI{}
	provider := newTestProvider(t, api)
	provider.config.NodeLoadBalancer = NodeLoadBalancerConfig{Enabled: true, DefaultNodeClass: "workers", NodesPerShard: 1}
	provider.kubeClient = kubefake.NewSimpleClientset(service.DeepCopy())
	provider.dynamicClient = newNodeLoadBalancerTestDynamicClient(base)
	serviceIndexer := newNamespacedIndexer()
	if err := serviceIndexer.Add(service.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	controller := &nodeLoadBalancerController{
		provider: provider, services: corelisters.NewServiceLister(serviceIndexer), nodes: corelisters.NewNodeLister(nodeIndexer),
		queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	defer controller.queue.ShutDown()

	for i := 0; i < 6; i++ {
		if err := controller.sync(ctx, "default/web"); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
		stored, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := serviceIndexer.Update(stored); err != nil {
			t.Fatal(err)
		}
	}
	stored, _ := provider.kubeClient.CoreV1().Services("default").Get(ctx, "web", metav1.GetOptions{})
	if !containsString(stored.Finalizers, nodeLoadBalancerFinalizer) || stored.Annotations[annotationNodeLoadBalancerShard] == "" {
		t.Fatalf("stored Service metadata = %#v", stored.ObjectMeta)
	}
	if stored.Annotations[annotationNodeLoadBalancerFirewallUUID] != "" ||
		stored.Annotations[annotationNodeLoadBalancerFirewallHash] != "" {
		t.Fatalf("stable controller persisted legacy per-Service firewall metadata: %#v", stored.Annotations)
	}
	child, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, nodeLoadBalancerDatapathName(stored), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("closed datapath Service was not staged before firewall creation: %v", err)
	}
	if len(child.Status.LoadBalancer.Ingress) != 0 || len(stored.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("datapath was published before ready capacity: child=%#v parent=%#v", child.Status.LoadBalancer, stored.Status.LoadBalancer)
	}
	nodeClassName := managedNodeLoadBalancerName(provider.config.ClusterID, "node-lb")
	nodeClass, err := provider.dynamicClient.Resource(nodeClassGVR).Get(ctx, nodeClassName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if profile, _, _ := unstructured.NestedString(nodeClass.Object, "spec", "firewallProfile"); profile != nodeLoadBalancerFirewallMode {
		t.Fatalf("generated NodeClass firewall profile = %q", profile)
	}
	nodePool, err := provider.dynamicClient.Resource(nodePoolGVR).Get(ctx, stored.Annotations[annotationNodeLoadBalancerShard], metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replicas, _, _ := unstructured.NestedInt64(nodePool.Object, "spec", "replicas"); replicas != 1 {
		t.Fatalf("generated NodePool replicas = %d", replicas)
	}
	if cluster, _, _ := unstructured.NestedString(nodePool.Object, "spec", "template", "metadata", "labels", nodeLoadBalancerNodeClusterLabel); cluster != provider.config.ClusterID {
		t.Fatalf("generated NodePool template cluster = %q", cluster)
	}
	requirements, _, _ := unstructured.NestedSlice(nodePool.Object, "spec", "template", "spec", "requirements")
	defaultShape := map[string]string{}
	for _, raw := range requirements {
		requirement := raw.(map[string]any)
		values := requirement["values"].([]any)
		if len(values) == 1 {
			defaultShape[requirement["key"].(string)] = values[0].(string)
		}
	}
	if defaultShape["inspace.cloud/instance-cpu"] != "1" || defaultShape["inspace.cloud/instance-memory"] != "4096" {
		t.Fatalf("generated default NodePool shape = %#v", defaultShape)
	}
	if len(api.createdFirewalls) != 2 {
		t.Fatalf("created firewalls = %#v", api.createdFirewalls)
	}
	createdICMP := 0
	createdShard := 0
	for _, request := range api.createdFirewalls {
		firewall := inspace.Firewall{
			DisplayName: request.DisplayName, Description: request.Description,
			BillingAccountID: request.BillingAccountID, Rules: request.Rules,
		}
		if inspace.ValidateNodeLoadBalancerClusterICMPFirewall(firewall, provider.config.ClusterID, provider.config.BillingAccountID) == nil {
			createdICMP++
		}
		hash, hashErr := inspace.NodeLoadBalancerShardFirewallSpecHash(request.Rules)
		if hashErr == nil && inspace.ValidateNodeLoadBalancerShardFirewall(
			firewall,
			provider.config.ClusterID,
			stored.Annotations[annotationNodeLoadBalancerShard],
			provider.config.BillingAccountID,
			hash,
		) == nil {
			createdShard++
		}
	}
	if createdICMP != 1 || createdShard != 1 {
		t.Fatalf("created firewall contracts: ICMP=%d shard=%d requests=%#v", createdICMP, createdShard, api.createdFirewalls)
	}

	shard := stored.Annotations[annotationNodeLoadBalancerShard]
	node := readyNode("lb-0", "inspace://bkk01/aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb")
	node.Labels = map[string]string{
		nodeLoadBalancerNodeLabel:        "true",
		nodeLoadBalancerNodeClusterLabel: provider.config.ClusterID,
		nodeLoadBalancerNodeShardLabel:   shard,
	}
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.20"},
		{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
	}
	installNodeLoadBalancerSafetyIdentity(t, provider, node, shard)
	if _, err := provider.kubeClient.CoreV1().Nodes().Create(ctx, node.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := nodeIndexer.Add(node.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := controller.sync(ctx, "default/web"); err != nil {
			t.Fatalf("ready sync %d: %v", i, err)
		}
		stored, err = provider.kubeClient.CoreV1().Services("default").Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := serviceIndexer.Update(stored); err != nil {
			t.Fatal(err)
		}
		currentNode, err := provider.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := nodeIndexer.Update(currentNode); err != nil {
			t.Fatal(err)
		}
	}
	datapath, err := provider.kubeClient.CoreV1().Services("default").Get(ctx, nodeLoadBalancerDatapathName(stored), metav1.GetOptions{})
	if err != nil || datapath.Spec.LoadBalancerClass == nil || *datapath.Spec.LoadBalancerClass != nodeLoadBalancerDatapathClass ||
		datapath.Annotations[annotationNodeLoadBalancerDatapathShard] != shard {
		t.Fatalf("datapath Service = %#v, %v", datapath, err)
	}
	if len(datapath.Status.LoadBalancer.Ingress) != 1 || datapath.Status.LoadBalancer.Ingress[0].IP != "10.0.0.20" ||
		datapath.Status.LoadBalancer.Ingress[0].IPMode == nil || *datapath.Status.LoadBalancer.Ingress[0].IPMode != corev1.LoadBalancerIPModeVIP {
		t.Fatalf("private VIP datapath status = %#v", datapath.Status.LoadBalancer)
	}
	stored, _ = provider.kubeClient.CoreV1().Services("default").Get(ctx, "web", metav1.GetOptions{})
	if len(stored.Status.LoadBalancer.Ingress) != 1 || stored.Status.LoadBalancer.Ingress[0].IP != "203.0.113.10" ||
		stored.Status.LoadBalancer.Ingress[0].IPMode == nil || *stored.Status.LoadBalancer.Ingress[0].IPMode != corev1.LoadBalancerIPModeProxy {
		t.Fatalf("published Service status = %#v", stored.Status.LoadBalancer)
	}
	if stored.Annotations[annotationNodeLoadBalancerDatapathActive] != shard {
		t.Fatalf("active datapath marker = %q, want %q", stored.Annotations[annotationNodeLoadBalancerDatapathActive], shard)
	}
}

func TestParseNodeLoadBalancerDedicatedSizing(t *testing.T) {
	service := nodeLoadBalancerTestService("database", "database-uid", corev1.ProtocolTCP, 5432)
	service.Annotations = map[string]string{
		annotationNodeLoadBalancerMode:          nodeLoadBalancerModeDedicated,
		annotationNodeLoadBalancerPool:          "databases",
		annotationNodeLoadBalancerNodesPerShard: "2",
		annotationNodeLoadBalancerCPU:           "4",
		annotationNodeLoadBalancerMemory:        "32Gi",
	}
	intent, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 1})
	if err != nil {
		t.Fatal(err)
	}
	if intent.Mode != nodeLoadBalancerModeDedicated || intent.Pool != "databases" || intent.NodesPerShard != 2 || intent.CPU != 4 || intent.MemoryMiB != 32768 {
		t.Fatalf("dedicated intent = %#v", intent)
	}

	delete(service.Annotations, annotationNodeLoadBalancerCPU)
	delete(service.Annotations, annotationNodeLoadBalancerMemory)
	defaults, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 1})
	if err != nil || defaults.CPU != nodeLoadBalancerDefaultCPU || defaults.MemoryMiB != nodeLoadBalancerDefaultMemoryMiB {
		t.Fatalf("dedicated sizing defaults = %#v, %v", defaults, err)
	}
}

func TestParseNodeLoadBalancerRejectsInvalidShapesAndContracts(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Service){
		"invalid mode": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerMode] = "cheap"
		},
		"local traffic": func(service *corev1.Service) {
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
		},
		"sctp": func(service *corev1.Service) {
			service.Spec.Ports[0].Protocol = corev1.ProtocolSCTP
		},
		"below minimum memory": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
			service.Annotations[annotationNodeLoadBalancerCPU] = "1"
			service.Annotations[annotationNodeLoadBalancerMemory] = "2Gi"
		},
		"invalid catalog shape": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
			service.Annotations[annotationNodeLoadBalancerCPU] = "3"
			service.Annotations[annotationNodeLoadBalancerMemory] = "6Gi"
		},
		"invalid quantity": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerMode] = nodeLoadBalancerModeDedicated
			service.Annotations[annotationNodeLoadBalancerMemory] = "lots"
		},
		"shared custom shape": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerCPU] = "2"
		},
		"zero nodes": func(service *corev1.Service) {
			service.Annotations[annotationNodeLoadBalancerNodesPerShard] = "0"
		},
		"selectorless": func(service *corev1.Service) {
			service.Spec.Selector = nil
		},
		"implicit node ports": func(service *corev1.Service) {
			service.Spec.AllocateLoadBalancerNodePorts = nil
		},
		"allocated node port": func(service *corev1.Service) {
			service.Spec.Ports[0].NodePort = 30443
		},
		"external IP": func(service *corev1.Service) {
			service.Spec.ExternalIPs = []string{"203.0.113.20"}
		},
		"IPv6 source range": func(service *corev1.Service) {
			service.Spec.LoadBalancerSourceRanges = []string{"2001:db8::/32"}
		},
		"dual-stack policy": func(service *corev1.Service) {
			policy := corev1.IPFamilyPolicyRequireDualStack
			service.Spec.IPFamilyPolicy = &policy
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := nodeLoadBalancerTestService("web", "web-uid", corev1.ProtocolTCP, 443)
			mutate(service)
			if _, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 1}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateNodeLoadBalancerShapeEnforcesNodeLBMinimum(t *testing.T) {
	for name, shape := range map[string]struct {
		cpu       int32
		memoryMiB int64
	}{
		"legacy one CPU two GiB shape": {cpu: 1, memoryMiB: 2048},
		"two CPU two GiB shape":        {cpu: 2, memoryMiB: 2048},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateNodeLoadBalancerShape(shape.cpu, shape.memoryMiB)
			if err == nil || !strings.Contains(err.Error(), "requires at least 1 CPU and 4096Mi memory") {
				t.Fatalf("minimum validation error = %v", err)
			}
		})
	}
	if err := validateNodeLoadBalancerShape(nodeLoadBalancerDefaultCPU, nodeLoadBalancerDefaultMemoryMiB); err != nil {
		t.Fatalf("default RKE2 shape was rejected: %v", err)
	}
}

func TestPlanNodeLoadBalancerShardsSharesAndAutomaticallySplitsConflicts(t *testing.T) {
	intents := []nodeLoadBalancerIntent{
		nodeLoadBalancerTestIntent("a", corev1.ProtocolTCP, 443),
		nodeLoadBalancerTestIntent("b", corev1.ProtocolUDP, 443),
		nodeLoadBalancerTestIntent("c", corev1.ProtocolTCP, 80),
		nodeLoadBalancerTestIntent("d", corev1.ProtocolTCP, 443),
	}
	first, err := planNodeLoadBalancerShards(intents)
	if err != nil {
		t.Fatal(err)
	}
	shared := first.Assignments["a"]
	if shared == "" || first.Assignments["b"] != shared || first.Assignments["c"] != shared {
		t.Fatalf("non-conflicting assignments = %#v", first.Assignments)
	}
	if first.Assignments["d"] == "" || first.Assignments["d"] == shared || len(first.Shards) != 2 {
		t.Fatalf("conflicting assignment did not create a second shard: %#v; shards=%#v", first.Assignments, first.Shards)
	}

	// Persist both assignments and reverse input order. Stable claims must win
	// before the planner considers any unassigned Service.
	for i := range intents {
		intents[i].ExistingShard = first.Assignments[intents[i].ServiceID]
	}
	for left, right := 0, len(intents)-1; left < right; left, right = left+1, right-1 {
		intents[left], intents[right] = intents[right], intents[left]
	}
	second, err := planNodeLoadBalancerShards(intents)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Assignments, second.Assignments) {
		t.Fatalf("assignments changed after reorder: first=%#v second=%#v", first.Assignments, second.Assignments)
	}
}

func TestPlanNodeLoadBalancerDedicatedServicesNeverShare(t *testing.T) {
	first := nodeLoadBalancerTestIntent("first", corev1.ProtocolTCP, 443)
	second := nodeLoadBalancerTestIntent("second", corev1.ProtocolTCP, 8443)
	first.Mode = nodeLoadBalancerModeDedicated
	second.Mode = nodeLoadBalancerModeDedicated
	plan, err := planNodeLoadBalancerShards([]nodeLoadBalancerIntent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Shards) != 2 || plan.Assignments[first.ServiceID] == plan.Assignments[second.ServiceID] {
		t.Fatalf("dedicated assignments = %#v, shards=%#v", plan.Assignments, plan.Shards)
	}
}

func TestRenderNodeLoadBalancerManifests(t *testing.T) {
	base := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.inspace.cloud/v1alpha1",
		"kind":       "InSpaceNodeClass",
		"metadata": map[string]any{
			"name": "workload", "resourceVersion": "9", "uid": "old-uid",
		},
		"spec": map[string]any{
			"clusterName": "cluster", "rootDiskGiB": int64(100), "reservePublicIPv4": false,
			"sshUsername": "ubuntu", "sshPublicKey": "ssh-ed25519 AAAA", "additionalUserData": "echo unsafe",
		},
		"status": map[string]any{"ready": true},
	}}
	nodeClass, err := renderNodeLoadBalancerNodeClass(base, "inspace-node-lb-class")
	if err != nil {
		t.Fatal(err)
	}
	if nodeClass.GetName() != "inspace-node-lb-class" || nodeClass.GetResourceVersion() != "" || nodeClass.GetUID() != "" {
		t.Fatalf("NodeClass metadata = %#v", nodeClass.Object["metadata"])
	}
	for path, want := range map[string]any{
		"firewallProfile":   nodeLoadBalancerFirewallMode,
		"rootDiskGiB":       int64(30),
		"reservePublicIPv4": true,
	} {
		got, exists, nestedErr := unstructured.NestedFieldNoCopy(nodeClass.Object, "spec", path)
		if nestedErr != nil || !exists || !reflect.DeepEqual(got, want) {
			t.Fatalf("NodeClass spec.%s = %#v, %t, %v; want %#v", path, got, exists, nestedErr, want)
		}
	}
	for _, field := range []string{"sshUsername", "sshPublicKey", "additionalUserData"} {
		if _, exists, _ := unstructured.NestedFieldNoCopy(nodeClass.Object, "spec", field); exists {
			t.Fatalf("NodeClass retained spec.%s", field)
		}
	}
	if _, exists := nodeClass.Object["status"]; exists {
		t.Fatal("NodeClass retained status")
	}

	shard := nodeLoadBalancerShardPlan{Name: "inlb-0123abcd", Mode: nodeLoadBalancerModeShared, Pool: "default", NodesPerShard: 2, CPU: 4, MemoryMiB: 32768}
	nodePool, err := renderNodeLoadBalancerNodePool(shard.Name, nodeClass.GetName(), shard)
	if err != nil {
		t.Fatal(err)
	}
	if replicas, _, _ := unstructured.NestedInt64(nodePool.Object, "spec", "replicas"); replicas != 2 {
		t.Fatalf("NodePool replicas = %d", replicas)
	}
	if nodes, _, _ := unstructured.NestedString(nodePool.Object, "spec", "limits", "nodes"); nodes != "3" {
		t.Fatalf("NodePool limits.nodes = %q", nodes)
	}
	if consolidateAfter, _, _ := unstructured.NestedString(nodePool.Object, "spec", "disruption", "consolidateAfter"); consolidateAfter != "0s" {
		t.Fatalf("NodePool disruption.consolidateAfter = %q", consolidateAfter)
	}
	if policy, _, _ := unstructured.NestedString(nodePool.Object, "spec", "disruption", "consolidationPolicy"); policy != "WhenEmptyOrUnderutilized" {
		t.Fatalf("NodePool disruption.consolidationPolicy = %q", policy)
	}
	budgets, _, _ := unstructured.NestedSlice(nodePool.Object, "spec", "disruption", "budgets")
	if len(budgets) != 1 || budgets[0].(map[string]any)["nodes"] != "10%" {
		t.Fatalf("NodePool disruption.budgets = %#v", budgets)
	}
	if expireAfter, _, _ := unstructured.NestedString(nodePool.Object, "spec", "template", "spec", "expireAfter"); expireAfter != "720h" {
		t.Fatalf("NodePool template.spec.expireAfter = %q", expireAfter)
	}
	labels, _, _ := unstructured.NestedStringMap(nodePool.Object, "spec", "template", "metadata", "labels")
	if labels[nodeLoadBalancerNodeLabel] != "true" || labels[nodeLoadBalancerNodeShardLabel] != shard.Name ||
		labels[nodeLoadBalancerPoolLabel] != shard.Pool || labels[nodeLoadBalancerModeLabel] != shard.Mode {
		t.Fatalf("NodePool labels = %#v", labels)
	}
	taints, _, _ := unstructured.NestedSlice(nodePool.Object, "spec", "template", "spec", "taints")
	if len(taints) != 1 || taints[0].(map[string]any)["key"] != nodeLoadBalancerLabel ||
		taints[0].(map[string]any)["value"] != "true" ||
		taints[0].(map[string]any)["effect"] != string(corev1.TaintEffectNoSchedule) {
		t.Fatalf("NodePool taints = %#v", taints)
	}
	requirements, _, _ := unstructured.NestedSlice(nodePool.Object, "spec", "template", "spec", "requirements")
	wantRequirements := map[string]string{
		"inspace.cloud/instance-cpu":    "4",
		"inspace.cloud/instance-memory": "32768",
		"inspace.cloud/host-class":      "amd-epyc",
		"karpenter.sh/capacity-type":    "on-demand",
		"kubernetes.io/arch":            "amd64",
		"kubernetes.io/os":              "linux",
	}
	for _, raw := range requirements {
		requirement := raw.(map[string]any)
		key := requirement["key"].(string)
		values := requirement["values"].([]any)
		if len(values) != 1 || values[0] != wantRequirements[key] {
			t.Fatalf("NodePool requirement %q = %#v", key, requirement)
		}
		delete(wantRequirements, key)
	}
	if len(wantRequirements) != 0 {
		t.Fatalf("missing NodePool requirements: %#v", wantRequirements)
	}
}

func nodeLoadBalancerTestService(name, uid string, protocol corev1.Protocol, port int32) *corev1.Service {
	class := nodeLoadBalancerClass
	allocateNodePorts := false
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID(uid), Annotations: map[string]string{}},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, LoadBalancerClass: &class,
			AllocateLoadBalancerNodePorts: &allocateNodePorts,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyCluster,
			Selector:                      map[string]string{"app": name},
			Ports:                         []corev1.ServicePort{{Protocol: protocol, Port: port}},
		},
	}
}

func nodeLoadBalancerTestIntent(serviceID string, protocol corev1.Protocol, port int32) nodeLoadBalancerIntent {
	return nodeLoadBalancerIntent{
		ServiceID: serviceID, Mode: nodeLoadBalancerModeShared, Pool: nodeLoadBalancerDefaultPool,
		NodesPerShard: 1, CPU: nodeLoadBalancerDefaultCPU, MemoryMiB: nodeLoadBalancerDefaultMemoryMiB,
		Ports: []nodeLoadBalancerPortClaim{{IPFamily: corev1.IPv4Protocol, Protocol: protocol, Port: port}},
	}
}
