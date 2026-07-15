package cloudprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	nodeLoadBalancerClass = "inspace.cloud/node"

	annotationNodeLoadBalancerMode          = "service.inspace.cloud/node-lb-mode"
	annotationNodeLoadBalancerPool          = "service.inspace.cloud/node-lb-pool"
	annotationNodeLoadBalancerNodesPerShard = "service.inspace.cloud/node-lb-nodes-per-shard"
	annotationNodeLoadBalancerCPU           = "service.inspace.cloud/node-lb-cpu"
	annotationNodeLoadBalancerMemory        = "service.inspace.cloud/node-lb-memory"
	annotationNodeLoadBalancerShard         = "service.inspace.cloud/node-lb-shard"

	nodeLoadBalancerModeShared    = "public-node-shared"
	nodeLoadBalancerModeDedicated = "public-node-dedicated"
	nodeLoadBalancerDefaultPool   = "default"

	nodeLoadBalancerDefaultCPU       = int32(1)
	nodeLoadBalancerDefaultMemoryMiB = int64(4096)
	nodeLoadBalancerMinimumCPU       = int32(1)
	nodeLoadBalancerMinimumMemoryMiB = int64(4096)

	nodeLoadBalancerLabel      = "inspace.cloud/node-lb"
	nodeLoadBalancerShardLabel = "inspace.cloud/node-lb-shard"
	nodeLoadBalancerPoolLabel  = "inspace.cloud/node-lb-pool"
	nodeLoadBalancerModeLabel  = "inspace.cloud/node-lb-mode"
	// These labels are copied to Nodes and identify controller-authorized public
	// load-balancer capacity. Their namespace is protected by the NodeRestriction
	// admission plugin, so a kubelet cannot opt itself into advertisement.
	nodeLoadBalancerNodeLabel        = "inspace.cloud.node-restriction.kubernetes.io/node-lb"
	nodeLoadBalancerNodeClusterLabel = "inspace.cloud.node-restriction.kubernetes.io/cluster"
	nodeLoadBalancerNodeShardLabel   = "inspace.cloud.node-restriction.kubernetes.io/shard"
	nodeLoadBalancerFirewallMode     = "public-node-load-balancer"
)

type nodeLoadBalancerDefaults struct {
	NodesPerShard int32
}

type nodeLoadBalancerPortClaim struct {
	IPFamily corev1.IPFamily
	Protocol corev1.Protocol
	Port     int32
}

type nodeLoadBalancerIntent struct {
	ServiceID     string
	Namespace     string
	Name          string
	Mode          string
	Pool          string
	NodesPerShard int32
	CPU           int32
	MemoryMiB     int64
	Ports         []nodeLoadBalancerPortClaim
	ExistingShard string
}

type nodeLoadBalancerShardPlan struct {
	Name          string
	Mode          string
	Pool          string
	NodesPerShard int32
	CPU           int32
	MemoryMiB     int64
	Claims        []string
	Ports         []nodeLoadBalancerPortClaim
}

type nodeLoadBalancerPlan struct {
	Assignments map[string]string
	Shards      []nodeLoadBalancerShardPlan
}

type nodeLoadBalancerPortReservations map[string]map[nodeLoadBalancerPortClaim]string

// parseNodeLoadBalancerService validates the user-facing, provider-owned
// Service contract. It intentionally does not mutate the Service or contact
// either Kubernetes or InSpace, so admission and reconciliation can share the
// exact same parser.
func parseNodeLoadBalancerService(service *corev1.Service, defaults nodeLoadBalancerDefaults) (nodeLoadBalancerIntent, error) {
	if service == nil {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: Service is required")
	}
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: Service type must be LoadBalancer")
	}
	if service.Spec.LoadBalancerClass == nil || *service.Spec.LoadBalancerClass != nodeLoadBalancerClass {
		return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: loadBalancerClass must be %q", nodeLoadBalancerClass)
	}
	if service.Spec.ExternalTrafficPolicy != "" && service.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyCluster {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: externalTrafficPolicy must be Cluster")
	}
	if service.Spec.AllocateLoadBalancerNodePorts == nil || *service.Spec.AllocateLoadBalancerNodePorts {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: allocateLoadBalancerNodePorts must be explicitly false")
	}
	if len(service.Spec.Selector) == 0 {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: Service selector is required because CCM does not mirror manually managed EndpointSlices")
	}
	if len(service.Spec.ExternalIPs) != 0 || service.Spec.LoadBalancerIP != "" {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: externalIPs and loadBalancerIP are unsupported")
	}
	if _, err := canonicalNodeLoadBalancerSourceRanges(service.Spec.LoadBalancerSourceRanges); err != nil {
		return nodeLoadBalancerIntent{}, err
	}
	if defaults.NodesPerShard == 0 {
		defaults.NodesPerShard = 1
	}
	if defaults.NodesPerShard < 1 {
		return nodeLoadBalancerIntent{}, errors.New("node load balancer: default nodes per shard must be positive")
	}

	annotations := service.GetAnnotations()
	mode, err := canonicalNodeLoadBalancerMode(strings.TrimSpace(annotations[annotationNodeLoadBalancerMode]))
	if err != nil {
		return nodeLoadBalancerIntent{}, err
	}
	pool := strings.TrimSpace(annotations[annotationNodeLoadBalancerPool])
	if pool == "" {
		pool = nodeLoadBalancerDefaultPool
	}
	if messages := utilvalidation.IsDNS1123Label(pool); len(messages) != 0 {
		return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: pool %q must be a DNS-1123 label: %s", pool, strings.Join(messages, "; "))
	}

	nodesPerShard := defaults.NodesPerShard
	if value, exists := annotations[annotationNodeLoadBalancerNodesPerShard]; exists {
		parsed, parseErr := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
		if parseErr != nil || parsed < 1 || parsed > 10 {
			return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: annotation %s must be an integer between 1 and 10", annotationNodeLoadBalancerNodesPerShard)
		}
		nodesPerShard = int32(parsed)
	}

	cpu := nodeLoadBalancerDefaultCPU
	memoryMiB := nodeLoadBalancerDefaultMemoryMiB
	_, cpuConfigured := annotations[annotationNodeLoadBalancerCPU]
	_, memoryConfigured := annotations[annotationNodeLoadBalancerMemory]
	if mode == nodeLoadBalancerModeShared && (cpuConfigured || memoryConfigured) {
		return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: annotations %s and %s are supported only in dedicated mode", annotationNodeLoadBalancerCPU, annotationNodeLoadBalancerMemory)
	}
	if mode == nodeLoadBalancerModeDedicated {
		if cpuConfigured {
			value := strings.TrimSpace(annotations[annotationNodeLoadBalancerCPU])
			parsed, parseErr := strconv.ParseInt(value, 10, 32)
			if parseErr != nil || parsed < 1 {
				return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: annotation %s must be a positive integer", annotationNodeLoadBalancerCPU)
			}
			cpu = int32(parsed)
		}
		if memoryConfigured {
			memoryMiB, err = parseNodeLoadBalancerMemory(annotations[annotationNodeLoadBalancerMemory])
			if err != nil {
				return nodeLoadBalancerIntent{}, err
			}
		}
	}
	if err := validateNodeLoadBalancerShape(cpu, memoryMiB); err != nil {
		return nodeLoadBalancerIntent{}, err
	}

	ports, err := nodeLoadBalancerPortClaims(service)
	if err != nil {
		return nodeLoadBalancerIntent{}, err
	}
	existingShard := strings.TrimSpace(annotations[annotationNodeLoadBalancerShard])
	if existingShard != "" {
		if messages := utilvalidation.IsDNS1123Label(existingShard); len(messages) != 0 {
			return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: persisted shard %q is invalid: %s", existingShard, strings.Join(messages, "; "))
		}
		if !isManagedNodeLoadBalancerShardName(existingShard) {
			return nodeLoadBalancerIntent{}, fmt.Errorf("node load balancer: persisted shard %q is not a CCM-managed shard name", existingShard)
		}
	}

	serviceID := string(service.UID)
	if serviceID == "" {
		serviceID = service.Namespace + "/" + service.Name
	}
	return nodeLoadBalancerIntent{
		ServiceID: serviceID, Namespace: service.Namespace, Name: service.Name,
		Mode: mode, Pool: pool, NodesPerShard: nodesPerShard, CPU: cpu, MemoryMiB: memoryMiB,
		Ports: ports, ExistingShard: existingShard,
	}, nil
}

func isManagedNodeLoadBalancerShardName(name string) bool {
	var suffix string
	switch {
	case strings.HasPrefix(name, "inlb-"):
		suffix = strings.TrimPrefix(name, "inlb-")
		return len(suffix) == 8 && isLowerHex(suffix)
	default:
		return false
	}
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return value != ""
}

func canonicalNodeLoadBalancerMode(value string) (string, error) {
	switch value {
	case "", "shared", nodeLoadBalancerModeShared:
		return nodeLoadBalancerModeShared, nil
	case "dedicated", nodeLoadBalancerModeDedicated:
		return nodeLoadBalancerModeDedicated, nil
	default:
		return "", fmt.Errorf("node load balancer: annotation %s must be %q or %q", annotationNodeLoadBalancerMode, nodeLoadBalancerModeShared, nodeLoadBalancerModeDedicated)
	}
}

func parseNodeLoadBalancerMemory(value string) (int64, error) {
	quantity, err := resource.ParseQuantity(strings.TrimSpace(value))
	if err != nil || quantity.Sign() <= 0 {
		return 0, fmt.Errorf("node load balancer: annotation %s must be a positive Kubernetes memory quantity", annotationNodeLoadBalancerMemory)
	}
	bytes := quantity.Value()
	const mebibyte = int64(1024 * 1024)
	if bytes%mebibyte != 0 {
		return 0, fmt.Errorf("node load balancer: annotation %s must resolve to a whole number of MiB", annotationNodeLoadBalancerMemory)
	}
	return bytes / mebibyte, nil
}

// validateNodeLoadBalancerShape enforces the NodeLB memory floor before
// mirroring the finite InSpace Karpenter catalog. Keeping the accepted set
// finite prevents a Service from creating a permanently unschedulable static
// NodePool.
func validateNodeLoadBalancerShape(cpu int32, memoryMiB int64) error {
	if cpu < nodeLoadBalancerMinimumCPU || memoryMiB < nodeLoadBalancerMinimumMemoryMiB {
		return fmt.Errorf(
			"node load balancer: requires at least %d CPU and %dMi memory; got %d CPU and %dMi memory",
			nodeLoadBalancerMinimumCPU,
			nodeLoadBalancerMinimumMemoryMiB,
			cpu,
			memoryMiB,
		)
	}
	valid := false
	if memoryMiB%1024 == 0 {
		memoryGiB := memoryMiB / 1024
		isEvenCatalogCPU := cpu >= 2 && cpu <= 16 && cpu%2 == 0
		switch {
		case isEvenCatalogCPU && memoryGiB == int64(cpu): // compute
			valid = true
		case (cpu == 1 || isEvenCatalogCPU) && memoryGiB == int64(cpu)*2: // general
			valid = true
		case (cpu == 1 || isEvenCatalogCPU) && memoryGiB == int64(cpu)*4: // memory
			valid = true
		case (cpu == 1 || cpu == 2 || cpu == 4 || cpu == 6 || cpu == 8) && memoryGiB == int64(cpu)*8: // extra-memory
			valid = true
		}
	}
	if !valid {
		return fmt.Errorf("node load balancer: %d CPU and %dMi memory is not an InSpace catalog shape", cpu, memoryMiB)
	}
	return nil
}

func nodeLoadBalancerPortClaims(service *corev1.Service) ([]nodeLoadBalancerPortClaim, error) {
	if len(service.Spec.Ports) == 0 {
		return nil, errors.New("node load balancer: Service must expose at least one port")
	}
	if len(service.Spec.IPFamilies) > 1 || (len(service.Spec.IPFamilies) == 1 && service.Spec.IPFamilies[0] != corev1.IPv4Protocol) {
		return nil, errors.New("node load balancer: only single-stack IPv4 Services are supported")
	}
	if service.Spec.IPFamilyPolicy != nil && *service.Spec.IPFamilyPolicy != corev1.IPFamilyPolicySingleStack {
		return nil, errors.New("node load balancer: ipFamilyPolicy must be SingleStack")
	}
	claims := make([]nodeLoadBalancerPortClaim, 0, len(service.Spec.Ports))
	seen := make(map[nodeLoadBalancerPortClaim]struct{}, len(service.Spec.Ports))
	for _, servicePort := range service.Spec.Ports {
		if servicePort.NodePort != 0 {
			return nil, fmt.Errorf("node load balancer: nodePort must be zero when allocateLoadBalancerNodePorts is false")
		}
		protocol := servicePort.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		if protocol != corev1.ProtocolTCP && protocol != corev1.ProtocolUDP {
			return nil, fmt.Errorf("node load balancer: protocol %s on port %d is unsupported; use TCP or UDP", protocol, servicePort.Port)
		}
		if servicePort.Port < 1 || servicePort.Port > 65535 {
			return nil, fmt.Errorf("node load balancer: port %d must be between 1 and 65535", servicePort.Port)
		}
		claim := nodeLoadBalancerPortClaim{IPFamily: corev1.IPv4Protocol, Protocol: protocol, Port: servicePort.Port}
		if _, exists := seen[claim]; exists {
			return nil, fmt.Errorf("node load balancer: duplicate %s/%d port claim", protocol, servicePort.Port)
		}
		seen[claim] = struct{}{}
		claims = append(claims, claim)
	}
	sortNodeLoadBalancerPorts(claims)
	return claims, nil
}

type mutableNodeLoadBalancerShard struct {
	plan  nodeLoadBalancerShardPlan
	ports map[nodeLoadBalancerPortClaim]string
}

// planNodeLoadBalancerShards preserves valid persisted assignments first, then
// best-fits unassigned shared Services into the fullest compatible shard. A
// collision allocates a new shard instead of rejecting the Service.
func planNodeLoadBalancerShards(intents []nodeLoadBalancerIntent) (nodeLoadBalancerPlan, error) {
	return planNodeLoadBalancerShardsWithReservations(intents, nil)
}

func planNodeLoadBalancerShardsWithReservations(
	intents []nodeLoadBalancerIntent,
	reservations nodeLoadBalancerPortReservations,
) (nodeLoadBalancerPlan, error) {
	ordered := append([]nodeLoadBalancerIntent(nil), intents...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ServiceID < ordered[j].ServiceID })
	seenServices := make(map[string]struct{}, len(ordered))
	for _, intent := range ordered {
		if intent.ServiceID == "" {
			return nodeLoadBalancerPlan{}, errors.New("node load balancer: Service identity is required")
		}
		if _, duplicate := seenServices[intent.ServiceID]; duplicate {
			return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: duplicate Service identity %q", intent.ServiceID)
		}
		seenServices[intent.ServiceID] = struct{}{}
		if intent.NodesPerShard < 1 {
			return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: Service %q has non-positive nodes per shard", intent.ServiceID)
		}
		if err := validateNodeLoadBalancerShape(intent.CPU, intent.MemoryMiB); err != nil {
			return nodeLoadBalancerPlan{}, fmt.Errorf("Service %q: %w", intent.ServiceID, err)
		}
		if intent.Mode != nodeLoadBalancerModeShared && intent.Mode != nodeLoadBalancerModeDedicated {
			return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: Service %q has invalid mode %q", intent.ServiceID, intent.Mode)
		}
	}

	assignments := make(map[string]string, len(ordered))
	shards := make(map[string]*mutableNodeLoadBalancerShard)
	pending := make([]nodeLoadBalancerIntent, 0, len(ordered))

	// Persisted assignments have priority over new claims, so a newly created
	// Service cannot steal a port from a stable shard during reconciliation.
	for _, intent := range ordered {
		if intent.ExistingShard == "" || !tryAssignNodeLoadBalancerShard(shards, reservations, intent.ExistingShard, intent) {
			pending = append(pending, intent)
			continue
		}
		assignments[intent.ServiceID] = intent.ExistingShard
	}

	for _, intent := range pending {
		if intent.Mode == nodeLoadBalancerModeDedicated {
			name := uniqueNodeLoadBalancerShardName(shards, reservations, "inlb-", "dedicated/"+intent.ServiceID)
			if !tryAssignNodeLoadBalancerShard(shards, reservations, name, intent) {
				return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: failed to allocate dedicated shard for %q", intent.ServiceID)
			}
			assignments[intent.ServiceID] = name
			continue
		}

		candidates := compatibleNodeLoadBalancerShards(shards, reservations, intent)
		if len(candidates) != 0 {
			name := candidates[0].plan.Name
			if !tryAssignNodeLoadBalancerShard(shards, reservations, name, intent) {
				return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: compatible shard %q rejected Service %q", name, intent.ServiceID)
			}
			assignments[intent.ServiceID] = name
			continue
		}
		name := uniqueNodeLoadBalancerShardName(shards, reservations, "inlb-", "shared/"+intent.Pool+"/"+intent.ServiceID)
		if !tryAssignNodeLoadBalancerShard(shards, reservations, name, intent) {
			return nodeLoadBalancerPlan{}, fmt.Errorf("node load balancer: failed to allocate shared shard for %q", intent.ServiceID)
		}
		assignments[intent.ServiceID] = name
	}

	result := nodeLoadBalancerPlan{Assignments: assignments, Shards: make([]nodeLoadBalancerShardPlan, 0, len(shards))}
	for _, shard := range shards {
		sort.Strings(shard.plan.Claims)
		shard.plan.Ports = make([]nodeLoadBalancerPortClaim, 0, len(shard.ports))
		for port := range shard.ports {
			shard.plan.Ports = append(shard.plan.Ports, port)
		}
		sortNodeLoadBalancerPorts(shard.plan.Ports)
		result.Shards = append(result.Shards, shard.plan)
	}
	sort.Slice(result.Shards, func(i, j int) bool { return result.Shards[i].Name < result.Shards[j].Name })
	return result, nil
}

func tryAssignNodeLoadBalancerShard(
	shards map[string]*mutableNodeLoadBalancerShard,
	reservations nodeLoadBalancerPortReservations,
	name string,
	intent nodeLoadBalancerIntent,
) bool {
	shard, exists := shards[name]
	if !exists {
		shard = &mutableNodeLoadBalancerShard{
			plan: nodeLoadBalancerShardPlan{
				Name: name, Mode: intent.Mode, Pool: intent.Pool, NodesPerShard: intent.NodesPerShard,
				CPU: intent.CPU, MemoryMiB: intent.MemoryMiB,
			},
			ports: make(map[nodeLoadBalancerPortClaim]string),
		}
		shards[name] = shard
	}
	if !nodeLoadBalancerShardProfileMatches(shard.plan, intent) {
		if !exists {
			delete(shards, name)
		}
		return false
	}
	if intent.Mode == nodeLoadBalancerModeDedicated && len(shard.plan.Claims) != 0 {
		return false
	}
	for _, port := range intent.Ports {
		if owner, reserved := reservations[name][port]; reserved && owner != intent.ServiceID {
			return false
		}
		if owner, conflict := shard.ports[port]; conflict && owner != intent.ServiceID {
			return false
		}
	}
	for _, port := range intent.Ports {
		shard.ports[port] = intent.ServiceID
	}
	shard.plan.Claims = append(shard.plan.Claims, intent.ServiceID)
	return true
}

func nodeLoadBalancerShardProfileMatches(shard nodeLoadBalancerShardPlan, intent nodeLoadBalancerIntent) bool {
	return shard.Mode == intent.Mode && shard.Pool == intent.Pool && shard.NodesPerShard == intent.NodesPerShard &&
		shard.CPU == intent.CPU && shard.MemoryMiB == intent.MemoryMiB
}

func nodeLoadBalancerIntentProfileHash(intent nodeLoadBalancerIntent) string {
	return nodeLoadBalancerProfileHash(intent.Mode, intent.Pool, intent.NodesPerShard, intent.CPU, intent.MemoryMiB)
}

func nodeLoadBalancerShardProfileHash(shard nodeLoadBalancerShardPlan) string {
	return nodeLoadBalancerProfileHash(shard.Mode, shard.Pool, shard.NodesPerShard, shard.CPU, shard.MemoryMiB)
}

func nodeLoadBalancerProfileHash(mode, pool string, nodesPerShard, cpu int32, memoryMiB int64) string {
	return nodeLoadBalancerHash(strings.Join([]string{
		mode,
		pool,
		strconv.FormatInt(int64(nodesPerShard), 10),
		strconv.FormatInt(int64(cpu), 10),
		strconv.FormatInt(memoryMiB, 10),
	}, "\x00"))[:8]
}

func compatibleNodeLoadBalancerShards(
	shards map[string]*mutableNodeLoadBalancerShard,
	reservations nodeLoadBalancerPortReservations,
	intent nodeLoadBalancerIntent,
) []*mutableNodeLoadBalancerShard {
	result := make([]*mutableNodeLoadBalancerShard, 0, len(shards))
	for _, shard := range shards {
		if shard.plan.Mode != nodeLoadBalancerModeShared || !nodeLoadBalancerShardProfileMatches(shard.plan, intent) {
			continue
		}
		compatible := true
		for _, port := range intent.Ports {
			if owner, reserved := reservations[shard.plan.Name][port]; reserved && owner != intent.ServiceID {
				compatible = false
				break
			}
			if _, conflict := shard.ports[port]; conflict {
				compatible = false
				break
			}
		}
		if compatible {
			result = append(result, shard)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if len(result[i].ports) != len(result[j].ports) {
			return len(result[i].ports) > len(result[j].ports)
		}
		return result[i].plan.Name < result[j].plan.Name
	})
	return result
}

func uniqueNodeLoadBalancerShardName(
	shards map[string]*mutableNodeLoadBalancerShard,
	reservations nodeLoadBalancerPortReservations,
	prefix, seed string,
) string {
	for attempt := 0; ; attempt++ {
		candidateSeed := seed
		if attempt != 0 {
			candidateSeed += "#" + strconv.Itoa(attempt)
		}
		name := prefix + nodeLoadBalancerHash(candidateSeed)[:8]
		_, shardExists := shards[name]
		_, reserved := reservations[name]
		if !shardExists && !reserved {
			return name
		}
	}
}

func nodeLoadBalancerHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sortNodeLoadBalancerPorts(ports []nodeLoadBalancerPortClaim) {
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].IPFamily != ports[j].IPFamily {
			return ports[i].IPFamily < ports[j].IPFamily
		}
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		return ports[i].Port < ports[j].Port
	})
}

// renderNodeLoadBalancerNodeClass clones the cluster's established NodeClass
// contract while stripping every operator-access/user-data escape hatch. The
// private base firewall remains in the clone; CCM attaches each additional
// public Service firewall only after the worker is healthy.
func renderNodeLoadBalancerNodeClass(base *unstructured.Unstructured, name string) (*unstructured.Unstructured, error) {
	if base == nil {
		return nil, errors.New("node load balancer: base InSpaceNodeClass is required")
	}
	if messages := utilvalidation.IsDNS1123Subdomain(name); len(messages) != 0 {
		return nil, fmt.Errorf("node load balancer: NodeClass name %q is invalid: %s", name, strings.Join(messages, "; "))
	}
	result := base.DeepCopy()
	result.SetName(name)
	result.SetNamespace("")
	result.SetUID("")
	result.SetResourceVersion("")
	result.SetGeneration(0)
	result.SetCreationTimestamp(metav1.Time{})
	result.SetManagedFields(nil)
	result.SetFinalizers(nil)
	result.SetOwnerReferences(nil)
	result.SetAnnotations(nil)
	result.SetLabels(nil)
	unstructured.RemoveNestedField(result.Object, "status")
	if err := unstructured.SetNestedField(result.Object, nodeLoadBalancerFirewallMode, "spec", "firewallProfile"); err != nil {
		return nil, err
	}
	if err := unstructured.SetNestedField(result.Object, int64(30), "spec", "rootDiskGiB"); err != nil {
		return nil, err
	}
	if err := unstructured.SetNestedField(result.Object, true, "spec", "reservePublicIPv4"); err != nil {
		return nil, err
	}
	for _, field := range []string{"sshUsername", "sshPublicKey", "additionalUserData"} {
		unstructured.RemoveNestedField(result.Object, "spec", field)
	}
	return result, nil
}

func renderNodeLoadBalancerNodePool(name, nodeClassName string, shard nodeLoadBalancerShardPlan) (*unstructured.Unstructured, error) {
	if err := validateNodeLoadBalancerShape(shard.CPU, shard.MemoryMiB); err != nil {
		return nil, err
	}
	return renderNodeLoadBalancerNodePoolManifest(name, nodeClassName, shard)
}

func renderNodeLoadBalancerNodePoolManifest(name, nodeClassName string, shard nodeLoadBalancerShardPlan) (*unstructured.Unstructured, error) {
	for field, value := range map[string]string{"NodePool name": name, "NodeClass name": nodeClassName, "shard name": shard.Name} {
		if messages := utilvalidation.IsDNS1123Subdomain(value); len(messages) != 0 {
			return nil, fmt.Errorf("node load balancer: %s %q is invalid: %s", field, value, strings.Join(messages, "; "))
		}
	}
	if shard.NodesPerShard < 1 {
		return nil, errors.New("node load balancer: NodePool replicas must be positive")
	}
	requirements := []any{
		nodeLoadBalancerRequirement("inspace.cloud/instance-cpu", strconv.FormatInt(int64(shard.CPU), 10)),
		nodeLoadBalancerRequirement("inspace.cloud/instance-memory", strconv.FormatInt(shard.MemoryMiB, 10)),
		nodeLoadBalancerRequirement("inspace.cloud/host-class", "amd-epyc"),
		nodeLoadBalancerRequirement("karpenter.sh/capacity-type", "on-demand"),
		nodeLoadBalancerRequirement("kubernetes.io/arch", "amd64"),
		nodeLoadBalancerRequirement("kubernetes.io/os", "linux"),
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1",
		"kind":       "NodePool",
		"metadata": map[string]any{
			"name": name,
			"labels": map[string]any{
				nodeLoadBalancerLabel:      "true",
				nodeLoadBalancerShardLabel: shard.Name,
				nodeLoadBalancerPoolLabel:  shard.Pool,
				nodeLoadBalancerModeLabel:  shard.Mode,
			},
		},
		"spec": map[string]any{
			"replicas": int64(shard.NodesPerShard),
			// Static NodePool drift replacement reserves one surge NodeClaim
			// before deleting the old node. Keep the steady-state replica count
			// exact while allowing that bounded replacement to converge.
			"limits": map[string]any{"nodes": strconv.FormatInt(int64(shard.NodesPerShard+1), 10)},
			// Render the Karpenter CRD defaults explicitly. The API server writes
			// these fields on create, so omitting them here would make the generic
			// desired-state comparison issue an UPDATE on every reconciliation.
			"disruption": map[string]any{
				"consolidateAfter":    "0s",
				"consolidationPolicy": "WhenEmptyOrUnderutilized",
				"budgets": []any{map[string]any{
					"nodes": "10%",
				}},
			},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{
					nodeLoadBalancerNodeLabel:      "true",
					nodeLoadBalancerNodeShardLabel: shard.Name,
					nodeLoadBalancerPoolLabel:      shard.Pool,
					nodeLoadBalancerModeLabel:      shard.Mode,
				}},
				"spec": map[string]any{
					"expireAfter": "720h",
					"nodeClassRef": map[string]any{
						"group": "karpenter.inspace.cloud", "kind": "InSpaceNodeClass", "name": nodeClassName,
					},
					"requirements": requirements,
					"taints": []any{map[string]any{
						"key": nodeLoadBalancerLabel, "value": "true", "effect": string(corev1.TaintEffectNoSchedule),
					}},
				},
			},
		},
	}}, nil
}

func nodeLoadBalancerRequirement(key, value string) map[string]any {
	return map[string]any{"key": key, "operator": string(corev1.NodeSelectorOpIn), "values": []any{value}}
}
