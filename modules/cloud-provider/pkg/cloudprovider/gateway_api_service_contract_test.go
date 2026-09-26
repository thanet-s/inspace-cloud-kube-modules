package cloudprovider

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ciliumGatewayService mirrors the LoadBalancer Service Cilium 1.20 generates
// for a Gateway (operator/pkg/model/translation/gateway-api/translator.go):
// Gateway spec.infrastructure labels and annotations are merged onto it, it is
// controller-owned by the Gateway, it has no selector (Cilium manages a dummy
// EndpointSlice), and its Service fields come from the GatewayClass
// CiliumGatewayClassConfig, which defaults to externalTrafficPolicy Cluster
// and no loadBalancerClass.
func ciliumGatewayService() *corev1.Service {
	controller := true
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "cilium-gateway-web", UID: types.UID("11111111-2222-3333-4444-555555555555"),
			Labels: map[string]string{
				"gateway.networking.k8s.io/gateway-name": "web",
				"io.cilium.gateway/owning-gateway":       "web",
				LabelLoadBalancerScope:                   LoadBalancerScopePublic,
			},
			Annotations: map[string]string{AnnotationPublicLoadBalancer: "true"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "gateway.networking.k8s.io/v1beta1", Kind: "Gateway", Name: "web",
				UID: types.UID("99999999-8888-7777-6666-555555555555"), Controller: &controller,
			}},
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
			IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol},
			Ports: []corev1.ServicePort{
				{Name: "port-80", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: 31080},
				{Name: "port-443", Protocol: corev1.ProtocolTCP, Port: 443, NodePort: 31443},
			},
		},
	}
}

func TestCiliumGatewayServiceSelectsThePaidPublicNLBThroughInfrastructureMarkers(t *testing.T) {
	service := ciliumGatewayService()
	public, err := explicitPublicRequested(service)
	if err != nil || !public {
		t.Fatalf("Gateway infrastructure markers did not request the paid public NLB: public=%t err=%v", public, err)
	}
	if err := validateService(service); err != nil {
		t.Fatalf("paid public NLB rejected a Cilium Gateway Service: %v", err)
	}
	rules := serviceRules(service)
	if len(rules) != 2 || rules[0].SourcePort != 80 || rules[0].TargetPort != 31080 ||
		rules[1].SourcePort != 443 || rules[1].TargetPort != 31443 {
		t.Fatalf("Gateway listener ports did not map to exact NodePort forwarding rules: %+v", rules)
	}

	unmarked := ciliumGatewayService()
	delete(unmarked.Labels, LabelLoadBalancerScope)
	delete(unmarked.Annotations, AnnotationPublicLoadBalancer)
	if public, err := explicitPublicRequested(unmarked); err != nil || public {
		t.Fatalf("a Gateway without infrastructure markers must stay implemented elsewhere: public=%t err=%v", public, err)
	}
}

func TestCiliumGatewayServiceIsRejectedByNodeLoadBalancerModes(t *testing.T) {
	for _, mode := range []string{"", nodeLoadBalancerModeLocal} {
		service := ciliumGatewayService()
		delete(service.Labels, LabelLoadBalancerScope)
		delete(service.Annotations, AnnotationPublicLoadBalancer)
		class := nodeLoadBalancerClass
		allocate := false
		service.Spec.LoadBalancerClass = &class
		service.Spec.AllocateLoadBalancerNodePorts = &allocate
		if mode != "" {
			service.Annotations[annotationNodeLoadBalancerMode] = mode
			service.Annotations[annotationNodeLoadBalancerPool] = "edge"
			service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
		}
		_, err := parseNodeLoadBalancerService(service, nodeLoadBalancerDefaults{NodesPerShard: 1})
		if err == nil || !strings.Contains(err.Error(), "selector is required") {
			t.Fatalf("mode %q: selectorless Gateway Service error=%v, want the fail-closed selector rejection", mode, err)
		}
	}
}
