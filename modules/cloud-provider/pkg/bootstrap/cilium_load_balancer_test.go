package bootstrap

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

type renderedCiliumLoadBalancerValues struct {
	LoadBalancer *struct {
		Algorithm       *string `json:"algorithm"`
		ServiceTopology *bool   `json:"serviceTopology"`
	} `json:"loadBalancer"`
	Maglev map[string]any `json:"maglev"`
}

func parseRenderedCiliumLoadBalancerValues(t *testing.T, helmChartConfig string) renderedCiliumLoadBalancerValues {
	t.Helper()
	var document struct {
		Spec struct {
			ValuesContent string `json:"valuesContent"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(helmChartConfig), &document); err != nil {
		t.Fatalf("parse rendered HelmChartConfig: %v", err)
	}
	var values renderedCiliumLoadBalancerValues
	if err := yaml.Unmarshal([]byte(document.Spec.ValuesContent), &values); err != nil {
		t.Fatalf("parse rendered Cilium values: %v", err)
	}
	return values
}

// TestRKE2CiliumConfigLoadBalancerOptionsAreAdditive proves each optional
// Cilium load-balancer value adds only its own Helm value lines. The zero
// options render no loadBalancer block, so default cloud-init stays
// byte-identical, and no option overrides Cilium's Maglev table size or
// hash seed defaults.
func TestRKE2CiliumConfigLoadBalancerOptionsAreAdditive(t *testing.T) {
	for _, single := range []bool{false, true} {
		base := renderRKE2CiliumConfig("10.42.0.0/16", 40, single, ciliumLoadBalancerOptions{})
		if values := parseRenderedCiliumLoadBalancerValues(t, base); values.LoadBalancer != nil || values.Maglev != nil {
			t.Fatalf("single=%t: default rendering sets Cilium load-balancer values:\n%s", single, base)
		}
		for _, test := range []struct {
			options   ciliumLoadBalancerOptions
			block     string
			algorithm string
			topology  bool
		}{
			{
				options:   ciliumLoadBalancerOptions{Algorithm: v1alpha1.LoadBalancerAlgorithmRandom},
				block:     "    loadBalancer:\n      algorithm: random\n",
				algorithm: v1alpha1.LoadBalancerAlgorithmRandom,
			},
			{
				options:   ciliumLoadBalancerOptions{Algorithm: v1alpha1.LoadBalancerAlgorithmMaglev},
				block:     "    loadBalancer:\n      algorithm: maglev\n",
				algorithm: v1alpha1.LoadBalancerAlgorithmMaglev,
			},
			{
				options:  ciliumLoadBalancerOptions{ServiceTopology: true},
				block:    "    loadBalancer:\n      serviceTopology: true\n",
				topology: true,
			},
			{
				options:   ciliumLoadBalancerOptions{Algorithm: v1alpha1.LoadBalancerAlgorithmMaglev, ServiceTopology: true},
				block:     "    loadBalancer:\n      algorithm: maglev\n      serviceTopology: true\n",
				algorithm: v1alpha1.LoadBalancerAlgorithmMaglev,
				topology:  true,
			},
		} {
			rendered := renderRKE2CiliumConfig("10.42.0.0/16", 40, single, test.options)
			if strings.Count(rendered, test.block) != 1 || strings.Replace(rendered, test.block, "", 1) != base {
				t.Fatalf("single=%t options=%#v changed more than its own loadBalancer block:\n%s", single, test.options, rendered)
			}
			values := parseRenderedCiliumLoadBalancerValues(t, rendered)
			if values.LoadBalancer == nil || values.Maglev != nil {
				t.Fatalf("single=%t options=%#v parsed as %#v", single, test.options, values)
			}
			gotAlgorithm := ""
			if values.LoadBalancer.Algorithm != nil {
				gotAlgorithm = *values.LoadBalancer.Algorithm
			}
			gotTopology := values.LoadBalancer.ServiceTopology != nil && *values.LoadBalancer.ServiceTopology
			if gotAlgorithm != test.algorithm || gotTopology != test.topology {
				t.Fatalf("single=%t options=%#v parsed algorithm=%q serviceTopology=%t", single, test.options, gotAlgorithm, gotTopology)
			}
		}
	}
}

func TestCloudInitRendersOnlySupportedLoadBalancerAlgorithms(t *testing.T) {
	input := cacheContractControlPlaneInput()
	input.LoadBalancerAlgorithm = v1alpha1.LoadBalancerAlgorithmMaglev
	input.ServiceTopology = true
	raw, err := RenderCloudInitJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	cilium := cacheContractDecodeCloudInit(t, raw)["/var/lib/inspace/rke2-cilium-config"].Content
	if !strings.Contains(cilium, "    loadBalancer:\n      algorithm: maglev\n      serviceTopology: true\n") {
		t.Fatalf("cloud-init lacks the selected Cilium load-balancer values:\n%s", cilium)
	}
	for _, invalid := range []string{"Maglev", "round_robin", "maglev\n    evil: true"} {
		input := cacheContractControlPlaneInput()
		input.LoadBalancerAlgorithm = invalid
		if _, err := RenderCloudInitJSON(input); err == nil {
			t.Errorf("RenderCloudInitJSON accepted unsupported load-balancer algorithm %q", invalid)
		}
	}
}

// TestDefaultCiliumLoadBalancerOptionsKeepCloudInitBytes proves the omitted
// options render byte-identical cloud-init, so the frozen ownership hash
// still covers the default path.
func TestDefaultCiliumLoadBalancerOptionsKeepCloudInitBytes(t *testing.T) {
	withFields := cacheContractControlPlaneInput()
	withFields.LoadBalancerAlgorithm = ""
	withFields.ServiceTopology = false
	got, err := RenderCloudInitJSON(withFields)
	if err != nil {
		t.Fatal(err)
	}
	want, err := RenderCloudInitJSON(cacheContractControlPlaneInput())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("omitted Cilium load-balancer options changed the rendered cloud-init")
	}
	if strings.Contains(cacheContractDecodeCloudInit(t, got)["/var/lib/inspace/rke2-cilium-config"].Content, "loadBalancer:") {
		t.Fatal("default cloud-init renders a Cilium loadBalancer block")
	}
}

func TestReconcilePropagatesCiliumLoadBalancerOptionsToEveryControlPlane(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	cluster.Spec.Network.LoadBalancerAlgorithm = v1alpha1.LoadBalancerAlgorithmMaglev
	cluster.Spec.Network.ServiceTopology = true
	reconciler := testReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		request := mustVMRequest(t, api.vmCreates, controlPlaneName(cluster.Metadata.Name, slot))
		cilium := cacheContractDecodeCloudInit(t, request.CloudInit)["/var/lib/inspace/rke2-cilium-config"].Content
		values := parseRenderedCiliumLoadBalancerValues(t, cilium)
		if values.LoadBalancer == nil || values.LoadBalancer.Algorithm == nil ||
			*values.LoadBalancer.Algorithm != v1alpha1.LoadBalancerAlgorithmMaglev ||
			values.LoadBalancer.ServiceTopology == nil || !*values.LoadBalancer.ServiceTopology {
			t.Fatalf("control plane %d did not receive the selected Cilium load-balancer values:\n%s", slot, cilium)
		}
	}
}
