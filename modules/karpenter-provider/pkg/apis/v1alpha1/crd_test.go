package v1alpha1

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"sigs.k8s.io/yaml"
)

func TestInSpaceNodeClassCRDPassesKubernetesValidation(t *testing.T) {
	data, err := os.ReadFile("../../../config/crd/bases/karpenter.inspace.cloud_inspacenodeclasses.yaml")
	if err != nil {
		t.Fatalf("read CRD: %v", err)
	}
	for _, expected := range []string{
		"- privateLoadBalancerPool",
		"privateLoadBalancerPool:",
		"range must contain 16 to",
		"self.privateLoadBalancerPool == oldSelf.privateLoadBalancerPool",
		"privateLoadBalancerPool is immutable",
		"- rke2",
		"rke2:",
		`\+rke2r[0-9]+$`,
		":9345$",
		"!self.startsWith('https://10.42.')",
		"!self.startsWith('https://10.43.')",
		"inspace-rke2-agent-token",
	} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("RKE2 CRD is missing %q", expected)
		}
	}
	if strings.Contains(strings.ToLower(string(data)), "k3s") {
		t.Fatal("RKE2 CRD retained a K3s schema field")
	}
	chartData, err := os.ReadFile("../../../../../charts/inspace-cloud-kube-modules-crds/templates/karpenter.inspace.cloud_inspacenodeclasses.yaml")
	if err != nil {
		t.Fatalf("read chart CRD: %v", err)
	}
	if !bytes.Equal(data, chartData) {
		t.Error("source and chart InSpaceNodeClass CRDs differ")
	}

	var versioned apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict(data, &versioned); err != nil {
		t.Fatalf("decode CRD: %v", err)
	}
	apiextensionsv1.SetDefaults_CustomResourceDefinition(&versioned)

	var internal apiextensions.CustomResourceDefinition
	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
		&versioned,
		&internal,
		nil,
	); err != nil {
		t.Fatalf("convert CRD: %v", err)
	}
	if errs := apiextensionsvalidation.ValidateCustomResourceDefinition(context.Background(), &internal); len(errs) != 0 {
		t.Fatalf("Kubernetes rejected CRD: %v", errs.ToAggregate())
	}
}
