package v1alpha1

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"sigs.k8s.io/yaml"
)

func TestInSpaceNodeClassCRDMatchesContract(t *testing.T) {
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
		"- bootstrapCache",
		"bootstrapCache:",
		"directDownload",
		"address",
		"caBundle",
		"- rke2",
		"rke2:",
		"skipOSUpgrade:",
		"Omitted or false performs the production OS package",
		`\+rke2r[0-9]+$`,
		":9345$",
		"!self.startsWith('https://10.42.')",
		"!self.startsWith('https://10.43.')",
		"inspace-rke2-agent-token",
		"hostPoolUUIDs:",
	} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("RKE2 CRD is missing %q", expected)
		}
	}
	if strings.Contains(strings.ToLower(string(data)), "k3s") {
		t.Fatal("RKE2 CRD retained a K3s schema field")
	}
	if strings.Contains(string(data), "hostPoolSelector") || strings.Contains(string(data), "hostPoolUUID:") {
		t.Fatal("NodeClass CRD still locks one host class instead of reporting both validated pools")
	}
	chartData, err := os.ReadFile("../../../../../charts/inspace-cloud-kube-modules-crds/templates/karpenter.inspace.cloud_inspacenodeclasses.yaml")
	if err != nil {
		t.Fatalf("read chart CRD: %v", err)
	}
	if !bytes.Equal(data, chartData) {
		t.Error("source and chart InSpaceNodeClass CRDs differ")
	}
	assertValidKubernetesCRD(t, data)
}

func TestAllCRDsPassKubernetesValidationWithoutQuadraticUniqueItems(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"../../../../*/config/crd/bases/*.yaml",
		"../../../../../charts/inspace-cloud-kube-modules-crds/templates/*.yaml",
	}
	var paths []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob CRDs using %q: %v", pattern, err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		t.Fatal("no CRDs found")
	}

	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read CRD: %v", err)
			}
			assertValidKubernetesCRD(t, data)
		})
	}
}

func assertValidKubernetesCRD(t *testing.T, data []byte) {
	t.Helper()

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
	if internal.Spec.Validation != nil && internal.Spec.Validation.OpenAPIV3Schema != nil {
		assertNoQuadraticUniqueItems(t, "spec.validation.openAPIV3Schema", internal.Spec.Validation.OpenAPIV3Schema)
	}
	for _, version := range internal.Spec.Versions {
		if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}
		assertNoQuadraticUniqueItems(t, "spec.versions["+version.Name+"].schema.openAPIV3Schema", version.Schema.OpenAPIV3Schema)
	}
}

func assertNoQuadraticUniqueItems(t *testing.T, path string, schema *apiextensions.JSONSchemaProps) {
	t.Helper()
	if schema == nil {
		return
	}
	if schema.UniqueItems {
		t.Errorf("%s sets forbidden uniqueItems: true; use Kubernetes list topology instead", path)
	}
	for name, property := range schema.Properties {
		property := property
		assertNoQuadraticUniqueItems(t, path+".properties["+name+"]", &property)
	}
	for name, property := range schema.PatternProperties {
		property := property
		assertNoQuadraticUniqueItems(t, path+".patternProperties["+name+"]", &property)
	}
	for name, definition := range schema.Definitions {
		definition := definition
		assertNoQuadraticUniqueItems(t, path+".definitions["+name+"]", &definition)
	}
	if schema.Items != nil {
		assertNoQuadraticUniqueItems(t, path+".items", schema.Items.Schema)
		for i := range schema.Items.JSONSchemas {
			assertNoQuadraticUniqueItems(t, path+".items[]", &schema.Items.JSONSchemas[i])
		}
	}
	if schema.AdditionalProperties != nil {
		assertNoQuadraticUniqueItems(t, path+".additionalProperties", schema.AdditionalProperties.Schema)
	}
	if schema.AdditionalItems != nil {
		assertNoQuadraticUniqueItems(t, path+".additionalItems", schema.AdditionalItems.Schema)
	}
	for i := range schema.AllOf {
		assertNoQuadraticUniqueItems(t, path+".allOf[]", &schema.AllOf[i])
	}
	for i := range schema.OneOf {
		assertNoQuadraticUniqueItems(t, path+".oneOf[]", &schema.OneOf[i])
	}
	for i := range schema.AnyOf {
		assertNoQuadraticUniqueItems(t, path+".anyOf[]", &schema.AnyOf[i])
	}
	assertNoQuadraticUniqueItems(t, path+".not", schema.Not)
	for name, dependency := range schema.Dependencies {
		assertNoQuadraticUniqueItems(t, path+".dependencies["+name+"]", dependency.Schema)
	}
}
