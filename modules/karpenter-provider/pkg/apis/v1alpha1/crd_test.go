package v1alpha1

import (
	"context"
	"os"
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
