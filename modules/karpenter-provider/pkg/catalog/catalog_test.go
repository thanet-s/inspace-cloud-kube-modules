package catalog

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

func TestCatalogHasAll24BoundedVariants(t *testing.T) {
	types, err := New(Options{Location: inspacev1.LocationBangkok, HostClass: inspacev1.HostClassIntelScalable, RootDiskGiB: 40})
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 24 {
		t.Fatalf("expected 24 instance types, got %d", len(types))
	}

	seen := map[string]bool{}
	for _, instanceType := range types {
		if seen[instanceType.Name] {
			t.Fatalf("duplicate instance type %q", instanceType.Name)
		}
		seen[instanceType.Name] = true
		cores := int(instanceType.Capacity.Cpu().Value())
		memoryGiB := int(instanceType.Capacity.Memory().Value() / (1024 * 1024 * 1024))
		if cores < 2 || cores > 16 || cores%2 != 0 {
			t.Fatalf("%s has invalid CPU count %d", instanceType.Name, cores)
		}
		if memoryGiB > 64 {
			t.Fatalf("%s exceeds the 64 GiB limit", instanceType.Name)
		}
		family := instanceType.Requirements.Get(LabelFamily).Any()
		ratio := map[string]int{"compute": 1, "general": 2, "memory": 4}[family]
		if memoryGiB != cores*ratio {
			t.Fatalf("%s has %d GiB, expected %d", instanceType.Name, memoryGiB, cores*ratio)
		}
		if instanceType.Requirements.Get(corev1.LabelArchStable).Any() != karpv1.ArchitectureAmd64 {
			t.Fatalf("%s is not amd64", instanceType.Name)
		}
		if instanceType.Requirements.Get(karpv1.CapacityTypeLabelKey).Any() != karpv1.CapacityTypeOnDemand {
			t.Fatalf("%s is not on-demand", instanceType.Name)
		}
		if got := instanceType.Allocatable()[corev1.ResourceEphemeralStorage]; got.Cmp(instanceType.Capacity[corev1.ResourceEphemeralStorage]) >= 0 {
			t.Fatalf("%s does not reserve root-disk space for Ubuntu/RKE2", instanceType.Name)
		}
	}

	for _, family := range Families {
		for _, cores := range CoreCounts {
			name := fmt.Sprintf("is-%s-%dc-%dg", family.Name, cores, cores*family.MemoryGiBPerVCPU)
			if !seen[name] {
				t.Errorf("catalog is missing %s", name)
			}
		}
	}
}

func TestCatalogSelectsHostClass(t *testing.T) {
	types, err := New(Options{HostClass: inspacev1.HostClassAMDEPYC})
	if err != nil {
		t.Fatal(err)
	}
	for _, instanceType := range types {
		if actual := instanceType.Requirements.Get(LabelHostClass).Any(); actual != inspacev1.HostClassAMDEPYC {
			t.Fatalf("%s has host class %q", instanceType.Name, actual)
		}
	}
}
