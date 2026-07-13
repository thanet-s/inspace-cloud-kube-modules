package catalog

import (
	"fmt"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"
	"sigs.k8s.io/karpenter/pkg/scheduling"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

func TestCatalogHasAll24BoundedVariants(t *testing.T) {
	types, err := New(Options{Location: inspacev1.LocationBangkok, RootDiskGiB: 40})
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
		if got := instanceType.Requirements.Get(LabelInstanceCPU).Any(); got != strconv.Itoa(cores) {
			t.Fatalf("%s instance-cpu=%q, want %d", instanceType.Name, got, cores)
		}
		if got := instanceType.Requirements.Get(LabelInstanceMemory).Any(); got != strconv.Itoa(memoryGiB*1024) {
			t.Fatalf("%s instance-memory=%q MiB, want %d", instanceType.Name, got, memoryGiB*1024)
		}
		if len(instanceType.Offerings) != 2 {
			t.Fatalf("%s has %d host-class offerings, want 2", instanceType.Name, len(instanceType.Offerings))
		}
		hostClasses := map[string]bool{}
		for _, offering := range instanceType.Offerings {
			hostClasses[offering.Requirements.Get(LabelHostClass).Any()] = true
		}
		for _, hostClass := range inspacev1.SupportedHostClasses() {
			if !hostClasses[hostClass] {
				t.Fatalf("%s is missing %s offering", instanceType.Name, hostClass)
			}
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

func TestNumericRequirementsSupportExclusiveAndInclusiveBounds(t *testing.T) {
	types, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	var target *cloudprovider.InstanceType
	for _, instanceType := range types {
		if instanceType.Name == "is-general-4c-8g" {
			target = instanceType
			break
		}
	}
	if target == nil {
		t.Fatal("catalog is missing is-general-4c-8g")
	}

	tests := []struct {
		name     string
		key      string
		operator corev1.NodeSelectorOperator
		value    string
		want     bool
	}{
		{name: "cpu greater than", key: LabelInstanceCPU, operator: corev1.NodeSelectorOpGt, value: "2", want: true},
		{name: "cpu less than", key: LabelInstanceCPU, operator: corev1.NodeSelectorOpLt, value: "4", want: false},
		{name: "cpu greater than or equal", key: LabelInstanceCPU, operator: karpv1.NodeSelectorOpGte, value: "4", want: true},
		{name: "cpu less than or equal", key: LabelInstanceCPU, operator: karpv1.NodeSelectorOpLte, value: "4", want: true},
		{name: "memory greater than", key: LabelInstanceMemory, operator: corev1.NodeSelectorOpGt, value: "4096", want: true},
		{name: "memory less than", key: LabelInstanceMemory, operator: corev1.NodeSelectorOpLt, value: "8192", want: false},
		{name: "memory greater than or equal", key: LabelInstanceMemory, operator: karpv1.NodeSelectorOpGte, value: "8192", want: true},
		{name: "memory less than or equal", key: LabelInstanceMemory, operator: karpv1.NodeSelectorOpLte, value: "8192", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requirements := scheduling.NewRequirements(scheduling.NewRequirement(test.key, test.operator, test.value))
			if got := requirements.IsCompatible(target.Requirements, scheduling.AllowUndefinedWellKnownLabels); got != test.want {
				t.Fatalf("compatibility=%t, want %t for %s %s %s", got, test.want, test.key, test.operator, test.value)
			}
		})
	}
}
