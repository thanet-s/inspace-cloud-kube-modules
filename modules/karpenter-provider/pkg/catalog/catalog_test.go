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

func TestCatalogHasAll31BoundedVariants(t *testing.T) {
	types, err := New(Options{Location: inspacev1.LocationBangkok, RootDiskGiB: 40})
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 31 {
		t.Fatalf("expected 31 instance types, got %d", len(types))
	}

	expected := map[string]bool{}
	for _, family := range Families {
		for _, cores := range family.CoreCounts {
			name := fmt.Sprintf("is-%s-%dc-%dg", family.Name, cores, cores*family.MemoryGiBPerVCPU)
			expected[name] = true
		}
	}
	if len(expected) != 31 {
		t.Fatalf("test catalog definition has %d unique variants, want 31", len(expected))
	}

	seen := map[string]bool{}
	for _, instanceType := range types {
		if seen[instanceType.Name] {
			t.Fatalf("duplicate instance type %q", instanceType.Name)
		}
		seen[instanceType.Name] = true
		if !expected[instanceType.Name] {
			t.Fatalf("catalog contains unexpected instance type %q", instanceType.Name)
		}
		cores := int(instanceType.Capacity.Cpu().Value())
		memoryGiB := int(instanceType.Capacity.Memory().Value() / (1024 * 1024 * 1024))
		if cores < 1 || cores > 16 || (cores > 1 && cores%2 != 0) {
			t.Fatalf("%s has invalid CPU count %d", instanceType.Name, cores)
		}
		if memoryGiB > 64 {
			t.Fatalf("%s exceeds the 64 GiB limit", instanceType.Name)
		}
		if cores == 1 && memoryGiB < 2 {
			t.Fatalf("%s is below the 1-vCPU/2-GiB catalog floor", instanceType.Name)
		}
		family := instanceType.Requirements.Get(LabelFamily).Any()
		ratio := map[string]int{"compute": 1, "general": 2, "memory": 4, "extra-memory": 8}[family]
		if ratio == 0 {
			t.Fatalf("%s has unknown family %q", instanceType.Name, family)
		}
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
		hostPrices := map[string]float64{}
		for _, offering := range instanceType.Offerings {
			hostClass := offering.Requirements.Get(LabelHostClass).Any()
			hostClasses[hostClass] = true
			hostPrices[hostClass] = offering.Price
			if want := hourlyComputePriceTHB(cores, memoryGiB); offering.Price != want {
				t.Fatalf("%s %s hourly price=%v THB, want %v THB", instanceType.Name, hostClass, offering.Price, want)
			}
		}
		for _, hostClass := range inspacev1.SupportedHostClasses() {
			if !hostClasses[hostClass] {
				t.Fatalf("%s is missing %s offering", instanceType.Name, hostClass)
			}
		}
		if hostPrices[inspacev1.HostClassIntelScalable] != hostPrices[inspacev1.HostClassAMDEPYC] {
			t.Fatalf("%s host-class prices differ: Intel=%v AMD=%v", instanceType.Name,
				hostPrices[inspacev1.HostClassIntelScalable], hostPrices[inspacev1.HostClassAMDEPYC])
		}
		if got := instanceType.Allocatable()[corev1.ResourceEphemeralStorage]; got.Cmp(instanceType.Capacity[corev1.ResourceEphemeralStorage]) >= 0 {
			t.Fatalf("%s does not reserve root-disk space for Ubuntu/RKE2", instanceType.Name)
		}
	}

	for _, family := range Families {
		for _, cores := range family.CoreCounts {
			name := fmt.Sprintf("is-%s-%dc-%dg", family.Name, cores, cores*family.MemoryGiBPerVCPU)
			if !seen[name] {
				t.Errorf("catalog is missing %s", name)
			}
		}
	}
}

func TestCSITopologyLocationNormalizesToCatalogLocation(t *testing.T) {
	if got := karpv1.NormalizedLabels[CSITopologyLocationKey]; got != LabelLocation {
		t.Fatalf("CSI topology alias normalizes to %q, want %q", got, LabelLocation)
	}

	types, err := New(Options{Location: inspacev1.LocationBangkok})
	if err != nil {
		t.Fatal(err)
	}
	matching := scheduling.NewRequirements(
		scheduling.NewRequirement(CSITopologyLocationKey, corev1.NodeSelectorOpIn, inspacev1.LocationBangkok),
	)
	if matching.Has(CSITopologyLocationKey) || !matching.Has(LabelLocation) {
		t.Fatalf("CSI topology requirement was not canonicalized: %v", matching)
	}
	for _, instanceType := range types {
		if !matching.IsCompatible(instanceType.Requirements, scheduling.AllowUndefinedWellKnownLabels) {
			t.Fatalf("%s rejects matching CSI topology location", instanceType.Name)
		}
	}

	mismatching := scheduling.NewRequirements(
		scheduling.NewRequirement(CSITopologyLocationKey, corev1.NodeSelectorOpIn, "sin01"),
	)
	for _, instanceType := range types {
		if mismatching.IsCompatible(instanceType.Requirements, scheduling.AllowUndefinedWellKnownLabels) {
			t.Fatalf("%s accepts mismatched CSI topology location", instanceType.Name)
		}
	}
}

func TestCatalogHasOnlySupportedOneCoreAndExtraMemoryShapes(t *testing.T) {
	types, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]*cloudprovider.InstanceType{}
	for _, instanceType := range types {
		byName[instanceType.Name] = append(byName[instanceType.Name], instanceType)
	}

	specialPrices := map[string]float64{
		"is-general-1c-2g":       120,
		"is-memory-1c-4g":        180,
		"is-extra-memory-1c-8g":  300,
		"is-extra-memory-2c-16g": 600,
		"is-extra-memory-4c-32g": 1200,
		"is-extra-memory-6c-48g": 1800,
		"is-extra-memory-8c-64g": 2400,
	}
	for name, monthlyPrice := range specialPrices {
		matches := byName[name]
		if len(matches) != 1 {
			t.Fatalf("%s occurs %d times, want exactly once", name, len(matches))
		}
		instanceType := matches[0]
		if len(instanceType.Offerings) != len(inspacev1.SupportedHostClasses()) {
			t.Fatalf("%s offerings=%d, want %d", name, len(instanceType.Offerings), len(inspacev1.SupportedHostClasses()))
		}
		prices := map[string]float64{}
		for _, offering := range instanceType.Offerings {
			hostClass := offering.Requirements.Get(LabelHostClass).Any()
			prices[hostClass] = offering.Price
			if want := monthlyPrice / billingHoursPerMonth; offering.Price != want {
				t.Fatalf("%s %s hourly price=%v THB, want %v THB", name, hostClass, offering.Price, want)
			}
		}
		if prices[inspacev1.HostClassIntelScalable] != prices[inspacev1.HostClassAMDEPYC] {
			t.Fatalf("%s host-class prices differ: Intel=%v AMD=%v", name,
				prices[inspacev1.HostClassIntelScalable], prices[inspacev1.HostClassAMDEPYC])
		}
	}

	unsupported := []string{
		"is-compute-1c-1g",
		"is-extra-memory-3c-24g",
		"is-extra-memory-5c-40g",
		"is-extra-memory-7c-56g",
		"is-extra-memory-10c-80g",
		"is-extra-memory-12c-96g",
		"is-extra-memory-14c-112g",
		"is-extra-memory-16c-128g",
	}
	for _, name := range unsupported {
		if len(byName[name]) != 0 {
			t.Errorf("catalog unexpectedly contains unsupported %s", name)
		}
	}
}

func TestInSpaceComputePriceFormula(t *testing.T) {
	tests := []struct {
		name            string
		cores           int
		memoryGiB       int
		monthlyPriceTHB float64
	}{
		{name: "1 CPU 2 GiB RAM", cores: 1, memoryGiB: 2, monthlyPriceTHB: 120},
		{name: "1 CPU 4 GiB RAM", cores: 1, memoryGiB: 4, monthlyPriceTHB: 180},
		{name: "1 CPU 8 GiB RAM", cores: 1, memoryGiB: 8, monthlyPriceTHB: 300},
		{name: "2 CPU 4 GiB RAM", cores: 2, memoryGiB: 4, monthlyPriceTHB: 240},
		{name: "2 CPU 8 GiB RAM", cores: 2, memoryGiB: 8, monthlyPriceTHB: 360},
		{name: "6 CPU 8 GiB RAM", cores: 6, memoryGiB: 8, monthlyPriceTHB: 600},
		{name: "10 CPU 26 GiB RAM", cores: 10, memoryGiB: 26, monthlyPriceTHB: 1380},
		{name: "8 CPU 64 GiB RAM", cores: 8, memoryGiB: 64, monthlyPriceTHB: 2400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := monthlyComputePriceTHB(test.cores, test.memoryGiB); got != test.monthlyPriceTHB {
				t.Fatalf("monthly price=%v THB, want %v THB", got, test.monthlyPriceTHB)
			}
			if got, want := hourlyComputePriceTHB(test.cores, test.memoryGiB), test.monthlyPriceTHB/billingHoursPerMonth; got != want {
				t.Fatalf("hourly price=%v THB, want %v THB", got, want)
			}
		})
	}
}

func TestCatalogPriceIgnoresNodeClassRootDisk(t *testing.T) {
	smallDisk, err := New(Options{RootDiskGiB: 30})
	if err != nil {
		t.Fatal(err)
	}
	largeDisk, err := New(Options{RootDiskGiB: 2000})
	if err != nil {
		t.Fatal(err)
	}
	for index := range smallDisk {
		if smallDisk[index].Name != largeDisk[index].Name {
			t.Fatalf("catalog order differs at %d: %s != %s", index, smallDisk[index].Name, largeDisk[index].Name)
		}
		for offeringIndex := range smallDisk[index].Offerings {
			if smallDisk[index].Offerings[offeringIndex].Price != largeDisk[index].Offerings[offeringIndex].Price {
				t.Fatalf("%s price changed with root disk: %v != %v", smallDisk[index].Name,
					smallDisk[index].Offerings[offeringIndex].Price, largeDisk[index].Offerings[offeringIndex].Price)
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
