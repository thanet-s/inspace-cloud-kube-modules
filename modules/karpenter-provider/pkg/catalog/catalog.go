package catalog

import (
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"
	"sigs.k8s.io/karpenter/pkg/scheduling"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

const (
	LabelFamily         = "inspace.cloud/instance-family"
	LabelHostClass      = "inspace.cloud/host-class"
	LabelInstanceCPU    = "inspace.cloud/instance-cpu"
	LabelInstanceMemory = "inspace.cloud/instance-memory"
	LabelLocation       = "inspace.cloud/location"
	RegionThailand      = "thailand"
	DefaultDiskGiB      = int32(40)

	monthlyCPUPriceTHB       = 60.0
	monthlyMemoryGiBPriceTHB = 30.0
	billingHoursPerMonth     = 730.0
)

type Family struct {
	Name             string
	MemoryGiBPerVCPU int
	CoreCounts       []int
}

var CoreCounts = []int{2, 4, 6, 8, 10, 12, 14, 16}

var Families = []Family{
	{Name: "compute", MemoryGiBPerVCPU: 1, CoreCounts: CoreCounts},
	{Name: "general", MemoryGiBPerVCPU: 2, CoreCounts: append([]int{1}, CoreCounts...)},
	{Name: "memory", MemoryGiBPerVCPU: 4, CoreCounts: append([]int{1}, CoreCounts...)},
	{Name: "extra-memory", MemoryGiBPerVCPU: 8, CoreCounts: []int{1, 2, 4, 6, 8}},
}

type Options struct {
	Location    string
	RootDiskGiB int32
}

func init() {
	karpv1.WellKnownLabels.Insert(LabelFamily, LabelHostClass, LabelInstanceCPU, LabelInstanceMemory, LabelLocation)
	karpv1.WellKnownLabelsForOfferings.Insert(LabelHostClass)
}

// New returns the complete, finite 31-variant InSpace catalog. Prices are
// deterministic relative scheduling weights, not a representation of a bill.
func New(opts Options) ([]*cloudprovider.InstanceType, error) {
	if opts.Location == "" {
		opts.Location = inspacev1.LocationBangkok
	}
	if opts.Location != inspacev1.LocationBangkok {
		return nil, fmt.Errorf("unsupported location %q", opts.Location)
	}
	if opts.RootDiskGiB == 0 {
		opts.RootDiskGiB = DefaultDiskGiB
	}
	if opts.RootDiskGiB < 30 || opts.RootDiskGiB > 2000 {
		return nil, fmt.Errorf("root disk must be between 30 and 2000 GiB")
	}

	result := make([]*cloudprovider.InstanceType, 0, 31)
	for _, family := range Families {
		for _, cores := range family.CoreCounts {
			memoryGiB := cores * family.MemoryGiBPerVCPU
			result = append(result, newInstanceType(opts, family.Name, cores, memoryGiB))
		}
	}
	return result, nil
}

func newInstanceType(opts Options, family string, cores, memoryGiB int) *cloudprovider.InstanceType {
	name := fmt.Sprintf("is-%s-%dc-%dg", family, cores, memoryGiB)
	capacity := corev1.ResourceList{
		corev1.ResourceCPU:              *resource.NewQuantity(int64(cores), resource.DecimalSI),
		corev1.ResourceMemory:           resource.MustParse(fmt.Sprintf("%dGi", memoryGiB)),
		corev1.ResourceEphemeralStorage: resource.MustParse(fmt.Sprintf("%dGi", opts.RootDiskGiB)),
		corev1.ResourcePods:             resource.MustParse("110"),
	}
	requirements := scheduling.NewRequirements(
		scheduling.NewRequirement(corev1.LabelInstanceTypeStable, corev1.NodeSelectorOpIn, name),
		scheduling.NewRequirement(corev1.LabelArchStable, corev1.NodeSelectorOpIn, karpv1.ArchitectureAmd64),
		scheduling.NewRequirement(corev1.LabelOSStable, corev1.NodeSelectorOpIn, string(corev1.Linux)),
		scheduling.NewRequirement(corev1.LabelTopologyZone, corev1.NodeSelectorOpIn, opts.Location),
		scheduling.NewRequirement(corev1.LabelTopologyRegion, corev1.NodeSelectorOpIn, RegionThailand),
		scheduling.NewRequirement(karpv1.CapacityTypeLabelKey, corev1.NodeSelectorOpIn, karpv1.CapacityTypeOnDemand),
		scheduling.NewRequirement(LabelFamily, corev1.NodeSelectorOpIn, family),
		scheduling.NewRequirement(LabelInstanceCPU, corev1.NodeSelectorOpIn, strconv.Itoa(cores)),
		// Instance memory follows Karpenter's established provider convention and
		// is an integer MiB value, making Gt/Lt/Gte/Lte comparisons unambiguous.
		scheduling.NewRequirement(LabelInstanceMemory, corev1.NodeSelectorOpIn, strconv.Itoa(memoryGiB*1024)),
		scheduling.NewRequirement(LabelLocation, corev1.NodeSelectorOpIn, opts.Location),
	)
	offerings := make(cloudprovider.Offerings, 0, len(inspacev1.SupportedHostClasses()))
	for _, hostClass := range inspacev1.SupportedHostClasses() {
		offerings = append(offerings, &cloudprovider.Offering{
			Available: true,
			Price:     hourlyComputePriceTHB(cores, memoryGiB),
			Requirements: scheduling.NewRequirements(
				scheduling.NewRequirement(corev1.LabelTopologyZone, corev1.NodeSelectorOpIn, opts.Location),
				scheduling.NewRequirement(karpv1.CapacityTypeLabelKey, corev1.NodeSelectorOpIn, karpv1.CapacityTypeOnDemand),
				scheduling.NewRequirement(LabelHostClass, corev1.NodeSelectorOpIn, hostClass),
			),
		})
	}
	return &cloudprovider.InstanceType{
		Name:         name,
		Requirements: requirements,
		Offerings:    offerings,
		Capacity:     capacity,
		Overhead: &cloudprovider.InstanceTypeOverhead{
			KubeReserved: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			SystemReserved: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("100m"),
				corev1.ResourceMemory:           resource.MustParse("128Mi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("8Gi"),
			},
			EvictionThreshold: corev1.ResourceList{
				corev1.ResourceMemory:           resource.MustParse("100Mi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("4Gi"),
			},
		},
	}
}

func monthlyComputePriceTHB(cores, memoryGiB int) float64 {
	return float64(cores)*monthlyCPUPriceTHB +
		float64(memoryGiB)*monthlyMemoryGiBPriceTHB
}

func hourlyComputePriceTHB(cores, memoryGiB int) float64 {
	return monthlyComputePriceTHB(cores, memoryGiB) / billingHoursPerMonth
}
