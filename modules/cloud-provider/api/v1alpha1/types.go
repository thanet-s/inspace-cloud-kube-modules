// Package v1alpha1 defines the spec-first InSpaceCluster API. The controller
// integration and generated Kubernetes runtime methods are intentionally left
// for the next increment; these structures mirror the CRD wire schema.
package v1alpha1

import (
	"fmt"
	"net/netip"
	"regexp"
)

const (
	Group      = "infrastructure.inspace.cloud"
	Version    = "v1alpha1"
	Kind       = "InSpaceCluster"
	APIVersion = Group + "/" + Version

	PrivateLoadBalancerPoolMinAddresses = 16
	PrivateLoadBalancerPoolMaxAddresses = 256
	CiliumNativeRoutingPodCIDR          = "10.42.0.0/16"
	KubernetesServiceCIDR               = "10.43.0.0/16"
)

var (
	locationPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	clusterNamePrefix  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?$`)
	uuidPattern        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rke2VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$`)
)

type InSpaceCluster struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   ObjectMeta           `json:"metadata"`
	Spec       InSpaceClusterSpec   `json:"spec"`
	Status     InSpaceClusterStatus `json:"status,omitempty"`
}

type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type InSpaceClusterSpec struct {
	Location             string               `json:"location"`
	BillingAccountID     int64                `json:"billingAccountID,omitempty"`
	CredentialsSecretRef SecretKeyReference   `json:"credentialsSecretRef"`
	ControlPlane         ControlPlaneSpec     `json:"controlPlane"`
	BootstrapCache       BootstrapCacheSpec   `json:"bootstrapCache"`
	RKE2                 RKE2Spec             `json:"rke2"`
	Network              NetworkSpec          `json:"network"`
	Firewall             FirewallSpec         `json:"firewall"`
	PublicIPv4           PublicIPv4Spec       `json:"publicIPv4"`
	Endpoint             ControlPlaneEndpoint `json:"endpoint"`
}

type SecretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ControlPlaneSpec struct {
	Replicas int32       `json:"replicas"`
	Machine  MachineSpec `json:"machine"`
}

type MachineSpec struct {
	VCPU         int32     `json:"vcpu"`
	MemoryMiB    int32     `json:"memoryMiB"`
	RootDiskGiB  int32     `json:"rootDiskGiB"`
	HostPoolUUID string    `json:"hostPoolUUID"`
	Image        ImageSpec `json:"image"`
}

type ImageSpec struct {
	OSName    string `json:"osName"`
	OSVersion string `json:"osVersion"`
}

// BootstrapCacheSpec selects the default bastion cache or explicitly opts a
// cluster into direct guest downloads.
type BootstrapCacheSpec struct {
	DirectDownload bool `json:"directDownload,omitempty"`
}

type RKE2Spec struct {
	Version        string             `json:"version"`
	TokenSecretRef SecretKeyReference `json:"tokenSecretRef"`
	// SkipOSUpgrade is an explicit bootstrap-time optimization for short-lived
	// test clusters. Omitted or false keeps the production security-upgrade
	// behavior; package indexes and required package installation are never
	// skipped.
	SkipOSUpgrade      bool     `json:"skipOSUpgrade,omitempty"`
	Disable            []string `json:"disable,omitempty"`
	TLSSubjectAltNames []string `json:"tlsSubjectAltNames,omitempty"`
}

type NetworkSpec struct {
	UUID                    string                      `json:"uuid"`
	PodCIDR                 string                      `json:"podCIDR"`
	ServiceCIDR             string                      `json:"serviceCIDR"`
	PrivateLoadBalancerPool PrivateLoadBalancerPoolSpec `json:"privateLoadBalancerPool"`
}

type PrivateLoadBalancerPoolSpec struct {
	Start string `json:"start"`
	Stop  string `json:"stop"`
}

// FirewallSpec requires controller-managed node and bastion firewalls.
type FirewallSpec struct {
	Managed bool `json:"managed,omitempty"`
}

// PublicIPv4Spec is explicit because InSpace has no outbound NAT. The MVP
// controller requires one managed floating IPv4 per control-plane VM and one
// for the bastion because InSpace has no outbound NAT.
type PublicIPv4Spec struct {
	Managed bool `json:"managed"`
}

type ControlPlaneEndpoint struct {
	VirtualIPv4 string `json:"virtualIPv4"`
	Port        int32  `json:"port"`
}

type InSpaceClusterStatus struct {
	Ready                bool   `json:"ready,omitempty"`
	ObservedGeneration   int64  `json:"observedGeneration,omitempty"`
	ControlPlaneEndpoint string `json:"controlPlaneEndpoint,omitempty"`
	Message              string `json:"message,omitempty"`
}

// ValidationError identifies one invalid field without depending on a
// webhook/controller framework.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string { return e.Field + ": " + e.Message }

func (s InSpaceClusterSpec) Validate() []error {
	var errs []error
	add := func(field, message string) { errs = append(errs, ValidationError{Field: field, Message: message}) }
	if !locationPattern.MatchString(s.Location) {
		add("spec.location", "must be a lowercase location slug")
	}
	if s.BillingAccountID < 1 {
		add("spec.billingAccountID", "must be a positive integer")
	}
	if s.CredentialsSecretRef.Name == "" || s.CredentialsSecretRef.Key == "" {
		add("spec.credentialsSecretRef", "name and key are required")
	}
	if s.ControlPlane.Replicas != 3 {
		add("spec.controlPlane.replicas", "must be exactly 3 in v1alpha1")
	}
	machine := s.ControlPlane.Machine
	if machine.VCPU < 2 || machine.VCPU > 16 {
		add("spec.controlPlane.machine.vcpu", "must be between 2 and 16")
	}
	if machine.MemoryMiB < 4096 || machine.MemoryMiB > 65536 {
		add("spec.controlPlane.machine.memoryMiB", "must be between 4096 and 65536")
	}
	if machine.RootDiskGiB < 30 || machine.RootDiskGiB > 2000 {
		add("spec.controlPlane.machine.rootDiskGiB", "must be between 30 and 2000")
	}
	if !uuidPattern.MatchString(machine.HostPoolUUID) {
		add("spec.controlPlane.machine.hostPoolUUID", "must be a UUID")
	}
	if machine.Image.OSName != "ubuntu" {
		add("spec.controlPlane.machine.image.osName", "must be ubuntu in v1alpha1")
	}
	if machine.Image.OSVersion != "24.04" {
		add("spec.controlPlane.machine.image.osVersion", "must be 24.04 in v1alpha1")
	}
	if !rke2VersionPattern.MatchString(s.RKE2.Version) {
		add("spec.rke2.version", "must be an exact vX.Y.Z+rke2rN release")
	}
	if s.RKE2.TokenSecretRef.Name == "" || s.RKE2.TokenSecretRef.Key == "" {
		add("spec.rke2.tokenSecretRef", "name and key are required")
	}
	for _, component := range s.RKE2.Disable {
		if component == "rke2-cilium" {
			add("spec.rke2.disable", "must not disable rke2-cilium while kube-proxy replacement is enabled")
		}
	}
	if !uuidPattern.MatchString(s.Network.UUID) {
		add("spec.network.uuid", "must be a UUID")
	}
	if !s.Firewall.Managed {
		add("spec.firewall.managed", "must be true for owned node and bastion firewalls")
	}
	if !s.PublicIPv4.Managed {
		add("spec.publicIPv4.managed", "must be true because InSpace has no outbound NAT")
	}
	podCIDR, podErr := netip.ParsePrefix(s.Network.PodCIDR)
	if podErr != nil {
		add("spec.network.podCIDR", "must be a valid CIDR")
	}
	serviceCIDR, serviceErr := netip.ParsePrefix(s.Network.ServiceCIDR)
	if serviceErr != nil {
		add("spec.network.serviceCIDR", "must be a valid CIDR")
	}
	if podErr == nil && serviceErr == nil && (podCIDR.Contains(serviceCIDR.Addr()) || serviceCIDR.Contains(podCIDR.Addr())) {
		add("spec.network", "podCIDR and serviceCIDR must not overlap")
	}
	if s.Network.PodCIDR != CiliumNativeRoutingPodCIDR {
		add("spec.network.podCIDR", "must be "+CiliumNativeRoutingPodCIDR+" in v1alpha1")
	}
	if s.Network.ServiceCIDR != KubernetesServiceCIDR {
		add("spec.network.serviceCIDR", "must be "+KubernetesServiceCIDR+" in v1alpha1")
	}
	virtualIPv4, virtualErr := netip.ParseAddr(s.Endpoint.VirtualIPv4)
	if virtualErr != nil || !virtualIPv4.Is4() || !virtualIPv4.IsPrivate() {
		add("spec.endpoint.virtualIPv4", "must be a private IPv4 address")
	} else {
		for _, reserved := range []struct {
			name   string
			prefix netip.Prefix
		}{
			{name: "pod CIDR", prefix: netip.MustParsePrefix(CiliumNativeRoutingPodCIDR)},
			{name: "Service CIDR", prefix: netip.MustParsePrefix(KubernetesServiceCIDR)},
		} {
			if reserved.prefix.Contains(virtualIPv4) {
				add("spec.endpoint.virtualIPv4", "must not overlap the "+reserved.name+" "+reserved.prefix.String())
			}
		}
	}
	poolStart, startErr := canonicalPrivateIPv4(s.Network.PrivateLoadBalancerPool.Start)
	if startErr != nil {
		add("spec.network.privateLoadBalancerPool.start", "must be a canonical RFC1918 IPv4 address")
	}
	poolStop, stopErr := canonicalPrivateIPv4(s.Network.PrivateLoadBalancerPool.Stop)
	if stopErr != nil {
		add("spec.network.privateLoadBalancerPool.stop", "must be a canonical RFC1918 IPv4 address")
	}
	if startErr == nil && stopErr == nil {
		if poolStart.Compare(poolStop) > 0 {
			add("spec.network.privateLoadBalancerPool", "start must be less than or equal to stop")
		} else {
			addressCount := inclusiveIPv4Count(poolStart, poolStop)
			if addressCount < PrivateLoadBalancerPoolMinAddresses || addressCount > PrivateLoadBalancerPoolMaxAddresses {
				add("spec.network.privateLoadBalancerPool", fmt.Sprintf("must contain between %d and %d addresses in v1alpha1", PrivateLoadBalancerPoolMinAddresses, PrivateLoadBalancerPoolMaxAddresses))
			}
			if virtualErr == nil && ipv4RangeContains(poolStart, poolStop, virtualIPv4) {
				add("spec.network.privateLoadBalancerPool", "must not contain spec.endpoint.virtualIPv4")
			}
			if podErr == nil && ipv4RangeOverlapsPrefix(poolStart, poolStop, podCIDR) {
				add("spec.network.privateLoadBalancerPool", "must not overlap spec.network.podCIDR")
			}
			if serviceErr == nil && ipv4RangeOverlapsPrefix(poolStart, poolStop, serviceCIDR) {
				add("spec.network.privateLoadBalancerPool", "must not overlap spec.network.serviceCIDR")
			}
		}
	}
	if s.Endpoint.Port != 6443 {
		add("spec.endpoint.port", "must be 6443 in v1alpha1")
	}
	return errs
}

func canonicalPrivateIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != value {
		return netip.Addr{}, fmt.Errorf("not a canonical private IPv4 address")
	}
	return address, nil
}

func inclusiveIPv4Count(start, stop netip.Addr) uint64 {
	return uint64(ipv4Value(stop)-ipv4Value(start)) + 1
}

func ipv4RangeContains(start, stop, address netip.Addr) bool {
	return address.Is4() && start.Compare(address) <= 0 && address.Compare(stop) <= 0
}

func ipv4RangeOverlapsPrefix(start, stop netip.Addr, prefix netip.Prefix) bool {
	if !prefix.Addr().Is4() {
		return false
	}
	masked := prefix.Masked()
	prefixStart := ipv4Value(masked.Addr())
	prefixHostMask := ^uint32(0) >> masked.Bits()
	prefixStop := prefixStart | prefixHostMask
	return ipv4Value(start) <= prefixStop && prefixStart <= ipv4Value(stop)
}

func ipv4Value(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func (c InSpaceCluster) Validate() []error {
	var errs []error
	if !clusterNamePrefix.MatchString(c.Metadata.Name) {
		errs = append(errs, ValidationError{
			Field:   "metadata.name",
			Message: "must be a lowercase DNS label of at most 55 characters so fixed bastion and control-plane hostnames fit within 63 characters",
		})
	}
	if c.Spec.ControlPlane.Replicas == 0 {
		errs = append(errs, fmt.Errorf("spec.controlPlane.replicas: must be explicitly set to 3"))
		return errs
	}
	return append(errs, c.Spec.Validate()...)
}
