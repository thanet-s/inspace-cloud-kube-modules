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
)

var (
	locationPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
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
	K3s                  K3sSpec              `json:"k3s"`
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

type K3sSpec struct {
	Version            string             `json:"version"`
	TokenSecretRef     SecretKeyReference `json:"tokenSecretRef"`
	Disable            []string           `json:"disable,omitempty"`
	TLSSubjectAltNames []string           `json:"tlsSubjectAltNames,omitempty"`
}

type NetworkSpec struct {
	UUID        string `json:"uuid"`
	PodCIDR     string `json:"podCIDR"`
	ServiceCIDR string `json:"serviceCIDR"`
}

// FirewallSpec selects either an existing firewall or a controller-managed
// cluster firewall. Exactly one mode must be configured.
type FirewallSpec struct {
	UUID    string `json:"uuid,omitempty"`
	Managed bool   `json:"managed,omitempty"`
}

// PublicIPv4Spec is explicit because InSpace has no outbound NAT. The MVP
// controller requires one managed floating IPv4 per control-plane VM.
type PublicIPv4Spec struct {
	Managed bool `json:"managed"`
}

type ControlPlaneEndpoint struct {
	Host   string `json:"host"`
	Port   int32  `json:"port"`
	Public bool   `json:"public,omitempty"`
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
	if machine.VCPU < 1 || machine.VCPU > 16 {
		add("spec.controlPlane.machine.vcpu", "must be between 1 and 16")
	}
	if machine.MemoryMiB < 2048 || machine.MemoryMiB > 65536 {
		add("spec.controlPlane.machine.memoryMiB", "must be between 2048 and 65536")
	}
	if machine.RootDiskGiB < 30 || machine.RootDiskGiB > 2000 {
		add("spec.controlPlane.machine.rootDiskGiB", "must be between 30 and 2000")
	}
	if !uuidPattern.MatchString(machine.HostPoolUUID) {
		add("spec.controlPlane.machine.hostPoolUUID", "must be a UUID")
	}
	if machine.Image.OSName == "" || machine.Image.OSVersion == "" {
		add("spec.controlPlane.machine.image", "osName and osVersion are required")
	}
	if machine.Image.OSName != "ubuntu" {
		add("spec.controlPlane.machine.image.osName", "must be ubuntu in v1alpha1")
	}
	if s.K3s.Version == "" {
		add("spec.k3s.version", "is required")
	}
	if s.K3s.TokenSecretRef.Name == "" || s.K3s.TokenSecretRef.Key == "" {
		add("spec.k3s.tokenSecretRef", "name and key are required")
	}
	if !uuidPattern.MatchString(s.Network.UUID) {
		add("spec.network.uuid", "must be a UUID")
	}
	if (s.Firewall.UUID == "") == !s.Firewall.Managed {
		add("spec.firewall", "set exactly one of uuid or managed: true")
	}
	if s.Firewall.UUID != "" && !uuidPattern.MatchString(s.Firewall.UUID) {
		add("spec.firewall.uuid", "must be a UUID")
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
	if s.Network.PodCIDR != "10.42.0.0/16" {
		add("spec.network.podCIDR", "must be 10.42.0.0/16 in v1alpha1")
	}
	if s.Network.ServiceCIDR != "10.43.0.0/16" {
		add("spec.network.serviceCIDR", "must be 10.43.0.0/16 in v1alpha1")
	}
	if s.Endpoint.Host == "" {
		add("spec.endpoint.host", "is required")
	}
	if s.Endpoint.Port != 6443 {
		add("spec.endpoint.port", "must be 6443 in v1alpha1")
	}
	return errs
}

func (c InSpaceCluster) Validate() []error {
	if c.Spec.ControlPlane.Replicas == 0 {
		return []error{fmt.Errorf("spec.controlPlane.replicas: must be explicitly set to 3")}
	}
	return c.Spec.Validate()
}
