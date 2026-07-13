package v1alpha1

import (
	"github.com/awslabs/operatorpkg/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LocationBangkok          = "bkk01"
	OSNameUbuntu             = "ubuntu"
	OSVersionUbuntu          = "24.04"
	RKE2AgentTokenSecretName = "inspace-rke2-agent-token"
	RKE2AgentTokenSecretKey  = "token"

	HostClassIntelScalable = "intel-scalable"
	HostClassAMDEPYC       = "amd-epyc"

	IntelScalableHostPoolUUID = "aac7dd66-f390-4edd-80c0-dd7cae49bd99"
	AMDEPYCHostPoolUUID       = "6976fdc8-4492-465b-bd16-9ad5f6b00b03"
)

// InSpaceNodeClass describes the immutable infrastructure and RKE2 bootstrap
// policy shared by one or more Karpenter NodePools.
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=inspacenodeclasses,scope=Cluster,categories=karpenter
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Location",type=string,JSONPath=`.spec.location`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type InSpaceNodeClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   InSpaceNodeClassSpec   `json:"spec"`
	Status InSpaceNodeClassStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type InSpaceNodeClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []InSpaceNodeClass `json:"items"`
}

type InSpaceNodeClassSpec struct {
	// ClusterName scopes cloud discovery and prevents cross-cluster deletion.
	ClusterName string `json:"clusterName"`
	// BillingAccountID is charged for worker compute and floating public IPv4.
	BillingAccountID int64 `json:"billingAccountID"`
	// Location is deliberately limited to bkk01 for the first release.
	Location string `json:"location"`
	// NetworkUUID is the existing private network joined by workers. Its subnet
	// must be RFC1918, /27 or shorter so it can contain the reserved Service
	// range plus a distinct usable supervisor VIP, and must not overlap Cilium
	// native-routing pod CIDR 10.42.0.0/16 or Kubernetes Service CIDR
	// 10.43.0.0/16. It must exactly match the controller-wide network UUID.
	NetworkUUID string `json:"networkUUID"`
	// PrivateLoadBalancerPool is the inclusive private IPv4 range reserved for
	// Cilium LB IPAM Services. It contains 16 to 256 addresses; worker NICs are
	// forbidden from this range.
	PrivateLoadBalancerPool PrivateLoadBalancerPool `json:"privateLoadBalancerPool"`
	// ReservePublicIPv4 makes VM creation reserve exactly one implicit floating
	// IPv4 because InSpace has no managed NAT gateway. The provider discovers
	// that exact VM assignment, PATCHes its deterministic name/account, and
	// requires readback before success. The address is for egress only; RKE2
	// uses RFC1918 and the external CCM publishes the Node ExternalIP.
	ReservePublicIPv4 bool `json:"reservePublicIPv4"`
	// FirewallUUID is a pre-created default-deny InSpace firewall assigned to
	// every worker before the provider reports a successful launch. Readiness
	// requires all-port TCP, UDP, and ICMP ingress from both the VPC subnet and
	// Cilium pod CIDR 10.42.0.0/16, plus matching any-destination egress, and
	// rejects every public inbound rule.
	FirewallUUID string `json:"firewallUUID"`
	// ImageSelector selects a stock operating-system image supported by the VM
	// create API. The first release supports Ubuntu 24.04 only.
	ImageSelector ImageSelector `json:"imageSelector"`
	// RootDiskGiB is ephemeral node storage. Persistent data belongs on CSI volumes.
	RootDiskGiB int32 `json:"rootDiskGiB"`
	// RKE2 configures agents to join the fixed supervisor endpoint.
	RKE2 RKE2Config `json:"rke2"`
	// SSHUsername and SSHPublicKey optionally enable controlled operator access.
	// They must be configured together. Private key material is never accepted.
	SSHUsername  string `json:"sshUsername,omitempty"`
	SSHPublicKey string `json:"sshPublicKey,omitempty"`
	// AdditionalUserData runs once through cloud-init-per. It must not contain secrets.
	AdditionalUserData string `json:"additionalUserData,omitempty"`
}

type ImageSelector struct {
	OSName    string `json:"osName"`
	OSVersion string `json:"osVersion"`
}

func (i ImageSelector) ID() string {
	return i.OSName + "@" + i.OSVersion
}

// HostPoolUUIDForClass resolves the provider's frozen hardware-class identity.
// Hardware selection belongs to NodePool requirements; NodeClass deliberately
// contains no host-class selector so one NodeClass can serve mixed-class pools.
func HostPoolUUIDForClass(class string) (string, bool) {
	switch class {
	case HostClassIntelScalable:
		return IntelScalableHostPoolUUID, true
	case HostClassAMDEPYC:
		return AMDEPYCHostPoolUUID, true
	default:
		return "", false
	}
}

// SupportedHostClasses returns a stable copy in deterministic scheduling and
// readiness-validation order.
func SupportedHostClasses() []string {
	return []string{HostClassIntelScalable, HostClassAMDEPYC}
}

type RKE2Config struct {
	// Version must exactly match the RKE2 server version.
	Version string `json:"version"`
	// Server is the stable private TCP/9345 RKE2 supervisor endpoint. Its host
	// must be a usable literal RFC1918 virtual IPv4 inside NetworkUUID, not its
	// network/broadcast address, and outside the fixed pod and Service CIDRs;
	// workers never join through a public endpoint. The VIP must exactly match
	// the controller-wide control-plane VIP.
	Server string `json:"server"`
	// TokenSecretRef points to a Secret containing the RKE2 agent token.
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
}

type SecretKeySelector struct {
	// The Secret is read from the controller's fixed secret namespace. This
	// keeps a cluster-scoped NodeClass from selecting arbitrary namespaces.
	Name string `json:"name"`
	Key  string `json:"key"`
}

type InSpaceNodeClassStatus struct {
	Conditions []status.Condition `json:"conditions,omitempty"`
	// +listType=set
	HostPoolUUIDs            []string `json:"hostPoolUUIDs,omitempty"`
	FirewallUUID             string   `json:"firewallUUID,omitempty"`
	ObservedImageID          string   `json:"observedImageID,omitempty"`
	ObservedSpecHash         string   `json:"observedSpecHash,omitempty"`
	ObservedGeneration       int64    `json:"observedGeneration,omitempty"`
	ObservedBillingAccountID int64    `json:"observedBillingAccountID,omitempty"`
}

func (n *InSpaceNodeClass) StatusConditions(opts ...status.ForOption) status.ConditionSet {
	return status.NewReadyConditions().For(n, opts...)
}

func (n *InSpaceNodeClass) GetConditions() []status.Condition {
	return n.Status.Conditions
}

func (n *InSpaceNodeClass) SetConditions(conditions []status.Condition) {
	n.Status.Conditions = conditions
}

func init() {
	SchemeBuilder.Register(&InSpaceNodeClass{}, &InSpaceNodeClassList{})
}
