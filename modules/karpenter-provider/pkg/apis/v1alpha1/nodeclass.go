package v1alpha1

import (
	"github.com/awslabs/operatorpkg/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LocationBangkok         = "bkk01"
	OSNameUbuntu            = "ubuntu"
	OSVersionUbuntu         = "24.04"
	K3sAgentTokenSecretName = "inspace-k3s-agent-token"
	K3sAgentTokenSecretKey  = "token"

	HostClassIntelScalable = "intel-scalable"
	HostClassAMDEPYC       = "amd-epyc"

	IntelScalableHostPoolUUID = "aac7dd66-f390-4edd-80c0-dd7cae49bd99"
	AMDEPYCHostPoolUUID       = "6976fdc8-4492-465b-bd16-9ad5f6b00b03"
)

// InSpaceNodeClass describes the immutable infrastructure and K3s bootstrap
// policy shared by one or more Karpenter NodePools.
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=inspacenodeclasses,scope=Cluster,categories=karpenter
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Location",type=string,JSONPath=`.spec.location`
// +kubebuilder:printcolumn:name="Host Class",type=string,JSONPath=`.spec.hostPoolSelector.class`
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
	// NetworkUUID is the existing private network joined by workers.
	NetworkUUID string `json:"networkUUID"`
	// ReservePublicIPv4 makes the provider own a separately named floating IPv4
	// because InSpace has no managed NAT gateway. The VM create call itself
	// reserves no implicit IP. The address is for egress only; K3s uses RFC1918.
	ReservePublicIPv4 bool `json:"reservePublicIPv4"`
	// FirewallUUID is a pre-created default-deny InSpace firewall assigned to
	// every worker before the provider reports a successful launch.
	FirewallUUID string `json:"firewallUUID"`
	// ImageSelector selects a stock operating-system image supported by the VM
	// create API. The first release supports Ubuntu 24.04 only.
	ImageSelector ImageSelector `json:"imageSelector"`
	// HostPoolSelector resolves one of the two supported hardware classes.
	HostPoolSelector HostPoolSelector `json:"hostPoolSelector"`
	// RootDiskGiB is ephemeral node storage. Persistent data belongs on CSI volumes.
	RootDiskGiB int32 `json:"rootDiskGiB"`
	// K3s configures workers to join the fixed control-plane endpoint.
	K3s K3sConfig `json:"k3s"`
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

type HostPoolSelector struct {
	// Class selects the Standard Intel Scalable or High Performance AMD EPYC pool.
	Class string `json:"class"`
}

func (h HostPoolSelector) UUID() (string, bool) {
	switch h.Class {
	case HostClassIntelScalable:
		return IntelScalableHostPoolUUID, true
	case HostClassAMDEPYC:
		return AMDEPYCHostPoolUUID, true
	default:
		return "", false
	}
}

type K3sConfig struct {
	// Version must exactly match the K3s server version.
	Version string `json:"version"`
	// Server is the stable TCP/6443 registration endpoint.
	Server string `json:"server"`
	// TokenSecretRef points to a Secret containing the K3s agent token.
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
}

type SecretKeySelector struct {
	// The Secret is read from the controller's fixed secret namespace. This
	// keeps a cluster-scoped NodeClass from selecting arbitrary namespaces.
	Name string `json:"name"`
	Key  string `json:"key"`
}

type InSpaceNodeClassStatus struct {
	Conditions               []status.Condition `json:"conditions,omitempty"`
	HostPoolUUID             string             `json:"hostPoolUUID,omitempty"`
	FirewallUUID             string             `json:"firewallUUID,omitempty"`
	ObservedImageID          string             `json:"observedImageID,omitempty"`
	ObservedSpecHash         string             `json:"observedSpecHash,omitempty"`
	ObservedGeneration       int64              `json:"observedGeneration,omitempty"`
	ObservedBillingAccountID int64              `json:"observedBillingAccountID,omitempty"`
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
