package inspace

import "encoding/json"

// Location identifies an InSpace data-centre/resource location.
type Location struct {
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Slug        string `json:"slug"`
	CountryCode string `json:"country_code,omitempty"`
	IsDefault   bool   `json:"is_default"`
	IsPreferred bool   `json:"is_preferred"`
	OrderNumber int    `json:"order_nr,omitempty"`
}

// HostPool is an available compute host class.
type HostPool struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Description         string `json:"description,omitempty"`
	IsDefaultDesignated bool   `json:"is_default_designated"`
	IsVisible           bool   `json:"is_visible"`
	StoragePoolUUID     string `json:"storage_pool_uuid,omitempty"`
	UIPosition          int    `json:"ui_position,omitempty"`
	GuestLimits         any    `json:"guest_limits,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

// VM is the stable subset of the VM response used by controllers.
type VM struct {
	UUID               string          `json:"uuid"`
	ID                 int64           `json:"id,omitempty"`
	UserID             int64           `json:"user_id,omitempty"`
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	Hostname           string          `json:"hostname,omitempty"`
	Status             string          `json:"status"`
	VCPU               int             `json:"vcpu"`
	MemoryMiB          int             `json:"memory"`
	OSName             string          `json:"os_name,omitempty"`
	OSVersion          string          `json:"os_version,omitempty"`
	Username           string          `json:"username,omitempty"`
	MAC                string          `json:"mac,omitempty"`
	LicenseType        string          `json:"license_type,omitempty"`
	PrivateIPv4        string          `json:"private_ipv4,omitempty"`
	PublicIPv4         string          `json:"public_ipv4,omitempty"`
	PublicIPv6         string          `json:"public_ipv6,omitempty"`
	NetworkUUID        string          `json:"network_uuid,omitempty"`
	BillingAccountID   int64           `json:"billing_account,omitempty"`
	DesignatedPoolName string          `json:"designated_pool_name,omitempty"`
	DesignatedPoolUUID string          `json:"designated_pool_uuid,omitempty"`
	Backup             bool            `json:"backup"`
	CreatedAt          string          `json:"created_at,omitempty"`
	UpdatedAt          string          `json:"updated_at,omitempty"`
	Tags               json.RawMessage `json:"tags,omitempty"`
	Storage            []VMStorage     `json:"storage,omitempty"`
}

type VMStorage struct {
	UUID      string `json:"uuid"`
	ID        int64  `json:"id,omitempty"`
	UserID    int64  `json:"user_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Pool      string `json:"pool,omitempty"`
	Type      string `json:"type,omitempty"`
	SizeGiB   int    `json:"size"`
	Primary   bool   `json:"primary"`
	Shared    bool   `json:"shared"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// CreateVMRequest follows the Warren-compatible form contract. Memory is MiB
// and disk size is GiB.
type CreateVMRequest struct {
	Name               string
	Description        string
	OSName             string
	OSVersion          string
	DiskGiB            int
	VCPU               int
	MemoryMiB          int
	DesignatedPoolUUID string
	Username           string
	Password           string
	PublicKey          string
	BillingAccountID   int64
	NetworkUUID        string
	// CloudInit is a JSON object string accepted by the Warren API's
	// cloud_init form field. It is not a raw #cloud-config YAML document.
	CloudInit string
	// CloudInitJSON is retained for source compatibility. New callers should
	// use CloudInit; setting both is rejected.
	CloudInitJSON   string
	ReservePublicIP *bool
}

type Disk struct {
	UUID             string         `json:"uuid"`
	DisplayName      string         `json:"display_name,omitempty"`
	Status           string         `json:"status"`
	SizeGiB          int            `json:"size_gb"`
	BillingAccountID int64          `json:"billing_account_id,omitempty"`
	StoragePoolUUID  string         `json:"storage_pool_uuid,omitempty"`
	SourceImageType  string         `json:"source_image_type,omitempty"`
	SourceImage      string         `json:"source_image,omitempty"`
	ReadOnlyBootable bool           `json:"read_only_bootable,omitempty"`
	CreatedAt        string         `json:"created_at,omitempty"`
	UpdatedAt        string         `json:"updated_at,omitempty"`
	Snapshots        []DiskSnapshot `json:"snapshots,omitempty"`
}

type DiskSnapshot struct {
	UUID        string `json:"uuid"`
	DiskUUID    string `json:"disk_uuid,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	SizeGiB     int    `json:"size_gb"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type CreateDiskRequest struct {
	DisplayName      string
	SizeGiB          int
	BillingAccountID int64
	SourceImageType  string
	SourceImage      string
}

type Network struct {
	UUID           string   `json:"uuid"`
	Name           string   `json:"name"`
	Type           string   `json:"type,omitempty"`
	VLANID         int      `json:"vlan_id,omitempty"`
	Subnet         string   `json:"subnet,omitempty"`
	SubnetIPv6     string   `json:"subnet_ipv6,omitempty"`
	IsDefault      bool     `json:"is_default"`
	VMUUIDs        []string `json:"vm_uuids,omitempty"`
	ResourcesCount int      `json:"resources_count,omitempty"`
	CreatedAt      string   `json:"created_at,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

type VMImage struct {
	OSName       string           `json:"os_name"`
	DisplayName  string           `json:"display_name"`
	UIPosition   int              `json:"ui_position,omitempty"`
	IsDefault    bool             `json:"is_default"`
	IsAppCatalog bool             `json:"is_app_catalog"`
	Icon         string           `json:"icon,omitempty"`
	Versions     []VMImageVersion `json:"versions"`
}

type VMImageVersion struct {
	OSVersion   string `json:"os_version"`
	DisplayName string `json:"display_name"`
	Published   bool   `json:"published"`
}

type LoadBalancer struct {
	UUID             string               `json:"uuid"`
	DisplayName      string               `json:"display_name"`
	NetworkUUID      string               `json:"network_uuid"`
	BillingAccountID int64                `json:"billing_account_id,omitempty"`
	PrivateAddress   string               `json:"private_address,omitempty"`
	PublicAddress    string               `json:"public_address,omitempty"`
	PublicIPv4       string               `json:"public_ipv4,omitempty"`
	IsDeleted        bool                 `json:"is_deleted"`
	CreatedAt        string               `json:"created_at,omitempty"`
	UpdatedAt        string               `json:"updated_at,omitempty"`
	ForwardingRules  []LoadBalancerRule   `json:"forwarding_rules,omitempty"`
	Targets          []LoadBalancerTarget `json:"targets,omitempty"`
}

type LoadBalancerRule struct {
	UUID       string `json:"uuid,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	SourcePort int32  `json:"source_port"`
	TargetPort int32  `json:"target_port"`
	CreatedAt  string `json:"created_at,omitempty"`
}

type LoadBalancerTarget struct {
	TargetUUID      string `json:"target_uuid"`
	TargetType      string `json:"target_type"`
	TargetIPAddress string `json:"target_ip_address,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

type CreateLoadBalancerRequest struct {
	DisplayName      string             `json:"display_name,omitempty"`
	BillingAccountID int64              `json:"billing_account_id,omitempty"`
	NetworkUUID      string             `json:"network_uuid,omitempty"`
	ReservePublicIP  bool               `json:"reserve_public_ip"`
	Rules            []LoadBalancerRule `json:"rules,omitempty"`
	// InSpace documents targets as optional, but its API currently returns
	// HTTP 500 when the key is omitted. Preserve an explicit empty array for a
	// load balancer that will receive targets after creation.
	Targets []LoadBalancerTarget `json:"targets"`
}

type Firewall struct {
	UUID              string             `json:"uuid"`
	Name              string             `json:"name,omitempty"`
	DisplayName       string             `json:"display_name,omitempty"`
	Description       string             `json:"description,omitempty"`
	BillingAccountID  int64              `json:"billing_account_id,omitempty"`
	Rules             []FirewallRule     `json:"rules,omitempty"`
	ResourcesAssigned []FirewallResource `json:"resources_assigned,omitempty"`
	CreatedAt         string             `json:"created_at,omitempty"`
}

func (f Firewall) EffectiveName() string {
	if f.DisplayName != "" {
		return f.DisplayName
	}
	return f.Name
}

type FirewallRule struct {
	UUID             string   `json:"uuid,omitempty"`
	Protocol         string   `json:"protocol"`
	Direction        string   `json:"direction"`
	PortStart        *int32   `json:"port_start"`
	PortEnd          *int32   `json:"port_end"`
	EndpointSpecType string   `json:"endpoint_spec_type"`
	EndpointSpec     []string `json:"endpoint_spec,omitempty"`
}

type FirewallResource struct {
	ResourceType string `json:"resource_type"`
	ResourceUUID string `json:"resource_uuid"`
}

type CreateFirewallRequest struct {
	DisplayName      string         `json:"display_name"`
	Description      string         `json:"description,omitempty"`
	BillingAccountID int64          `json:"billing_account_id,omitempty"`
	Rules            []FirewallRule `json:"rules"`
}

type FloatingIP struct {
	UUID                   string `json:"uuid,omitempty"`
	ID                     int64  `json:"id,omitempty"`
	Address                string `json:"address"`
	UserID                 int64  `json:"user_id,omitempty"`
	BillingAccountID       int64  `json:"billing_account_id,omitempty"`
	Type                   string `json:"type,omitempty"`
	Name                   string `json:"name,omitempty"`
	Enabled                bool   `json:"enabled"`
	IsDeleted              bool   `json:"is_deleted"`
	IsVirtual              bool   `json:"is_virtual"`
	AssignedTo             string `json:"assigned_to,omitempty"`
	AssignedToResourceType string `json:"assigned_to_resource_type,omitempty"`
	AssignedToPrivateIP    string `json:"assigned_to_private_ip,omitempty"`
	CreatedAt              string `json:"created_at,omitempty"`
	UpdatedAt              string `json:"updated_at,omitempty"`
	UnassignedAt           string `json:"unassigned_at,omitempty"`
}

type CreateFloatingIPRequest struct {
	Name             string `json:"name,omitempty"`
	BillingAccountID int64  `json:"billing_account_id"`
}

type FloatingIPFilters struct {
	BillingAccountID int64
	VMUUID           string
}
