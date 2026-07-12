// Package inspace adapts the shared InSpace API client to Karpenter's cloud
// model. VM, firewall-assignment, and floating-IP POSTs are never blindly
// retried. Reconciliation uses deterministic ownership records and read-back.
package inspace

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	ownershipSchema                             = "karpenter.inspace.cloud/v1"
	defaultUsername                             = "user"
	passwordByteSize                            = 21
	defaultNetworkAttachmentReadbackTimeout     = 60 * time.Second
	defaultNetworkAttachmentRequestTimeout      = 10 * time.Second
	defaultNetworkAttachmentReadbackMinInterval = 500 * time.Millisecond
	defaultNetworkAttachmentReadbackMaxInterval = 5 * time.Second
)

type API interface {
	ListHostPools(context.Context, string) ([]sdk.HostPool, error)
	GetNetwork(context.Context, string, string) (*sdk.Network, error)
	ListFirewalls(context.Context, string) ([]sdk.Firewall, error)
	AssignFirewallToVM(context.Context, string, string, string) error
	UnassignFirewallFromVM(context.Context, string, string, string) error

	ListFloatingIPs(context.Context, string, *sdk.FloatingIPFilters) ([]sdk.FloatingIP, error)
	CreateFloatingIP(context.Context, string, sdk.CreateFloatingIPRequest) (*sdk.FloatingIP, error)
	AssignFloatingIP(context.Context, string, string, string, string) (*sdk.FloatingIP, error)
	UnassignFloatingIP(context.Context, string, string) (*sdk.FloatingIP, error)
	DeleteFloatingIP(context.Context, string, string) error

	ListVMs(context.Context, string) ([]sdk.VM, error)
	GetVM(context.Context, string, string) (*sdk.VM, error)
	CreateVM(context.Context, string, sdk.CreateVMRequest) (*sdk.VM, error)
	DeleteVM(context.Context, string, string) error
}

type Adapter struct {
	api                               API
	generatePassword                  func() (string, error)
	networkAttachmentReadbackTimeout  time.Duration
	networkAttachmentRequestTimeout   time.Duration
	networkAttachmentReadbackMinDelay time.Duration
	networkAttachmentReadbackMaxDelay time.Duration
}

func New(api API) (*Adapter, error) {
	return newAdapter(api, generatePassword)
}

func newAdapter(api API, passwordGenerator func() (string, error)) (*Adapter, error) {
	if api == nil {
		return nil, fmt.Errorf("InSpace API client is required")
	}
	if passwordGenerator == nil {
		return nil, fmt.Errorf("secure VM password generator is required")
	}
	return &Adapter{
		api:                               api,
		generatePassword:                  passwordGenerator,
		networkAttachmentReadbackTimeout:  defaultNetworkAttachmentReadbackTimeout,
		networkAttachmentRequestTimeout:   defaultNetworkAttachmentRequestTimeout,
		networkAttachmentReadbackMinDelay: defaultNetworkAttachmentReadbackMinInterval,
		networkAttachmentReadbackMaxDelay: defaultNetworkAttachmentReadbackMaxInterval,
	}, nil
}

type ownership struct {
	Schema           string `json:"schema"`
	Cluster          string `json:"cluster"`
	NodeClaim        string `json:"nodeClaim"`
	KeyHash          string `json:"keyHash"`
	HostClass        string `json:"hostClass"`
	InstanceType     string `json:"instanceType"`
	RootDiskGiB      int32  `json:"rootDiskGiB"`
	SpecHash         string `json:"specHash"`
	BootstrapHash    string `json:"bootstrapHash"`
	FirewallUUID     string `json:"firewallUUID"`
	OSName           string `json:"osName"`
	OSVersion        string `json:"osVersion"`
	BillingAccountID int64  `json:"billingAccountID"`
	FloatingIPName   string `json:"floatingIPName"`
	PublicIPv4       string `json:"publicIPv4"`
}

func newOwnership(request cloudapi.CreateVMRequest, floatingIP sdk.FloatingIP) ownership {
	return ownership{
		Schema: ownershipSchema, Cluster: request.ClusterName, NodeClaim: request.NodeClaimName,
		KeyHash: hashKey(request.IdempotencyKey), HostClass: request.HostClass, InstanceType: request.InstanceType,
		RootDiskGiB: request.RootDiskGiB, SpecHash: request.SpecHash, BootstrapHash: request.BootstrapHash,
		FirewallUUID: request.FirewallUUID, OSName: request.OSName, OSVersion: request.OSVersion,
		BillingAccountID: request.BillingAccountID, FloatingIPName: floatingIP.Name, PublicIPv4: floatingIP.Address,
	}
}

func (a *Adapter) CreateVM(ctx context.Context, request cloudapi.CreateVMRequest) (*cloudapi.VM, error) {
	if err := validateCreateRequest(request); err != nil {
		return nil, err
	}
	if err := a.ValidateNodeClass(ctx, request.Location, request.NetworkUUID, request.HostPoolUUID, request.FirewallUUID); err != nil {
		return nil, fmt.Errorf("preflight NodeClass infrastructure: %w", err)
	}
	if existing, actual, err := a.findOwnedVM(ctx, request); err != nil {
		return nil, err
	} else if existing != nil {
		expectedFloatingIP := sdk.FloatingIP{
			Name: floatingIPName(request.ClusterName, request.NodeClaimName), Address: actual.PublicIPv4,
			BillingAccountID: request.BillingAccountID,
		}
		expected := newOwnership(request, expectedFloatingIP)
		if err := validateExisting(*existing, request, actual, expected); err != nil {
			return nil, err
		}
		floatingIP, err := a.findFloatingIPByName(ctx, request.Location, expectedFloatingIP.Name, request.BillingAccountID)
		if err != nil {
			return nil, fmt.Errorf("finding floating IP recorded by owned VM %s: %w", existing.UUID, err)
		}
		if err := validateExistingFloatingIP(*floatingIP, actual, existing.UUID); err != nil {
			return nil, err
		}
		if err := a.ensureProtection(ctx, request, existing.UUID, *floatingIP); err != nil {
			return nil, fmt.Errorf("verifying protection for owned VM %s: %w", existing.UUID, err)
		}
		return fromSDK(existing, request.Location, actual), nil
	}
	floatingIP, floatingIPCreated, err := a.ensureFloatingIP(ctx, request)
	if err != nil {
		return nil, err
	}
	resolvedCloudInit, err := bootstrap.ResolveExternalIPv4(request.CloudInitJSON, floatingIP.Address)
	if err != nil {
		var cleanupErr error
		if floatingIPCreated {
			cleanupErr = a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		}
		return nil, errors.Join(fmt.Errorf("resolving K3s external node IP: %w", err), cleanupErr)
	}
	request.CloudInitJSON = resolvedCloudInit
	record := newOwnership(request, *floatingIP)
	description, err := json.Marshal(record)
	if err != nil {
		var cleanupErr error
		if floatingIPCreated {
			cleanupErr = a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		}
		return nil, errors.Join(fmt.Errorf("encoding VM ownership: %w", err), cleanupErr)
	}

	if existing, err := a.findCreate(ctx, request, record, floatingIP); err != nil {
		var cleanupErr error
		if floatingIPCreated {
			cleanupErr = a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		}
		return nil, errors.Join(err, cleanupErr)
	} else if existing != nil {
		return existing, nil
	}
	if floatingIP.AssignedTo != "" {
		return nil, fmt.Errorf("%w: owned floating IP %s is assigned to %s but no matching VM exists", cloudapi.ErrOwnershipMismatch, floatingIP.Address, floatingIP.AssignedTo)
	}

	// The provider owns a separately named floating IP. Asking VM create to
	// reserve another address would leak an untracked resource.
	reservePublicIP := false
	username := request.SSHUsername
	if username == "" {
		username = defaultUsername
	}
	password, err := a.generatePassword()
	if err != nil {
		var cleanupErr error
		if floatingIPCreated {
			cleanupErr = a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		}
		return nil, errors.Join(fmt.Errorf("generating ephemeral VM password: %w", err), cleanupErr)
	}
	if err := validateGeneratedPassword(password); err != nil {
		var cleanupErr error
		if floatingIPCreated {
			cleanupErr = a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		}
		return nil, errors.Join(fmt.Errorf("generated ephemeral VM password is invalid: %w", err), cleanupErr)
	}
	created, createErr := a.api.CreateVM(ctx, request.Location, sdk.CreateVMRequest{
		Name: request.Name, Description: string(description), OSName: request.OSName, OSVersion: request.OSVersion,
		DiskGiB: int(request.RootDiskGiB), VCPU: request.VCPU, MemoryMiB: request.MemoryGiB * 1024,
		DesignatedPoolUUID: request.HostPoolUUID, NetworkUUID: request.NetworkUUID,
		Username: username, Password: password, PublicKey: request.SSHPublicKey,
		BillingAccountID: request.BillingAccountID, CloudInit: request.CloudInitJSON, ReservePublicIP: &reservePublicIP,
	})
	if createErr != nil {
		// A retryable/transport response may be ambiguous. Recover with reads
		// only; never issue a second VM POST in this call. If the VM is not yet
		// visible, preserve the deterministically named floating IP so the next
		// reconciliation can adopt a late-committed VM with the same ownership
		// record and public address.
		if isAmbiguousCreate(createErr) {
			if recovered, recoveryErr := a.findCreate(ctx, request, record, floatingIP); recoveryErr == nil && recovered != nil {
				return recovered, nil
			} else if recoveryErr != nil {
				return nil, errors.Join(fmt.Errorf("creating InSpace VM had an ambiguous outcome: %w", createErr), recoveryErr)
			}
			return nil, fmt.Errorf("creating InSpace VM had an ambiguous outcome; preserving owned floating IP %q for reconciliation: %w", floatingIP.Name, createErr)
		}
		cleanupErr := a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		return nil, errors.Join(fmt.Errorf("creating InSpace VM (POST was not retried): %w", createErr), cleanupErr)
	}
	if created == nil || created.UUID == "" {
		cleanupErr := a.cleanupUnassignedFloatingIP(ctx, request.Location, *floatingIP)
		return nil, errors.Join(fmt.Errorf("creating InSpace VM returned no UUID"), cleanupErr)
	}
	// Some create responses omit request fields. Merge only sent values;
	// subsequent Get/List still require the persisted ownership JSON.
	created.Description = string(description)
	created.OSName = request.OSName
	created.OSVersion = request.OSVersion
	created.DesignatedPoolUUID = request.HostPoolUUID
	if created.NetworkUUID != "" && created.NetworkUUID != request.NetworkUUID {
		return nil, a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, created.UUID, *floatingIP,
			fmt.Errorf("created VM is attached to network %q instead of %q", created.NetworkUUID, request.NetworkUUID))
	}
	if err := a.ensureProtection(ctx, request, created.UUID, *floatingIP); err != nil {
		return nil, a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, created.UUID, *floatingIP, err)
	}
	return fromSDK(created, request.Location, record), nil
}

func (a *Adapter) findCreate(ctx context.Context, request cloudapi.CreateVMRequest, expected ownership, floatingIP *sdk.FloatingIP) (*cloudapi.VM, error) {
	vm, actual, err := a.findOwnedVM(ctx, request)
	if err != nil || vm == nil {
		return nil, err
	}
	if err := validateExisting(*vm, request, actual, expected); err != nil {
		return nil, err
	}
	if err := validateExistingFloatingIP(*floatingIP, actual, vm.UUID); err != nil {
		return nil, err
	}
	if err := a.ensureProtection(ctx, request, vm.UUID, *floatingIP); err != nil {
		return nil, fmt.Errorf("verifying protection for owned VM %s: %w", vm.UUID, err)
	}
	return fromSDK(vm, request.Location, actual), nil
}

func (a *Adapter) findOwnedVM(ctx context.Context, request cloudapi.CreateVMRequest) (*sdk.VM, ownership, error) {
	vms, err := a.api.ListVMs(ctx, request.Location)
	if err != nil {
		return nil, ownership{}, fmt.Errorf("listing VMs before create: %w", err)
	}
	type match struct {
		vm     sdk.VM
		record ownership
	}
	var matches []match
	keyHash := hashKey(request.IdempotencyKey)
	for i := range vms {
		record, managed := parseOwnership(vms[i].Description)
		if managed && record.Cluster == request.ClusterName && record.NodeClaim == request.NodeClaimName && record.KeyHash == keyHash {
			matches = append(matches, match{vm: vms[i], record: record})
			continue
		}
		if vms[i].Name == request.Name {
			return nil, ownership{}, fmt.Errorf("refusing create: VM name %q already exists without matching ownership", request.Name)
		}
	}
	if len(matches) > 1 {
		return nil, ownership{}, fmt.Errorf("refusing create: %d VMs have the same Karpenter ownership identity", len(matches))
	}
	if len(matches) == 1 {
		return &matches[0].vm, matches[0].record, nil
	}
	return nil, ownership{}, nil
}

func (a *Adapter) GetVM(ctx context.Context, location, uuid, clusterName string) (*cloudapi.VM, error) {
	vm, err := a.api.GetVM(ctx, location, uuid)
	if err != nil {
		if sdk.IsNotFound(err) {
			return nil, cloudapi.ErrNotFound
		}
		return nil, err
	}
	record, managed := parseOwnership(vm.Description)
	if !managed || record.Cluster != clusterName {
		return nil, fmt.Errorf("%w: VM %s is not managed for cluster %q", cloudapi.ErrOwnershipMismatch, uuid, clusterName)
	}
	return fromSDK(vm, location, record), nil
}

func (a *Adapter) ListVMs(ctx context.Context, location, clusterName string) ([]*cloudapi.VM, error) {
	vms, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return nil, err
	}
	result := make([]*cloudapi.VM, 0, len(vms))
	for i := range vms {
		record, managed := parseOwnership(vms[i].Description)
		if managed && record.Cluster == clusterName {
			result = append(result, fromSDK(&vms[i], location, record))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	return result, nil
}

func (a *Adapter) DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string) error {
	vm, getErr := a.api.GetVM(ctx, location, uuid)
	var record ownership
	vmMissing := false
	if getErr != nil {
		if !sdk.IsNotFound(getErr) {
			return getErr
		}
		vmMissing = true
	} else {
		var managed bool
		record, managed = parseOwnership(vm.Description)
		if !managed || record.Cluster != clusterName || record.NodeClaim != nodeClaimName {
			return fmt.Errorf("%w: VM %s is not managed for cluster %q and NodeClaim %q", cloudapi.ErrOwnershipMismatch, uuid, clusterName, nodeClaimName)
		}
	}

	floatingIP, floatingErr := a.findFloatingIPByName(ctx, location, floatingIPName(clusterName, nodeClaimName), 0)
	if floatingErr != nil && !errors.Is(floatingErr, cloudapi.ErrNotFound) {
		return floatingErr
	}
	if floatingIP != nil && record.PublicIPv4 != "" && (floatingIP.Address != record.PublicIPv4 || floatingIP.Name != record.FloatingIPName) {
		return fmt.Errorf("%w: floating IP ownership does not match VM %s", cloudapi.ErrOwnershipMismatch, uuid)
	}

	var errs []error
	var floatingCleanupErr error
	if floatingIP != nil {
		floatingCleanupErr = a.deleteOwnedFloatingIP(ctx, location, *floatingIP, uuid)
	}
	vmGone := vmMissing
	if !vmMissing {
		if err := a.api.DeleteVM(ctx, location, uuid); err != nil {
			if sdk.IsNotFound(err) {
				vmGone = true
				vmMissing = true
			} else {
				// The cloud firewall deliberately remains attached whenever VM
				// deletion fails, even if floating-IP cleanup also failed.
				if floatingCleanupErr != nil {
					errs = append(errs, floatingCleanupErr)
				}
				errs = append(errs, fmt.Errorf("deleting VM %s: %w", uuid, err))
				return errors.Join(errs...)
			}
		} else {
			vmGone = true
		}
	}
	if vmGone && floatingCleanupErr != nil && floatingIP != nil {
		// VM deletion may cause the API to release an assignment, so retry the
		// owned IP cleanup once after the protected VM is gone.
		floatingCleanupErr = a.deleteOwnedFloatingIP(ctx, location, *floatingIP, uuid)
	}
	if floatingCleanupErr != nil {
		errs = append(errs, floatingCleanupErr)
	}
	if vmGone {
		if err := a.detachFirewallAfterVMDeletion(ctx, location, record.FirewallUUID, uuid); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if vmMissing {
		return cloudapi.ErrNotFound
	}
	return nil
}

func (a *Adapter) ValidateNodeClass(ctx context.Context, location, networkUUID, hostPoolUUID, firewallUUID string) error {
	pools, err := a.api.ListHostPools(ctx, location)
	if err != nil {
		return fmt.Errorf("listing InSpace host pools: %w", err)
	}
	foundPool := false
	for _, pool := range pools {
		if pool.UUID == hostPoolUUID {
			foundPool = true
			break
		}
	}
	if !foundPool {
		return fmt.Errorf("host pool %s is not available in location %s", hostPoolUUID, location)
	}
	network, err := a.api.GetNetwork(ctx, location, networkUUID)
	if err != nil {
		return fmt.Errorf("getting InSpace network %s: %w", networkUUID, err)
	}
	if network == nil {
		return fmt.Errorf("getting InSpace network %s: API returned no network", networkUUID)
	}
	if network.UUID != networkUUID {
		return fmt.Errorf("network read-back UUID %q does not match %q", network.UUID, networkUUID)
	}
	networkPrefix, err := netip.ParsePrefix(network.Subnet)
	if err != nil || !isRFC1918Prefix(networkPrefix) {
		return fmt.Errorf("network %s subnet %q must be an RFC1918 IPv4 prefix", networkUUID, network.Subnet)
	}
	firewall, err := a.findFirewall(ctx, location, firewallUUID)
	if err != nil {
		return err
	}
	return validateDefaultDenyFirewall(*firewall, networkPrefix)
}

func validateCreateRequest(r cloudapi.CreateVMRequest) error {
	switch {
	case r.IdempotencyKey == "":
		return fmt.Errorf("idempotency key is required")
	case r.Name == "" || r.ClusterName == "" || r.NodeClaimName == "":
		return fmt.Errorf("VM name, cluster name, and NodeClaim name are required")
	case r.BillingAccountID <= 0:
		return fmt.Errorf("billing account ID must be positive")
	case r.Location == "" || r.NetworkUUID == "" || r.HostPoolUUID == "" || r.FirewallUUID == "":
		return fmt.Errorf("location, network UUID, host pool UUID, and firewall UUID are required")
	case r.OSName == "" || r.OSVersion == "":
		return fmt.Errorf("OS name and version are required")
	case r.VCPU <= 0 || r.MemoryGiB <= 0 || r.RootDiskGiB <= 0:
		return fmt.Errorf("vCPU, memory, and root disk must be positive")
	case !r.PublicIPv4:
		return fmt.Errorf("public IPv4 allocation is required because InSpace has no managed NAT")
	case r.CloudInitJSON == "":
		return fmt.Errorf("cloud-init JSON is required")
	}
	if err := inspacev1.ValidateSSHAccess(r.SSHUsername, r.SSHPublicKey); err != nil {
		return fmt.Errorf("invalid worker SSH access: %w", err)
	}
	if err := bootstrap.ValidateExternalIPv4Template(r.CloudInitJSON); err != nil {
		return err
	}
	return nil
}

func generatePassword() (string, error) {
	random := make([]byte, passwordByteSize)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	// The fixed prefix satisfies Warren's documented character-class contract;
	// the random suffix supplies 168 bits from crypto/rand. The caller sends the
	// result directly to the API and never stores, hashes, logs, or returns it.
	return "Aa1!" + base64.RawURLEncoding.EncodeToString(random), nil
}

func validateGeneratedPassword(password string) error {
	if len(password) != 32 {
		return fmt.Errorf("must be exactly 32 characters")
	}
	var lower, upper, digit, symbol bool
	for _, character := range password {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case character >= '0' && character <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	if !lower || !upper || !digit || !symbol {
		return fmt.Errorf("must contain lowercase, uppercase, digit, and symbol characters")
	}
	return nil
}

func validateExisting(vm sdk.VM, request cloudapi.CreateVMRequest, actual, expected ownership) error {
	if actual != expected || vm.Name != request.Name || vm.VCPU != request.VCPU || vm.MemoryMiB != request.MemoryGiB*1024 ||
		(vm.OSName != "" && vm.OSName != request.OSName) || (vm.OSVersion != "" && vm.OSVersion != request.OSVersion) ||
		(vm.DesignatedPoolUUID != "" && vm.DesignatedPoolUUID != request.HostPoolUUID) ||
		(vm.NetworkUUID != "" && vm.NetworkUUID != request.NetworkUUID) {
		return fmt.Errorf("owned VM %s exists but launch parameters differ; refusing duplicate create", vm.UUID)
	}
	return nil
}

func validateExistingFloatingIP(floatingIP sdk.FloatingIP, record ownership, vmUUID string) error {
	if floatingIP.Name != record.FloatingIPName || floatingIP.Address != record.PublicIPv4 ||
		(floatingIP.BillingAccountID != 0 && floatingIP.BillingAccountID != record.BillingAccountID) {
		return fmt.Errorf("%w: floating IP recorded by owned VM %s changed", cloudapi.ErrOwnershipMismatch, vmUUID)
	}
	if floatingIP.AssignedTo != "" &&
		(floatingIP.AssignedTo != vmUUID || floatingIP.AssignedToResourceType != "virtual_machine") {
		return fmt.Errorf("%w: floating IP %s is assigned to %s", cloudapi.ErrOwnershipMismatch, floatingIP.Address, floatingIP.AssignedTo)
	}
	return nil
}

func fromSDK(vm *sdk.VM, location string, record ownership) *cloudapi.VM {
	rootDiskGiB := record.RootDiskGiB
	if rootDiskGiB == 0 {
		for _, disk := range vm.Storage {
			if disk.Primary || rootDiskGiB == 0 {
				rootDiskGiB = int32(disk.SizeGiB)
			}
			if disk.Primary {
				break
			}
		}
	}
	osName, osVersion := vm.OSName, vm.OSVersion
	if osName == "" {
		osName = record.OSName
	}
	if osVersion == "" {
		osVersion = record.OSVersion
	}
	return &cloudapi.VM{
		UUID: vm.UUID, Name: vm.Name, ClusterName: record.Cluster, BillingAccountID: record.BillingAccountID,
		NodeClaimName: record.NodeClaim, Location: location, OSName: osName, OSVersion: osVersion,
		HostClass: record.HostClass, InstanceType: record.InstanceType, VCPU: vm.VCPU, MemoryGiB: vm.MemoryMiB / 1024,
		RootDiskGiB: rootDiskGiB, FirewallUUID: record.FirewallUUID, SpecHash: record.SpecHash,
		BootstrapHash: record.BootstrapHash, PublicIPv4: record.PublicIPv4, FloatingIPName: record.FloatingIPName,
		State: mapLifecycle(vm.Status), RawState: vm.Status,
	}
}

func (a *Adapter) ensureFloatingIP(ctx context.Context, request cloudapi.CreateVMRequest) (*sdk.FloatingIP, bool, error) {
	name := floatingIPName(request.ClusterName, request.NodeClaimName)
	if existing, err := a.findFloatingIPByName(ctx, request.Location, name, request.BillingAccountID); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, cloudapi.ErrNotFound) {
		return nil, false, err
	}
	created, createErr := a.api.CreateFloatingIP(ctx, request.Location, sdk.CreateFloatingIPRequest{
		Name: name, BillingAccountID: request.BillingAccountID,
	})
	if createErr != nil {
		if isAmbiguousCreate(createErr) {
			if recovered, recoveryErr := a.findFloatingIPByName(ctx, request.Location, name, request.BillingAccountID); recoveryErr == nil {
				return recovered, true, nil
			}
		}
		return nil, false, fmt.Errorf("creating named floating IP (POST was not retried): %w", createErr)
	}
	if created == nil || created.Address == "" {
		return nil, false, fmt.Errorf("creating named floating IP returned no address")
	}
	created.Name = name
	created.BillingAccountID = request.BillingAccountID
	return created, true, nil
}

func (a *Adapter) ensureProtection(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, floatingIP sdk.FloatingIP) error {
	networkPrefix, err := a.ensureNetworkAttachment(ctx, request.Location, request.NetworkUUID, vmUUID)
	if err != nil {
		return err
	}
	if err := a.ensureFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, networkPrefix); err != nil {
		return err
	}
	if err := a.ensureFloatingAssignment(ctx, request.Location, floatingIP, vmUUID); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) ensureNetworkAttachment(ctx context.Context, location, networkUUID, vmUUID string) (netip.Prefix, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		network, err := a.api.GetNetwork(requestCtx, location, networkUUID)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return netip.Prefix{}, fmt.Errorf(
				"VM %s attachment to network %s read-back stopped: %w", vmUUID, networkUUID, readbackErr,
			)
		}
		if err != nil {
			lastObservation = fmt.Errorf("getting worker network: %w", err)
			if !isRetryableReadback(readbackCtx, err) {
				return netip.Prefix{}, lastObservation
			}
		} else if network == nil {
			return netip.Prefix{}, fmt.Errorf("getting worker network: API returned no network")
		} else {
			if network.UUID != networkUUID {
				return netip.Prefix{}, fmt.Errorf("worker network read-back UUID %q does not match %q", network.UUID, networkUUID)
			}
			networkPrefix, err := netip.ParsePrefix(network.Subnet)
			if err != nil || !isRFC1918Prefix(networkPrefix) {
				return netip.Prefix{}, fmt.Errorf("worker network subnet %q is not RFC1918", network.Subnet)
			}
			membershipCount := 0
			for _, attachedVMUUID := range network.VMUUIDs {
				if attachedVMUUID == vmUUID {
					membershipCount++
				}
			}
			if membershipCount == 1 {
				return networkPrefix, nil
			}
			if membershipCount > 1 {
				return netip.Prefix{}, fmt.Errorf("worker network %s contains VM %s %d times", networkUUID, vmUUID, membershipCount)
			}
			lastObservation = fmt.Errorf("VM %s attachment to network %s is not visible yet", vmUUID, networkUUID)
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return netip.Prefix{}, fmt.Errorf(
				"VM %s attachment to network %s was not visible before the read-back deadline: %w",
				vmUUID, networkUUID, errors.Join(lastObservation, err),
			)
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) ensureFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix) error {
	firewall, err := a.findFirewall(ctx, location, firewallUUID)
	if err != nil {
		return fmt.Errorf("validating worker firewall: %w", err)
	}
	if err := validateDefaultDenyFirewall(*firewall, networkPrefix); err != nil {
		return err
	}
	if firewallHasVM(*firewall, vmUUID) {
		return nil
	}
	if err := a.api.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID); err != nil {
		return fmt.Errorf("assigning firewall %s to VM %s: %w", firewallUUID, vmUUID, err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		firewall, err = a.findFirewall(ctx, location, firewallUUID)
		if err == nil && firewallHasVM(*firewall, vmUUID) {
			return nil
		}
		if err := waitReadback(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("firewall %s assignment to VM %s was not visible after read-back", firewallUUID, vmUUID)
}

func (a *Adapter) ensureFloatingAssignment(ctx context.Context, location string, floatingIP sdk.FloatingIP, vmUUID string) error {
	current, err := a.findFloatingIPByName(ctx, location, floatingIP.Name, floatingIP.BillingAccountID)
	if err != nil {
		return err
	}
	if current.Address != floatingIP.Address {
		return fmt.Errorf("%w: named floating IP address changed", cloudapi.ErrOwnershipMismatch)
	}
	if current.AssignedTo != "" {
		if current.AssignedTo == vmUUID && current.AssignedToResourceType == "virtual_machine" {
			return nil
		}
		return fmt.Errorf("%w: floating IP %s is assigned to %s", cloudapi.ErrOwnershipMismatch, current.Address, current.AssignedTo)
	}
	if _, err := a.api.AssignFloatingIP(ctx, location, current.Address, vmUUID, "virtual_machine"); err != nil {
		return fmt.Errorf("assigning floating IP %s to VM %s: %w", current.Address, vmUUID, err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		current, err = a.findFloatingIPByName(ctx, location, floatingIP.Name, floatingIP.BillingAccountID)
		if err == nil && current.Address == floatingIP.Address && current.AssignedTo == vmUUID && current.AssignedToResourceType == "virtual_machine" {
			return nil
		}
		if err := waitReadback(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("floating IP %s assignment to VM %s was not visible after read-back", floatingIP.Address, vmUUID)
}

func (a *Adapter) cleanupLaunch(ctx context.Context, location, firewallUUID, vmUUID string, floatingIP sdk.FloatingIP, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var errs []error
	floatingErr := a.deleteOwnedFloatingIP(cleanupCtx, location, floatingIP, vmUUID)
	vmDeleteErr := a.api.DeleteVM(cleanupCtx, location, vmUUID)
	if vmDeleteErr != nil && !sdk.IsNotFound(vmDeleteErr) {
		if floatingErr != nil {
			errs = append(errs, floatingErr)
		}
		errs = append(errs, fmt.Errorf("cleanup of unprotected VM %s failed; cloud firewall remains attached: %w", vmUUID, vmDeleteErr))
		return errors.Join(append([]error{cause}, errs...)...)
	}
	if floatingErr != nil {
		floatingErr = a.deleteOwnedFloatingIP(cleanupCtx, location, floatingIP, vmUUID)
	}
	if floatingErr != nil {
		errs = append(errs, floatingErr)
	}
	if err := a.detachFirewallAfterVMDeletion(cleanupCtx, location, firewallUUID, vmUUID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(append([]error{cause}, errs...)...)
}

func (a *Adapter) cleanupUnassignedFloatingIP(ctx context.Context, location string, floatingIP sdk.FloatingIP) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return a.deleteOwnedFloatingIP(cleanupCtx, location, floatingIP, "")
}

func (a *Adapter) detachFirewallAfterVMDeletion(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if firewallUUID != "" {
		firewall, err := a.findFirewall(ctx, location, firewallUUID)
		if err != nil {
			return err
		}
		if !firewallHasVM(*firewall, vmUUID) {
			return nil
		}
		if err := a.api.UnassignFirewallFromVM(ctx, location, firewallUUID, vmUUID); err != nil && !sdk.IsNotFound(err) {
			return fmt.Errorf("cleaning stale firewall %s assignment for deleted VM %s: %w", firewallUUID, vmUUID, err)
		}
		return nil
	}
	// If the VM vanished before ownership could be read, scan only for the
	// exact provider-ID UUID and clean stale assignments after confirming the
	// VM is gone. This never detaches a live VM.
	firewalls, err := a.api.ListFirewalls(ctx, location)
	if err != nil {
		return fmt.Errorf("listing firewalls for deleted VM cleanup: %w", err)
	}
	var errs []error
	for _, firewall := range firewalls {
		if !firewallHasVM(firewall, vmUUID) {
			continue
		}
		if err := a.api.UnassignFirewallFromVM(ctx, location, firewall.UUID, vmUUID); err != nil && !sdk.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("cleaning stale firewall %s assignment for deleted VM %s: %w", firewall.UUID, vmUUID, err))
		}
	}
	return errors.Join(errs...)
}

func (a *Adapter) deleteOwnedFloatingIP(ctx context.Context, location string, floatingIP sdk.FloatingIP, expectedVMUUID string) error {
	current, err := a.findFloatingIPByName(ctx, location, floatingIP.Name, floatingIP.BillingAccountID)
	if err != nil {
		if errors.Is(err, cloudapi.ErrNotFound) {
			return nil
		}
		return err
	}
	if current.Address != floatingIP.Address {
		return fmt.Errorf("%w: refusing to delete changed floating IP %q", cloudapi.ErrOwnershipMismatch, floatingIP.Name)
	}
	if current.AssignedTo != "" {
		if expectedVMUUID == "" || current.AssignedTo != expectedVMUUID || current.AssignedToResourceType != "virtual_machine" {
			return fmt.Errorf("%w: refusing to unassign floating IP %s from %s", cloudapi.ErrOwnershipMismatch, current.Address, current.AssignedTo)
		}
		if _, err := a.api.UnassignFloatingIP(ctx, location, current.Address); err != nil && !sdk.IsNotFound(err) {
			return fmt.Errorf("unassigning floating IP %s: %w", current.Address, err)
		}
	}
	if err := a.api.DeleteFloatingIP(ctx, location, current.Address); err != nil && !sdk.IsNotFound(err) {
		return fmt.Errorf("deleting floating IP %s: %w", current.Address, err)
	}
	return nil
}

func (a *Adapter) findFloatingIPByName(ctx context.Context, location, name string, billingAccountID int64) (*sdk.FloatingIP, error) {
	var filters *sdk.FloatingIPFilters
	if billingAccountID > 0 {
		filters = &sdk.FloatingIPFilters{BillingAccountID: billingAccountID}
	}
	addresses, err := a.api.ListFloatingIPs(ctx, location, filters)
	if err != nil {
		return nil, fmt.Errorf("listing floating IPs: %w", err)
	}
	var matches []sdk.FloatingIP
	for _, address := range addresses {
		if address.Name == name && !address.IsDeleted {
			matches = append(matches, address)
		}
	}
	if len(matches) == 0 {
		return nil, cloudapi.ErrNotFound
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%w: %d floating IPs share owned name %q", cloudapi.ErrOwnershipMismatch, len(matches), name)
	}
	return &matches[0], nil
}

func floatingIPName(clusterName, nodeClaimName string) string {
	base := sanitizeName(nodeClaimName)
	if !strings.HasPrefix(base, "inspace-e2e-") {
		base = "karpenter-" + base
	}
	suffix := hashKey(clusterName + "\x00" + nodeClaimName)[:10]
	const maxBase = 63 - 1 - 10
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + "-" + suffix
}

func sanitizeName(value string) string {
	value = strings.ToLower(value)
	var out strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		} else {
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func (a *Adapter) findFirewall(ctx context.Context, location, uuid string) (*sdk.Firewall, error) {
	// GET-by-UUID currently returns 405; list and match instead.
	firewalls, err := a.api.ListFirewalls(ctx, location)
	if err != nil {
		return nil, fmt.Errorf("listing InSpace firewalls: %w", err)
	}
	for i := range firewalls {
		if firewalls[i].UUID == uuid {
			return &firewalls[i], nil
		}
	}
	return nil, fmt.Errorf("firewall %s is not available in location %s", uuid, location)
}

func firewallHasVM(firewall sdk.Firewall, vmUUID string) bool {
	for _, resource := range firewall.ResourcesAssigned {
		if strings.EqualFold(resource.ResourceType, "vm") && resource.ResourceUUID == vmUUID {
			return true
		}
	}
	return false
}

func validateDefaultDenyFirewall(firewall sdk.Firewall, network netip.Prefix) error {
	inboundAllPorts := map[string]bool{}
	outboundAllPorts := map[string]bool{}
	for _, rule := range firewall.Rules {
		if rule.Direction != "inbound" && rule.Direction != "outbound" {
			return fmt.Errorf("firewall %s has unsupported rule direction %q", firewall.UUID, rule.Direction)
		}
		if rule.Direction == "outbound" {
			if rule.EndpointSpecType == "any" && allPorts(rule) {
				outboundAllPorts[rule.Protocol] = true
			}
			continue
		}
		if rule.Direction != "inbound" {
			continue
		}
		if rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) == 0 {
			return fmt.Errorf("firewall %s has unrestricted inbound rule %s", firewall.UUID, rule.UUID)
		}
		for _, value := range rule.EndpointSpec {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("firewall %s inbound prefix %q is invalid", firewall.UUID, value)
			}
			if isRFC1918Prefix(prefix) {
				if allPorts(rule) && prefixContains(prefix, network) {
					inboundAllPorts[rule.Protocol] = true
				}
				continue
			}
			// A public source is safe only as a single-host allowlist on explicit
			// ports. This supports guarded SSH/E2E access without accepting public
			// any/all-port rules on worker firewalls.
			if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() ||
				(prefix.Addr().Is4() && prefix.Bits() != 32) || (prefix.Addr().Is6() && prefix.Bits() != 128) || allPorts(rule) ||
				rule.PortStart == nil || rule.PortEnd == nil {
				return fmt.Errorf("firewall %s public inbound prefix %q must be a host prefix on explicit ports", firewall.UUID, value)
			}
			if *rule.PortStart < 1 || *rule.PortEnd > 65535 || *rule.PortStart > *rule.PortEnd {
				return fmt.Errorf("firewall %s has invalid public inbound port range", firewall.UUID)
			}
			if rule.Protocol != "tcp" && rule.Protocol != "udp" {
				return fmt.Errorf("firewall %s public inbound rule must use TCP or UDP", firewall.UUID)
			}
		}
	}
	if !inboundAllPorts["tcp"] || !inboundAllPorts["udp"] {
		return fmt.Errorf("firewall %s must allow all inbound TCP and UDP ports from network subnet %s", firewall.UUID, network)
	}
	if !outboundAllPorts["tcp"] || !outboundAllPorts["udp"] {
		return fmt.Errorf("firewall %s must allow all outbound TCP and UDP ports to any endpoint", firewall.UUID)
	}
	return nil
}

func allPorts(rule sdk.FirewallRule) bool {
	return (rule.PortStart == nil && rule.PortEnd == nil) ||
		(rule.PortStart != nil && rule.PortEnd != nil && *rule.PortStart == 1 && *rule.PortEnd == 65535)
}

func prefixContains(outer, inner netip.Prefix) bool {
	return outer.IsValid() && inner.IsValid() && outer.Addr().BitLen() == inner.Addr().BitLen() &&
		outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func isRFC1918Prefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return false
	}
	for _, allowed := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func parseOwnership(description string) (ownership, bool) {
	var record ownership
	if json.Unmarshal([]byte(description), &record) != nil || record.Schema != ownershipSchema || record.Cluster == "" ||
		record.NodeClaim == "" || record.KeyHash == "" || record.FloatingIPName == "" || record.PublicIPv4 == "" {
		return ownership{}, false
	}
	return record, true
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func isAmbiguousCreate(err error) bool {
	var apiErr *sdk.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.Retryable || apiErr.StatusCode == http.StatusRequestTimeout
}

func isRetryableReadback(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, sdk.ErrCrossOriginRedirect) || errors.Is(err, sdk.ErrMutationBlocked) {
		return false
	}
	var apiErr *sdk.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable || apiErr.StatusCode == http.StatusRequestTimeout
	}
	// A non-HTTP error from a GET is a transport or response-read failure. It is
	// safe to retry within the bounded window because reads do not mutate state.
	return true
}

func nextReadbackDelay(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitForReadback(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitReadback(ctx context.Context, attempt int) error {
	if attempt == 4 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func mapLifecycle(value string) cloudapi.LifecycleState {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "running", "started", "online":
		return cloudapi.LifecycleRunning
	case "new", "queued", "pending", "provisioning", "creating", "building", "starting":
		return cloudapi.LifecyclePending
	case "stopping", "shutting_down", "shutting-down":
		return cloudapi.LifecycleStopping
	case "stopped", "off", "shutdown":
		return cloudapi.LifecycleStopped
	case "deleting", "deleted", "terminating":
		return cloudapi.LifecycleDeleting
	case "failed", "error", "errored":
		return cloudapi.LifecycleFailed
	default:
		return cloudapi.LifecycleUnknown
	}
}
