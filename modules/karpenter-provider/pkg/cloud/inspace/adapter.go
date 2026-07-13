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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

const (
	ownershipSchemaNamespace                    = "karpenter.inspace.cloud/"
	ownershipSchema                             = ownershipSchemaNamespace + "v3"
	legacyV2OwnershipSchema                     = ownershipSchemaNamespace + "v2"
	legacyOwnershipSchema                       = ownershipSchemaNamespace + "v1"
	defaultUsername                             = "user"
	passwordByteSize                            = 21
	defaultNetworkAttachmentReadbackTimeout     = 60 * time.Second
	defaultNetworkAttachmentRequestTimeout      = 10 * time.Second
	defaultNetworkAttachmentReadbackMinInterval = 500 * time.Millisecond
	defaultNetworkAttachmentReadbackMaxInterval = 5 * time.Second
	defaultProtectionAuditTimeout               = 15 * time.Second
	defaultLaunchCleanupTimeout                 = 30 * time.Second
	defaultLaunchFloatingIPCleanupTimeout       = 10 * time.Second
	canonicalVMReadConcurrency                  = 8
)

var (
	errWorkerSupervisorVIPCollision  = errors.New("worker private IPv4 collides with the private RKE2 supervisor VIP")
	errWorkerServiceVIPPoolCollision = errors.New("worker private IPv4 collides with the reserved private Service VIP pool")
	errFirewallAssignmentNotVisible  = errors.New("intended worker firewall assignment is not visible")
	errEarlyFirewallProtection       = errors.New("early worker firewall protection failed")
	errFreshOwnershipProof           = errors.New("fresh worker canonical ownership proof failed")
	errPersistedOwnershipIncomplete  = errors.New("persisted VM ownership record is incomplete")
	errVMAbsenceUncertain            = errors.New("VM absence could not be established")
	errFloatingIPCleanupUncertain    = errors.New("floating IP cleanup did not converge")
	errFirewallCleanupUncertain      = errors.New("firewall cleanup did not converge")
	vmUUIDPattern                    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	ownedInstanceTypePattern         = regexp.MustCompile(`^is-(compute|general|memory)-([0-9]+)c-([0-9]+)g$`)
	karpenterOwnershipPrefixPattern  = regexp.MustCompile(`^\s*\{\s*"schema"\s*:\s*"(karpenter\.inspace\.cloud/[^"\s]+)"(?:\s*[,}]|\s*$)`)
	karpenterClusterPattern          = regexp.MustCompile(`"cluster"\s*:\s*"([^"]*)"`)
	fixedClusterNetworks             = [...]struct {
		description string
		prefix      netip.Prefix
	}{
		{description: "Cilium native-routing pod CIDR", prefix: netip.MustParsePrefix(inspacev1.CiliumNativeRoutingPodCIDR)},
		{description: "Kubernetes Service CIDR", prefix: netip.MustParsePrefix(inspacev1.KubernetesServiceCIDR)},
	}
)

type API interface {
	ListHostPools(context.Context, string) ([]sdk.HostPool, error)
	GetNetwork(context.Context, string, string) (*sdk.Network, error)
	ListFirewalls(context.Context, string) ([]sdk.Firewall, error)
	AssignFirewallToVM(context.Context, string, string, string) error
	UnassignFirewallFromVM(context.Context, string, string, string) error

	ListFloatingIPs(context.Context, string, *sdk.FloatingIPFilters) ([]sdk.FloatingIP, error)
	UpdateFloatingIP(context.Context, string, string, sdk.UpdateFloatingIPRequest) (*sdk.FloatingIP, error)
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
	protectionAuditTimeout            time.Duration
	launchCleanupTimeout              time.Duration
	launchFloatingIPCleanupTimeout    time.Duration
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
		protectionAuditTimeout:            defaultProtectionAuditTimeout,
		launchCleanupTimeout:              defaultLaunchCleanupTimeout,
		launchFloatingIPCleanupTimeout:    defaultLaunchFloatingIPCleanupTimeout,
	}, nil
}

type ownership struct {
	Schema                       string `json:"schema"`
	Cluster                      string `json:"cluster"`
	NodeClaim                    string `json:"nodeClaim"`
	VMName                       string `json:"vmName,omitempty"`
	KeyHash                      string `json:"keyHash"`
	HostClass                    string `json:"hostClass"`
	InstanceType                 string `json:"instanceType"`
	HostPoolUUID                 string `json:"hostPoolUUID,omitempty"`
	VCPU                         int    `json:"vCPU,omitempty"`
	MemoryGiB                    int    `json:"memoryGiB,omitempty"`
	RootDiskGiB                  int32  `json:"rootDiskGiB"`
	SpecHash                     string `json:"specHash"`
	BootstrapHash                string `json:"bootstrapHash"`
	FirewallUUID                 string `json:"firewallUUID"`
	NetworkUUID                  string `json:"networkUUID,omitempty"`
	ControlPlaneVIP              string `json:"controlPlaneVIP,omitempty"`
	PrivateLoadBalancerPoolStart string `json:"privateLoadBalancerPoolStart,omitempty"`
	PrivateLoadBalancerPoolStop  string `json:"privateLoadBalancerPoolStop,omitempty"`
	OSName                       string `json:"osName"`
	OSVersion                    string `json:"osVersion"`
	BillingAccountID             int64  `json:"billingAccountID"`
	FloatingIPName               string `json:"floatingIPName"`
	PublicIPv4                   string `json:"publicIPv4,omitempty"`
}

func newOwnership(request cloudapi.CreateVMRequest) ownership {
	return ownership{
		Schema: ownershipSchema, Cluster: request.ClusterName, NodeClaim: request.NodeClaimName, VMName: request.Name,
		KeyHash: hashKey(request.IdempotencyKey), HostClass: request.HostClass, InstanceType: request.InstanceType,
		HostPoolUUID: request.HostPoolUUID, VCPU: request.VCPU, MemoryGiB: request.MemoryGiB,
		RootDiskGiB: request.RootDiskGiB, SpecHash: request.SpecHash, BootstrapHash: request.BootstrapHash,
		FirewallUUID: request.FirewallUUID, NetworkUUID: request.NetworkUUID, ControlPlaneVIP: request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: request.PrivateLoadBalancerPoolStop,
		OSName: request.OSName, OSVersion: request.OSVersion,
		BillingAccountID: request.BillingAccountID, FloatingIPName: floatingIPName(request.ClusterName, request.NodeClaimName),
	}
}

func (a *Adapter) CreateVM(ctx context.Context, request cloudapi.CreateVMRequest) (*cloudapi.VM, error) {
	if err := validateCreateRequest(request); err != nil {
		return nil, err
	}
	networkPrefix, err := a.validateNodeClass(ctx, request.Location, request.NetworkUUID, request.ControlPlaneVIP, request.PrivateLoadBalancerPoolStart, request.PrivateLoadBalancerPoolStop, request.HostPoolUUID, request.FirewallUUID)
	if err != nil {
		return nil, fmt.Errorf("preflight NodeClass infrastructure: %w", err)
	}
	resolvedCloudInit, err := bootstrap.ResolveVPCSubnet(request.CloudInitJSON, networkPrefix.String())
	if err != nil {
		return nil, fmt.Errorf("resolving exact worker VPC subnet: %w", err)
	}
	request.CloudInitJSON = resolvedCloudInit
	record := newOwnership(request)
	if existing, actual, err := a.findOwnedVM(ctx, request); err != nil {
		return nil, err
	} else if existing != nil {
		if err := validateExisting(*existing, request, actual, record); err != nil {
			return nil, err
		}
		return a.completeOwnedVM(ctx, request, *existing, actual, record, networkPrefix, false, true)
	}
	description, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encoding VM ownership: %w", err)
	}

	if existing, err := a.findCreate(ctx, request, record, networkPrefix, false); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	if err := a.rejectActiveFloatingIPNameCollision(ctx, request.Location, record.FloatingIPName); err != nil {
		return nil, err
	}
	if err := a.preflightFreshFirewall(ctx, request.Location, request.FirewallUUID, networkPrefix); err != nil {
		return nil, err
	}

	// InSpace has no NAT service. VM creation atomically reserves and assigns
	// one public address; the provider discovers and names that address from the
	// authoritative assignment after the VM identity is durable.
	reservePublicIP := true
	username := request.SSHUsername
	if username == "" {
		username = defaultUsername
	}
	password, err := a.generatePassword()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral VM password: %w", err)
	}
	if err := validateGeneratedPassword(password); err != nil {
		return nil, fmt.Errorf("generated ephemeral VM password is invalid: %w", err)
	}
	created, createErr := a.api.CreateVM(ctx, request.Location, sdk.CreateVMRequest{
		Name: request.Name, Description: string(description), OSName: request.OSName, OSVersion: request.OSVersion,
		DiskGiB: int(request.RootDiskGiB), VCPU: request.VCPU, MemoryMiB: request.MemoryGiB * 1024,
		DesignatedPoolUUID: request.HostPoolUUID, NetworkUUID: request.NetworkUUID,
		Username: username, Password: password, PublicKey: request.SSHPublicKey,
		BillingAccountID: request.BillingAccountID, CloudInit: request.CloudInitJSON, ReservePublicIP: &reservePublicIP,
	})
	if createErr != nil {
		if created != nil && vmUUIDPattern.MatchString(created.UUID) {
			if recovered, recoveryErr := a.recoverAmbiguousResponseUUID(ctx, request, record, networkPrefix, created.UUID); recoveryErr == nil && recovered != nil {
				return recovered, nil
			} else if recoveryErr != nil {
				return nil, errors.Join(fmt.Errorf("creating InSpace VM returned UUID %s with an error: %w", created.UUID, createErr), recoveryErr)
			}
		}
		// A retryable/transport response may be ambiguous. Recover with reads
		// only; never issue a second VM POST in this call. If the VM is not yet
		// visible, preserve the possible VM and its implicit assigned address so
		// the next reconciliation can adopt it by the durable ownership record.
		if isAmbiguousCreate(createErr) {
			if recovered, recoveryErr := a.findCreate(ctx, request, record, networkPrefix, true); recoveryErr == nil && recovered != nil {
				return recovered, nil
			} else if recoveryErr != nil {
				return nil, errors.Join(fmt.Errorf("creating InSpace VM had an ambiguous outcome: %w", createErr), recoveryErr)
			}
			return nil, fmt.Errorf("creating InSpace VM had an ambiguous outcome; preserving possible VM and auto-reserved floating IP for reconciliation: %w", createErr)
		}
		return nil, fmt.Errorf("creating InSpace VM (POST was not retried): %w", createErr)
	}
	if created == nil || !vmUUIDPattern.MatchString(created.UUID) {
		if recovered, recoveryErr := a.findCreate(ctx, request, record, networkPrefix, true); recoveryErr == nil && recovered != nil {
			return recovered, nil
		} else if recoveryErr != nil {
			return nil, fmt.Errorf("creating InSpace VM returned no valid UUID; protective recovery failed: %w", recoveryErr)
		}
		return nil, fmt.Errorf("creating InSpace VM returned no valid UUID; protective recovery remains uncertain")
	}
	// A create response may be sparse and is not durable ownership authority.
	// Use only its UUID, immediately attach the prevalidated firewall, then
	// require the subsequent VM detail read to contain the complete, exact v3
	// ownership record before ownership-sensitive mutations. The detail endpoint
	// may omit its redundant top-level network field; exact VPC membership is
	// proved separately before any FIP mutation.
	persisted, floatingIP, ownershipProven, err := a.ensureProtection(ctx, request, created.UUID, record, networkPrefix, nil, true)
	if err != nil {
		unsafeAddressCollision := errors.Is(err, errWorkerSupervisorVIPCollision) || errors.Is(err, errWorkerServiceVIPPoolCollision)
		if ownershipProven && (unsafeAddressCollision || errors.Is(err, errEarlyFirewallProtection) || errors.Is(err, errFreshOwnershipProof)) {
			return nil, a.cleanupProvenAutoLaunch(ctx, request, created.UUID, floatingIP, err)
		}
		if ownershipProven && exactNamedFloatingIP(floatingIP, record) {
			return nil, a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, created.UUID, *floatingIP, err)
		}
		return nil, fmt.Errorf("protecting newly created worker VM %s: %w", created.UUID, err)
	}
	record.PublicIPv4 = floatingIP.Address
	return fromSDK(persisted, request.Location, record), nil
}

func (a *Adapter) recoverAmbiguousResponseUUID(ctx context.Context, request cloudapi.CreateVMRequest, expected ownership, networkPrefix netip.Prefix, vmUUID string) (*cloudapi.VM, error) {
	// A UUID returned alongside a transport/retryable error is authority only
	// for the non-destructive protection mutation. Canonical v3 detail must
	// still converge before adoption or rollback is authorized.
	protectionErr := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, networkPrefix)
	persisted, proofErr := a.ensurePersistedVMIdentity(context.WithoutCancel(ctx), request, vmUUID, expected, nil)
	if proofErr != nil {
		return nil, fmt.Errorf("ambiguous VM %s protection/ownership remains uncertain: %w", vmUUID, errors.Join(protectionErr, proofErr))
	}
	if protectionErr != nil {
		return nil, a.cleanupProvenAutoLaunch(ctx, request, vmUUID, nil, errors.Join(errEarlyFirewallProtection, protectionErr))
	}
	return a.completeOwnedVM(ctx, request, *persisted, expected, expected, networkPrefix, true, false)
}

func (a *Adapter) rejectActiveFloatingIPNameCollision(ctx context.Context, location, expectedName string) error {
	addresses, err := a.api.ListFloatingIPs(ctx, location, nil)
	if err != nil {
		return fmt.Errorf("listing floating IPs before worker VM create: %w", err)
	}
	for i := range addresses {
		if !addresses[i].IsDeleted && addresses[i].Name == expectedName {
			return fmt.Errorf("%w: active floating IP %q already exists before worker VM create", cloudapi.ErrOwnershipMismatch, expectedName)
		}
	}
	return nil
}

func (a *Adapter) preflightFreshFirewall(ctx context.Context, location, firewallUUID string, networkPrefix netip.Prefix) error {
	firewalls, err := a.api.ListFirewalls(ctx, location)
	if err != nil {
		return fmt.Errorf("listing InSpace firewalls immediately before worker VM create: %w", err)
	}
	firewall, err := findFirewallInList(firewalls, firewallUUID, location)
	if err != nil {
		return fmt.Errorf("validating worker firewall immediately before VM create: %w", err)
	}
	if err := validateDefaultDenyFirewall(*firewall, networkPrefix); err != nil {
		return fmt.Errorf("validating worker firewall immediately before VM create: %w", err)
	}
	return nil
}

func (a *Adapter) findCreate(ctx context.Context, request cloudapi.CreateVMRequest, expected ownership, networkPrefix netip.Prefix, rollbackNewLaunch bool) (*cloudapi.VM, error) {
	if rollbackNewLaunch {
		summary, err := a.findOwnedVMSummary(ctx, request)
		if err != nil {
			return nil, err
		}
		if summary == nil {
			return nil, fmt.Errorf("ambiguous VM create protection remains uncertain: no unique VM UUID is visible for deterministic name %q", request.Name)
		}
		// A unique deterministic list identity is sufficient only to apply the
		// prevalidated firewall. Destructive/adoption authority still requires
		// canonical v3 detail below.
		protectionErr := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, summary.UUID, networkPrefix)
		vm, actual, proofErr := a.readCanonicalCreateCandidate(context.WithoutCancel(ctx), request, *summary)
		if proofErr != nil {
			return nil, fmt.Errorf("ambiguous VM %s protection/ownership remains uncertain: %w", summary.UUID, errors.Join(protectionErr, proofErr))
		}
		if err := validateExisting(*vm, request, actual, expected); err != nil {
			return nil, err
		}
		if protectionErr != nil {
			if authorityErr := a.ensureReadDiscoveredCleanupNetworkAuthority(ctx, request, vm.UUID); authorityErr != nil {
				return nil, fmt.Errorf("ambiguous VM %s firewall recovery failed but destructive cleanup is not authorized: %w", vm.UUID, errors.Join(errEarlyFirewallProtection, protectionErr, authorityErr))
			}
			return nil, a.cleanupProvenAutoLaunch(ctx, request, vm.UUID, nil, errors.Join(errEarlyFirewallProtection, protectionErr))
		}
		return a.completeOwnedVM(ctx, request, *vm, actual, expected, networkPrefix, true, true)
	}
	vm, actual, err := a.findOwnedVM(ctx, request)
	if err != nil || vm == nil {
		return nil, err
	}
	if err := validateExisting(*vm, request, actual, expected); err != nil {
		return nil, err
	}
	return a.completeOwnedVM(ctx, request, *vm, actual, expected, networkPrefix, rollbackNewLaunch, true)
}

func (a *Adapter) completeOwnedVM(ctx context.Context, request cloudapi.CreateVMRequest, vm sdk.VM, actual, expected ownership, networkPrefix netip.Prefix, rollbackNewLaunch, readDiscovered bool) (*cloudapi.VM, error) {
	persisted, floatingIP, ownershipProven, err := a.ensureProtection(ctx, request, vm.UUID, expected, networkPrefix, &vm, false)
	if err != nil {
		unsafeAddressCollision := actual.ControlPlaneVIP != "" &&
			(errors.Is(err, errWorkerSupervisorVIPCollision) || errors.Is(err, errWorkerServiceVIPPoolCollision))
		unprotectedAfterAssignment := errors.Is(err, errEarlyFirewallProtection) && errors.Is(err, errFirewallAssignmentNotVisible)
		if ownershipProven && (rollbackNewLaunch || unprotectedAfterAssignment) && (unsafeAddressCollision || errors.Is(err, errEarlyFirewallProtection)) {
			if readDiscovered && errors.Is(err, errEarlyFirewallProtection) {
				if authorityErr := a.ensureReadDiscoveredCleanupNetworkAuthority(ctx, request, vm.UUID); authorityErr != nil {
					return nil, fmt.Errorf("owned VM %s firewall recovery failed but destructive cleanup is not authorized: %w", vm.UUID, errors.Join(err, authorityErr))
				}
			}
			return nil, a.cleanupProvenAutoLaunch(ctx, request, vm.UUID, floatingIP, err)
		}
		if ownershipProven && rollbackNewLaunch && exactNamedFloatingIP(floatingIP, expected) {
			return nil, a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, vm.UUID, *floatingIP, err)
		}
		return nil, fmt.Errorf("verifying protection for owned VM %s: %w", vm.UUID, err)
	}
	actual.PublicIPv4 = floatingIP.Address
	return fromSDK(persisted, request.Location, actual), nil
}

// ensureReadDiscoveredCleanupNetworkAuthority requires stronger authority than
// either an omitted or echoed top-level NetworkUUID. Canonical v3 ownership
// proves intent, but a read-discovered UUID is not destructive authority by
// itself. Before an early-firewall failure may PATCH/delete its FIP or delete
// the VM, the specifically configured VPC must contain that UUID exactly once.
// A UUID returned directly by the current CreateVM POST does not use this guard
// because that response is the invocation's launch anchor.
func (a *Adapter) ensureReadDiscoveredCleanupNetworkAuthority(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string) error {
	vip, err := validateControlPlaneVIP(request.ControlPlaneVIP)
	if err != nil {
		return err
	}
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{
		Start: request.PrivateLoadBalancerPoolStart,
		Stop:  request.PrivateLoadBalancerPoolStop,
	}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return fmt.Errorf("private load-balancer pool: %w", err)
	}
	if _, err := a.ensureNetworkAttachment(context.WithoutCancel(ctx), request.Location, request.NetworkUUID, vmUUID, vip, privateLoadBalancerPool); err != nil {
		return fmt.Errorf("read-discovered VM %s lacks exact membership in configured network %s: %w", vmUUID, request.NetworkUUID, err)
	}
	return nil
}

func exactNamedFloatingIP(floatingIP *sdk.FloatingIP, record ownership) bool {
	return floatingIP != nil && floatingIP.Name == record.FloatingIPName &&
		floatingIP.BillingAccountID == record.BillingAccountID && floatingIP.Address != ""
}

// cleanupProvenAutoLaunch is called only for a VM authorized either by the
// fresh POST UUID or by canonical v3 ownership. First give its auto-reserved
// address a detached, bounded chance to become durably nameable. If the FIP
// remains invisible or ambiguous, never guess at an address mutation: delete
// the public VM anyway and report the dependent cleanup uncertainty.
func (a *Adapter) cleanupProvenAutoLaunch(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, floatingIP *sdk.FloatingIP, cause error) error {
	expected := newOwnership(request)
	if exactNamedFloatingIP(floatingIP, expected) {
		return a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, vmUUID, *floatingIP, cause)
	}
	var discoveryErr error
	if floatingIP == nil || floatingIP.Name == "" || floatingIP.BillingAccountID != request.BillingAccountID {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchFloatingIPCleanupTimeout)
		floatingIP, discoveryErr = a.ensureAutoFloatingIPForCleanup(cleanupCtx, request.Location, vmUUID, expected.FloatingIPName, request.BillingAccountID)
		cancel()
	}
	if exactNamedFloatingIP(floatingIP, expected) {
		return a.cleanupLaunch(ctx, request.Location, request.FirewallUUID, vmUUID, *floatingIP, errors.Join(cause, discoveryErr))
	}
	if discoveryErr == nil {
		discoveryErr = fmt.Errorf("auto-reserved floating IP for VM %s has no exact durable name/address/account cleanup anchor", vmUUID)
	}
	return a.cleanupLaunchWithoutFloatingIP(ctx, request.Location, request.FirewallUUID, vmUUID, cause, discoveryErr)
}

func (a *Adapter) cleanupLaunchWithoutFloatingIP(ctx context.Context, location, firewallUUID, vmUUID string, cause, floatingUncertainty error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchCleanupTimeout)
	defer cancel()
	var errs []error
	vmDeleteErr := a.api.DeleteVM(cleanupCtx, location, vmUUID)
	if vmDeleteErr != nil {
		errs = append(errs, fmt.Errorf("deleting public VM %s without a safe floating IP anchor: %w", vmUUID, vmDeleteErr))
	}
	if absenceErr := a.waitForVMAbsence(cleanupCtx, location, vmUUID, "after security-priority launch rollback"); absenceErr != nil {
		errs = append(errs, fmt.Errorf("cleanup of public VM %s did not prove absence; cloud firewall remains attached: %w", vmUUID, absenceErr))
		return errors.Join(append([]error{cause, fmt.Errorf("floating IP cleanup remains uncertain: %w", floatingUncertainty)}, errs...)...)
	}
	if err := a.detachFirewallAfterVMDeletion(cleanupCtx, location, firewallUUID, vmUUID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(append([]error{cause, fmt.Errorf("floating IP cleanup remains uncertain after VM deletion: %w", floatingUncertainty)}, errs...)...)
}

func (a *Adapter) findOwnedVM(ctx context.Context, request cloudapi.CreateVMRequest) (*sdk.VM, ownership, error) {
	summary, err := a.findOwnedVMSummary(ctx, request)
	if err != nil || summary == nil {
		return nil, ownership{}, err
	}
	vm, record, err := a.readCanonicalCreateCandidate(ctx, request, *summary)
	if err != nil {
		return nil, ownership{}, fmt.Errorf("refusing create: canonical detail for listed VM %q: %w", summary.Name, err)
	}
	return vm, record, nil
}

func (a *Adapter) findOwnedVMSummary(ctx context.Context, request cloudapi.CreateVMRequest) (*sdk.VM, error) {
	vms, err := a.api.ListVMs(ctx, request.Location)
	if err != nil {
		return nil, fmt.Errorf("listing VMs before create: %w", err)
	}
	if err := validateVMListSnapshot(vms); err != nil {
		return nil, fmt.Errorf("validating VM list before create: %w", err)
	}
	var candidates []sdk.VM
	keyHash := hashKey(request.IdempotencyKey)
	for i := range vms {
		record, managed := parseOwnership(vms[i].Description)
		listOwnershipCandidate := managed && record.Cluster == request.ClusterName &&
			record.NodeClaim == request.NodeClaimName && record.KeyHash == keyHash
		if vms[i].Name == request.Name || listOwnershipCandidate {
			candidates = append(candidates, vms[i])
		}
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("refusing create: %d VM list rows match the deterministic name or Karpenter ownership key", len(candidates))
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	copy := candidates[0]
	return &copy, nil
}

func validateVMListSnapshot(vms []sdk.VM) error {
	uuids := make(map[string]bool, len(vms))
	for i := range vms {
		if !vmUUIDPattern.MatchString(vms[i].UUID) {
			return fmt.Errorf("VM list row %d has invalid UUID %q", i, vms[i].UUID)
		}
		if uuids[vms[i].UUID] {
			return fmt.Errorf("VM list contains duplicate UUID %s", vms[i].UUID)
		}
		uuids[vms[i].UUID] = true
	}
	return nil
}

// readCanonicalCreateCandidate treats ListVMs only as location-wide discovery
// and collision evidence. Ownership, launch identity, and adoption authority
// all come from bounded GetVM detail reads for the exact listed UUID.
func (a *Adapter) readCanonicalCreateCandidate(ctx context.Context, request cloudapi.CreateVMRequest, summary sdk.VM) (*sdk.VM, ownership, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, request.Location, summary.UUID)
		requestCancel()
		var currentObservation error
		if err != nil {
			currentObservation = fmt.Errorf("getting canonical VM %s: %w", summary.UUID, err)
		}
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, ownership{}, fmt.Errorf("canonical VM %s read-back stopped: %w", summary.UUID, errors.Join(lastObservation, currentObservation, readbackErr))
		}
		switch {
		case err != nil:
			if !sdk.IsNotFound(err) && !isRetryableReadback(readbackCtx, err) {
				return nil, ownership{}, currentObservation
			}
			lastObservation = currentObservation
		case vm == nil:
			lastObservation = fmt.Errorf("%w: canonical VM %s detail response is empty: %w", cloudapi.ErrOwnershipMismatch, summary.UUID, errPersistedOwnershipIncomplete)
		case vm.UUID != summary.UUID:
			return nil, ownership{}, fmt.Errorf("%w: canonical VM detail UUID %q does not match listed UUID %q", cloudapi.ErrOwnershipMismatch, vm.UUID, summary.UUID)
		case summary.Name != "" && vm.Name != "" && vm.Name != summary.Name:
			return nil, ownership{}, fmt.Errorf("%w: canonical VM detail name %q does not match listed name %q", cloudapi.ErrOwnershipMismatch, vm.Name, summary.Name)
		default:
			var actual ownership
			_ = json.Unmarshal([]byte(vm.Description), &actual)
			expected := newOwnership(request)
			validationErr := validatePersistedVM(*vm, summary.UUID, request, expected)
			if errors.Is(validationErr, errPersistedOwnershipIncomplete) {
				lastObservation = validationErr
			} else if validationErr != nil {
				return nil, ownership{}, validationErr
			} else {
				return vm, actual, nil
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, ownership{}, fmt.Errorf("canonical VM %s ownership did not converge before the read-back deadline: %w", summary.UUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) GetVM(ctx context.Context, location, uuid, clusterName string) (*cloudapi.VM, error) {
	vm, record, err := a.readEstablishedVM(ctx, location, uuid, clusterName)
	if err != nil {
		return nil, err
	}
	owned := []ownedVM{{vm: *vm, record: record}}
	if err := a.auditEstablishedVMProtections(ctx, location, owned); err != nil {
		return nil, err
	}
	return fromSDK(vm, location, owned[0].record), nil
}

// readEstablishedVM gives eventually consistent detail fields a bounded
// chance to converge. Missing ownership or launch fields are uncertainty;
// every supplied conflict remains an immediate, fail-closed error.
func (a *Adapter) readEstablishedVM(ctx context.Context, location, uuid, clusterName string) (*sdk.VM, ownership, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.protectionAuditTimeout)
	defer cancel()
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, ownership{}, fmt.Errorf("canonical VM %s established read-back stopped: %w", uuid, errors.Join(lastObservation, readbackErr))
		}
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, location, uuid)
		requestCancel()
		if err != nil {
			if sdk.IsNotFound(err) {
				return nil, ownership{}, cloudapi.ErrNotFound
			}
			if readbackErr := readbackCtx.Err(); readbackErr != nil {
				observation := fmt.Errorf("reading canonical detail for established VM %s: %w", uuid, err)
				return nil, ownership{}, fmt.Errorf("canonical VM %s established read-back stopped: %w", uuid, errors.Join(lastObservation, observation, readbackErr))
			}
			if !isRetryableReadback(readbackCtx, err) {
				return nil, ownership{}, err
			}
			lastObservation = fmt.Errorf("reading canonical detail for established VM %s: %w", uuid, err)
		} else if vm == nil {
			lastObservation = fmt.Errorf("%w: canonical VM %s detail response is empty: %w", cloudapi.ErrOwnershipMismatch, uuid, errPersistedOwnershipIncomplete)
		} else if vm.UUID != uuid {
			return nil, ownership{}, fmt.Errorf("%w: canonical VM %s returned detail UUID %q", cloudapi.ErrOwnershipMismatch, uuid, vm.UUID)
		} else {
			record, managed, complete, err := inspectOwnershipDescription(vm.Description, clusterName)
			if err != nil {
				return nil, ownership{}, fmt.Errorf("canonical VM %s ownership: %w", uuid, err)
			}
			if !managed || record.Cluster != clusterName {
				return nil, ownership{}, fmt.Errorf("%w: VM %s is not managed for cluster %q", cloudapi.ErrOwnershipMismatch, uuid, clusterName)
			}
			switch {
			case !complete:
				lastObservation = fmt.Errorf("%w: established worker VM %s lacks complete persisted ownership: %w", cloudapi.ErrOwnershipMismatch, uuid, errPersistedOwnershipIncomplete)
			default:
				validationErr := validateEstablishedLaunchIdentity(*vm, record)
				if validationErr == nil {
					return vm, record, nil
				}
				if !errors.Is(validationErr, errPersistedOwnershipIncomplete) {
					return nil, ownership{}, fmt.Errorf("established worker VM %s launch identity drift: %w", uuid, validationErr)
				}
				lastObservation = fmt.Errorf("established worker VM %s launch identity has not converged: %w", uuid, validationErr)
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, ownership{}, fmt.Errorf("canonical VM %s established identity did not converge before the read-back deadline: %w", uuid, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) ListVMs(ctx context.Context, location, clusterName string) ([]*cloudapi.VM, error) {
	listed, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return nil, err
	}
	vms, err := a.canonicalListedVMDetails(ctx, location, clusterName, listed)
	if err != nil {
		return nil, err
	}
	owned := make([]ownedVM, 0, len(vms))
	for i := range vms {
		record, managed, complete, err := inspectOwnershipDescription(vms[i].Description, clusterName)
		if err != nil {
			return nil, fmt.Errorf("canonical VM %s ownership: %w", vms[i].UUID, err)
		}
		if managed && record.Cluster == clusterName {
			if !complete {
				return nil, fmt.Errorf("%w: established worker VM %s lacks complete persisted ownership: %w", cloudapi.ErrOwnershipMismatch, vms[i].UUID, errPersistedOwnershipIncomplete)
			}
			if err := validateEstablishedLaunchIdentity(vms[i], record); err != nil {
				return nil, fmt.Errorf("established worker VM %s launch identity drift: %w", vms[i].UUID, err)
			}
			owned = append(owned, ownedVM{vm: vms[i], record: record})
		}
	}
	if err := a.auditEstablishedVMProtections(ctx, location, owned); err != nil {
		return nil, err
	}
	result := make([]*cloudapi.VM, 0, len(owned))
	for i := range owned {
		result = append(result, fromSDK(&owned[i].vm, location, owned[i].record))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	return result, nil
}

func (a *Adapter) canonicalListedVMDetails(ctx context.Context, location, clusterName string, listed []sdk.VM) ([]sdk.VM, error) {
	if err := validateVMListSnapshot(listed); err != nil {
		return nil, fmt.Errorf("validating VM list for canonical read audit: %w", err)
	}
	auditCtx, cancel := context.WithTimeout(ctx, a.protectionAuditTimeout)
	defer cancel()
	workerCtx, cancelWorkers := context.WithCancel(auditCtx)
	defer cancelWorkers()
	summaries := append([]sdk.VM(nil), listed...)
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].UUID < summaries[j].UUID })
	details := make([]*sdk.VM, len(summaries))
	errs := make([]error, len(summaries))
	jobs := make(chan int, len(summaries))
	for index := range summaries {
		jobs <- index
	}
	close(jobs)
	workers := canonicalVMReadConcurrency
	if len(summaries) < workers {
		workers = len(summaries)
	}
	var reads sync.WaitGroup
	var firstErr error
	var firstErrOnce sync.Once
	for range workers {
		reads.Add(1)
		go func() {
			defer reads.Done()
			for index := range jobs {
				details[index], errs[index] = a.readCanonicalListedVM(workerCtx, location, clusterName, summaries[index])
				if errs[index] != nil {
					firstErrOnce.Do(func() {
						firstErr = errs[index]
						cancelWorkers()
					})
				}
			}
		}()
	}
	reads.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	result := make([]sdk.VM, 0, len(details))
	for i := range details {
		if errs[i] != nil {
			return nil, errs[i]
		}
		if details[i] != nil {
			result = append(result, *details[i])
		}
	}
	return result, nil
}

// readCanonicalListedVM lets an authoritative 404 remove a stale list row and
// lets definitively unmanaged descriptions pass through for the caller to
// ignore. Once either the list row or a detail response carries Karpenter
// ownership evidence, however, an incomplete canonical record is uncertainty:
// poll it within the shared ListVMs bound and fail closed if it never converges.
func (a *Adapter) readCanonicalListedVM(ctx context.Context, location, clusterName string, summary sdk.VM) (*sdk.VM, error) {
	listedRecord, listedKarpenter, listedRecordComplete, err := inspectOwnershipDescription(summary.Description, clusterName)
	if err != nil {
		return nil, fmt.Errorf("listed VM %s ownership: %w", summary.UUID, err)
	}
	ownershipEvidence := listedKarpenter && (listedRecord.Cluster == "" || listedRecord.Cluster == clusterName)
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		if readbackErr := ctx.Err(); readbackErr != nil {
			return nil, fmt.Errorf("canonical VM %s list read-back stopped: %w", summary.UUID, errors.Join(lastObservation, readbackErr))
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, location, summary.UUID)
		requestCancel()
		var currentObservation error
		if err != nil {
			currentObservation = fmt.Errorf("reading canonical detail for listed VM %s: %w", summary.UUID, err)
		}
		if readbackErr := ctx.Err(); readbackErr != nil {
			return nil, fmt.Errorf("canonical VM %s list read-back stopped: %w", summary.UUID, errors.Join(lastObservation, currentObservation, readbackErr))
		}
		if sdk.IsNotFound(err) {
			// The list row became stale after the snapshot. Canonical current
			// state says the VM is absent, so omitting it is authoritative.
			return nil, nil
		}
		if err != nil {
			if ownershipEvidence && isRetryableReadback(ctx, err) {
				lastObservation = currentObservation
				if err := waitForReadback(ctx, readbackDelay); err != nil {
					return nil, fmt.Errorf("canonical VM %s Karpenter ownership did not converge before the list read-back deadline: %w", summary.UUID, errors.Join(lastObservation, err))
				}
				readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
				continue
			}
			return nil, currentObservation
		}
		if vm == nil {
			if ownershipEvidence {
				lastObservation = fmt.Errorf("%w: canonical detail for listed VM %s is empty: %w", cloudapi.ErrOwnershipMismatch, summary.UUID, errPersistedOwnershipIncomplete)
				if err := waitForReadback(ctx, readbackDelay); err != nil {
					return nil, fmt.Errorf("canonical VM %s Karpenter ownership did not converge before the list read-back deadline: %w", summary.UUID, errors.Join(lastObservation, err))
				}
				readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
				continue
			}
			return nil, fmt.Errorf("%w: canonical detail for listed VM %s is empty", cloudapi.ErrOwnershipMismatch, summary.UUID)
		}
		if vm.UUID != summary.UUID || (summary.Name != "" && vm.Name != "" && vm.Name != summary.Name) {
			return nil, fmt.Errorf("%w: canonical detail identity for listed VM %s/%q does not match its list row", cloudapi.ErrOwnershipMismatch, summary.UUID, summary.Name)
		}
		record, canonicalKarpenter, canonicalRecordComplete, err := inspectOwnershipDescription(vm.Description, clusterName)
		if err != nil {
			return nil, fmt.Errorf("canonical VM %s ownership: %w", summary.UUID, err)
		}
		if canonicalKarpenter && record.Cluster != "" && record.Cluster != clusterName && !ownershipEvidence {
			// With no list-side target or ambiguous ownership evidence, an
			// explicit record for another cluster is foreign to this query.
			// Its cluster and unrelated ownership fields may legitimately
			// change without blocking target-cluster inventory.
			return vm, nil
		}
		if listedKarpenter && canonicalKarpenter && listedRecord.Cluster != "" && record.Cluster != "" && listedRecord.Cluster != record.Cluster {
			return nil, fmt.Errorf("%w: canonical Karpenter cluster %q for listed VM %s differs from list cluster %q", cloudapi.ErrOwnershipMismatch, record.Cluster, summary.UUID, listedRecord.Cluster)
		}
		if listedRecordComplete && canonicalRecordComplete && listedRecord != record {
			return nil, fmt.Errorf("%w: canonical Karpenter ownership for listed VM %s differs from its complete list record", cloudapi.ErrOwnershipMismatch, summary.UUID)
		}
		if canonicalRecordComplete && record.Cluster == clusterName {
			validationErr := validateEstablishedLaunchIdentity(*vm, record)
			if validationErr == nil {
				return vm, nil
			}
			if !errors.Is(validationErr, errPersistedOwnershipIncomplete) {
				return nil, fmt.Errorf("established worker VM %s launch identity drift: %w", summary.UUID, validationErr)
			}
			ownershipEvidence = true
			lastObservation = fmt.Errorf("established worker VM %s launch identity has not converged: %w", summary.UUID, validationErr)
			if err := waitForReadback(ctx, readbackDelay); err != nil {
				return nil, fmt.Errorf("canonical VM %s established identity did not converge before the list read-back deadline: %w", summary.UUID, errors.Join(lastObservation, err))
			}
			readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
			continue
		}
		canonicalTargetsCluster := canonicalKarpenter && (record.Cluster == "" || record.Cluster == clusterName)
		if !ownershipEvidence && !canonicalTargetsCluster {
			// A non-Karpenter description is authoritative unmanaged inventory,
			// not an account-wide reason to fail a cluster-scoped list.
			return vm, nil
		}
		ownershipEvidence = true
		lastObservation = fmt.Errorf("%w: canonical detail for listed VM %s lacks a complete Karpenter ownership record: %w", cloudapi.ErrOwnershipMismatch, summary.UUID, errPersistedOwnershipIncomplete)
		if err := waitForReadback(ctx, readbackDelay); err != nil {
			return nil, fmt.Errorf("canonical VM %s Karpenter ownership did not converge before the list read-back deadline: %w", summary.UUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

type ownedVM struct {
	vm     sdk.VM
	record ownership
}

func (a *Adapter) auditEstablishedVMProtections(ctx context.Context, location string, owned []ownedVM) error {
	if len(owned) == 0 {
		return nil
	}
	auditCtx, cancel := context.WithTimeout(ctx, a.protectionAuditTimeout)
	defer cancel()
	firewalls, err := a.api.ListFirewalls(auditCtx, location)
	if err != nil {
		return fmt.Errorf("auditing established worker firewalls: %w", err)
	}
	addresses, err := a.api.ListFloatingIPs(auditCtx, location, nil)
	if err != nil {
		return fmt.Errorf("auditing established worker floating IPs: %w", err)
	}
	networks := map[string]*sdk.Network{}
	for _, item := range owned {
		if item.record.NetworkUUID == "" || item.record.ControlPlaneVIP == "" || item.record.PrivateLoadBalancerPoolStart == "" || item.record.PrivateLoadBalancerPoolStop == "" {
			return fmt.Errorf("%w: owned VM %s lacks recorded VPC, RKE2 supervisor VIP, or private Service pool", cloudapi.ErrOwnershipMismatch, item.vm.UUID)
		}
		if _, exists := networks[item.record.NetworkUUID]; exists {
			continue
		}
		network, err := a.api.GetNetwork(auditCtx, location, item.record.NetworkUUID)
		if err != nil {
			return fmt.Errorf("auditing established worker network %s: %w", item.record.NetworkUUID, err)
		}
		if network == nil || network.UUID != item.record.NetworkUUID {
			return fmt.Errorf("%w: established worker network %s returned invalid identity", cloudapi.ErrOwnershipMismatch, item.record.NetworkUUID)
		}
		networks[item.record.NetworkUUID] = network
	}
	for i := range owned {
		publicIPv4, err := auditEstablishedVMProtection(owned[i].vm, owned[i].record, networks[owned[i].record.NetworkUUID], firewalls, addresses)
		if err != nil {
			return fmt.Errorf("established worker VM %s protection drift: %w", owned[i].vm.UUID, err)
		}
		owned[i].record.PublicIPv4 = publicIPv4
	}
	return nil
}

func auditEstablishedVMProtection(vm sdk.VM, record ownership, network *sdk.Network, firewalls []sdk.Firewall, addresses []sdk.FloatingIP) (string, error) {
	if network == nil {
		return "", fmt.Errorf("worker network is missing")
	}
	networkPrefix, err := netip.ParsePrefix(network.Subnet)
	if err != nil || !isRFC1918Prefix(networkPrefix) {
		return "", fmt.Errorf("worker network subnet %q is not RFC1918", network.Subnet)
	}
	networkPrefix = networkPrefix.Masked()
	if err := validateVPCPrefixExclusions(networkPrefix); err != nil {
		return "", err
	}
	vip, err := validateControlPlaneVIP(record.ControlPlaneVIP)
	if err != nil {
		return "", err
	}
	if err := validateUsableSubnetAddress(networkPrefix, vip, "private RKE2 supervisor VIP"); err != nil {
		return "", err
	}
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{Start: record.PrivateLoadBalancerPoolStart, Stop: record.PrivateLoadBalancerPoolStop}
	if _, _, err := validatePrivateLoadBalancerPoolInSubnet(networkPrefix, vip, privateLoadBalancerPool); err != nil {
		return "", err
	}
	if vm.NetworkUUID != "" && vm.NetworkUUID != record.NetworkUUID {
		return "", fmt.Errorf("VM network %q differs from recorded network %q", vm.NetworkUUID, record.NetworkUUID)
	}
	membershipCount := 0
	for _, uuid := range network.VMUUIDs {
		if uuid == vm.UUID {
			membershipCount++
		}
	}
	if membershipCount != 1 {
		return "", fmt.Errorf("worker network contains VM UUID %d times, want exactly once", membershipCount)
	}
	if _, err := validateWorkerPrivateIPv4(vm, networkPrefix, vip, privateLoadBalancerPool); err != nil {
		return "", err
	}
	intendedFirewall, err := findFirewallInList(firewalls, record.FirewallUUID, "read audit")
	if err != nil {
		return "", err
	}
	if err := validateDefaultDenyFirewall(*intendedFirewall, networkPrefix); err != nil {
		return "", err
	}
	if _, err := validateWorkerFirewallAssignments(firewalls, record.FirewallUUID, vm.UUID, true); err != nil {
		return "", err
	}
	expectedAddress, err := findFloatingIPInListRaw(addresses, record.FloatingIPName, record.BillingAccountID)
	if err != nil {
		return "", err
	}
	if err := validateExistingFloatingIP(*expectedAddress, record, vm.UUID); err != nil {
		return "", err
	}
	if expectedAddress.AssignedTo != vm.UUID || expectedAddress.AssignedToResourceType != "virtual_machine" {
		return "", fmt.Errorf("%w: provider-owned floating IP is not assigned to worker VM", cloudapi.ErrOwnershipMismatch)
	}
	if err := validateWorkerFloatingIPAssignmentsInList(addresses, *expectedAddress, vm.UUID, true); err != nil {
		return "", err
	}
	return expectedAddress.Address, nil
}

func (a *Adapter) DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string, identity cloudapi.DeleteVMIdentity) error {
	vm, vmMissing, getErr := a.readVMForDelete(ctx, location, uuid)
	if getErr != nil {
		return getErr
	}
	var record ownership
	if !vmMissing {
		var managed, complete bool
		var ownershipErr error
		record, managed, complete, ownershipErr = inspectOwnershipDescription(vm.Description, clusterName)
		if ownershipErr != nil {
			return fmt.Errorf("authorizing deletion of VM %s: %w", uuid, ownershipErr)
		}
		if !managed || !complete || record.Cluster != clusterName || record.NodeClaim != nodeClaimName {
			return fmt.Errorf("%w: VM %s is not managed for cluster %q and NodeClaim %q", cloudapi.ErrOwnershipMismatch, uuid, clusterName, nodeClaimName)
		}
	}

	var floatingIP *sdk.FloatingIP
	if vmMissing {
		var floatingErr error
		floatingIP, floatingErr = a.readOrphanFloatingIPForDelete(ctx, location, uuid, floatingIPName(clusterName, nodeClaimName), identity)
		if floatingErr != nil {
			return floatingErr
		}
	} else {
		var floatingErr error
		floatingIP, _, floatingErr = a.readOwnedFloatingIPForDelete(ctx, location, record, uuid, identity)
		if floatingErr != nil {
			return fmt.Errorf("finding named floating IP before deleting VM %s: %w", uuid, floatingErr)
		}
	}

	var errs []error
	var floatingCleanupErr error
	if floatingIP != nil {
		floatingCleanupErr = a.deleteOwnedFloatingIP(ctx, location, *floatingIP, uuid)
	}
	if floatingCleanupErr != nil {
		// Dependent identity or convergence failures are a hard precondition:
		// preserve the VM and firewall so the next reconciliation can retry from
		// an owned, protected state.
		return floatingCleanupErr
	}
	if !vmMissing {
		requestCtx, requestCancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
		deleteErr := a.api.DeleteVM(requestCtx, location, uuid)
		requestCancel()
		// A remote 2xx, 404, or error response only proves that the request was
		// dispatched. Keep the firewall attached until canonical GET and list
		// read-back independently agree that the VM is absent.
		if absenceErr := a.waitForVMAbsence(ctx, location, uuid, "after delete"); absenceErr != nil {
			if deleteErr != nil {
				errs = append(errs, fmt.Errorf("deleting VM %s: %w", uuid, deleteErr))
			}
			errs = append(errs, absenceErr)
			return errors.Join(errs...)
		}
	}
	if err := a.detachFirewallAfterVMDeletion(ctx, location, record.FirewallUUID, uuid); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	if vmMissing {
		return cloudapi.ErrNotFound
	}
	return nil
}

// readOwnedFloatingIPForDelete uses the unfiltered inventory so a changed
// name/account cannot be hidden by server-side filters. One empty list is only
// eventual-consistency evidence; two consecutive absences are required. An
// exact deletion tombstone proves that the dependent is already gone, while a
// genuinely missing active address keeps a live VM intact for reconciliation.
func (a *Adapter) readOwnedFloatingIPForDelete(ctx context.Context, location string, record ownership, vmUUID string, identity cloudapi.DeleteVMIdentity) (*sdk.FloatingIP, bool, error) {
	identity = normalizeLiveDeleteIdentity(identity, record)
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		addresses, err := a.api.ListFloatingIPs(requestCtx, location, nil)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, false, fmt.Errorf("floating IP delete discovery for VM %s stopped: %w", vmUUID, errors.Join(lastObservation, readbackErr))
		}
		if err != nil {
			absenceConfirmations = 0
			lastObservation = fmt.Errorf("listing floating IPs before deleting VM %s: %w", vmUUID, err)
			if !isRetryableReadback(readbackCtx, err) {
				return nil, false, lastObservation
			}
		} else {
			active := make([]sdk.FloatingIP, 0, 1)
			exactTombstone := false
			for i := range addresses {
				address := addresses[i]
				overlaps := address.Name == record.FloatingIPName || address.AssignedTo == vmUUID ||
					(record.PublicIPv4 != "" && address.Address == record.PublicIPv4) ||
					(identity.PublicIPv4 != "" && address.Address == identity.PublicIPv4)
				if !overlaps {
					continue
				}
				if address.IsDeleted {
					exactAccount := address.BillingAccountID == record.BillingAccountID ||
						(record.Schema != ownershipSchema && address.BillingAccountID == 0)
					exactAddress := record.PublicIPv4 == "" || address.Address == record.PublicIPv4
					if address.Name == record.FloatingIPName && exactAccount && exactAddress {
						exactTombstone = true
					}
					continue
				}
				active = append(active, address)
			}
			switch len(active) {
			case 0:
				absenceConfirmations++
				lastObservation = fmt.Errorf("active floating IP absence confirmation %d of 2 for VM %s", absenceConfirmations, vmUUID)
				if absenceConfirmations == 2 {
					if exactTombstone || durableDeleteIdentityMatchesRecord(identity, record) {
						return nil, true, nil
					}
					return nil, false, cloudapi.ErrNotFound
				}
			case 1:
				if err := validateExistingFloatingIP(active[0], record, vmUUID); err != nil {
					return nil, false, err
				}
				return &active[0], false, nil
			default:
				return nil, false, fmt.Errorf("%w: %d active floating IPs overlap the delete identity for VM %s", cloudapi.ErrOwnershipMismatch, len(active), vmUUID)
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, false, fmt.Errorf("floating IP delete discovery for VM %s did not converge: %w", vmUUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func durableDeleteIdentityMatchesRecord(identity cloudapi.DeleteVMIdentity, record ownership) bool {
	if record.Schema != ownershipSchema {
		legacy := cloudapi.DeleteVMIdentity{
			FloatingIPName:   record.FloatingIPName,
			PublicIPv4:       record.PublicIPv4,
			BillingAccountID: record.BillingAccountID,
		}
		return validateDurableDeleteIdentity(legacy, record.FloatingIPName) == nil
	}
	identity = normalizeLiveDeleteIdentity(identity, record)
	return validateDurableDeleteIdentity(identity, record.FloatingIPName) == nil &&
		identity.BillingAccountID == record.BillingAccountID
}

func normalizeLiveDeleteIdentity(identity cloudapi.DeleteVMIdentity, record ownership) cloudapi.DeleteVMIdentity {
	if record.Schema != ownershipSchema || identity.BillingAccountID != 0 || record.BillingAccountID <= 0 || identity.FloatingIPName != record.FloatingIPName {
		return identity
	}
	address, err := netip.ParseAddr(identity.PublicIPv4)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return identity
	}
	identity.BillingAccountID = record.BillingAccountID
	return identity
}

func validateDurableDeleteIdentity(identity cloudapi.DeleteVMIdentity, expectedName string) error {
	if err := validateDurableDeleteLookupIdentity(identity, expectedName); err != nil {
		return err
	}
	if identity.BillingAccountID <= 0 {
		return fmt.Errorf("billing account ID must be positive")
	}
	return nil
}

func validateDurableDeleteLookupIdentity(identity cloudapi.DeleteVMIdentity, expectedName string) error {
	if identity.FloatingIPName == "" || identity.FloatingIPName != expectedName {
		return fmt.Errorf("floating IP name %q does not equal expected name %q", identity.FloatingIPName, expectedName)
	}
	if identity.BillingAccountID < 0 {
		return fmt.Errorf("billing account ID must not be negative")
	}
	address, err := netip.ParseAddr(identity.PublicIPv4)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return fmt.Errorf("public address %q must be a public IPv4 address", identity.PublicIPv4)
	}
	return nil
}

// waitForVMAbsence is the post-mutation counterpart to readVMForDelete. It
// never turns a DELETE response into state: two consecutive canonical 404s,
// each corroborated by a valid location-wide list without the UUID, are
// required before dependent firewall cleanup can begin.
func (a *Adapter) waitForVMAbsence(ctx context.Context, location, uuid, phase string) error {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return fmt.Errorf("VM %s absence %s stopped: %w", uuid, phase, errors.Join(errVMAbsenceUncertain, lastObservation, readbackErr))
		}
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, getErr := a.api.GetVM(requestCtx, location, uuid)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return fmt.Errorf("VM %s absence %s stopped: %w", uuid, phase, errors.Join(errVMAbsenceUncertain, lastObservation, getErr, readbackErr))
		}
		switch {
		case getErr == nil && vm == nil:
			absenceConfirmations = 0
			lastObservation = fmt.Errorf("%w: VM %s detail response is empty", errVMAbsenceUncertain, uuid)
		case getErr == nil && vm.UUID != uuid:
			return fmt.Errorf("%w: canonical VM detail UUID %q does not match delete target %q", cloudapi.ErrOwnershipMismatch, vm.UUID, uuid)
		case getErr == nil:
			absenceConfirmations = 0
			lastObservation = fmt.Errorf("VM %s remains visible %s", uuid, phase)
		case !sdk.IsNotFound(getErr):
			absenceConfirmations = 0
			lastObservation = fmt.Errorf("getting VM %s %s: %w", uuid, phase, getErr)
			if !isRetryableReadback(readbackCtx, getErr) {
				return lastObservation
			}
		default:
			requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
			listed, listErr := a.api.ListVMs(requestCtx, location)
			requestCancel()
			if readbackErr := readbackCtx.Err(); readbackErr != nil {
				return fmt.Errorf("VM %s absence %s stopped: %w", uuid, phase, errors.Join(errVMAbsenceUncertain, lastObservation, listErr, readbackErr))
			}
			if listErr != nil {
				absenceConfirmations = 0
				lastObservation = fmt.Errorf("listing VMs to confirm absence of %s %s: %w", uuid, phase, listErr)
				if !isRetryableReadback(readbackCtx, listErr) {
					return lastObservation
				}
			} else if err := validateVMListSnapshot(listed); err != nil {
				return fmt.Errorf("validating VM list to confirm absence of %s %s: %w", uuid, phase, err)
			} else {
				listedPresent := false
				for i := range listed {
					if listed[i].UUID == uuid {
						listedPresent = true
						break
					}
				}
				if listedPresent {
					absenceConfirmations = 0
					lastObservation = fmt.Errorf("%w: GetVM reports %s absent while ListVMs still contains it", cloudapi.ErrOwnershipMismatch, uuid)
				} else {
					absenceConfirmations++
					lastObservation = fmt.Errorf("VM %s absence confirmation %d of 2 %s", uuid, absenceConfirmations, phase)
					if absenceConfirmations == 2 {
						return nil
					}
				}
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return fmt.Errorf("VM %s absence did not converge %s: %w", uuid, phase, errors.Join(errVMAbsenceUncertain, lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

// readVMForDelete never treats one eventually consistent 404 as permission to
// clean dependent resources. Absence requires two consecutive confirmations
// from both GetVM and the location-wide VM list. If either source still sees
// the UUID, reads continue within a fixed bound and no mutation is attempted.
func (a *Adapter) readVMForDelete(ctx context.Context, location, uuid string) (*sdk.VM, bool, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, false, fmt.Errorf("VM %s delete preflight stopped: %w", uuid, errors.Join(errVMAbsenceUncertain, lastObservation, readbackErr))
		}
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, getErr := a.api.GetVM(requestCtx, location, uuid)
		requestCancel()
		var currentObservation error
		if getErr != nil {
			currentObservation = fmt.Errorf("getting VM %s before delete: %w", uuid, getErr)
		}
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, false, fmt.Errorf("VM %s delete preflight stopped: %w", uuid, errors.Join(errVMAbsenceUncertain, lastObservation, currentObservation, readbackErr))
		}
		switch {
		case getErr == nil && vm == nil:
			absenceConfirmations = 0
			lastObservation = fmt.Errorf("%w: VM %s detail response is empty", errVMAbsenceUncertain, uuid)
		case getErr == nil && vm.UUID != uuid:
			return nil, false, fmt.Errorf("%w: canonical VM detail UUID %q does not match delete target %q", cloudapi.ErrOwnershipMismatch, vm.UUID, uuid)
		case getErr == nil:
			return vm, false, nil
		case !sdk.IsNotFound(getErr):
			absenceConfirmations = 0
			if !isRetryableReadback(readbackCtx, getErr) {
				return nil, false, currentObservation
			}
			lastObservation = currentObservation
		default:
			requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
			listed, listErr := a.api.ListVMs(requestCtx, location)
			requestCancel()
			if readbackErr := readbackCtx.Err(); readbackErr != nil {
				return nil, false, fmt.Errorf("VM %s delete preflight stopped: %w", uuid, errors.Join(errVMAbsenceUncertain, lastObservation, currentObservation, listErr, readbackErr))
			}
			if listErr != nil {
				absenceConfirmations = 0
				lastObservation = fmt.Errorf("listing VMs to confirm absence of %s: %w", uuid, listErr)
				if !isRetryableReadback(readbackCtx, listErr) {
					return nil, false, lastObservation
				}
			} else if err := validateVMListSnapshot(listed); err != nil {
				return nil, false, fmt.Errorf("validating VM list to confirm absence of %s: %w", uuid, err)
			} else {
				listedPresent := false
				for i := range listed {
					if listed[i].UUID == uuid {
						listedPresent = true
						break
					}
				}
				if listedPresent {
					absenceConfirmations = 0
					lastObservation = fmt.Errorf("%w: GetVM reports %s absent while ListVMs still contains it", cloudapi.ErrOwnershipMismatch, uuid)
				} else {
					absenceConfirmations++
					lastObservation = fmt.Errorf("VM %s absence confirmation %d of 2", uuid, absenceConfirmations)
					if absenceConfirmations == 2 {
						return nil, true, nil
					}
				}
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, false, fmt.Errorf("VM %s absence did not converge before delete preflight deadline: %w", uuid, errors.Join(errVMAbsenceUncertain, lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) ValidateNodeClass(ctx context.Context, location, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID string) error {
	_, err := a.validateNodeClass(ctx, location, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID)
	return err
}

func (a *Adapter) validateNodeClass(ctx context.Context, location, networkUUID, controlPlaneVIP, privateLoadBalancerPoolStart, privateLoadBalancerPoolStop, hostPoolUUID, firewallUUID string) (netip.Prefix, error) {
	vip, err := validateControlPlaneVIP(controlPlaneVIP)
	if err != nil {
		return netip.Prefix{}, err
	}
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{Start: privateLoadBalancerPoolStart, Stop: privateLoadBalancerPoolStop}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return netip.Prefix{}, fmt.Errorf("private load-balancer pool: %w", err)
	}
	pools, err := a.api.ListHostPools(ctx, location)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("listing InSpace host pools: %w", err)
	}
	foundPool := false
	for _, pool := range pools {
		if pool.UUID == hostPoolUUID {
			foundPool = true
			break
		}
	}
	if !foundPool {
		return netip.Prefix{}, fmt.Errorf("host pool %s is not available in location %s", hostPoolUUID, location)
	}
	network, err := a.api.GetNetwork(ctx, location, networkUUID)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("getting InSpace network %s: %w", networkUUID, err)
	}
	if network == nil {
		return netip.Prefix{}, fmt.Errorf("getting InSpace network %s: API returned no network", networkUUID)
	}
	if network.UUID != networkUUID {
		return netip.Prefix{}, fmt.Errorf("network read-back UUID %q does not match %q", network.UUID, networkUUID)
	}
	networkPrefix, err := netip.ParsePrefix(network.Subnet)
	if err != nil || !isRFC1918Prefix(networkPrefix) {
		return netip.Prefix{}, fmt.Errorf("network %s subnet %q must be an RFC1918 IPv4 prefix", networkUUID, network.Subnet)
	}
	if err := validateVPCPrefixExclusions(networkPrefix); err != nil {
		return netip.Prefix{}, fmt.Errorf("network %s: %w", networkUUID, err)
	}
	if err := validateUsableSubnetAddress(networkPrefix, vip, "private RKE2 supervisor VIP"); err != nil {
		return netip.Prefix{}, fmt.Errorf("network %s: %w", networkUUID, err)
	}
	if _, _, err := validatePrivateLoadBalancerPoolInSubnet(networkPrefix, vip, privateLoadBalancerPool); err != nil {
		return netip.Prefix{}, fmt.Errorf("network %s: %w", networkUUID, err)
	}
	firewall, err := a.findFirewall(ctx, location, firewallUUID)
	if err != nil {
		return netip.Prefix{}, err
	}
	if err := validateDefaultDenyFirewall(*firewall, networkPrefix); err != nil {
		return netip.Prefix{}, err
	}
	return networkPrefix.Masked(), nil
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
	case r.ControlPlaneVIP == "":
		return fmt.Errorf("private RKE2 supervisor VIP is required")
	case r.OSName == "" || r.OSVersion == "":
		return fmt.Errorf("OS name and version are required")
	case r.VCPU <= 0 || r.MemoryGiB <= 0 || r.RootDiskGiB <= 0:
		return fmt.Errorf("vCPU, memory, and root disk must be positive")
	case !r.PublicIPv4:
		return fmt.Errorf("public IPv4 allocation is required because InSpace has no managed NAT")
	case r.CloudInitJSON == "":
		return fmt.Errorf("cloud-init JSON is required")
	}
	if err := validateV2WorkerName(r.ClusterName, r.NodeClaimName, r.Name); err != nil {
		return err
	}
	if _, err := validateControlPlaneVIP(r.ControlPlaneVIP); err != nil {
		return err
	}
	if _, partial, err := normalizeOwnershipLaunchIdentity(ownership{
		HostClass: r.HostClass, InstanceType: r.InstanceType, HostPoolUUID: r.HostPoolUUID, VCPU: r.VCPU, MemoryGiB: r.MemoryGiB,
	}); err != nil {
		return fmt.Errorf("invalid worker launch identity: %v", err)
	} else if partial {
		return fmt.Errorf("invalid worker launch identity: host class and instance type are required")
	}
	vip, _ := validateControlPlaneVIP(r.ControlPlaneVIP)
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{Start: r.PrivateLoadBalancerPoolStart, Stop: r.PrivateLoadBalancerPoolStop}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return fmt.Errorf("private load-balancer pool: %w", err)
	}
	if err := inspacev1.ValidateSSHAccess(r.SSHUsername, r.SSHPublicKey); err != nil {
		return fmt.Errorf("invalid worker SSH access: %w", err)
	}
	if err := bootstrap.ValidateVPCSubnetTemplate(r.CloudInitJSON); err != nil {
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
	normalizedActual, actualPartial, actualErr := normalizeOwnershipLaunchIdentity(actual)
	normalizedExpected, expectedPartial, expectedErr := normalizeOwnershipLaunchIdentity(expected)
	if actualErr != nil || expectedErr != nil || actualPartial || expectedPartial || normalizedActual != normalizedExpected ||
		vm.Name != request.Name || vm.VCPU != request.VCPU || vm.MemoryMiB != request.MemoryGiB*1024 ||
		(vm.Hostname != "" && vm.Hostname != request.Name) ||
		(vm.OSName != "" && vm.OSName != request.OSName) || (vm.OSVersion != "" && vm.OSVersion != request.OSVersion) ||
		(vm.DesignatedPoolUUID != "" && vm.DesignatedPoolUUID != request.HostPoolUUID) ||
		(vm.NetworkUUID != "" && vm.NetworkUUID != request.NetworkUUID) ||
		(actual.Schema == ownershipSchema && vm.PublicIPv4 != "") {
		return fmt.Errorf("owned VM %s exists but launch parameters differ; refusing duplicate create", vm.UUID)
	}
	return nil
}

func validatePersistedVM(vm sdk.VM, vmUUID string, request cloudapi.CreateVMRequest, expected ownership) error {
	if vm.UUID != vmUUID {
		return fmt.Errorf("%w: VM detail read-back UUID %q does not match launched VM %q", cloudapi.ErrOwnershipMismatch, vm.UUID, vmUUID)
	}
	incomplete := false
	var actual ownership
	if err := json.Unmarshal([]byte(vm.Description), &actual); err != nil {
		incomplete = true
	} else {
		normalizedActual, actualPartial, actualErr := normalizeOwnershipLaunchIdentity(actual)
		normalizedExpected, expectedPartial, expectedErr := normalizeOwnershipLaunchIdentity(expected)
		if actualErr != nil || expectedErr != nil {
			return fmt.Errorf("%w: VM %s persisted Karpenter ownership has conflicting launch identity", cloudapi.ErrOwnershipMismatch, vmUUID)
		}
		if actualPartial || expectedPartial {
			incomplete = true
		}
		if normalizedActual != normalizedExpected && ownershipMatchesExpectedWherePresent(normalizedActual, normalizedExpected) {
			incomplete = true
		} else if normalizedActual != normalizedExpected {
			return fmt.Errorf("%w: VM %s persisted Karpenter ownership differs from the launched NodeClaim", cloudapi.ErrOwnershipMismatch, vmUUID)
		}
	}
	launchIdentityIncomplete, err := validatePersistedLaunchIdentity(vm, request)
	if err != nil {
		return fmt.Errorf("%w: VM %s persisted launch identity differs from the launched NodeClaim: %v", cloudapi.ErrOwnershipMismatch, vmUUID, err)
	}
	if incomplete || launchIdentityIncomplete {
		return fmt.Errorf("%w: VM %s detail read-back lacks complete persisted ownership or launch identity: %w", cloudapi.ErrOwnershipMismatch, vmUUID, errPersistedOwnershipIncomplete)
	}
	return nil
}

// validatePersistedLaunchIdentity returns incomplete=true only when every
// value the API supplied agrees with the create request but at least one
// required field is still absent. Any present conflict fails immediately.
// NetworkUUID does not contribute to incomplete because InSpace's canonical
// VM detail response does not always echo it. Any present value must match.
// The complete v3 description still records the exact requested network, and
// GetNetwork membership is required separately before a worker can be adopted,
// returned, or have its FIP named.
func validatePersistedLaunchIdentity(vm sdk.VM, request cloudapi.CreateVMRequest) (incomplete bool, err error) {
	checkString := func(field, actual, expected string) error {
		if actual == "" {
			incomplete = true
			return nil
		}
		if actual != expected {
			return fmt.Errorf("%s %q does not match %q", field, actual, expected)
		}
		return nil
	}
	checkPositive := func(field string, actual, expected int) error {
		if actual == 0 {
			incomplete = true
			return nil
		}
		if actual != expected {
			return fmt.Errorf("%s %d does not match %d", field, actual, expected)
		}
		return nil
	}
	for _, check := range []func() error{
		func() error { return checkString("name", vm.Name, request.Name) },
		func() error {
			if vm.Hostname != "" && vm.Hostname != request.Name {
				return fmt.Errorf("hostname %q does not match %q", vm.Hostname, request.Name)
			}
			return nil
		},
		func() error { return checkPositive("vCPU", vm.VCPU, request.VCPU) },
		func() error { return checkPositive("memory MiB", vm.MemoryMiB, request.MemoryGiB*1024) },
		func() error { return checkString("OS name", vm.OSName, request.OSName) },
		func() error { return checkString("OS version", vm.OSVersion, request.OSVersion) },
		func() error { return checkString("designated pool UUID", vm.DesignatedPoolUUID, request.HostPoolUUID) },
		func() error {
			if vm.NetworkUUID == "" {
				return nil
			}
			if vm.NetworkUUID != request.NetworkUUID {
				return fmt.Errorf("worker is attached to network %q instead of %q", vm.NetworkUUID, request.NetworkUUID)
			}
			return nil
		},
	} {
		if err := check(); err != nil {
			return false, err
		}
	}
	if vm.BillingAccountID == 0 {
		incomplete = true
	} else if vm.BillingAccountID != request.BillingAccountID {
		return false, fmt.Errorf("billing account %d does not match %d", vm.BillingAccountID, request.BillingAccountID)
	}
	primaryDisks := 0
	for _, disk := range vm.Storage {
		if !disk.Primary {
			continue
		}
		primaryDisks++
		if primaryDisks > 1 {
			return false, fmt.Errorf("VM reports multiple primary root disks")
		}
		if disk.SizeGiB == 0 {
			incomplete = true
		} else if disk.SizeGiB != int(request.RootDiskGiB) {
			return false, fmt.Errorf("primary root disk size %d GiB does not match %d GiB", disk.SizeGiB, request.RootDiskGiB)
		}
	}
	if primaryDisks == 0 {
		incomplete = true
	}
	return incomplete, nil
}

func normalizeOwnershipLaunchIdentity(record ownership) (normalized ownership, partial bool, err error) {
	normalized = record
	// v1 records used the NodeClaim name for the VM, guest hostname, and RKE2
	// Node name. Normalize that deliberate compatibility contract to v2 before
	// comparing ownership; a v2 record may never omit its separate VM name.
	if normalized.Schema == legacyOwnershipSchema {
		if normalized.VMName != "" && normalized.VMName != normalized.NodeClaim {
			return ownership{}, false, fmt.Errorf("legacy v1 VM name %q contradicts NodeClaim identity %q", normalized.VMName, normalized.NodeClaim)
		}
		normalized.VMName = normalized.NodeClaim
	} else if normalized.Schema == ownershipSchema || normalized.Schema == legacyV2OwnershipSchema {
		if normalized.Cluster == "" || normalized.NodeClaim == "" || normalized.VMName == "" {
			return normalized, true, nil
		}
		if err := validateV2WorkerName(normalized.Cluster, normalized.NodeClaim, normalized.VMName); err != nil {
			return ownership{}, false, fmt.Errorf("invalid v2/v3 worker identity: %v", err)
		}
	}
	if record.HostClass == "" || record.InstanceType == "" {
		return normalized, true, nil
	}
	derivedHostPoolUUID, knownHostClass := inspacev1.HostPoolUUIDForClass(record.HostClass)
	if !knownHostClass {
		return ownership{}, false, fmt.Errorf("unsupported recorded host class %q", record.HostClass)
	}
	if record.HostPoolUUID != "" && record.HostPoolUUID != derivedHostPoolUUID {
		return ownership{}, false, fmt.Errorf("recorded host pool %q does not match host class %q", record.HostPoolUUID, record.HostClass)
	}
	matches := ownedInstanceTypePattern.FindStringSubmatch(record.InstanceType)
	if len(matches) != 4 {
		return ownership{}, false, fmt.Errorf("recorded instance type %q is not canonical", record.InstanceType)
	}
	derivedVCPU, vCPUErr := strconv.Atoi(matches[2])
	derivedMemoryGiB, memoryErr := strconv.Atoi(matches[3])
	memoryPerVCPU := map[string]int{"compute": 1, "general": 2, "memory": 4}[matches[1]]
	if vCPUErr != nil || memoryErr != nil || derivedVCPU < 2 || derivedVCPU > 16 || derivedVCPU%2 != 0 || derivedMemoryGiB != derivedVCPU*memoryPerVCPU {
		return ownership{}, false, fmt.Errorf("recorded instance type %q has invalid capacity", record.InstanceType)
	}
	if record.VCPU < 0 || record.MemoryGiB < 0 {
		return ownership{}, false, fmt.Errorf("recorded exact capacity must be positive")
	}
	if (record.VCPU != 0 && record.VCPU != derivedVCPU) || (record.MemoryGiB != 0 && record.MemoryGiB != derivedMemoryGiB) {
		return ownership{}, false, fmt.Errorf("recorded exact capacity %d vCPU/%d GiB differs from instance type %q", record.VCPU, record.MemoryGiB, record.InstanceType)
	}
	extensionFields := 0
	if record.HostPoolUUID != "" {
		extensionFields++
	}
	if record.VCPU != 0 {
		extensionFields++
	}
	if record.MemoryGiB != 0 {
		extensionFields++
	}
	partial = extensionFields != 0 && extensionFields != 3
	normalized.HostPoolUUID = derivedHostPoolUUID
	normalized.VCPU = derivedVCPU
	normalized.MemoryGiB = derivedMemoryGiB
	return normalized, partial, nil
}

func validateV2WorkerName(clusterName, nodeClaimName, vmName string) error {
	if messages := k8svalidation.IsDNS1123Label(clusterName); len(messages) != 0 {
		return fmt.Errorf("cluster name %q must be a DNS-1123 hostname label: %s", clusterName, strings.Join(messages, "; "))
	}
	if messages := k8svalidation.IsDNS1123Label(nodeClaimName); len(messages) != 0 {
		return fmt.Errorf("NodeClaim name %q must be a DNS-1123 hostname label: %s", nodeClaimName, strings.Join(messages, "; "))
	}
	expected := clusterName + "-karp-" + nodeClaimName
	if vmName != expected {
		return fmt.Errorf("VM name %q must exactly equal cluster-derived worker name %q", vmName, expected)
	}
	if messages := k8svalidation.IsDNS1123Label(vmName); len(messages) != 0 {
		return fmt.Errorf("derived VM name %q must be a DNS-1123 hostname label: %s", vmName, strings.Join(messages, "; "))
	}
	return nil
}

func validateEstablishedLaunchIdentity(vm sdk.VM, record ownership) error {
	normalized, partial, err := normalizeOwnershipLaunchIdentity(record)
	if err != nil {
		return fmt.Errorf("%w: established ownership cannot resolve exact launch identity: %v", cloudapi.ErrOwnershipMismatch, err)
	}
	if partial {
		return fmt.Errorf("%w: established ownership lacks complete exact launch identity: %w", cloudapi.ErrOwnershipMismatch, errPersistedOwnershipIncomplete)
	}
	if record.Schema == ownershipSchema && vm.PublicIPv4 != "" {
		return fmt.Errorf("%w: v3 worker VM must not report a direct public IPv4", cloudapi.ErrOwnershipMismatch)
	}
	expected := cloudapi.CreateVMRequest{
		Name:             normalized.VMName,
		BillingAccountID: normalized.BillingAccountID,
		NetworkUUID:      normalized.NetworkUUID,
		OSName:           normalized.OSName,
		OSVersion:        normalized.OSVersion,
		HostPoolUUID:     normalized.HostPoolUUID,
		VCPU:             normalized.VCPU,
		MemoryGiB:        normalized.MemoryGiB,
		RootDiskGiB:      normalized.RootDiskGiB,
	}
	incomplete, err := validatePersistedLaunchIdentity(vm, expected)
	if err != nil {
		return fmt.Errorf("%w: established VM launch identity differs from persisted ownership: %v", cloudapi.ErrOwnershipMismatch, err)
	}
	if incomplete {
		return fmt.Errorf("%w: established VM lacks complete launch identity: %w", cloudapi.ErrOwnershipMismatch, errPersistedOwnershipIncomplete)
	}
	return nil
}

// ownershipMatchesExpectedWherePresent distinguishes an eventually
// consistent partial read-back from a complete conflicting ownership record.
// Empty fields are allowed only as missing evidence; every field the API did
// return must already agree with the exact record sent on create.
func ownershipMatchesExpectedWherePresent(actual, expected ownership) bool {
	return fieldMatchesOrIsMissing(actual.Schema, expected.Schema) &&
		fieldMatchesOrIsMissing(actual.Cluster, expected.Cluster) &&
		fieldMatchesOrIsMissing(actual.NodeClaim, expected.NodeClaim) &&
		fieldMatchesOrIsMissing(actual.VMName, expected.VMName) &&
		fieldMatchesOrIsMissing(actual.KeyHash, expected.KeyHash) &&
		fieldMatchesOrIsMissing(actual.HostClass, expected.HostClass) &&
		fieldMatchesOrIsMissing(actual.InstanceType, expected.InstanceType) &&
		fieldMatchesOrIsMissing(actual.HostPoolUUID, expected.HostPoolUUID) &&
		fieldMatchesOrIsMissing(actual.VCPU, expected.VCPU) &&
		fieldMatchesOrIsMissing(actual.MemoryGiB, expected.MemoryGiB) &&
		fieldMatchesOrIsMissing(actual.RootDiskGiB, expected.RootDiskGiB) &&
		fieldMatchesOrIsMissing(actual.SpecHash, expected.SpecHash) &&
		fieldMatchesOrIsMissing(actual.BootstrapHash, expected.BootstrapHash) &&
		fieldMatchesOrIsMissing(actual.FirewallUUID, expected.FirewallUUID) &&
		fieldMatchesOrIsMissing(actual.NetworkUUID, expected.NetworkUUID) &&
		fieldMatchesOrIsMissing(actual.ControlPlaneVIP, expected.ControlPlaneVIP) &&
		fieldMatchesOrIsMissing(actual.PrivateLoadBalancerPoolStart, expected.PrivateLoadBalancerPoolStart) &&
		fieldMatchesOrIsMissing(actual.PrivateLoadBalancerPoolStop, expected.PrivateLoadBalancerPoolStop) &&
		fieldMatchesOrIsMissing(actual.OSName, expected.OSName) &&
		fieldMatchesOrIsMissing(actual.OSVersion, expected.OSVersion) &&
		fieldMatchesOrIsMissing(actual.BillingAccountID, expected.BillingAccountID) &&
		fieldMatchesOrIsMissing(actual.FloatingIPName, expected.FloatingIPName) &&
		fieldMatchesOrIsMissing(actual.PublicIPv4, expected.PublicIPv4)
}

func fieldMatchesOrIsMissing[T comparable](actual, expected T) bool {
	var zero T
	return actual == zero || actual == expected
}

func validateExistingFloatingIP(floatingIP sdk.FloatingIP, record ownership, vmUUID string) error {
	if err := validateUsableFloatingIP(floatingIP); err != nil {
		return fmt.Errorf("%w: floating IP recorded by owned VM %s is unusable: %v", cloudapi.ErrOwnershipMismatch, vmUUID, err)
	}
	billingMismatch := (record.Schema == ownershipSchema && floatingIP.BillingAccountID != record.BillingAccountID) ||
		(record.Schema != ownershipSchema && floatingIP.BillingAccountID != 0 && floatingIP.BillingAccountID != record.BillingAccountID)
	if floatingIP.Name != record.FloatingIPName || (record.PublicIPv4 != "" && floatingIP.Address != record.PublicIPv4) || billingMismatch {
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
		RootDiskGiB: rootDiskGiB, FirewallUUID: record.FirewallUUID, NetworkUUID: record.NetworkUUID, ControlPlaneVIP: record.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: record.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: record.PrivateLoadBalancerPoolStop, SpecHash: record.SpecHash,
		BootstrapHash: record.BootstrapHash, PrivateIPv4: vm.PrivateIPv4, PublicIPv4: record.PublicIPv4, FloatingIPName: record.FloatingIPName,
		State: mapLifecycle(vm.Status), RawState: vm.Status,
	}
}

func (a *Adapter) ensureProtection(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, expected ownership, prevalidatedNetworkPrefix netip.Prefix, canonicalHint *sdk.VM, freshLaunch bool) (*sdk.VM, *sdk.FloatingIP, bool, error) {
	// reserve=true exposes the VM publicly as soon as CreateVM commits. Prove
	// the complete v3 ownership description and every top-level launch field
	// supplied by the API before touching a VM discovered by reads. A fresh POST
	// is different: its returned UUID is this invocation's launch anchor, so
	// attach/read back the firewall immediately and only then wait for canonical
	// ownership. The redundant top-level NetworkUUID may be absent, but exact
	// GetNetwork membership must converge before any FIP mutation or return.
	var persisted *sdk.VM
	var err error
	if freshLaunch {
		if err := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, prevalidatedNetworkPrefix); err != nil {
			return nil, nil, true, errors.Join(errEarlyFirewallProtection, err)
		}
		persisted, err = a.ensurePersistedVMIdentity(context.WithoutCancel(ctx), request, vmUUID, expected, canonicalHint)
		if err != nil {
			return nil, nil, true, errors.Join(errFreshOwnershipProof, err)
		}
	} else {
		persisted, err = a.ensurePersistedVMIdentity(ctx, request, vmUUID, expected, canonicalHint)
		if err != nil {
			return nil, nil, false, err
		}
		if err := a.ensureEarlyFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, prevalidatedNetworkPrefix); err != nil {
			return persisted, nil, true, errors.Join(errEarlyFirewallProtection, err)
		}
	}
	persisted, networkPrefix, _, err := a.ensureWorkerNetworkIdentity(ctx, request, vmUUID, expected, persisted)
	if err != nil {
		return nil, nil, true, err
	}
	floatingIP, err := a.ensureAutoFloatingIP(ctx, request.Location, vmUUID, expected.FloatingIPName, expected.BillingAccountID)
	if err != nil {
		return nil, floatingIP, true, err
	}
	if err := a.ensureCloudProtections(ctx, request, vmUUID, *floatingIP, networkPrefix); err != nil {
		return nil, floatingIP, true, err
	}
	return persisted, floatingIP, true, nil
}

func (a *Adapter) ensurePersistedVMIdentity(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, expected ownership, canonicalHint *sdk.VM) (*sdk.VM, error) {
	if canonicalHint != nil {
		if err := validatePersistedVM(*canonicalHint, vmUUID, request, expected); err != nil {
			return nil, err
		}
		copy := *canonicalHint
		return &copy, nil
	}
	timeout := a.protectionAuditTimeout
	if a.networkAttachmentReadbackTimeout < timeout {
		timeout = a.networkAttachmentReadbackTimeout
	}
	readbackCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, request.Location, vmUUID)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, fmt.Errorf("VM %s canonical ownership proof stopped: %w", vmUUID, errors.Join(lastObservation, readbackErr))
		}
		switch {
		case err != nil:
			lastObservation = fmt.Errorf("getting worker VM %s for canonical ownership proof: %w", vmUUID, err)
			if !sdk.IsNotFound(err) && !isRetryableReadback(readbackCtx, err) {
				return nil, lastObservation
			}
		case vm == nil:
			lastObservation = fmt.Errorf("worker VM %s detail before firewall attachment is empty: %w", vmUUID, errPersistedOwnershipIncomplete)
		default:
			validationErr := validatePersistedVM(*vm, vmUUID, request, expected)
			if errors.Is(validationErr, errPersistedOwnershipIncomplete) {
				lastObservation = validationErr
			} else if validationErr != nil {
				return nil, validationErr
			} else {
				return vm, nil
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, fmt.Errorf("VM %s canonical ownership did not converge: %w", vmUUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) ensureEarlyFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix) error {
	timeout := a.protectionAuditTimeout
	if a.networkAttachmentReadbackTimeout < timeout {
		timeout = a.networkAttachmentReadbackTimeout
	}
	protectionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return a.ensureFirewall(protectionCtx, location, firewallUUID, vmUUID, networkPrefix)
}

func (a *Adapter) ensureFreshFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix) error {
	timeout := a.protectionAuditTimeout
	if a.networkAttachmentReadbackTimeout < timeout {
		timeout = a.networkAttachmentReadbackTimeout
	}
	protectionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	// The intended firewall was authoritatively validated immediately before
	// the POST. Minimize the reserve=true exposure window by assigning first;
	// the following readback revalidates both policy and exact assignment.
	mutationErr := a.api.AssignFirewallToVM(protectionCtx, location, firewallUUID, vmUUID)
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		firewalls, err := a.api.ListFirewalls(protectionCtx, location)
		if readbackErr := protectionCtx.Err(); readbackErr != nil {
			return fmt.Errorf("fresh firewall %s assignment to VM %s read-back stopped: %w", firewallUUID, vmUUID, errors.Join(mutationErr, lastObservation, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing firewalls after immediately assigning %s to fresh VM %s: %w", firewallUUID, vmUUID, err)
			if !isRetryableReadback(protectionCtx, err) {
				return errors.Join(mutationErr, lastObservation)
			}
		} else {
			firewall, validationErr := findFirewallInList(firewalls, firewallUUID, location)
			if validationErr == nil {
				validationErr = validateDefaultDenyFirewall(*firewall, networkPrefix)
			}
			if validationErr == nil {
				_, validationErr = validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, true)
			}
			if validationErr == nil {
				return nil
			}
			lastObservation = validationErr
			if !errors.Is(validationErr, errFirewallAssignmentNotVisible) {
				return errors.Join(mutationErr, validationErr)
			}
		}
		if err := waitForReadback(protectionCtx, readbackDelay); err != nil {
			return fmt.Errorf("fresh firewall %s assignment to VM %s did not converge: %w", firewallUUID, vmUUID, errors.Join(mutationErr, lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) ensureAutoFloatingIP(ctx context.Context, location, vmUUID, expectedName string, billingAccountID int64) (*sdk.FloatingIP, error) {
	return a.ensureAutoFloatingIPReadback(ctx, location, vmUUID, expectedName, billingAccountID, true)
}

func (a *Adapter) ensureAutoFloatingIPForCleanup(ctx context.Context, location, vmUUID, expectedName string, billingAccountID int64) (*sdk.FloatingIP, error) {
	return a.ensureAutoFloatingIPReadback(ctx, location, vmUUID, expectedName, billingAccountID, false)
}

func (a *Adapter) ensureAutoFloatingIPReadback(ctx context.Context, location, vmUUID, expectedName string, billingAccountID int64, requireUsable bool) (*sdk.FloatingIP, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	readbackDelay := a.networkAttachmentReadbackMinDelay
	var lastObservation, updateErr error
	var lastCandidate *sdk.FloatingIP
	updateAttempted := false
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		addresses, err := a.api.ListFloatingIPs(requestCtx, location, nil)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return lastCandidate, fmt.Errorf("auto-reserved floating IP for VM %s read-back stopped: %w", vmUUID, errors.Join(lastObservation, updateErr, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing auto-reserved floating IP for VM %s: %w", vmUUID, err)
			if !isRetryableReadback(readbackCtx, err) {
				return nil, lastObservation
			}
		} else {
			candidate, needsUpdate, validationErr := autoFloatingIPForVM(addresses, vmUUID, expectedName, billingAccountID, requireUsable)
			lastCandidate = candidate
			if validationErr != nil {
				return candidate, validationErr
			}
			if candidate == nil {
				lastObservation = fmt.Errorf("VM %s has no visible auto-reserved floating IP yet", vmUUID)
			} else if !needsUpdate {
				return candidate, nil
			} else if !updateAttempted {
				updateAttempted = true
				requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
				_, updateErr = a.api.UpdateFloatingIP(requestCtx, location, candidate.Address, sdk.UpdateFloatingIPRequest{
					Name: expectedName, BillingAccountID: billingAccountID,
				})
				requestCancel()
				lastObservation = fmt.Errorf("auto-reserved floating IP %s rename/account update is not visible yet", candidate.Address)
			} else {
				lastObservation = fmt.Errorf("auto-reserved floating IP %s remains unnamed after its deterministic PATCH", candidate.Address)
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return lastCandidate, fmt.Errorf("auto-reserved floating IP for VM %s did not converge: %w", vmUUID, errors.Join(lastObservation, updateErr, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func autoFloatingIPForVM(addresses []sdk.FloatingIP, vmUUID, expectedName string, billingAccountID int64, requireUsable bool) (*sdk.FloatingIP, bool, error) {
	assigned := make([]sdk.FloatingIP, 0, 1)
	namedMatches := make([]sdk.FloatingIP, 0, 1)
	for i := range addresses {
		address := addresses[i]
		if address.IsDeleted {
			continue
		}
		if address.Name == expectedName {
			namedMatches = append(namedMatches, address)
		}
		if address.AssignedTo != vmUUID {
			continue
		}
		if address.AssignedToResourceType != "virtual_machine" {
			return nil, false, fmt.Errorf("%w: floating IP %s is assigned to worker UUID %s with resource type %q", cloudapi.ErrOwnershipMismatch, address.Address, vmUUID, address.AssignedToResourceType)
		}
		assigned = append(assigned, address)
	}
	if len(namedMatches) > 1 {
		return nil, false, fmt.Errorf("%w: %d floating IPs share deterministic worker name %q", cloudapi.ErrOwnershipMismatch, len(namedMatches), expectedName)
	}
	if len(assigned) == 0 {
		if len(namedMatches) != 0 {
			return nil, false, fmt.Errorf("%w: deterministic floating IP %q exists but is not assigned to worker VM %s", cloudapi.ErrOwnershipMismatch, expectedName, vmUUID)
		}
		return nil, false, nil
	}
	if len(assigned) != 1 {
		return nil, false, fmt.Errorf("%w: worker VM %s has %d floating IP assignments, want exactly one", cloudapi.ErrOwnershipMismatch, vmUUID, len(assigned))
	}
	candidate := assigned[0]
	if candidate.Address == "" {
		return &candidate, false, fmt.Errorf("%w: auto-reserved floating IP for worker VM %s has no address", cloudapi.ErrOwnershipMismatch, vmUUID)
	}
	if err := validateUsableFloatingIP(candidate); requireUsable && err != nil {
		return &candidate, false, fmt.Errorf("%w: auto-reserved floating IP for worker VM %s is unusable: %v", cloudapi.ErrOwnershipMismatch, vmUUID, err)
	}
	if candidate.BillingAccountID != 0 && candidate.BillingAccountID != billingAccountID {
		return &candidate, false, fmt.Errorf("%w: auto-reserved floating IP for worker VM %s belongs to billing account %d", cloudapi.ErrOwnershipMismatch, vmUUID, candidate.BillingAccountID)
	}
	switch candidate.Name {
	case "":
		if len(namedMatches) != 0 {
			return &candidate, false, fmt.Errorf("%w: deterministic floating IP %q is distinct from the worker's unnamed auto-reserved address", cloudapi.ErrOwnershipMismatch, expectedName)
		}
		return &candidate, true, nil
	case expectedName:
		if candidate.BillingAccountID == 0 {
			return &candidate, true, nil
		}
		if candidate.BillingAccountID != billingAccountID {
			return &candidate, false, fmt.Errorf("%w: named worker floating IP has billing account %d, want %d", cloudapi.ErrOwnershipMismatch, candidate.BillingAccountID, billingAccountID)
		}
		return &candidate, false, nil
	default:
		return &candidate, false, fmt.Errorf("%w: worker VM %s auto-reserved floating IP has foreign name %q", cloudapi.ErrOwnershipMismatch, vmUUID, candidate.Name)
	}
}

func (a *Adapter) ensureWorkerNetworkIdentity(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, expected ownership, persistedHint *sdk.VM) (*sdk.VM, netip.Prefix, bool, error) {
	if vmUUID == "" {
		return nil, netip.Prefix{}, false, fmt.Errorf("worker VM UUID is required for protection read-back")
	}
	vip, err := validateControlPlaneVIP(request.ControlPlaneVIP)
	if err != nil {
		return nil, netip.Prefix{}, false, err
	}
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{Start: request.PrivateLoadBalancerPoolStart, Stop: request.PrivateLoadBalancerPoolStop}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return nil, netip.Prefix{}, false, err
	}
	// Do not infer attachment from the VM detail: its top-level NetworkUUID is
	// legitimately absent in the canonical API response. Require exactly one
	// membership row from the specifically configured network before allowing
	// FIP discovery/rename, adoption, or a successful return.
	networkPrefix, err := a.ensureNetworkAttachment(ctx, request.Location, request.NetworkUUID, vmUUID, vip, privateLoadBalancerPool)
	if err != nil {
		return nil, netip.Prefix{}, false, err
	}
	if persistedHint != nil {
		privateIPv4, privateIPv4Err := validateWorkerPrivateIPv4(*persistedHint, networkPrefix, vip, privateLoadBalancerPool)
		if privateIPv4Err == nil {
			copy := *persistedHint
			copy.PrivateIPv4 = privateIPv4.String()
			return &copy, networkPrefix, true, nil
		}
		if persistedHint.PrivateIPv4 != "" {
			return nil, netip.Prefix{}, true, privateIPv4Err
		}
	}
	persisted, privateIPv4, ownershipProven, err := a.ensureWorkerPrivateIPv4(ctx, request, vmUUID, networkPrefix, vip, privateLoadBalancerPool, expected)
	if err != nil {
		return nil, netip.Prefix{}, ownershipProven, err
	}
	persisted.PrivateIPv4 = privateIPv4.String()
	return persisted, networkPrefix, true, nil
}

func (a *Adapter) ensureCloudProtections(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, floatingIP sdk.FloatingIP, networkPrefix netip.Prefix) error {
	if err := validateUsableFloatingIP(floatingIP); err != nil {
		return fmt.Errorf("worker floating IP is unusable: %w", err)
	}
	if err := a.ensureFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, networkPrefix); err != nil {
		return err
	}
	if err := a.ensureFloatingAssignment(ctx, request.Location, floatingIP, vmUUID); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) ensureNetworkAttachment(ctx context.Context, location, networkUUID, vmUUID string, controlPlaneVIP netip.Addr, privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool) (netip.Prefix, error) {
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
				"VM %s attachment to network %s read-back stopped: %w", vmUUID, networkUUID, errors.Join(lastObservation, readbackErr),
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
			if err := validateVPCPrefixExclusions(networkPrefix); err != nil {
				return netip.Prefix{}, err
			}
			if err := validateUsableSubnetAddress(networkPrefix, controlPlaneVIP, "private RKE2 supervisor VIP"); err != nil {
				return netip.Prefix{}, err
			}
			if _, _, err := validatePrivateLoadBalancerPoolInSubnet(networkPrefix, controlPlaneVIP, privateLoadBalancerPool); err != nil {
				return netip.Prefix{}, err
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
				return netip.Prefix{}, fmt.Errorf("%w: worker network %s contains VM %s %d times", cloudapi.ErrOwnershipMismatch, networkUUID, vmUUID, membershipCount)
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

func (a *Adapter) ensureWorkerPrivateIPv4(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, networkPrefix netip.Prefix, controlPlaneVIP netip.Addr, privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool, expected ownership) (*sdk.VM, netip.Addr, bool, error) {
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	var lastObservation error
	ownershipProven := false
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, request.Location, vmUUID)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, netip.Addr{}, ownershipProven, fmt.Errorf("VM %s private IPv4 read-back stopped: %w", vmUUID, errors.Join(lastObservation, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("getting worker VM %s for private IPv4 read-back: %w", vmUUID, err)
			if !sdk.IsNotFound(err) && !isRetryableReadback(readbackCtx, err) {
				return nil, netip.Addr{}, ownershipProven, lastObservation
			}
		} else if vm == nil {
			return nil, netip.Addr{}, ownershipProven, fmt.Errorf("getting worker VM %s for private IPv4 read-back: API returned no VM", vmUUID)
		} else {
			if validationErr := validatePersistedVM(*vm, vmUUID, request, expected); errors.Is(validationErr, errPersistedOwnershipIncomplete) {
				lastObservation = validationErr
			} else if validationErr != nil {
				// A conflicting authoritative detail invalidates any sparse-list
				// ownership signal. The caller must not delete or protect this VM.
				return nil, netip.Addr{}, false, validationErr
			} else {
				ownershipProven = true
				privateIPv4, privateIPv4Err := validateWorkerPrivateIPv4(*vm, networkPrefix, controlPlaneVIP, privateLoadBalancerPool)
				if privateIPv4Err == nil {
					return vm, privateIPv4, true, nil
				}
				if vm.PrivateIPv4 != "" {
					return nil, netip.Addr{}, true, privateIPv4Err
				}
				lastObservation = privateIPv4Err
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, netip.Addr{}, ownershipProven, fmt.Errorf("VM %s did not expose complete persisted identity and exactly one safe private IPv4 before the read-back deadline: %w", vmUUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func validateControlPlaneVIP(value string) (netip.Addr, error) {
	vip, err := netip.ParseAddr(value)
	if err != nil || !vip.Is4() || !vip.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("private RKE2 supervisor VIP %q must be a literal RFC1918 IPv4 address", value)
	}
	for _, reserved := range fixedClusterNetworks {
		if reserved.prefix.Contains(vip) {
			return netip.Addr{}, fmt.Errorf("private RKE2 supervisor VIP %s must not overlap %s %s", vip, reserved.description, reserved.prefix)
		}
	}
	return vip, nil
}

func validateWorkerPrivateIPv4(vm sdk.VM, networkPrefix netip.Prefix, controlPlaneVIP netip.Addr, privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool) (netip.Addr, error) {
	if vm.PrivateIPv4 == "" {
		return netip.Addr{}, fmt.Errorf("worker VM %s has no private IPv4", vm.UUID)
	}
	if strings.TrimSpace(vm.PrivateIPv4) != vm.PrivateIPv4 {
		return netip.Addr{}, fmt.Errorf("worker VM %s private IPv4 %q is not exactly one address", vm.UUID, vm.PrivateIPv4)
	}
	privateIPv4, err := netip.ParseAddr(vm.PrivateIPv4)
	if err != nil || !privateIPv4.Is4() || !privateIPv4.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("worker VM %s private IPv4 %q must be exactly one RFC1918 IPv4 address", vm.UUID, vm.PrivateIPv4)
	}
	if !networkPrefix.Contains(privateIPv4) {
		return netip.Addr{}, fmt.Errorf("worker VM %s private IPv4 %s is outside VPC subnet %s", vm.UUID, privateIPv4, networkPrefix)
	}
	if err := validateUsableSubnetAddress(networkPrefix, privateIPv4, "worker private IPv4"); err != nil {
		return netip.Addr{}, fmt.Errorf("worker VM %s: %w", vm.UUID, err)
	}
	if privateIPv4 == controlPlaneVIP {
		return netip.Addr{}, fmt.Errorf("%w: worker VM %s uses %s", errWorkerSupervisorVIPCollision, vm.UUID, privateIPv4)
	}
	inReservedPool, err := privateLoadBalancerPool.Contains(privateIPv4)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("worker VM %s private load-balancer pool: %w", vm.UUID, err)
	}
	if inReservedPool {
		return netip.Addr{}, fmt.Errorf("%w: worker VM %s uses %s in %s-%s", errWorkerServiceVIPPoolCollision, vm.UUID, privateIPv4, privateLoadBalancerPool.Start, privateLoadBalancerPool.Stop)
	}
	return privateIPv4, nil
}

func validatePrivateLoadBalancerPoolInSubnet(networkPrefix netip.Prefix, controlPlaneVIP netip.Addr, privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool) (netip.Addr, netip.Addr, error) {
	if err := privateLoadBalancerPool.ValidateForSupervisor(controlPlaneVIP); err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("private load-balancer pool: %w", err)
	}
	start, stop, _ := privateLoadBalancerPool.Range()
	if networkPrefix.Bits() > 27 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("private load-balancer pool requires VPC prefix length /27 or shorter, got %s", networkPrefix)
	}
	if err := validateUsableSubnetAddress(networkPrefix, start, "private load-balancer pool start"); err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if err := validateUsableSubnetAddress(networkPrefix, stop, "private load-balancer pool stop"); err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	return start, stop, nil
}

func validateVPCPrefixExclusions(networkPrefix netip.Prefix) error {
	for _, reserved := range fixedClusterNetworks {
		if prefixesOverlap(networkPrefix, reserved.prefix) {
			return fmt.Errorf("worker VPC subnet %s must not overlap %s %s", networkPrefix, reserved.description, reserved.prefix)
		}
	}
	return nil
}

func validateUsableSubnetAddress(prefix netip.Prefix, address netip.Addr, description string) error {
	prefix = prefix.Masked()
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return fmt.Errorf("%s cannot use unusable IPv4 subnet %s; prefix length must be /30 or shorter", description, prefix)
	}
	if !prefix.Contains(address) {
		return fmt.Errorf("%s %s must be inside subnet %s", description, address, prefix)
	}
	start, end, valid := ipv4PrefixBounds(prefix)
	value, valueValid := ipv4AddressValue(address)
	if !valid || !valueValid {
		return fmt.Errorf("%s %s is not a usable IPv4 address in subnet %s", description, address, prefix)
	}
	if value == start {
		return fmt.Errorf("%s %s is the network address of subnet %s", description, address, prefix)
	}
	if value == end {
		return fmt.Errorf("%s %s is the broadcast address of subnet %s", description, address, prefix)
	}
	return nil
}

func ipv4AddressValue(address netip.Addr) (uint64, bool) {
	if !address.IsValid() || !address.Is4() {
		return 0, false
	}
	bytes := address.As4()
	return uint64(bytes[0])<<24 | uint64(bytes[1])<<16 | uint64(bytes[2])<<8 | uint64(bytes[3]), true
}

func (a *Adapter) ensureFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix) error {
	firewalls, err := a.api.ListFirewalls(ctx, location)
	if err != nil {
		return fmt.Errorf("listing InSpace firewalls for worker assignment audit: %w", err)
	}
	firewall, err := findFirewallInList(firewalls, firewallUUID, location)
	if err != nil {
		return fmt.Errorf("validating worker firewall: %w", err)
	}
	if err := validateDefaultDenyFirewall(*firewall, networkPrefix); err != nil {
		return err
	}
	assigned, err := validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, false)
	if err != nil {
		return err
	}
	if assigned {
		return nil
	}
	mutationErr := a.api.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID)
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		firewalls, err = a.api.ListFirewalls(ctx, location)
		if readbackErr := ctx.Err(); readbackErr != nil {
			return fmt.Errorf("firewall %s assignment to VM %s read-back stopped: %w", firewallUUID, vmUUID, errors.Join(mutationErr, lastObservation, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing firewalls after assigning %s to VM %s: %w", firewallUUID, vmUUID, err)
			if !isRetryableReadback(ctx, err) {
				return errors.Join(mutationErr, lastObservation)
			}
		} else {
			firewall, err = findFirewallInList(firewalls, firewallUUID, location)
			if err == nil {
				err = validateDefaultDenyFirewall(*firewall, networkPrefix)
			}
			if err == nil {
				_, err = validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, true)
			}
			if err == nil {
				// An authoritative assignment readback wins over an ambiguous
				// mutation response; the public VM is now protected.
				return nil
			}
			lastObservation = err
			if !errors.Is(err, errFirewallAssignmentNotVisible) {
				return errors.Join(mutationErr, err)
			}
		}
		if err := waitForReadback(ctx, readbackDelay); err != nil {
			return fmt.Errorf("firewall %s assignment to VM %s did not converge: %w", firewallUUID, vmUUID, errors.Join(mutationErr, lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func validateWorkerFirewallAssignments(firewalls []sdk.Firewall, intendedFirewallUUID, vmUUID string, requireIntended bool) (bool, error) {
	assignments := make([]string, 0, 1)
	for _, firewall := range firewalls {
		for _, resource := range firewall.ResourcesAssigned {
			if strings.EqualFold(resource.ResourceType, "vm") && resource.ResourceUUID == vmUUID {
				assignments = append(assignments, firewall.UUID)
			}
		}
	}
	if len(assignments) == 0 && !requireIntended {
		return false, nil
	}
	if len(assignments) == 0 {
		return false, fmt.Errorf("%w: worker VM %s", errFirewallAssignmentNotVisible, vmUUID)
	}
	if len(assignments) != 1 || assignments[0] != intendedFirewallUUID {
		return false, fmt.Errorf("%w: worker VM %s must be attached exactly once to intended firewall %s, got %v", cloudapi.ErrOwnershipMismatch, vmUUID, intendedFirewallUUID, assignments)
	}
	return true, nil
}

func (a *Adapter) ensureFloatingAssignment(ctx context.Context, location string, floatingIP sdk.FloatingIP, vmUUID string) error {
	current, err := a.findFloatingIPByName(ctx, location, floatingIP.Name, floatingIP.BillingAccountID)
	if err != nil {
		return err
	}
	if current.Address != floatingIP.Address {
		return fmt.Errorf("%w: named floating IP address changed", cloudapi.ErrOwnershipMismatch)
	}
	if err := a.validateWorkerFloatingIPAssignments(ctx, location, *current, vmUUID, false); err != nil {
		return err
	}
	if current.AssignedTo != "" {
		if current.AssignedTo == vmUUID && current.AssignedToResourceType == "virtual_machine" {
			return a.validateWorkerFloatingIPAssignments(ctx, location, *current, vmUUID, true)
		}
		return fmt.Errorf("%w: floating IP %s is assigned to %s", cloudapi.ErrOwnershipMismatch, current.Address, current.AssignedTo)
	}
	return fmt.Errorf("%w: auto-reserved floating IP %s is no longer assigned to worker VM %s", cloudapi.ErrOwnershipMismatch, current.Address, vmUUID)
}

func (a *Adapter) validateWorkerFloatingIPAssignments(ctx context.Context, location string, expected sdk.FloatingIP, vmUUID string, requireExpected bool) error {
	addresses, err := a.api.ListFloatingIPs(ctx, location, nil)
	if err != nil {
		return fmt.Errorf("auditing floating IP assignments for worker VM %s: %w", vmUUID, err)
	}
	return validateWorkerFloatingIPAssignmentsInList(addresses, expected, vmUUID, requireExpected)
}

func validateWorkerFloatingIPAssignmentsInList(addresses []sdk.FloatingIP, expected sdk.FloatingIP, vmUUID string, requireExpected bool) error {
	assigned := make([]sdk.FloatingIP, 0, 1)
	for _, address := range addresses {
		if address.AssignedTo != vmUUID {
			continue
		}
		if err := validateUsableFloatingIP(address); err != nil {
			return fmt.Errorf("%w: worker VM %s has an unusable floating IP assignment %q: %v", cloudapi.ErrOwnershipMismatch, vmUUID, address.Address, err)
		}
		assigned = append(assigned, address)
	}
	if len(assigned) == 0 && !requireExpected {
		return nil
	}
	if len(assigned) != 1 || assigned[0].Address != expected.Address || assigned[0].Name != expected.Name || assigned[0].AssignedToResourceType != "virtual_machine" {
		return fmt.Errorf("%w: worker VM %s must have exactly one floating IP, the provider-owned address %s", cloudapi.ErrOwnershipMismatch, vmUUID, expected.Address)
	}
	return nil
}

func (a *Adapter) cleanupLaunch(ctx context.Context, location, firewallUUID, vmUUID string, floatingIP sdk.FloatingIP, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchCleanupTimeout)
	defer cancel()
	var errs []error
	// Reserve most of the detached cleanup window for deletion of the
	// ownership-proven unprotected VM. A persistently uncertain floating-IP
	// readback must not consume the entire window before VM DELETE is sent.
	floatingCtx, floatingCancel := context.WithTimeout(cleanupCtx, a.launchFloatingIPCleanupTimeout)
	floatingErr := a.deleteOwnedFloatingIP(floatingCtx, location, floatingIP, vmUUID)
	floatingCancel()
	vmDeleteErr := a.api.DeleteVM(cleanupCtx, location, vmUUID)
	if absenceErr := a.waitForVMAbsence(cleanupCtx, location, vmUUID, "after launch rollback"); absenceErr != nil {
		if floatingErr != nil {
			errs = append(errs, floatingErr)
		}
		if vmDeleteErr != nil {
			errs = append(errs, fmt.Errorf("deleting unprotected VM %s during launch rollback: %w", vmUUID, vmDeleteErr))
		}
		errs = append(errs, fmt.Errorf("cleanup of unprotected VM %s did not prove absence; cloud firewall remains attached: %w", vmUUID, absenceErr))
		return errors.Join(append([]error{cause}, errs...)...)
	}
	// Once VM absence is canonical, retire every stale firewall assignment
	// before spending the remaining detached cleanup budget on the recoverable,
	// deterministically named floating IP.
	if err := a.detachFirewallAfterVMDeletion(cleanupCtx, location, firewallUUID, vmUUID); err != nil {
		errs = append(errs, err)
	}
	if floatingErr != nil {
		// A VM deletion may release the assignment asynchronously. Retry the
		// exact address only after canonical VM absence has been established.
		floatingErr = a.deleteOwnedFloatingIP(cleanupCtx, location, floatingIP, vmUUID)
	}
	if floatingErr != nil {
		errs = append(errs, floatingErr)
	}
	return errors.Join(append([]error{cause}, errs...)...)
}

func (a *Adapter) detachFirewallAfterVMDeletion(ctx context.Context, location, _ string, vmUUID string) error {
	// The caller invokes this only after VM absence is confirmed. Scan every
	// firewall for the exact deleted VM UUID so rollback also cleans unexpected
	// second-firewall assignments without ever detaching a live VM. A mutation
	// response is not convergence: require repeated authoritative list absence.
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation, mutationErr error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		firewalls, err := a.api.ListFirewalls(requestCtx, location)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return fmt.Errorf("firewall cleanup for deleted VM %s stopped: %w", vmUUID, errors.Join(errFirewallCleanupUncertain, lastObservation, mutationErr, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing firewalls for deleted VM cleanup: %w", err)
			if !isRetryableReadback(readbackCtx, err) {
				return lastObservation
			}
		} else {
			assignments, validationErr := firewallAssignmentsForVM(firewalls, vmUUID)
			if validationErr != nil {
				return validationErr
			}
			if len(assignments) == 0 {
				absenceConfirmations++
				lastObservation = fmt.Errorf("firewall assignment absence confirmation %d of 2 for VM %s", absenceConfirmations, vmUUID)
				if absenceConfirmations == 2 {
					return nil
				}
			} else {
				absenceConfirmations = 0
				lastObservation = fmt.Errorf("VM %s remains assigned to firewalls %v", vmUUID, assignments)
				for _, firewallUUID := range assignments {
					requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
					err := a.api.UnassignFirewallFromVM(requestCtx, location, firewallUUID, vmUUID)
					requestCancel()
					if err != nil {
						mutationErr = fmt.Errorf("unassigning firewall %s from deleted VM %s: %w", firewallUUID, vmUUID, err)
						if !isRetryableCleanupMutation(err) {
							return mutationErr
						}
					}
				}
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return fmt.Errorf("firewall assignments for deleted VM %s did not converge: %w", vmUUID, errors.Join(errFirewallCleanupUncertain, lastObservation, mutationErr, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) deleteOwnedFloatingIP(ctx context.Context, location string, floatingIP sdk.FloatingIP, expectedVMUUID string) error {
	if floatingIP.Name == "" || floatingIP.Address == "" || floatingIP.BillingAccountID <= 0 {
		return fmt.Errorf("%w: incomplete floating IP ownership anchor", cloudapi.ErrOwnershipMismatch)
	}
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation, mutationErr error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		addresses, err := a.api.ListFloatingIPs(requestCtx, location, nil)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return fmt.Errorf("floating IP %s cleanup stopped: %w", floatingIP.Address, errors.Join(errFloatingIPCleanupUncertain, lastObservation, mutationErr, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing floating IPs for cleanup: %w", err)
			if !isRetryableReadback(readbackCtx, err) {
				return lastObservation
			}
		} else {
			current, present, validationErr := exactFloatingIPForCleanup(addresses, floatingIP, expectedVMUUID)
			if validationErr != nil {
				return validationErr
			}
			if !present {
				absenceConfirmations++
				lastObservation = fmt.Errorf("floating IP %s absence confirmation %d of 2", floatingIP.Address, absenceConfirmations)
				if absenceConfirmations == 2 {
					return nil
				}
			} else {
				absenceConfirmations = 0
				switch {
				case current.AssignedTo != "":
					if expectedVMUUID == "" || current.AssignedTo != expectedVMUUID || current.AssignedToResourceType != "virtual_machine" {
						return fmt.Errorf("%w: refusing to unassign floating IP %s from %s", cloudapi.ErrOwnershipMismatch, current.Address, current.AssignedTo)
					}
					lastObservation = fmt.Errorf("floating IP %s remains assigned to VM %s", current.Address, expectedVMUUID)
					requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
					_, err := a.api.UnassignFloatingIP(requestCtx, location, current.Address)
					requestCancel()
					if err != nil {
						mutationErr = fmt.Errorf("unassigning floating IP %s: %w", current.Address, err)
						if !isRetryableCleanupMutation(err) {
							return mutationErr
						}
					}
				default:
					lastObservation = fmt.Errorf("floating IP %s remains visible and unassigned", current.Address)
					requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
					err := a.api.DeleteFloatingIP(requestCtx, location, current.Address)
					requestCancel()
					if err != nil {
						mutationErr = fmt.Errorf("deleting floating IP %s: %w", current.Address, err)
						if !isRetryableCleanupMutation(err) {
							return mutationErr
						}
					}
				}
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return fmt.Errorf("floating IP %s cleanup did not converge: %w", floatingIP.Address, errors.Join(errFloatingIPCleanupUncertain, lastObservation, mutationErr, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func exactFloatingIPForCleanup(addresses []sdk.FloatingIP, expected sdk.FloatingIP, expectedVMUUID string) (*sdk.FloatingIP, bool, error) {
	var exact []sdk.FloatingIP
	for i := range addresses {
		address := addresses[i]
		if address.IsDeleted {
			// List responses may retain stale deletion tombstones. They are not
			// active ownership conflicts and cannot be mutation targets.
			continue
		}
		identityOverlap := address.Name == expected.Name || address.Address == expected.Address ||
			(expectedVMUUID != "" && address.AssignedTo == expectedVMUUID)
		if !identityOverlap {
			continue
		}
		if address.Name != expected.Name || address.Address != expected.Address || address.BillingAccountID != expected.BillingAccountID {
			return nil, false, fmt.Errorf("%w: floating IP ownership anchor %q/%s/account-%d changed", cloudapi.ErrOwnershipMismatch, expected.Name, expected.Address, expected.BillingAccountID)
		}
		exact = append(exact, address)
	}
	if len(exact) == 0 {
		return nil, false, nil
	}
	if len(exact) != 1 {
		return nil, false, fmt.Errorf("%w: floating IP ownership anchor %q/%s appears %d times", cloudapi.ErrOwnershipMismatch, expected.Name, expected.Address, len(exact))
	}
	return &exact[0], true, nil
}

func firewallAssignmentsForVM(firewalls []sdk.Firewall, vmUUID string) ([]string, error) {
	seenFirewalls := make(map[string]bool, len(firewalls))
	assignments := make([]string, 0, 1)
	for i := range firewalls {
		if firewalls[i].UUID == "" {
			return nil, fmt.Errorf("%w: firewall list row %d has no UUID", cloudapi.ErrOwnershipMismatch, i)
		}
		if seenFirewalls[firewalls[i].UUID] {
			return nil, fmt.Errorf("%w: firewall list contains duplicate UUID %s", cloudapi.ErrOwnershipMismatch, firewalls[i].UUID)
		}
		seenFirewalls[firewalls[i].UUID] = true
		for _, resource := range firewalls[i].ResourcesAssigned {
			if resource.ResourceUUID != vmUUID {
				continue
			}
			if !strings.EqualFold(resource.ResourceType, "vm") {
				return nil, fmt.Errorf("%w: resource UUID %s appears on firewall %s with type %q", cloudapi.ErrOwnershipMismatch, vmUUID, firewalls[i].UUID, resource.ResourceType)
			}
			assignments = append(assignments, firewalls[i].UUID)
		}
	}
	sort.Strings(assignments)
	return assignments, nil
}

func (a *Adapter) readOrphanFloatingIPForDelete(ctx context.Context, location, vmUUID, expectedName string, identity cloudapi.DeleteVMIdentity) (*sdk.FloatingIP, error) {
	if err := validateDurableDeleteLookupIdentity(identity, expectedName); err != nil {
		return nil, fmt.Errorf("%w: missing VM %s orphan cleanup requires durable floating IP name/address lookup identity: %v", cloudapi.ErrOwnershipMismatch, vmUUID, err)
	}
	readbackCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentReadbackTimeout)
	defer cancel()
	absenceConfirmations := 0
	var lastObservation error
	readbackDelay := a.networkAttachmentReadbackMinDelay
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		addresses, err := a.api.ListFloatingIPs(requestCtx, location, nil)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return nil, fmt.Errorf("orphan floating IP discovery for missing VM %s stopped: %w", vmUUID, errors.Join(lastObservation, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("listing floating IPs for missing VM %s: %w", vmUUID, err)
			if !isRetryableReadback(readbackCtx, err) {
				return nil, lastObservation
			}
		} else {
			if identity.BillingAccountID == 0 {
				for i := range addresses {
					if addresses[i].IsDeleted {
						continue
					}
					if addresses[i].Name == identity.FloatingIPName || addresses[i].Address == identity.PublicIPv4 || addresses[i].AssignedTo == vmUUID {
						return nil, fmt.Errorf("%w: active floating IP overlaps pre-billing durable identity for missing VM %s", cloudapi.ErrOwnershipMismatch, vmUUID)
					}
				}
			}
			matches := make([]sdk.FloatingIP, 0, 1)
			var contradictory []sdk.FloatingIP
			for i := range addresses {
				if addresses[i].IsDeleted {
					continue
				}
				overlaps := addresses[i].Name == identity.FloatingIPName ||
					addresses[i].Address == identity.PublicIPv4 || addresses[i].AssignedTo == vmUUID
				if !overlaps {
					continue
				}
				if addresses[i].Name == identity.FloatingIPName &&
					addresses[i].Address == identity.PublicIPv4 &&
					addresses[i].BillingAccountID == identity.BillingAccountID {
					matches = append(matches, addresses[i])
				} else {
					contradictory = append(contradictory, addresses[i])
				}
			}
			if len(contradictory) != 0 {
				return nil, fmt.Errorf("%w: floating IP inventory contradicts durable orphan identity %q/%s/account-%d for missing VM %s", cloudapi.ErrOwnershipMismatch, identity.FloatingIPName, identity.PublicIPv4, identity.BillingAccountID, vmUUID)
			}
			switch len(matches) {
			case 0:
				absenceConfirmations++
				lastObservation = fmt.Errorf("named floating IP absence confirmation %d of 2 for missing VM %s", absenceConfirmations, vmUUID)
				if absenceConfirmations == 2 {
					return nil, nil
				}
			case 1:
				candidate := matches[0]
				assignedIdentityValid := candidate.AssignedTo == "" ||
					(candidate.AssignedTo == vmUUID && candidate.AssignedToResourceType == "virtual_machine")
				if !assignedIdentityValid {
					return nil, fmt.Errorf("%w: durable floating IP %q cannot be proven to belong to missing VM %s", cloudapi.ErrOwnershipMismatch, expectedName, vmUUID)
				}
				if err := validateUsableFloatingIP(candidate); err != nil {
					return nil, fmt.Errorf("%w: durable floating IP %q for missing VM %s is unusable: %v", cloudapi.ErrOwnershipMismatch, expectedName, vmUUID, err)
				}
				return &candidate, nil
			default:
				return nil, fmt.Errorf("%w: %d floating IPs share exact durable orphan identity %q/%s/account-%d", cloudapi.ErrOwnershipMismatch, len(matches), identity.FloatingIPName, identity.PublicIPv4, identity.BillingAccountID)
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return nil, fmt.Errorf("orphan floating IP discovery for missing VM %s did not converge: %w", vmUUID, errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func (a *Adapter) findFloatingIPByName(ctx context.Context, location, name string, billingAccountID int64) (*sdk.FloatingIP, error) {
	address, err := a.findFloatingIPByNameRaw(ctx, location, name, billingAccountID)
	if err != nil {
		return nil, err
	}
	if err := validateUsableFloatingIP(*address); err != nil {
		return nil, fmt.Errorf("%w: named floating IP %q is unusable: %v", cloudapi.ErrOwnershipMismatch, name, err)
	}
	return address, nil
}

func (a *Adapter) findFloatingIPByNameRaw(ctx context.Context, location, name string, billingAccountID int64) (*sdk.FloatingIP, error) {
	var filters *sdk.FloatingIPFilters
	if billingAccountID > 0 {
		filters = &sdk.FloatingIPFilters{BillingAccountID: billingAccountID}
	}
	addresses, err := a.api.ListFloatingIPs(ctx, location, filters)
	if err != nil {
		return nil, fmt.Errorf("listing floating IPs: %w", err)
	}
	return findFloatingIPInListRaw(addresses, name, billingAccountID)
}

func findFloatingIPInListRaw(addresses []sdk.FloatingIP, name string, billingAccountID int64) (*sdk.FloatingIP, error) {
	var matches []sdk.FloatingIP
	for _, address := range addresses {
		if address.Name == name && !address.IsDeleted && (billingAccountID == 0 || address.BillingAccountID == 0 || address.BillingAccountID == billingAccountID) {
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

func validateUsableFloatingIP(address sdk.FloatingIP) error {
	parsed, err := netip.ParseAddr(address.Address)
	if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return fmt.Errorf("address %q must be a public IPv4 address", address.Address)
	}
	if !address.Enabled {
		return fmt.Errorf("address %s is disabled", address.Address)
	}
	if address.IsDeleted {
		return fmt.Errorf("address %s is deleted", address.Address)
	}
	if address.IsVirtual {
		return fmt.Errorf("address %s is virtual", address.Address)
	}
	if !strings.EqualFold(strings.TrimSpace(address.Type), "public") {
		return fmt.Errorf("address %s has type %q, want public", address.Address, address.Type)
	}
	return nil
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
	return findFirewallInList(firewalls, uuid, location)
}

func findFirewallInList(firewalls []sdk.Firewall, uuid, location string) (*sdk.Firewall, error) {
	var matches []sdk.Firewall
	for i := range firewalls {
		if firewalls[i].UUID == uuid {
			matches = append(matches, firewalls[i])
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("firewall %s is not available in location %s", uuid, location)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%w: %d firewalls share UUID %s", cloudapi.ErrOwnershipMismatch, len(matches), uuid)
	}
	return &matches[0], nil
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
	podCIDR := netip.MustParsePrefix(bootstrap.NativeRoutingPodCIDR)
	inboundAllTraffic := map[string][]netip.Prefix{}
	outboundAnyAllPorts := map[string]bool{}
	for _, rule := range firewall.Rules {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
			return fmt.Errorf("firewall %s has unsupported rule protocol %q", firewall.UUID, rule.Protocol)
		}
		if rule.Direction != "inbound" && rule.Direction != "outbound" {
			return fmt.Errorf("firewall %s has unsupported rule direction %q", firewall.UUID, rule.Direction)
		}
		if rule.Direction == "outbound" {
			if rule.EndpointSpecType == "any" && allProtocolTraffic(rule) {
				outboundAnyAllPorts[rule.Protocol] = true
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
			if !isRFC1918Prefix(prefix) {
				return fmt.Errorf("firewall %s must not allow public inbound prefix %q on workers", firewall.UUID, value)
			}
			if allProtocolTraffic(rule) {
				inboundAllTraffic[rule.Protocol] = append(inboundAllTraffic[rule.Protocol], prefix)
			}
		}
	}
	if missing := missingInboundFirewallProtocols(inboundAllTraffic, network); len(missing) != 0 {
		return fmt.Errorf("firewall %s must allow all inbound %s traffic from network subnet %s", firewall.UUID, strings.Join(missing, ", "), network)
	}
	if missing := missingInboundFirewallProtocols(inboundAllTraffic, podCIDR); len(missing) != 0 {
		return fmt.Errorf("firewall %s must allow all inbound %s traffic from Cilium native-routing pod CIDR %s", firewall.UUID, strings.Join(missing, ", "), podCIDR)
	}
	if missing := missingFirewallProtocols(outboundAnyAllPorts); len(missing) != 0 {
		return fmt.Errorf("firewall %s must allow all outbound %s traffic to any endpoint for public-IP egress", firewall.UUID, strings.Join(missing, ", "))
	}
	return nil
}

func missingInboundFirewallProtocols(covered map[string][]netip.Prefix, target netip.Prefix) []string {
	missing := make([]string, 0, 3)
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		if !prefixesCover(target, covered[protocol]) {
			missing = append(missing, strings.ToUpper(protocol))
		}
	}
	return missing
}

func missingFirewallProtocols(covered map[string]bool) []string {
	missing := make([]string, 0, 3)
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		if !covered[protocol] {
			missing = append(missing, strings.ToUpper(protocol))
		}
	}
	return missing
}

func allPorts(rule sdk.FirewallRule) bool {
	return (rule.PortStart == nil && rule.PortEnd == nil) ||
		(rule.PortStart != nil && rule.PortEnd != nil && *rule.PortStart == 1 && *rule.PortEnd == 65535)
}

func allProtocolTraffic(rule sdk.FirewallRule) bool {
	if rule.Protocol == "icmp" {
		return rule.PortStart == nil && rule.PortEnd == nil
	}
	return allPorts(rule)
}

func prefixesCover(target netip.Prefix, prefixes []netip.Prefix) bool {
	targetStart, targetEnd, ok := ipv4PrefixBounds(target)
	if !ok {
		return false
	}
	type interval struct{ start, end uint64 }
	intervals := make([]interval, 0, len(prefixes))
	for _, prefix := range prefixes {
		start, end, valid := ipv4PrefixBounds(prefix)
		if !valid || end < targetStart || start > targetEnd {
			continue
		}
		if start < targetStart {
			start = targetStart
		}
		if end > targetEnd {
			end = targetEnd
		}
		intervals = append(intervals, interval{start: start, end: end})
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start == intervals[j].start {
			return intervals[i].end < intervals[j].end
		}
		return intervals[i].start < intervals[j].start
	})
	cursor := targetStart
	for _, current := range intervals {
		if current.start > cursor {
			return false
		}
		if current.end >= targetEnd {
			return true
		}
		if next := current.end + 1; next > cursor {
			cursor = next
		}
	}
	return false
}

func ipv4PrefixBounds(prefix netip.Prefix) (uint64, uint64, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
		return 0, 0, false
	}
	address := prefix.Masked().Addr().As4()
	start := uint64(address[0])<<24 | uint64(address[1])<<16 | uint64(address[2])<<8 | uint64(address[3])
	size := uint64(1) << uint(32-prefix.Bits())
	return start, start + size - 1, true
}

func prefixesOverlap(first, second netip.Prefix) bool {
	firstStart, firstEnd, firstValid := ipv4PrefixBounds(first)
	secondStart, secondEnd, secondValid := ipv4PrefixBounds(second)
	return firstValid && secondValid && firstStart <= secondEnd && secondStart <= firstEnd
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
	if json.Unmarshal([]byte(description), &record) != nil || !supportedOwnershipSchema(record.Schema) || record.Cluster == "" ||
		record.NodeClaim == "" || record.KeyHash == "" || record.FloatingIPName == "" ||
		(record.Schema != ownershipSchema && record.PublicIPv4 == "") {
		return ownership{}, false
	}
	return record, true
}

func inspectOwnershipDescription(description, targetCluster string) (record ownership, karpenter, complete bool, err error) {
	var envelope struct {
		Schema  json.RawMessage `json:"schema"`
		Cluster json.RawMessage `json:"cluster"`
	}
	if json.Unmarshal([]byte(description), &envelope) == nil {
		var schema string
		if json.Unmarshal(envelope.Schema, &schema) != nil {
			return ownership{}, false, false, nil
		}
		if strings.HasPrefix(schema, ownershipSchemaNamespace) && !supportedOwnershipSchema(schema) {
			return ownership{}, false, false, fmt.Errorf("%w: unsupported Karpenter ownership schema %q", cloudapi.ErrOwnershipMismatch, schema)
		}
		if !supportedOwnershipSchema(schema) {
			return ownership{}, false, false, nil
		}
		if json.Unmarshal([]byte(description), &record) != nil {
			// The minimal schema envelope is authoritative even when another
			// v1 field has an incompatible JSON type. Preserve any independently
			// decodable cluster evidence and keep the record fail-closed.
			record.Schema = schema
			_ = json.Unmarshal(envelope.Cluster, &record.Cluster)
			return record, true, false, nil
		}
		if !ownershipRecordStructurallyComplete(record) {
			return record, true, false, nil
		}
		// A complete, explicit record for another cluster is foreign inventory.
		// Route it before interpreting target-cluster host/capacity extensions:
		// another provider revision's semantics must not break this scoped list.
		// Reserved future schemas remain rejected above for every cluster.
		if record.Cluster != targetCluster {
			return record, true, true, nil
		}
		normalized, partial, err := normalizeOwnershipLaunchIdentity(record)
		if err != nil {
			return ownership{}, false, false, fmt.Errorf("%w: invalid Karpenter ownership launch identity: %v", cloudapi.ErrOwnershipMismatch, err)
		}
		return normalized, true, !partial, nil
	}
	// Ownership JSON is encoded with schema first. An anchored prefix retains
	// evidence from an eventually consistent truncated response without
	// treating arbitrary user notes that mention the schema as managed state.
	prefix := karpenterOwnershipPrefixPattern.FindStringSubmatch(description)
	if len(prefix) != 2 {
		return ownership{}, false, false, nil
	}
	record.Schema = prefix[1]
	if !supportedOwnershipSchema(record.Schema) {
		return ownership{}, false, false, fmt.Errorf("%w: unsupported Karpenter ownership schema %q", cloudapi.ErrOwnershipMismatch, record.Schema)
	}
	if match := karpenterClusterPattern.FindStringSubmatch(description); len(match) == 2 {
		record.Cluster = match[1]
	}
	return record, true, false, nil
}

func ownershipRecordStructurallyComplete(record ownership) bool {
	validSchemaAndName := ((record.Schema == ownershipSchema || record.Schema == legacyV2OwnershipSchema) && record.VMName != "") || record.Schema == legacyOwnershipSchema
	validPublicIdentity := record.Schema == ownershipSchema || record.PublicIPv4 != ""
	return validSchemaAndName && record.Cluster != "" && record.NodeClaim != "" && record.KeyHash != "" &&
		record.HostClass != "" && record.InstanceType != "" && record.RootDiskGiB > 0 && record.SpecHash != "" &&
		record.BootstrapHash != "" && record.FirewallUUID != "" && record.NetworkUUID != "" && record.ControlPlaneVIP != "" &&
		record.PrivateLoadBalancerPoolStart != "" && record.PrivateLoadBalancerPoolStop != "" && record.OSName != "" &&
		record.OSVersion != "" && record.BillingAccountID > 0 && record.FloatingIPName != "" && validPublicIdentity
}

func supportedOwnershipSchema(schema string) bool {
	return schema == ownershipSchema || schema == legacyV2OwnershipSchema || schema == legacyOwnershipSchema
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

func isRetryableCleanupMutation(err error) bool {
	if errors.Is(err, sdk.ErrCrossOriginRedirect) || errors.Is(err, sdk.ErrMutationBlocked) {
		return false
	}
	if sdk.IsNotFound(err) {
		// A remote 404 may be stale or may describe an asynchronously applied
		// prior mutation. Re-read exact state and retry only if it remains.
		return true
	}
	var apiErr *sdk.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable || apiErr.StatusCode == http.StatusRequestTimeout
	}
	// Transport and response-read failures are ambiguous. Exact identity is
	// revalidated before every bounded retry.
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
