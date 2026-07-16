// Package inspace adapts the shared InSpace API client to Karpenter's cloud
// model. VM, firewall-assignment, and floating-IP POSTs are never blindly
// retried. Reconciliation uses deterministic ownership records and read-back.
package inspace

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	// The SDK permits a VM mutation request to run for up to five minutes.
	// Cleanup waits an additional visibility allowance before absence proof.
	defaultCreateAmbiguityWindow     = 10 * time.Minute
	defaultCreateAbsenceReadInterval = 30 * time.Second
	createAbsenceConfirmations       = 3
	canonicalVMReadConcurrency       = 8
)

var (
	errWorkerSupervisorVIPCollision        = errors.New("worker private IPv4 collides with the private RKE2 supervisor VIP")
	errWorkerServiceVIPPoolCollision       = errors.New("worker private IPv4 collides with the reserved private Service VIP pool")
	errFirewallAssignmentNotVisible        = errors.New("intended worker firewall assignment is not visible")
	errFirewallAssignmentReadbackDuplicate = errors.New("intended worker firewall assignment appears more than once during readback")
	errEarlyFirewallProtection             = errors.New("early worker firewall protection failed")
	errFreshOwnershipProof                 = errors.New("fresh worker canonical ownership proof failed")
	errPersistedOwnershipIncomplete        = errors.New("persisted VM ownership record is incomplete")
	errVMAbsenceUncertain                  = errors.New("VM absence could not be established")
	errFloatingIPCleanupUncertain          = errors.New("floating IP cleanup did not converge")
	errFirewallCleanupUncertain            = errors.New("firewall cleanup did not converge")
	vmUUIDPattern                          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	ownedInstanceTypePattern               = regexp.MustCompile(`^is-(compute|general|memory|extra-memory)-([0-9]+)c-([0-9]+)g$`)
	nodeLoadBalancerShardPattern           = regexp.MustCompile(`^inlb-[0-9a-f]{8}$`)
	nodeLoadBalancerShardFirewallPattern   = regexp.MustCompile(`^inlb-[0-9a-f]{32}-shard-([0-9a-f]{8})$`)
	createAttemptTokenPattern              = regexp.MustCompile(`^[0-9a-f]{32}$`)
	karpenterOwnershipPrefixPattern        = regexp.MustCompile(`^\s*\{\s*"schema"\s*:\s*"(karpenter\.inspace\.cloud/[^"\s]+)"(?:\s*[,}]|\s*$)`)
	karpenterClusterPattern                = regexp.MustCompile(`"cluster"\s*:\s*"([^"]*)"`)
	fixedClusterNetworks                   = [...]struct {
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
	createAmbiguityWindow             time.Duration
	createAbsenceReadInterval         time.Duration
	now                               func() time.Time
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
		createAmbiguityWindow:             defaultCreateAmbiguityWindow,
		createAbsenceReadInterval:         defaultCreateAbsenceReadInterval,
		now:                               time.Now,
	}, nil
}

type ownership struct {
	Schema                       string                    `json:"schema"`
	Cluster                      string                    `json:"cluster"`
	NodePool                     string                    `json:"nodePool,omitempty"`
	NodeClaim                    string                    `json:"nodeClaim"`
	VMName                       string                    `json:"vmName,omitempty"`
	KeyHash                      string                    `json:"keyHash"`
	HostClass                    string                    `json:"hostClass"`
	InstanceType                 string                    `json:"instanceType"`
	HostPoolUUID                 string                    `json:"hostPoolUUID,omitempty"`
	VCPU                         int                       `json:"vCPU,omitempty"`
	MemoryGiB                    int                       `json:"memoryGiB,omitempty"`
	RootDiskGiB                  int32                     `json:"rootDiskGiB"`
	SpecHash                     string                    `json:"specHash"`
	BootstrapHash                string                    `json:"bootstrapHash"`
	FirewallUUID                 string                    `json:"firewallUUID"`
	FirewallProfile              inspacev1.FirewallProfile `json:"firewallProfile,omitempty"`
	NetworkUUID                  string                    `json:"networkUUID,omitempty"`
	ControlPlaneVIP              string                    `json:"controlPlaneVIP,omitempty"`
	PrivateLoadBalancerPoolStart string                    `json:"privateLoadBalancerPoolStart,omitempty"`
	PrivateLoadBalancerPoolStop  string                    `json:"privateLoadBalancerPoolStop,omitempty"`
	OSName                       string                    `json:"osName"`
	OSVersion                    string                    `json:"osVersion"`
	BillingAccountID             int64                     `json:"billingAccountID"`
	FloatingIPName               string                    `json:"floatingIPName"`
	PublicIPv4                   string                    `json:"publicIPv4,omitempty"`
}

func newOwnership(request cloudapi.CreateVMRequest) ownership {
	return ownership{
		Schema: ownershipSchema, Cluster: request.ClusterName, NodePool: request.NodePoolName, NodeClaim: request.NodeClaimName, VMName: request.Name,
		KeyHash: hashKey(request.IdempotencyKey), HostClass: request.HostClass, InstanceType: request.InstanceType,
		HostPoolUUID: request.HostPoolUUID, VCPU: request.VCPU, MemoryGiB: request.MemoryGiB,
		RootDiskGiB: request.RootDiskGiB, SpecHash: request.SpecHash, BootstrapHash: request.BootstrapHash,
		FirewallUUID: request.FirewallUUID, FirewallProfile: inspacev1.EffectiveFirewallProfile(request.FirewallProfile),
		NetworkUUID: request.NetworkUUID, ControlPlaneVIP: request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: request.PrivateLoadBalancerPoolStop,
		OSName: request.OSName, OSVersion: request.OSVersion,
		BillingAccountID: request.BillingAccountID, FloatingIPName: floatingIPName(request.ClusterName, request.NodeClaimName),
	}
}

// PrepareCreate captures the bounded raw resource inventory before Kubernetes
// grants this NodeClaim its immutable one-POST fence. It performs no mutation.
func (a *Adapter) PrepareCreate(ctx context.Context, request cloudapi.CreateVMRequest) (cloudapi.CreateInventory, error) {
	if err := validateCreateRequest(request); err != nil {
		return cloudapi.CreateInventory{}, err
	}
	// ListVMs, VPC membership, and assigned FIPs are all eventually consistent
	// discovery indexes. Baseline their union and exact-read every UUID so a VM
	// hidden from one index cannot later be mistaken for a post-POST result.
	canonicalVMs, addresses, err := a.fenceDiscoverySnapshot(ctx, request.Location, request.NetworkUUID, fenceDiscoveryPolicy{BeforeCreate: true})
	if err != nil {
		return cloudapi.CreateInventory{}, fmt.Errorf("capturing symmetric pre-POST discovery inventory: %w", err)
	}
	inventory := cloudapi.CreateInventory{VMs: make([]string, 0, len(canonicalVMs))}
	targetVMs := make(map[string]struct{})
	for i := range canonicalVMs {
		vmUUID := strings.ToLower(canonicalVMs[i].UUID)
		inventory.VMs = append(inventory.VMs, vmUUID)
		record, managed, complete, definitivelyForeign, inspectErr := inspectOwnershipForFence(canonicalVMs[i].Description, request.ClusterName, request.NodeClaimName)
		clearlyForeign := definitivelyForeign || (inspectErr == nil && ((managed && complete && record.NodeClaim != "" && record.NodeClaim != request.NodeClaimName) ||
			(!managed && canonicalVMs[i].Name != "" && canonicalVMs[i].Name != request.Name)))
		candidate := canonicalVMs[i].Name == request.Name ||
			(managed && (record.Cluster == "" || record.Cluster == request.ClusterName) &&
				(record.NodeClaim == "" || record.NodeClaim == request.NodeClaimName) &&
				(record.KeyHash == "" || record.KeyHash == hashKey(request.IdempotencyKey)))
		if candidate || !clearlyForeign {
			inventory.PotentialVMs = append(inventory.PotentialVMs, vmUUID)
		}
		if candidate {
			inventory.TargetVMs = append(inventory.TargetVMs, vmUUID)
			targetVMs[vmUUID] = struct{}{}
		}
	}
	for i := range addresses {
		if addresses[i].IsDeleted {
			continue
		}
		identity, identityErr := floatingIPInventoryIdentity(addresses[i])
		if identityErr != nil {
			return cloudapi.CreateInventory{}, fmt.Errorf("validating floating IP pre-POST inventory: %w", identityErr)
		}
		inventory.FloatingIPs = append(inventory.FloatingIPs, identity)
		assignedVMUUID := strings.ToLower(addresses[i].AssignedTo)
		if _, target := targetVMs[assignedVMUUID]; target {
			address, addressErr := netip.ParseAddr(addresses[i].Address)
			if addresses[i].AssignedToResourceType != "virtual_machine" || addressErr != nil || !address.Is4() ||
				!address.IsGlobalUnicast() || address.IsPrivate() || addresses[i].BillingAccountID != request.BillingAccountID {
				return cloudapi.CreateInventory{}, fmt.Errorf("%w: target VM %s has an invalid pre-authorization floating-IP association", cloudapi.ErrOwnershipMismatch, assignedVMUUID)
			}
			inventory.TargetFloatingIPs = append(inventory.TargetFloatingIPs, cloudapi.CreateFloatingIPAssignment{
				Identity: identity, VMUUID: assignedVMUUID, Address: address.String(), Name: addresses[i].Name,
				BillingAccountID: addresses[i].BillingAccountID,
			})
		}
	}
	sort.Strings(inventory.VMs)
	sort.Strings(inventory.PotentialVMs)
	sort.Strings(inventory.TargetVMs)
	sort.Strings(inventory.FloatingIPs)
	sort.Slice(inventory.TargetFloatingIPs, func(i, j int) bool {
		if inventory.TargetFloatingIPs[i].VMUUID != inventory.TargetFloatingIPs[j].VMUUID {
			return inventory.TargetFloatingIPs[i].VMUUID < inventory.TargetFloatingIPs[j].VMUUID
		}
		return inventory.TargetFloatingIPs[i].Identity < inventory.TargetFloatingIPs[j].Identity
	})
	inventory.VMs = compactSortedIdentities(inventory.VMs)
	inventory.PotentialVMs = compactSortedIdentities(inventory.PotentialVMs)
	inventory.TargetVMs = compactSortedIdentities(inventory.TargetVMs)
	inventory.FloatingIPs = compactSortedIdentities(inventory.FloatingIPs)
	if len(inventory.VMs) > cloudapi.MaxCreateInventoryEntries || len(inventory.PotentialVMs) > cloudapi.MaxCreateInventoryEntries || len(inventory.TargetVMs) > cloudapi.MaxCreateInventoryEntries || len(inventory.FloatingIPs) > cloudapi.MaxCreateInventoryEntries || len(inventory.TargetFloatingIPs) > cloudapi.MaxCreateTargetFloatingIPAssignments {
		return cloudapi.CreateInventory{}, fmt.Errorf("pre-POST inventory exceeds the safe bound of %d VM or floating-IP identities", cloudapi.MaxCreateInventoryEntries)
	}
	if encoded, err := json.Marshal(inventory); err != nil || len(encoded) > cloudapi.MaxCreateInventoryEncodedBytes {
		return cloudapi.CreateInventory{}, fmt.Errorf("pre-POST inventory exceeds the safe encoded bound of %d bytes", cloudapi.MaxCreateInventoryEncodedBytes)
	}
	return inventory, nil
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
	if request.CreatedVMUUID != "" {
		anchored, missing, err := a.readVMForDelete(ctx, request.Location, request.NetworkUUID, request.CreatedVMUUID)
		if err != nil {
			return nil, fmt.Errorf("exact-reading durable created VM anchor %s: %w", request.CreatedVMUUID, err)
		}
		if missing {
			return nil, fmt.Errorf("%w: durably anchored VM %s is currently absent; cleanup/finalizer reconciliation must resolve it", cloudapi.ErrCreateAttemptPending, request.CreatedVMUUID)
		}
		actual, managed, complete, inspectErr := inspectOwnershipDescription(anchored.Description, request.ClusterName)
		if inspectErr != nil || !managed || !complete {
			return nil, fmt.Errorf("%w: durably anchored VM %s lacks complete canonical ownership: %v", cloudapi.ErrCreateAttemptPending, request.CreatedVMUUID, inspectErr)
		}
		if err := validateExisting(*anchored, request, actual, record); err != nil {
			return nil, err
		}
		if err := authorizeFencedLaunchResolution(ctx, request, anchored.UUID); err != nil {
			return nil, err
		}
		return a.completeOwnedVM(ctx, request, *anchored, actual, record, networkPrefix, true, false)
	}
	if existing, actual, err := a.findOwnedVM(ctx, request); err != nil {
		return nil, err
	} else if existing != nil {
		if err := validateExisting(*existing, request, actual, record); err != nil {
			return nil, err
		}
		if err := authorizeFencedLaunchResolution(ctx, request, existing.UUID); err != nil {
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
	if existing, actual, err := a.findBaselineCreateTarget(ctx, request, record); err != nil {
		return nil, err
	} else if existing != nil {
		if err := authorizeFencedLaunchResolution(ctx, request, existing.UUID); err != nil {
			return nil, err
		}
		return a.completeOwnedVM(ctx, request, *existing, actual, record, networkPrefix, false, true)
	}
	if request.CreateAttemptToken != "" && !request.CreateAttemptAllowPOST {
		return nil, fmt.Errorf("%w: NodeClaim %q already exercised its immutable VM create attempt; only read/adoption or finalizer cleanup is safe", cloudapi.ErrCreateAttemptPending, request.NodeClaimName)
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
	if request.CreateAttemptToken != "" {
		if request.AuthorizeLaunch == nil {
			return nil, fmt.Errorf("durable VM create attempt lacks an immediate pre-POST authorizer")
		}
		if err := request.AuthorizeLaunch(ctx, cloudapi.CreateAuthorizationPost); err != nil {
			if errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
				return nil, fmt.Errorf("%w: durable VM create authorization aborted after issue CAS and before POST: %w", cloudapi.ErrCreateAttemptRejected, err)
			}
			return nil, fmt.Errorf("durable VM create attempt was not authorized immediately before POST: %w", err)
		}
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
			if anchorErr := recordFencedCreatedVM(ctx, request, created.UUID); anchorErr != nil {
				return nil, errors.Join(fmt.Errorf("creating InSpace VM returned UUID %s with an error: %w", created.UUID, createErr), anchorErr)
			}
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
		return nil, fmt.Errorf("%w: creating InSpace VM received a definitive non-retryable rejection (POST was not retried): %w", cloudapi.ErrCreateAttemptRejected, createErr)
	}
	if created == nil || !vmUUIDPattern.MatchString(created.UUID) {
		if recovered, recoveryErr := a.findCreate(ctx, request, record, networkPrefix, true); recoveryErr == nil && recovered != nil {
			return recovered, nil
		} else if recoveryErr != nil {
			return nil, fmt.Errorf("creating InSpace VM returned no valid UUID; protective recovery failed: %w", recoveryErr)
		}
		return nil, fmt.Errorf("creating InSpace VM returned no valid UUID; protective recovery remains uncertain")
	}
	if err := recordFencedCreatedVM(ctx, request, created.UUID); err != nil {
		return nil, fmt.Errorf("persisting exact created VM UUID before cloud protection: %w", err)
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
			return nil, a.cleanupFencedLaunch(ctx, request, created.UUID, *floatingIP, err)
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
	protectionErr := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, networkPrefix, request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName)
	persisted, proofErr := a.ensurePersistedVMIdentity(context.WithoutCancel(ctx), request, vmUUID, expected, nil)
	if proofErr != nil {
		return nil, fmt.Errorf("ambiguous VM %s protection/ownership remains uncertain: %w", vmUUID, errors.Join(protectionErr, proofErr))
	}
	if protectionErr != nil {
		return nil, a.cleanupProvenAutoLaunch(ctx, request, vmUUID, nil, errors.Join(errEarlyFirewallProtection, protectionErr))
	}
	return a.completeOwnedVM(ctx, request, *persisted, expected, expected, networkPrefix, true, false)
}

// ProtectFencedCreate re-establishes the prevalidated base-deny firewall for a
// durably anchored public VM after a controller/process crash. The sparse UUID
// anchor authorizes only this protection mutation; FIP or materialization work
// still requires canonical ownership.
func (a *Adapter) ProtectFencedCreate(ctx context.Context, request cloudapi.FencedCreateCleanupRequest) error {
	if err := validateFencedCreateCleanupRequest(request); err != nil {
		return err
	}
	if !vmUUIDPattern.MatchString(request.CreatedVMUUID) || request.RollbackChosen {
		return fmt.Errorf("fenced VM protection requires an anchored UUID with no rollback decision")
	}
	vip, err := validateControlPlaneVIP(request.ControlPlaneVIP)
	if err != nil {
		return err
	}
	pool := inspacev1.PrivateLoadBalancerPool{Start: request.PrivateLoadBalancerPoolStart, Stop: request.PrivateLoadBalancerPoolStop}
	if err := pool.ValidateForSupervisor(vip); err != nil {
		return fmt.Errorf("private load-balancer pool: %w", err)
	}
	protectCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.protectionAuditTimeout+a.networkAttachmentReadbackTimeout)
	defer cancel()
	networkPrefix, err := a.ensureNetworkAttachment(protectCtx, request.Location, request.NetworkUUID, request.CreatedVMUUID, vip, pool)
	if err != nil {
		return fmt.Errorf("proving anchored VM %s network membership before base-deny protection: %w", request.CreatedVMUUID, err)
	}
	if err := a.ensureFencedCreateAnchorOwnership(protectCtx, request); err != nil {
		return fmt.Errorf("proving anchored VM %s exact ownership before base-deny protection: %w", request.CreatedVMUUID, err)
	}
	if err := a.ensureFreshFirewall(protectCtx, request.Location, request.FirewallUUID, request.CreatedVMUUID, networkPrefix,
		request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName); err != nil {
		return fmt.Errorf("protecting anchored VM %s with base-deny firewall: %w", request.CreatedVMUUID, err)
	}
	return nil
}

func (a *Adapter) ensureFencedCreateAnchorOwnership(ctx context.Context, request cloudapi.FencedCreateCleanupRequest) error {
	readbackCtx, cancel := context.WithTimeout(ctx, a.protectionAuditTimeout)
	defer cancel()
	readbackDelay := a.networkAttachmentReadbackMinDelay
	var lastObservation error
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		vm, err := a.api.GetVM(requestCtx, request.Location, request.CreatedVMUUID)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return fmt.Errorf("fenced VM ownership readback stopped: %w", errors.Join(lastObservation, readbackErr))
		}
		if err != nil {
			lastObservation = fmt.Errorf("reading fenced VM detail: %w", err)
			if !sdk.IsNotFound(err) && !isRetryableReadback(readbackCtx, err) {
				return lastObservation
			}
		} else if vm == nil || !strings.EqualFold(vm.UUID, request.CreatedVMUUID) {
			return fmt.Errorf("%w: fenced VM detail has invalid identity", cloudapi.ErrOwnershipMismatch)
		} else {
			record, managed, complete, inspectErr := inspectOwnershipDescription(vm.Description, request.ClusterName)
			if inspectErr != nil {
				return inspectErr
			}
			if !managed || !complete {
				lastObservation = fmt.Errorf("%w: fenced VM ownership is incomplete", cloudapi.ErrCreateAttemptPending)
			} else if vm.Name != request.VMName || vm.BillingAccountID != request.BillingAccountID ||
				record.Schema != ownershipSchema || record.Cluster != request.ClusterName || record.NodePool != request.NodePoolName ||
				record.NodeClaim != request.NodeClaimName || record.VMName != request.VMName || record.KeyHash != request.OwnershipKeyHash ||
				record.SpecHash != request.SpecHash || record.BootstrapHash != request.BootstrapHash || record.FirewallUUID != request.FirewallUUID ||
				inspacev1.EffectiveFirewallProfile(record.FirewallProfile) != request.FirewallProfile || record.NetworkUUID != request.NetworkUUID ||
				record.ControlPlaneVIP != request.ControlPlaneVIP || record.PrivateLoadBalancerPoolStart != request.PrivateLoadBalancerPoolStart ||
				record.PrivateLoadBalancerPoolStop != request.PrivateLoadBalancerPoolStop || record.BillingAccountID != request.BillingAccountID ||
				record.FloatingIPName != floatingIPName(request.ClusterName, request.NodeClaimName) {
				return fmt.Errorf("%w: fenced VM %s does not match its exact durable launch binding", cloudapi.ErrOwnershipMismatch, request.CreatedVMUUID)
			} else {
				return nil
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return fmt.Errorf("fenced VM ownership did not converge: %w", errors.Join(lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

// CleanupFencedCreate reconciles an issued create whose NodeClaim is deleting
// before ProviderID persistence. It deletes only canonical exact ownership.
// Otherwise it keeps the provider finalizer until three spaced snapshots after
// the ambiguity window contain no target and no post-baseline unattributed VM
// or floating IP. It never grants another VM POST.
func (a *Adapter) CleanupFencedCreate(ctx context.Context, request cloudapi.FencedCreateCleanupRequest) (cloudapi.FencedCreateCleanupResult, error) {
	empty := cloudapi.FencedCreateCleanupResult{}
	if err := validateFencedCreateCleanupRequest(request); err != nil {
		return empty, err
	}
	baselineVMs := identitySet(request.Baseline.VMs)
	attemptResolved := request.AttemptResolved
	for _, resolution := range request.Resolutions {
		if _, existedBeforeFence := baselineVMs[resolution.VMUUID]; !existedBeforeFence {
			attemptResolved = true
			break
		}
	}
	anchorReceipt := false
	for _, resolution := range request.Resolutions {
		if strings.EqualFold(resolution.VMUUID, request.CreatedVMUUID) {
			anchorReceipt = true
			break
		}
	}
	// A durable receipt can identify an unprotected public VM. Reconcile it
	// immediately; the ambiguity window gates only final absence conclusions,
	// never security-priority deletion of an exact owned target.
	if err := a.reconcileFencedCleanupReceipts(ctx, request); err != nil {
		return empty, err
	}
	if request.CreatedVMUUID != "" {
		resolution, err := a.reconcileFencedCreatedVMAnchor(ctx, request, anchorReceipt)
		if err != nil {
			return empty, err
		}
		if resolution != nil {
			return cloudapi.FencedCreateCleanupResult{Resolution: resolution}, nil
		}
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	eligibleAt := request.AttemptIssuedAt.Add(a.createAmbiguityWindow)
	targetVMs := identitySet(request.Baseline.TargetVMs)
	baselineFloatingIPs := identitySet(request.Baseline.FloatingIPs)
	issuedUnobserved := request.POSTIssued && !attemptResolved
	dependentUnresolved := request.DependentUnresolved && !anchorReceipt
	dependentTracking := (request.DependentUnresolved || request.DependentsResolved) && !anchorReceipt
	_, anchoredVMExistedBeforeFence := baselineVMs[strings.ToLower(request.CreatedVMUUID)]
	anchoredBaselineDependents := targetFloatingIPAssignmentsForVM(request.Baseline, request.CreatedVMUUID)
	for confirmation := 1; confirmation <= createAbsenceConfirmations; confirmation++ {
		if err := a.reconcileFencedCleanupReceipts(ctx, request); err != nil {
			return empty, err
		}
		strictUUIDs := make(map[string]struct{}, len(request.Baseline.PotentialVMs)+len(request.Baseline.TargetVMs)+len(request.Resolutions)+2)
		for _, uuid := range request.Baseline.PotentialVMs {
			strictUUIDs[strings.ToLower(uuid)] = struct{}{}
		}
		for _, uuid := range request.Baseline.TargetVMs {
			strictUUIDs[strings.ToLower(uuid)] = struct{}{}
		}
		for _, resolution := range request.Resolutions {
			strictUUIDs[strings.ToLower(resolution.VMUUID)] = struct{}{}
		}
		if request.CreatedVMUUID != "" {
			strictUUIDs[strings.ToLower(request.CreatedVMUUID)] = struct{}{}
		}
		if request.ObservedVMUUID != "" {
			strictUUIDs[strings.ToLower(request.ObservedVMUUID)] = struct{}{}
		}
		vms, addresses, err := a.fenceDiscoverySnapshot(ctx, request.Location, request.NetworkUUID, fenceDiscoveryPolicy{
			BaselineVMs: baselineVMs, StrictUUIDs: strictUUIDs,
		})
		if err != nil {
			return empty, fmt.Errorf("capturing fenced VM cleanup discovery inventory: %w", err)
		}
		listedVMs := make(map[string]struct{}, len(vms))
		for i := range vms {
			listedVMs[strings.ToLower(vms[i].UUID)] = struct{}{}
		}
		for _, possibleUUID := range request.Baseline.PotentialVMs {
			if _, listed := listedVMs[possibleUUID]; listed {
				continue
			}
			vm, missing, getErr := a.readVMForDelete(ctx, request.Location, request.NetworkUUID, possibleUUID)
			if getErr != nil {
				return empty, fmt.Errorf("exact-reading potential baseline VM %s during fenced cleanup: %w", possibleUUID, getErr)
			}
			if !missing {
				vms = append(vms, *vm)
				listedVMs[possibleUUID] = struct{}{}
			}
		}
		prioritizeFencedCleanupVMs(vms, addresses, floatingIPName(request.ClusterName, request.NodeClaimName))
		foreignVMs := make(map[string]bool, len(vms))
		for i := range vms {
			vmUUID := strings.ToLower(vms[i].UUID)
			record, managed, complete, definitivelyForeign, inspectErr := inspectOwnershipForFence(vms[i].Description, request.ClusterName, request.NodeClaimName)
			_, durableTarget := targetVMs[vmUUID]
			candidate := durableTarget || vms[i].Name == request.VMName ||
				(managed && (record.Cluster == "" || record.Cluster == request.ClusterName) &&
					(record.NodeClaim == "" || record.NodeClaim == request.NodeClaimName) &&
					(record.KeyHash == "" || record.KeyHash == request.OwnershipKeyHash))
			if candidate {
				if vmUUID == strings.ToLower(request.ObservedVMUUID) {
					return empty, fmt.Errorf("%w: durably resolved VM %s remains visible after delete", cloudapi.ErrCreateAttemptPending, vms[i].UUID)
				}
				if inspectErr != nil || !managed || !complete {
					return empty, fmt.Errorf("%w: possible fenced VM %s has not converged to complete ownership", cloudapi.ErrCreateAttemptPending, vms[i].UUID)
				}
				if record.Cluster != request.ClusterName || record.NodeClaim != request.NodeClaimName || record.KeyHash != request.OwnershipKeyHash ||
					!fencedCleanupVMNameMatches(record, vms[i].Name, request.VMName, request.NodeClaimName) {
					return empty, fmt.Errorf("%w: deterministic fenced VM %s has conflicting ownership", cloudapi.ErrOwnershipMismatch, vms[i].UUID)
				}
				resolution, err := a.resolveCanonicalFencedVM(ctx, request, vms[i].UUID)
				if err != nil {
					return empty, err
				}
				return cloudapi.FencedCreateCleanupResult{Resolution: resolution}, nil
			}
			if inspectErr != nil {
				if _, existed := baselineVMs[vmUUID]; !existed {
					return empty, fmt.Errorf("%w: post-baseline VM %s has unparseable ownership", cloudapi.ErrCreateAttemptPending, vms[i].UUID)
				}
				continue
			}
			foreign := definitivelyForeign || (managed && complete && record.NodeClaim != "" && record.NodeClaim != request.NodeClaimName) ||
				(!managed && vms[i].Name != "" && vms[i].Name != request.VMName)
			foreignVMs[vmUUID] = foreign
			if _, existed := baselineVMs[vmUUID]; !existed && !foreign {
				return empty, fmt.Errorf("%w: post-baseline VM %s is sparse or unattributed", cloudapi.ErrCreateAttemptPending, vms[i].UUID)
			}
		}
		if dependentTracking {
			resolution, resolutionErr := a.resolveBaselineTargetFloatingIP(ctx, request, addresses)
			if resolutionErr != nil {
				return empty, resolutionErr
			}
			if resolution != nil {
				return cloudapi.FencedCreateCleanupResult{Resolution: resolution}, nil
			}
		}
		for i := range addresses {
			if addresses[i].IsDeleted {
				continue
			}
			identity, identityErr := floatingIPInventoryIdentity(addresses[i])
			if identityErr != nil {
				return empty, fmt.Errorf("reconciling fenced VM create cleanup: %w", identityErr)
			}
			if addresses[i].BillingAccountID != 0 && addresses[i].BillingAccountID != request.BillingAccountID {
				continue
			}
			if addresses[i].Name == floatingIPName(request.ClusterName, request.NodeClaimName) {
				if request.CreatedVMUUID != "" && !anchorReceipt && addresses[i].BillingAccountID == request.BillingAccountID &&
					addresses[i].AssignedToResourceType == "virtual_machine" &&
					strings.EqualFold(addresses[i].AssignedTo, request.CreatedVMUUID) {
					return cloudapi.FencedCreateCleanupResult{Resolution: &cloudapi.FencedCreateCleanupResolution{
						VMUUID: request.CreatedVMUUID, FloatingIPName: addresses[i].Name, PublicIPv4: addresses[i].Address,
					}}, nil
				}
				return empty, fmt.Errorf("%w: deterministic floating IP %q remains visible", cloudapi.ErrCreateAttemptPending, addresses[i].Name)
			}
			if _, possibleTarget := targetVMs[strings.ToLower(addresses[i].AssignedTo)]; possibleTarget {
				return empty, fmt.Errorf("%w: floating IP %s remains assigned to potential fenced VM %s", cloudapi.ErrCreateAttemptPending, addresses[i].Address, addresses[i].AssignedTo)
			}
			if _, existed := baselineFloatingIPs[identity]; existed {
				continue
			}
			if !issuedUnobserved && !dependentTracking {
				continue
			}
			assignedVM := strings.ToLower(addresses[i].AssignedTo)
			if addresses[i].AssignedToResourceType == "virtual_machine" && vmUUIDPattern.MatchString(assignedVM) && foreignVMs[assignedVM] {
				continue
			}
			return empty, fmt.Errorf("%w: post-baseline floating IP %s is unnamed or not attributable to a proven foreign VM", cloudapi.ErrCreateAttemptPending, addresses[i].Address)
		}
		if confirmation == 1 && request.POSTIssued && (!attemptResolved || dependentUnresolved) && now().Before(eligibleAt) {
			return empty, fmt.Errorf("%w: issued VM create fence %s has no exact visible result or dependent and is inside the cleanup ambiguity window until %s", cloudapi.ErrCreateAttemptPending, request.AttemptToken, eligibleAt.UTC().Format(time.RFC3339Nano))
		}
		if confirmation < createAbsenceConfirmations {
			if err := waitForReadback(ctx, a.createAbsenceReadInterval); err != nil {
				return empty, fmt.Errorf("fenced VM create cleanup absence proof stopped after confirmation %d: %w", confirmation, err)
			}
		}
	}
	if request.POSTIssued && !attemptResolved {
		return empty, fmt.Errorf("%w: issued VM create attempt %s remains permanently ambiguous after %d spaced empty observations; retain the finalizer until an exact VM materializes or an operator resolves it", cloudapi.ErrCreateAttemptUnresolved, request.AttemptToken, createAbsenceConfirmations)
	}
	if dependentUnresolved {
		if anchoredVMExistedBeforeFence && len(anchoredBaselineDependents) == 0 {
			return empty, fmt.Errorf("%w: adopted VM %s had no durable target floating-IP association; retain the finalizer until an operator resolves its dependent", cloudapi.ErrCreateAttemptUnresolved, request.CreatedVMUUID)
		}
		// Three complete location/VPC/FIP snapshots after the exact VM DELETE are
		// the provider's terminal proof, after the original create ambiguity
		// window, that the auto-reserved dependent was removed with the VM.
		// Persist that fact before releasing protection.
		return cloudapi.FencedCreateCleanupResult{DependentsResolved: true}, nil
	}
	if len(request.Resolutions) != 0 {
		return empty, nil
	}
	if request.POSTRejected || request.AttemptResolved {
		return empty, cloudapi.ErrNotFound
	}
	return empty, cloudapi.ErrNotFound
}

func prioritizeFencedCleanupVMs(vms []sdk.VM, addresses []sdk.FloatingIP, expectedName string) {
	namedAssignment := make(map[string]bool)
	for i := range addresses {
		if !addresses[i].IsDeleted && addresses[i].Name == expectedName && addresses[i].AssignedToResourceType == "virtual_machine" {
			namedAssignment[strings.ToLower(addresses[i].AssignedTo)] = true
		}
	}
	sort.SliceStable(vms, func(i, j int) bool {
		return namedAssignment[strings.ToLower(vms[i].UUID)] && !namedAssignment[strings.ToLower(vms[j].UUID)]
	})
}

// fenceDiscoverySnapshot returns canonical VM details for the union of all
// cloud indexes that can reveal a launch: ListVMs, exact configured-VPC
// membership, and active FIPs assigned to VM UUIDs. Index rows never grant
// destructive authority; every UUID must survive an exact GetVM first.
type fenceDiscoveryPolicy struct {
	BeforeCreate bool
	BaselineVMs  map[string]struct{}
	StrictUUIDs  map[string]struct{}
}

func (a *Adapter) fenceDiscoverySnapshot(ctx context.Context, location, networkUUID string, policy fenceDiscoveryPolicy) ([]sdk.VM, []sdk.FloatingIP, error) {
	listed, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return nil, nil, fmt.Errorf("listing VMs: %w", err)
	}
	if err := validateVMListSnapshot(listed); err != nil {
		return nil, nil, err
	}
	addresses, err := a.api.ListFloatingIPs(ctx, location, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("listing floating IPs: %w", err)
	}
	network, err := a.api.GetNetwork(ctx, location, networkUUID)
	if err != nil {
		return nil, nil, fmt.Errorf("reading configured VPC %s: %w", networkUUID, err)
	}
	if network == nil || network.UUID != networkUUID {
		return nil, nil, fmt.Errorf("%w: configured VPC %s returned invalid identity", cloudapi.ErrOwnershipMismatch, networkUUID)
	}
	hints := make(map[string]sdk.VM, len(listed)+len(network.VMUUIDs))
	strictMissing := make(map[string]bool, len(listed)+len(policy.StrictUUIDs))
	for i := range listed {
		uuid := strings.ToLower(listed[i].UUID)
		if !vmUUIDPattern.MatchString(uuid) {
			return nil, nil, fmt.Errorf("VM discovery contains malformed UUID %q", listed[i].UUID)
		}
		if _, duplicate := hints[uuid]; duplicate {
			return nil, nil, fmt.Errorf("%w: VM discovery contains duplicate UUID %s", cloudapi.ErrOwnershipMismatch, uuid)
		}
		summary := listed[i]
		summary.UUID = uuid
		hints[uuid] = summary
		strictMissing[uuid] = true
	}
	for _, member := range network.VMUUIDs {
		uuid := strings.ToLower(member)
		if !vmUUIDPattern.MatchString(uuid) {
			return nil, nil, fmt.Errorf("configured VPC %s contains malformed VM UUID %q", networkUUID, member)
		}
		if _, exists := hints[uuid]; !exists {
			hints[uuid] = sdk.VM{UUID: uuid}
		}
		// VPC membership can be the only pre-POST evidence of a hidden existing
		// target. It must remain fail-closed or PrepareCreate could omit it from
		// the baseline and authorize a duplicate POST. Only FIP-only hints are
		// soft when unrelated.
		if policy.BeforeCreate {
			strictMissing[uuid] = true
		} else if _, preexisting := policy.BaselineVMs[uuid]; !preexisting {
			strictMissing[uuid] = true
		}
	}
	for i := range addresses {
		if addresses[i].IsDeleted {
			continue
		}
		if _, identityErr := floatingIPInventoryIdentity(addresses[i]); identityErr != nil {
			return nil, nil, identityErr
		}
		if addresses[i].AssignedToResourceType != "virtual_machine" || addresses[i].AssignedTo == "" {
			continue
		}
		uuid := strings.ToLower(addresses[i].AssignedTo)
		if !vmUUIDPattern.MatchString(uuid) {
			return nil, nil, fmt.Errorf("floating IP %s is assigned to malformed VM UUID %q", addresses[i].Address, addresses[i].AssignedTo)
		}
		if _, exists := hints[uuid]; !exists {
			hints[uuid] = sdk.VM{UUID: uuid}
		}
	}
	for uuid := range policy.StrictUUIDs {
		strictMissing[strings.ToLower(uuid)] = true
	}
	if len(hints) > cloudapi.MaxCreateInventoryEntries {
		return nil, nil, fmt.Errorf("VM discovery union exceeds the safe bound of %d identities", cloudapi.MaxCreateInventoryEntries)
	}
	ordered := make([]string, 0, len(hints))
	for uuid := range hints {
		ordered = append(ordered, uuid)
	}
	sort.Strings(ordered)
	summaries := make([]sdk.VM, 0, len(ordered))
	for _, uuid := range ordered {
		summaries = append(summaries, hints[uuid])
	}
	canonical, err := a.canonicalFenceInventoryVMDetails(ctx, location, summaries, strictMissing)
	if err != nil {
		return nil, nil, err
	}
	return canonical, addresses, nil
}

func (a *Adapter) reconcileFencedCleanupReceipts(ctx context.Context, request cloudapi.FencedCreateCleanupRequest) error {
	for _, resolution := range request.Resolutions {
		err := a.DeleteVM(ctx, request.Location, resolution.VMUUID, request.ClusterName, request.NodeClaimName, cloudapi.DeleteVMIdentity{
			FloatingIPName: resolution.FloatingIPName, PublicIPv4: resolution.PublicIPv4, BillingAccountID: request.BillingAccountID, NetworkUUID: request.NetworkUUID,
		})
		if err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
			return fmt.Errorf("reconciling durable cleanup receipt for VM %s: %w", resolution.VMUUID, err)
		}
	}
	return nil
}

func (a *Adapter) reconcileFencedCreatedVMAnchor(ctx context.Context, request cloudapi.FencedCreateCleanupRequest, hasReceipt bool) (*cloudapi.FencedCreateCleanupResolution, error) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchCleanupTimeout)
	defer cancel()

	if !hasReceipt {
		expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
		fipCtx, fipCancel := context.WithTimeout(cleanupCtx, a.launchFloatingIPCleanupTimeout)
		floatingIP, err := a.ensureAutoFloatingIPForCleanup(fipCtx, request.Location, request.CreatedVMUUID, expectedName, request.BillingAccountID)
		fipCancel()
		if err == nil && floatingIP != nil && floatingIP.Name == expectedName && floatingIP.BillingAccountID == request.BillingAccountID &&
			floatingIP.AssignedToResourceType == "virtual_machine" && strings.EqualFold(floatingIP.AssignedTo, request.CreatedVMUUID) {
			return &cloudapi.FencedCreateCleanupResolution{
				VMUUID: strings.ToLower(request.CreatedVMUUID), FloatingIPName: floatingIP.Name, PublicIPv4: floatingIP.Address,
			}, nil
		}
	}
	// A durable SDK/canonical anchor is exact authority for this VM UUID. Always
	// dispatch the idempotent DELETE even when every eventually consistent read
	// currently omits it; visibility is never a prerequisite for deletion.
	if err := a.api.DeleteVM(cleanupCtx, request.Location, request.CreatedVMUUID); err != nil && !sdk.IsNotFound(err) {
		return nil, fmt.Errorf("deleting durably anchored VM %s: %w", request.CreatedVMUUID, err)
	}
	if err := a.waitForVMAbsence(cleanupCtx, request.Location, request.NetworkUUID, request.CreatedVMUUID, "after anchored create rollback"); err != nil {
		return nil, fmt.Errorf("anchored VM %s deletion has not converged: %w", request.CreatedVMUUID, err)
	}
	if err := a.detachFirewallAfterVMDeletion(cleanupCtx, request.Location, request.FirewallUUID, request.CreatedVMUUID); err != nil {
		return nil, err
	}
	return nil, nil
}

// canonicalFenceInventoryVMDetails treats ListVMs strictly as discovery. Every
// row receives an exact GetVM before ownership classification, but unrelated
// launch-shape drift is not audited here. A same-snapshot List hit/Get 404 is
// uncertainty, never absence authority for finalizer release.
func (a *Adapter) canonicalFenceInventoryVMDetails(ctx context.Context, location string, listed []sdk.VM, strictMissing map[string]bool) ([]sdk.VM, error) {
	if len(listed) == 0 {
		return nil, nil
	}
	readCtx, cancel := context.WithTimeout(ctx, a.protectionAuditTimeout)
	defer cancel()
	details := make([]sdk.VM, len(listed))
	errs := make([]error, len(listed))
	jobs := make(chan int, len(listed))
	for i := range listed {
		jobs <- i
	}
	close(jobs)
	workers := canonicalVMReadConcurrency
	if len(listed) < workers {
		workers = len(listed)
	}
	var reads sync.WaitGroup
	for range workers {
		reads.Add(1)
		go func() {
			defer reads.Done()
			for i := range jobs {
				strict := strictMissing[strings.ToLower(listed[i].UUID)]
				requestCtx, requestCancel := context.WithTimeout(readCtx, a.networkAttachmentRequestTimeout)
				vm, err := a.api.GetVM(requestCtx, location, listed[i].UUID)
				requestCancel()
				switch {
				case sdk.IsNotFound(err):
					if strict {
						errs[i] = fmt.Errorf("%w: relevant VM hint %s returned canonical GetVM 404", cloudapi.ErrCreateAttemptPending, listed[i].UUID)
					}
				case err != nil:
					if strict {
						errs[i] = fmt.Errorf("exact-reading relevant VM %s for fenced cleanup: %w", listed[i].UUID, err)
					}
				case vm == nil:
					if strict {
						errs[i] = fmt.Errorf("%w: exact detail for relevant VM %s is empty", cloudapi.ErrCreateAttemptPending, listed[i].UUID)
					}
				case !strings.EqualFold(vm.UUID, listed[i].UUID) || (listed[i].Name != "" && vm.Name != "" && listed[i].Name != vm.Name):
					if strict {
						errs[i] = fmt.Errorf("%w: exact detail identity for relevant VM %s does not match", cloudapi.ErrOwnershipMismatch, listed[i].UUID)
					}
				default:
					details[i] = *vm
				}
			}
		}()
	}
	reads.Wait()
	for i := range errs {
		if errs[i] != nil {
			return nil, errs[i]
		}
	}
	canonical := details[:0]
	for i := range details {
		if details[i].UUID != "" {
			canonical = append(canonical, details[i])
		}
	}
	return canonical, nil
}

func (a *Adapter) resolveCanonicalFencedVM(ctx context.Context, request cloudapi.FencedCreateCleanupRequest, vmUUID string) (*cloudapi.FencedCreateCleanupResolution, error) {
	vm, missing, err := a.readVMForDelete(ctx, request.Location, request.NetworkUUID, vmUUID)
	if err != nil {
		return nil, err
	}
	if missing {
		return nil, fmt.Errorf("%w: canonical VM %s is temporarily absent", cloudapi.ErrCreateAttemptPending, vmUUID)
	}
	record, managed, complete, err := inspectOwnershipDescription(vm.Description, request.ClusterName)
	if err != nil || !managed || !complete {
		return nil, fmt.Errorf("%w: canonical VM %s lacks complete fenced ownership: %v", cloudapi.ErrCreateAttemptPending, vmUUID, err)
	}
	if record.Cluster != request.ClusterName || record.NodeClaim != request.NodeClaimName || record.KeyHash != request.OwnershipKeyHash ||
		!fencedCleanupVMNameMatches(record, vm.Name, request.VMName, request.NodeClaimName) || record.BillingAccountID != request.BillingAccountID ||
		record.NodePool != request.NodePoolName || record.NetworkUUID != request.NetworkUUID || record.ControlPlaneVIP != request.ControlPlaneVIP ||
		record.PrivateLoadBalancerPoolStart != request.PrivateLoadBalancerPoolStart || record.PrivateLoadBalancerPoolStop != request.PrivateLoadBalancerPoolStop ||
		record.FirewallUUID != request.FirewallUUID || inspacev1.EffectiveFirewallProfile(record.FirewallProfile) != request.FirewallProfile ||
		record.SpecHash != request.SpecHash || record.BootstrapHash != request.BootstrapHash ||
		record.FloatingIPName != floatingIPName(request.ClusterName, request.NodeClaimName) {
		return nil, fmt.Errorf("%w: canonical VM %s does not match fenced cleanup identity", cloudapi.ErrOwnershipMismatch, vmUUID)
	}
	cleanupRequest := cloudapi.CreateVMRequest{
		Name: request.VMName, ClusterName: request.ClusterName,
		BillingAccountID: request.BillingAccountID, NodePoolName: request.NodePoolName, NodeClaimName: request.NodeClaimName,
		Location: request.Location, NetworkUUID: request.NetworkUUID, ControlPlaneVIP: request.ControlPlaneVIP,
		PrivateLoadBalancerPoolStart: request.PrivateLoadBalancerPoolStart, PrivateLoadBalancerPoolStop: request.PrivateLoadBalancerPoolStop,
		FirewallUUID: request.FirewallUUID, FirewallProfile: request.FirewallProfile, SpecHash: request.SpecHash, BootstrapHash: request.BootstrapHash,
	}
	networkPrefix, err := a.readDiscoveredCleanupNetworkAuthority(ctx, cleanupRequest, vmUUID)
	if err != nil {
		return nil, err
	}
	_ = a.ensureFreshFirewall(context.WithoutCancel(ctx), request.Location, request.FirewallUUID, vmUUID, networkPrefix,
		request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchFloatingIPCleanupTimeout)
	floatingIP, err := a.ensureAutoFloatingIPForCleanup(cleanupCtx, request.Location, vmUUID, record.FloatingIPName, request.BillingAccountID)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("establishing durable floating-IP cleanup identity for fenced VM %s: %w", vmUUID, err)
	}
	return &cloudapi.FencedCreateCleanupResolution{
		VMUUID: vmUUID, FloatingIPName: floatingIP.Name, PublicIPv4: floatingIP.Address,
	}, nil
}

func fencedCleanupVMNameMatches(record ownership, actualName, currentVMName, nodeClaimName string) bool {
	expectedName := currentVMName
	if record.Schema == legacyOwnershipSchema {
		expectedName = nodeClaimName
	}
	return record.VMName == expectedName && actualName == expectedName
}

func floatingIPInventoryIdentity(address sdk.FloatingIP) (string, error) {
	if address.UUID != "" {
		if !vmUUIDPattern.MatchString(address.UUID) {
			return "", fmt.Errorf("floating IP %q has malformed UUID %q", address.Address, address.UUID)
		}
		return "uuid:" + strings.ToLower(address.UUID), nil
	}
	if parsed, err := netip.ParseAddr(address.Address); err == nil && parsed.Is4() {
		return "address:" + parsed.String(), nil
	}
	if address.ID > 0 {
		return "id:" + strconv.FormatInt(address.ID, 10), nil
	}
	return "", fmt.Errorf("active floating IP has no stable UUID, IPv4 address, or numeric ID")
}

func targetFloatingIPAssignmentsForVM(inventory cloudapi.CreateInventory, vmUUID string) []cloudapi.CreateFloatingIPAssignment {
	vmUUID = strings.ToLower(vmUUID)
	assignments := make([]cloudapi.CreateFloatingIPAssignment, 0, 1)
	for _, assignment := range inventory.TargetFloatingIPs {
		if assignment.VMUUID == vmUUID {
			assignments = append(assignments, assignment)
		}
	}
	return assignments
}

// resolveBaselineTargetFloatingIP recovers an adopted target's dependent after
// VM DELETE has removed AssignedTo. Its stable pre-authorization identity,
// address, billing account, and former VM association are Kubernetes-durable,
// so this path may name that exact row and return a receipt without guessing.
func (a *Adapter) resolveBaselineTargetFloatingIP(
	ctx context.Context,
	request cloudapi.FencedCreateCleanupRequest,
	addresses []sdk.FloatingIP,
) (*cloudapi.FencedCreateCleanupResolution, error) {
	assignments := targetFloatingIPAssignmentsForVM(request.Baseline, request.CreatedVMUUID)
	if len(assignments) == 0 {
		return nil, nil
	}
	if len(assignments) != 1 {
		return nil, fmt.Errorf("%w: adopted VM %s has %d baseline floating-IP dependents", cloudapi.ErrCreateAttemptPending, request.CreatedVMUUID, len(assignments))
	}
	assignment := assignments[0]
	expectedName := floatingIPName(request.ClusterName, request.NodeClaimName)
	if assignment.Name != "" && assignment.Name != expectedName {
		return nil, fmt.Errorf("%w: adopted VM %s baseline floating IP has foreign name %q", cloudapi.ErrOwnershipMismatch, request.CreatedVMUUID, assignment.Name)
	}
	current, present, err := baselineTargetFloatingIP(addresses, assignment, request.CreatedVMUUID, expectedName)
	if err != nil || !present {
		return nil, err
	}
	if current.Name == "" {
		current, err = a.ensureBaselineTargetFloatingIPName(ctx, request.Location, assignment, request.CreatedVMUUID, expectedName)
		if err != nil {
			return nil, err
		}
	}
	return &cloudapi.FencedCreateCleanupResolution{
		VMUUID: strings.ToLower(request.CreatedVMUUID), FloatingIPName: current.Name, PublicIPv4: current.Address,
	}, nil
}

func (a *Adapter) ensureBaselineTargetFloatingIPName(
	ctx context.Context,
	location string,
	assignment cloudapi.CreateFloatingIPAssignment,
	vmUUID, expectedName string,
) (sdk.FloatingIP, error) {
	readbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.networkAttachmentReadbackTimeout)
	defer cancel()
	readbackDelay := a.networkAttachmentReadbackMinDelay
	updateAttempted := false
	var lastObservation, updateErr error
	for {
		requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
		addresses, listErr := a.api.ListFloatingIPs(requestCtx, location, nil)
		requestCancel()
		if readbackErr := readbackCtx.Err(); readbackErr != nil {
			return sdk.FloatingIP{}, fmt.Errorf("baseline target floating IP %s rename stopped: %w", assignment.Address, errors.Join(lastObservation, updateErr, readbackErr))
		}
		if listErr != nil {
			lastObservation = fmt.Errorf("listing baseline target floating IP %s: %w", assignment.Address, listErr)
			if !isRetryableReadback(readbackCtx, listErr) {
				return sdk.FloatingIP{}, lastObservation
			}
		} else {
			current, present, validationErr := baselineTargetFloatingIP(addresses, assignment, vmUUID, expectedName)
			if validationErr != nil {
				return sdk.FloatingIP{}, validationErr
			}
			if !present {
				lastObservation = fmt.Errorf("baseline target floating IP %s is temporarily absent", assignment.Address)
			} else if current.Name == expectedName {
				return current, nil
			} else if !updateAttempted {
				updateAttempted = true
				requestCtx, requestCancel := context.WithTimeout(readbackCtx, a.networkAttachmentRequestTimeout)
				_, updateErr = a.api.UpdateFloatingIP(requestCtx, location, current.Address, sdk.UpdateFloatingIPRequest{
					Name: expectedName, BillingAccountID: assignment.BillingAccountID,
				})
				requestCancel()
				lastObservation = fmt.Errorf("baseline target floating IP %s deterministic name is not visible yet", assignment.Address)
			} else {
				lastObservation = fmt.Errorf("baseline target floating IP %s remains unnamed after its deterministic PATCH", assignment.Address)
			}
		}
		if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
			return sdk.FloatingIP{}, fmt.Errorf("baseline target floating IP %s rename did not converge: %w", assignment.Address, errors.Join(lastObservation, updateErr, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func baselineTargetFloatingIP(
	addresses []sdk.FloatingIP,
	assignment cloudapi.CreateFloatingIPAssignment,
	vmUUID, expectedName string,
) (sdk.FloatingIP, bool, error) {
	var matches []sdk.FloatingIP
	for i := range addresses {
		if addresses[i].IsDeleted {
			continue
		}
		identity, err := floatingIPInventoryIdentity(addresses[i])
		if err != nil {
			return sdk.FloatingIP{}, false, err
		}
		if identity == assignment.Identity {
			matches = append(matches, addresses[i])
		}
	}
	if len(matches) == 0 {
		return sdk.FloatingIP{}, false, nil
	}
	if len(matches) != 1 {
		return sdk.FloatingIP{}, false, fmt.Errorf("%w: baseline floating-IP identity %q appears %d times", cloudapi.ErrOwnershipMismatch, assignment.Identity, len(matches))
	}
	current := matches[0]
	address, addressErr := netip.ParseAddr(current.Address)
	if addressErr != nil || address.String() != assignment.Address || current.BillingAccountID != assignment.BillingAccountID ||
		(current.Name != "" && current.Name != expectedName) ||
		(current.AssignedTo != "" && (!strings.EqualFold(current.AssignedTo, vmUUID) || current.AssignedToResourceType != "virtual_machine")) ||
		(current.AssignedTo == "" && current.AssignedToResourceType != "" && current.AssignedToResourceType != "virtual_machine") {
		return sdk.FloatingIP{}, false, fmt.Errorf("%w: baseline target floating IP %s changed address, account, name, or assignment", cloudapi.ErrOwnershipMismatch, assignment.Address)
	}
	return current, true, nil
}

func compactSortedIdentities(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}

func identitySet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
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
		protectionErr := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, summary.UUID, networkPrefix, request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName)
		vm, actual, proofErr := a.readCanonicalCreateCandidate(context.WithoutCancel(ctx), request, *summary)
		if proofErr != nil {
			return nil, fmt.Errorf("ambiguous VM %s protection/ownership remains uncertain: %w", summary.UUID, errors.Join(protectionErr, proofErr))
		}
		if err := validateExisting(*vm, request, actual, expected); err != nil {
			return nil, err
		}
		if err := recordFencedCreatedVM(ctx, request, vm.UUID); err != nil {
			return nil, fmt.Errorf("anchoring canonically recovered VM %s: %w", vm.UUID, err)
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
	if err := authorizeFencedLaunchResolution(ctx, request, vm.UUID); err != nil {
		return nil, err
	}
	return a.completeOwnedVM(ctx, request, *vm, actual, expected, networkPrefix, rollbackNewLaunch, true)
}

func authorizeFencedLaunchResolution(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string) error {
	if request.CreateAttemptToken == "" {
		return nil
	}
	if !request.CreateAttemptAllowPOST {
		switch request.CreateAttemptIntent {
		case cloudapi.CreateAuthorizationAdoption:
			return recordFencedCreatedVM(ctx, request, vmUUID)
		case cloudapi.CreateAuthorizationPost:
			if _, existedBeforePOST := identitySet(request.CreateBaseline.VMs)[strings.ToLower(vmUUID)]; existedBeforePOST {
				return fmt.Errorf("%w: baseline VM %s cannot resolve a previously issued POST because a second delayed result may still materialize", cloudapi.ErrCreateAttemptPending, vmUUID)
			}
			return recordFencedCreatedVM(ctx, request, vmUUID)
		default:
			return fmt.Errorf("%w: issued VM create attempt has no durable authorization intent", cloudapi.ErrCreateAttemptPending)
		}
	}
	if request.AuthorizeLaunch == nil {
		return fmt.Errorf("durable VM launch resolution lacks an immediate authorizer")
	}
	if err := request.AuthorizeLaunch(ctx, cloudapi.CreateAuthorizationAdoption); err != nil {
		if errors.Is(err, cloudapi.ErrCreateAttemptRejected) {
			return fmt.Errorf("%w: durable VM launch adoption authorization aborted after issue CAS: %w", cloudapi.ErrCreateAttemptRejected, err)
		}
		return fmt.Errorf("durable VM launch resolution was not authorized before adoption: %w", err)
	}
	return recordFencedCreatedVM(ctx, request, vmUUID)
}

func recordFencedCreatedVM(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string) error {
	if request.CreateAttemptToken == "" {
		return nil
	}
	if request.RecordCreatedVM == nil {
		return fmt.Errorf("durable VM create attempt lacks an exact created-VM anchor writer")
	}
	anchorCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultLaunchCleanupTimeout)
	defer cancel()
	if err := request.RecordCreatedVM(anchorCtx, strings.ToLower(vmUUID)); err != nil {
		return fmt.Errorf("persisting and reading back exact created VM %s: %w", vmUUID, err)
	}
	return nil
}

// findBaselineCreateTarget closes the ListVMs omission race between the
// durable pre-POST inventory and the last launch check. Every exact target
// captured by PrepareCreate must still be accounted for before a fresh POST is
// allowed. A disappeared target remains pending so deletion can safely retire
// the reserved fence and Karpenter can create a new NodeClaim.
func (a *Adapter) findBaselineCreateTarget(ctx context.Context, request cloudapi.CreateVMRequest, expected ownership) (*sdk.VM, ownership, error) {
	if request.CreateAttemptToken == "" || len(request.CreateBaseline.TargetVMs) == 0 {
		return nil, ownership{}, nil
	}
	var found *sdk.VM
	var actual ownership
	for _, vmUUID := range request.CreateBaseline.TargetVMs {
		vm, missing, err := a.readVMForDelete(ctx, request.Location, request.NetworkUUID, vmUUID)
		if err != nil {
			return nil, ownership{}, fmt.Errorf("exact-reading pre-fence target VM %s before launch: %w", vmUUID, err)
		}
		if missing {
			return nil, ownership{}, fmt.Errorf("%w: pre-fence target VM %s disappeared before launch authorization", cloudapi.ErrCreateAttemptPending, vmUUID)
		}
		record, managed, complete, inspectErr := inspectOwnershipDescription(vm.Description, request.ClusterName)
		if inspectErr != nil || !managed || !complete {
			return nil, ownership{}, fmt.Errorf("%w: pre-fence target VM %s lost complete ownership: %v", cloudapi.ErrOwnershipMismatch, vmUUID, inspectErr)
		}
		if err := validateExisting(*vm, request, record, expected); err != nil {
			return nil, ownership{}, err
		}
		if found != nil {
			return nil, ownership{}, fmt.Errorf("%w: multiple exact pre-fence targets remain for NodeClaim %q", cloudapi.ErrCreateAttemptPending, request.NodeClaimName)
		}
		found = vm
		actual = record
	}
	return found, actual, nil
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
			return nil, a.cleanupFencedLaunch(ctx, request, vm.UUID, *floatingIP, err)
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
	_, err := a.readDiscoveredCleanupNetworkAuthority(ctx, request, vmUUID)
	return err
}

func (a *Adapter) readDiscoveredCleanupNetworkAuthority(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string) (netip.Prefix, error) {
	vip, err := validateControlPlaneVIP(request.ControlPlaneVIP)
	if err != nil {
		return netip.Prefix{}, err
	}
	privateLoadBalancerPool := inspacev1.PrivateLoadBalancerPool{
		Start: request.PrivateLoadBalancerPoolStart,
		Stop:  request.PrivateLoadBalancerPoolStop,
	}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return netip.Prefix{}, fmt.Errorf("private load-balancer pool: %w", err)
	}
	networkPrefix, err := a.ensureNetworkAttachment(context.WithoutCancel(ctx), request.Location, request.NetworkUUID, vmUUID, vip, privateLoadBalancerPool)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("read-discovered VM %s lacks exact membership in configured network %s: %w", vmUUID, request.NetworkUUID, err)
	}
	return networkPrefix, nil
}

func exactNamedFloatingIP(floatingIP *sdk.FloatingIP, record ownership) bool {
	return floatingIP != nil && floatingIP.Name == record.FloatingIPName &&
		floatingIP.BillingAccountID == record.BillingAccountID && floatingIP.Address != ""
}

// cleanupProvenAutoLaunch is called only for a VM authorized either by the
// fresh POST UUID or by canonical v3 ownership. The irreversible rollback CAS
// is made before destructive work, then the exact VM DELETE is dispatched
// immediately. Floating-IP discovery is deliberately not on the security
// critical path; the create-protection controller enriches/deletes it later.
func (a *Adapter) cleanupProvenAutoLaunch(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, floatingIP *sdk.FloatingIP, cause error) error {
	expected := newOwnership(request)
	if exactNamedFloatingIP(floatingIP, expected) {
		return a.cleanupFencedLaunch(ctx, request, vmUUID, *floatingIP, cause)
	}
	// Make one bounded attempt to retain exact dependent identity before VM
	// deletion can auto-unassign the address. Firewall failure must still lead
	// to VM deletion when this lookup cannot converge, so the durable rollback
	// records DependentUnresolved and the finalizer keeps post-baseline FIPs
	// ambiguous instead of silently leaking one.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchFloatingIPCleanupTimeout)
	discovered, discoveryErr := a.ensureAutoFloatingIPForCleanup(cleanupCtx, request.Location, vmUUID, expected.FloatingIPName, request.BillingAccountID)
	cleanupCancel()
	if exactNamedFloatingIP(discovered, expected) {
		return a.cleanupFencedLaunch(ctx, request, vmUUID, *discovered, errors.Join(cause, discoveryErr))
	}
	if request.CreateAttemptToken != "" {
		if request.ChooseRollback == nil {
			return errors.Join(cause, fmt.Errorf("refusing destructive launch rollback for VM %s without a durable rollback-decision writer", vmUUID))
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultLaunchCleanupTimeout)
		err := request.ChooseRollback(rollbackCtx, strings.ToLower(vmUUID), nil)
		cancel()
		if err != nil {
			return errors.Join(cause, fmt.Errorf("persisting rollback choice before security-priority delete of VM %s: %w", vmUUID, err))
		}
	}
	if discoveryErr == nil {
		discoveryErr = fmt.Errorf("auto-reserved floating IP for VM %s has no exact durable name/address/account cleanup anchor", vmUUID)
	}
	return a.cleanupLaunchWithoutFloatingIP(ctx, request.Location, request.NetworkUUID, request.FirewallUUID, vmUUID, cause, discoveryErr)
}

func (a *Adapter) cleanupFencedLaunch(ctx context.Context, request cloudapi.CreateVMRequest, vmUUID string, floatingIP sdk.FloatingIP, cause error) error {
	if request.CreateAttemptToken != "" {
		if request.ChooseRollback == nil {
			return errors.Join(cause, fmt.Errorf("refusing destructive launch rollback for VM %s without a durable rollback-decision writer", vmUUID))
		}
		resolution := cloudapi.FencedCreateCleanupResolution{
			VMUUID: vmUUID, FloatingIPName: floatingIP.Name, PublicIPv4: floatingIP.Address,
		}
		receiptCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultLaunchCleanupTimeout)
		err := request.ChooseRollback(receiptCtx, strings.ToLower(vmUUID), &resolution)
		cancel()
		if err != nil {
			return errors.Join(cause, fmt.Errorf("persisting rollback choice and exact cleanup receipt before destructive rollback of VM %s: %w", vmUUID, err))
		}
	}
	return a.cleanupLaunch(ctx, request.Location, request.NetworkUUID, request.FirewallUUID, vmUUID, floatingIP, cause)
}

func (a *Adapter) cleanupLaunchWithoutFloatingIP(ctx context.Context, location, networkUUID, firewallUUID, vmUUID string, cause, floatingUncertainty error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchCleanupTimeout)
	defer cancel()
	var errs []error
	vmDeleteErr := a.api.DeleteVM(cleanupCtx, location, vmUUID)
	if vmDeleteErr != nil {
		errs = append(errs, fmt.Errorf("deleting public VM %s without a safe floating IP anchor: %w", vmUUID, vmDeleteErr))
	}
	if absenceErr := a.waitForVMAbsence(cleanupCtx, location, networkUUID, vmUUID, "after security-priority launch rollback"); absenceErr != nil {
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
		canonicalUUID := strings.ToLower(vms[i].UUID)
		if uuids[canonicalUUID] {
			return fmt.Errorf("VM list contains duplicate UUID %s", vms[i].UUID)
		}
		uuids[canonicalUUID] = true
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
		} else if !strings.EqualFold(vm.UUID, uuid) {
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
	if _, err := validateWorkerFirewallAssignments(firewalls, record.FirewallUUID, vm.UUID, true, record.FirewallProfile, record.Cluster, record.NodePool, record.NodeClaim); err != nil {
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
	vm, vmMissing, getErr := a.readVMForDelete(ctx, location, identity.NetworkUUID, uuid)
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
	// The durable ProviderID/cleanup receipt authorizes this exact UUID. Always
	// dispatch the idempotent DELETE even if Get/List/VPC/FIP indexes all omit a
	// still-live VM; visibility is not deletion authority.
	requestCtx, requestCancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
	deleteErr := a.api.DeleteVM(requestCtx, location, uuid)
	requestCancel()
	// First prove only the core VM indexes absent. A stale expected FIP may still
	// point at the deleted UUID and is intentionally cleaned in the next stage.
	if absenceErr := a.waitForVMCoreAbsence(ctx, location, identity.NetworkUUID, uuid, "after delete"); absenceErr != nil {
		if deleteErr != nil {
			errs = append(errs, fmt.Errorf("deleting VM %s: %w", uuid, deleteErr))
		}
		errs = append(errs, absenceErr)
		return errors.Join(errs...)
	}
	if floatingIP != nil {
		if floatingCleanupErr := a.deleteOwnedFloatingIP(ctx, location, *floatingIP, uuid); floatingCleanupErr != nil {
			// Dependents and firewalls remain intact until every VM index has
			// converged absent after an idempotent VM DELETE.
			return floatingCleanupErr
		}
	}
	// Before detaching any firewall, require the core indexes and every active
	// FIP assignment to agree that the exact VM UUID is gone.
	if absenceErr := a.waitForVMAbsence(ctx, location, identity.NetworkUUID, uuid, "after dependent cleanup"); absenceErr != nil {
		return absenceErr
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
	exactDurableIdentity := validateDurableDeleteIdentity(identity, record.FloatingIPName) == nil &&
		identity.BillingAccountID == record.BillingAccountID
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
				overlaps := address.Name == record.FloatingIPName || strings.EqualFold(address.AssignedTo, vmUUID) ||
					(record.PublicIPv4 != "" && address.Address == record.PublicIPv4) ||
					(identity.PublicIPv4 != "" && address.Address == identity.PublicIPv4)
				if exactDurableIdentity {
					// Multiple historical launches for one NodeClaim intentionally
					// reuse the deterministic name. A full durable receipt narrows
					// mutation authority to its exact address or target VM; a sibling
					// receipt with the same name is handled independently.
					overlaps = address.Address == identity.PublicIPv4 || strings.EqualFold(address.AssignedTo, vmUUID)
					if strings.EqualFold(address.AssignedTo, vmUUID) && address.Address != identity.PublicIPv4 {
						return nil, false, fmt.Errorf("%w: VM %s has active floating IP %s outside its durable cleanup receipt", cloudapi.ErrOwnershipMismatch, vmUUID, address.Address)
					}
				}
				if !overlaps {
					continue
				}
				if address.IsDeleted {
					exactAccount := address.BillingAccountID == record.BillingAccountID ||
						(record.Schema != ownershipSchema && address.BillingAccountID == 0)
					expectedAddress := record.PublicIPv4
					if exactDurableIdentity {
						expectedAddress = identity.PublicIPv4
					}
					exactAddress := expectedAddress == "" || address.Address == expectedAddress
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
				if err := validateDeletableFloatingIP(active[0], record, vmUUID); err != nil {
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
func (a *Adapter) waitForVMAbsence(ctx context.Context, location, networkUUID, uuid, phase string) error {
	return a.waitForVMAbsenceWithDependents(ctx, location, networkUUID, uuid, phase, true)
}

func (a *Adapter) waitForVMCoreAbsence(ctx context.Context, location, networkUUID, uuid, phase string) error {
	return a.waitForVMAbsenceWithDependents(ctx, location, networkUUID, uuid, phase, false)
}

func (a *Adapter) waitForVMAbsenceWithDependents(ctx context.Context, location, networkUUID, uuid, phase string, includeFloatingIP bool) error {
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
		case getErr == nil && !strings.EqualFold(vm.UUID, uuid):
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
					if strings.EqualFold(listed[i].UUID, uuid) {
						listedPresent = true
						break
					}
				}
				if listedPresent {
					absenceConfirmations = 0
					lastObservation = fmt.Errorf("%w: GetVM reports %s absent while ListVMs still contains it", cloudapi.ErrOwnershipMismatch, uuid)
				} else {
					networkPresent, networkErr := a.networkContainsVM(readbackCtx, location, networkUUID, uuid)
					if networkErr != nil {
						return fmt.Errorf("checking VPC membership to confirm absence of %s %s: %w", uuid, phase, networkErr)
					}
					if networkPresent {
						absenceConfirmations = 0
						lastObservation = fmt.Errorf("%w: GetVM/ListVMs omit %s while configured VPC still contains it", cloudapi.ErrOwnershipMismatch, uuid)
						if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
							return fmt.Errorf("VM %s VPC absence did not converge %s: %w", uuid, phase, errors.Join(lastObservation, err))
						}
						readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
						continue
					}
					if includeFloatingIP {
						floatingAssigned, floatingErr := a.floatingIPAssignedToVM(readbackCtx, location, uuid)
						if floatingErr != nil {
							return fmt.Errorf("checking floating-IP assignment to confirm absence of %s %s: %w", uuid, phase, floatingErr)
						}
						if floatingAssigned {
							absenceConfirmations = 0
							lastObservation = fmt.Errorf("%w: VM indexes omit %s while an active floating IP remains assigned", cloudapi.ErrOwnershipMismatch, uuid)
							if err := waitForReadback(readbackCtx, readbackDelay); err != nil {
								return fmt.Errorf("VM %s floating-IP assignment did not converge absent %s: %w", uuid, phase, errors.Join(lastObservation, err))
							}
							readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
							continue
						}
					}
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
func (a *Adapter) readVMForDelete(ctx context.Context, location, networkUUID, uuid string) (*sdk.VM, bool, error) {
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
		case getErr == nil && !strings.EqualFold(vm.UUID, uuid):
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
					if strings.EqualFold(listed[i].UUID, uuid) {
						listedPresent = true
						break
					}
				}
				if listedPresent {
					absenceConfirmations = 0
					lastObservation = fmt.Errorf("%w: GetVM reports %s absent while ListVMs still contains it", cloudapi.ErrOwnershipMismatch, uuid)
				} else {
					networkPresent, networkErr := a.networkContainsVM(readbackCtx, location, networkUUID, uuid)
					if networkErr != nil {
						return nil, false, fmt.Errorf("checking VPC membership before treating VM %s as absent: %w", uuid, networkErr)
					}
					if networkPresent {
						absenceConfirmations = 0
						lastObservation = fmt.Errorf("%w: GetVM/ListVMs omit %s while configured VPC still contains it", cloudapi.ErrOwnershipMismatch, uuid)
						break
					}
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

func (a *Adapter) networkContainsVM(ctx context.Context, location, networkUUID, vmUUID string) (bool, error) {
	if networkUUID == "" {
		return false, nil
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
	defer cancel()
	network, err := a.api.GetNetwork(requestCtx, location, networkUUID)
	if err != nil {
		return false, err
	}
	if network == nil || network.UUID != networkUUID {
		return false, fmt.Errorf("%w: configured VPC %s returned invalid identity", cloudapi.ErrOwnershipMismatch, networkUUID)
	}
	count := 0
	for _, member := range network.VMUUIDs {
		if strings.EqualFold(member, vmUUID) {
			count++
		}
	}
	if count > 1 {
		return false, fmt.Errorf("%w: configured VPC %s contains VM %s %d times", cloudapi.ErrOwnershipMismatch, networkUUID, vmUUID, count)
	}
	return count == 1, nil
}

func (a *Adapter) floatingIPAssignedToVM(ctx context.Context, location, vmUUID string) (bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
	defer cancel()
	addresses, err := a.api.ListFloatingIPs(requestCtx, location, nil)
	if err != nil {
		return false, err
	}
	found := false
	for i := range addresses {
		if addresses[i].IsDeleted || !strings.EqualFold(addresses[i].AssignedTo, vmUUID) {
			continue
		}
		if addresses[i].AssignedToResourceType != "virtual_machine" {
			return false, fmt.Errorf("%w: floating IP %s points at VM UUID %s with resource type %q", cloudapi.ErrOwnershipMismatch, addresses[i].Address, vmUUID, addresses[i].AssignedToResourceType)
		}
		found = true
	}
	return found, nil
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
	fenced := r.CreateAttemptToken != "" || !r.CreateAttemptStartedAt.IsZero() || r.CreateAttemptAllowPOST || r.CreatedVMUUID != "" ||
		len(r.CreateBaseline.VMs) != 0 || len(r.CreateBaseline.PotentialVMs) != 0 || len(r.CreateBaseline.TargetVMs) != 0 ||
		len(r.CreateBaseline.FloatingIPs) != 0 || r.AuthorizeLaunch != nil
	if fenced {
		if !createAttemptTokenPattern.MatchString(r.CreateAttemptToken) || r.CreateAttemptStartedAt.IsZero() {
			return fmt.Errorf("durable VM create attempt requires a 32-character lowercase hex token and start time")
		}
		if err := validateAdapterCreateInventory(r.CreateBaseline); err != nil {
			return fmt.Errorf("durable VM create baseline: %w", err)
		}
		if r.CreateAttemptAllowPOST && r.AuthorizeLaunch == nil {
			return fmt.Errorf("durable VM create POST authority requires an immediate authorizer")
		}
		if r.CreatedVMUUID != "" && (!vmUUIDPattern.MatchString(r.CreatedVMUUID) || r.CreatedVMUUID != strings.ToLower(r.CreatedVMUUID)) {
			return fmt.Errorf("durable created VM anchor must be a canonical UUID")
		}
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
	switch r.FirewallProfile {
	case "", inspacev1.FirewallProfilePrivateWorker, inspacev1.FirewallProfilePublicNodeLoadBalancer, inspacev1.FirewallProfilePublicNodeLocal:
	default:
		return fmt.Errorf("unsupported firewall profile %q", r.FirewallProfile)
	}
	if inspacev1.EffectiveFirewallProfile(r.FirewallProfile) == inspacev1.FirewallProfilePublicNodeLoadBalancer {
		if _, err := nodeLoadBalancerShardFromOwnedNodeClaim(r.NodePoolName, r.NodeClaimName); err != nil {
			return fmt.Errorf("public Node load balancer NodeClaim/NodePool shard identity: %w", err)
		}
	} else if inspacev1.EffectiveFirewallProfile(r.FirewallProfile) == inspacev1.FirewallProfilePublicNodeLocal {
		if err := validateOwnedNodePoolIdentity(r.NodePoolName, r.NodeClaimName); err != nil {
			return fmt.Errorf("public local NodeClaim/NodePool identity: %w", err)
		}
	}
	if err := bootstrap.ValidateVPCSubnetTemplate(r.CloudInitJSON); err != nil {
		return err
	}
	return nil
}

func validateFencedCreateCleanupRequest(r cloudapi.FencedCreateCleanupRequest) error {
	validIssuedIdentity := !r.POSTIssued || !r.AttemptIssuedAt.IsZero()
	validRejectedIdentity := !r.POSTRejected || r.POSTIssued
	validObservedIdentity := r.ObservedVMUUID == "" || (vmUUIDPattern.MatchString(r.ObservedVMUUID) && r.FloatingIPName != "" && r.PublicIPv4 != "")
	validCreatedIdentity := r.CreatedVMUUID == "" || (vmUUIDPattern.MatchString(r.CreatedVMUUID) && r.CreatedVMUUID == strings.ToLower(r.CreatedVMUUID))
	if r.ClusterName == "" || r.Location == "" || r.NetworkUUID == "" || r.ControlPlaneVIP == "" ||
		r.PrivateLoadBalancerPoolStart == "" || r.PrivateLoadBalancerPoolStop == "" || r.FirewallUUID == "" ||
		r.FirewallProfile != inspacev1.EffectiveFirewallProfile(r.FirewallProfile) || r.SpecHash == "" || r.BootstrapHash == "" ||
		r.NodeClaimName == "" || r.VMName == "" || r.BillingAccountID <= 0 ||
		!createAttemptTokenPattern.MatchString(r.OwnershipKeyHash) || !createAttemptTokenPattern.MatchString(r.AttemptToken) || !validIssuedIdentity || !validRejectedIdentity || !validObservedIdentity || !validCreatedIdentity {
		return fmt.Errorf("fenced VM cleanup requires exact cluster, location, NodeClaim, VM, billing, key-hash, token, phase, and observed identity")
	}
	if (r.FirewallProfile == inspacev1.FirewallProfilePrivateWorker && r.NodePoolName != "") ||
		((r.FirewallProfile == inspacev1.FirewallProfilePublicNodeLoadBalancer || r.FirewallProfile == inspacev1.FirewallProfilePublicNodeLocal) && r.NodePoolName == "") {
		return fmt.Errorf("fenced VM cleanup firewall profile and NodePool binding are inconsistent")
	}
	if r.FirewallProfile == inspacev1.FirewallProfilePublicNodeLoadBalancer || r.FirewallProfile == inspacev1.FirewallProfilePublicNodeLocal {
		if err := validateOwnedNodePoolIdentity(r.NodePoolName, r.NodeClaimName); err != nil {
			return fmt.Errorf("fenced VM cleanup NodePool/NodeClaim binding: %w", err)
		}
	}
	if err := validateV2WorkerName(r.ClusterName, r.NodeClaimName, r.VMName); err != nil {
		return err
	}
	if len(r.Resolutions) > cloudapi.MaxCreateCleanupResolutions {
		return fmt.Errorf("fenced VM cleanup resolution history exceeds %d receipts", cloudapi.MaxCreateCleanupResolutions)
	}
	activeFound := r.ObservedVMUUID == ""
	createdReceipt := false
	for i, resolution := range r.Resolutions {
		address, addressErr := netip.ParseAddr(resolution.PublicIPv4)
		if !vmUUIDPattern.MatchString(resolution.VMUUID) || resolution.VMUUID != strings.ToLower(resolution.VMUUID) || resolution.FloatingIPName == "" ||
			addressErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != resolution.PublicIPv4 ||
			(i > 0 && r.Resolutions[i-1].VMUUID >= resolution.VMUUID) {
			return fmt.Errorf("fenced VM cleanup resolution history contains a malformed, non-canonical, unsorted, or duplicate receipt")
		}
		if resolution.VMUUID == r.ObservedVMUUID && resolution.FloatingIPName == r.FloatingIPName && resolution.PublicIPv4 == r.PublicIPv4 {
			activeFound = true
		}
		if resolution.VMUUID == r.CreatedVMUUID {
			createdReceipt = true
		}
	}
	if !activeFound {
		return fmt.Errorf("fenced VM cleanup active identity is absent from its full receipt history")
	}
	if r.RollbackChosen {
		states := 0
		if createdReceipt {
			states++
		}
		if r.DependentUnresolved {
			states++
		}
		if r.DependentsResolved {
			states++
		}
		if r.CreatedVMUUID == "" || states != 1 {
			return fmt.Errorf("fenced VM rollback has inconsistent anchored dependent state")
		}
	} else if r.DependentUnresolved || r.DependentsResolved {
		return fmt.Errorf("fenced VM cleanup cannot have dependent disposition without rollback")
	}
	if err := validateAdapterCreateInventory(r.Baseline); err != nil {
		return err
	}
	for _, assignment := range r.Baseline.TargetFloatingIPs {
		if assignment.BillingAccountID != r.BillingAccountID {
			return fmt.Errorf("fenced VM cleanup target floating-IP billing account changed")
		}
	}
	return nil
}

func validateAdapterCreateInventory(inventory cloudapi.CreateInventory) error {
	encoded, err := json.Marshal(inventory)
	if err != nil || len(encoded) > cloudapi.MaxCreateInventoryEncodedBytes {
		return fmt.Errorf("create inventory exceeds the safe encoded bound of %d bytes", cloudapi.MaxCreateInventoryEncodedBytes)
	}
	for name, entries := range map[string][]string{"VM": inventory.VMs, "potential VM": inventory.PotentialVMs, "target VM": inventory.TargetVMs, "floating IP": inventory.FloatingIPs} {
		if len(entries) > cloudapi.MaxCreateInventoryEntries || !sort.StringsAreSorted(entries) {
			return fmt.Errorf("%s inventory exceeds %d entries or is not sorted", name, cloudapi.MaxCreateInventoryEntries)
		}
		for i := range entries {
			if entries[i] == "" || len(entries[i]) > 128 || (i > 0 && entries[i] == entries[i-1]) {
				return fmt.Errorf("%s inventory contains an empty, oversized, or duplicate identity", name)
			}
		}
	}
	vmSet := identitySet(inventory.VMs)
	for _, possible := range inventory.PotentialVMs {
		if _, ok := vmSet[possible]; !ok {
			return fmt.Errorf("potential VM identity %q is absent from the complete VM baseline", possible)
		}
	}
	potentialSet := identitySet(inventory.PotentialVMs)
	for _, target := range inventory.TargetVMs {
		if _, ok := potentialSet[target]; !ok {
			return fmt.Errorf("target VM identity %q is absent from the potential VM baseline", target)
		}
	}
	targetSet := identitySet(inventory.TargetVMs)
	floatingIPSet := identitySet(inventory.FloatingIPs)
	if len(inventory.TargetFloatingIPs) > cloudapi.MaxCreateTargetFloatingIPAssignments {
		return fmt.Errorf("target floating-IP inventory exceeds %d entries", cloudapi.MaxCreateTargetFloatingIPAssignments)
	}
	for i, assignment := range inventory.TargetFloatingIPs {
		address, addressErr := netip.ParseAddr(assignment.Address)
		if assignment.Identity == "" || len(assignment.Identity) > 128 ||
			!vmUUIDPattern.MatchString(assignment.VMUUID) || assignment.VMUUID != strings.ToLower(assignment.VMUUID) ||
			addressErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.String() != assignment.Address ||
			assignment.BillingAccountID <= 0 || len(assignment.Name) > 128 {
			return fmt.Errorf("target floating-IP inventory contains a malformed assignment")
		}
		if _, ok := targetSet[assignment.VMUUID]; !ok {
			return fmt.Errorf("target floating-IP assignment references non-target VM %q", assignment.VMUUID)
		}
		if _, ok := floatingIPSet[assignment.Identity]; !ok {
			return fmt.Errorf("target floating-IP assignment %q is absent from the complete floating-IP baseline", assignment.Identity)
		}
		if i > 0 {
			previous := inventory.TargetFloatingIPs[i-1]
			if previous.VMUUID > assignment.VMUUID || (previous.VMUUID == assignment.VMUUID && previous.Identity >= assignment.Identity) {
				return fmt.Errorf("target floating-IP inventory is unsorted or contains a duplicate assignment")
			}
		}
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
	if !strings.EqualFold(vm.UUID, vmUUID) {
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
	publicOwnershipPartial := false
	switch normalized.FirewallProfile {
	case "", inspacev1.FirewallProfilePrivateWorker, inspacev1.FirewallProfilePublicNodeLoadBalancer, inspacev1.FirewallProfilePublicNodeLocal:
		normalized.FirewallProfile = inspacev1.EffectiveFirewallProfile(normalized.FirewallProfile)
	default:
		return ownership{}, false, fmt.Errorf("unsupported recorded firewall profile %q", normalized.FirewallProfile)
	}
	if normalized.FirewallProfile == inspacev1.FirewallProfilePublicNodeLoadBalancer {
		if normalized.NodePool == "" || normalized.NodeClaim == "" {
			publicOwnershipPartial = true
		} else if _, err := nodeLoadBalancerShardFromOwnedNodeClaim(normalized.NodePool, normalized.NodeClaim); err != nil {
			return ownership{}, false, fmt.Errorf("invalid public Node load balancer NodePool/NodeClaim ownership: %v", err)
		}
	} else if normalized.FirewallProfile == inspacev1.FirewallProfilePublicNodeLocal {
		if normalized.NodePool == "" || normalized.NodeClaim == "" {
			publicOwnershipPartial = true
		} else if err := validateOwnedNodePoolIdentity(normalized.NodePool, normalized.NodeClaim); err != nil {
			return ownership{}, false, fmt.Errorf("invalid public local NodePool/NodeClaim ownership: %v", err)
		}
	} else if normalized.NodePool != "" {
		return ownership{}, false, fmt.Errorf("private worker ownership must not record NodePool identity %q", normalized.NodePool)
	}
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
	family := matches[1]
	memoryPerVCPU := map[string]int{"compute": 1, "general": 2, "memory": 4, "extra-memory": 8}[family]
	parsedCapacity := vCPUErr == nil && memoryErr == nil &&
		record.InstanceType == fmt.Sprintf("is-%s-%dc-%dg", family, derivedVCPU, derivedMemoryGiB)
	currentSchema := record.Schema == "" || record.Schema == ownershipSchema
	validOriginalCapacity := parsedCapacity && family != "extra-memory" &&
		derivedVCPU >= 2 && derivedVCPU <= 16 && derivedVCPU%2 == 0 && derivedMemoryGiB == derivedVCPU*memoryPerVCPU
	validCurrentMiniCapacity := parsedCapacity && currentSchema && derivedVCPU == 1 &&
		((family == "general" && derivedMemoryGiB == 2) || (family == "memory" && derivedMemoryGiB == 4))
	validCurrentExtraMemoryCapacity := parsedCapacity && currentSchema && family == "extra-memory" &&
		derivedVCPU >= 1 && derivedVCPU <= 8 && (derivedVCPU == 1 || derivedVCPU%2 == 0) && derivedMemoryGiB == derivedVCPU*memoryPerVCPU
	if !validOriginalCapacity && !validCurrentMiniCapacity && !validCurrentExtraMemoryCapacity {
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
	partial = publicOwnershipPartial || (extensionFields != 0 && extensionFields != 3)
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
		fieldMatchesOrIsMissing(actual.NodePool, expected.NodePool) &&
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
		fieldMatchesOrIsMissing(actual.FirewallProfile, expected.FirewallProfile) &&
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
		(!strings.EqualFold(floatingIP.AssignedTo, vmUUID) || floatingIP.AssignedToResourceType != "virtual_machine") {
		return fmt.Errorf("%w: floating IP %s is assigned to %s", cloudapi.ErrOwnershipMismatch, floatingIP.Address, floatingIP.AssignedTo)
	}
	return nil
}

func validateDeletableFloatingIP(floatingIP sdk.FloatingIP, record ownership, vmUUID string) error {
	parsed, err := netip.ParseAddr(floatingIP.Address)
	if err != nil || !parsed.Is4() || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || floatingIP.IsDeleted || floatingIP.IsVirtual ||
		!strings.EqualFold(strings.TrimSpace(floatingIP.Type), "public") {
		return fmt.Errorf("%w: floating IP recorded by owned VM %s is not a deletable public address", cloudapi.ErrOwnershipMismatch, vmUUID)
	}
	billingMismatch := (record.Schema == ownershipSchema && floatingIP.BillingAccountID != record.BillingAccountID) ||
		(record.Schema != ownershipSchema && floatingIP.BillingAccountID != 0 && floatingIP.BillingAccountID != record.BillingAccountID)
	if floatingIP.Name != record.FloatingIPName || (record.PublicIPv4 != "" && floatingIP.Address != record.PublicIPv4) || billingMismatch {
		return fmt.Errorf("%w: floating IP recorded by owned VM %s changed", cloudapi.ErrOwnershipMismatch, vmUUID)
	}
	if floatingIP.AssignedTo != "" && (!strings.EqualFold(floatingIP.AssignedTo, vmUUID) || floatingIP.AssignedToResourceType != "virtual_machine") {
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
		NodePoolName: record.NodePool, NodeClaimName: record.NodeClaim, Location: location, OSName: osName, OSVersion: osVersion,
		HostClass: record.HostClass, InstanceType: record.InstanceType, VCPU: vm.VCPU, MemoryGiB: vm.MemoryMiB / 1024,
		RootDiskGiB: rootDiskGiB, FirewallUUID: record.FirewallUUID, NetworkUUID: record.NetworkUUID, ControlPlaneVIP: record.ControlPlaneVIP,
		FirewallProfile:              inspacev1.EffectiveFirewallProfile(record.FirewallProfile),
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
		if err := a.ensureFreshFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, prevalidatedNetworkPrefix, request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName); err != nil {
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
		if err := a.ensureEarlyFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, prevalidatedNetworkPrefix, request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName); err != nil {
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

func (a *Adapter) ensureEarlyFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix, profile inspacev1.FirewallProfile, clusterName, nodePoolName, nodeClaimName string) error {
	timeout := a.protectionAuditTimeout
	if a.networkAttachmentReadbackTimeout < timeout {
		timeout = a.networkAttachmentReadbackTimeout
	}
	protectionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return a.ensureFirewall(protectionCtx, location, firewallUUID, vmUUID, networkPrefix, profile, clusterName, nodePoolName, nodeClaimName)
}

func (a *Adapter) ensureFreshFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix, profile inspacev1.FirewallProfile, clusterName, nodePoolName, nodeClaimName string) error {
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
				_, validationErr = validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, true, profile, clusterName, nodePoolName, nodeClaimName)
			}
			if validationErr == nil {
				return nil
			}
			lastObservation = validationErr
			if !isRetryableFirewallAssignmentReadback(validationErr) {
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
	return a.ensureAutoFloatingIPReadback(ctx, location, vmUUID, expectedName, billingAccountID, true, false)
}

func (a *Adapter) ensureAutoFloatingIPForCleanup(ctx context.Context, location, vmUUID, expectedName string, billingAccountID int64) (*sdk.FloatingIP, error) {
	return a.ensureAutoFloatingIPReadback(ctx, location, vmUUID, expectedName, billingAccountID, false, true)
}

func (a *Adapter) ensureAutoFloatingIPReadback(ctx context.Context, location, vmUUID, expectedName string, billingAccountID int64, requireUsable, allowSharedName bool) (*sdk.FloatingIP, error) {
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
			candidate, needsUpdate, validationErr := autoFloatingIPForVM(addresses, vmUUID, expectedName, billingAccountID, requireUsable, allowSharedName)
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

func autoFloatingIPForVM(addresses []sdk.FloatingIP, vmUUID, expectedName string, billingAccountID int64, requireUsable, allowSharedName bool) (*sdk.FloatingIP, bool, error) {
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
		if !strings.EqualFold(address.AssignedTo, vmUUID) {
			continue
		}
		if address.AssignedToResourceType != "virtual_machine" {
			return nil, false, fmt.Errorf("%w: floating IP %s is assigned to worker UUID %s with resource type %q", cloudapi.ErrOwnershipMismatch, address.Address, vmUUID, address.AssignedToResourceType)
		}
		assigned = append(assigned, address)
	}
	if !allowSharedName && len(namedMatches) > 1 {
		return nil, false, fmt.Errorf("%w: %d floating IPs share deterministic worker name %q", cloudapi.ErrOwnershipMismatch, len(namedMatches), expectedName)
	}
	if len(assigned) == 0 {
		if !allowSharedName && len(namedMatches) != 0 {
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
		if len(namedMatches) != 0 && !allowSharedName {
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
	if err := a.ensureFirewall(ctx, request.Location, request.FirewallUUID, vmUUID, networkPrefix, request.FirewallProfile, request.ClusterName, request.NodePoolName, request.NodeClaimName); err != nil {
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
				if strings.EqualFold(attachedVMUUID, vmUUID) {
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

func (a *Adapter) ensureFirewall(ctx context.Context, location, firewallUUID, vmUUID string, networkPrefix netip.Prefix, profile inspacev1.FirewallProfile, clusterName, nodePoolName, nodeClaimName string) error {
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
	assigned, err := validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, false, profile, clusterName, nodePoolName, nodeClaimName)
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
				_, err = validateWorkerFirewallAssignments(firewalls, firewallUUID, vmUUID, true, profile, clusterName, nodePoolName, nodeClaimName)
			}
			if err == nil {
				// An authoritative assignment readback wins over an ambiguous
				// mutation response; the public VM is now protected.
				return nil
			}
			lastObservation = err
			if !isRetryableFirewallAssignmentReadback(err) {
				return errors.Join(mutationErr, err)
			}
		}
		if err := waitForReadback(ctx, readbackDelay); err != nil {
			return fmt.Errorf("firewall %s assignment to VM %s did not converge: %w", firewallUUID, vmUUID, errors.Join(mutationErr, lastObservation, err))
		}
		readbackDelay = nextReadbackDelay(readbackDelay, a.networkAttachmentReadbackMaxDelay)
	}
}

func validateWorkerFirewallAssignments(firewalls []sdk.Firewall, intendedFirewallUUID, vmUUID string, requireIntended bool, profile inspacev1.FirewallProfile, clusterName, nodePoolName, nodeClaimName string) (bool, error) {
	assignments, err := firewallAssignmentsForVM(firewalls, vmUUID)
	if err != nil {
		return false, err
	}
	profile = inspacev1.EffectiveFirewallProfile(profile)
	expectedShard := ""
	switch profile {
	case inspacev1.FirewallProfilePrivateWorker:
		if len(assignments) == 0 && !requireIntended {
			return false, nil
		}
		if len(assignments) == 0 {
			return false, fmt.Errorf("%w: worker VM %s", errFirewallAssignmentNotVisible, vmUUID)
		}
		intendedCount := 0
		for _, firewallUUID := range assignments {
			if firewallUUID == intendedFirewallUUID {
				intendedCount++
			}
		}
		if intendedCount > 1 && intendedCount == len(assignments) {
			return false, fmt.Errorf("%w: %w: worker VM %s has duplicate intended firewall %s assignments", cloudapi.ErrOwnershipMismatch, errFirewallAssignmentReadbackDuplicate, vmUUID, intendedFirewallUUID)
		}
		if len(assignments) != 1 || assignments[0] != intendedFirewallUUID {
			return false, fmt.Errorf("%w: worker VM %s must be attached exactly once to intended firewall %s, got %v", cloudapi.ErrOwnershipMismatch, vmUUID, intendedFirewallUUID, assignments)
		}
		return true, nil
	case inspacev1.FirewallProfilePublicNodeLocal:
		if len(assignments) == 0 && !requireIntended {
			return false, nil
		}
		if len(assignments) == 0 {
			return false, fmt.Errorf("%w: public-node-local VM %s", errFirewallAssignmentNotVisible, vmUUID)
		}
		byUUID := make(map[string]*sdk.Firewall, len(firewalls))
		for i := range firewalls {
			byUUID[firewalls[i].UUID] = &firewalls[i]
		}
		intendedFirewall := byUUID[intendedFirewallUUID]
		if intendedFirewall == nil || intendedFirewall.BillingAccountID < 1 {
			return false, fmt.Errorf("%w: intended public-node-local firewall %s is absent or lacks billing identity", cloudapi.ErrOwnershipMismatch, intendedFirewallUUID)
		}
		intendedCount := 0
		seenAdditional := make(map[string]struct{}, len(assignments))
		for _, firewallUUID := range assignments {
			if firewallUUID == intendedFirewallUUID {
				intendedCount++
				continue
			}
			firewall := byUUID[firewallUUID]
			if firewall == nil {
				return false, fmt.Errorf("%w: assigned firewall %s is absent from the authoritative list", cloudapi.ErrOwnershipMismatch, firewallUUID)
			}
			if _, duplicate := seenAdditional[firewallUUID]; duplicate {
				return false, fmt.Errorf("%w: public-node-local VM %s has duplicate Service firewall %s assignments", cloudapi.ErrOwnershipMismatch, vmUUID, firewallUUID)
			}
			seenAdditional[firewallUUID] = struct{}{}
			if err := sdk.ValidateNodeLoadBalancerServiceFirewall(*firewall, clusterName, intendedFirewall.BillingAccountID); err != nil {
				return false, fmt.Errorf("%w: public-node-local VM %s additional firewall %s: %v", cloudapi.ErrOwnershipMismatch, vmUUID, firewallUUID, err)
			}
		}
		if intendedCount > 1 {
			return false, fmt.Errorf("%w: %w: public-node-local VM %s has duplicate intended firewall %s assignments", cloudapi.ErrOwnershipMismatch, errFirewallAssignmentReadbackDuplicate, vmUUID, intendedFirewallUUID)
		}
		if intendedCount == 0 {
			if requireIntended {
				return false, fmt.Errorf("%w: public-node-local VM %s", errFirewallAssignmentNotVisible, vmUUID)
			}
			return false, nil
		}
		return true, nil
	case inspacev1.FirewallProfilePublicNodeLoadBalancer:
		expectedShard, err = nodeLoadBalancerShardFromOwnedNodeClaim(nodePoolName, nodeClaimName)
		if err != nil {
			return false, fmt.Errorf("%w: public Node load balancer VM %s has invalid NodeClaim/NodePool shard ownership: %v", cloudapi.ErrOwnershipMismatch, vmUUID, err)
		}
	default:
		return false, fmt.Errorf("%w: worker VM %s has unsupported firewall profile %q", cloudapi.ErrOwnershipMismatch, vmUUID, profile)
	}

	byUUID := make(map[string]*sdk.Firewall, len(firewalls))
	for i := range firewalls {
		byUUID[firewalls[i].UUID] = &firewalls[i]
	}
	intendedFirewall := byUUID[intendedFirewallUUID]
	if intendedFirewall == nil {
		return false, fmt.Errorf("%w: intended worker firewall %s is absent from the authoritative list", cloudapi.ErrOwnershipMismatch, intendedFirewallUUID)
	}
	if intendedFirewall.BillingAccountID < 1 {
		return false, fmt.Errorf("%w: intended worker firewall %s has no positive billing-account identity", cloudapi.ErrOwnershipMismatch, intendedFirewallUUID)
	}
	intendedCount := 0
	icmpFirewallCount := 0
	shardFirewallCount := 0
	for _, firewallUUID := range assignments {
		if firewallUUID == intendedFirewallUUID {
			intendedCount++
			continue
		}
		firewall := byUUID[firewallUUID]
		if firewall == nil {
			return false, fmt.Errorf("%w: assigned firewall %s is absent from the authoritative list", cloudapi.ErrOwnershipMismatch, firewallUUID)
		}
		if err := validateNodeLoadBalancerClusterICMPFirewall(*firewall, clusterName, intendedFirewall.BillingAccountID); err == nil {
			icmpFirewallCount++
			if icmpFirewallCount > 1 {
				return false, fmt.Errorf("%w: worker VM %s has more than one cluster ICMP firewall", cloudapi.ErrOwnershipMismatch, vmUUID)
			}
			continue
		}
		if err := validateNodeLoadBalancerShardFirewall(*firewall, clusterName, expectedShard, intendedFirewall.BillingAccountID); err != nil {
			return false, fmt.Errorf("%w: worker VM %s additional firewall %s: %v", cloudapi.ErrOwnershipMismatch, vmUUID, firewallUUID, err)
		}
		shardFirewallCount++
		if shardFirewallCount > 1 {
			return false, fmt.Errorf("%w: worker VM %s has more than one cluster-owned shard firewall", cloudapi.ErrOwnershipMismatch, vmUUID)
		}
	}
	if intendedCount > 1 {
		return false, fmt.Errorf("%w: %w: worker VM %s has duplicate intended firewall %s assignments", cloudapi.ErrOwnershipMismatch, errFirewallAssignmentReadbackDuplicate, vmUUID, intendedFirewallUUID)
	}
	if intendedCount == 0 {
		if requireIntended {
			return false, fmt.Errorf("%w: worker VM %s", errFirewallAssignmentNotVisible, vmUUID)
		}
		return false, nil
	}
	return true, nil
}

// Only a duplicate observation of the exact intended firewall is safe to
// retry after an assignment mutation: at least one default-deny attachment is
// already visible, and the bounded readback may converge to the canonical
// single resource row. Established-state audits call the validator directly
// and remain strict, while any foreign or malformed assignment still fails
// immediately.
func isRetryableFirewallAssignmentReadback(err error) bool {
	return errors.Is(err, errFirewallAssignmentNotVisible) || errors.Is(err, errFirewallAssignmentReadbackDuplicate)
}

// nodeLoadBalancerShardFromOwnedNodeClaim returns the exact durable NodePool
// shard identity persisted at VM creation. Karpenter creates NodeClaims with
// GenerateName "<NodePool>-", and workerNodeName proves the live NodeClaim's
// karpenter.sh/nodepool label and generated-name prefix before the provider
// submits this ownership pair. Never infer a shorter shard from NodeClaim text:
// a foreign NodePool such as inlb-deadbeef-extra would otherwise alias shard
// inlb-deadbeef.
func nodeLoadBalancerShardFromOwnedNodeClaim(nodePoolName, nodeClaimName string) (string, error) {
	if !nodeLoadBalancerShardPattern.MatchString(nodePoolName) {
		return "", fmt.Errorf("NodePool name %q must exactly match inlb-<8 lowercase hex characters>", nodePoolName)
	}
	if err := validateOwnedNodePoolIdentity(nodePoolName, nodeClaimName); err != nil {
		return "", err
	}
	return nodePoolName, nil
}

func validateOwnedNodePoolIdentity(nodePoolName, nodeClaimName string) error {
	if messages := k8svalidation.IsDNS1123Label(nodePoolName); len(messages) != 0 {
		return fmt.Errorf("NodePool name %q is not a DNS-1123 label: %s", nodePoolName, strings.Join(messages, "; "))
	}
	if messages := k8svalidation.IsDNS1123Label(nodeClaimName); len(messages) != 0 {
		return fmt.Errorf("NodeClaim name %q is not a DNS-1123 label: %s", nodeClaimName, strings.Join(messages, "; "))
	}
	prefix := nodePoolName + "-"
	if !strings.HasPrefix(nodeClaimName, prefix) || len(nodeClaimName) == len(prefix) {
		return fmt.Errorf("NodeClaim name %q must use exact NodePool-generated prefix %q followed by a nonempty suffix", nodeClaimName, prefix)
	}
	return nil
}

func validateNodeLoadBalancerClusterICMPFirewall(firewall sdk.Firewall, clusterName string, billingAccountID int64) error {
	return sdk.ValidateNodeLoadBalancerClusterICMPFirewall(firewall, clusterName, billingAccountID)
}

func validateNodeLoadBalancerShardFirewall(firewall sdk.Firewall, clusterName, expectedShard string, billingAccountID int64) error {
	// The stable cloud name carries the shard identity while the mutable policy
	// hash is deliberately stored outside the name. Karpenter does not own the
	// CCM ledger, so derive the current hash only to validate the authoritative
	// rule shape; the CCM separately gates desired-policy convergence.
	if !nodeLoadBalancerShardPattern.MatchString(expectedShard) {
		return fmt.Errorf("expected shard %q is not a managed NodePool identity", expectedShard)
	}
	matches := nodeLoadBalancerShardFirewallPattern.FindStringSubmatch(firewall.EffectiveName())
	if len(matches) != 2 {
		return fmt.Errorf("name %q is not a stable shard firewall", firewall.EffectiveName())
	}
	actualShard := "inlb-" + matches[1]
	if actualShard != expectedShard {
		return fmt.Errorf("shard firewall belongs to NodePool %q, want %q", actualShard, expectedShard)
	}
	policyHash, err := sdk.NodeLoadBalancerShardFirewallSpecHash(firewall.Rules)
	if err != nil {
		return err
	}
	return sdk.ValidateNodeLoadBalancerShardFirewall(
		firewall,
		clusterName,
		expectedShard,
		billingAccountID,
		policyHash,
	)
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
		if strings.EqualFold(current.AssignedTo, vmUUID) && current.AssignedToResourceType == "virtual_machine" {
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
		if !strings.EqualFold(address.AssignedTo, vmUUID) {
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

func (a *Adapter) cleanupLaunch(ctx context.Context, location, networkUUID, firewallUUID, vmUUID string, floatingIP sdk.FloatingIP, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.launchCleanupTimeout)
	defer cancel()
	var errs []error
	vmDeleteErr := a.api.DeleteVM(cleanupCtx, location, vmUUID)
	if absenceErr := a.waitForVMCoreAbsence(cleanupCtx, location, networkUUID, vmUUID, "after launch rollback"); absenceErr != nil {
		if vmDeleteErr != nil {
			errs = append(errs, fmt.Errorf("deleting unprotected VM %s during launch rollback: %w", vmUUID, vmDeleteErr))
		}
		errs = append(errs, fmt.Errorf("cleanup of unprotected VM %s did not prove absence; cloud firewall remains attached: %w", vmUUID, absenceErr))
		return errors.Join(append([]error{cause}, errs...)...)
	}
	// Once Get/List/VPC prove the VM absent, explicitly retire the exact FIP;
	// its assignment may legitimately lag the VM deletion.
	floatingCtx, floatingCancel := context.WithTimeout(cleanupCtx, a.launchFloatingIPCleanupTimeout)
	floatingErr := a.deleteOwnedFloatingIP(floatingCtx, location, floatingIP, vmUUID)
	floatingCancel()
	if floatingErr != nil {
		errs = append(errs, floatingErr)
	}
	if absenceErr := a.waitForVMAbsence(cleanupCtx, location, networkUUID, vmUUID, "after launch dependent cleanup"); absenceErr != nil {
		errs = append(errs, absenceErr)
		return errors.Join(append([]error{cause}, errs...)...)
	}
	// Only after the final VM/FIP absence proof may firewall assignments go.
	if err := a.detachFirewallAfterVMDeletion(cleanupCtx, location, firewallUUID, vmUUID); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return fmt.Errorf("%w: ownership-proven VM %s and its dependents were fully rolled back before ProviderID persistence: %w", cloudapi.ErrCreateAttemptRejected, vmUUID, cause)
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
					if expectedVMUUID == "" || !strings.EqualFold(current.AssignedTo, expectedVMUUID) || current.AssignedToResourceType != "virtual_machine" {
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
		// The exact public address is the durable mutation anchor. Historical
		// duplicate launches can legitimately share the deterministic name; never
		// mutate those siblings and do not make them block this receipt.
		identityOverlap := address.Address == expected.Address ||
			(expectedVMUUID != "" && strings.EqualFold(address.AssignedTo, expectedVMUUID))
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
			if !strings.EqualFold(resource.ResourceUUID, vmUUID) {
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
					if addresses[i].Name == identity.FloatingIPName || addresses[i].Address == identity.PublicIPv4 || strings.EqualFold(addresses[i].AssignedTo, vmUUID) {
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
				overlaps := addresses[i].Address == identity.PublicIPv4 || strings.EqualFold(addresses[i].AssignedTo, vmUUID)
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
					(strings.EqualFold(candidate.AssignedTo, vmUUID) && candidate.AssignedToResourceType == "virtual_machine")
				if !assignedIdentityValid {
					return nil, fmt.Errorf("%w: durable floating IP %q cannot be proven to belong to missing VM %s", cloudapi.ErrOwnershipMismatch, expectedName, vmUUID)
				}
				if err := validateDeletableFloatingIP(candidate, ownership{
					Schema: ownershipSchema, FloatingIPName: identity.FloatingIPName, PublicIPv4: identity.PublicIPv4,
					BillingAccountID: identity.BillingAccountID,
				}, vmUUID); err != nil {
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
		if strings.EqualFold(resource.ResourceType, "vm") && strings.EqualFold(resource.ResourceUUID, vmUUID) {
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

// inspectOwnershipForFence routes an explicitly foreign cluster/NodeClaim by
// the durable ownership envelope before interpreting mutable launch-shape
// fields. A drifted or older foreign worker must not wedge cleanup for this
// claim, while an ambiguous record for the target claim remains fail-closed.
func inspectOwnershipForFence(description, targetCluster, targetNodeClaim string) (record ownership, karpenter, complete, definitivelyForeign bool, err error) {
	var envelope struct {
		Schema    json.RawMessage `json:"schema"`
		Cluster   json.RawMessage `json:"cluster"`
		NodeClaim json.RawMessage `json:"nodeClaim"`
	}
	if json.Unmarshal([]byte(description), &envelope) == nil {
		var schema, cluster, nodeClaim string
		if json.Unmarshal(envelope.Schema, &schema) == nil && supportedOwnershipSchema(schema) {
			_ = json.Unmarshal(envelope.Cluster, &cluster)
			_ = json.Unmarshal(envelope.NodeClaim, &nodeClaim)
			if (cluster != "" && cluster != targetCluster) ||
				(cluster == targetCluster && nodeClaim != "" && nodeClaim != targetNodeClaim) {
				// Best-effort decode preserves diagnostics. Routing authority comes
				// only from the supported schema plus explicit cluster/claim pair.
				_ = json.Unmarshal([]byte(description), &record)
				record.Schema = schema
				record.Cluster = cluster
				record.NodeClaim = nodeClaim
				return record, true, ownershipRecordStructurallyComplete(record), true, nil
			}
		}
	}
	record, karpenter, complete, err = inspectOwnershipDescription(description, targetCluster)
	return record, karpenter, complete, false, err
}

func ownershipRecordStructurallyComplete(record ownership) bool {
	validSchemaAndName := ((record.Schema == ownershipSchema || record.Schema == legacyV2OwnershipSchema) && record.VMName != "") || record.Schema == legacyOwnershipSchema
	validPublicIdentity := record.Schema == ownershipSchema || record.PublicIPv4 != ""
	profile := inspacev1.EffectiveFirewallProfile(record.FirewallProfile)
	validNodePoolIdentity := (profile != inspacev1.FirewallProfilePublicNodeLoadBalancer && profile != inspacev1.FirewallProfilePublicNodeLocal) || record.NodePool != ""
	return validSchemaAndName && record.Cluster != "" && record.NodeClaim != "" && record.KeyHash != "" &&
		record.HostClass != "" && record.InstanceType != "" && record.RootDiskGiB > 0 && record.SpecHash != "" &&
		record.BootstrapHash != "" && record.FirewallUUID != "" && record.NetworkUUID != "" && record.ControlPlaneVIP != "" &&
		record.PrivateLoadBalancerPoolStart != "" && record.PrivateLoadBalancerPoolStop != "" && record.OSName != "" &&
		record.OSVersion != "" && record.BillingAccountID > 0 && record.FloatingIPName != "" && validPublicIdentity && validNodePoolIdentity
}

func supportedOwnershipSchema(schema string) bool {
	return schema == ownershipSchema || schema == legacyV2OwnershipSchema || schema == legacyOwnershipSchema
}

func hashKey(key string) string {
	return cloudapi.OwnershipKeyHash(key)
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
